// --- GLOBALS ---
const socket = io();
const earlyCandidates = {};
let myHostedFiles = [];
let currentRemoteFiles = [];
let myRootFolderName = "ROOT";
let incomingFileBuffer = [];
let isPreviewMode = false;
let currentActiveFolderName = "ROOT";
let currentPathStr = "";
let currentActivePeerId = null;
let isZipBatchMode = false;

// --- WEBRTC GLOBALS ---
const peers = {};
const iceConfig = {
    iceServers: [
        { urls: 'stun:stun.l.google.com:19302' },
        { urls: 'stun:stun1.l.google.com:19302' },
        { urls: 'stun:stun2.l.google.com:19302' },
        { urls: 'stun:stun3.l.google.com:19302' },
        { urls: 'stun:global.stun.twilio.com:3478' }
    ]
};
const jsonChunkBuffer = {};

// --- LIFECYCLE MANAGEMENT ---
const lifeCycleChannel = new BroadcastChannel('terminal_chat_lifecycle');

lifeCycleChannel.onmessage = (event) => {
    if (event.data.type === 'MASTER_DISCONNECT') {
        console.log("Master session ended. Closing interface...");
        window.close();
    }
};

// --- INITIALISIERUNG ---
const user = localStorage.getItem('fs_username');
const userKey = localStorage.getItem('fs_key');

if(!user) {
    document.body.innerHTML = `
        <div style="display:flex; justify-content:center; align-items:center; height:100vh; flex-direction:column; color:red;">
            <h1>ACCESS DENIED</h1>
            <p>Please login via TERMINAL_CHAT first.</p>
            <button onclick="window.close()" style="background:#000; color:#0f0; border:1px solid #0f0; padding:10px;">CLOSE</button>
        </div>
    `;
    throw new Error("No Auth");
}

console.log(`SYSTEM: Initialized for user ${user}`);

// --- MOCK DATA ---
const mockFileSystem = {
    'share1': {
        name: 'PROJECT_OMEGA',
        user: 'Neo',
        files: [
            { type: 'folder', name: 'Blueprints', content: [] },
            { type: 'file', name: 'passwords.txt', content: 'ROOT: admin123\nUSER: guest' }
        ]
    }
};

renderSidebarMock();

// --- SOCKET EVENTS ---
socket.on('connect', () => {
    console.log("Connected to File System Network");
    const savedUser = localStorage.getItem('fs_username');
    if (savedUser) {
        socket.emit('fs_login', { username: savedUser, key: localStorage.getItem('fs_key') });
    }
    socket.emit('fs_request_update');
});

socket.on('fs_update_shares', (sharesList) => {
    if (currentActivePeerId && !sharesList[currentActivePeerId]) {
        console.log("Active host disconnected.");
        closePreview();
        document.getElementById('fileGrid').innerHTML = '<div class="empty-state" style="color:red;">&lt; SIGNAL LOST: HOST DISCONNECTED &gt;</div>';
        currentActivePeerId = null;
        currentActiveFolderName = "ROOT";
        updateBreadcrumbs(['ROOT']);
    }
    renderSidebar(sharesList);
});

socket.on('p2p_signal', async (data) => {
    await handleP2PMessage(data.senderId, data.signal, data.type);
});

// --- P2P CONNECTION LOGIC (DEBUG VERSION) ---

// 1. Verbindung starten (Als GAST / SENDER)
async function connectToPeer(targetId) {
    if (peers[targetId]) {
        console.warn(`Resetting connection to ${targetId}`);
        if(peers[targetId].connection) peers[targetId].connection.close();
        if(peers[targetId].channel) peers[targetId].channel.close();
        delete peers[targetId];
    }

    console.log(`Starting connection to ${targetId}...`);

    const pc = new RTCPeerConnection(iceConfig);

    let iceQueue = [];
    let offerSent = false;

    const channel = pc.createDataChannel("fileSystem");
    setupChannelHandlers(channel, targetId);

    peers[targetId] = {
        connection: pc,
        channel: channel,
        pendingQueue: []
    };

    pc.onicecandidate = (event) => {
        if (event.candidate) {
            console.log("Generated Candidate:", event.candidate.candidate); // DEBUG LOG
            if (offerSent) {
                socket.emit('p2p_signal', { targetId: targetId, type: 'candidate', signal: event.candidate });
            } else {
                iceQueue.push(event.candidate);
            }
        } else {
            console.log("End of Candidates (Host)");
        }
    };

    pc.oniceconnectionstatechange = () => {
        console.log(`ICE State (${targetId}): ${pc.iceConnectionState}`);
        if (pc.iceConnectionState === 'failed' || pc.iceConnectionState === 'disconnected') {
            const grid = document.getElementById('fileGrid');
            if(grid) grid.innerHTML = '<div style="color:red; margin-top:50px; text-align:center;">CONNECTION FAILED.<br>CHECK FIREWALL/EXTENSIONS.</div>';
        }
    };

    try {
        const offer = await pc.createOffer();
        await pc.setLocalDescription(offer);

        console.log("Sending Offer...");
        socket.emit('p2p_signal', { targetId: targetId, type: 'offer', signal: offer });
        offerSent = true;

        if (iceQueue.length > 0) {
            console.log(`Flushing ${iceQueue.length} buffered candidates.`);
            iceQueue.forEach(c => socket.emit('p2p_signal', { targetId: targetId, type: 'candidate', signal: c }));
        }

    } catch (err) {
        console.error("Error creating connection:", err);
    }
}

// 2. Eingehende Signale verarbeiten
async function handleP2PMessage(senderId, signal, type) {

    // FALL A: ZU FRÜHE CANDIDATES
    if (!peers[senderId] && type === 'candidate') {
        console.log(`[Cache] Storing early candidate from ${senderId}`);
        if (!earlyCandidates[senderId]) earlyCandidates[senderId] = [];
        earlyCandidates[senderId].push(signal);
        return;
    }

    // FALL B: NEUES ANGEBOT (OFFER)
    if (type === 'offer') {
        if (peers[senderId]) {
            if(peers[senderId].connection) peers[senderId].connection.close();
            delete peers[senderId];
        }

        const pc = new RTCPeerConnection(iceConfig);

        pc.ondatachannel = (event) => {
            console.log("Host: Data Channel received!");
            const channel = event.channel;
            setupChannelHandlers(channel, senderId);
            if(peers[senderId]) peers[senderId].channel = channel;
        };

        pc.onicecandidate = (event) => {
            if (event.candidate) {
                console.log("Host generated candidate"); // DEBUG LOG
                socket.emit('p2p_signal', { targetId: senderId, type: 'candidate', signal: event.candidate });
            }
        };

        peers[senderId] = {
            connection: pc,
            channel: null,
            pendingQueue: []
        };

        if (earlyCandidates[senderId]) {
            console.log(`[Cache] Found ${earlyCandidates[senderId].length} early candidates.`);
            peers[senderId].pendingQueue.push(...earlyCandidates[senderId]);
            delete earlyCandidates[senderId];
        }
    }

    if (!peers[senderId]) return;

    const p = peers[senderId];
    const pc = p.connection;

    try {
        if (type === 'offer') {
            await pc.setRemoteDescription(new RTCSessionDescription(signal));
            const answer = await pc.createAnswer();
            await pc.setLocalDescription(answer);
            socket.emit('p2p_signal', { targetId: senderId, type: 'answer', signal: answer });

            processPendingQueue(p, pc);
        }
        else if (type === 'answer') {
            await pc.setRemoteDescription(new RTCSessionDescription(signal));
            processPendingQueue(p, pc);
        }
        else if (type === 'candidate') {
            if (!pc.remoteDescription || pc.remoteDescription.type === null) {
                p.pendingQueue.push(signal);
            } else {
                await pc.addIceCandidate(new RTCIceCandidate(signal)).catch(e => console.warn("Candidate Error:", e));
            }
        }
    } catch (e) {
        console.error("WebRTC Error:", e);
    }
}

// 3. Queue Helper
async function processPendingQueue(peerObj, pc) {
    if (peerObj.pendingQueue.length > 0) {
        console.log(`Processing ${peerObj.pendingQueue.length} queued candidates.`);
        for (const candidate of peerObj.pendingQueue) {
            try {
                await pc.addIceCandidate(new RTCIceCandidate(candidate));
            } catch (e) { console.warn("Candidate skip:", e); }
        }
        peerObj.pendingQueue = [];
    }
}

// 4. Kanal Events
function setupChannelHandlers(channel, peerId) {
    channel.onopen = () => {
        console.log(`CHANNEL OPENED with ${peerId} -> Requesting ROOT`);
        channel.send(JSON.stringify({ type: 'REQUEST_ROOT' }));
    };

    channel.onmessage = (event) => {
        try {
            const msg = JSON.parse(event.data);
            handleChannelMessage(msg, peerId, channel);
        } catch (e) {
            if (event.data.includes('JSON_CHUNK')) {
                const chunkMsg = JSON.parse(event.data);
                handleChannelMessage(chunkMsg, peerId, channel);
            }
        }
    };

    channel.onclose = () => {
        console.log(`Channel closed with ${peerId}`);
        delete peers[peerId];
    };
    channel.onerror = (err) => console.error("Channel Error:", err);
}

// --- FILE SYSTEM LOGIC & PROTOCOL ---

function handleChannelMessage(msg, peerId, channel) {

    if (msg.type === 'JSON_CHUNK') {
        if (!jsonChunkBuffer[peerId]) jsonChunkBuffer[peerId] = '';
        jsonChunkBuffer[peerId] += msg.data;
        if (msg.isLast) {
            const fullMessage = JSON.parse(jsonChunkBuffer[peerId]);
            delete jsonChunkBuffer[peerId];
            handleChannelMessage(fullMessage, peerId, channel);
        }
        return;
    }

    if (msg.type === 'REQUEST_ROOT') {
        const rootItems = getItemsInPath(myHostedFiles, myRootFolderName);
        sendLargeJSON(channel, 'RESPONSE_DIRECTORY', { items: rootItems, path: myRootFolderName });
    }

    if (msg.type === 'REQUEST_DIRECTORY') {
        const items = getItemsInPath(myHostedFiles, msg.path);
        sendLargeJSON(channel, 'RESPONSE_DIRECTORY', { items: items, path: msg.path });
    }

    if (msg.type === 'REQUEST_DOWNLOAD') {
        console.log(`[HOST] Incoming request for: "${msg.filename}"`);
        let requestedFile = myHostedFiles.find(f => f.webkitRelativePath === msg.filename);
        if (!requestedFile) requestedFile = myHostedFiles.find(f => f.name === msg.filename);
        if (!requestedFile) requestedFile = myHostedFiles.find(f => f.webkitRelativePath.endsWith(msg.filename));

        if (requestedFile) {
            streamFileToPeer(requestedFile, channel);
        } else {
            channel.send(JSON.stringify({ type: 'ERROR', message: `File not found on host: ${msg.filename}` }));
        }
    }

    if (msg.type === 'REQUEST_RECURSIVE_LIST') {
        const files = getAllFilesInPathRecursive(myHostedFiles, msg.path);
        const metaList = files.map(f => ({
            fullPath: f.webkitRelativePath,
            relativePath: msg.path ? f.webkitRelativePath.substring(msg.path.length + 1) : f.webkitRelativePath
        }));
        sendLargeJSON(channel, 'RESPONSE_RECURSIVE_LIST', { list: metaList });
    }

    if (msg.type === 'RESPONSE_DIRECTORY') {
        currentPathStr = msg.payload.path;
        const crumbs = currentPathStr.split('/');
        updateBreadcrumbs(['ROOT', ...crumbs]);
        renderRemoteGrid(msg.payload.items, peerId);
    }

    if (msg.type === 'RESPONSE_RECURSIVE_LIST') {
        console.log(`Starting Batch Download for ${msg.payload.list.length} files.`);
        zipQueue = msg.payload.list;
        processZipQueue();
    }

    if (msg.type === 'ERROR') {
        console.error("P2P Error:", msg.message);
        if (isZipBatchMode) {
            processZipQueue();
        } else if (isPreviewMode) {
            document.getElementById('previewContent').innerHTML = `<div style="color:red; text-align:center; margin-top:20%;">${msg.message}</div>`;
        } else {
            alert("Error: " + msg.message);
        }
        incomingFileBuffer = [];
    }

    if (msg.type === 'FILE_CHUNK') {
        const chunkData = base64ToArrayBuffer(msg.data);
        incomingFileBuffer.push(chunkData);

        if (msg.isLast) {
            const blob = new Blob(incomingFileBuffer, {type: 'application/octet-stream'});

            if (isZipBatchMode) {
                let zipPath = msg.filename;
                if (currentPathStr && zipPath.startsWith(currentPathStr + '/')) {
                    zipPath = zipPath.substring(currentPathStr.length + 1);
                } else if (zipPath.startsWith(currentPathStr)) {
                    zipPath = zipPath.substring(currentPathStr.length);
                    if(zipPath.startsWith('/')) zipPath = zipPath.substring(1);
                }
                if (zipInstance) zipInstance.file(zipPath, blob);
                incomingFileBuffer = [];
                processZipQueue();

            } else if (isPreviewMode) {
                renderRemoteBlob(blob, msg.filename);
                incomingFileBuffer = [];
            } else {
                triggerBrowserDownload(blob, msg.filename);
                incomingFileBuffer = [];
            }
        }
    }
}

// --- UI / RENDERING ---

function triggerMount() { document.getElementById('folderInput').click(); }

document.getElementById('folderInput').addEventListener('change', (e) => {
    const files = e.target.files;
    if (files.length === 0) return;
    myHostedFiles = Array.from(files);
    const rootFolderName = files[0].webkitRelativePath.split('/')[0];
    myRootFolderName = rootFolderName;
    console.log(`MOUNTING: ${rootFolderName}`);
    document.getElementById('btnMount').style.display = 'none';
    const unmountBtn = document.getElementById('btnUnmount');
    unmountBtn.style.display = 'block';
    unmountBtn.innerText = `[-] UNMOUNT [${rootFolderName}]`;
    socket.emit('fs_start_hosting', { folderName: rootFolderName });
});

function unmountDrive() {
    myHostedFiles = [];
    document.getElementById('folderInput').value = '';
    closePreview();
    document.getElementById('fileGrid').innerHTML = '<div class="empty-state">&lt; DRIVE UNMOUNTED &gt;</div>';
    currentActivePeerId = null;
    document.getElementById('btnMount').style.display = 'block';
    document.getElementById('btnUnmount').style.display = 'none';
    socket.emit('fs_stop_hosting');
}

function renderSidebar(shares) {
    const list = document.getElementById('shareList');
    list.innerHTML = '';
    const shareIds = Object.keys(shares);
    if (shareIds.length === 0) {
        list.innerHTML = '<li style="padding:15px; color:#555; text-align:center;">No active drives.</li>';
        return;
    }
    shareIds.forEach(socketId => {
        const item = shares[socketId];
        const isMe = (socketId === socket.id);
        const li = document.createElement('li');
        li.className = 'share-item';
        if(isMe) li.style.cssText = 'color:#0f0; border-left:4px solid #0f0;';

        li.onclick = () => {
            document.getElementById('filePreview').style.display = 'none';
            document.getElementById('fileGrid').style.display = 'grid';
            incomingFileBuffer = [];
            currentActivePeerId = socketId;
            document.querySelectorAll('.share-item').forEach(el => el.classList.remove('active'));
            li.classList.add('active');

            if(isMe) {
                currentPathStr = item.folderName;
                renderLocalGrid(getItemsInPath(myHostedFiles, currentPathStr));
                updateBreadcrumbs([item.folderName]);
            } else {
                document.getElementById('fileGrid').innerHTML = '<div style="color:#0f0; text-align:center; margin-top:50px;">ESTABLISHING P2P UPLINK...</div>';
                connectToPeer(socketId);
            }
        };
        li.innerHTML = `<span class="share-name">${isMe ? item.folderName + ' (LOCAL)' : item.folderName}</span><span class="share-user">${isMe ? 'HOSTED BY YOU' : item.username}</span>`;
        list.appendChild(li);
    });
}

function renderLocalGrid(items) {
    const grid = document.getElementById('fileGrid');
    grid.innerHTML = '';
    document.getElementById('folderActions').style.display = 'none';

    if (currentPathStr && currentPathStr !== myRootFolderName) {
        addBackButton(grid, () => {
            const parts = currentPathStr.split('/');
            parts.pop();
            currentPathStr = parts.join('/');
            renderLocalGrid(getItemsInPath(myHostedFiles, currentPathStr));
            updateBreadcrumbs(['ROOT', ...parts]);
        });
    }

    if(items.length === 0) { grid.innerHTML += '<div class="empty-state">EMPTY FOLDER</div>'; return; }

    items.forEach(item => {
        const el = createGridItem(item);
        if(item.type === 'folder') {
            el.onclick = () => {
                currentPathStr = item.fullPath;
                renderLocalGrid(getItemsInPath(myHostedFiles, currentPathStr));
                const crumbs = currentPathStr.split('/');
                updateBreadcrumbs(['ROOT', ...crumbs]);
            };
        } else {
            el.onclick = () => {
                let realFile = myHostedFiles.find(f => f.webkitRelativePath === item.fullPath || f.name === item.name);
                if(realFile) openFile(realFile);
            };
        }
        grid.appendChild(el);
    });
}

function renderRemoteGrid(items, peerId) {
    const grid = document.getElementById('fileGrid');
    grid.innerHTML = '';

    const actionArea = document.getElementById('folderActions');
    const zipBtn = document.getElementById('btnZipDownload');
    actionArea.style.display = 'block';
    const folderName = currentPathStr.split('/').pop() || "ROOT";
    zipBtn.textContent = `[ DOWNLOAD '${folderName}' AS .ZIP ]`;
    zipBtn.onclick = () => downloadFolderAsZip(currentPathStr, false, peerId);

    if (currentPathStr && currentPathStr.includes('/')) {
        addBackButton(grid, () => {
            const parts = currentPathStr.split('/');
            parts.pop();
            navigateRemote(parts.join('/'), peerId);
        });
    }

    if(!items || items.length === 0) { grid.innerHTML += '<div class="empty-state">EMPTY FOLDER</div>'; return; }

    items.forEach(item => {
        const el = createGridItem(item);
        if(item.type === 'folder') {
            el.onclick = () => navigateRemote(item.fullPath, peerId);
        } else {
            el.onclick = () => openRemoteFilePreview(item, peerId);
        }
        grid.appendChild(el);
    });
}

// Helper UI functions
function addBackButton(grid, onClick) {
    const backDiv = document.createElement('div');
    backDiv.className = 'file-icon';
    backDiv.style.opacity = "0.7";
    backDiv.innerHTML = `<div class="icon-img" style="font-size:30px; display:flex; justify-content:center; align-items:center; border:1px solid #0f0; border-radius:50%;"><svg viewBox="0 0 24 24" style="width:32px; height:32px; fill:#0f0;"><path d="M20 11H7.83l5.59-5.59L12 4l-8 8 8 8 1.41-1.41L7.83 13H20v-2z"/></svg></div><div class="file-label">[ GO BACK ]</div>`;
    backDiv.onclick = onClick;
    grid.appendChild(backDiv);
}

function createGridItem(item) {
    const el = document.createElement('div');
    el.className = 'file-icon';
    let iconSvg = item.type === 'folder' ?
        `<svg viewBox="0 0 24 24" style="width:48px; height:48px; fill:#0f0;"><path d="M10 4H4c-1.1 0-1.99.9-1.99 2L2 18c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2h-8l-2-2z"/></svg>` :
        `<svg viewBox="0 0 24 24" style="width:48px; height:48px; fill:#0f0;"><path d="M14 2H6c-1.1 0-1.99.9-1.99 2L4 20c0 1.1.89 2 1.99 2H18c1.1 0 2-.9 2-2V8l-6-6zm2 16H8v-2h8v2zm0-4H8v-2h8v2zm-3-5V3.5L18.5 9H13z"/></svg>`;
    el.innerHTML = `<div class="icon-img">${iconSvg}</div><div class="file-label">${item.name}</div>`;
    return el;
}

function openFile(file) {
    document.getElementById('fileGrid').style.display = 'none';
    document.getElementById('filePreview').style.display = 'flex';
    document.getElementById('previewFileName').textContent = file.name;
    const btn = document.querySelector('#filePreview .btn-action');
    btn.style.opacity = "0.5"; btn.style.cursor = "default"; btn.onclick = null; btn.textContent = "[ LOCAL SOURCE ]";

    const contentDiv = document.getElementById('previewContent');
    contentDiv.textContent = "Loading preview...";
    const reader = new FileReader();
    reader.onload = (e) => {
        const isImage = file.name.match(/\.(jpeg|jpg|gif|png|webp)$/i);
        if (isImage) {
            contentDiv.innerHTML = '';
            const img = document.createElement('img');
            img.src = e.target.result;
            img.style.maxWidth = '100%'; img.style.border = '1px solid #0f0';
            contentDiv.appendChild(img);
        } else { contentDiv.textContent = e.target.result; }
    };
    if (file.name.match(/\.(jpeg|jpg|gif|png|webp)$/i)) reader.readAsDataURL(file); else reader.readAsText(file);
    updateBreadcrumbs([currentActiveFolderName, file.name]);
}

function openRemoteFilePreview(item, peerId) {
    document.getElementById('fileGrid').style.display = 'none';
    document.getElementById('filePreview').style.display = 'flex';
    document.getElementById('previewFileName').textContent = item.name;
    document.getElementById('previewContent').innerHTML = '<div style="color:#0f0; text-align:center; margin-top:20%;">[ P2P STREAMING IN PROGRESS... ]<br>Receiving Data packets...</div>';

    const btn = document.querySelector('#filePreview .btn-action');
    const newBtn = btn.cloneNode(true);
    btn.parentNode.replaceChild(newBtn, btn);
    newBtn.textContent = "[ SAVE TO DISK ]"; newBtn.style.opacity = "1"; newBtn.style.cursor = "pointer";
    newBtn.onclick = () => { isPreviewMode = false; requestFileFromPeer(item.fullPath || item.name, peerId); };

    isPreviewMode = true;
    requestFileFromPeer(item.fullPath || item.name, peerId);
    const crumbs = currentPathStr ? currentPathStr.split('/') : [currentActiveFolderName];
    updateBreadcrumbs([currentActiveFolderName, item.name]);
}

function closePreview() {
    document.getElementById('filePreview').style.display = 'none';
    document.getElementById('fileGrid').style.display = 'grid';
    incomingFileBuffer = [];
    updateBreadcrumbs([currentActiveFolderName]);
}

function updateBreadcrumbs(pathArray) {
    const bar = document.getElementById('breadcrumbs');
    bar.innerHTML = 'ROOT <span class="separator">></span> ';
    let accumulatedPath = "";
    pathArray.forEach((crumb, index) => {
        if (index > 0) accumulatedPath = accumulatedPath ? `${accumulatedPath}/${crumb}` : crumb;
        const span = document.createElement('span');
        span.className = 'crumb';
        span.textContent = crumb;
        if (index < pathArray.length - 1) {
            span.onclick = () => {
                if (index === 0) return;
                if (currentActivePeerId && currentActivePeerId !== socket.id) {
                    navigateRemote(accumulatedPath, currentActivePeerId);
                } else {
                    currentPathStr = accumulatedPath;
                    renderLocalGrid(getItemsInPath(myHostedFiles, currentPathStr));
                    const newCrumbs = pathArray.slice(0, index + 1);
                    updateBreadcrumbs(newCrumbs);
                }
            };
        } else { span.style.color = "#fff"; span.style.cursor = "default"; }
        bar.appendChild(span);
        if(index < pathArray.length - 1) bar.innerHTML += '<span class="separator">></span>';
    });
}

function renderSidebarMock() { /* Keep existing mock */ }

// --- HELPERS (Logic) ---

function requestFileList(targetId) {
    if (peers[targetId]?.channel?.readyState === 'open') peers[targetId].channel.send(JSON.stringify({ type: 'REQUEST_ROOT' }));
}

function navigateRemote(path, peerId) {
    if (peers[peerId]?.channel) {
        console.log(`Navigating to: ${path}`);
        peers[peerId].channel.send(JSON.stringify({ type: 'REQUEST_DIRECTORY', path: path }));
    }
}

function requestFileFromPeer(pathOrName, peerId) {
    incomingFileBuffer = [];
    if (peers[peerId]?.channel) {
        console.log(`Requesting ${pathOrName}`);
        peers[peerId].channel.send(JSON.stringify({ type: 'REQUEST_DOWNLOAD', filename: pathOrName }));
    }
}

function sendLargeJSON(channel, type, payload) {
    const json = JSON.stringify({ type, payload });
    const MAX = 12000;
    for (let i = 0; i < json.length; i += MAX) {
        channel.send(JSON.stringify({ type: 'JSON_CHUNK', data: json.slice(i, i + MAX), isLast: i + MAX >= json.length }));
    }
}

function getItemsInPath(allFiles, currentPath) {
    const items = [];
    const knownFolders = new Set();
    allFiles.forEach(file => {
        const fullPath = file.webkitRelativePath;
        if (!fullPath.startsWith(currentPath + '/')) { if (currentPath !== "" && currentPath !== file.webkitRelativePath.split('/')[0]) return; }
        const relativePart = fullPath.substring(currentPath.length + (currentPath ? 1 : 0));
        const parts = relativePart.split('/');
        if (parts.length === 1) {
            if(parts[0] !== "") items.push({ name: parts[0], type: 'file', size: file.size, fullPath: fullPath });
        } else {
            const folderName = parts[0];
            if (!knownFolders.has(folderName)) {
                knownFolders.add(folderName);
                items.push({ name: folderName, type: 'folder', fullPath: currentPath ? `${currentPath}/${folderName}` : folderName });
            }
        }
    });
    return items;
}

function getAllFilesInPathRecursive(allFiles, startPath) {
    return allFiles.filter(file => {
        const path = file.webkitRelativePath;
        if (startPath === "" || startPath === myRootFolderName) return true;
        return path.startsWith(startPath + '/');
    });
}

function streamFileToPeer(file, channel) {
    if (file.size === 0) {
        channel.send(JSON.stringify({ type: 'FILE_CHUNK', filename: file.webkitRelativePath || file.name, data: "", isLast: true }));
        return;
    }
    const chunkSize = 16384;
    let offset = 0;
    const reader = new FileReader();
    reader.onload = (e) => {
        if (channel.readyState !== 'open') return;
        channel.send(JSON.stringify({ type: 'FILE_CHUNK', filename: file.webkitRelativePath || file.name, data: arrayBufferToBase64(e.target.result), isLast: (offset + chunkSize >= file.size) }));
        offset += chunkSize;
        if (offset < file.size) setTimeout(readNextChunk, 10);
        else console.log("Upload complete.");
    };
    const readNextChunk = () => { const slice = file.slice(offset, offset + chunkSize); reader.readAsArrayBuffer(slice); };
    readNextChunk();
}

// --- UTILS ---
function arrayBufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
    return window.btoa(binary);
}
function base64ToArrayBuffer(base64) {
    const binary_string = window.atob(base64);
    const bytes = new Uint8Array(binary_string.length);
    for (let i = 0; i < binary_string.length; i++) bytes[i] = binary_string.charCodeAt(i);
    return bytes.buffer;
}
function renderRemoteBlob(blob, filename) {
    const contentDiv = document.getElementById('previewContent');
    contentDiv.innerHTML = '';
    const isImage = filename.match(/\.(jpeg|jpg|gif|png|webp)$/i);
    if (isImage) {
        const url = URL.createObjectURL(blob);
        const img = document.createElement('img');
        img.src = url;
        img.style.maxWidth = '100%'; img.style.border = '1px solid #0f0';
        contentDiv.appendChild(img);
    } else {
        const reader = new FileReader();
        reader.onload = (e) => { contentDiv.textContent = e.target.result; };
        reader.readAsText(blob);
    }
}
function triggerBrowserDownload(blob, filename) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = filename;
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
}

// --- ZIP LOGIC ---
async function downloadFolderAsZip(path, isLocal, peerId) {
    const folderName = path.split('/').pop() || "archive";
    if (isLocal) {
        const zip = new JSZip();
        const filesToZip = getAllFilesInPathRecursive(myHostedFiles, path);
        if(filesToZip.length === 0) { alert("Folder is empty."); return; }
        const btn = document.getElementById('btnZipDownload');
        btn.textContent = "[ ZIPPING... ]";
        filesToZip.forEach(file => {
            let relativePath = file.webkitRelativePath;
            if(path) relativePath = relativePath.substring(path.length + 1);
            zip.file(relativePath, file);
        });
        const content = await zip.generateAsync({type:"blob"});
        triggerBrowserDownload(content, `${folderName}.zip`);
        btn.textContent = `[ DOWNLOAD '${folderName}' AS .ZIP ]`;
    } else if (peerId) {
        zipInstance = new JSZip(); zipQueue = []; isZipBatchMode = false;
        const btn = document.getElementById('btnZipDownload');
        btn.textContent = "[ REQUESTING LIST... ]";
        isZipping = true; currentZipPeerId = peerId;
        peers[peerId].channel.send(JSON.stringify({ type: 'REQUEST_RECURSIVE_LIST', path: path }));
    }
}

let zipInstance = null;
let currentZipPeerId = null;
let isZipping = false;

function processZipQueue() {
    if (zipQueue.length === 0) { finalizeRemoteZip(); return; }
    const nextFile = zipQueue.shift();
    const btn = document.getElementById('btnZipDownload');
    if(btn) btn.textContent = `[ ZIPPING: ${zipQueue.length} FILES ]`;
    isZipBatchMode = true;
    requestFileFromPeer(nextFile.fullPath, currentZipPeerId);
}

async function finalizeRemoteZip() {
    if (!zipInstance) { isZipping = false; isZipBatchMode = false; return; }
    const btn = document.getElementById('btnZipDownload');
    if(btn) btn.textContent = "[ FINALIZING ZIP... ]";
    try {
        const content = await zipInstance.generateAsync({type:"blob"});
        const name = currentPathStr.split('/').pop() || "remote_archive";
        triggerBrowserDownload(content, `${name}.zip`);
        if(btn) btn.textContent = "[ COMPLETE ]";
    } catch (e) { console.error(e); }
    finally {
        isZipping = false; isZipBatchMode = false; currentZipPeerId = null; zipInstance = null; zipQueue = [];
        setTimeout(() => { if(btn) btn.textContent = `[ DOWNLOAD AS .ZIP ]`; }, 3000);
    }
}