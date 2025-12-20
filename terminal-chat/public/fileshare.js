// --- GLOBALS ---
const socket = io();
const earlyCandidates = {};
let myHostedFiles = [];
let currentRemoteFiles = [];
let myRootFolderName = "ROOT";
let myRealRootName = "";
let myMountPassword = null;
let incomingFileBuffer = [];
let isPreviewMode = false;
let currentPathStr = "";
let currentActivePeerId = null;
let isZipBatchMode = false;

// Variables for Mounting & Passwords
let pendingFiles = null;
let targetPeerForPassword = null;

// --- WEBRTC CONFIG ---
const peers = {};
const iceConfig = {
    iceServers: [
        { urls: 'stun:stun.l.google.com:19302' },
        { urls: 'stun:stun1.l.google.com:19302' },
        { urls: 'stun:stun2.l.google.com:19302' },
        { urls: 'stun:global.stun.twilio.com:3478' }
    ]
};
const jsonChunkBuffer = {};

// --- LIFECYCLE ---
const lifeCycleChannel = new BroadcastChannel('terminal_chat_lifecycle');
lifeCycleChannel.onmessage = (event) => {
    if (event.data.type === 'MASTER_DISCONNECT') window.close();
};

// --- AUTH CHECK ---
const user = localStorage.getItem('fs_username');
if(!user) {
    document.body.innerHTML = `<div style="display:flex;justify-content:center;align-items:center;height:100vh;color:red;"><h1>ACCESS DENIED</h1></div>`;
    throw new Error("No Auth");
}
console.log(`SYSTEM: Initialized for user ${user}`);

// --- SOCKET EVENTS ---
socket.on('connect', () => {
    console.log("Connected to File System Network");
    if (localStorage.getItem('fs_username')) {
        socket.emit('fs_login', { username: localStorage.getItem('fs_username'), key: localStorage.getItem('fs_key') });
    }
    socket.emit('fs_request_update');
});

socket.on('fs_update_shares', (sharesList) => {
    if (currentActivePeerId && !sharesList[currentActivePeerId]) {
        closePreview();
        document.getElementById('fileGrid').innerHTML = '<div class="empty-state" style="color:red;">&lt; HOST DISCONNECTED &gt;</div>';
        currentActivePeerId = null;
        updateBreadcrumbs(['ROOT']);
    }
    renderSidebar(sharesList);
});

socket.on('p2p_signal', async (data) => {
    await handleP2PMessage(data.senderId, data.signal, data.type);
});

// --- MOUNT MODAL LOGIC ---

function triggerMount() {
    document.getElementById('mountModal').style.display = 'flex';
    document.getElementById('mountName').value = '';
    document.getElementById('mountAllowedUsers').value = '';
    document.getElementById('mountPassword').value = '';
    document.getElementById('selectedFolderName').textContent = 'No folder selected';
    pendingFiles = null;
}

function closeMountModal() {
    document.getElementById('mountModal').style.display = 'none';
    pendingFiles = null;
}

// Hidden Input Change Listener
const hiddenInput = document.getElementById('hiddenFolderInput');
if(hiddenInput) {
    hiddenInput.addEventListener('change', (e) => {
        if (e.target.files.length === 0) return;
        pendingFiles = Array.from(e.target.files);

        const detectedName = pendingFiles[0].webkitRelativePath.split('/')[0];
        document.getElementById('selectedFolderName').textContent = detectedName;

        if(document.getElementById('mountName').value === '') {
            document.getElementById('mountName').value = detectedName;
        }
    });
}

function confirmMount() {
    if (!pendingFiles || pendingFiles.length === 0) {
        alert("Please select a folder first.");
        return;
    }

    const customName = document.getElementById('mountName').value || "Unnamed Drive";
    const allowedStr = document.getElementById('mountAllowedUsers').value;
    const password = document.getElementById('mountPassword').value;
    const allowedUsers = allowedStr ? allowedStr.split(',').map(s => s.trim()).filter(Boolean) : [];

    // GLOBALS SETZEN
    myHostedFiles = pendingFiles;
    myRootFolderName = customName;
    myRealRootName = pendingFiles[0].webkitRelativePath.split('/')[0];
    myMountPassword = password || null;

    console.log(`[MOUNT] Virtual: "${myRootFolderName}" -> Real: "${myRealRootName}"`);

    closeMountModal();

    document.getElementById('btnMount').style.display = 'none';
    const unmountBtn = document.getElementById('btnUnmount');
    unmountBtn.style.display = 'block';
    unmountBtn.innerText = `[-] UNMOUNT [${customName}]`;

    socket.emit('fs_start_hosting', {
        folderName: customName,
        allowedUsers: allowedUsers,
        isProtected: !!password
    });
}

function unmountDrive() {
    myHostedFiles = [];
    myRootFolderName = "ROOT";
    myRealRootName = "";
    myMountPassword = null;
    closePreview();
    document.getElementById('fileGrid').innerHTML = '<div class="empty-state">&lt; UNMOUNTED &gt;</div>';
    document.getElementById('btnMount').style.display = 'block';
    document.getElementById('btnUnmount').style.display = 'none';
    socket.emit('fs_stop_hosting');
}

// --- PASSWORD MODAL LOGIC ---

function closePasswordModal() {
    document.getElementById('passwordModal').style.display = 'none';
    document.getElementById('accessPassword').value = '';
    targetPeerForPassword = null;
}

function submitPassword() {
    const pw = document.getElementById('accessPassword').value;
    if(!pw) return;
    const peerId = targetPeerForPassword;
    closePasswordModal();
    initiateConnectionWithPassword(peerId, pw);
}

// --- UI LOGIC ---

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
        const isLocked = item.isProtected && !isMe;

        const li = document.createElement('li');
        li.className = 'share-item';
        if(isMe) li.style.cssText = 'color:#0f0; border-left:4px solid #0f0;';

        const lockIcon = isLocked ? '🔒 ' : '';
        li.innerHTML = `<span class="share-name">${lockIcon}${isMe ? item.folderName + ' (LOCAL)' : item.folderName}</span><span class="share-user">${isMe ? 'HOSTED BY YOU' : item.username}</span>`;

        li.onclick = () => {
            document.querySelectorAll('.share-item').forEach(el => el.classList.remove('active'));
            li.classList.add('active');

            if (isMe) {
                // LOCAL
                document.getElementById('filePreview').style.display = 'none';
                document.getElementById('fileGrid').style.display = 'grid';
                currentActivePeerId = socketId;

                currentPathStr = item.folderName;
                const items = getMappedLocalItems(currentPathStr);
                renderLocalGrid(items);
                updateBreadcrumbs(['ROOT', item.folderName]);
            } else {
                // REMOTE
                if (item.isProtected) {
                    targetPeerForPassword = socketId;
                    document.getElementById('passwordModal').style.display = 'flex';
                    document.getElementById('accessPassword').focus();
                } else {
                    initiateConnectionWithPassword(socketId, null);
                }
            }
        };
        list.appendChild(li);
    });
}

function initiateConnectionWithPassword(peerId, password) {
    document.getElementById('filePreview').style.display = 'none';
    document.getElementById('fileGrid').style.display = 'grid';
    document.getElementById('fileGrid').innerHTML = '<div style="color:#0f0; text-align:center; margin-top:50px;">AUTHENTICATING...<br>(Establishing secure P2P Tunnel)</div>';
    currentActivePeerId = peerId;

    // FIX: Passwort direkt übergeben!
    connectToPeer(peerId, password);
}

function renderLocalGrid(items) {
    const grid = document.getElementById('fileGrid');
    grid.innerHTML = '';
    document.getElementById('folderActions').style.display = 'none';

    if (currentPathStr && currentPathStr !== myRootFolderName) {
        addBackButton(grid, () => {
            const parts = currentPathStr.split('/').filter(Boolean);
            parts.pop();
            currentPathStr = parts.join('/');
            if(currentPathStr === "") currentPathStr = myRootFolderName;

            renderLocalGrid(getMappedLocalItems(currentPathStr));
            updateBreadcrumbs(['ROOT', ...parts]);
        });
    }

    if(items.length === 0) {
        grid.innerHTML += '<div class="empty-state">EMPTY FOLDER</div>';
        return;
    }

    items.forEach(item => {
        const el = createGridItem(item);
        if(item.type === 'folder') {
            el.onclick = () => {
                currentPathStr = item.fullPath;
                renderLocalGrid(getMappedLocalItems(currentPathStr));
                const crumbs = currentPathStr.split('/').filter(Boolean);
                updateBreadcrumbs(['ROOT', ...crumbs]);
            };
        } else {
            el.onclick = () => {
                const realPath = mapVirtualToReal(item.fullPath);
                const realFile = myHostedFiles.find(f => f.webkitRelativePath === realPath);
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

    if(!items || items.length === 0) {
        grid.innerHTML += '<div class="empty-state">EMPTY FOLDER</div>';
        return;
    }

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

// --- FILE & PATH LOGIC ---

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

    const parts = currentPathStr ? currentPathStr.split('/').filter(Boolean) : [];
    updateBreadcrumbs(['ROOT', ...parts, file.name]);
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

    const parts = currentPathStr ? currentPathStr.split('/') : [];
    updateBreadcrumbs(['ROOT', ...parts, item.name]);
}

function updateBreadcrumbs(pathArray) {
    const bar = document.getElementById('breadcrumbs');
    bar.innerHTML = '';

    let accumulatedPath = "";

    pathArray.forEach((crumb, index) => {
        if (index > 0) accumulatedPath = accumulatedPath ? `${accumulatedPath}/${crumb}` : crumb;

        const pathToThisCrumb = accumulatedPath;

        const span = document.createElement('span');
        span.className = 'crumb';
        span.textContent = crumb;

        if (index < pathArray.length - 1) {
            span.style.cursor = "pointer";
            span.onclick = () => {
                document.getElementById('filePreview').style.display = 'none';
                document.getElementById('fileGrid').style.display = 'grid';
                isPreviewMode = false;
                incomingFileBuffer = [];

                if (index === 0) {
                    // ROOT
                    if (currentActivePeerId && currentActivePeerId !== socket.id) {
                        navigateRemote("", currentActivePeerId);
                    } else {
                        currentPathStr = myRootFolderName;
                        renderLocalGrid(getMappedLocalItems(currentPathStr));
                        updateBreadcrumbs(['ROOT', myRootFolderName]);
                    }
                } else {
                    // FOLDER
                    if (currentActivePeerId && currentActivePeerId !== socket.id) {
                        navigateRemote(pathToThisCrumb, currentActivePeerId);
                    } else {
                        currentPathStr = pathToThisCrumb;
                        renderLocalGrid(getMappedLocalItems(currentPathStr));
                        const newCrumbs = pathArray.slice(0, index + 1);
                        updateBreadcrumbs(newCrumbs);
                    }
                }
            };
        } else {
            span.style.color = "#fff"; span.style.cursor = "default";
        }
        bar.appendChild(span);
        if(index < pathArray.length - 1) {
            const sep = document.createElement('span'); sep.className = 'separator'; sep.textContent = '>'; bar.appendChild(sep);
        }
    });
}

function closePreview() {
    document.getElementById('filePreview').style.display = 'none';
    document.getElementById('fileGrid').style.display = 'grid';
    incomingFileBuffer = [];
    const parts = currentPathStr ? currentPathStr.split('/').filter(Boolean) : [];
    updateBreadcrumbs(['ROOT', ...parts]);
}

// --- HELPER: PATH MAPPING ---

function mapVirtualToReal(virtualPath) {
    if (!virtualPath) return "";
    if (myRootFolderName && myRealRootName && virtualPath.startsWith(myRootFolderName)) {
        return virtualPath.replace(myRootFolderName, myRealRootName);
    }
    return virtualPath;
}

function mapRealToVirtual(realPath) {
    if (!realPath) return "";
    if (myRootFolderName && myRealRootName && realPath.startsWith(myRealRootName)) {
        return realPath.replace(myRealRootName, myRootFolderName);
    }
    return realPath;
}

function getMappedLocalItems(virtualPath) {
    const realSearchPath = mapVirtualToReal(virtualPath);
    console.log(`[DEBUG] Mapping: "${virtualPath}" -> "${realSearchPath}"`); // DEBUG LOG

    const rawItems = getItemsInPath(myHostedFiles, realSearchPath);
    console.log(`[DEBUG] Found ${rawItems.length} items.`); // DEBUG LOG

    return rawItems.map(item => {
        return { ...item, fullPath: mapRealToVirtual(item.fullPath) };
    });
}

// --- P2P CONNECTION LOGIC ---

// FIX: password parameter added
async function connectToPeer(targetId, password = null) {
    if (peers[targetId]) {
        if(peers[targetId].connection) peers[targetId].connection.close();
        delete peers[targetId];
    }
    console.log(`Starting connection to ${targetId}...`);

    const pc = new RTCPeerConnection(iceConfig);
    const channel = pc.createDataChannel("fileSystem");
    let iceQueue = [];
    let offerSent = false;

    // FIX: password passed to handlers
    setupChannelHandlers(channel, targetId, password);

    peers[targetId] = { connection: pc, channel: channel, pendingQueue: [] };

    pc.onicecandidate = (event) => {
        if (event.candidate) {
            if (offerSent) socket.emit('p2p_signal', { targetId: targetId, type: 'candidate', signal: event.candidate });
            else iceQueue.push(event.candidate);
        }
    };
    pc.oniceconnectionstatechange = () => {
        if(pc.iceConnectionState === 'failed') document.getElementById('fileGrid').innerHTML = '<div style="color:red; margin-top:50px; text-align:center;">CONNECTION FAILED.<br>FIREWALL BLOCKED P2P.</div>';
    };

    try {
        const offer = await pc.createOffer();
        await pc.setLocalDescription(offer);
        socket.emit('p2p_signal', { targetId: targetId, type: 'offer', signal: offer });
        offerSent = true;
        if (iceQueue.length > 0) iceQueue.forEach(c => socket.emit('p2p_signal', { targetId: targetId, type: 'candidate', signal: c }));
    } catch (err) { console.error("Connection Error:", err); }
}

async function handleP2PMessage(senderId, signal, type) {
    if (!peers[senderId] && type === 'candidate') {
        if (!earlyCandidates[senderId]) earlyCandidates[senderId] = [];
        earlyCandidates[senderId].push(signal);
        return;
    }
    if (type === 'offer') {
        if (peers[senderId]) { if(peers[senderId].connection) peers[senderId].connection.close(); delete peers[senderId]; }
        const pc = new RTCPeerConnection(iceConfig);
        pc.ondatachannel = (event) => {
            const channel = event.channel;
            // Host braucht kein Passwort zum Antworten, aber wir lassen die Funktion generisch
            setupChannelHandlers(channel, senderId, null);
            if(peers[senderId]) peers[senderId].channel = channel;
        };
        pc.onicecandidate = (event) => {
            if (event.candidate) socket.emit('p2p_signal', { targetId: senderId, type: 'candidate', signal: event.candidate });
        };
        peers[senderId] = { connection: pc, channel: null, pendingQueue: [] };
        if (earlyCandidates[senderId]) {
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
            if (!pc.remoteDescription || pc.remoteDescription.type === null) p.pendingQueue.push(signal);
            else await pc.addIceCandidate(new RTCIceCandidate(signal)).catch(e => {});
        }
    } catch (e) { console.error("WebRTC Error:", e); }
}

async function processPendingQueue(peerObj, pc) {
    if (peerObj.pendingQueue.length > 0) {
        for (const candidate of peerObj.pendingQueue) {
            try { await pc.addIceCandidate(new RTCIceCandidate(candidate)); } catch (e) {}
        }
        peerObj.pendingQueue = [];
    }
}

// FIX: password parameter added
function setupChannelHandlers(channel, peerId, password) {
    channel.onopen = () => {
        console.log(`CHANNEL OPENED with ${peerId}`);
        // WICHTIG: Passwort mitsenden!
        channel.send(JSON.stringify({ type: 'REQUEST_ROOT', password: password }));
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
    channel.onclose = () => delete peers[peerId];
}

function handleChannelMessage(msg, peerId, channel) {
    if (msg.type === 'JSON_CHUNK') {
        if (!jsonChunkBuffer[peerId]) jsonChunkBuffer[peerId] = '';
        jsonChunkBuffer[peerId] += msg.data;
        if (msg.isLast) {
            const full = JSON.parse(jsonChunkBuffer[peerId]);
            delete jsonChunkBuffer[peerId];
            handleChannelMessage(full, peerId, channel);
        }
        return;
    }

    // --- HOST LOGIC ---
    if (msg.type === 'REQUEST_ROOT') {
        if (myMountPassword && msg.password !== myMountPassword) {
            channel.send(JSON.stringify({ type: 'ERROR', message: 'ACCESS DENIED: WRONG PASSWORD' }));
            return;
        }

        const items = getMappedLocalItems(myRootFolderName);
        sendLargeJSON(channel, 'RESPONSE_DIRECTORY', { items: items, path: myRootFolderName });
    }

    if (msg.type === 'REQUEST_DIRECTORY') {
        const items = getMappedLocalItems(msg.path);
        sendLargeJSON(channel, 'RESPONSE_DIRECTORY', { items: items, path: msg.path });
    }

    if (msg.type === 'REQUEST_DOWNLOAD') {
        const realPath = mapVirtualToReal(msg.filename);
        let file = myHostedFiles.find(f => f.webkitRelativePath === realPath);
        if(!file) file = myHostedFiles.find(f => f.name === msg.filename.split('/').pop());

        if (file) streamFileToPeer(file, channel);
        else channel.send(JSON.stringify({ type: 'ERROR', message: 'File not found.' }));
    }

    if (msg.type === 'REQUEST_RECURSIVE_LIST') {
        const realSearchPath = mapVirtualToReal(msg.path);
        const files = getAllFilesInPathRecursive(myHostedFiles, realSearchPath);

        const list = files.map(f => {
            const virtualFull = mapRealToVirtual(f.webkitRelativePath);
            let relative = virtualFull;
            if(msg.path && virtualFull.startsWith(msg.path)) {
                relative = virtualFull.substring(msg.path.length + 1);
            }
            return { fullPath: virtualFull, relativePath: relative };
        });

        sendLargeJSON(channel, 'RESPONSE_RECURSIVE_LIST', { list });
    }

    // --- CLIENT LOGIC ---
    if (msg.type === 'RESPONSE_DIRECTORY') {
        currentPathStr = msg.payload.path;
        const crumbs = currentPathStr.split('/').filter(Boolean);
        updateBreadcrumbs(['ROOT', ...crumbs]);
        renderRemoteGrid(msg.payload.items, peerId);
    }
    if (msg.type === 'RESPONSE_RECURSIVE_LIST') {
        zipQueue = msg.payload.list;
        processZipQueue();
    }
    if (msg.type === 'ERROR') {
        if(isZipBatchMode) processZipQueue();
        else if (isPreviewMode) document.getElementById('previewContent').innerHTML = `<div style="color:red;margin-top:20%;text-align:center">${msg.message}</div>`;
        else {
            document.getElementById('fileGrid').innerHTML = `<div class="empty-state" style="color:red;">${msg.message}</div>`;
            alert(msg.message);
        }
        incomingFileBuffer = [];
    }
    if (msg.type === 'FILE_CHUNK') {
        incomingFileBuffer.push(base64ToArrayBuffer(msg.data));
        if (msg.isLast) {
            const blob = new Blob(incomingFileBuffer, {type: 'application/octet-stream'});
            if (isZipBatchMode) {
                let p = msg.filename;
                if (currentPathStr && p.startsWith(currentPathStr)) p = p.substring(currentPathStr.length + 1);
                if(zipInstance) zipInstance.file(p, blob);
                incomingFileBuffer = []; processZipQueue();
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

// --- HELPERS ---
function createGridItem(i){
    const d=document.createElement('div'); d.className='file-icon';
    d.innerHTML=`<div class="icon-img">${i.type==='folder'?'[DIR]':'[FILE]'}</div><div class="file-label">${i.name}</div>`;
    if(i.type==='folder') d.querySelector('.icon-img').innerHTML = `<svg viewBox="0 0 24 24" style="width:48px; height:48px; fill:#0f0;"><path d="M10 4H4c-1.1 0-1.99.9-1.99 2L2 18c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2h-8l-2-2z"/></svg>`;
    else d.querySelector('.icon-img').innerHTML = `<svg viewBox="0 0 24 24" style="width:48px; height:48px; fill:#0f0;"><path d="M14 2H6c-1.1 0-1.99.9-1.99 2L4 20c0 1.1.89 2 1.99 2H18c1.1 0 2-.9 2-2V8l-6-6zm2 16H8v-2h8v2zm0-4H8v-2h8v2zm-3-5V3.5L18.5 9H13z"/></svg>`;
    return d;
}

function addBackButton(g,cb){
    const d=document.createElement('div'); d.className='file-icon'; d.style.opacity='0.7';
    d.innerHTML=`<div class="icon-img" style="font-size:30px;display:flex;justify-content:center;align-items:center;border:1px solid #0f0;border-radius:50%;"><svg viewBox="0 0 24 24" style="width:32px; height:32px; fill:#0f0;"><path d="M20 11H7.83l5.59-5.59L12 4l-8 8 8 8 1.41-1.41L7.83 13H20v-2z"/></svg></div><div class="file-label">[ GO BACK ]</div>`;
    d.onclick=cb; g.appendChild(d);
}

function sendLargeJSON(c,t,p){ const j=JSON.stringify({type:t,payload:p}); const MAX=12000; for(let i=0;i<j.length;i+=MAX) c.send(JSON.stringify({type:'JSON_CHUNK',data:j.slice(i,i+MAX),isLast:i+MAX>=j.length})); }

function getItemsInPath(files,path){
    return files.filter(f => f.webkitRelativePath.startsWith(path + '/')).map(f => {
        const p = f.webkitRelativePath.substring(path.length + 1).split('/');
        return p.length === 1 ?
            {name:p[0], type:'file', fullPath:f.webkitRelativePath} :
            {name:p[0], type:'folder', fullPath:path+'/'+p[0]};
    }).filter((v,i,a) => a.findIndex(t => (t.name === v.name)) === i);
}

function getAllFilesInPathRecursive(files,path){ return files.filter(f=>f.webkitRelativePath.startsWith(path+'/')); }

function streamFileToPeer(f,c){
    const chunk=16384; let off=0; const r=new FileReader();
    r.onload=e=>{ if(c.readyState!=='open')return; c.send(JSON.stringify({type:'FILE_CHUNK',filename:f.webkitRelativePath,data:arrayBufferToBase64(e.target.result),isLast:(off+chunk>=f.size)})); off+=chunk; if(off<f.size)setTimeout(readNext,5); };
    const readNext=()=>r.readAsArrayBuffer(f.slice(off,off+chunk)); readNext();
}
function arrayBufferToBase64(b){ let binary=''; const bytes=new Uint8Array(b); for(let i=0;i<bytes.byteLength;i++)binary+=String.fromCharCode(bytes[i]); return window.btoa(binary); }
function base64ToArrayBuffer(b){ const s=window.atob(b); const y=new Uint8Array(s.length); for(let i=0;i<s.length;i++)y[i]=s.charCodeAt(i); return y.buffer; }
// Zeigt Remote-Dateien (Blobs) an, statt nur einen Link zu geben
function renderRemoteBlob(blob, filename) {
    const contentDiv = document.getElementById('previewContent');
    contentDiv.innerHTML = ''; // Lade-Text entfernen

    // 1. Prüfen auf Bild-Endungen
    const isImage = filename.match(/\.(jpeg|jpg|gif|png|webp|bmp|svg)$/i);

    if (isImage) {
        // BILD ANZEIGEN
        const url = URL.createObjectURL(blob);
        const img = document.createElement('img');
        img.src = url;
        img.style.maxWidth = '100%';
        img.style.maxHeight = '600px'; // Damit es nicht den Screen sprengt
        img.style.border = '1px solid #0f0';
        contentDiv.appendChild(img);
    }
    else {
        // TEXT / CODE ANZEIGEN
        // Sicherheits-Check: Keine riesigen Dateien (> 2MB) als Text rendern, das friert den Browser ein
        if (blob.size > 2 * 1024 * 1024) {
            contentDiv.innerHTML = `
                <div style="color:orange; text-align:center; margin-top:20%;">
                    [ FILE TOO LARGE FOR PREVIEW ]<br>
                    Please use the [ SAVE TO DISK ] button above.
                </div>`;
            return;
        }

        const reader = new FileReader();

        reader.onload = (e) => {
            // Wir packen den Text in ein <pre> Tag, damit Formatierung erhalten bleibt
            const pre = document.createElement('pre');
            pre.style.whiteSpace = 'pre-wrap';       // Zeilenumbruch
            pre.style.wordBreak = 'break-word';      // Lange Wörter brechen
            pre.style.textAlign = 'left';
            pre.style.fontFamily = "'Courier New', monospace";
            pre.style.margin = '10px';
            pre.textContent = e.target.result;       // Sicherer als innerHTML (verhindert XSS)

            contentDiv.appendChild(pre);
        };

        reader.onerror = () => {
            contentDiv.innerHTML = '<div style="color:red">Error reading file content.</div>';
        };

        // Versuchen als Text zu lesen
        reader.readAsText(blob);
    }
}function triggerBrowserDownload(b,n){ const u=URL.createObjectURL(b); const a=document.createElement('a'); a.href=u; a.download=n; document.body.appendChild(a); a.click(); document.body.removeChild(a); }
function requestFileList(tid){ if(peers[tid]?.channel?.readyState==='open') peers[tid].channel.send(JSON.stringify({type:'REQUEST_ROOT'})); }
function navigateRemote(p,tid){ if(peers[tid]?.channel) peers[tid].channel.send(JSON.stringify({type:'REQUEST_DIRECTORY',path:p})); }
function requestFileFromPeer(n,tid){ incomingFileBuffer=[]; if(peers[tid]?.channel) peers[tid].channel.send(JSON.stringify({type:'REQUEST_DOWNLOAD',filename:n})); }
async function downloadFolderAsZip(p,l,tid){
    if (l) { /* local */ }
    else if (tid) { zipInstance = new JSZip(); zipQueue = []; isZipBatchMode = false; isZipping = true; currentZipPeerId = tid; peers[tid].channel.send(JSON.stringify({ type: 'REQUEST_RECURSIVE_LIST', path: p })); document.getElementById('btnZipDownload').textContent="[ REQUESTING... ]"; }
}
function processZipQueue(){
    if (zipQueue.length === 0) { finalizeRemoteZip(); return; }
    const next = zipQueue.shift(); document.getElementById('btnZipDownload').textContent = `[ ZIPPING: ${zipQueue.length} ]`;
    isZipBatchMode = true; requestFileFromPeer(next.fullPath, currentZipPeerId);
}
async function finalizeRemoteZip(){
    if(!zipInstance) { isZipping=false; isZipBatchMode=false; return; }
    const c=await zipInstance.generateAsync({type:"blob"}); triggerBrowserDownload(c, `${currentPathStr.split('/').pop()}.zip`);
    isZipping=false; isZipBatchMode=false; zipInstance=null; zipQueue=[];
    document.getElementById('btnZipDownload').textContent="[ DONE ]"; setTimeout(()=>document.getElementById('btnZipDownload').textContent="[ DOWNLOAD ZIP ]", 2000);
}
function renderSidebarMock(){ }