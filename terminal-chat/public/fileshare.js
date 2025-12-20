// --- GLOBALS ---
const socket = io();
const earlyCandidates = {};
let myHostedFiles = [];
let currentRemoteFiles = [];
let myRootFolderName = "ROOT"; // Der "Custom Name"
let myRealRootName = "";       // Der echte Name des Ordners auf der Festplatte
let myMountPassword = null;    // Passwort (null = keins)
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

// Hidden Input Change Listener (in fileshare.js, needs HTML element)
// Stelle sicher, dass <input type="file" id="hiddenFolderInput" ...> im HTML existiert
const hiddenInput = document.getElementById('hiddenFolderInput');
if(hiddenInput) {
    hiddenInput.addEventListener('change', (e) => {
        if (e.target.files.length === 0) return;
        pendingFiles = Array.from(e.target.files);

        // Echten Namen ermitteln
        const detectedName = pendingFiles[0].webkitRelativePath.split('/')[0];
        document.getElementById('selectedFolderName').textContent = detectedName;

        // Name vorschlagen, falls leer
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

    // SET GLOBALS
    myHostedFiles = pendingFiles;
    myRootFolderName = customName; // Der Name, den User sehen
    // Den echten Ordnernamen speichern wir für das Mapping
    myRealRootName = pendingFiles[0].webkitRelativePath.split('/')[0];
    myMountPassword = password || null;

    closeMountModal();

    // UI Update
    document.getElementById('btnMount').style.display = 'none';
    const unmountBtn = document.getElementById('btnUnmount');
    unmountBtn.style.display = 'block';
    unmountBtn.innerText = `[-] UNMOUNT [${customName}]`;

    // Server Info
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

// --- UI LOGIC (SIDEBAR & GRID) ---

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
                // LOCAL VIEW
                document.getElementById('filePreview').style.display = 'none';
                document.getElementById('fileGrid').style.display = 'grid';
                currentActivePeerId = socketId;

                // Wir starten mit dem Custom Name als Pfad
                currentPathStr = item.folderName;

                // MAPPED Items holen
                const items = getMappedLocalItems(currentPathStr);
                renderLocalGrid(items);
                updateBreadcrumbs(['ROOT', item.folderName]);
            } else {
                // REMOTE VIEW
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

    // Auth speichern
    if(!peers[peerId]) peers[peerId] = {};
    peers[peerId].authPassword = password;

    connectToPeer(peerId);
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

            // Wenn Pfad leer ist, zurück zum Root-Namen
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
                currentPathStr = item.fullPath; // Das ist der virtuelle Pfad (CustomName/...)
                renderLocalGrid(getMappedLocalItems(currentPathStr));

                const crumbs = currentPathStr.split('/').filter(Boolean);
                updateBreadcrumbs(['ROOT', ...crumbs]);
            };
        } else {
            el.onclick = () => {
                // Echte Datei finden über Mapping
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

        // FREEZE VALUE for closure
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


// --- HELPER: PATH MAPPING (DAS IST DER FIX FÜR EMPTY FOLDERS) ---

// Wandelt "CustomName/Sub" in "RealName/Sub" um
function mapVirtualToReal(virtualPath) {
    if (!virtualPath) return "";
    if (myRootFolderName && myRealRootName && virtualPath.startsWith(myRootFolderName)) {
        return virtualPath.replace(myRootFolderName, myRealRootName);
    }
    return virtualPath;
}

// Wandelt "RealName/Sub" in "CustomName/Sub" um
function mapRealToVirtual(realPath) {
    if (!realPath) return "";
    if (myRootFolderName && myRealRootName && realPath.startsWith(myRealRootName)) {
        return realPath.replace(myRealRootName, myRootFolderName);
    }
    return realPath;
}

// Liefert Items für das lokale Grid basierend auf virtuellem Pfad (Custom Name)
function getMappedLocalItems(virtualPath) {
    // 1. Suchepfad übersetzen (Custom -> Real)
    const realSearchPath = mapVirtualToReal(virtualPath);

    // 2. Items suchen (mit echten Pfaden)
    const rawItems = getItemsInPath(myHostedFiles, realSearchPath);

    // 3. Ergebnis-Pfade zurückübersetzen (Real -> Custom) für die Anzeige
    return rawItems.map(item => {
        return {
            ...item,
            fullPath: mapRealToVirtual(item.fullPath)
        };
    });
}

// --- P2P CONNECTION LOGIC ---

async function connectToPeer(targetId) {
    if (peers[targetId]) {
        if(peers[targetId].connection) peers[targetId].connection.close();
        delete peers[targetId];
    }
    console.log(`Starting connection to ${targetId}...`);

    const pc = new RTCPeerConnection(iceConfig);
    const channel = pc.createDataChannel("fileSystem");
    let iceQueue = [];
    let offerSent = false;

    setupChannelHandlers(channel, targetId);

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
            setupChannelHandlers(channel, senderId);
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

function setupChannelHandlers(channel, peerId) {
    channel.onopen = () => {
        console.log(`CHANNEL OPENED with ${peerId}`);
        // PW mitsenden!
        const pw = peers[peerId]?.authPassword || null;
        channel.send(JSON.stringify({ type: 'REQUEST_ROOT', password: pw }));
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
        // PASSWORD CHECK
        if (myMountPassword && msg.password !== myMountPassword) {
            channel.send(JSON.stringify({ type: 'ERROR', message: 'ACCESS DENIED: WRONG PASSWORD' }));
            return;
        }

        // Mapped Root items senden
        const items = getMappedLocalItems(myRootFolderName);
        sendLargeJSON(channel, 'RESPONSE_DIRECTORY', { items: items, path: myRootFolderName });
    }

    if (msg.type === 'REQUEST_DIRECTORY') {
        // Mapped items senden
        const items = getMappedLocalItems(msg.path);
        sendLargeJSON(channel, 'RESPONSE_DIRECTORY', { items: items, path: msg.path });
    }

    if (msg.type === 'REQUEST_DOWNLOAD') {
        // 1. Virtuellen Pfad (CustomName) in Echten Pfad (RealName) wandeln
        const realPath = mapVirtualToReal(msg.filename);

        let file = myHostedFiles.find(f => f.webkitRelativePath === realPath);
        // Fallback Name Check
        if(!file) file = myHostedFiles.find(f => f.name === msg.filename.split('/').pop());

        if (file) streamFileToPeer(file, channel);
        else {
            channel.send(JSON.stringify({ type: 'ERROR', message: 'File not found.' }));
        }
    }

    if (msg.type === 'REQUEST_RECURSIVE_LIST') {
        const realSearchPath = mapVirtualToReal(msg.path);
        const files = getAllFilesInPathRecursive(myHostedFiles, realSearchPath);

        // Wir müssen dem Client die virtuellen Pfade zurückgeben!
        const list = files.map(f => {
            const virtualFull = mapRealToVirtual(f.webkitRelativePath);
            // Relativer Pfad im Zip: Wenn wir Ordner "X" laden, und Datei ist "X/Y/Z", wollen wir "Y/Z"
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
            // Wenn wir noch beim Verbinden sind (Grid zeigt loading), dann dort anzeigen
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
                let p = msg.filename; // filename ist hier der volle virtuelle Pfad
                // Wir müssen ihn relativ zum Zip Root machen, aber das passiert jetzt schon im Host Mapping
                // Warte: Host sendet fullPath als filename.
                // Client hat zipQueue objects mit relativePath.
                // Wir sollten processZipQueue anpassen, um relativePath zu nutzen?
                // Einfacher: Host schickt nur Rohdaten. Client muss wissen wo es hin gehört.
                // Workaround: Wir speichern den aktuellen Zip-File-Namen global? Nein async.

                // Besserer Fix: Host sendet in msg NICHT NUR filename, sondern auch Metadaten?
                // Oder wir nutzen den currentPathStr Logik hier.

                // Simple logic:
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

    // FIX: Pfad sauber bauen
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

    // FIX: Pfad + Dateiname
    const parts = currentPathStr ? currentPathStr.split('/') : [];
    updateBreadcrumbs(['ROOT', ...parts, item.name]);
}

function closePreview() {
    document.getElementById('filePreview').style.display = 'none';
    document.getElementById('fileGrid').style.display = 'grid';
    incomingFileBuffer = [];

    // FIX: Zurück zum Ordner-Pfad (ohne Dateiname)
    const parts = currentPathStr ? currentPathStr.split('/') : [];
    updateBreadcrumbs(['ROOT', ...parts]);
}

function updateBreadcrumbs(pathArray) {
    const bar = document.getElementById('breadcrumbs');
    bar.innerHTML = '';

    let accumulatedPath = "";

    pathArray.forEach((crumb, index) => {
        // Pfad bauen
        if (index > 0) {
            accumulatedPath = accumulatedPath ? `${accumulatedPath}/${crumb}` : crumb;
        }

        // WICHTIG: Den aktuellen Stand des Pfades für DIESEN Klick einfrieren!
        const pathToThisCrumb = accumulatedPath;

        const span = document.createElement('span');
        span.className = 'crumb';
        span.textContent = crumb;

        // Klickbar machen (außer der letzte Eintrag)
        if (index < pathArray.length - 1) {
            span.style.cursor = "pointer";
            span.onclick = () => {
                // 1. ANSICHT ZURÜCKSETZEN
                document.getElementById('filePreview').style.display = 'none';
                document.getElementById('fileGrid').style.display = 'grid';
                isPreviewMode = false;
                incomingFileBuffer = [];

                // 2. NAVIGIEREN
                if (index === 0) {
                    // ROOT Klick
                    if (currentActivePeerId && currentActivePeerId !== socket.id) {
                        navigateRemote("", currentActivePeerId);
                    } else {
                        currentPathStr = "";
                        renderLocalGrid(getItemsInPath(myHostedFiles, ""));
                        updateBreadcrumbs(['ROOT']);
                    }
                } else {
                    // ORDNER Klick (Nutzt jetzt die eingefrorene Variable!)
                    if (currentActivePeerId && currentActivePeerId !== socket.id) {
                        navigateRemote(pathToThisCrumb, currentActivePeerId);
                    } else {
                        currentPathStr = pathToThisCrumb;

                        // Inhalt laden
                        const items = getItemsInPath(myHostedFiles, currentPathStr);
                        if(items.length === 0 && currentPathStr !== "") {
                            // Fallback, falls Pfad ungültig
                            console.warn("Path fallback trigger");
                            currentPathStr = "";
                            renderLocalGrid(getItemsInPath(myHostedFiles, ""));
                            updateBreadcrumbs(['ROOT']);
                            return;
                        }
                        renderLocalGrid(items);

                        // Breadcrumbs neu zeichnen (alles rechts vom Klick abschneiden)
                        const newCrumbs = pathArray.slice(0, index + 1);
                        updateBreadcrumbs(newCrumbs);
                    }
                }
            };
        } else {
            // Letztes Element (aktueller Ort)
            span.style.color = "#fff";
            span.style.cursor = "default";
        }

        bar.appendChild(span);

        if(index < pathArray.length - 1) {
            const sep = document.createElement('span');
            sep.className = 'separator';
            sep.textContent = '>';
            bar.appendChild(sep);
        }
    });
}

// Ersetzte renderSidebar, um Schloss-Icon und Passwort-Check einzubauen
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
        const isLocked = item.isProtected && !isMe; // Eigene Ordner brauchen kein PW

        const li = document.createElement('li');
        li.className = 'share-item';
        if(isMe) li.style.cssText = 'color:#0f0; border-left:4px solid #0f0;';

        // Anzeige mit Schloss, falls nötig
        const lockIcon = isLocked ? '🔒 ' : '';
        li.innerHTML = `<span class="share-name">${lockIcon}${isMe ? item.folderName + ' (LOCAL)' : item.folderName}</span><span class="share-user">${isMe ? 'HOSTED BY YOU' : item.username}</span>`;

        li.onclick = () => {
            // UI Reset
            document.querySelectorAll('.share-item').forEach(el => el.classList.remove('active'));
            li.classList.add('active');

            if (isMe) {
                // Lokal öffnen (wie bisher)
                document.getElementById('filePreview').style.display = 'none';
                document.getElementById('fileGrid').style.display = 'grid';
                currentActivePeerId = socketId;
                currentPathStr = item.folderName;
                renderLocalGrid(getItemsInPath(myHostedFiles, currentPathStr));
                updateBreadcrumbs(['ROOT', item.folderName]);
            } else {
                // Remote öffnen
                if (item.isProtected) {
                    // Passwort abfragen!
                    targetPeerForPassword = socketId;
                    document.getElementById('passwordModal').style.display = 'flex';
                    document.getElementById('accessPassword').focus();
                } else {
                    // Direkt verbinden (Kein Passwort)
                    initiateConnectionWithPassword(socketId, null);
                }
            }
        };
        list.appendChild(li);
    });
}

// Neue Funktion, die connectToPeer aufruft und PW speichert
function initiateConnectionWithPassword(peerId, password) {
    document.getElementById('filePreview').style.display = 'none';
    document.getElementById('fileGrid').style.display = 'grid';
    document.getElementById('fileGrid').innerHTML = '<div style="color:#0f0; text-align:center; margin-top:50px;">AUTHENTICATING P2P UPLINK...</div>';
    currentActivePeerId = peerId;

    // Wir speichern das Passwort temporär im Peer-Objekt,
    // damit wir es senden können, sobald der Channel offen ist.
    if(!peers[peerId]) peers[peerId] = {};
    peers[peerId].authPassword = password; // Speichern für Handshake

    connectToPeer(peerId);
}

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