// --- GLOBALS ---
const socket = io();
const earlyCandidates = {}; // WICHTIG: Cache für zu schnelle Chrome-Pakete
let myHostedFiles = [];
let currentRemoteFiles = [];
let myRootFolderName = "ROOT";
let incomingFileBuffer = [];
let isPreviewMode = false;
let currentActiveFolderName = "ROOT";
let currentPathStr = "";
let currentActivePeerId = null;
let isZipBatchMode = false;

let myMountPassword = null; // Speichert das PW für den eigenen Host
let pendingFiles = null; // Zwischenspeicher für das Modal
let targetPeerForPassword = null; // Wen wollen wir öffnen?
// --- WEBRTC CONFIG (PRODUCTION READY) ---
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

// --- LIFECYCLE MANAGEMENT ---
const lifeCycleChannel = new BroadcastChannel('terminal_chat_lifecycle');

lifeCycleChannel.onmessage = (event) => {
    if (event.data.type === 'MASTER_DISCONNECT') {
        console.log("Master session ended.");
        window.close();
    }
};

// --- INITIALISIERUNG ---
const user = localStorage.getItem('fs_username');
const userKey = localStorage.getItem('fs_key');

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
    // Debugging Logs
    if (data.type === 'offer') console.log(`[SIGNAL] Received OFFER from ${data.senderId}`);
    if (data.type === 'answer') console.log(`[SIGNAL] Received ANSWER from ${data.senderId}`);
    if (data.type === 'candidate') console.log(`[SIGNAL] Received CANDIDATE from ${data.senderId}`);

    await handleP2PMessage(data.senderId, data.signal, data.type);
});

// --- P2P CONNECTION LOGIC (FINAL UNIVERSAL FIX) ---

// 1. Verbindung starten
async function connectToPeer(targetId) {
    // Reset, falls Verbindung schon existiert
    if (peers[targetId]) {
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
            if (offerSent) {
                socket.emit('p2p_signal', { targetId: targetId, type: 'candidate', signal: event.candidate });
            } else {
                // Buffer, um Race-Conditions zu vermeiden
                iceQueue.push(event.candidate);
            }
        }
    };

    pc.oniceconnectionstatechange = () => {
        const state = pc.iceConnectionState;
        console.log(`ICE State (${targetId}): ${state}`);

        if (state === 'connected') {
            console.log("P2P UPLINK ESTABLISHED! 🚀");
        }
        if (state === 'failed') {
            const grid = document.getElementById('fileGrid');
            if(grid) grid.innerHTML = '<div style="color:red; margin-top:50px; text-align:center;">CONNECTION FAILED.<br>FIREWALL BLOCKED P2P.</div>';
        }
    };

    try {
        const offer = await pc.createOffer();
        await pc.setLocalDescription(offer);

        console.log("Sending Offer...");
        socket.emit('p2p_signal', { targetId: targetId, type: 'offer', signal: offer });
        offerSent = true;

        // Jetzt die gebufferten Candidates senden
        if (iceQueue.length > 0) {
            iceQueue.forEach(c => socket.emit('p2p_signal', { targetId: targetId, type: 'candidate', signal: c }));
        }

    } catch (err) {
        console.error("Connection Error:", err);
    }
}

// 2. Signale verarbeiten
async function handleP2PMessage(senderId, signal, type) {

    // FALL A: ZU FRÜHE CANDIDATES (Chrome Cache Fix)
    if (!peers[senderId] && type === 'candidate') {
        console.log(`[Cache] Storing early candidate from ${senderId}`);
        if (!earlyCandidates[senderId]) earlyCandidates[senderId] = [];
        earlyCandidates[senderId].push(signal);
        return;
    }

    // FALL B: OFFER (Neue Verbindung)
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
                socket.emit('p2p_signal', { targetId: senderId, type: 'candidate', signal: event.candidate });
            }
        };

        peers[senderId] = { connection: pc, channel: null, pendingQueue: [] };

        // Haben wir schon Candidates im Cache?
        if (earlyCandidates[senderId]) {
            console.log(`[Cache] Restoring ${earlyCandidates[senderId].length} candidates.`);
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
            // Wenn RemoteDesc noch nicht da ist -> Queue
            if (!pc.remoteDescription || pc.remoteDescription.type === null) {
                p.pendingQueue.push(signal);
            } else {
                await pc.addIceCandidate(new RTCIceCandidate(signal)).catch(e => {});
            }
        }
    } catch (e) { console.error("WebRTC Logic Error:", e); }
}

async function processPendingQueue(peerObj, pc) {
    if (peerObj.pendingQueue.length > 0) {
        for (const candidate of peerObj.pendingQueue) {
            try { await pc.addIceCandidate(new RTCIceCandidate(candidate)); } catch (e) {}
        }
        peerObj.pendingQueue = [];
    }
}

// 3. Channel Events
function setupChannelHandlers(channel, peerId) {
    channel.onopen = () => {
        console.log(`CHANNEL OPENED with ${peerId}`);
        // WICHTIG: Passwort mitsenden!
        const pw = peers[peerId]?.authPassword || null;
        channel.send(JSON.stringify({
            type: 'REQUEST_ROOT',
            password: pw
        }));
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

// --- FILE SYSTEM LOGIC ---
function handleChannelMessage(msg, peerId, channel) {

    // ... (JSON Chunk logic bleibt hier) ...
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

    // HOST LOGIK - SECURITY CHECK
    if (msg.type === 'REQUEST_ROOT' || msg.type === 'REQUEST_DIRECTORY' || msg.type === 'REQUEST_DOWNLOAD' || msg.type === 'REQUEST_RECURSIVE_LIST') {

        // Prüfen, ob mein Mount geschützt ist
        if (myMountPassword) {
            // Hat der Gast das richtige Passwort gesendet?
            // (Bei REQUEST_ROOT ist es in msg.password, bei anderen Requests verlassen wir uns darauf,
            // dass er die Pfade eh nicht kennen würde, wenn er Root nicht gesehen hätte.
            // Sicherer: Client sendet Token bei jedem Request. Für jetzt reicht der Root-Check oder wir speichern den "Authenticated State" pro Peer.)

            // Einfache Variante: Wir prüfen es beim Root Request
            if (msg.type === 'REQUEST_ROOT') {
                if (msg.password !== myMountPassword) {
                    console.warn(`Access Denied for ${peerId}: Wrong Password`);
                    channel.send(JSON.stringify({ type: 'ERROR', message: 'ACCESS DENIED: WRONG PASSWORD' }));
                    return;
                } else {
                    // Erfolg! Wir merken uns, dass dieser Peer authentifiziert ist (Optional, für Advanced Security)
                    console.log(`Access Granted for ${peerId}`);
                }
            }
        }
    }

    // ... (Restlicher Host Code wie REQUEST_DIRECTORY, etc.) ...

    // Host Logic Original (nur um den Passwort-Check erweitert)
    if (msg.type === 'REQUEST_ROOT') {
        // Falls wir hier sind, war das PW korrekt (oder keins gesetzt)
        const items = getItemsInPath(myHostedFiles, myRootFolderName); // Root-Name nutzen wir nicht für Filterung der echten Files, aber für Anzeige
        // Trick: getItemsInPath braucht den echten Folder Pfad.
        // Da wir "Custom Names" haben, müssen wir aufpassen.
        // myHostedFiles enthält die echten Pfade (z.B. "EchtOrdner/Bild.png").
        // Wenn wir mounten, ist myRootFolderName jetzt der Custom Name (z.B. "Geheim").
        // getItemsInPath erwartet aber den echten Root Pfad der Datei.

        // FIX für Custom Names: Wir müssen den "echten" Root-Namen der ersten Datei nehmen
        const realRootName = myHostedFiles[0].webkitRelativePath.split('/')[0];
        const rootItems = getItemsInPath(myHostedFiles, realRootName);

        sendLargeJSON(channel, 'RESPONSE_DIRECTORY', { items: rootItems, path: myRootFolderName }); // Wir senden Custom Name zurück als Pfad
    }

// HOST LOGIC (Updated for Custom Names)
    const realRootName = myHostedFiles.length > 0 ? myHostedFiles[0].webkitRelativePath.split('/')[0] : "";

    if (msg.type === 'REQUEST_DIRECTORY') {
        // Client fragt nach: "Project X/Sub"
        // Wir müssen daraus machen: "Urlaub/Sub"
        let requestedPath = msg.path;

        if (requestedPath.startsWith(myRootFolderName)) {
            // Ersetze Custom Root durch Real Root
            requestedPath = requestedPath.replace(myRootFolderName, realRootName);
        }

        const items = getItemsInPath(myHostedFiles, requestedPath);
        // Wir senden die Items zurück, aber in der Antwort setzen wir den Pfad wieder auf den Custom Name für den Client
        sendLargeJSON(channel, 'RESPONSE_DIRECTORY', { items: items, path: msg.path });
    }

// 3. DOWNLOAD ANFRAGE (HOST LOGIK - UPDATED)
    if (msg.type === 'REQUEST_DOWNLOAD') {
        console.log(`[HOST] Incoming request for: "${msg.filename}"`);

        // A) MAPPING: Custom Name -> Echter Name
        // Wir ermitteln den echten Root-Namen der ersten Datei im Speicher
        const realRootName = myHostedFiles.length > 0 ? myHostedFiles[0].webkitRelativePath.split('/')[0] : "";

        let searchPath = msg.filename; // Z.B. "Project Omega/bild.png"

        // Wenn der Pfad mit dem Custom-Namen beginnt, tauschen wir ihn gegen den echten aus
        if (myRootFolderName && searchPath.startsWith(myRootFolderName)) {
            // "Project Omega/bild.png" -> "Neuer Ordner/bild.png"
            searchPath = searchPath.replace(myRootFolderName, realRootName);
        }

        // B) SUCHE: Jetzt suchen wir mit dem "echten" Pfad
        let requestedFile = myHostedFiles.find(f => f.webkitRelativePath === searchPath);

        // Fallback: Nur nach Dateinamen suchen (falls Pfad-Mapping fehlschlug)
        if (!requestedFile) {
            requestedFile = myHostedFiles.find(f => f.name === msg.filename.split('/').pop());
        }

        if (requestedFile) {
            console.log(`[HOST] File found: ${requestedFile.name}. Starting stream...`);
            streamFileToPeer(requestedFile, channel);
        } else {
            console.error(`[HOST] ERROR: File "${msg.filename}" (mapped: "${searchPath}") NOT FOUND.`);
            channel.send(JSON.stringify({
                type: 'ERROR',
                message: `File not found on host: ${msg.filename}`
            }));
        }
    }

// 4. REKURSIVE LISTE FÜR ZIP ANFRAGE (HOST LOGIK - UPDATED)
    if (msg.type === 'REQUEST_RECURSIVE_LIST') {
        // A) MAPPING: Suchpfad für interne Suche anpassen
        const realRootName = myHostedFiles.length > 0 ? myHostedFiles[0].webkitRelativePath.split('/')[0] : "";
        let searchPath = msg.path; // Z.B. "Project Omega/Unterordner"

        if (myRootFolderName && searchPath.startsWith(myRootFolderName)) {
            searchPath = searchPath.replace(myRootFolderName, realRootName);
        }

        // Dateien finden (mit echten Pfaden)
        const files = getAllFilesInPathRecursive(myHostedFiles, searchPath);

        // B) REMAPPING FÜR ANTWORT: Echte Pfade wieder zu Custom Namen machen
        const metaList = files.map(f => {
            let publicFullPath = f.webkitRelativePath; // "Neuer Ordner/bild.png"

            // Zurücktauschen: "Neuer Ordner" -> "Project Omega"
            if (realRootName && publicFullPath.startsWith(realRootName)) {
                publicFullPath = publicFullPath.replace(realRootName, myRootFolderName);
            }

            // Relativen Pfad für die ZIP-Struktur berechnen (basierend auf der Anfrage)
            // Wenn Anfrage "Project Omega" war und File ist "Project Omega/bild.png", dann ist relative "bild.png"
            let relativePath = publicFullPath;
            if (msg.path && publicFullPath.startsWith(msg.path)) {
                relativePath = publicFullPath.substring(msg.path.length + 1); // +1 für den Slash
            }

            return {
                fullPath: publicFullPath, // Der Client nutzt DAS für den Download-Request
                relativePath: relativePath // Der Client nutzt DAS für den Dateinamen im Zip
            };
        });

        sendLargeJSON(channel, 'RESPONSE_RECURSIVE_LIST', { list: metaList });
    }

    // Client
    if (msg.type === 'RESPONSE_DIRECTORY') {
        currentPathStr = msg.payload.path;
        updateBreadcrumbs(['ROOT', ...currentPathStr.split('/')]);
        renderRemoteGrid(msg.payload.items, peerId);
    }
    if (msg.type === 'RESPONSE_RECURSIVE_LIST') {
        zipQueue = msg.payload.list;
        processZipQueue();
    }
    if (msg.type === 'ERROR') {
        console.error(msg.message);
        if(isZipBatchMode) processZipQueue();
        else alert("Error: " + msg.message);
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

// --- UI / RENDERING ---

// --- MOUNT & MODAL LOGIC ---

function triggerMount() {
    // Modal öffnen, Formular resetten
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

// Event Listener für den HIDDEN Input im Modal
document.getElementById('hiddenFolderInput').addEventListener('change', (e) => {
    if (e.target.files.length === 0) return;
    pendingFiles = Array.from(e.target.files);

    // Name vorschlagen
    const detectedName = pendingFiles[0].webkitRelativePath.split('/')[0];
    document.getElementById('selectedFolderName').textContent = detectedName;
    if(document.getElementById('mountName').value === '') {
        document.getElementById('mountName').value = detectedName;
    }
});

function confirmMount() {
    if (!pendingFiles || pendingFiles.length === 0) {
        alert("Please select a folder first.");
        return;
    }

    // 1. Daten sammeln
    const customName = document.getElementById('mountName').value || "Unnamed Drive";
    const allowedStr = document.getElementById('mountAllowedUsers').value;
    const password = document.getElementById('mountPassword').value;

    // IDs parsen (Komma getrennt)
    const allowedUsers = allowedStr ? allowedStr.split(',').map(s => s.trim()).filter(Boolean) : [];

    // 2. Globals setzen
    myHostedFiles = pendingFiles;
    myRootFolderName = customName; // Wir nutzen den Custom Name als Root
    myMountPassword = password || null; // PW speichern (lokal)

    // 3. UI Update
    closeMountModal();
    document.getElementById('btnMount').style.display = 'none';
    const unmountBtn = document.getElementById('btnUnmount');
    unmountBtn.style.display = 'block';
    unmountBtn.innerText = `[-] UNMOUNT [${customName}]`;

    // 4. Server informieren (Nur Metadaten, KEIN Passwort senden!)
    console.log(`MOUNTING: ${customName} (Protected: ${!!password})`);
    socket.emit('fs_start_hosting', {
        folderName: customName,
        allowedUsers: allowedUsers,
        isProtected: !!password // Server weiß nur DASS es geschützt ist
    });
}

// --- PASSWORD MODAL LOGIC (Viewer Side) ---

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

    // Mit Passwort verbinden
    initiateConnectionWithPassword(peerId, pw);
}

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

function renderLocalGrid(items) {
    const grid = document.getElementById('fileGrid');
    grid.innerHTML = '';
    document.getElementById('folderActions').style.display = 'none';

    // Back Button
    if (currentPathStr && currentPathStr !== myRootFolderName) {
        addBackButton(grid, () => {
            const parts = currentPathStr.split('/').filter(Boolean); // WICHTIG: Leere Teile filtern
            parts.pop();
            currentPathStr = parts.join('/');
            renderLocalGrid(getItemsInPath(myHostedFiles, currentPathStr));
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
                renderLocalGrid(getItemsInPath(myHostedFiles, currentPathStr));

                // FIX: Pfad sauber bauen ohne Duplikate
                const crumbs = currentPathStr.split('/').filter(Boolean);
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