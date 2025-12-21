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
const knownPasswords = {}; // NEU: Speichert Passwörter für diese Session

let latestSharesList = {};

// NEU: Für Edit-Mode
let myAllowedUsers = [];
let isEditMode = false;
let isSingleFileGlobal = false; // Wir merken uns das Flag global

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
    // 1. Daten global speichern
    latestSharesList = sharesList;

    // 2. Sicherheits-Check (wie vorher)
    if (currentActivePeerId && !sharesList[currentActivePeerId]) {
        closePreview();
        document.getElementById('fileGrid').innerHTML = '<div class="empty-state" style="color:red;">&lt; HOST DISCONNECTED &gt;</div>';
        currentActivePeerId = null;
        updateBreadcrumbs(['ROOT']);
    }

    // 3. Rendern (nutzt jetzt die globale Liste + Suchfilter)
    renderSidebar();
});

// NEU: Event Listener für die Suche
document.getElementById('driveSearch').addEventListener('input', () => {
    renderSidebar(); // Neu rendern bei jedem Tastendruck
});

socket.on('p2p_signal', async (data) => {
    await handleP2PMessage(data.senderId, data.signal, data.type);
});

// --- MOUNT MODAL LOGIC ---

function triggerMount() {
    isEditMode = false; // Wir mounten neu
    document.getElementById('mountModal').style.display = 'flex';
    document.getElementById('modalTitle').innerText = "MOUNT CONFIGURATION";
    document.getElementById('fileSelectionArea').style.display = 'flex'; // Datei-Wahl anzeigen
    document.getElementById('btnConfirmMount').innerText = "[ MOUNT DRIVE ]";

    // Reset Fields
    document.getElementById('mountName').value = '';
    document.getElementById('mountAllowedUsers').value = '';
    document.getElementById('mountPassword').value = '';
    document.getElementById('selectedFolderName').textContent = 'No content selected';
    pendingFiles = null;
}

function triggerEdit() {
    isEditMode = true; // Wir editieren nur
    document.getElementById('mountModal').style.display = 'flex';
    document.getElementById('modalTitle').innerText = "EDIT CONFIGURATION";
    document.getElementById('fileSelectionArea').style.display = 'none'; // Datei-Wahl ausblenden
    document.getElementById('btnConfirmMount').innerText = "[ PUBLISH EDITS ]";

    // Felder mit aktuellen Werten füllen
    document.getElementById('mountName').value = myRootFolderName;
    document.getElementById('mountAllowedUsers').value = myAllowedUsers.join(', ');
    // Passwort füllen (oder leer lassen, sicherheitshalber leer lassen oder Platzhalter)
    document.getElementById('mountPassword').value = myMountPassword || "";
}

function closeMountModal() {
    document.getElementById('mountModal').style.display = 'none';
    pendingFiles = null;
    isEditMode = false;
}

// Hidden Input Change Listener
const hiddenInput = document.getElementById('hiddenFolderInput');
if(hiddenInput) {
    hiddenInput.addEventListener('change', (e) => {
        if (e.target.files.length === 0) return;
        pendingFiles = Array.from(e.target.files);

        // Root-Ordnernamen ermitteln
        const rootName = pendingFiles[0].webkitRelativePath.split('/')[0];

        // HINWEIS: Browser verbieten den Zugriff auf den absoluten Pfad (C:/...).
        // Stattdessen zeigen wir jetzt technische Details (Typ + Anzahl) an:
        document.getElementById('selectedFolderName').textContent = `📂 /${rootName}/ [${pendingFiles.length} FILES DETECTED]`;
        document.getElementById('selectedFolderName').style.color = "#0f0"; // Hacker-Grün
        document.getElementById('selectedFolderName').style.fontFamily = "monospace";

        // Name vorschlagen, falls leer
        if(document.getElementById('mountName').value === '') {
            document.getElementById('mountName').value = rootName;
        }
    });
}

function confirmMount() {
    // FALL 1: NEUER MOUNT (Dateien müssen gewählt sein)
    if (!isEditMode) {
        if (!pendingFiles || pendingFiles.length === 0) {
            alert("Please select a folder or file first.");
            return;
        }
        // Daten aus Input übernehmen
        myHostedFiles = pendingFiles;

        // Check: Single File?
        isSingleFileGlobal = pendingFiles.length === 1 && (!pendingFiles[0].webkitRelativePath || pendingFiles[0].webkitRelativePath === "");

        // Real Root setzen
        myRealRootName = isSingleFileGlobal ? "" : pendingFiles[0].webkitRelativePath.split('/')[0];
    }

    // FALL 2: EDIT MODE (Dateien bleiben gleich, wir lesen sie NICHT neu ein)
    // Wir nutzen einfach die existierenden `myHostedFiles`, `myRealRootName` und `isSingleFileGlobal` weiter.

    // GEMEINSAME LOGIK (Daten aus Formular lesen)
    const customName = document.getElementById('mountName').value || "Unnamed Drive";
    const allowedStr = document.getElementById('mountAllowedUsers').value;
    const password = document.getElementById('mountPassword').value;

    // Globals updaten
    myAllowedUsers = allowedStr ? allowedStr.split(',').map(s => s.trim()).filter(Boolean) : [];
    myRootFolderName = customName;
    myMountPassword = password || null;

    console.log(`[${isEditMode ? 'EDIT' : 'MOUNT'}] Name: "${customName}" | Protected: ${!!password}`);

    closeMountModal();

    // UI Buttons Update
    document.getElementById('btnMount').style.display = 'none';
    const unmountBtn = document.getElementById('btnUnmount');
    const editBtn = document.getElementById('btnEdit'); // Den neuen Button holen

    unmountBtn.style.display = 'block';
    unmountBtn.innerText = `[-] UNMOUNT`;

    editBtn.style.display = 'block'; // Edit Button anzeigen

    // UI Reset (Nur bei neuem Mount nötig, aber schadet bei Edit nicht, um Namen zu refreshen)
    if (!isEditMode) {
        document.getElementById('filePreview').style.display = 'none';
        document.getElementById('fileGrid').style.display = 'grid';
        document.getElementById('fileGrid').innerHTML = '';
        incomingFileBuffer = [];
        isPreviewMode = false;
        currentActivePeerId = socket.id;
    }

    // Breadcrumbs & Title update (falls wir gerade im eigenen Ordner sind)
    if (currentActivePeerId === socket.id) {
        currentPathStr = customName;
        document.querySelectorAll('.share-item').forEach(el => el.classList.remove('active'));

        if (isSingleFileGlobal) {
            openFile(myHostedFiles[0]);
        } else {
            const items = getMappedLocalItems(currentPathStr);
            renderLocalGrid(items);
            updateBreadcrumbs(['ROOT', customName]);
        }
    }

    // SERVER UPDATE SENDEN
    // Der Server überschreibt einfach die Daten für unseren Socket -> Perfektes Update
    socket.emit('fs_start_hosting', {
        folderName: customName,
        username: user,
        allowedUsers: myAllowedUsers,
        isProtected: !!password,
        isSingleFile: isSingleFileGlobal
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

    // NEU: Passwort für die Zukunft speichern
    knownPasswords[peerId] = pw;

    initiateConnectionWithPassword(peerId, pw);
}

// --- UI LOGIC ---

function renderSidebar(shares) {
    const dataToRender = shares || latestSharesList;
    latestSharesList = dataToRender;

    const list = document.getElementById('shareList');
    list.innerHTML = '';

    const searchTerm = document.getElementById('driveSearch').value.toLowerCase();
    const allIds = Object.keys(dataToRender);

    const filteredIds = allIds.filter(id => {
        const item = dataToRender[id];
        return item.folderName.toLowerCase().includes(searchTerm) ||
            item.username.toLowerCase().includes(searchTerm) ||
            id.toLowerCase().includes(searchTerm);
    });

    if (filteredIds.length === 0) {
        list.innerHTML = '<li style="padding:15px; color:#555; text-align:center;">No matches found.</li>';
        return;
    }

    filteredIds.forEach(socketId => {
        const item = dataToRender[socketId];
        const isMe = (socketId === socket.id);
        const isLocked = item.isProtected && !isMe;

        const li = document.createElement('li');
        li.className = 'share-item';
        if (socketId === currentActivePeerId) li.classList.add('active');
        if (isMe) li.style.cssText += 'color:#0f0; border-left:4px solid #0f0;';

        const lockIcon = isLocked ? '🔒 ' : '';
        const typeIcon = item.isSingleFile ? '📄 ' : '📁 ';
        const idDisplay = `<span style="font-size:0.7em; color:#444;">[ID: ${socketId.substr(0,5)}]</span>`;

        li.innerHTML = `
            <span class="share-name">${lockIcon}${typeIcon}${isMe ? item.folderName + ' (LOCAL)' : item.folderName}</span>
            <span class="share-user">${isMe ? 'HOSTED BY YOU' : item.username} ${idDisplay}</span>
        `;

        li.onclick = () => {
            document.querySelectorAll('.share-item').forEach(el => el.classList.remove('active'));
            li.classList.add('active');

            if (isMe) {
                // LOCAL LOGIC
                currentActivePeerId = socketId;
                currentPathStr = item.folderName;

                if (item.isSingleFile) {
                    // DIREKT ÖFFNEN (Lokal)
                    // Bei SingleFile ist myHostedFiles[0] die Datei
                    openFile(myHostedFiles[0]);
                } else {
                    // ORDNER ÖFFNEN
                    document.getElementById('filePreview').style.display = 'none';
                    document.getElementById('fileGrid').style.display = 'grid';
                    renderLocalGrid(getMappedLocalItems(currentPathStr));
                    updateBreadcrumbs(['ROOT', item.folderName]);
                }
            } else {
                // REMOTE LOGIC
                // Wir übergeben jetzt das ganze Item, damit wir wissen ob es ein SingleFile ist
                if (item.isProtected) {
                    if (knownPasswords[socketId]) {
                        initiateConnectionWithPassword(socketId, knownPasswords[socketId], item);
                    } else {
                        targetPeerForPassword = socketId;
                        // Zwischenspeichern des Items für später (nach Passworteingabe)
                        peers[socketId] = { ...peers[socketId], pendingItemInfo: item };
                        document.getElementById('passwordModal').style.display = 'flex';
                        document.getElementById('accessPassword').focus();
                    }
                } else {
                    initiateConnectionWithPassword(socketId, null, item);
                }
            }
        };
        list.appendChild(li);
    });
}

// Signatur geändert: itemInfo hinzugefügt
function initiateConnectionWithPassword(peerId, password, itemInfo = null) {
    currentActivePeerId = peerId;

    if (!itemInfo && peers[peerId]?.pendingItemInfo) {
        itemInfo = peers[peerId].pendingItemInfo;
    }

    if(password) knownPasswords[peerId] = password;
    const finalPassword = password || knownPasswords[peerId];

    // Infos ermitteln
    const isSingle = itemInfo ? itemInfo.isSingleFile : false;
    const targetName = itemInfo ? itemInfo.folderName : "";

    // UI vorbereiten
    if (isSingle) {
        document.getElementById('fileGrid').style.display = 'none';
        document.getElementById('filePreview').style.display = 'flex';
        document.getElementById('previewFileName').textContent = targetName;
        document.getElementById('previewContent').innerHTML = '<div style="color:#0f0; text-align:center; margin-top:20%;">[ DIRECT LINK ]<br>Requesting Single File...</div>';
        isPreviewMode = true;
    } else {
        document.getElementById('filePreview').style.display = 'none';
        document.getElementById('fileGrid').style.display = 'grid';
        document.getElementById('fileGrid').innerHTML = '<div style="color:#0f0; text-align:center; margin-top:50px;">AUTHENTICATING...</div>';
        isPreviewMode = false;
    }

    // Reuse Connection Check
    const p = peers[peerId];
    if (p && p.channel && p.channel.readyState === 'open') {
        console.log("Reusing channel.");
        if (isSingle) {
            p.channel.send(JSON.stringify({
                type: 'REQUEST_DOWNLOAD',
                filename: targetName,
                password: finalPassword
            }));
        } else {
            p.channel.send(JSON.stringify({ type: 'REQUEST_ROOT', password: finalPassword }));
        }
        return;
    }

    // Neue Verbindung: Infos direkt übergeben!
    if(!peers[peerId]) peers[peerId] = {};
    peers[peerId].authPassword = finalPassword;

    // WICHTIG: Hier übergeben wir isSingle und targetName als Parameter!
    connectToPeer(peerId, finalPassword, isSingle, targetName);
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
                    if (currentActivePeerId && currentActivePeerId !== socket.id) {
                        navigateRemote("", currentActivePeerId);
                    } else {
                        currentPathStr = myRootFolderName;
                        renderLocalGrid(getMappedLocalItems(currentPathStr));
                        updateBreadcrumbs(['ROOT', myRootFolderName]);
                    }
                } else {
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

// --- HELPERS ---

function mapVirtualToReal(virtualPath) {
    if (!virtualPath) return "";

    // Wenn wir im Root des virtuellen Drives suchen (z.B. "MeinDrive")
    if (virtualPath === myRootFolderName) {
        return myRealRootName; // Gib "" zurück bei SingleFile oder "EchterOrdner" bei Ordnern
    }

    // Wenn wir in Unterordnern suchen (z.B. "MeinDrive/Sub")
    if (myRootFolderName && virtualPath.startsWith(myRootFolderName + '/')) {
        const relative = virtualPath.substring(myRootFolderName.length + 1);
        return myRealRootName ? `${myRealRootName}/${relative}` : relative;
    }
    return virtualPath;
}

function mapRealToVirtual(realPath) {
    if (!realPath && myRealRootName === "") return myRootFolderName; // Single File Root

    // Single File Fall: realPath ist "bild.png" -> Virtual: "MeinDrive/bild.png"
    if (myRealRootName === "") {
        return `${myRootFolderName}/${realPath}`;
    }

    // Ordner Fall
    if (realPath.startsWith(myRealRootName)) {
        return realPath.replace(myRealRootName, myRootFolderName);
    }
    return realPath;
}

function getMappedLocalItems(virtualPath) {
    const realSearchPath = mapVirtualToReal(virtualPath);
    const rawItems = getItemsInPath(myHostedFiles, realSearchPath);
    return rawItems.map(item => {
        return { ...item, fullPath: mapRealToVirtual(item.fullPath) };
    });
}

function renderRemoteBlob(blob, filename) {
    const contentDiv = document.getElementById('previewContent');
    contentDiv.innerHTML = '';

    const isImage = filename.match(/\.(jpeg|jpg|gif|png|webp|bmp|svg)$/i);

    if (isImage) {
        const url = URL.createObjectURL(blob);
        const img = document.createElement('img');
        img.src = url;
        img.style.maxWidth = '100%';
        img.style.maxHeight = '600px';
        img.style.border = '1px solid #0f0';
        contentDiv.appendChild(img);
    }
    else {
        if (blob.size > 2 * 1024 * 1024) {
            contentDiv.innerHTML = `<div style="color:orange; text-align:center; margin-top:20%;">[ FILE TOO LARGE FOR PREVIEW ]<br>Please use the [ SAVE TO DISK ] button above.</div>`;
            return;
        }

        const reader = new FileReader();
        reader.onload = (e) => {
            const pre = document.createElement('pre');
            pre.style.whiteSpace = 'pre-wrap';
            pre.style.wordBreak = 'break-word';
            pre.style.textAlign = 'left';
            pre.style.fontFamily = "'Courier New', monospace";
            pre.style.margin = '10px';
            pre.textContent = e.target.result;
            contentDiv.appendChild(pre);
        };
        reader.onerror = () => { contentDiv.innerHTML = '<div style="color:red">Error reading file content.</div>'; };
        reader.readAsText(blob);
    }
}

// --- P2P CONNECTION LOGIC ---

// Signatur geändert: isSingleFile und targetName hinzugefügt
async function connectToPeer(targetId, password = null, isSingleFile = false, targetName = "") {
    if (peers[targetId]) {
        if(peers[targetId].connection) peers[targetId].connection.close();
        delete peers[targetId];
    }
    console.log(`Starting connection to ${targetId}... (SingleFile: ${isSingleFile})`);

    const pc = new RTCPeerConnection(iceConfig);
    const channel = pc.createDataChannel("fileSystem");
    let iceQueue = [];
    let offerSent = false;

    // WICHTIG: Infos weiterreichen an setupChannelHandlers
    setupChannelHandlers(channel, targetId, password, isSingleFile, targetName);

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

// Signatur geändert: Infos hinzugefügt
function setupChannelHandlers(channel, peerId, password, isSingleFile, targetName) {
    channel.onopen = () => {
        console.log(`CHANNEL OPENED with ${peerId}`);

        // WICHTIG: Wir nutzen jetzt die Argumente der Funktion, nicht mehr das peers-Objekt!
        if (isSingleFile) {
            console.log("Requesting Direct Single File immediately...");
            channel.send(JSON.stringify({
                type: 'REQUEST_DOWNLOAD',
                filename: targetName,
                password: password
            }));
        } else {
            console.log("Requesting Directory Root...");
            channel.send(JSON.stringify({
                type: 'REQUEST_ROOT',
                password: password
            }));
        }
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
        let file = null;

        // SINGLE FILE FORCE MODE
        // Wenn wir exakt eine Datei hosten und der "Echte Root Name" leer ist (Kennzeichen für Single File),
        // dann senden wir IMMER diese eine Datei, egal was der Client angefordert hat.
        // Das löst alle Probleme mit unterschiedlichen Namen (Drive Name vs. Dateiname).
        if (myRealRootName === "" && myHostedFiles.length === 1) {
            console.log("[HOST] Single File Mode: Serving the only file available.");
            file = myHostedFiles[0];
        } else {
            // NORMALER ORDNER MODUS
            // 1. Pfad übersetzen (Virtual -> Real)
            const realPath = mapVirtualToReal(msg.filename);

            // 2. Datei suchen (Pfad oder Name)
            file = myHostedFiles.find(f => (f.webkitRelativePath || f.name) === realPath);

            // 3. Fallback: Nur nach Dateinamen suchen
            if (!file) {
                const requestedName = msg.filename.split('/').pop();
                file = myHostedFiles.find(f => f.name === requestedName);
            }
        }

        if (file) {
            console.log(`[HOST] Serving file: "${file.name}" to peer ${peerId}`);
            streamFileToPeer(file, channel);
        } else {
            console.error(`[HOST] File not found: "${msg.filename}"`);
            channel.send(JSON.stringify({ type: 'ERROR', message: 'File not found on host.' }));
        }
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
        // NEU: Wenn Passwort falsch war, müssen wir es löschen, damit User neu eingeben kann
        if (msg.message.includes('PASSWORD')) {
            delete knownPasswords[peerId]; // Passwort vergessen
            document.getElementById('fileGrid').innerHTML = `<div class="empty-state" style="color:red;">ACCESS DENIED: WRONG PASSWORD<br>Try again.</div>`;
            return;
        }

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

// --- HELPER FUNCTIONS ---
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

function getItemsInPath(files, currentPath) {
    const items = [];
    const knownFolders = new Set();

    // Normalisiere den Suchpfad (leere Strings bleiben leer)
    const searchPath = currentPath || "";

    files.forEach(file => {
        // Fallback für Single Files: Wenn webkitRelativePath fehlt, nimm den Dateinamen
        const fullPath = file.webkitRelativePath || file.name;

        // CHECK 1: Sind wir im Root? (searchPath ist leer)
        if (searchPath === "") {
            if (!fullPath.includes('/')) {
                // Datei liegt direkt im Root -> Hinzufügen!
                items.push({ name: fullPath, type: 'file', size: file.size, fullPath: fullPath });
            } else {
                // Datei liegt in einem Unterordner -> Ordner hinzufügen
                const folderName = fullPath.split('/')[0];
                if (!knownFolders.has(folderName)) {
                    knownFolders.add(folderName);
                    items.push({ name: folderName, type: 'folder', fullPath: folderName });
                }
            }
            return;
        }

        // CHECK 2: Sind wir in einem Unterordner?
        if (fullPath.startsWith(searchPath + '/')) {
            const relativePart = fullPath.substring(searchPath.length + 1);
            const parts = relativePart.split('/');

            if (parts.length === 1) {
                // Direkte Datei im Unterordner
                if(parts[0] !== "") items.push({ name: parts[0], type: 'file', size: file.size, fullPath: fullPath });
            } else {
                // Noch ein Unterordner
                const folderName = parts[0];
                if (!knownFolders.has(folderName)) {
                    knownFolders.add(folderName);
                    items.push({ name: folderName, type: 'folder', fullPath: searchPath + '/' + folderName });
                }
            }
        }
    });

    // Duplikate entfernen (Sicherheitsnetz)
    return items.filter((v,i,a) => a.findIndex(t => (t.name === v.name && t.type === v.type)) === i);
}

function getAllFilesInPathRecursive(files, startPath) {
    return files.filter(file => {
        const path = file.webkitRelativePath || file.name;
        if (!startPath || startPath === "") return true;
        return path.startsWith(startPath + '/');
    });
}

function streamFileToPeer(f, c) {
    const chunk = 16384;
    let off = 0;
    const r = new FileReader();

    // WICHTIG: Fallback für den Namen.
    // webkitRelativePath ist bei Single Files oft leer, daher nehmen wir f.name.
    const nameToSend = f.webkitRelativePath || f.name;

    r.onload = e => {
        if(c.readyState !== 'open') return;

        c.send(JSON.stringify({
            type: 'FILE_CHUNK',
            filename: nameToSend, // Hier muss der echte Dateiname ("bild.png") stehen!
            data: arrayBufferToBase64(e.target.result),
            isLast: (off + chunk >= f.size)
        }));

        off += chunk;
        if(off < f.size) setTimeout(readNext, 5);
    };

    const readNext = () => r.readAsArrayBuffer(f.slice(off, off + chunk));
    readNext();
}

function arrayBufferToBase64(b){ let binary=''; const bytes=new Uint8Array(b); for(let i=0;i<bytes.byteLength;i++)binary+=String.fromCharCode(bytes[i]); return window.btoa(binary); }
function base64ToArrayBuffer(b){ const s=window.atob(b); const y=new Uint8Array(s.length); for(let i=0;i<s.length;i++)y[i]=s.charCodeAt(i); return y.buffer; }
function triggerBrowserDownload(b,n){ const u=URL.createObjectURL(b); const a=document.createElement('a'); a.href=u; a.download=n; document.body.appendChild(a); a.click(); document.body.removeChild(a); }
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