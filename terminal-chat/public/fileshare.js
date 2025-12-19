// --- GLOBALS ---
const socket = io();
const earlyCandidates = {};
let myHostedFiles = []; // Hier liegen DEINE echten File-Objekte (RAM)
let currentRemoteFiles = []; // Dateien von jemand anderem (die wir gerade ansehen)
let myRootFolderName = "ROOT"; // Speichert den Namen des gemounteten Ordners
let incomingFileBuffer = []; // Speichert Chunks für den Download
let isPreviewMode = false; // Steuert, ob wir anzeigen oder speichern
let currentActiveFolderName = "ROOT"; // Speichert den Namen des aktuell offenen Ordners
let currentPathStr = ""; // Speichert den kompletten Pfad (z.B. "Project/src/assets")
let currentActivePeerId = null; // Speichert die Socket-ID des aktuellen Hosts
let isZipBatchMode = false;
// --- WEBRTC GLOBALS ---
const peers = {}; // Speichert aktive Verbindungen: { socketId: { connection, channel } }
const iceServers = {
    iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] // Google STUN Server für NAT Traversal
};
const jsonChunkBuffer = {};
// --- LIFECYCLE MANAGEMENT ---
const lifeCycleChannel = new BroadcastChannel('terminal_chat_lifecycle');

// Zuhören, ob der Master (Chat) stirbt
lifeCycleChannel.onmessage = (event) => {
    if (event.data.type === 'MASTER_DISCONNECT') {
        console.log("Master session ended. Closing interface...");

        // Optional: Sauber unmounten, falls Zeit bleibt (Browser killt Skripte oft sofort)
        // Aber Socket disconnect passiert eh automatisch beim Schließen.

        // Fenster schließen
        window.close();
    }
};

// --- INITIALISIERUNG ---
const user = localStorage.getItem('fs_username');
const userKey = localStorage.getItem('fs_key'); // Falls vorhanden

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

// --- MOCK DATA (PLATZHALTER FÜR SPÄTER) ---
const mockFileSystem = {
    'share1': {
        name: 'PROJECT_OMEGA',
        user: 'Neo',
        files: [
            { type: 'folder', name: 'Blueprints', content: [] },
            { type: 'file', name: 'passwords.txt', content: 'ROOT: admin123\nUSER: guest' },
            { type: 'file', name: 'network_map.png', content: '(Binary Image Data)' },
            { type: 'file', name: 'readme.md', content: '# READ ME\nDo not distribute.' }
        ]
    },
    'share2': {
        name: 'MUSIC_ARCHIVE',
        user: 'Trinity',
        files: []
    }
};

// Start: Mock-Daten anzeigen
renderSidebarMock();


// Sobald verbunden, authentifizieren wir uns beim Server
socket.on('connect', () => {
    console.log("Connected to File System Network");

    // Wir holen die Daten, die wir im Chat gespeichert haben
    const savedUser = localStorage.getItem('fs_username');
    const savedKey = localStorage.getItem('fs_key'); // Falls vorhanden

    if (savedUser) {
        // Wir melden uns als File-System-Client an
        socket.emit('fs_login', { username: savedUser, key: savedKey });
    }

    // Danach Liste anfordern
    socket.emit('fs_request_update');
});

// --- SERVER EVENTS ---

// Liste der Shares wird aktualisiert
socket.on('fs_update_shares', (sharesList) => {
    // sharesList: { socketId: { ... } }

    // --- NEU: SICHERHEITS-CHECK ---
    // Wenn wir gerade einen Ordner offen haben (currentActivePeerId ist gesetzt)
    // ABER dieser User nicht mehr in der Liste ist (sharesList[currentActivePeerId] existiert nicht)
    if (currentActivePeerId && !sharesList[currentActivePeerId]) {
        console.log("Active host disconnected. Closing session.");

        // 1. Vorschau hart schließen
        closePreview();

        // 2. Grid leeren und Fehlermeldung zeigen
        const grid = document.getElementById('fileGrid');
        grid.innerHTML = '<div class="empty-state" style="color:red;">&lt; SIGNAL LOST: HOST DISCONNECTED &gt;</div>';

        // 3. Status resetten
        currentActivePeerId = null;
        currentActiveFolderName = "ROOT";
        updateBreadcrumbs(['ROOT']);
    }
    // -----------------------------

    renderSidebar(sharesList);
});
// Empfängt Signale (Offer, Answer, Candidates) von anderen
socket.on('p2p_signal', async (data) => {
    // data: { senderId, signal, type }
    await handleP2PMessage(data.senderId, data.signal, data.type);
});


// --- LOCAL MOUNT LOGIC (Host) ---

function triggerMount() {
    document.getElementById('folderInput').click();
}

// Event Listener für Datei-Auswahl
document.getElementById('folderInput').addEventListener('change', (e) => {
    const files = e.target.files;
    if (files.length === 0) return;

    // 1. Dateien lokal speichern (Referenz)
    myHostedFiles = Array.from(files);

    // 2. Ordnernamen ermitteln
    const rootFolderName = files[0].webkitRelativePath.split('/')[0];
    myRootFolderName = rootFolderName; // <--- HIER SPEICHERN WIR IHN GLOBAL

    console.log(`MOUNTING: ${rootFolderName} with ${files.length} files.`);

    // 3. UI Update (Buttons tauschen)
    document.getElementById('btnMount').style.display = 'none';
    const unmountBtn = document.getElementById('btnUnmount');
    unmountBtn.style.display = 'block';
    unmountBtn.innerText = `[-] UNMOUNT [${rootFolderName}]`;

    // 4. Server informieren
    socket.emit('fs_start_hosting', { folderName: rootFolderName });
});

function unmountDrive() {
    // 1. Lokal aufräumen
    myHostedFiles = [];
    document.getElementById('folderInput').value = ''; // Reset Input

    // --- NEU: Offene Datei schließen ---
    closePreview();
    document.getElementById('fileGrid').innerHTML = '<div class="empty-state">&lt; DRIVE UNMOUNTED &gt;</div>';
    currentActivePeerId = null; // Reset
    // ----------------------------------

    // 2. UI Reset
    document.getElementById('btnMount').style.display = 'block';
    document.getElementById('btnUnmount').style.display = 'none';

    // 3. Server informieren
    socket.emit('fs_stop_hosting');
}


// --- SIDEBAR RENDERING ---

function renderSidebar(shares) {
    const list = document.getElementById('shareList');
    list.innerHTML = '';

    const shareIds = Object.keys(shares);

    if (shareIds.length === 0) {
        list.innerHTML = '<li style="padding:15px; color:#555; text-align:center;">No active drives detected.</li>';
        return;
    }

    shareIds.forEach(socketId => {
        const item = shares[socketId];

        const isMe = (socketId === socket.id);
        const displayName = isMe ? `${item.folderName} (LOCAL)` : item.folderName;
        const displayUser = isMe ? 'HOSTED BY YOU' : `Source: ${item.username} [ID: ${item.key}]`;
        const styleClass = isMe ? 'color:#0f0; border-left:4px solid #0f0;' : '';

        const li = document.createElement('li');
        li.className = 'share-item';
        if(isMe) li.style.cssText = styleClass;

        // --- HIER IST DER FIX ---
        li.onclick = () => {
            // 1. UI ZWANGS-RESET (Grid an, Preview aus)
            document.getElementById('filePreview').style.display = 'none';
            document.getElementById('fileGrid').style.display = 'grid';

            // 2. Buffer bereinigen (falls gerade ein Download lief)
            incomingFileBuffer = [];

            // --- NEU: Wir merken uns, wessen Ordner das ist ---
            currentActivePeerId = socketId;
            // --------------------------------------------------

            // 3. Logik ausführen
            if(isMe) {
                // START: Root Ordner Name (z.B. "MeinProjekt")
                currentPathStr = item.folderName;

                // Wir nutzen jetzt die neue Helper Funktion
                const items = getItemsInPath(myHostedFiles, currentPathStr);

                renderLocalGrid(items); // Grid rendert jetzt die gefilterte Liste
                updateBreadcrumbs([item.folderName]);
            } else {
                // REMOTE: Wir fragen nach dem Root
                const grid = document.getElementById('fileGrid');
                grid.innerHTML = '<div style="color:#0f0; text-align:center; margin-top:50px;">ESTABLISHING P2P UPLINK...</div>';
                connectToPeer(socketId);
                // (Der connectToPeer ruft später requestFileList auf)
            }

            // 4. Active Klasse setzen (Optik)
            document.querySelectorAll('.share-item').forEach(el => el.classList.remove('active'));
            li.classList.add('active');
        };
        // ------------------------

        li.innerHTML = `
            <span class="share-name">${displayName}</span>
            <span class="share-user">${displayUser}</span>
        `;
        list.appendChild(li);
    });
}

// --- LOKALE DATEIEN ANZEIGEN (Vorschau für den Host) ---

function renderLocalGrid(items) {
    const grid = document.getElementById('fileGrid');
    grid.innerHTML = '';

// --- ÄNDERUNG: Folder Action Button VERSTECKEN für Host ---
    const actionArea = document.getElementById('folderActions');
    // Wir verstecken den Bereich für den Host, wie gewünscht
    actionArea.style.display = 'none';
    // ---------------------------------------------------------

    // --- NEU: ZURÜCK BUTTON EINFÜGEN ---
    // Wenn currentPathStr länger ist als der Root-Name, sind wir tief drin
    if (currentPathStr && currentPathStr !== myRootFolderName) {
        const backDiv = document.createElement('div');
        backDiv.className = 'file-icon';
        backDiv.style.opacity = "0.7";
        backDiv.innerHTML = `
            <div class="icon-img" style="font-size:30px; display:flex; justify-content:center; align-items:center; border:1px solid #0f0; border-radius:50%;">
                <svg viewBox="0 0 24 24" style="width:32px; height:32px; fill:#0f0;"><path d="M20 11H7.83l5.59-5.59L12 4l-8 8 8 8 1.41-1.41L7.83 13H20v-2z"/></svg>
            </div>
            <div class="file-label">[ GO BACK ]</div>
        `;
        backDiv.onclick = () => {
            // Pfad eine Ebene hoch (String Manipulation)
            const parts = currentPathStr.split('/');
            parts.pop(); // Letzten Ordner entfernen
            currentPathStr = parts.join('/');

            const newItems = getItemsInPath(myHostedFiles, currentPathStr);
            renderLocalGrid(newItems);

            // Breadcrumbs anpassen
            updateBreadcrumbs(['ROOT', ...parts]); // Quick fix, besser wäre sauberes Array management
        };
        grid.appendChild(backDiv);
    }
    // -----------------------------------

    if(items.length === 0) {
        // Falls Ordner leer ist, trotzdem den Zurück Button anzeigen lassen, daher kein Return oben
        const msg = document.createElement('div');
        msg.innerHTML = "EMPTY FOLDER";
        msg.className = "empty-state";
        grid.appendChild(msg);
        return;
    }

    // ... (Dein restlicher items.forEach Loop bleibt fast gleich) ...
    items.forEach(item => {
        // ... (Dein existierender Code für Folder/File Icons) ...
        const el = document.createElement('div');
        el.className = 'file-icon';

        let iconSvg = '';
        if(item.type === 'folder') {
            iconSvg = `<svg viewBox="0 0 24 24" style="width:48px; height:48px; fill:#0f0;"><path d="M10 4H4c-1.1 0-1.99.9-1.99 2L2 18c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2h-8l-2-2z"/></svg>`;
            el.onclick = () => {
                currentPathStr = item.fullPath;
                const newItems = getItemsInPath(myHostedFiles, currentPathStr);
                renderLocalGrid(newItems);

                const crumbs = currentPathStr.split('/');
                updateBreadcrumbs(['ROOT', ...crumbs]);
            };
        } else {
            // ... (File Code wie gehabt) ...
            iconSvg = `<svg viewBox="0 0 24 24" style="width:48px; height:48px; fill:#0f0;"><path d="M14 2H6c-1.1 0-1.99.9-1.99 2L4 20c0 1.1.89 2 1.99 2H18c1.1 0 2-.9 2-2V8l-6-6zm2 16H8v-2h8v2zm0-4H8v-2h8v2zm-3-5V3.5L18.5 9H13z"/></svg>`;
            el.onclick = () => {
                // ... (Dein existierender Code mit openFile) ...
                let realFile = myHostedFiles.find(f => f.webkitRelativePath === item.fullPath);
                if (!realFile) realFile = myHostedFiles.find(f => f.name === item.name);
                if(realFile) openFile(realFile);
            };
        }
        el.innerHTML = `<div class="icon-img">${iconSvg}</div><div class="file-label">${item.name}</div>`;
        grid.appendChild(el);
    });
}

// --- UI FUNCTIONS ---

function renderSidebarMock() {
    const list = document.getElementById('shareList');
    list.innerHTML = '';

    Object.keys(mockFileSystem).forEach(key => {
        const item = mockFileSystem[key];
        const li = document.createElement('li');
        li.className = 'share-item';
        li.onclick = () => selectShare(key, li);
        li.innerHTML = `
            <span class="share-name">${item.name}</span>
            <span class="share-user">Shared by: ${item.user}</span>
        `;
        list.appendChild(li);
    });
}

function selectShare(id, element) {
    // UI Reset
    document.getElementById('filePreview').style.display = 'none';
    document.getElementById('fileGrid').style.display = 'grid';

    // Active State setzen
    document.querySelectorAll('.share-item').forEach(el => el.classList.remove('active'));
    if(element) element.classList.add('active');

    // Daten laden
    const data = mockFileSystem[id];

    // Breadcrumb Update
    updateBreadcrumbs([data.name]);

    // Grid füllen
    renderGrid(data.files);
}

function renderGrid(files) {
    const grid = document.getElementById('fileGrid');
    grid.innerHTML = '';

    if(!files || files.length === 0) {
        grid.innerHTML = '<div class="empty-state">EMPTY DIRECTORY</div>';
        return;
    }

    files.forEach(file => {
        const el = document.createElement('div');
        el.className = 'file-icon';

        let iconSvg = '';
        if(file.type === 'folder') {
            // Folder Icon
            iconSvg = `<svg viewBox="0 0 24 24" style="width:48px; height:48px; fill:#0f0;"><path d="M10 4H4c-1.1 0-1.99.9-1.99 2L2 18c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2h-8l-2-2z"/></svg>`;
            el.onclick = () => openFolder(file);
        } else {
            // File Icon
            iconSvg = `<svg viewBox="0 0 24 24" style="width:48px; height:48px; fill:#0f0;"><path d="M14 2H6c-1.1 0-1.99.9-1.99 2L4 20c0 1.1.89 2 1.99 2H18c1.1 0 2-.9 2-2V8l-6-6zm2 16H8v-2h8v2zm0-4H8v-2h8v2zm-3-5V3.5L18.5 9H13z"/></svg>`;
            el.onclick = () => openFile(file);
        }

        el.innerHTML = `
            <div class="icon-img">${iconSvg}</div>
            <div class="file-label">${file.name}</div>
        `;
        grid.appendChild(el);
    });
}

// Lokale Datei öffnen (Host View)
function openFile(file) {
    // 1. UI Umschalten
    document.getElementById('fileGrid').style.display = 'none';
    document.getElementById('filePreview').style.display = 'flex';
    document.getElementById('previewFileName').textContent = file.name;

    updateBreadcrumbs([currentActiveFolderName, file.name]);

    // 2. Button deaktivieren (Local Source)
    const btn = document.querySelector('#filePreview .btn-action');
    const newBtn = btn.cloneNode(true);
    btn.parentNode.replaceChild(newBtn, btn);
    newBtn.textContent = "[ LOCAL SOURCE ]";
    newBtn.style.opacity = "0.5";
    newBtn.style.cursor = "default";
    newBtn.onclick = null;

    const contentDiv = document.getElementById('previewContent');
    contentDiv.textContent = "Loading preview...";

    // --- FIX: DIE ECHTE DATEI FINDEN ---
    let realFile = file;

    // Wir prüfen, ob 'file' die Methode .slice besitzt (das haben nur echte Dateien)
    // Wenn nicht, suchen wir die echte Datei in unserem Speicher
    if (typeof file.slice !== 'function') {
        console.log("Looking up real file object for:", file.name);
        realFile = myHostedFiles.find(f => f.name === file.name);
    }

    if (!realFile) {
        contentDiv.textContent = "ERROR: FILE CONTENT LOST IN MEMORY.";
        return;
    }
    // -----------------------------------

    const reader = new FileReader();

    reader.onload = (e) => {
        const result = e.target.result;

        // Bild-Erkennung (Typ oder Endung)
        const isImage = realFile.type.startsWith('image/') ||
            realFile.name.match(/\.(jpeg|jpg|gif|png|webp)$/i);

        if (isImage) {
            contentDiv.innerHTML = '';
            const img = document.createElement('img');
            img.src = result;
            img.style.maxWidth = '100%';
            img.style.maxHeight = '100%';
            img.style.border = '1px solid #0f0';
            contentDiv.appendChild(img);
        } else {
            // Alles andere als Text anzeigen
            contentDiv.textContent = result;
        }
    };

    reader.onerror = (err) => {
        console.error(err);
        contentDiv.textContent = "ERROR READING LOCAL FILE.";
    };

    // Lesen starten
    // Wir versuchen Bilder als DataURL, alles andere als Text
    const isImage = realFile.type.startsWith('image/') ||
        realFile.name.match(/\.(jpeg|jpg|gif|png|webp)$/i);

    if (isImage) {
        reader.readAsDataURL(realFile);
    } else {
        reader.readAsText(realFile);
    }
}

function closePreview() {
    document.getElementById('filePreview').style.display = 'none';
    document.getElementById('fileGrid').style.display = 'grid';

    updateBreadcrumbs([currentActiveFolderName]);
    // -------------------------------------

    // Optional: Buffer leeren beim Schließen, um Speicher freizugeben
    incomingFileBuffer = [];
}

function openFolder(folder) {
    alert(`System Message: Navigation into '${folder.name}' simulated.`);
    // Hier würde später renderGrid(folder.children) aufgerufen
}

function updateBreadcrumbs(pathArray) {
    const bar = document.getElementById('breadcrumbs');
    bar.innerHTML = 'ROOT <span class="separator">></span> '; // Reset

    // pathArray ist z.B. ["ROOT", "Project", "src"]

    // Wir bauen den Pfad schrittweise wieder zusammen
    let accumulatedPath = "";

    pathArray.forEach((crumb, index) => {
        if (index > 0) { // ROOT überspringen wir im Pfad-Bau
            accumulatedPath = accumulatedPath ? `${accumulatedPath}/${crumb}` : crumb;
        }

        const span = document.createElement('span');
        span.className = 'crumb';
        span.textContent = crumb;

        // Klickbar machen (außer der letzte, das ist der aktuelle)
        if (index < pathArray.length - 1) {
            span.onclick = () => {
                // Navigieren!
                if (index === 0) {
                    // Klick auf ROOT -> Reset? Oder Root Drive?
                    // Hier etwas tricky. Am besten wir lassen ROOT nicht klickbar
                    // oder wir speichern den Drive Namen separat.
                } else {
                    // Navigiere zu accumulatedPath
                    if (currentActivePeerId && currentActivePeerId !== socket.id) {
                        navigateRemote(accumulatedPath, currentActivePeerId);
                    } else {
                        currentPathStr = accumulatedPath;
                        const items = getItemsInPath(myHostedFiles, currentPathStr);
                        renderLocalGrid(items);

                        // Breadcrumbs neu berechnen (Rekursion vermeiden, manuell schneiden)
                        const newCrumbs = pathArray.slice(0, index + 1);
                        updateBreadcrumbs(newCrumbs);
                    }
                }
            };
        } else {
            span.style.color = "#fff"; // Aktueller Ordner weiß
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

function downloadCurrentFile() {
    alert("Initiating secure P2P transfer protocol...");
}

// ===== Utility Functions (oben in fileshare.js) =====
function sendLargeJSON(channel, type, payload) {
    const json = JSON.stringify({ type, payload });
    const MAX = 12000;

    for (let i = 0; i < json.length; i += MAX) {
        channel.send(JSON.stringify({
            type: 'JSON_CHUNK',
            data: json.slice(i, i + MAX),
            isLast: i + MAX >= json.length
        }));
    }
}


function sendDirectoryToPeer(path, channel) {
    const directoryData = readDirectory(path);

    sendLargeJSON(channel, 'RESPONSE_DIRECTORY', directoryData);

}


// --- P2P CONNECTION LOGIC (FINAL CHROME FIX) ---

// 1. Verbindung starten (Als GAST / SENDER)
async function connectToPeer(targetId) {
    // Alte Verbindung rigoros löschen
    if (peers[targetId]) {
        if(peers[targetId].connection) peers[targetId].connection.close();
        delete peers[targetId];
    }

    console.log(`Starting connection to ${targetId}...`);

    const config = {
        iceServers: [
            { urls: 'stun:stun.l.google.com:19302' },
            { urls: 'stun:stun1.l.google.com:19302' }
        ]
    };

    const pc = new RTCPeerConnection(config);
    const channel = pc.createDataChannel("fileSystem");

    // Setup Handlers
    setupChannelHandlers(channel, targetId);

    // Peer speichern
    peers[targetId] = {
        connection: pc,
        channel: channel,
        pendingQueue: [] // Lokale Queue für später
    };

    pc.onicecandidate = (event) => {
        if (event.candidate) {
            socket.emit('p2p_signal', { targetId: targetId, type: 'candidate', signal: event.candidate });
        }
    };

    pc.oniceconnectionstatechange = () => {
        console.log(`ICE State (${targetId}): ${pc.iceConnectionState}`);
        if(pc.iceConnectionState === 'failed') {
            console.error("Critical: ICE Connection failed.");
        }
    };

    try {
        const offer = await pc.createOffer();
        await pc.setLocalDescription(offer);
        socket.emit('p2p_signal', { targetId: targetId, type: 'offer', signal: offer });
    } catch (err) {
        console.error("Connection Start Error:", err);
    }
}

// 2. Eingehende Signale verarbeiten (Als HOST oder GAST)
async function handleP2PMessage(senderId, signal, type) {

    // --- FALL A: EIN CANDIDATE KOMMT, ABER WIR KENNEN DEN PEER NOCH NICHT ---
    if (!peers[senderId] && type === 'candidate') {
        console.log(`[Cache] Storing early candidate from ${senderId}`);
        if (!earlyCandidates[senderId]) earlyCandidates[senderId] = [];
        earlyCandidates[senderId].push(signal);
        return; // Wichtig: Nicht weitermachen, da PC noch nicht existiert
    }

    // --- FALL B: EIN NEUES ANGEBOT (OFFER) KOMMT ---
    if (type === 'offer') {
        // Alte Verbindung killen, falls vorhanden
        if (peers[senderId]) {
            if(peers[senderId].connection) peers[senderId].connection.close();
            delete peers[senderId];
        }

        const config = {
            iceServers: [
                { urls: 'stun:stun.l.google.com:19302' },
                { urls: 'stun:stun1.l.google.com:19302' }
            ]
        };
        const pc = new RTCPeerConnection(config);

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

        // Peer anlegen
        peers[senderId] = {
            connection: pc,
            channel: null,
            pendingQueue: []
        };

        // GIBT ES FRÜHE CANDIDATES IM GLOBALEN CACHE?
        if (earlyCandidates[senderId]) {
            console.log(`[Cache] Found ${earlyCandidates[senderId].length} early candidates. Moving to queue.`);
            peers[senderId].pendingQueue.push(...earlyCandidates[senderId]);
            delete earlyCandidates[senderId]; // Cache leeren
        }
    }

    // Sicherheits-Check: Wenn jetzt immer noch kein Peer da ist, ignorieren wir es
    if (!peers[senderId]) return;

    const p = peers[senderId];
    const pc = p.connection;

    try {
        if (type === 'offer') {
            await pc.setRemoteDescription(new RTCSessionDescription(signal));
            const answer = await pc.createAnswer();
            await pc.setLocalDescription(answer);
            socket.emit('p2p_signal', { targetId: senderId, type: 'answer', signal: answer });

            // Queue abarbeiten
            processPendingQueue(p, pc);
        }
        else if (type === 'answer') {
            await pc.setRemoteDescription(new RTCSessionDescription(signal));
            // Queue abarbeiten
            processPendingQueue(p, pc);
        }
        else if (type === 'candidate') {
            // Chrome Fix: Wenn RemoteDescription fehlt -> Queue
            if (!pc.remoteDescription || pc.remoteDescription.type === null) {
                p.pendingQueue.push(signal);
            } else {
                await pc.addIceCandidate(new RTCIceCandidate(signal)).catch(e => {});
            }
        }
    } catch (e) {
        console.error("WebRTC Handling Error:", e);
    }
}

// 3. Queue Helper (Integriert, damit keine ReferenceErrors kommen)
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
        } catch (e) { console.error("Invalid JSON:", event.data); }
    };

    channel.onclose = () => {
        console.log(`Channel closed with ${peerId}`);
        delete peers[peerId];
    };

    channel.onerror = (err) => console.error("Channel Error:", err);
}


// --- DIESE FUNKTION FEHLT BEI DIR ---
async function processCandidateQueue(peerObj, pc) {
    if (peerObj.candidateQueue.length > 0) {
        console.log(`Processing ${peerObj.candidateQueue.length} queued candidates.`);
        for (const candidate of peerObj.candidateQueue) {
            try {
                await pc.addIceCandidate(new RTCIceCandidate(candidate));
            } catch (e) {
                console.warn("Candidate skip:", e);
            }
        }
        peerObj.candidateQueue = [];
    }
}

// 4. Nachrichten Protokoll (Was schicken wir uns hin und her?)
function handleChannelMessage(msg, peerId, channel) {

// --- HOST LOGIK ---

    // 1. GAST WILL DEN START-ORDNER SEHEN
    if (msg.type === 'REQUEST_ROOT') {
        // Wir nutzen die Helper-Funktion, um nur die oberste Ebene zu holen
        // myRootFolderName ist z.B. "MeinProjekt"
        const rootItems = getItemsInPath(myHostedFiles, myRootFolderName);

        channel.send(JSON.stringify({
            type: 'RESPONSE_DIRECTORY', // Wir nutzen ab jetzt immer diesen Typ
            items: rootItems,
            path: myRootFolderName
        }));
    }

    // 2. GAST KLICKT AUF EINEN UNTERORDNER
    if (msg.type === 'REQUEST_DIRECTORY') {
        // msg.path ist z.B. "MeinProjekt/src/assets"
        const items = getItemsInPath(myHostedFiles, msg.path);

        channel.send(JSON.stringify({
            type: 'RESPONSE_DIRECTORY',
            items: items,
            path: msg.path
        }));
    }

    if (msg.type === 'JSON_CHUNK') {
        if (!jsonChunkBuffer[peerId]) jsonChunkBuffer[peerId] = '';

        jsonChunkBuffer[peerId] += msg.data;

        if (msg.isLast) {
            const fullMessage = JSON.parse(jsonChunkBuffer[peerId]);
            delete jsonChunkBuffer[peerId];

            // Rekursiv normal verarbeiten
            handleChannelMessage(fullMessage, peerId, channel);
        }
        return;
    }

// --- CLIENT LOGIK ---

    if (msg.type === 'RESPONSE_DIRECTORY') {
        currentPathStr = msg.path; // Pfad merken

        // Breadcrumbs
        const crumbs = currentPathStr.split('/');
        updateBreadcrumbs(['ROOT', ...crumbs]);

        // Rendern
        renderRemoteGrid(msg.items, peerId);
    }

    // 3. DOWNLOAD ANFRAGE (HOST LOGIK)
    if (msg.type === 'REQUEST_DOWNLOAD') {
        console.log(`[HOST] Incoming request for: "${msg.filename}"`);

        // A) Versuch 1: Exakter Pfad (webkitRelativePath)
        let requestedFile = myHostedFiles.find(f => f.webkitRelativePath === msg.filename);

        // B) Versuch 2: Falls msg.filename nur der Name ist, suchen wir danach
        if (!requestedFile) {
            // Findet die erste Datei, die exakt so heißt (ignoriert Ordner)
            requestedFile = myHostedFiles.find(f => f.name === msg.filename);
        }

        // C) Versuch 3: "Ends With" Suche (Falls Pfad-Teile abweichen)
        if (!requestedFile) {
            requestedFile = myHostedFiles.find(f => f.webkitRelativePath.endsWith(msg.filename));
        }

        if (requestedFile) {
            console.log(`[HOST] File found: ${requestedFile.name} (${requestedFile.size} bytes). Starting stream...`);

            // Start Stream
            streamFileToPeer(requestedFile, channel);
        } else {
            console.error(`[HOST] ERROR: File "${msg.filename}" NOT FOUND in memory.`);
            // WICHTIG: Dem Gast sagen, dass es nicht klappt!
            channel.send(JSON.stringify({
                type: 'ERROR',
                message: `File not found on host: ${msg.filename}`
            }));
        }
    }

    // NEU: FEHLER VOM HOST EMPFANGEN
    if (msg.type === 'ERROR') {
        console.error("P2P Error received:", msg.message);

        // Fall A: Wir sind im ZIP Modus -> Einfach weitermachen (Datei überspringen)
        if (isZipBatchMode) {
            console.warn("Skipping missing file in ZIP queue.");
            processZipQueue();
            return;
        }

        // Fall B: Wir sind in der Vorschau -> Fehler anzeigen
        if (isPreviewMode) {
            const contentDiv = document.getElementById('previewContent');
            if (contentDiv) {
                contentDiv.innerHTML = `
                    <div style="color:red; text-align:center; margin-top:20%;">
                        [ TRANSMISSION ERROR ]<br>
                        ${msg.message}<br><br>
                        <button onclick="closePreview()" style="background:#333; color:#fff; border:1px solid red; padding:5px;">CLOSE</button>
                    </div>
                `;
            }
        } else {
            // Fall C: Normaler Download -> Alert
            alert("Download failed: " + msg.message);
        }

        // Reset Buffer
        incomingFileBuffer = [];
    }

    // IN handleChannelMessage - HOST BEREICH

    // 4. REKURSIVE LISTE FÜR ZIP ANFRAGE
    if (msg.type === 'REQUEST_RECURSIVE_LIST') {
        // Alle Dateien finden
        const files = getAllFilesInPathRecursive(myHostedFiles, msg.path);

        // Wir senden nur Pfade und Namen zurück, um Traffic zu sparen
        const metaList = files.map(f => ({
            fullPath: f.webkitRelativePath,
            relativePath: msg.path ? f.webkitRelativePath.substring(msg.path.length + 1) : f.webkitRelativePath
        }));

        channel.send(JSON.stringify({
            type: 'RESPONSE_RECURSIVE_LIST',
            list: metaList
        }));
    }

    // NEU: WIR BEKOMMEN EINEN CHUNK
    if (msg.type === 'FILE_CHUNK') {
        const chunkData = base64ToArrayBuffer(msg.data);
        incomingFileBuffer.push(chunkData);

        if (msg.isLast) {
            // Blob erstellen
            const blob = new Blob(incomingFileBuffer, {type: 'application/octet-stream'});

            // --- UNTERSCHEIDUNG DER MODI ---

            if (isZipBatchMode) {
                // MODUS C: ZIP BATCH DOWNLOAD

                // Pfad säubern: Wenn wir "OrdnerA" laden, soll "OrdnerA/Unterordner/Bild.png"
                // im Zip zu "Unterordner/Bild.png" werden.
                let zipPath = msg.filename;

                // Falls wir in einem Unterordner sind, diesen Teil vom Pfad abschneiden
                if (currentPathStr && zipPath.startsWith(currentPathStr + '/')) {
                    zipPath = zipPath.substring(currentPathStr.length + 1);
                } else if (zipPath.startsWith(currentPathStr)) {
                    // Fallback falls der Slash fehlt
                    zipPath = zipPath.substring(currentPathStr.length);
                    if(zipPath.startsWith('/')) zipPath = zipPath.substring(1);
                }

                // Zur Zip hinzufügen
                if (zipInstance) {
                    zipInstance.file(zipPath, blob);
                }

                // Aufräumen & Weitermachen
                incomingFileBuffer = [];
                processZipQueue(); // <--- NEXT!

            } else if (isPreviewMode) {
                // MODUS A: VORSCHAU
                renderRemoteBlob(blob, msg.filename);
                incomingFileBuffer = [];

            } else {
                // MODUS B: NORMALER DOWNLOAD
                triggerBrowserDownload(blob, msg.filename);

                const btn = document.querySelector('#filePreview .btn-action');
                if (btn) {
                    btn.textContent = "[ SAVED ]";
                    setTimeout(() => btn.textContent = "[ SAVE TO DISK ]", 2000);
                }
                incomingFileBuffer = [];
            }
        }
    }

// IN handleChannelMessage - CLIENT BEREICH

// ANTWORT AUF ZIP ANFRAGE
    if (msg.type === 'RESPONSE_RECURSIVE_LIST') {
        console.log(`Starting Batch Download for ${msg.list.length} files.`);

        // Queue füllen
        zipQueue = msg.list; // { fullPath, relativePath }

        // Prozess starten
        processZipQueue();
    }
}

// 5. Hilfsfunktion: Liste anfordern
function requestFileList(targetId) {
    const p = peers[targetId];
    if (p && p.channel && p.channel.readyState === 'open') {
        p.channel.send(JSON.stringify({ type: 'REQUEST_ROOT' }));
    }
}

function renderRemoteGrid(items, peerId) {
    const grid = document.getElementById('fileGrid');
    grid.innerHTML = '';

    // --- NEU: Folder Action Button Remote ---
    const actionArea = document.getElementById('folderActions');
    const zipBtn = document.getElementById('btnZipDownload');

    actionArea.style.display = 'block';
    const folderName = currentPathStr.split('/').pop() || "ROOT";
    zipBtn.textContent = `[ DOWNLOAD '${folderName}' AS .ZIP ]`;
    zipBtn.onclick = () => downloadFolderAsZip(currentPathStr, false, peerId); // false = remote
    // ----------------------------------------

    // --- NEU: ZURÜCK BUTTON REMOTE ---
    // Wir prüfen ob im Pfad Slashes sind (außer es ist nur der Root Name)
    // Einfacher Check: Wenn currentPathStr != dem ersten Teil vom Request Response
    if (currentPathStr && currentPathStr.includes('/')) {
        const backDiv = document.createElement('div');
        backDiv.className = 'file-icon';
        backDiv.style.opacity = "0.7";
        backDiv.innerHTML = `
             <div class="icon-img" style="font-size:30px; display:flex; justify-content:center; align-items:center; border:1px solid #0f0; border-radius:50%;">
                <svg viewBox="0 0 24 24" style="width:32px; height:32px; fill:#0f0;"><path d="M20 11H7.83l5.59-5.59L12 4l-8 8 8 8 1.41-1.41L7.83 13H20v-2z"/></svg>
            </div>
            <div class="file-label">[ GO BACK ]</div>
        `;
        backDiv.onclick = () => {
            const parts = currentPathStr.split('/');
            parts.pop();
            const upPath = parts.join('/');
            navigateRemote(upPath, peerId); // Server fragen
        };
        grid.appendChild(backDiv);
    }
    // ---------------------------------

    // ... (Restlicher Loop wie gehabt) ...
    if(!items || items.length === 0) {
        const msg = document.createElement('div');
        msg.innerHTML = "EMPTY FOLDER";
        msg.className = "empty-state";
        grid.appendChild(msg);
        return;
    }

    items.forEach(item => {
        // ... (Dein existierender Item Loop) ...
        // Hier nur der gekürzte Code zur Orientierung:
        const el = document.createElement('div');
        el.className = 'file-icon';
        let iconSvg = '';
        if(item.type === 'folder') {
            iconSvg = `<svg viewBox="0 0 24 24" style="width:48px; height:48px; fill:#0f0;"><path d="M10 4H4c-1.1 0-1.99.9-1.99 2L2 18c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2h-8l-2-2z"/></svg>`;
            el.onclick = () => navigateRemote(item.fullPath, peerId);
        } else {
            iconSvg = `<svg viewBox="0 0 24 24" style="width:48px; height:48px; fill:#0f0;"><path d="M14 2H6c-1.1 0-1.99.9-1.99 2L4 20c0 1.1.89 2 1.99 2H18c1.1 0 2-.9 2-2V8l-6-6zm2 16H8v-2h8v2zm0-4H8v-2h8v2zm-3-5V3.5L18.5 9H13z"/></svg>`;
            el.onclick = () => openRemoteFilePreview(item, peerId);
        }
        el.innerHTML = `<div class="icon-img">${iconSvg}</div><div class="file-label">${item.name}</div>`;
        grid.appendChild(el);
    });
}

function openRemoteFilePreview(file, peerId) {
    // 1. UI Öffnen
    document.getElementById('fileGrid').style.display = 'none';
    document.getElementById('filePreview').style.display = 'flex';
    document.getElementById('previewFileName').textContent = file.name;

    // Breadcrumbs bauen (Pfad splitten und Dateinamen anhängen)
    const crumbs = currentPathStr ? currentPathStr.split('/') : [currentActiveFolderName];
    updateBreadcrumbs([currentActiveFolderName, file.name]);

    // Status anzeigen
    const contentDiv = document.getElementById('previewContent');
    contentDiv.innerHTML = '<div style="color:#0f0; text-align:center; margin-top:20%;">[ P2P STREAMING IN PROGRESS... ]<br>Receiving Data packets...</div>';

    // 2. Download Button vorbereiten (Falls man es doch speichern will)
    const btn = document.querySelector('#filePreview .btn-action');
    const newBtn = btn.cloneNode(true);
    btn.parentNode.replaceChild(newBtn, btn);

    newBtn.textContent = "[ SAVE TO DISK ]";
    newBtn.style.opacity = "1";
    newBtn.style.cursor = "pointer";

    newBtn.onclick = () => {
        // Manueller Klick = Speichern auf Festplatte
        isPreviewMode = false;
        requestFileFromPeer(file.name, peerId);
    };

    // 3. AUTOMATISCH STARTEN (Preview Modus)
    isPreviewMode = true;

    // WICHTIG: Wir nutzen item.fullPath als ID für die Anfrage
    // Falls fullPath fehlt (altes System), Fallback auf name
    const requestID = file.fullPath || file.name;

    requestFileFromPeer(requestID, peerId);
}

// Hilfsfunktion, um Code-Dopplung zu vermeiden
function requestFileFromPeer(pathOrName, peerId) {
    incomingFileBuffer = []; // Buffer leeren

    const p = peers[peerId];
    if (p && p.channel) {
        console.log(`Requesting ${pathOrName} from ${peerId} (Preview: ${isPreviewMode})`);

        p.channel.send(JSON.stringify({
            type: 'REQUEST_DOWNLOAD',
            // WICHTIG: Hier nutzen wir direkt den übergebenen Parameter 'pathOrName'
            // Vorher stand hier 'file.fullPath', aber 'file' existiert hier nicht!
            filename: pathOrName
        }));
    } else {
        alert("ERROR: Peer connection lost.");
    }
}

// --- UTILITIES ---

// ArrayBuffer zu Base64 String konvertieren
function arrayBufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
}

// Base64 String zu ArrayBuffer konvertieren
function base64ToArrayBuffer(base64) {
    const binary_string = window.atob(base64);
    const len = binary_string.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binary_string.charCodeAt(i);
    }
    return bytes.buffer;
}

function streamFileToPeer(file, channel) {
    // Check auf leere Datei
    if (file.size === 0) {
        channel.send(JSON.stringify({
            type: 'FILE_CHUNK',
            filename: file.name,
            data: "",
            isLast: true
        }));
        return;
    }

    const chunkSize = 8192; // 16KB WebRTC safe chunk
    const MAX_BUFFER = 512 * 1024; // 512 KB Backpressure-Grenze
    let offset = 0;
    const reader = new FileReader();

    reader.onload = (e) => {
        // ArrayBuffer -> Base64
        const base64Data = arrayBufferToBase64(e.target.result);

        // Channel-Status prüfen
        if (channel.readyState !== 'open') {
            console.warn("Channel closed during stream.");
            return;
        }

        channel.send(JSON.stringify({
            type: 'FILE_CHUNK',
            filename: file.name,
            data: base64Data,
            isLast: (offset + chunkSize >= file.size)
        }));

        offset += chunkSize;

        if (offset < file.size) {
            waitForBuffer();
        } else {
            console.log(`[HOST] Upload complete: ${file.name}`);
        }
    };

    reader.onerror = (err) => console.error("Error reading file:", err);

    // 🔑 Backpressure-aware scheduling
    const waitForBuffer = () => {
        if (channel.bufferedAmount > MAX_BUFFER) {
            setTimeout(waitForBuffer, 20);
            return;
        }
        readNextChunk();
    };

    const readNextChunk = () => {
        const slice = file.slice(offset, offset + chunkSize);
        reader.readAsArrayBuffer(slice);
    };

    readNextChunk(); // Start
}


// Zeigt einen Blob (aus dem RAM) im Preview-Fenster an
function renderRemoteBlob(blob, filename) {
    const contentDiv = document.getElementById('previewContent');
    contentDiv.innerHTML = ''; // "Streaming..." Text entfernen

    // Prüfen auf Bild
    const isImage = filename.match(/\.(jpeg|jpg|gif|png|webp)$/i);

    if (isImage) {
        const url = URL.createObjectURL(blob);
        const img = document.createElement('img');
        img.src = url;
        img.style.maxWidth = '100%';
        img.style.border = '1px solid #0f0';
        contentDiv.appendChild(img);
    }
    else {
        // Versuchen als Text zu lesen
        const reader = new FileReader();
        reader.onload = (e) => {
            contentDiv.textContent = e.target.result;
        };
        reader.onerror = () => {
            contentDiv.textContent = "ERROR: Could not decode text data.";
        };
        reader.readAsText(blob);
    }
}

// Startet den klassischen Browser-Download
function triggerBrowserDownload(blob, filename) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

// --- HELPER: ORDNER STRUKTUR ---

// Filtert die flache Dateiliste basierend auf dem aktuellen Pfad
function getItemsInPath(allFiles, currentPath) {
    const items = [];
    const knownFolders = new Set(); // Damit wir Ordner nicht doppelt anzeigen

    // currentPath ist z.B. "Project/src"
    // file.webkitRelativePath ist z.B. "Project/src/components/header.js"

    allFiles.forEach(file => {
        const fullPath = file.webkitRelativePath;

        // Check 1: Beginnt die Datei mit dem aktuellen Pfad?
        if (!fullPath.startsWith(currentPath + '/')) {
            // Sonderfall: Wenn wir ganz am Anfang sind (Root)
            if (currentPath !== "" && currentPath !== file.webkitRelativePath.split('/')[0]) return;
        }

        // Rest des Pfads holen (alles nach dem aktuellen Ordner)
        // Bsp: "components/header.js"
        const relativePart = fullPath.substring(currentPath.length + (currentPath ? 1 : 0));

        const parts = relativePart.split('/');

        if (parts.length === 1) {
            // Keine weiteren Slashes -> Es ist eine Datei in diesem Ordner
            // Aber Achtung: Manchmal sind leere Einträge dabei
            if(parts[0] !== "") {
                items.push({
                    name: parts[0],
                    type: 'file', // Echte Datei
                    size: file.size,
                    fullPath: fullPath // Wichtig für Download Identifikation
                });
            }
        } else {
            // Es gibt noch Slashes -> Es ist ein Unterordner
            const folderName = parts[0];
            if (!knownFolders.has(folderName)) {
                knownFolders.add(folderName);
                items.push({
                    name: folderName,
                    type: 'folder', // Virtueller Ordner
                    fullPath: currentPath ? `${currentPath}/${folderName}` : folderName
                });
            }
        }
    });

    return items;
}

function navigateRemote(path, peerId) {
    const p = peers[peerId];
    if (p && p.channel) {
        console.log(`Navigating to: ${path}`);
        p.channel.send(JSON.stringify({
            type: 'REQUEST_DIRECTORY', // Neuer Befehl
            path: path
        }));
    }
}

// --- HELPER: REKURSIVE SUCHE ---

// Findet ALLE Dateien (auch in Unterordnern) ab einem bestimmten Pfad
function getAllFilesInPathRecursive(allFiles, startPath) {
    return allFiles.filter(file => {
        const path = file.webkitRelativePath;
        // Ist die Datei innerhalb dieses Pfades?
        // Wenn startPath leer ist (ROOT), nehmen wir alles.
        if (startPath === "" || startPath === myRootFolderName) return true;
        return path.startsWith(startPath + '/');
    });
}

// --- ZIP DOWNLOAD LOGIK ---

let zipQueue = []; // Liste der Dateien, die noch geladen werden müssen
let zipInstance = null; // Das JSZip Objekt
let isZipping = false;
let currentZipPeerId = null;

async function downloadFolderAsZip(path, isLocal, peerId) {
    const folderName = path.split('/').pop() || "archive";

    // Fall 1: LOKALER DOWNLOAD (Simpel)
    if (isLocal) {
        const zip = new JSZip();
        // Alle Dateien rekursiv finden
        const filesToZip = getAllFilesInPathRecursive(myHostedFiles, path);

        if(filesToZip.length === 0) {
            alert("Folder is empty.");
            return;
        }

        const btn = document.getElementById('btnZipDownload');
        btn.textContent = "[ ZIPPING LOCAL FILES... ]";

        // Dateien zum Zip hinzufügen
        filesToZip.forEach(file => {
            // Wir müssen den Pfad relativ zum ZIP Root machen
            // Wenn Download Pfad = "A/B" und File = "A/B/C/img.png"
            // Soll im Zip stehen: "C/img.png"
            let relativePath = file.webkitRelativePath;
            if(path) {
                relativePath = relativePath.substring(path.length + 1);
            }
            zip.file(relativePath, file);
        });

        // Generieren
        const content = await zip.generateAsync({type:"blob"});
        triggerBrowserDownload(content, `${folderName}.zip`);
        btn.textContent = `[ DOWNLOAD '${folderName}' AS .ZIP ]`;
        return;
    }

    // Fall 2: REMOTE DOWNLOAD (Komplex)
    if (!isLocal && peerId) {
        // Reset flags
        zipInstance = new JSZip(); // <--- MUSS HIER SEIN
        zipQueue = [];
        isZipBatchMode = false;

        const btn = document.getElementById('btnZipDownload');
        btn.textContent = "[ REQUESTING FILE LIST... ]";

        // Wir senden einen neuen Befehl: Gib mir ALLE Pfade in diesem Ordner
        const p = peers[peerId];
        p.channel.send(JSON.stringify({
            type: 'REQUEST_RECURSIVE_LIST',
            path: path
        }));

        isZipping = true;
        currentZipPeerId = peerId;
    }
}

// --- QUEUE PROCESSOR FÜR REMOTE ZIP ---

function processZipQueue() {
    if (zipQueue.length === 0) {
        // FERTIG!
        finalizeRemoteZip();
        return;
    }

    // Nächste Datei holen
    const nextFile = zipQueue.shift(); // Erstes Element nehmen

    // UI Update
    const btn = document.getElementById('btnZipDownload');
    if(btn) btn.textContent = `[ ZIPPING: ${zipQueue.length} FILES REMAINING ]`;

    // Download anfordern (nutzt existierende Logik, aber mit Flag)
    // Wir nutzen hier eine spezielle Funktion oder setzen isPreviewMode = false
    // Aber wir müssen wissen, dass es für die Zip ist.

    // Trick: Wir nutzen die existierende requestFileFromPeer, aber setzen ein globales Flag
    isZipBatchMode = true; // Neue Variable oben definieren!
    requestFileFromPeer(nextFile.fullPath, currentZipPeerId);
}

async function finalizeRemoteZip() {
    // SICHERHEITS-CHECK: Existiert die Zip-Instanz überhaupt?
    if (!zipInstance) {
        console.warn("Aborting finalizeRemoteZip: No zip instance found (already finished?).");
        isZipping = false;
        isZipBatchMode = false;
        return;
    }

    const btn = document.getElementById('btnZipDownload');
    if(btn) btn.textContent = "[ FINALIZING ZIP... ]";

    try {
        // Zip erstellen
        const content = await zipInstance.generateAsync({type:"blob"});

        // Name raten (aus Pfad)
        const name = currentPathStr.split('/').pop() || "remote_archive";
        triggerBrowserDownload(content, `${name}.zip`);

        if(btn) btn.textContent = "[ DOWNLOAD COMPLETE ]";

    } catch (e) {
        console.error("Error generating ZIP:", e);
        if(btn) btn.textContent = "[ ZIP ERROR ]";
    } finally {
        // Aufräumen
        isZipping = false;
        isZipBatchMode = false;
        currentZipPeerId = null;
        zipInstance = null; // Hier wird es gelöscht
        zipQueue = [];      // Queue leeren

        // Button Reset nach 3 Sekunden
        setTimeout(() => {
            if(btn) {
                // Reset Button Text
                const folderName = currentPathStr.split('/').pop() || "ROOT";
                btn.textContent = `[ DOWNLOAD '${folderName}' AS .ZIP ]`;
            }
        }, 3000);
    }
}