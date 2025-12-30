// =============================================================================
// TERMINAL CHAT CLIENT - COMPLETE SYSTEM
// =============================================================================

// --- DOM ELEMENTS ---
const output = document.getElementById('output');
const input = document.getElementById('command-input');
const promptSpan = document.getElementById('prompt');
const inputWrapper = document.querySelector('.input-wrapper');
const cmdMirror = document.getElementById('cmd-mirror'); // Sicherstellen, dass das Element geladen wird
const lifeCycleChannel = new BroadcastChannel('terminal_chat_lifecycle');

// Voice / Side Panel Elements
const voiceStatus = document.getElementById('voice-status');
const voiceControls = document.getElementById('voice-controls');
const voiceVisualizer = document.querySelector('.voice-visualizer');
const remoteAudio = document.getElementById('remote-audio');
const chatList = document.getElementById('chat-list');

// --- GLOBAL VARIABLES ---
const socket = io();


// =============================================================================
// PROTOCOL: SCORCHED EARTH (DATA WIPER)
// =============================================================================

function nukeSystem(trigger = "manual") {
    console.log(`>>> INITIATING DATA PURGE (${trigger})...`);

    // 1. Lokalen Speicher komplett vernichten
    try {
        localStorage.clear();
        sessionStorage.clear();
    } catch (e) { console.error("Storage Wipe Error", e); }

    // 2. Cookies töten (falls vorhanden)
    document.cookie.split(";").forEach((c) => {
        document.cookie = c.replace(/^ +/, "").replace(/=.*/, "=;expires=" + new Date().toUTCString() + ";path=/");
    });

    // 3. Wenn es ein Notfall ist (Panic), RAM leeren durch Redirect
    if (trigger === "panic") {
        document.body.innerHTML = '<div style="background:#000;width:100%;height:100vh;color:#f00;display:flex;justify-content:center;align-items:center;font-family:monospace;font-size:2em;">SYSTEM HALTED. DATA PURGED.</div>';
        // Kurze Pause für den Effekt, dann ins Nirvana
        setTimeout(() => {
            window.location.href = "about:blank";
        }, 500);
    }
}

// AUTOMATISCHE REINIGUNG BEIM START
// Stellt sicher, dass wir IMMER mit einem sauberen Zustand beginnen,
// selbst wenn der Browser vorher abgestürzt ist.
nukeSystem("startup");

// PANIC TRIGGER LISTENER (3x ESC in 1 Sekunde)
let escCount = 0;
let escTimer = null;

document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        escCount++;

        // Timer starten beim ersten Drücken
        if (!escTimer) {
            escTimer = setTimeout(() => {
                escCount = 0;
                escTimer = null;
            }, 1000); // Man hat 1 Sekunde Zeit
        }

        // Bei 3 Klicks -> BOOM
        if (escCount >= 3) {
            nukeSystem("panic");
        }
    }
});


let myKey = null;
let myUsername = null;
let appState = 'BOOTING'; // BOOTING, IDLE, CHATTING, GROUP_CHATTING, PUB_CHATTING

// --- MULTI-CHAT SYSTEM (KEYCHAIN) ---
let activeChatId = 'LOCAL';
let myChats = {
    'LOCAL': {
        id: 'LOCAL',
        name: 'LOCAL_SHELL',
        type: 'system',
        history: [],
        unread: 0,
        key: null // Kein Key für lokales System
    }
};
let pendingRequests = {};
let tempDerivedKey = null; // Speichert den Schlüssel kurz zwischen bei /accept

// --- AUDIO / WEBRTC VARIABLES ---
let peerConnection = null;
let dataChannel = null;
let localStream = null;
let audioContext = null;
let analyser = null;
let visualizerFrameId = null;
let receivedBuffers = [];
let receivedSize = 0;
let incomingFileInfo = null;
let adminKickTargetKey = null; // Speichert die ID des Owners, den der Admin kicken will
let iamAdmin = false; // Speichert, ob wir globaler Admin sind

// --- HISTORY ---
let commandHistory = [];
let historyIndex = -1;
let currentKickTarget = null; // Für Admin Entscheidungen
let pendingKickTargets = []; // Speichert wen wir kicken wollen, während wir den Grund tippen
let pendingJoinGroupId = null; // Merkt sich die Gruppe, während wir das Passwort tippen

// --- CRYPTO KEYS (ECDH) ---
let myKeyPair = null; // Unser eigenes Schlüsselpaar

let outgoingConnects = {};
let currentVoiceTarget = null; // Speichert den Key des aktuellen Gesprächspartners

let fileShareWindow = null;

let institutionStyles = {}; // Speichert: { UserKey: { color: '#...', tag: '...' } }
let requestData = {};

// Hilfsfunktion für den Accept-Button
window.triggerAccept = (key) => {
    // Simuliert die Eingabe von /accept [KEY]
    input.value = `/accept ${key}`;
    handleInput(input.value);
    input.value = '';
};

// Hilfsfunktion für den Gruppen-Accept-Button
window.triggerGroupAccept = (targetKey) => {
    // Senden der Entscheidung an den Server
    socket.emit('group_decision', { targetKey: targetKey, accept: true });
};

// Hilfsfunktion: Einladung annehmen (User joint Gruppe)
window.triggerInviteAccept = (groupId) => {
    // Sendet { groupId: 1234, accept: true }
    socket.emit('group_decision', { groupId: groupId, accept: true });
};

window.triggerLinkJoin = (linkId) => {
    printLine('Processing invite link...', 'system-msg');
    socket.emit('group_use_link_req', linkId);
};

// A) FÜR ADMINS / OWNER / MODS (Reveal + Copy)
window.handleNameClick = (key) => {
    // 1. Visuelles Feedback (Input Fokus)
    const inputField = document.getElementById('command-input');
    inputField.focus();

    // --- NEU: Start-Text für den Identity Screen ---
    inputField.placeholder = "Type your identity...";
// -----------------------------------------------

    // 2. ID in die Zwischenablage kopieren (statt ins Input Feld!)
    navigator.clipboard.writeText(key).then(() => {
        // Kleines Feedback im Chat (nur lokal)
        printLine(`(i) COPIED ID TO CLIPBOARD: ${key}`, 'system-msg');
    }).catch(err => {
        console.error('Copy failed', err);
    });

    // 3. Server Anfrage: Wer ist das? (Nur für Berechtigte)
    socket.emit('ghost_reveal_req', key);
};

// B) FÜR NORMALE USER (Nur Copy, kein Reveal)
window.handleSimpleCopy = (key) => {
    // 1. Fokus
    document.getElementById('command-input').focus();

    // 2. Nur kopieren!
    navigator.clipboard.writeText(key).then(() => {
        printLine(`(i) COPIED ID: ${key}`, 'system-msg');
    }).catch(err => {
        console.error('Copy failed', err);
    });

    // KEIN socket.emit() -> Kein "Access Denied" Fehler mehr!
};

// WENN TAB GESCHLOSSEN ODER NEU GELADEN WIRD
window.addEventListener('beforeunload', () => {
    // 1. Anderen Tabs (Filesystem) sagen, sie sollen sterben
    lifeCycleChannel.postMessage({ type: 'MASTER_DISCONNECT' });

    // 2. Alle Daten löschen
    nukeSystem("exit");
});

function openFileSystem() {
    // Wir speichern unsere Identität kurz, damit die neue Seite weiß, wer wir sind
    if(!myUsername) {
        alert("ACCESS DENIED. Login required.");
        return;
    }
    // Speichern für die neue Seite
    localStorage.setItem('fs_username', myUsername);

    // Kleiner Sicherheitscheck, falls myKey noch undefined ist
    if (typeof myKey !== 'undefined') {
        localStorage.setItem('fs_key', myKey);
    }

    // WICHTIG: Das Fenster in der Variable speichern!
    // Du kannst auch Dimensionen angeben (z.B. 'width=950,height=700'),
    // dann öffnet es sich als schickes Popup statt als neuer Tab.
    fileShareWindow = window.open('/fileshare.html', '_blank');
}

function getDynamicName(name, key) {
    if (!key) return name;

    // --- STYLE CHECK (Institutionen) ---
    const instStyle = institutionStyles[key];
    let customStyle = 'cursor: pointer;'; // Immer klickbar jetzt

    if (instStyle) {
        customStyle += `color: ${instStyle.color}; text-shadow: 0 0 5px ${instStyle.color}; font-weight: bold;`;
    }

    // --- NEU: IMMER openUserPopup aufrufen ---
    // Wir übergeben 'event' damit wir wissen, wo die Maus ist
    const action = `window.openUserPopup(event, '${key}')`;

    // Ghost Prüfung für lokalen Namen (nur kosmetisch im Chat-Flow)
    let displayName = name;

    return `<span class="dynamic-name" style="${customStyle}" data-key="${key}" onclick="${action}">${displayName}</span>`;
}

// =============================================================================
// 1. CRYPTO ENGINE (WEB CRYPTO API)
// =============================================================================

async function generateKeyPair() {
    return window.crypto.subtle.generateKey(
        { name: "ECDH", namedCurve: "P-256" },
        true,
        ["deriveKey", "deriveBits"]
    );
}

async function exportPublicKey(key) {
    const exported = await window.crypto.subtle.exportKey("spki", key);
    return btoa(String.fromCharCode(...new Uint8Array(exported)));
}

async function importPublicKey(pem) {
    const binaryDer = Uint8Array.from(atob(pem), c => c.charCodeAt(0));
    return window.crypto.subtle.importKey(
        "spki",
        binaryDer,
        { name: "ECDH", namedCurve: "P-256" },
        true,
        []
    );
}

// Schlüssel aus Hex-String importieren (für Gruppen/Pubs)
async function importRoomKey(hexKey) {
    const rawBuffer = new Uint8Array(hexKey.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
    return window.crypto.subtle.importKey(
        "raw", rawBuffer, { name: "AES-GCM" }, true, ["encrypt", "decrypt"]
    );
}

// Shared Secret berechnen (P2P)
async function deriveSecretKey(privateKey, publicKeyPem) {
    const publicKey = await importPublicKey(publicKeyPem);
    return window.crypto.subtle.deriveKey(
        { name: "ECDH", public: publicKey },
        privateKey,
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );
}

async function encryptMessage(text, key) {
    if (!key) throw new Error("CRITICAL: No encryption key provided.");
    const enc = new TextEncoder();
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const payload = JSON.stringify({ msg: text, timestamp: Date.now() });

    const encryptedContent = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv }, key, enc.encode(payload)
    );

    return { iv: Array.from(iv), content: Array.from(new Uint8Array(encryptedContent)) };
}

async function decryptMessage(encryptedData, key) {
    try {
        if (!key) return "[NO KEY AVAILABLE]";
        const iv = new Uint8Array(encryptedData.iv);
        const content = new Uint8Array(encryptedData.content);

        const decryptedBuffer = await window.crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv }, key, content
        );
        const dec = new TextDecoder();
        const jsonString = dec.decode(decryptedBuffer);
        const payload = JSON.parse(jsonString);
        return payload.msg;
    } catch (e) {
        return "[DECRYPTION FAILED]";
    }
}

// =============================================================================
// 2. CHAT MANAGER & UI
// =============================================================================

function printToChat(chatId, text, className = '') {
    const targetId = myChats[chatId] ? chatId : 'LOCAL';
    const chat = myChats[targetId];

    const div = document.createElement('div');
    div.classList.add('line');
    if (className) div.classList.add(className);

    // --- FIX: innerHTML statt textContent ---
    // Damit unsere <span class="dynamic-name"> Tags funktionieren
    div.innerHTML = text;
    // ----------------------------------------

    // In History speichern
    chat.history.push(div.outerHTML);

    if (targetId === activeChatId) {
        output.appendChild(div);
        output.scrollTop = output.scrollHeight;
    } else {
        chat.unread++;
        renderChatList();
    }
}

// Wrapper für alten Code
function printLine(text, className = '') {
    printToChat(activeChatId, text, className);
}

// Wir fügen 'role' als optionalen Parameter hinzu
function registerChat(id, name, type, cryptoKey = null, role = 'MEMBER') {
    if (myChats[id]) {
        if (cryptoKey) myChats[id].key = cryptoKey;
        // Update Rolle falls vorhanden
        if (role !== 'MEMBER') myChats[id].role = role;
        return;
    }
    myChats[id] = {
        id: id,
        name: name,
        type: type,
        history: [],
        unread: 0,
        key: cryptoKey,
        role: role // <--- Speichern (MEMBER, MOD, OWNER)
    };
    renderChatList();
}

function switchChat(id) {

    if (!myUsername) {
        // Fokus zurück in das Namens-Feld zwingen
        document.getElementById('command-input').focus();
        return; // ABBRUCH: Funktion hier beenden!
    }
    // -----------------------------------------------

    // 1. Definition der Variable 'chat' (WICHTIG für den Fix)
    const chat = myChats[id];

    // Sicherheits-Check: Abbruch, wenn Chat nicht existiert (außer es ist LOCAL)
    if (id !== 'LOCAL' && !chat) return;

    // 2. State setzen
    activeChatId = id;
    viewMode = 'CHAT'; // Zwingt Ansicht zurück auf Chat (falls man aus Dashboard kommt)

    if (chat) chat.unread = 0;

    // 3. Input Feld zurücksetzen
    const inputField = document.getElementById('command-input');
    inputField.value = "";
    inputField.disabled = false;
    inputField.focus();


    // 4. Logik für Placeholder und Prompts

    // FALL A: HQ INBOX
    if (id === 'HQ_INBOX') {
        inputField.placeholder = "Search Secure Inbox...";

        if (window.isHqLoggedIn) {
            promptSpan.textContent = 'HQ/SEARCH>';
            promptSpan.className = 'prompt-error';
        }
    }
    // FALL B: LOCAL SHELL
    else if (id === 'LOCAL') {
        inputField.placeholder = "Enter command...";
        promptSpan.textContent = '>';
        promptSpan.className = 'prompt-default';
        appState = 'IDLE';
    }
    // FALL C: NORMALE CHATS (Variable 'chat' ist hier sicher vorhanden)
    else if (chat) {
        const pName = chat.name || chat.id;
        promptSpan.className = 'prompt-default';

        if (chat.type === 'group') {
            inputField.placeholder = `Message #${pName}...`;
            promptSpan.textContent = `group/${pName}>`;
            appState = 'GROUP_CHATTING';
        }
        else if (chat.type === 'pub') {
            inputField.placeholder = `Message Sector ${chat.id}...`;
            promptSpan.textContent = `PUB/${chat.id}>`;
            appState = 'PUB_CHATTING';
        }
        else {
            // Private
            inputField.placeholder = `Message ${pName}...`;
            promptSpan.textContent = `SECURE/${pName}>`;
            appState = 'CHATTING';
        }

        updateVoiceUI('idle');
    }

    // 5. Rendering
    renderChatList();

    output.innerHTML = '';

    // History laden (Fallback für LOCAL, falls kein Chat-Objekt existiert)
    const historySource = chat ? chat.history : (myChats['LOCAL'] ? myChats['LOCAL'].history : []);

    if (historySource) {
        historySource.forEach(html => {
            const div = document.createElement('div');
            div.innerHTML = html;
            output.appendChild(div);
        });
    }

    output.scrollTop = output.scrollHeight;
}

// Chat komplett aus dem Speicher löschen (Mit Voice-Cleanup)
function deleteChat(chatId) {
    // 1. Voice Cleanup: War das unser Gesprächspartner?
    if (currentVoiceTarget === chatId) {
        // Audio stoppen, aber ohne 'emit' (Verbindung ist eh weg)
        endAudioStream();
        currentVoiceTarget = null;
        updateVoiceUI('idle');
    }

    if (myChats[chatId]) {
        // Wenn wir gerade in diesem Chat sind -> Zurück zum Local Shell
        if (activeChatId === chatId) {
            switchChat('LOCAL');
        }

        // Daten vernichten
        delete myChats[chatId];

        // Sidebar updaten
        renderChatList();

        // Voice UI resetten falls nötig (doppelt hält besser)
        if (activeChatId === 'LOCAL') updateVoiceUI('idle');
    }
}

// HILFSFUNKTION: Generiert den exakten Anzeigenamen für einen Chat
// (Wird für Anzeige UND Suche genutzt -> 100% Übereinstimmung)
function getChatDisplayName(chat) {
    if (!chat) return '';

    // 1. Local Shell
    if (chat.id === 'LOCAL') return '> LOCAL_SHELL';

    // 2. Private Chats
    if (chat.type === 'private') return `[P2P] ${chat.name}`;

    // 3. Gruppen
    if (chat.type === 'group') return `${chat.name} [${chat.id}]`;

    // 4. Public Sektoren
    if (chat.type === 'pub') return `SECTOR ${chat.name}`;

    // Fallback
    return chat.name || 'UNKNOWN';
}

// HAUPTFUNKTION: Sidebar rendern & filtern
function renderChatList() {
    const listContainer = document.getElementById('chat-list');
    if (!listContainer) return;

    // 1. Suchbegriff holen
    const searchInput = document.getElementById('chat-search-input');
    const query = searchInput ? searchInput.value.toLowerCase().trim() : '';

    // listContainer leeren
    listContainer.innerHTML = '';

    // 2. FILTERN
    const allChats = Object.values(myChats).filter(chat => {
        const displayName = getChatDisplayName(chat).toLowerCase();
        const id = String(chat.id || '').toLowerCase();
        return displayName.includes(query) || id.includes(query);
    });

    // 3. KATEGORISIEREN (Hier fehlte 'internal')
    const buckets = {
        local: [],
        internal: [], // <--- NEU: Bucket für Internal Chats
        private: [],
        group: [],
        pub: []
    };

    allChats.forEach(chat => {
        if (chat.id === 'LOCAL' || chat.type === 'system') buckets.local.push(chat);
        // --- NEU: Check für Internal Chat ---
        else if (chat.type === 'hq_internal') buckets.internal.push(chat);
        // ------------------------------------
        else if (chat.type === 'private') buckets.private.push(chat);
        else if (chat.type === 'group') buckets.group.push(chat);
        else if (chat.type === 'pub') buckets.pub.push(chat);
    });

    // 4. SORTIEREN
    const sorter = (a, b) => (a.name || '').localeCompare(b.name || '');
    buckets.internal.sort(sorter);
    buckets.private.sort(sorter);
    buckets.group.sort(sorter);
    buckets.pub.sort(sorter);

    // 5. RENDER HELPER
    const renderSection = (title, chats) => {
        if (chats.length === 0) return;

        if (title) {
            const header = document.createElement('div');
            header.className = 'chat-category-header';
            header.innerText = title;
            listContainer.appendChild(header);
        }

        chats.forEach(chat => {
            const item = document.createElement('div');
            // Wichtig: internal Chats bekommen einen speziellen Look (optional)
            const extraClass = chat.type === 'hq_internal' ? 'chat-internal' : '';

            item.className = `chat-item ${extraClass} ${chat.id === activeChatId ? 'active' : ''}`;
            item.onclick = () => switchChat(chat.id);

            // Spezielles Icon für Internal
            let display = getChatDisplayName(chat);
            if (chat.type === 'hq_internal') display = `🛡️ ${display}`;

            item.innerHTML = `
                <span>${display}</span>
                <span class="unread-badge ${chat.unread > 0 ? 'visible' : ''}">!${chat.unread}</span>
            `;
            listContainer.appendChild(item);
        });
    };

    // 6. OUTPUT (Reihenfolge ist wichtig!)
    renderSection(null, buckets.local);
    renderSection('/// CLASSIFIED SQUAD', buckets.internal); // <--- HIER ANZEIGEN
    renderSection('/// DIRECT UPLINKS', buckets.private);
    renderSection('/// SECURE GROUPS', buckets.group);
    renderSection('/// PUBLIC SECTORS', buckets.pub);

    if (allChats.length === 0 && query !== '') {
        listContainer.innerHTML = '<div style="padding:15px; color:#444; font-size:0.8em; text-align:center;">NO SIGNALS FOUND</div>';
    }
}

// =============================================================================
// 3. BOOT SEQUENCE
// =============================================================================

const wait = (ms) => new Promise(resolve => setTimeout(resolve, ms));

function getSystemStats() {
    const ua = navigator.userAgent;
    let os = "UNKNOWN OS";
    let arch = "x86_64";
    if (ua.includes("Win")) os = "MICROSOFT WINDOWS NT";
    else if (ua.includes("Mac")) { os = "DARWIN / MACOS"; arch = "ARM64/x64"; }
    else if (ua.includes("Linux")) os = "LINUX KERNEL";
    else if (ua.includes("Android")) { os = "ANDROID SYSTEM"; arch = "ARMv8"; }
    else if (ua.includes("iPhone")) { os = "IOS SUBSYSTEM"; arch = "ARM64"; }

    const cores = navigator.hardwareConcurrency || 4;
    const ramGB = navigator.deviceMemory || 8;
    const ramKB = ramGB * 1024 * 1024;

    let engine = "GECKO";
    if (ua.includes("Chrome")) engine = "BLINK/V8";
    else if (ua.includes("Safari")) engine = "WEBKIT";

    return { os, cores, ramKB, res: `${window.screen.width}x${window.screen.height}`, engine, arch };
}

async function runBootSequence() {
    input.disabled = true;
    promptSpan.className = 'prompt-hidden';
    const stats = getSystemStats();
    const now = new Date();

    printLine(`BIOS DATE ${now.toLocaleDateString()} ${now.toLocaleTimeString()} VER 4.02`, 'system-msg');
    await wait(200);
    printLine(`DETECTED CPU: GEN-X ${stats.arch} (${stats.cores} LOGICAL CORES) ... OK`, 'system-msg');
    await wait(100);
    printLine(`MEMORY CHECK: ${stats.ramKB} KB OK`, 'system-msg');
    await wait(100);
    printLine(`VIDEO ADAPTER: GPU INTEGRATED GRAPHICS [${stats.res}] ... OK`, 'system-msg');
    await wait(200);

    const progressDiv = document.createElement('div');
    progressDiv.className = 'line system-msg';
    output.appendChild(progressDiv);

    for (let i = 0; i <= 100; i += 5) {
        const bars = '#'.repeat(Math.floor(i / 5)).padEnd(20, '.');
        progressDiv.textContent = `LOADING ${stats.os} KERNEL... [${bars}] ${i}%`;
        output.scrollTop = output.scrollHeight;
        await wait(10);
    }

    progressDiv.textContent = `LOADING ${stats.os} KERNEL... [####################] 100% COMPLETE`;
    await wait(200);
    printLine(`MOUNTING VIRTUAL FILESYSTEM (${stats.engine})...`, 'system-msg');
    await wait(200);
    printLine('SYSTEM READY.', 'system-msg');
    printLine(' ', '');
    printLine('⚠️  AUTHENTICATION REQUIRED  ⚠️', 'error-msg');
    printLine('Please enter your CODENAME to initialize uplink.', 'my-msg');

    promptSpan.textContent = 'IDENTITY>';
    promptSpan.className = 'prompt-error';
    document.getElementById('command-input').placeholder = "Type your identity...";
    input.disabled = false;
    input.focus();
    renderChatList(); // Sidebar initialisieren
}

// =============================================================================
// 4. INPUT & COMMAND HANDLER (PERFORMANCE ENGINE)
// =============================================================================

function updateMirror() {
    const inp = document.getElementById("command-input");
    const mirror = document.getElementById("cmd-mirror");

    if (!inp || !mirror) return;

    const val = inp.value;

    // --- INTELLIGENTE CURSOR POSITION ---
    let cursorPos = inp.selectionStart;

    // Regel 1: Wenn wir von Links nach Rechts markieren -> Nimm das Ende
    if (inp.selectionDirection === 'forward') {
        cursorPos = inp.selectionEnd;
    }

    // Regel 2 (Der Cmd+A Fix): Wenn ALLES markiert ist, setze Cursor ans Ende
    if (inp.selectionStart === 0 && inp.selectionEnd === val.length && val.length > 0) {
        cursorPos = inp.selectionEnd;
    }
    // ------------------------------------

    // HTML Bauen
    const left = val.slice(0, cursorPos);
    const charAtCursor = val.charAt(cursorPos) || ' ';
    const right = val.slice(cursorPos + 1);

    const escapeHTML = (str) => str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

    const cursorHTML = `<span class="cursor-block">${escapeHTML(charAtCursor)}</span>`;
    mirror.innerHTML = escapeHTML(left) + cursorHTML + escapeHTML(right);
}

// Event Listeners aktivieren
const inputField = document.getElementById('command-input');

if (inputField) {

    // --- A) DER SMART RENDER LOOP (VISUALS) ---
    // Ersetzt alle mousemove/click/select Events für maximale Performance
    let lastState = { val: '', start: -1, end: -1, dir: '' };

    function cursorLoop() {
        if (document.activeElement === inputField) {
            const currentVal = inputField.value;
            const currentStart = inputField.selectionStart;
            const currentEnd = inputField.selectionEnd;
            const currentDir = inputField.selectionDirection;

            const hasChanged =
                currentVal !== lastState.val ||
                currentStart !== lastState.start ||
                currentEnd !== lastState.end ||
                currentDir !== lastState.dir;

            if (hasChanged) {
                updateMirror();
                lastState = { val: currentVal, start: currentStart, end: currentEnd, dir: currentDir };
            }
        }
        requestAnimationFrame(cursorLoop);
    }
    cursorLoop(); // Starten

    // --- B) INPUT EVENT (LOGIK: Auto-Grow & History Reset) ---
    inputField.addEventListener('input', (e) => {
        // Auto-Grow
        inputField.style.height = 'auto';
        inputField.style.height = (inputField.scrollHeight) + 'px';
        if (inputField.value === '') inputField.style.height = 'auto';

        // History Reset (nur beim Chatten)
        if (e.isTrusted && viewMode !== 'BLOG' && viewMode !== 'WIRE') {
            historyIndex = commandHistory.length;
        }

        // Live Search für Blog
        if (viewMode === 'BLOG') {
            filterBlogPosts(inputField.value);
        }

        // --- NEU: LIVE FILTER FÜR WIRE ---
        if (viewMode === 'WIRE') {
            const term = inputField.value.toLowerCase().trim();

            if (!term) {
                // Wenn leer -> Zeige alles (Cache)
                renderWireFeed(wireFeedCache);
                return;
            }

            // Filtern
            const filtered = wireFeedCache.filter(p => {
                return p.content.toLowerCase().includes(term) ||
                    p.authorName.toLowerCase().includes(term) ||
                    p.tags.some(t => t.toLowerCase().includes(term));
            });
            renderWireFeed(filtered);
        }
        // --------------------------------
    });

    // --- C) KEYDOWN EVENT (AKTIONEN: Senden & History) ---
    inputField.addEventListener('keydown', async (e) => {

        // BLOG & WIRE MODE: Enter blockieren (Suche ist live)
        if (viewMode === 'BLOG' || viewMode === 'WIRE') {
            if (e.key === 'Enter') e.preventDefault(); // Nichts tun
            return;
        }

        // SENDEN (Enter)
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();

            // INBOX INPUT SPERREN
            if (activeChatId === 'HQ_INBOX') return;

            const val = inputField.value.trim();
            if (val) {
                commandHistory.push(val);
                historyIndex = commandHistory.length;

                inputField.value = '';
                inputField.style.height = 'auto';

                // Wir erzwingen ein Update für den Loop
                lastState.val = '';
                updateMirror();

                if (!appState.startsWith('DECIDING')) {
                    // Echo lokal
                    const safeVal = val.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
                    const displayVal = safeVal.replace(/\n/g, '<br>');
                    printLine(`> ${displayVal}`, 'my-msg');
                }
                await handleInput(val);
            } else {
                inputField.value = '';
                updateMirror();
            }
        }
        // HISTORY HOCH
        else if (e.key === 'ArrowUp') {
            if (inputField.value === '' || historyIndex !== commandHistory.length) {
                if (historyIndex > 0) {
                    e.preventDefault();
                    historyIndex--;
                    inputField.value = commandHistory[historyIndex];
                    // Cursor ans Ende setzen (Trick für den Loop)
                    setTimeout(() => {
                        inputField.selectionStart = inputField.selectionEnd = inputField.value.length;
                    }, 0);
                }
            }
        }
        // HISTORY RUNTER
        else if (e.key === 'ArrowDown') {
            if (inputField.value === '' || historyIndex !== commandHistory.length) {
                if (historyIndex < commandHistory.length - 1) {
                    historyIndex++;
                    inputField.value = commandHistory[historyIndex];
                } else {
                    historyIndex = commandHistory.length;
                    inputField.value = '';
                }
            }
        }
    });

    // Initialer Aufruf
    setTimeout(updateMirror, 100);
}

async function handleInput(text) {

    // --- NEU: ADMIN LOGIN FLOW ---
    if (appState === 'ADMIN_PASS') {
        if (text === 'cancel') {
            printLine('Admin login aborted.', 'system-msg');
            appState = 'IDLE';
            promptSpan.textContent = '>';
            promptSpan.className = 'prompt-default';
            return;
        }
        // Passwort an Server senden
        printLine('Verifying credentials...', 'system-msg');
        socket.emit('admin_verify_pass', text);
        return;
    }

    if (appState === 'ADMIN_2FA') {
        if (text === 'cancel') {
            printLine('Admin login aborted.', 'system-msg');
            appState = 'IDLE';
            promptSpan.textContent = '>';
            promptSpan.className = 'prompt-default';
            return;
        }
        // 2FA Code an Server senden
        socket.emit('admin_verify_2fa', text);
        return;
    }
    // -----------------------------

    if (appState === 'BOOTING') {
        // 1. SOFORT-CHECK: Ist der Name gültig?
        if (text.startsWith('/') || text.trim().length === 0 || text.length > 20) {
            printLine('ERROR: Invalid format. No "/" allowed at start.', 'error-msg');
            printLine('Please try another CODENAME.', 'my-msg');
            return; // Wir brechen ab und bleiben im BOOTING Modus!
        }

        // --- NEU: RESERVIERTER NAME ---
        if (text.toLowerCase() === 'anonymous') {
            printLine('ERROR: "Anonymous" is a reserved system designation.', 'error-msg');
            printLine('Identity spoofing is strictly prohibited.', 'system-msg');
            return;
        }
        // -----------------------------

        // 2. Wenn okay, Anfrage senden
        myUsername = text;
        myKeyPair = await generateKeyPair();
        socket.emit('register', myUsername);

        switchChat('LOCAL');

        printLine('Authenticating...', 'system-msg');

        // WICHTIG: Wir setzen appState HIER NICHT auf 'IDLE'!
        // Wir warten, bis der Server uns das 'registered' Event schickt.
        // Solange bleibt der User im "Eingabe"-Modus für den Namen.
        return;
    }

    // --- SETUP WIZARD ---
    if (appState === 'SETUP_TAG') {
        if (text.trim()) socket.emit('setup_step_tag', text.trim());
        return;
    }
    if (appState === 'SETUP_PASS') {
        if (text.trim()) socket.emit('setup_step_pass', text.trim());
        return; // Verhindert, dass Passwort im Terminal-Verlauf bleibt
    }
    if (appState === 'SETUP_2FA_VERIFY') {
        if (text.trim()) socket.emit('setup_step_2fa_verify', text.trim());
        return;
    }

    // --- WIZARD: REQUEST INSTITUTION ---
    if (appState === 'REQ_NAME') {
        if (text.trim()) {
            requestData.name = text.trim();
            appState = 'REQ_TAG';
            printLine('2. Enter Official Agency ID (TAG) [e.g. CIA]:', 'system-msg');
            promptSpan.textContent = 'TAG>';
        }
        return;
    }
    if (appState === 'REQ_TAG') {
        if (text.trim()) {
            requestData.tag = text.trim().toUpperCase();
            appState = 'REQ_MSG';
            printLine('3. Enter Application Message (Reason for access):', 'system-msg');
            promptSpan.textContent = 'MSG>';
        }
        return;
    }
    if (appState === 'REQ_MSG') {
        if (text.trim()) {
            requestData.msg = text.trim();
            appState = 'REQ_EMAIL';
            printLine('4. Enter Contact Email (for secure verification):', 'system-msg');
            promptSpan.textContent = 'EMAIL>';
        }
        return;
    }
    if (appState === 'REQ_EMAIL') {
        if (text.trim()) {
            requestData.email = text.trim();
            printLine('Submitting application packet...', 'system-msg');
            // Alles absenden
            socket.emit('register_request_submit', requestData);

            // Reset
            appState = 'IDLE';
            promptSpan.textContent = '>';
            requestData = {};
        }
        return;
    }

    // --- WIZARD: SETUP (Erweitert) ---
    if (appState === 'SETUP_CONFIRM') {
        socket.emit('setup_step_confirm', text.trim());
        return;
    }
    if (appState === 'SETUP_EDIT_NAME') {
        socket.emit('setup_step_edit_name', text.trim());
        return;
    }
    if (appState === 'SETUP_EDIT_TAG') {
        socket.emit('setup_step_edit_tag', text.trim());
        return;
    }
    if (appState === 'SETUP_DESC') {
        socket.emit('setup_step_desc', text.trim());
        return;
    }

    // --- AUTH FLOW: PASSWORT EINGABE ---
    if (appState === 'AUTH_PASS') {
        if (text === 'cancel') {
            printLine('Authentication aborted.', 'system-msg');
            appState = 'IDLE';
            promptSpan.textContent = promptSpan.getAttribute('data-prev-prompt') || '>';
            promptSpan.className = 'prompt-default';
            return;
        }
        // Passwort senden (Visuell sieht man es leider im Terminal,
        // für echte Sicherheit könnte man input.type='password' toggeln,
        // aber das bricht den Terminal-Look. Wir lassen es textbasiert für den Hack-Vibe.)
        socket.emit('auth_verify_pass', text);
        // Wir bleiben im State, bis Server antwortet
        return;
    }

    // --- AUTH FLOW: 2FA EINGABE ---
    if (appState === 'AUTH_2FA') {
        if (text === 'cancel') {
            printLine('Authentication aborted.', 'system-msg');
            appState = 'IDLE';
            promptSpan.textContent = promptSpan.getAttribute('data-prev-prompt') || '>';
            promptSpan.className = 'prompt-default';
            return;
        }
        socket.emit('auth_verify_2fa', text);
        return;
    }

    // --- NEU: GROUP EXIT DECISION ---
    if (appState === 'DECIDING_GROUP_EXIT') {
        const args = text.split(' ');
        const choice = args[0].toLowerCase();

        if (choice === 'close') {
            socket.emit('group_owner_action', { action: 'close' });
        }
        else if (choice === 'random') {
            socket.emit('group_owner_action', { action: 'transfer', target: 'random' });
        }
        else if (choice === 'transfer') {
            if (args[1]) {
                socket.emit('group_owner_action', { action: 'transfer', target: args[1] });
            } else {
                printLine('USAGE: transfer [USER_KEY]', 'error-msg');
                return;
            }
        }
        else if (choice === 'cancel') {
            printLine('Aborted.', 'system-msg');
            appState = 'GROUP_CHATTING'; // Zurück zum Chat-Modus
            // Prompt wiederherstellen
            const oldPrompt = promptSpan.getAttribute('data-prev-prompt');
            if (oldPrompt) promptSpan.textContent = oldPrompt;
            promptSpan.className = 'prompt-default';
            return;
        }
        else {
            printLine('Invalid option. Type: close, random, transfer [KEY], or cancel.', 'error-msg');
            return;
        }

        // Wenn wir hier sind, wurde ein Befehl gesendet -> UI Reset
        appState = 'IDLE'; // Wird gleich durch group_left_success korrigiert oder wir landen in Local
        promptSpan.textContent = '>';
        promptSpan.className = 'prompt-default';
        return;
    }

    // --- GROUP PASSWORD ENTRY (Retry Fix) ---
    if (appState === 'ENTERING_GROUP_PASSWORD') {
        // User hat Passwort getippt (oder Abbruch)
        if (text === 'cancel') {
            printLine('Join aborted.', 'system-msg');
            pendingJoinGroupId = null;
            appState = 'IDLE';
            promptSpan.textContent = '>';
            promptSpan.className = 'prompt-default';
        } else {
            // Passwort an Server senden
            printLine('Verifying credentials...', 'system-msg');
            socket.emit('group_join_with_password', {
                groupId: pendingJoinGroupId,
                password: text
            });

            // WICHTIG: Wir bleiben hier im State 'ENTERING_GROUP_PASSWORD'!
            // Wir löschen NICHTS. Der Prompt bleibt 'PASSWORD>'.
            // Der User kann sofort nochmal tippen, falls eine Fehlermeldung kommt.
        }
        return;
    }

    // --- NEU: KICK DIALOG ZUSTÄNDE ---

    // 1. Frage: Grund hinzufügen? (y/n)
    if (appState === 'DECIDING_KICK_YN') {
        const choice = text.toLowerCase();

        if (choice === 'y' || choice === 'yes') {
            appState = 'ENTERING_KICK_REASON';
            printLine(' ', '');
            printLine('Please enter the reason for expulsion:', 'system-msg');
            promptSpan.textContent = 'REASON>';
        }
        else if (choice === 'n' || choice === 'no') {
            // Kicken ohne Grund
            socket.emit('group_kick_req', { targets: pendingKickTargets, reason: null });

            // Reset
            pendingKickTargets = [];
            appState = 'GROUP_CHATTING'; // oder IDLE
            promptSpan.textContent = promptSpan.getAttribute('data-prev-prompt') || '>';
            promptSpan.className = 'prompt-default';
        }
        else {
            printLine('Invalid input. Type [y]es or [n]o.', 'error-msg');
        }
        return;
    }

    // 2. Eingabe: Der Grund
    if (appState === 'ENTERING_KICK_REASON') {
        if (text.trim().length === 0) {
            printLine('Reason cannot be empty. Type a reason or "cancel".', 'error-msg');
            return;
        }
        if (text === 'cancel') {
            printLine('Kick aborted.', 'system-msg');
            pendingKickTargets = [];
        } else {
            // Kicken MIT Grund
            socket.emit('group_kick_req', { targets: pendingKickTargets, reason: text });
        }

        // Reset
        appState = 'GROUP_CHATTING'; // oder IDLE
        promptSpan.textContent = promptSpan.getAttribute('data-prev-prompt') || '>';
        promptSpan.className = 'prompt-default';
        return;
    }

    // --- ADMIN KICK WIZARD ---

    // 1. SCHRITT: Bestätigung (Y/N)
    if (appState === 'ADMIN_KICK_CONFIRM') {
        const c = text.toLowerCase();
        if (c === 'y' || c === 'yes') {
            appState = 'ADMIN_KICK_ACTION';
            printLine(' ', '');
            printLine('⚠ AUTHORITY TRANSFER REQUIRED ⚠', 'error-msg');
            printLine('Choose action:', 'system-msg');
            printLine('  [1] dissolve  -> Delete group completely.', 'system-msg');
            printLine('  [2] transfer  -> Appoint new Owner.', 'system-msg');
            printLine('  [3] cancel    -> Abort.', 'system-msg');
            promptSpan.textContent = 'ACTION>';
        } else {
            printLine('Admin override aborted.', 'system-msg');
            appState = 'IDLE'; // oder GROUP_CHATTING
            promptSpan.textContent = promptSpan.getAttribute('data-prev-prompt') || '>';
            promptSpan.className = 'prompt-error'; // Admin Farbe behalten
        }
        return;
    }

    // 2. SCHRITT: Aktion wählen (Dissolve/Transfer)
    if (appState === 'ADMIN_KICK_ACTION') {
        const c = text.toLowerCase();

        if (c === 'dissolve') {
            // Sofortige Vernichtung
            socket.emit('admin_complete_owner_kick', {
                targetKey: adminKickTargetKey,
                action: 'dissolve'
            });
            appState = 'IDLE';
            promptSpan.textContent = promptSpan.getAttribute('data-prev-prompt');
        }
        else if (c === 'transfer') {
            // Weiter zu Schritt 3
            appState = 'ADMIN_KICK_TRANSFER_MODE';
            printLine(' ', '');
            printLine('SELECT SUCCESSOR:', 'system-msg');
            printLine('  [1] random          -> Prioritizes Mods, then Members.', 'system-msg');
            printLine('  [2] specific [KEY]  -> Define ID manually.', 'system-msg');
            promptSpan.textContent = 'SUCCESSOR>';
        }
        else if (c === 'cancel') {
            printLine('Aborted.', 'system-msg');
            appState = 'IDLE';
            promptSpan.textContent = promptSpan.getAttribute('data-prev-prompt');
        }
        else {
            printLine('Invalid action. Type: dissolve, transfer, or cancel.', 'error-msg');
        }
        return;
    }

    // 3. SCHRITT: Nachfolger bestimmen
    if (appState === 'ADMIN_KICK_TRANSFER_MODE') {
        const args = text.split(' ');
        const mode = args[0].toLowerCase();

        if (mode === 'random') {
            socket.emit('admin_complete_owner_kick', {
                targetKey: adminKickTargetKey,
                action: 'transfer',
                method: 'random'
            });
            appState = 'IDLE'; // Reset
            promptSpan.textContent = promptSpan.getAttribute('data-prev-prompt');
        }
        else if (mode === 'specific' || mode === 's') { // Allow shortcut 's'
            if (args[1]) {
                socket.emit('admin_complete_owner_kick', {
                    targetKey: adminKickTargetKey,
                    action: 'transfer',
                    method: 'specific',
                    newOwnerKey: args[1]
                });
                appState = 'IDLE'; // Reset
                promptSpan.textContent = promptSpan.getAttribute('data-prev-prompt');
            } else {
                printLine('USAGE: specific [USER_KEY]', 'error-msg');
            }
        }
        else {
            printLine('Invalid selection. Type: random OR specific [KEY]', 'error-msg');
        }
        return;
    }

    // --- DECISION MODES ---
    if (appState === 'DECIDING_OWNER_KICK') {
        const args = text.split(' ');
        if (text === 'r' || text === 'random') {
            socket.emit('group_admin_resolve_owner', { mode: 'random', oldOwnerKey: currentKickTarget });
        } else if (args[0] === 's' || args[0] === 'specific') {
            socket.emit('group_admin_resolve_owner', { mode: 'specific', oldOwnerKey: currentKickTarget, newOwnerKey: args[1] });
        } else if (text === 'cancel') {
            printLine('Aborted.', 'system-msg');
        }
        appState = 'CHATTING'; // Fallback state
        promptSpan.textContent = promptSpan.getAttribute('data-prev-prompt');
        return;
    }

    // --- COMMANDS ---
    if (text.startsWith('/')) {
        const args = text.split(' ');
        const cmd = args[0].toLowerCase();

        if (cmd === '/connect') {
            if (args[1]) {
                const targetKey = args[1];
                printLine(`Initiating handshake protocol with Node [${targetKey}]...`, 'system-msg');

                // 1. Ephemeren Schlüssel generieren
                const ephemeralKeyPair = await generateKeyPair();
                const pubKeyPem = await exportPublicKey(ephemeralKeyPair.publicKey);

                // --- FIX: Wir speichern jetzt BEIDES (Private Key & Public String) ---
                // Damit wir später wissen, mit welchem "Gesicht" wir uns vorgestellt haben.
                outgoingConnects[targetKey] = {
                    privateKey: ephemeralKeyPair.privateKey,
                    publicKeyString: pubKeyPem
                };
                // --------------------------------------------------------------------

                // Senden
                socket.emit('request_connection', {
                    targetKey: targetKey,
                    publicKey: pubKeyPem
                });
            } else {
                printLine('USAGE: /connect [TARGET_KEY]', 'error-msg');
            }
        }
        else if (cmd === '/accept') {
            const targetKey = args[1]; // Wir nutzen den Key aus dem Button/Anfrage

            if (targetKey && pendingRequests[targetKey]) {
                const reqData = pendingRequests[targetKey];
                printLine(`Handshaking with ${reqData.username}...`, 'system-msg');

                // 1. Keys generieren
                myKeyPair = await generateKeyPair();

                // 2. Secret berechnen und ZWISCHENSPEICHERN (Nicht registrieren!)
                tempDerivedKey = await deriveSecretKey(myKeyPair.privateKey, reqData.publicKey);
                window.tempPartnerPubKeyString = reqData.publicKey;

                // 3. Dem Server antworten
                const myPubKeyPem = await exportPublicKey(myKeyPair.publicKey);

                socket.emit('respond_connection', {
                    requesterId: reqData.socketId,
                    accepted: true,
                    publicKey: myPubKeyPem
                });

                // Aufräumen
                delete pendingRequests[targetKey];

                // WICHTIG: Hier KEIN registerChat() und KEIN switchChat()!
                // Wir warten geduldig auf 'chat_start'.
            } else {
                printLine('ERROR: No pending request found.', 'error-msg');
            }
        }
        else if (cmd === '/deny') {
            const targetKey = args[1];
            if (targetKey && pendingRequests[targetKey]) {
                socket.emit('respond_connection', {
                    requesterId: pendingRequests[targetKey].socketId,
                    accepted: false
                });
                printLine('Connection request denied.', 'system-msg');
                delete pendingRequests[targetKey];
            }
        }
     // Universeller LEAVE Befehl
     else if (cmd === '/leave') {
         const currentChat = myChats[activeChatId];

         if (currentChat.type === 'private') {
             // 1. Voice Check: Sind wir im Call mit diesem Chat?
             if (currentVoiceTarget === currentChat.id) {
                 printLine('>>> TERMINATING AUDIO UPLINK BEFORE EXIT...', 'error-msg');
                 // Wir senden ein Hangup-Signal und stoppen lokal
                 socket.emit('voice_hangup', { targetKey: currentChat.id });
                 endAudioStream();
                 currentVoiceTarget = null;
             }

             // 2. Chat verlassen
             printLine('Terminating secure connection...', 'system-msg');
             socket.emit('private_leave', currentChat.id);
         }
         else if (currentChat.type === 'group') {
             printLine('Leaving group...', 'system-msg');
             socket.emit('group_leave');
         }
         else if (currentChat.type === 'pub') {
             printLine('Disconnecting from sector...', 'system-msg');
             socket.emit('pub_leave');
         }
         else {
             printLine('ERROR: Nothing to leave here (LOCAL mode).', 'error-msg');
         }
     }
        // --- WHISPER COMMAND (ENCRYPTED) ---
        else if (cmd === '/whisper') {
            // Format: /whisper [TARGET_KEY] [MESSAGE]
            const targetKey = args[1];
            const msgRaw = args.slice(2).join(' ');

            if (targetKey && msgRaw) {

                // 1. Prüfen: Sind wir in einem sicheren Raum?
                const currentChat = myChats[activeChatId];

                if (!currentChat || !currentChat.key) {
                    printLine('ERROR: Encryption key not found. Cannot whisper securely.', 'error-msg');
                    return;
                }

                // 2. Nachricht mit dem RAUM-KEY verschlüsseln
                // (So kann sie nur jemand lesen, der auch im Raum ist + der Empfänger)
                printLine('Encrypting whisper signal...', 'system-msg');

                // Da encryptMessage async ist, müssen wir hier warten.
                // Aber handleInput ist bereits async, also geht 'await'.
                // Wir fangen Fehler ab:
                try {
                    const encryptedObj = await encryptMessage(msgRaw, currentChat.key);

                    // 3. Senden (Das Objekt, nicht den Text!)
                    socket.emit('room_whisper_req', {
                        targetKey: targetKey,
                        message: encryptedObj // <--- Verschlüsseltes Paket
                    });

                } catch (e) {
                    console.error(e);
                    printLine('ERROR: Encryption failed.', 'error-msg');
                }

            } else {
                printLine('USAGE: /whisper [USER_ID] [MESSAGE]', 'error-msg');
            }
        }

        else if (cmd === '/auth') {
            const param = args[1]; // Das Argument nach /auth

            if (!param) {
                printLine('USAGE: /auth [INSTITUTION_TAG]', 'error-msg');
                return;
            }

            // WICHTIG: Keine Regex-Prüfung mehr!
            // /auth ist JETZT NUR NOCH für Institutionen.
            printLine(`Connecting to secure gateway [${param.toUpperCase()}]...`, 'system-msg');
            socket.emit('auth_init', param);
        }

        // --- ADMIN COMMANDS ---
        else if (cmd === '/admin') {
            const sub = args[1];

            if (sub === 'auth') {
                printLine(' ', '');
                printLine('⚠️  SYSTEM ADMINISTRATOR ACCESS  ⚠️', 'error-msg');
                printLine('Enter Master Password:', 'system-msg');

                appState = 'ADMIN_PASS';
                promptSpan.textContent = 'ADMIN-PASS>';
                promptSpan.className = 'prompt-error';
                return;
            }

            else if (sub === 'requests') {
                printLine('Fetching pending applications...', 'system-msg');
                socket.emit('admin_list_requests');
            }
            else if (sub === 'approve') {
                const id = args[2];
                if (!id) {
                    printLine('USAGE: /admin approve [REQUEST_ID]', 'error-msg');
                    return;
                }
                printLine(`Authorizing Request ID [${id}]...`, 'system-msg');
                socket.emit('admin_approve_request', args[2]);
            }
            // Deine alten Befehle (ban, broadcast) kannst du hier lassen...
            else if (sub === 'broadcast') {
                socket.emit('admin_broadcast', args.slice(2).join(' '));
            }
            else {
                printLine('ADMIN TOOLS: auth, requests, approve [ID], broadcast [MSG]', 'system-msg');
            }
        }

     // --- ADMIN BAN HAMMER ---
     else if (cmd === '/ban') {
         const targets = args.slice(1); // Alle IDs nach /ban
         if (targets.length > 0) {
             printLine(`Initializing ban protocol for ${targets.length} targets...`, 'system-msg');
             socket.emit('admin_ban', targets);
         } else {
             printLine('USAGE: /ban [ID] [ID] ...', 'error-msg');
         }
     }

     // --- ADMIN GLOBAL BROADCAST ---
     else if (cmd === '/broadcast') {
         const msg = args.slice(1).join(' ');
         if (msg) {
             socket.emit('admin_broadcast', msg);
         } else {
             printLine('USAGE: /broadcast [MESSAGE]', 'error-msg');
         }
     }
        else if (cmd === '/ping') {
            socket.emit('ping_request', args[1] || '');
        }
        else if (cmd === '/nudge') {
            socket.emit('send_nudge', args[1]);
        }
        else if (cmd === '/info') {
            socket.emit('info_request', args[1]);
        }
     else if (cmd === '/safety') {
         if (!activeChatId || activeChatId === 'LOCAL' || myChats[activeChatId].type !== 'private') {
             printLine("ERROR: Safety Numbers are only available in private P2P chats.", "error-msg");
             return;
         }

         const chat = myChats[activeChatId];
         // Wir generieren die Nummer aus den gespeicherten Strings
         const safetyNum = await generateSafetyNumber(chat.myPublicKeyString, chat.partnerPublicKeyString);

         printLine("------------------------------------------------", "system-msg");
         printLine("🔐 SECURITY FINGERPRINT (SAFETY NUMBER)", "success-msg");
         printLine("Compare this number with your partner (e.g. via Phone):", "system-msg");
         printLine(safetyNum, "highlight-msg");
         printLine("If it matches, the connection is secure (No Man-in-the-Middle).", "system-msg");
         printLine("------------------------------------------------", "system-msg");
     }
    // --- GHOST MODE ---
    else if (cmd === '/ghost') {
        printLine('Initiating Stealth Protocols...', 'system-msg');
        socket.emit('toggle_ghost');
    }

     // --- GHOST SCANNER ---
     else if (cmd === '/scan') {
         printLine('Initiating spectral scan...', 'system-msg');
         socket.emit('ghost_scan_req');
     }

        else if (cmd === '/group') {
            const sub = args[1];
             if (sub === 'create') {
                 // Wir nehmen alle Wörter nach 'create' und bauen sie zu einem String zusammen
                 const groupName = args.slice(2).join(' ');

                 // Wir senden jetzt ein Objekt an den Server (wie vorhin besprochen)
                 socket.emit('group_create', {
                     name: groupName,
                     invites: [] // Invites lassen wir hier leer, dafür gibt es /group invite
                 });
             }
            else if (sub === 'join') socket.emit('group_join_req', args[2]);
            else if (sub === 'leave') socket.emit('group_leave');
            else // --- KICK BEFEHL (Preview Update) ---
            if (sub === 'kick') {
                const targets = args.slice(2);
                if (targets.length > 0) {
                    // WICHTIG: Wir speichern die IDs noch nicht endgültig und starten noch keinen Dialog.
                    // Wir fragen erst den Server nach den Namen.
                    printLine('Locating targets...', 'system-msg');
                    socket.emit('group_kick_preview_req', targets);
                } else {
                    printLine('USAGE: /group kick [ID] [ID] ...', 'error-msg');
                }
            }
            else if (sub === 'invite') socket.emit('group_invite_req', args.slice(2));
            else if (sub === 'open') socket.emit('group_toggle_privacy', true);
            else if (sub === 'close') socket.emit('group_toggle_privacy', false);
            else if (sub === 'rename') socket.emit('group_rename', args.slice(2).join(' '));
            else if (sub === 'promote') socket.emit('group_promote', args.slice(2).join(' '));
            else if (sub === 'dissolve') socket.emit('group_dissolve');
            else if (sub === 'accept') socket.emit('group_decision', { targetKey: args[2], accept: true });
            else if (sub === 'list') socket.emit('group_list_req');
            else if (sub === 'link') {
                // Syntax: /group link [GROUP_ID] [LIMIT]
                const groupId = args[2];
                const limit = args[3] || 0; // Optional

                if (!groupId) {
                    printLine('USAGE: /group link [GROUP_ID] [OPTIONAL_LIMIT]', 'error-msg');
                } else {
                    // Wir senden die ID des Chats mit, in dem wir gerade sind!
                    socket.emit('group_create_link_req', {
                        groupId: groupId,
                        limit: limit,
                        targetRoomId: activeChatId // <--- WICHTIG: Damit der Server weiß wohin
                    });
                }
            }
            else if (sub === 'password') {
                // /group password [PW]
                const pw = args[2]; // Kann leer sein (zum Löschen)
                socket.emit('group_set_password', pw);
            }
            else if (sub === 'broadcast') {
                // Alles nach "broadcast" ist die Nachricht
                const msg = args.slice(2).join(' ');
                if (msg) {
                    socket.emit('group_broadcast', msg);
                } else {
                    printLine('USAGE: /group broadcast [MESSAGE]', 'error-msg');
                }
            }

            // ... (andere /group befehle) ...

            else if (sub === 'accept') {
                // Check: Ist es eine Zahl? Dann ist es eine Gruppen-ID (Einladung annehmen)
                // Ist es ein String? Dann ist es ein User-Key (Owner akzeptiert User)
                const param = args[2];
                if (!isNaN(parseInt(param))) {
                    // Es ist eine Zahl -> Wir nehmen eine Gruppeneinladung an
                    socket.emit('group_decision', { groupId: param, accept: true });
                } else {
                    // Es ist ein String -> Wir (als Owner) lassen jemanden rein
                    socket.emit('group_decision', { targetKey: param, accept: true });
                }
            }
            else if (sub === 'deny') {
                const param = args[2];
                if (!isNaN(parseInt(param))) {
                    socket.emit('group_decision', { groupId: param, accept: false });
                } else {
                    socket.emit('group_decision', { targetKey: param, accept: false });
                }
            }
        }
     // --- MOD SHORTCUT ---
     else if (cmd === '/mod') {
         if (args[1]) {
             // FIX: Sende an 'group_user_promote' statt 'group_promote'
             socket.emit('group_user_promote', args[1]);
         } else {
             printLine('USAGE: /mod [USER_KEY]', 'error-msg');
         }
     }
        else if (cmd === '/pub') {
            const sub = args[1];
            if (sub === 'create') socket.emit('pub_create', args.slice(2).join(' '));
            else if (sub === 'join') socket.emit('pub_join', args[2]);
            else if (sub === 'list') socket.emit('pub_list_request');
            else if (sub === 'leave') socket.emit('pub_leave');
            else if (sub === 'whisper') socket.emit('pub_whisper', { targetKey: args[2], message: args.slice(3).join(' ') });
        }
        else if (cmd === '/drop') {
            const sub = args[1];
            if (sub === 'create') {
                let timer = parseInt(args[2]) || 5;
                let msg = !isNaN(parseInt(args[2])) ? args.slice(3).join(' ') : args.slice(2).join(' ');
                socket.emit('drop_create', { message: msg, timer });
            } else if (sub === 'pickup') socket.emit('drop_pickup', args[2]);
        }
        // --- SECURE DROP (INFORMANT) ---
        else if (cmd === '/tip') {
            // Format: /tip [TARGET_ID] [MESSAGE]
            const target = args[1]; // z.B. MI6
            const msg = args.slice(2).join(' ');

            if (!target || !msg) {
                printLine('USAGE: /tip [MI6|CIA] [MESSAGE]', 'error-msg');
                return;
            }

            printLine(`Establishing secure uplink to ${target.toUpperCase()}...`, 'system-msg');

            // Key anfordern
            socket.emit('hq_get_key_req', target.toUpperCase());

            // Merken was wir senden wollten
            window.pendingTip = { target: target.toUpperCase(), msg: msg };
        }

        // --- LIST COMMAND CENTER ---
        else if (cmd === '/list') {
            const sub = args[1]; // Das Wort nach /list

            // 1. INSTITUTIONEN
            if (sub === 'institutions' || sub === 'inst') {
                printLine('Accessing global secure registry...', 'system-msg');
                socket.emit('list_institutions_req');
            }

                // HIER KANNST DU SPÄTER ANDERE LISTEN HINZUFÜGEN:
                // else if (sub === 'groups') socket.emit('group_list_req');
            // else if (sub === 'pubs') socket.emit('pub_list_request');

            else {
                printLine('USAGE: /list institutions', 'error-msg');
                // printLine('       /list groups', 'error-msg'); // Wenn du das später umziehst
            }
        }

        // --- HQ LOGIN & DASHBOARD ---
        else if (cmd === '/hq') {
            const sub = args[1];
            if (sub === 'broadcast') {
                // Prüfen ob eingeloggt
                if (!window.isHqLoggedIn) {
                    printLine('ACCESS DENIED. Log in first.', 'error-msg');
                    return;
                }

                // Nachricht extrahieren (alles nach "/hq broadcast")
                const msg = args.slice(2).join(' ');
                if (!msg) {
                    printLine('USAGE: /hq broadcast [MESSAGE]', 'error-msg');
                    return;
                }

                socket.emit('hq_broadcast_req', msg);
            }

            else if (sub === 'description') {
                // Check: Sind wir eingeloggt?
                if (!window.isHqLoggedIn) {
                    printLine('ACCESS DENIED. Login required.', 'error-msg');
                    return;
                }

                // Alles nach "/hq description" ist der Text
                const desc = args.slice(2).join(' ');

                if (!desc) {
                    printLine('USAGE: /hq description [TEXT]', 'error-msg');
                    return;
                }

                // Senden
                socket.emit('hq_update_description', desc);
            }
        }

        else if (cmd === '/setup') {
            const token = args[1];
            if (token) {
                printLine('Initializing Setup Protocol...', 'system-msg');
                socket.emit('setup_init', token);
            } else {
                printLine('USAGE: /setup [TOKEN]', 'error-msg');
            }
        }

        else if (cmd === '/request') {
            if (args[1] === 'institution') {
                printLine('--- NEW INSTITUTION APPLICATION ---', 'highlight-msg');
                printLine('1. Enter Official Institution Name:', 'system-msg');
                appState = 'REQ_NAME';
                promptSpan.textContent = 'NAME>';
            } else {
                printLine('USAGE: /request institution', 'error-msg');
            }
        }

        // NEUER BEFEHL: /verify
        else if (cmd === '/verify') {
            const email = args[1];
            const code = args[2];
            if (email && code) {
                printLine('Verifying identity...', 'system-msg');
                socket.emit('register_verify_submit', { email, code });
            } else {
                printLine('USAGE: /verify [EMAIL] [CODE]', 'error-msg');
            }
        }

     else if (cmd === '/help') {
         printLine('COMMANDS: /connect, /group, /pub, /drop, /ping, /nudge, /info, /auth, /ghost, /leave', 'system-msg');
     }

     // --- NEU: UNBEKANNTER BEFEHL ---
     else {
         printLine(`ERROR: Unknown command '${cmd}'.`, 'error-msg');
         printLine('Type /help for a list of available protocols.', 'system-msg');
     }

        return; // WICHTIG: Damit der Befehl nicht als Chat-Nachricht gesendet wird!
    }

    // --- MESSAGING (MIT ROTATION & COUNTER) ---
    if (activeChatId === 'HQ_INBOX') {
        return; // Nichts tun (Enter wird ignoriert)
    }

    // --- NEU: INTERNAL CHAT HANDLER ---
    if (activeChatId === 'HQ_INTERNAL') {
        if (!window.internalGroupKey) {
            printLine("ERROR: Encryption key missing. Re-login required.", "error-msg");
            return;
        }

        // 1. Verschlüsseln (AES-GCM)
        const encrypted = await encryptMessage(text, window.internalGroupKey);

        // 2. Verschlüsseltes Objekt senden (nicht mehr nur 'text')
        socket.emit('hq_internal_chat', encrypted);
        return;
    }

    const currentChat = myChats[activeChatId];
    if (!currentChat || activeChatId === 'LOCAL') {
        printLine('SYSTEM: Local shell. Connect first.', 'error-msg');
        return;
    }
    if (!currentChat.key) {
        printLine('ERROR: Missing encryption key.', 'error-msg');
        return;
    }

    // --- AUTOMATIC KEY ROTATION LOGIC ---
    if (currentChat.type === 'private') {
        // Zähler initialisieren falls undefined
        if (typeof currentChat.msgCount === 'undefined') currentChat.msgCount = 0;

        // Wenn 50 Nachrichten erreicht sind -> Rotieren!
        if (currentChat.msgCount >= 50) {
            printLine("[SECURITY] Re-Keying Session (Automatic Rotation)...", "system-msg");
            await performKeyRotation(activeChatId);

            currentChat.msgCount = 0; // Reset

            // Kurze Pause (500ms), damit der Schlüsseltausch durchgeht, bevor die Nachricht verschlüsselt wird
            // Wir nutzen await wait(500) - wait Funktion ist oben in deinem Code definiert
            await wait(500);
        }

        currentChat.msgCount++;
    }
    // ------------------------------------

    const encrypted = await encryptMessage(text, currentChat.key);

    if (currentChat.type === 'pub') socket.emit('pub_message', encrypted);
    else if (currentChat.type === 'group') socket.emit('group_message', encrypted);
    if (currentChat.type === 'private') {
        socket.emit('message', {
            targetKey: currentChat.id,
            payload: encrypted
        });
    }
}

// =============================================================================
// 5. SOCKET EVENTS
// =============================================================================

// Allgemeine Systemnachrichten
socket.on('system_message', (msg) => {
    // Unterscheidung: Fehler rot, Rest grau
    const type = msg.includes('ERROR') || msg.includes('DENIED') || msg.includes('FAILED') ? 'error-msg' : 'system-msg';
    printLine(msg, type);
});

// 1. REGISTRIERUNG (Hier fehlte die ID Anzeige!)
socket.on('registered', (data) => {
    myKey = data.key;
    myUsername = data.username;

    // --- NEU HINZUFÜGEN ---
    sessionStartTime = Date.now();
    updateUserUI(); // Füllt die Leiste unten links
    // ----------------------

    // Status ändern, falls wir noch im Boot-Screen sind
    if (appState === 'BOOTING') {
        appState = 'IDLE';
    }

    // Willkommens-Nachricht mit ID drucken
    printLine('----------------------------------------');
    printLine(`IDENTITY CONFIRMED: ${myUsername}`);
    printLine(`KEY: [ ${myKey} ]`, 'my-msg'); // <--- Das fehlte!
    printLine('Security Level: P-256 E2E ENCRYPTION ENABLED');
    printLine('SUBSPACE COMMS (PUSH): ENABLED.');
    printLine('----------------------------------------');

    promptSpan.textContent = '>';
    promptSpan.className = 'prompt-default';

    // Push registrieren
    if (data.vapidPublicKey) registerSw(data.vapidPublicKey);

    // Promo Liste abrufen (damit rechts was steht)
    socket.emit('request_promo_list');
});

// 2. PING / NETZWERK SCAN (Das fehlte komplett!)
socket.on('ping_result', (data) => {
    printLine('----------------------------------------');
    printLine(`Scanning network for entity '${data.query}'...`, 'system-msg');

    if (data.results && data.results.length > 0) {
        printLine(`>>> NETWORK SCAN COMPLETE. FOUND ${data.results.length} MATCH(ES):`, 'partner-msg');
        data.results.forEach(u => {
            printLine(`ID: ${u.key} :: USER: ${u.username}`, 'system-msg');
        });
    } else {
        printLine(`>>> NETWORK SCAN COMPLETE. 0 MATCHES FOUND.`, 'error-msg');
    }
    printLine('----------------------------------------');
});

// 3. INFO RESULT (Das fehlte auch)
socket.on('info_result', (data) => {
    printLine('----------------------------------------');
    printLine(`>>> TARGET ANALYSIS: ${data.username}`, 'system-msg');
    printLine(`ID:       ${data.key}`);
    printLine(`STATUS:   ${data.status}`);
    printLine(`DEVICE:   ${data.device}`);
    printLine(`LOGIN:    ${new Date(data.loginTime).toLocaleTimeString()}`);
    printLine('----------------------------------------');
});

// EINGEHENDE VERBINDUNGSANFRAGE (Umgeleitet nach LOCAL)
// EINGEHENDE VERBINDUNGSANFRAGE (Mit fixiertem Button)
socket.on('incoming_request', (data) => {
    // Anfrage speichern
    pendingRequests[data.requesterKey] = {
        socketId: data.requesterId,
        username: data.requesterName,
        publicKey: data.publicKey
    };

    updateVoiceUI('ringing', data.requesterName);

    const target = 'LOCAL';
    const key = data.requesterKey; // Kürzer für String-Bau

    printToChat(target, ' ', '');
    printToChat(target, '----------------------------------------', 'partner-msg');
    printToChat(target, '>>> INCOMING SECURE HANDSHAKE REQUEST', 'partner-msg');
    printToChat(target, `NODE:     ${getDynamicName(data.requesterName, data.requesterKey)}`, 'system-msg');
    printToChat(target, `ID:       ${key}`, 'system-msg');
    printToChat(target, 'SECURITY: P-256 KEY EXCHANGE READY', 'system-msg');
    printToChat(target, ' ', '');

    printToChat(target, `ACTION REQUIRED:`, 'system-msg');
    printToChat(target, `Type: /accept ${key}`, 'my-msg');

    // FIX: Button als HTML-String direkt in die History injizieren
    // Wir nutzen 'onclick="window.triggerAccept(...)"', das überlebt auch Chat-Wechsel
    const btnHtml = `<div class="system-msg" style="margin-top:5px; cursor:pointer; color:#0f0; border:1px solid #0f0; display:inline-block; padding:5px 10px; font-weight:bold;" onclick="window.triggerAccept('${key}')">[ ACCEPT UPLINK ]</div>`;

    // Wir nutzen einen Trick: Wir pushen den HTML String direkt in die History von LOCAL
    // Dazu brauchen wir Zugriff auf das Chat-Objekt
    if (myChats['LOCAL']) {
        myChats['LOCAL'].history.push(btnHtml);

        // Wenn wir gerade drauf schauen, auch anzeigen
        if (activeChatId === 'LOCAL') {
            const div = document.createElement('div');
            div.innerHTML = btnHtml;
            output.appendChild(div);
            output.scrollTop = output.scrollHeight;
        } else {
            myChats['LOCAL'].unread++;
            renderChatList();
        }
    }

    printToChat(target, ' ', '');
    printToChat(target, '----------------------------------------', 'partner-msg');

    if (activeChatId !== 'LOCAL') {
        printLine(`(i) New Connection Request in LOCAL_SHELL`, 'system-msg');
    }
});

// GHOST STATUS UPDATE (Fix: Immer Popup nutzen & Style erhalten)
socket.on('user_ghost_update', (data) => {
    // data: { key, username, isGhost }
    const newDisplayName = data.isGhost ? 'Anonymous' : data.username;

    // Hilfsfunktion: Baut den Tag neu - JETZT IMMER MIT POPUP
    const getNewTagHtml = () => {

        // 1. Style prüfen (Institutionen)
        const instStyle = institutionStyles[data.key];
        let customStyle = 'cursor: pointer;';

        if (instStyle) {
            customStyle += `color: ${instStyle.color}; text-shadow: 0 0 5px ${instStyle.color}; font-weight: bold;`;
        }

        // 2. Aktion: IMMER das Popup öffnen
        // Wir übergeben 'event', damit das Popup an der Mausposition aufgeht
        const action = `window.openUserPopup(event, '${data.key}')`;

        // 3. HTML zurückgeben
        return `<span class="dynamic-name" style="${customStyle}" data-key="${data.key}" onclick="${action}">`;
    };

    // 1. LIVE DOM UPDATE (Nur im aktuellen Chat sichtbar)
    const visibleElements = document.querySelectorAll(`.dynamic-name[data-key="${data.key}"]`);
    if (visibleElements.length > 0) {
        const newOpenTag = getNewTagHtml();

        visibleElements.forEach(el => {
            // Wir ersetzen das Element komplett, um alte Event-Listener loszuwerden
            el.outerHTML = `${newOpenTag}${newDisplayName}</span>`;
        });
    }

    // 2. HISTORY SPEICHER UPDATE (Für alle Chats im Hintergrund)
    Object.values(myChats).forEach(c => {
        if (c.history && c.history.length > 0) {
            const newTag = getNewTagHtml();

            c.history = c.history.map(line => {
                // Regex sucht den ganzen Span: (<span ...>)(Inhalt)(</span>)
                // Wir suchen spezifisch nach dem Span mit dieser data-key
                const regex = new RegExp(`(<span [^>]*data-key="${data.key}"[^>]*>)(.*?)(</span>)`, 'g');

                return line.replace(regex, (match, oldOpen, content, close) => {
                    // Wir tauschen den Öffnungs-Tag (mit dem neuen onclick) UND den Namen aus
                    return `${newTag}${newDisplayName}${close}`;
                });
            });
        }
    });

    // 3. Sidebar Update (Falls privater Chat)
    const chat = myChats[data.key];
    if (chat && chat.type === 'private') {
        chat.name = newDisplayName;
        renderChatList();
        if (activeChatId === data.key) {
            promptSpan.textContent = `SECURE/${newDisplayName}>`;
        }
    }

    // 4. Eigener Status (für Settings Modal)
    if (data.key === myKey) {
        window.isGhostActive = data.isGhost;

        // Avatar Update
        if (data.isGhost) {
            document.getElementById('current-user-avatar').style.backgroundColor = '#666';
            document.getElementById('current-user-avatar').innerHTML = '👻';
        } else {
            document.getElementById('current-user-avatar').style.backgroundColor = 'var(--accent-color)';
            updateUserUI(); // Reset to Initial
        }
    }
});

// GHOST SCANNER ERGEBNIS (Universal)
socket.on('ghost_scan_result', (data) => {
    // data: { ghosts: [], context: "Group 123" }
    const target = activeChatId;

    printToChat(target, ' ', '');
    printToChat(target, `--- SPECTRAL SCAN: ${data.context} ---`, 'system-msg');

    if (data.ghosts.length === 0) {
        printToChat(target, '>>> No anomalies detected. All signals clear.', 'partner-msg');
    } else {
        printToChat(target, `>>> WARNING: ${data.ghosts.length} MASKED SIGNAL(S) UNVEILED:`, 'error-msg');

        data.ghosts.forEach(ghost => {
            // Hier nutzen wir copyIdToInput direkt im HTML, da wir wissen:
            // Wer das hier sieht, hat die Berechtigung (kam vom Server).
            const action = `window.copyIdToInput('${ghost.key}')`;
            const style = "cursor:pointer; text-decoration:underline; color:#ff3333;";

            const line = `👺 ${ghost.realName} [<span onclick="${action}" style="${style}" title="Copy ID">${ghost.key}</span>]`;

            // Wir müssen printToChat mit innerHTML nutzen
            printToChat(target, line, 'system-msg');
        });

        printToChat(target, ' ', '');
        printToChat(target, 'Use ID to take action.', 'system-msg');
    }
    printToChat(target, '----------------------------------------', 'system-msg');
});

// GHOST IDENTITY REVEALED (Antwort auf Klick)
socket.on('ghost_reveal_result', (data) => {
    // data: { realName, key, isGhost }

    const target = activeChatId;
    const ghostStatus = data.isGhost ? '[MASKED]' : '[VISIBLE]';

    printToChat(target, ' ', '');
    printToChat(target, '------------------------------', 'system-msg');
    printToChat(target, `>>> IDENTITY REVEALED`, 'partner-msg');
    // Die gewünschte Nachricht:
    printToChat(target, `USER:   ${data.realName}`, 'system-msg');
    printToChat(target, `ID:     ${data.key}`, 'system-msg');
    printToChat(target, `STATUS: ${ghostStatus}`, 'system-msg');
    printToChat(target, '------------------------------', 'system-msg');

    // Optional: Automatisch Input füllen hatten wir schon im Klick-Handler gemacht.
});

// INSTITUTION STATUS UPDATE (Farbe & Name & Rang-Erhaltung)
socket.on('user_institution_update', (data) => {
    // data: { key, username, tag, color }

    // 1. Im Style-Cache speichern
    institutionStyles[data.key] = {
        tag: data.tag,
        color: data.color
    };

    // Der neue Style für Institutionen
    const newStyle = `color: ${data.color}; text-shadow: 0 0 5px ${data.color}; font-weight: bold; cursor: pointer;`;

    // Hilfsfunktion: Baut den neuen Text und behält Ränge bei
    const getPreservedContent = (oldContent) => {
        // Prüfen, ob ein Rang davor steht (z.B. "[OWNER] ", "[MOD] ", "[ADMIN] ")
        const roleMatch = oldContent.match(/^\[(OWNER|MOD|ADMIN)\]\s*/);
        const prefix = roleMatch ? roleMatch[0] : '';

        // Neuer Inhalt = Alter Rang + Neuer Institutions-Name
        return prefix + data.username;
    };

    // 2. LIVE DOM UPDATE (Was du gerade siehst)
    const elements = document.querySelectorAll(`.dynamic-name[data-key="${data.key}"]`);
    elements.forEach(el => {
        const newText = getPreservedContent(el.textContent);
        el.innerHTML = newText;
        el.style.cssText = newStyle; // Wendet den Neon-Style an
    });

    // 3. HISTORY SPEICHER UPDATE (Damit es beim Tab-Wechsel bleibt)
    Object.values(myChats).forEach(c => {
        if (c.history && c.history.length > 0) {
            c.history = c.history.map(line => {
                // Regex sucht nach dem Span mit der ID
                const regex = new RegExp(`(<span class="dynamic-name"[^>]*data-key="${data.key}"[^>]*>)(.*?)(</span>)`, 'g');

                return line.replace(regex, (match, openTag, content, closeTag) => {
                    const newText = getPreservedContent(content);

                    // Wir bauen den Tag neu, um den Style und onClick Attribute sicher hinzuzufügen
                    const action = `window.handleNameClick('${data.key}')`;
                    const title = "OFFICIAL INSTITUTION ACCOUNT";
                    const newOpenTag = `<span class="dynamic-name" style="${newStyle}" data-key="${data.key}" onclick="${action}" title="${title}">`;

                    return `${newOpenTag}${newText}${closeTag}`;
                });
            });
        }
    });

    // 4. Sidebar Update (Falls Chat offen)
    const chat = myChats[data.key];
    if (chat) {
        chat.name = data.username;
        renderChatList();

        if (activeChatId === data.key) {
            promptSpan.textContent = `SECURE/${data.username}>`;
        }
    }
});

// INTERNAL CHAT NACHRICHT EMPFANGEN
socket.on('hq_internal_msg_rcv', async (data) => {
    // data: { sender, text, tag, color }

    const target = 'HQ_INTERNAL';
    // Sicherheitscheck: Existiert der Chat?
    if (!myChats[target]) return;

    let clearText = "";

    // --- LOGIK-WEICHE: SYSTEM ODER USER? ---

    if (data.sender === 'SYSTEM') {
        // FALL A: System-Nachrichten kommen vom Server im KLARTEXT
        // (Der Server kennt den Encryption-Key nicht, daher sendet er plain)
        clearText = data.text;
    }
    else {
        // FALL B: Nachrichten von Agenten sind VERSCHLÜSSELT
        try {
            if (window.internalGroupKey) {
                clearText = await decryptMessage(data.text, window.internalGroupKey);
            } else {
                clearText = "[WAITING FOR KEY...]";
            }
        } catch (e) {
            console.error("Decryption failed:", e);
            clearText = "[DECRYPTION FAILED]";
        }
    }
    // ---------------------------------------

    // XSS Schutz
    const safeText = clearText.replace(/</g, "&lt;").replace(/>/g, "&gt;");

    // Design bauen
    const style = `color: ${data.color}; font-weight: bold;`;
    const msgHtml = `<span style="${style}">[${data.sender}]:</span> <span style="color:#fff;">${safeText}</span>`;

    printToChat(target, msgHtml, '');

    if (activeChatId !== target) {
        printLine(`(i) New Internal Msg from ${data.sender}`, 'system-msg');
    }
});

// 4. CHAT START (Final HQ Fix)
socket.on('chat_start', async (data) => {
    const chatId = data.partnerKey || data.partner;
    let finalKey = null;

    // Variablen für Safety Number
    let myCorrectPubKeyString = null;
    let partnerPubKeyString = null;

    // FALL A: Wir sind der Initiator
    if (data.publicKey) {
        try {
            let usedPrivateKey;

            // --- DER FIX: ZUERST DEN GLOBALEN HQ KEY PRÜFEN ---
            if (window.hqPendingKeyPair) {
                console.log("CLIENT DEBUG: Using HQ Pending Key!");
                usedPrivateKey = window.hqPendingKeyPair.privateKey;
                myCorrectPubKeyString = await exportPublicKey(window.hqPendingKeyPair.publicKey);

                // WICHTIG: Sofort löschen, damit er nicht für andere Chats benutzt wird
                window.hqPendingKeyPair = null;
            }
                // --------------------------------------------------

            // Falls kein HQ Key da war, suchen wir normal weiter (P2P Logik)
            else {
                // Versuche Key unter ChatID oder PartnerID zu finden
                let storedData = outgoingConnects[chatId];
                if (!storedData && data.partner) {
                    storedData = outgoingConnects[data.partner];
                    if (storedData) delete outgoingConnects[data.partner];
                }

                if (storedData) {
                    usedPrivateKey = storedData.privateKey;
                    myCorrectPubKeyString = storedData.publicKeyString;
                    if (outgoingConnects[chatId]) delete outgoingConnects[chatId];
                } else {
                    // Fallback (Notlösung)
                    usedPrivateKey = myKeyPair.privateKey;
                    myCorrectPubKeyString = await exportPublicKey(myKeyPair.publicKey);
                }
            }

            finalKey = await deriveSecretKey(usedPrivateKey, data.publicKey);
            partnerPubKeyString = data.publicKey;

        } catch(e) { console.error("Key Error:", e); }
    }
    // FALL B: Wir sind der Akzeptierer
    else if (tempDerivedKey) {
        finalKey = tempDerivedKey;
        tempDerivedKey = null;
        myCorrectPubKeyString = await exportPublicKey(myKeyPair.publicKey);
        partnerPubKeyString = window.tempPartnerPubKeyString;
    }

    if (finalKey) {
        registerChat(chatId, data.partner, 'private', finalKey);

        const chat = myChats[chatId];
        chat.myKeyPair = myKeyPair;
        chat.myPublicKeyString = myCorrectPubKeyString;
        chat.partnerPublicKeyString = partnerPubKeyString || "UNKNOWN";
        chat.msgCount = 0;

        // Automatisch wechseln wenn wir in der Inbox sind
        if (activeChatId === 'HQ_INBOX') {
            switchChat(chatId);
        } else {
            // Notification oder Wechsel
            switchChat(chatId);
        }

        printToChat(chatId, '----------------------------------------', 'system-msg');
        printToChat(chatId, `>>> SECURE CHANNEL ESTABLISHED WITH: ${getDynamicName(data.partner, chatId)}`, 'system-msg');
        printToChat(chatId, '----------------------------------------', 'system-msg');
        updateVoiceUI('idle');
    }
});

// 5. NACHRICHTEN EMPFANGEN (DIAGNOSE MODUS)
socket.on('message', async (data) => {
    console.log("CLIENT DEBUG: Nachricht empfangen!", data);

    const senderKey = data.senderKey;
    console.log("CLIENT DEBUG: Suche Chat für Key:", senderKey);
    console.log("CLIENT DEBUG: Meine offenen Chats:", Object.keys(myChats));

    // Suche Chat
    const chat = myChats[senderKey];

    if (!chat) {
        console.error("CLIENT FEHLER: Kein Chat für diesen Key gefunden!");
        // Versuch über Namen als Fallback für alte Logs
        const nameMatch = Object.values(myChats).find(c => c.type === 'private' && c.name === data.user);
        if (nameMatch) {
            console.log("CLIENT DEBUG: Habe Chat über Namen gefunden (Fallback).");
            printToChat(nameMatch.id, `[${data.user}]: ${await decryptMessage(data.text, nameMatch.key)}`, 'partner-msg');
        }
        return;
    }

    console.log("CLIENT DEBUG: Chat gefunden! Entschlüssele...");
    const clearText = await decryptMessage(data.text, chat.key);
    const safeText = clearText.replace(/</g, "&lt;").replace(/>/g, "&gt;");
    printToChat(chat.id, `[${getDynamicName(data.user, data.senderKey)}]: ${clearText}`, 'partner-msg');
});

// Dynamische Join/Leave/Status Nachrichten (Final Check)
socket.on('room_user_status', (data) => {
    // data: { username, key, type, context, roomId, isGhost }

    // 1. Zwingend "Anonymous" nutzen, wenn das Flag da ist
    let displayName = data.username;
    if (data.isGhost === true) {
        displayName = 'Anonymous';
    }

    // 2. HTML bauen
    const nameHtml = getDynamicName(displayName, data.key);

    let msg = '';

    if (data.type === 'join') {
        if (data.context === 'pub') msg = `NETWORK ALERT: Node ${nameHtml} has established uplink.`;
        else msg = `User ${nameHtml} has joined the group.`;
    }
    else if (data.type === 'leave') {
        if (data.context === 'pub') msg = `User ${nameHtml} disconnected from sector.`;
        else msg = `User ${nameHtml} has left the group.`;
    }
    else if (data.type === 'approved') {
        // Hier wird der String gebaut
        msg = `User ${nameHtml} request approved by Staff.`;
    }

    printToChat(data.roomId, msg, 'system-msg');
});

// GROUP JOIN REQUEST (Für Owner & Mods - Mit Button!)
socket.on('group_join_request_alert', (data) => {
    // data: { username, userKey, groupId, isGhost }

    const initialName = data.isGhost ? 'Anonymous' : data.username;
    const nameHtml = getDynamicName(initialName, data.userKey);
    const targetChat = data.groupId;
    const dest = myChats[targetChat] ? targetChat : 'LOCAL';

    printToChat(dest, ' ', '');
    printToChat(dest, '----------------------------------------', 'partner-msg');
    printToChat(dest, `GROUP ALERT: User ${nameHtml} [${data.userKey}] wants to join.`, 'partner-msg');

    // --- DER BUTTON ---
    const btnHtml = `<div class="system-msg" style="margin-top:5px; cursor:pointer; color:#0f0; border:1px solid #0f0; display:inline-block; padding:5px 10px; font-weight:bold;" onclick="window.triggerGroupAccept('${data.userKey}')">[ ACCEPT REQUEST ]</div>`;

    // Da wir printToChat mit innerHTML nutzen, können wir den Button direkt injizieren.
    // Wir müssen ihn aber in den History-String packen.

    // Trick: Wir nutzen printToChat für den Text, aber für den Button hängen wir ihn manuell an
    // ODER wir packen ihn direkt in den printToChat Aufruf, da dieser jetzt HTML kann:

    printToChat(dest, btnHtml, '');
    // ------------------

    printToChat(dest, '----------------------------------------', 'partner-msg');

    if (activeChatId !== dest) {
        printLine(`(i) New Join Request in ${dest}`, 'system-msg');
    }
});

// 6. GRUPPEN EVENTS
socket.on('group_joined_success', async (data) => {
    // --- FIX: Passwort-Modus beenden ---
    if (appState === 'ENTERING_GROUP_PASSWORD') {
        pendingJoinGroupId = null;
        // appState wird gleich durch switchChat gesetzt, das passt.
    }
    // -----------------------------------

    updateLocalGroups(data.id, 'add');

    let key = data.key ? await importRoomKey(data.key) : null;
    const name = data.name || `Group_${data.id}`;

    registerChat(data.id, name, 'group', key, data.role);
    switchChat(data.id);

    printToChat(data.id, '----------------------------------------');
    printToChat(data.id, `>>> SECURE GROUP ESTABLISHED: ${name} (ID: ${data.id})`, 'system-msg');
    printToChat(data.id, `>>> YOUR ROLE: ${data.role}`, 'system-msg');
    printToChat(data.id, '----------------------------------------');

    updateVoiceUI('idle');
});

// EINLADUNG EMPFANGEN (LOCAL + Button + Details)
socket.on('group_invite_received', (data) => {
    // data: { groupId, groupName, inviterName, inviterKey, inviterRole, isGhost }

    const target = 'LOCAL';

    // Ghost Logic für den Namen des Einladenden
    const initialName = data.isGhost ? 'Anonymous' : data.inviterName;
    const inviterHtml = getDynamicName(initialName, data.inviterKey);

    printToChat(target, ' ', '');
    printToChat(target, '----------------------------------------', 'partner-msg');
    printToChat(target, `>>> GROUP INVITATION RECEIVED`, 'partner-msg');

    // Details anzeigen (Rang, Name, ID)
    // Da wir innerHTML nutzen, wird inviterHtml korrekt gerendert
    printToChat(target, `FROM:     ${inviterHtml} [ID: ${data.inviterKey}]`, 'system-msg');
    printToChat(target, `RANK:     ${data.inviterRole}`, 'system-msg');
    printToChat(target, `GROUP:    ${data.groupName} (ID: ${data.groupId})`, 'system-msg');
    printToChat(target, ' ', '');

    // Instructions
    printToChat(target, `ACTION REQUIRED:`, 'system-msg');
    printToChat(target, `Type: /group accept ${data.groupId}`, 'my-msg');

    // Der Button
    const btnHtml = `<div class="system-msg" style="margin-top:5px; cursor:pointer; color:#0f0; border:1px solid #0f0; display:inline-block; padding:5px 10px; font-weight:bold;" onclick="window.triggerInviteAccept('${data.groupId}')">[ ACCEPT INVITE ]</div>`;

    // Button in History injizieren (damit er Tab-Wechsel überlebt)
    if (myChats['LOCAL']) {
        myChats['LOCAL'].history.push(btnHtml);
        if (activeChatId === 'LOCAL') {
            const div = document.createElement('div');
            div.innerHTML = btnHtml;
            output.appendChild(div);
            output.scrollTop = output.scrollHeight;
        } else {
            myChats['LOCAL'].unread++;
            renderChatList();
        }
    }

    printToChat(target, ' ', '');
    printToChat(target, '----------------------------------------', 'partner-msg');

    if (activeChatId !== 'LOCAL') {
        printLine(`(i) New Group Invite in LOCAL_SHELL`, 'system-msg');
    }
});

socket.on('group_message_received', async (data) => {
    // 1. Check: Kennen wir diesen Chat schon?
    let chat = myChats[data.groupId];

    // 2. Fallback: Wenn wir die Nachricht bekommen, aber den Chat lokal nicht haben
    // (Kann passieren bei schnellen Reloads oder Auto-Joins)
    if (!chat) {
        // Wir registrieren ihn vorläufig OHNE Key (Key kommt meist erst mit joined_success)
        // Aber wir versuchen es trotzdem anzuzeigen
        registerChat(data.groupId, `Group ${data.groupId}`, 'group');
        chat = myChats[data.groupId];
    }

    // 3. Entschlüsseln
    let clearText = "[ENCRYPTED SIGNAL]";
    if (chat.key) {
        try {
            clearText = await decryptMessage(data.text, chat.key);
        } catch (e) {
            console.error("Decryption Error:", e);
            clearText = "[DECRYPTION FAILED]";
        }
    } else {
        // Falls wir den Key noch nicht haben (z.B. Invite noch nicht fertig verarbeitet)
        clearText = "[WAITING FOR KEY EXCHANGE...]";
    }

    // XSS Schutz
    const safeText = clearText.replace(/</g, "&lt;").replace(/>/g, "&gt;");

    printToChat(data.groupId, `[${getDynamicName(data.user, data.senderKey)}]: ${safeText}`, 'partner-msg');
});

// OWNER LEAVE DIALOG
socket.on('group_owner_leave_dialog', () => {
    appState = 'DECIDING_GROUP_EXIT';
    // Prompt ändern, damit man weiß, wo man ist
    promptSpan.setAttribute('data-prev-prompt', promptSpan.textContent);
    promptSpan.textContent = 'DECISION>';
    promptSpan.className = 'prompt-error';

    printLine(' ', '');
    printLine('⚠️  WARNING: YOU ARE THE OWNER  ⚠️', 'error-msg');
    printLine('You cannot simply leave. Choose the fate of this group:', 'system-msg');
    printLine('  [1] close           -> Delete group, kick everyone.', 'system-msg');
    printLine('  [2] random          -> Promote random member, then leave.', 'system-msg');
    printLine('  [3] transfer [KEY]  -> Promote specific user, then leave.', 'system-msg');
    printLine('  [4] cancel          -> Stay in group.', 'system-msg');
    printLine(' ', '');
});

// Event wenn man erfolgreich raus ist (zum Resetten)
// Event wenn man erfolgreich raus ist (zum Resetten)
socket.on('group_left_success', () => {
    // Falls wir gerade entschieden haben, State resetten
    if (appState === 'DECIDING_GROUP_EXIT') {
        appState = 'IDLE';
    }

    // Wir ermitteln die ID der Gruppe, die wir gerade verlassen
    const currentGroupId = Object.keys(myChats).find(k => myChats[k].type === 'group' && activeChatId === k);

    if (currentGroupId) {
        // --- NEU: Zuerst aus dem Speicher entfernen! ---
        updateLocalGroups(currentGroupId, 'remove');
        // -----------------------------------------------

        deleteChat(currentGroupId);
    }
    else if (activeChatId !== 'LOCAL') {
        switchChat('LOCAL');
    }
});

// PUB LEAVE ERFOLGREICH (Client aufräumen)
socket.on('pub_left_success', () => {
    // 1. Die ID des aktuellen Public Chats finden
    const currentPubId = Object.keys(myChats).find(k => myChats[k].type === 'pub' && activeChatId === k);

    // 2. Chat löschen und UI wechseln
    if (currentPubId) {
        deleteChat(currentPubId); // Löscht Chat aus der Liste und dem Speicher
    }

    // 3. Zurück zur Konsole, falls wir noch im Chat-Fenster hängen
    if (activeChatId !== 'LOCAL') {
        switchChat('LOCAL');
    }

    printLine('>>> DISCONNECTED FROM SECTOR. LOCAL SHELL ACTIVE.', 'system-msg');
});

// EVENT: GRUPPEN-NAME GEÄNDERT
socket.on('group_name_changed', (data) => {
    // data: { id, newName }

    // 1. Im lokalen Speicher updaten
    if (myChats[data.id]) {
        myChats[data.id].name = data.newName;

        // 2. Sidebar neu malen (damit der neue Name dort steht)
        renderChatList();

        // 3. Prompt aktualisieren (nur wenn wir gerade in dieser Gruppe sind)
        if (activeChatId === data.id) {
            // Format: group/(NAME)>
            promptSpan.textContent = `group/${data.newName}>`;
        }

        // Kleine Info im Chat selbst (optional, da Server eh system_message schickt)
        // printToChat(data.id, `(i) Title updated to: ${data.newName}`, 'system-msg');
    }
});

// PASSWORT ABFRAGE (Vom Server ausgelöst)
socket.on('group_password_required', (groupId) => {
    pendingJoinGroupId = groupId;
    appState = 'ENTERING_GROUP_PASSWORD';

    printLine(' ', '');
    printLine('🔒 SECURITY ALERT: ENCRYPTED GROUP', 'error-msg');
    printLine(`Group ${groupId} requires an access code.`, 'system-msg');
    printLine('Enter password (or type "cancel"):', 'my-msg');

    promptSpan.textContent = 'PASSWORD>';
    promptSpan.className = 'prompt-warn';
});

// GROUP BROADCAST EMPFANGEN (Hervorgehoben & Dynamisch)
socket.on('group_broadcast_received', (data) => {
    // data: { text, senderName, senderKey, isGhost, role, groupId }

    // 1. Initialen Namen bestimmen
    const initialName = data.isGhost ? 'Anonymous' : data.senderName;

    // 2. Dynamischen HTML-Namen bauen
    const nameHtml = getDynamicName(initialName, data.senderKey);

    // 3. Ziel bestimmen (Gruppen-Tab oder Local fallback)
    const targetChat = data.groupId;
    // Wenn wir den Chat noch nicht haben (selten), ignorieren oder Local nutzen
    const dest = myChats[targetChat] ? targetChat : 'LOCAL';

    // 4. Das Design bauen (ASCII Style Box)
    // Wir nutzen CSS Border und Padding für den "Wichtig"-Effekt
    const broadcastHtml = `
        <div class="group-broadcast-box">
            <div class="group-broadcast-header">⚠️ GROUP BROADCAST [${data.role}]</div>
            <div class="group-broadcast-text">"${data.text}"</div>
            <div class="group-broadcast-footer">— ${nameHtml}</div>
        </div>
    `;

    // 5. Anzeigen (printToChat kann HTML!)
    printToChat(dest, broadcastHtml, '');

    // Sound oder visueller Hinweis, falls man woanders ist
    if (activeChatId !== dest) {
        printLine(`(i) ⚠️ BROADCAST in ${myChats[dest].name}`, 'system-msg');
    }
});

// LINK ANZEIGEN
socket.on('group_link_display', (data) => {
    // data: { linkId, groupId, groupName, creator, limit, isProtected, isPrivate }

    // Ziel: Aktueller Chat (activeChatId)
    // Da wir das Event per io.to(roomId) bekommen haben, passt das,
    // aber wir müssen sicherstellen, dass wir es im richtigen Tab anzeigen.
    // Wir nutzen einfach activeChatId oder besser: Wir zeigen es dort an, wo es ankam.
    // Da Socket.io Rooms nutzt, kommt es nur an, wenn wir in dem Raum sind.

    // Wir rendern es in den Chat, in dem wir gerade sind (das ist vereinfacht,
    // aber passt meistens, da man Links ja im aktiven Gespräch postet).
    const target = activeChatId;

    const lockIcon = data.isProtected ? '🔒' : (data.isPrivate ? '🛡️' : '🌍');
    const limitText = data.limit === 0 ? 'UNLIMITED' : `${data.limit} USES LEFT`;

    // Button Action
    const action = `window.triggerLinkJoin('${data.linkId}')`;

    const html = `
        <div id="link-${data.linkId}" style="border: 1px dashed #0f0; background: rgba(0,255,0,0.05); padding: 10px; margin: 10px 0; position: relative;">
            <div style="font-weight: bold; color: #0f0; border-bottom: 1px solid #333; padding-bottom: 5px; margin-bottom: 5px;">
                ${lockIcon} GROUP INVITE: ${data.groupName}
            </div>
            <div style="font-size: 0.9em; color: #aaa;">
                ID: ${data.groupId}<br>
                HOST: ${data.creator}<br>
                LIMIT: <span id="limit-${data.linkId}">${limitText}</span>
            </div>
            <div style="margin-top: 10px; text-align: center;">
                <button onclick="${action}" class="voice-btn" style="width: 100%; border-color: #0f0; color: #0f0;">
                    [ JOIN GROUP ]
                </button>
            </div>
        </div>
    `;

    printToChat(target, html, '');
});

// LINK ABGELAUFEN (UI Update)
socket.on('group_link_expired', (linkId) => {
    const el = document.getElementById(`link-${linkId}`);
    if (el) {
        // Option A: Löschen
        // el.remove();

        // Option B: Als "Expired" markieren (Cooler)
        el.style.borderColor = '#555';
        el.style.background = 'rgba(0,0,0,0.5)';
        el.innerHTML = `
            <div style="color: #555; text-align: center; padding: 10px;">
                [ LINK EXPIRED / LIMIT REACHED ]
            </div>
        `;
    }
});

// WHISPER EMPFANGEN / GESENDET (DECRYPTION UPDATE)
socket.on('room_whisper_received', async (data) => {
    // data: { senderKey, senderName, isGhost, targetKey, text, context, roomId, type }
    // ACHTUNG: 'data.text' ist hier jetzt das verschlüsselte Objekt!

    // Ziel bestimmen
    const targetChatId = data.roomId;
    const chat = myChats[targetChatId];

    // Ohne Chat-Key können wir nicht entschlüsseln
    if (!chat || !chat.key) return;

    // Ghost-Namen auflösen
    const initialName = data.isGhost ? 'Anonymous' : data.senderName;
    const nameHtml = getDynamicName(initialName, data.senderKey);

    // --- ENTSCHLÜSSELN ---
    let clearText = "[ENCRYPTED]";
    try {
        clearText = await decryptMessage(data.text, chat.key);
    } catch (e) {
        console.error("Whisper Decryption Error:", e);
        clearText = "[DECRYPTION FAILED]";
    }

    // XSS Schutz für den entschlüsselten Text
    const safeText = clearText.replace(/</g, "&lt;").replace(/>/g, "&gt;");

    // Design bauen
    let msgHtml = '';

    if (data.type === 'incoming') {
        // Jemand flüstert mir zu
        msgHtml = `<span style="color: #d000ff;">[WHISPER from ${nameHtml}]:</span> <span style="color: #e0e0e0; font-style: italic;">${safeText}</span>`;
    }
    else {
        // Ich habe geflüstert (Bestätigung)
        msgHtml = `<span style="color: #d000ff;">[WHISPER to ${data.targetKey}]:</span> <span style="color: #888; font-style: italic;">${safeText}</span>`;
    }

    // Anzeigen
    printToChat(targetChatId, msgHtml, '');

    // Hinweis, falls man gerade woanders ist
    if (activeChatId !== targetChatId && data.type === 'incoming') {
        printLine(`(i) New Encrypted Whisper in ${chat.name}`, 'system-msg');
    }
});

// 7. PUBLIC CHAT EVENTS
socket.on('pub_joined_success', async (data) => {
    let key = data.key ? await importRoomKey(data.key) : null;
    const name = data.name || `Sector_${data.id}`;

    registerChat(data.id, name, 'pub', key);
    switchChat(data.id);

    printToChat(data.id, '----------------------------------------');
    printToChat(data.id, `>>> UPLINK ESTABLISHED: SECTOR #${data.id}`, 'system-msg');
    printToChat(data.id, '----------------------------------------');

    updateVoiceUI('idle');
});

// EVENT: PUB CHAT ID GEÄNDERT (Renumbering)
socket.on('pub_id_changed', (data) => {
    // data: { oldId, newId, newName }

    // 1. Haben wir den Chat?
    const chat = myChats[data.oldId];
    if (chat) {
        // Chat Objekt updaten
        chat.id = data.newId;
        chat.name = data.newName;

        // Key im Objekt ändern: Wir müssen den Eintrag unter oldId löschen und unter newId speichern
        delete myChats[data.oldId];
        myChats[data.newId] = chat;

        // 2. Wenn wir diesen Chat gerade offen haben -> UI anpassen
        if (activeChatId === data.oldId) {
            activeChatId = data.newId;
            promptSpan.textContent = `PUB/${data.newId}>`;
        }

        // 3. Sidebar aktualisieren
        renderChatList();

        // 4. Systemnachricht in den Chat drucken (für den User lokal)
        printToChat(data.newId, ' ', '');
        printToChat(data.newId, `>>> SYSTEM UPDATE: Sector ID reassigned to #${data.newId}`, 'system-msg');
    }
});

// FORCED GROUP DELETION (Wenn Owner schließt)
socket.on('group_dissolved', (groupId) => {

    updateLocalGroups(groupId, 'remove');

    // 1. Nachricht anzeigen (falls User gerade hinschaut)
    // Wir nutzen printToChat direkt, falls der Chat noch existiert
    if (myChats[groupId]) {
        printToChat(groupId, ' ', '');
        printToChat(groupId, '----------------------------------------', 'error-msg');
        printToChat(groupId, '>>> GROUP DISBANDED BY OWNER.', 'error-msg');
        printToChat(groupId, '>>> CLOSING UPLINK...', 'error-msg');
        printToChat(groupId, '----------------------------------------', 'error-msg');
    }

    // 2. Kurze Verzögerung für den dramatischen Effekt, dann löschen
    setTimeout(() => {
        deleteChat(groupId);

        // Falls wir im Local Shell sind, Info geben
        if (activeChatId === 'LOCAL') {
            printLine(`INFO: Group ${groupId} has been dissolved by command.`, 'system-msg');
        }
    }, 2000); // 2 Sekunden Zeit zum Lesen der roten Nachricht
});

// GRUPPEN LISTE EMPFANGEN
socket.on('group_list_result', (data) => {
    // data: { owner:Obj, mods:[Obj], members:[Obj] }

    // Hilfsfunktion für eine Zeile
    const formatLine = (u) => {
        const initialName = u.isGhost ? 'Anonymous' : u.username;
        const dynamicName = getDynamicName(initialName, u.key);
        return `   ${dynamicName} <span style="color:#666">[ID: ${u.key}]</span>`;
    };

    const target = activeChatId; // Ausgabe im aktuellen Chat

    printToChat(target, ' ', '');
    printToChat(target, '--- GROUP HIERARCHY ---', 'system-msg');

    // 1. OWNER
    if (data.owner) {
        printToChat(target, '[ OWNER ]', 'partner-msg'); // Etwas heller
        printToChat(target, formatLine(data.owner), 'system-msg');
    }

    // 2. MODS
    if (data.mods.length > 0) {
        printToChat(target, ' ', '');
        printToChat(target, `[ MODERATORS (${data.mods.length}) ]`, 'partner-msg');
        data.mods.forEach(m => {
            printToChat(target, formatLine(m), 'system-msg');
        });
    }

    // 3. MEMBERS
    if (data.members.length > 0) {
        printToChat(target, ' ', '');
        printToChat(target, `[ MEMBERS (${data.members.length}) ]`, 'partner-msg');
        data.members.forEach(m => {
            printToChat(target, formatLine(m), 'system-msg');
        });
    } else {
        // Falls keine normalen Member da sind (nur Owner/Mods)
        printToChat(target, ' ', '');
        printToChat(target, '[ MEMBERS (0) ]', 'system-msg');
        printToChat(target, '   (None)', 'system-msg');
    }

    printToChat(target, '-----------------------', 'system-msg');
});

// MAN WURDE GEKICKT (Local Shell Nachricht)
socket.on('group_kicked_notification', (data) => {
    // data: { groupName, groupId, reason, kickerName }

    updateLocalGroups(data.groupId, 'remove');

    // 1. Gruppe sofort löschen und UI wechseln
    deleteChat(data.groupId);
    if (activeChatId !== 'LOCAL') switchChat('LOCAL');

    // 2. Die Nachricht in LOCAL_SHELL drucken
    const target = 'LOCAL';

    printToChat(target, ' ', '');
    printToChat(target, '----------------------------------------', 'error-msg');
    printToChat(target, '>>> YOU HAVE BEEN KICKED FROM A GROUP', 'error-msg');
    printToChat(target, `GROUP:    ${data.groupName} [ID: ${data.groupId}]`, 'system-msg');
    printToChat(target, `BY:       ${data.kickerName}`, 'system-msg');
    printToChat(target, ' ', '');
    printToChat(target, `REASON:   "${data.reason}"`, 'my-msg'); // Reason hervorheben
    printToChat(target, '----------------------------------------', 'error-msg');

    // Sound/Notification
    // (Optional, falls du Sounds hast)
});

// KICK VORSCHAU EMPFANGEN (Startet den Dialog)
socket.on('group_kick_preview_res', (list) => {
    // list: [{ username, key, isGhost }]

    // 1. Liste formatieren und anzeigen
    printLine(' ', '');
    printLine('INITIATING KICK PROTOCOL FOR:', 'system-msg');

    // Wir speichern die Keys für den eigentlichen Kick-Befehl später
    pendingKickTargets = [];

    list.forEach(u => {
        pendingKickTargets.push(u.key); // Key zur Liste hinzufügen

        // Dynamischen Namen bauen (falls Ghost)
        const initialName = u.isGhost ? 'Anonymous' : u.username;
        const nameHtml = getDynamicName(initialName, u.key);

        // Anzeige: (username) (id)
        // Wir nutzen printToChat direkt mit der aktiven ChatID, damit HTML geht
        printToChat(activeChatId, `  - ${nameHtml} (${u.key})`, 'partner-msg');
    });

    printLine(' ', '');
    printLine('Do you want to add a reason? [y/n]', 'system-msg');

    // 2. Jetzt erst den Status setzen
    appState = 'DECIDING_KICK_YN';

    // Prompt ändern
    promptSpan.setAttribute('data-prev-prompt', promptSpan.textContent);
    promptSpan.textContent = 'REASON? [y/n]>';
    promptSpan.className = 'prompt-error';
});

// BEFÖRDERUNG EMPFANGEN
socket.on('you_are_promoted', (data) => {
    // data: { groupId, role }

    // Ziel bestimmen
    const target = data.groupId;

    // Nur anzeigen, wenn wir den Chat noch haben
    if (myChats[target]) {
        // Design wie gewünscht
        printToChat(target, ' ', '');
        printToChat(target, '----------------------------------------', 'system-msg');
        printToChat(target, `>>> You got promoted`, 'partner-msg'); // Hellgrün
        printToChat(target, `>>> YOUR ROLE: ${data.role}`, 'partner-msg');
        printToChat(target, '----------------------------------------', 'system-msg');

        // Optional: Hinweis im Local Shell, falls man gerade nicht hinguckt
        if (activeChatId !== target) {
            printLine(`(i) You are now ${data.role} of Group ${target}`, 'system-msg');
        }
    }
});

socket.on('pub_message_received', async (data) => {
    // data: { senderName, senderKey, text, pubId }

    // 1. Chat finden
    const chat = myChats[data.pubId];
    if (!chat) return; // Chat nicht gefunden

    // 2. Entschlüsseln
    let clearText = "[ENCRYPTED]";
    try {
        clearText = await decryptMessage(data.text, chat.key);
    } catch (e) { return; }

    // 3. XSS Schutz
    const safeText = clearText.replace(/</g, "&lt;").replace(/>/g, "&gt;");

    // 4. Anzeigen mit DYNAMISCHEM NAMEN
    // Wir nutzen den senderKey, damit sich der Name später ändern kann
    printToChat(data.pubId, `[${getDynamicName(data.senderName, data.senderKey)}]: ${safeText}`, 'partner-msg');
});

// 8. ADMIN DIALOG
socket.on('admin_kick_owner_dialog', (data) => {
    appState = 'DECIDING_OWNER_KICK';
    currentKickTarget = data.oldOwnerKey;
    promptSpan.setAttribute('data-prev-prompt', promptSpan.textContent);

    printLine(' ', '');
    printLine('⚠️  ADMIN INTERVENTION: OWNER KICK INITIATED  ⚠️', 'error-msg');
    printLine(`Target is Owner. Choose successor:`, 'system-msg');
    printLine(' [r]andom OR [s]pecific [KEY]', 'system-msg');

    promptSpan.textContent = 'SUCCESSOR>';
});

// ADMIN KICK WIZARD START
socket.on('admin_kick_owner_start', (data) => {
    adminKickTargetKey = data.targetKey; // ID merken

    appState = 'ADMIN_KICK_CONFIRM';
    promptSpan.setAttribute('data-prev-prompt', promptSpan.textContent);

    printLine(' ', '');
    printLine('⚠️  ADMIN OVERRIDE INITIATED  ⚠️', 'error-msg');
    printLine(`You are about to KICK THE OWNER (${data.targetName}) of Group '${data.groupName}'.`, 'system-msg');
    printLine('This requires re-assigning authority or dissolving the group.', 'system-msg');
    printLine(' ', '');
    printLine('Do you want to proceed? [y/n]', 'my-msg');

    promptSpan.textContent = 'CONFIRM>';
    promptSpan.className = 'prompt-error';
});

// ADMIN AUTH: PASSWORT WAR KORREKT -> JETZT 2FA
socket.on('admin_step_2fa_req', () => {
    appState = 'ADMIN_2FA';

    printLine('Credentials accepted.', 'success-msg');
    printLine('Enter 2FA Code:', 'my-msg');

    promptSpan.textContent = 'ADMIN-2FA>';
    promptSpan.className = 'prompt-highlight';
});

// --- PRIVATE LEAVE EVENTS ---

// Fall A: Ich habe /leave getippt
socket.on('private_leave_confirm', () => {
    // Sofort raus, ohne Timer (ich wollte ja gehen)
    deleteChat(activeChatId);
    printLine('>>> CONNECTION TERMINATED. LOCAL SHELL ACTIVE.', 'system-msg');
});

// Fall B: Mein Partner ist gegangen (Countdown startet + Voice Kill)
socket.on('private_leave_received', (data) => {
    // ID bestimmen
    const targetChatId = data.key || data.name;

    // Check: Chat vorhanden?
    if (!myChats[targetChatId]) {
        // Falls Chat schon weg ist, aber wir noch Voice haben -> Kill it
        if (currentVoiceTarget === targetChatId) {
            endAudioStream();
            currentVoiceTarget = null;
            printLine('>>> AUDIO SIGNAL LOST (Remote Disconnect).', 'error-msg');
        }
        return;
    }

    // --- NEU: VOICE KILL SWITCH ---
    if (currentVoiceTarget === targetChatId) {
        // Audio hart beenden
        endAudioStream();
        currentVoiceTarget = null;
        updateVoiceUI('idle');

        // Nachricht IN den Chat schreiben, bevor er gelöscht wird
        printToChat(targetChatId, '----------------------------------------', 'error-msg');
        printToChat(targetChatId, '>>> CRITICAL ALERT: AUDIO UPLINK SEVERED.', 'error-msg');
        printToChat(targetChatId, '>>> VOICE CONNECTION TERMINATED BY REMOTE EXIT.', 'error-msg');
        printToChat(targetChatId, '----------------------------------------', 'error-msg');
    }
    // -----------------------------

    // Nachricht für Text-Chat Abbruch
    printToChat(targetChatId, ' ', '');
    printToChat(targetChatId, '----------------------------------------', 'error-msg');
    printToChat(targetChatId, `>>> CONNECTION SEVERED: ${data.name} left the chat.`, 'error-msg');
    printToChat(targetChatId, `>>> AUTO-DESTRUCT SEQUENCE INITIATED.`, 'error-msg');
    printToChat(targetChatId, `>>> DATA PURGE IN 15 SECONDS...`, 'error-msg');
    printToChat(targetChatId, '----------------------------------------', 'error-msg');

    // UI Update, falls wir drauf gucken
    if (activeChatId === targetChatId) updateVoiceUI('idle');

    // Timer (wie vorher)
    let timeLeft = 15;
    const timerInterval = setInterval(() => {
        timeLeft--;
        if (timeLeft === 10 || timeLeft === 5) {
            printToChat(targetChatId, `>>> DELETION IN ${timeLeft}s...`, 'system-msg');
        }
        if (timeLeft <= 0) {
            clearInterval(timerInterval);
            deleteChat(targetChatId);
            if (activeChatId === 'LOCAL') {
                printLine(`SYSTEM ALERT: Encrypted logs with ${data.name} have been incinerated.`, 'system-msg');
            }
        }
    }, 1000);
});

// 9. PROMO / INFO BOARD (Das hier aktualisiert die Liste rechts oben)
socket.on('promo_update', (list) => {
    const el = document.getElementById('promo-list');
    if(!el) return;
    el.innerHTML = ''; // Leeren

    if (list.length === 0) {
        el.innerHTML = '<div class="system-msg">No active signals found ...</div>';
        return;
    }

    list.forEach(g => {
        const div = document.createElement('div');
        div.style.marginBottom = '10px';
        div.style.borderBottom = '1px dashed #333';
        div.style.paddingBottom = '5px';
        div.style.cursor = 'pointer';

        // Klick auf Promo joint der Gruppe (optional)
        div.onclick = () => {
            input.value = `/group join ${g.id}`;
            input.focus();
        };

        div.className = 'promo-item';
        div.innerHTML = `
            <div class="promo-name">${g.name} [${g.count}]</div>
            <div class="promo-desc">${g.desc}</div>
            <div class="promo-meta">ID: ${g.id}</div>
        `;
        el.appendChild(div);
    });
});

// ADMIN LOGIN ERFOLGREICH
socket.on('admin_success', (msg) => {
    iamAdmin = true;

    printLine(' ', '');
    printLine('----------------------------------------', 'system-msg');
    printLine(msg, 'system-msg'); // "ACCESS GRANTED..."
    printLine('----------------------------------------', 'system-msg');

    // UI Update: Prompt rot machen und Tag hinzufügen
    promptSpan.textContent = `ADMIN/${myUsername}>`;
    promptSpan.className = 'prompt-error';

    // --- DER FIX: STATE RESET ---
    // Wir müssen prüfen, wo wir vor dem Login waren, und den Status wiederherstellen.

    if (activeChatId === 'LOCAL' || activeChatId === 'HQ_INBOX') {
        appState = 'IDLE';
    }
    else {
        // Wir sind in einem Chat, also müssen wir den Chat-Modus wieder aktivieren
        const currentChat = myChats[activeChatId];

        if (currentChat) {
            if (currentChat.type === 'group') appState = 'GROUP_CHATTING';
            else if (currentChat.type === 'pub') appState = 'PUB_CHATTING';
            else appState = 'CHATTING'; // Privat
        } else {
            appState = 'IDLE'; // Fallback
        }
    }
    // ----------------------------

    // Kleines Update für das User-Panel (falls wir das schon eingebaut haben)
    if (typeof updateUserUI === 'function') updateUserUI();
});

// GLOBAL BROADCAST EMPFANGEN (Das hat auch gefehlt!)
socket.on('global_broadcast_received', (data) => {
    const target = 'LOCAL';
    const initialName = data.isGhost ? 'Anonymous' : data.senderName;

    const broadcastHtml = `
    <div class="broadcast-box">
        <div class="broadcast-title">⚠️ GLOBAL SYSTEM BROADCAST ⚠️</div>
        <div class="broadcast-text">"${data.text}"</div>
        <div class="broadcast-footer">— AUTHORITY: [ADMIN] ${initialName}</div>
    </div>
    `;

    if (myChats[target]) {
        myChats[target].history.push(broadcastHtml);
        if (activeChatId === target) {
            const div = document.createElement('div');
            div.innerHTML = broadcastHtml;
            output.appendChild(div);
            output.scrollTop = output.scrollHeight;
        } else {
            myChats[target].unread++;
            renderChatList();
            // Kleiner Hinweis im aktuellen Chat
            printToChat(activeChatId, `(i) ⚠️ GLOBAL ALERT received. Check LOCAL_SHELL.`, 'error-msg');
        }
    }
});

// BAN EMPFANGEN (Game Over)
socket.on('ban_notification', (data) => {
    // 1. Alle Chats löschen (Visuelle Reinigung)
    myChats = {
        'LOCAL': {
            id: 'LOCAL',
            name: 'LOCAL_SHELL',
            type: 'system',
            history: [],
            unread: 0,
            key: null
        }
    };
    activeChatId = 'LOCAL';
    renderChatList();
    output.innerHTML = ''; // Screen clearen

    // 2. Voice beenden (falls aktiv)
    if (typeof endAudioStream === 'function') endAudioStream();

    // 3. Fette Rote Nachricht
    const banHtml = `
        <div style="
            border: 4px solid #f00; 
            background: #000; 
            color: #f00; 
            padding: 20px; 
            margin-top: 20px; 
            text-align: center;
            font-weight: bold;
            font-family: monospace;
            box-shadow: 0 0 20px #f00;
        ">
            <h1 style="margin:0; font-size: 2em;">ACCESS TERMINATED</h1>
            <p style="font-size: 1.2em; margin: 10px 0;">YOU HAVE BEEN BANNED FROM THE SYSTEM.</p>
            <p style="font-size: 0.8em; color: #888;">Admin Authority Override Initiated.</p>
            <p style="font-size: 0.8em; margin-top: 10px;">[ CONNECTION LOST ]</p>
        </div>
    `;

    const div = document.createElement('div');
    div.innerHTML = banHtml;
    output.appendChild(div);

    // 4. Input deaktivieren (Das "Einfrieren")
    input.disabled = true;
    input.value = '';
    input.placeholder = "SYSTEM LOCKDOWN";
    input.style.borderBottom = "1px solid #f00";

    // Prompt ändern
    promptSpan.textContent = "OFFLINE>";
    promptSpan.style.color = "#f00";

    // Socket client-seitig sicherheitshalber auch schließen
    socket.disconnect();
});

// =============================================================================
// 6. WEBRTC / VOICE / FILE TRANSFER (MULTI-CHAT FIX)
// =============================================================================

function updateVoiceUI(state, callerName = '') {
    if (appState !== 'CHATTING') {
        voiceStatus.textContent = 'SYSTEM IDLE';
        voiceStatus.classList.remove('active', 'alert');
        voiceVisualizer.classList.remove('active');
        voiceControls.innerHTML = `<button class="voice-btn" style="border-color:#333;color:#333;cursor:not-allowed">[ OFFLINE ]</button>`;
        return;
    }
    voiceStatus.style.color = '';
    voiceVisualizer.classList.remove('active'); voiceStatus.classList.remove('active', 'alert');

    if (state === 'idle') {
        voiceStatus.textContent = 'STANDBY';
        voiceControls.innerHTML = `<button class="voice-btn" onclick="startVoiceCall()">[ INIT_CALL ]</button>`;
    } else if (state === 'dialing') {
        voiceStatus.textContent = 'DIALING...'; voiceStatus.classList.add('active');
        voiceControls.innerHTML = `<button class="voice-btn danger" onclick="hangupVoiceCall()">[ ABORT ]</button>`;
    } else if (state === 'ringing') {
        voiceStatus.textContent = `INCOMING: ${callerName}`; voiceStatus.classList.add('alert');
        voiceControls.innerHTML = `<button class="voice-btn" onclick="acceptVoiceCall()">[ ACCEPT ]</button><button class="voice-btn danger" onclick="hangupVoiceCall()">[ DENY ]</button>`;
    } else if (state === 'active') {
        voiceStatus.textContent = 'UPLINK ACTIVE'; voiceStatus.classList.add('active'); voiceVisualizer.classList.add('active');
        voiceControls.innerHTML = `<button class="voice-btn danger" onclick="hangupVoiceCall()">[ TERMINATE ]</button>`;
    }
}

// --- VOICE ACTIONS ---

async function startVoiceCall() {
    // Ziel ist der aktuell offene Chat
    if (!myChats[activeChatId] || myChats[activeChatId].type !== 'private') {
        printLine('ERROR: Voice only available in private channels.', 'error-msg');
        return;
    }

    currentVoiceTarget = activeChatId; // ID merken (das ist der Key)

    socket.emit('voice_request', { targetKey: currentVoiceTarget });
    updateVoiceUI('dialing');
}

async function acceptVoiceCall() {
    if (!currentVoiceTarget) return; // Sollte durch voice_incoming gesetzt sein

    updateVoiceUI('active');

    // Dem Anrufer sagen: Ja, ich nehme ab.
    socket.emit('voice_accept', { targetKey: currentVoiceTarget });

    // Audio starten
    await initAudioStream();
}

function hangupVoiceCall() {
    if (currentVoiceTarget) {
        socket.emit('voice_hangup', { targetKey: currentVoiceTarget });
    }
    endAudioStream();

    printLine('----------------------------------------', 'error-msg');
    printLine('>>> AUDIO UPLINK TERMINATED.', 'error-msg');
    printLine('----------------------------------------', 'error-msg');

    currentVoiceTarget = null;
}

// --- VOICE EVENTS ---

socket.on('voice_incoming', (data) => {
    // data: { caller, callerKey }

    // Wir speichern, wer anruft, damit der Accept-Button weiß, wohin
    currentVoiceTarget = data.callerKey;

    // Wenn wir nicht im Chat des Anrufers sind, wechseln wir vielleicht hin?
    // Oder wir zeigen es nur an. Für jetzt: Anzeigen.

    // Falls wir gerade woanders sind, wechseln wir idealerweise zum Anrufer, damit das UI Sinn macht
    if (activeChatId !== data.callerKey && myChats[data.callerKey]) {
        switchChat(data.callerKey);
    }

    updateVoiceUI('ringing', data.caller);
});

socket.on('voice_connected', async () => {
    // Der andere hat abgenommen!
    await initAudioStream();
    updateVoiceUI('active');
});

socket.on('voice_terminated', () => {
    endAudioStream();
    currentVoiceTarget = null;

    printLine('----------------------------------------', 'error-msg');
    printLine('>>> AUDIO UPLINK SEVERED BY REMOTE SIGNAL.', 'error-msg');
    printLine('----------------------------------------', 'error-msg');
});

// --- HQ EVENTS ---

// 1. Key empfangen (Informant) -> Verschlüsseln & Senden
// SERVER LIEFERT DEN KEY -> WIR VERSCHLÜSSELN & SENDEN
socket.on('hq_key_resp', async (data) => {
    // data: { targetId: "KGB", publicKey: "-----BEGIN PUBLIC KEY..." }

    // Prüfen, ob wir überhaupt einen Tipp senden wollten
    if (!window.pendingTip || window.pendingTip.target !== data.targetId) {
        return;
    }

    printLine('Uplink secured. Encrypting payload...', 'system-msg');

    try {
        // 1. Nachricht verschlüsseln (Mit dem Key aus der DB)
        // Wir nutzen eine Hilfsfunktion (siehe Schritt 2)
        const encryptedContent = await encryptHqMessage(window.pendingTip.msg, data.publicKey);

        // 2. Den verschlüsselten Brief abschicken
        socket.emit('hq_send_tip', {
            targetId: data.targetId,
            content: encryptedContent
        });

        // Aufräumen
        window.pendingTip = null;

    } catch (e) {
        console.error(e);
        printLine('ENCRYPTION ERROR: Could not seal message.', 'error-msg');
    }
});

// AUTH STUFE 1 ERFOLGREICH -> PASSWORT ABFRAGE
socket.on('auth_step_pass_req', (name) => {
    appState = 'AUTH_PASS';
    promptSpan.setAttribute('data-prev-prompt', promptSpan.textContent);

    printLine(' ', '');
    printLine('----------------------------------------', 'system-msg');
    printLine(`UPLINK ESTABLISHED: ${name}`, 'success-msg');
    printLine('IDENTITY VERIFIED. CREDENTIALS REQUIRED.', 'system-msg');
    printLine('Enter Access Password (or "cancel"):', 'my-msg');

    promptSpan.textContent = 'PASSWORD>';
    promptSpan.className = 'prompt-warn';
});

// AUTH STUFE 2 ERFOLGREICH -> 2FA ABFRAGE
socket.on('auth_step_2fa_req', () => {
    appState = 'AUTH_2FA';

    printLine(' ', '');
    printLine('CREDENTIALS ACCEPTED.', 'success-msg');
    printLine('⚠️  MULTI-FACTOR AUTHENTICATION REQUIRED  ⚠️', 'error-msg');
    printLine('Enter 6-digit Google Authenticator Code:', 'my-msg');

    promptSpan.textContent = '2FA CODE>';
    promptSpan.className = 'prompt-error';
});

// AUTH FEHLGESCHLAGEN (Lockout)
socket.on('auth_failed', (reason) => {
    appState = 'IDLE'; // Reset
    promptSpan.textContent = promptSpan.getAttribute('data-prev-prompt') || '>';
    promptSpan.className = 'prompt-default';

    printLine(' ', '');
    printLine('🛑 AUTHENTICATION FAILED 🛑', 'error-msg');
    printLine(reason, 'error-msg');
    printLine('Local terminal session has been flagged.', 'system-msg');
});

// AUTHENTIFIZIERUNGS-SCHRITTE (Antwort vom Server verarbeiten)
socket.on('auth_step', (data) => {
    // data sieht so aus: { step: 'PASS', msg: 'UPLINK ESTABLISHED...' }

    // 1. Nachricht anzeigen
    printLine(data.msg, 'success-msg');

    // 2. Modus umschalten
    if (data.step === 'PASS') {
        appState = 'AUTH_PASS';

        // Prompt ändern
        promptSpan.setAttribute('data-prev-prompt', promptSpan.textContent);
        promptSpan.textContent = 'PASSWORD>';
        promptSpan.className = 'prompt-error'; // Rot für "Sicherheitsbereich"
    }
    else if (data.step === '2FA') {
        appState = 'AUTH_2FA';
        promptSpan.textContent = '2FA-CODE>';
        promptSpan.className = 'prompt-highlight'; // Gelb/Cyan für Wichtigkeit
    }
});

// AUTH FEHLGESCHLAGEN
socket.on('auth_fail', (msg) => {
    printLine(msg, 'error-msg');

    // Reset zum Normalzustand
    appState = 'IDLE';
    promptSpan.textContent = '>';
    promptSpan.className = 'prompt-default';
});

// AUTH SUCCESS (HQ)
socket.on('hq_login_success', async (data) => {
    // data: { id, username, privateKey, ... }

    window.isHqLoggedIn = true;
    window.myInstitutionTag = data.id;

    window.hqSessionStart = Date.now();
    // ------------------------------------

    // --- WICHTIG: PRIVATE KEY SPEICHERN ---
    // Den brauchen wir gleich zum Entschlüsseln der Inbox
    window.hqPrivateKey = data.privateKey;
    // --------------------------------------

    // 1. Private Key speichern (fürs Entschlüsseln)
// 1. Private Key speichern (fürs Entschlüsseln)
    if (data.privateKey) {
        try {
            // WICHTIG: Hier nutzen wir jetzt pemToArrayBuffer!
            const keyBuffer = pemToArrayBuffer(data.privateKey);

            window.hqPrivateKey = await window.crypto.subtle.importKey(
                "pkcs8",
                keyBuffer,
                { name: "RSA-OAEP", hash: "SHA-256" },
                true,
                ["decrypt"]
            );
            window.internalGroupKey = await deriveSharedGroupKey(data.privateKey);
            console.log("[CRYPTO] Shared Group AES-Key generated.");
        } catch(e) {
            console.error("Key Import Error:", e);
            printLine("CRITICAL ERROR: Could not import Encryption Key.", "error-msg");
        }
    }

    myUsername = data.username;

    // 2. Chat "SECURE_INBOX" erstellen
    registerChat('HQ_INBOX', 'SECURE_INBOX', 'system');

    registerChat('HQ_INTERNAL', `[${data.id}] INTERNAL`, 'hq_internal');

    // 3. UI Updates
    printLine(' ', '');
    printLine('########################################', 'success-msg');
    printLine(`WELCOME, DIRECTOR.`, 'success-msg');
    printLine(`UPLINK SECURED: ${data.id}`, 'success-msg');
    printLine('########################################', 'success-msg');

    promptSpan.textContent = `${data.id}/COMMAND>`;
    promptSpan.className = 'prompt-error';

// UI Updates
    activeChatId = 'HQ_INBOX';

    // Chat Objekt anlegen falls nicht existiert
    if (!myChats['HQ_INBOX']) {
        myChats['HQ_INBOX'] = {
            id: 'HQ_INBOX',
            name: 'Secure Inbox',
            type: 'system',
            history: [],
            unread: data.inboxCount || 0
        };
    }

    switchChat('HQ_INBOX');
});

// 3. Inbox Daten (HQ)
// INBOX DATEN EMPFANGEN (Live-Ticker Modus)
socket.on('hq_inbox_data', async (inbox) => {
    const chatId = 'HQ_INBOX';
    const chat = myChats[chatId];
    if (!chat) return;

    // 1. SORTIEREN: Das Neueste (höchster Timestamp) soll nach OBEN (Index 0)
    inbox.sort((a, b) => b.timestamp - a.timestamp);

    // 2. FILTERN: Nur Nachrichten anzeigen, die NACH meinem Login kamen
    // (Wir ignorieren alles, was schon vorher da war)
    const liveMessages = inbox.filter(msg => msg.timestamp >= window.hqSessionStart);

    // Verlauf leeren, wir bauen ihn neu auf
    chat.history = [];

    // Header Info (Optional, damit man sieht, dass es live ist)
    chat.history.push(`<div class="system-msg" style="margin-bottom:20px;">/// SECURE LIVE FEED (SESSION STARTED: ${new Date(window.hqSessionStart).toLocaleTimeString()}) ///</div>`);

    for (const msg of liveMessages) {
        let content = "[DECRYPTING...]";

        // Prüfen ob Key da ist
        if (window.hqPrivateKey) {
            try {
                // Hier rufen wir die NEUE Funktion auf
                content = await decryptHqMessage(msg.content, window.hqPrivateKey);
            } catch(e) {
                console.error(e);
                content = "[DECRYPTION FAILED]";
            }
        } else {
            content = "[KEY MISSING]";
        }

        const senderInfo = `SENDER: ${msg.senderName} [ID: ${msg.senderId}]`;

        // HTML Box
        const html = `
            <div class="inbox-message" style="border: 1px solid #d00; background: rgba(50,0,0,0.2); margin: 10px 0; padding: 10px; position:relative;">
                <div style="font-size: 0.7em; color: #d00; border-bottom: 1px solid #d00; margin-bottom: 5px; display:flex; justify-content:space-between; align-items:center;">
                    <span>RECEIVED: ${new Date(msg.timestamp).toLocaleTimeString()}</span>
                    
                    <button class="voice-btn" style="font-size:0.8em; padding:2px 5px;" onclick="window.initHqConnection('${msg.senderId}')">
                        [ INITIATE HANDSHAKE ]
                    </button>
                </div>
                
                <div style="color: #0f0; font-size: 0.8em; margin-bottom: 5px; font-weight:bold;">
                    ${senderInfo}
                </div>

                <div style="color: #fff; font-family: monospace; white-space: pre-wrap;">${content}</div>
            </div>
        `;
        chat.history.push(html);
    }

    // Wenn gar nichts Neues da ist
    if (liveMessages.length === 0) {
        chat.history.push(`<div class="system-msg" style="opacity:0.5;">... WAITING FOR INCOMING SIGNALS ...</div>`);
    }

    // UI Refresh
    if (activeChatId === chatId) {
        // Da wir switchChat nutzen, wird normalerweise nach unten gescrollt.
        // Bei "Neuestes Oben" ist das okay, aber man sieht halt das Unterste (Älteste der Session).
        // Wir rendern neu:
        switchChat(chatId);

        // OPTIONAL: Wenn du willst, dass man immer OBEN landet (beim Neuesten):
        output.scrollTop = 0;
    } else {
        if (liveMessages.length > 0) {
            chat.unread = liveMessages.length;
            renderChatList();
            printLine(`(i) NEW INTEL RECEIVED (${liveMessages.length})`, 'system-msg');
        }
    }
});

// HQ BROADCAST EMPFANGEN
socket.on('hq_broadcast_received', (data) => {
    // data: { text, instName, instTag, instColor, senderName, timestamp }

    const target = 'LOCAL'; // Immer im Local Shell anzeigen

    // Design: Rahmen und Titel in der Farbe der Institution
    const color = data.instColor;
    const shadow = `0 0 5px ${color}`;

    const html = `
    <div style="
        border: 2px solid ${color}; 
        background: rgba(0, 0, 0, 0.8); 
        padding: 15px; 
        margin: 15px 0; 
        box-shadow: ${shadow};
        position: relative;
    ">
        <div style="
            color: ${color}; 
            font-weight: bold; 
            font-size: 1.1em; 
            border-bottom: 1px solid ${color}; 
            padding-bottom: 8px; 
            margin-bottom: 8px;
            text-shadow: ${shadow};
            text-transform: uppercase;
        ">
            ⚠️ OFFICIAL ANNOUNCEMENT: [${data.instTag}]
        </div>
        
        <div style="
            color: #fff; 
            font-size: 1.1em; 
            text-align: center; 
            padding: 10px 0;
            font-family: monospace;
        ">
            "${data.text}"
        </div>
        
        <div style="
            text-align: right; 
            font-size: 0.8em; 
            color: ${color}; 
            margin-top: 10px;
            opacity: 0.8;
        ">
            — ISSUED BY: ${data.instTag} ${data.senderName}<br>
            ${data.instName}
        </div>
    </div>
    `;

    // 1. In Local Shell History speichern & anzeigen
    if (myChats[target]) {
        myChats[target].history.push(html);

        if (activeChatId === target) {
            const div = document.createElement('div');
            div.innerHTML = html;
            output.appendChild(div);
            output.scrollTop = output.scrollHeight;
        } else {
            myChats[target].unread++;
            renderChatList();

            // 2. Warnung im aktuellen Chat (falls man woanders ist)
            // Wir nutzen hier auch die Farbe der Institution für den Hinweis!
            const alertMsg = `<span style="color:${color}">⚠️ INCOMING SIGNAL from [${data.instTag}] in LOCAL_SHELL</span>`;
            printToChat(activeChatId, alertMsg, '');
        }
    }
});

// --- WEBRTC SIGNALING (P2P) ---

const rtcConfig = { iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] };

function createPeerConnection() {
    peerConnection = new RTCPeerConnection(rtcConfig);

    peerConnection.onicecandidate = e => {
        if (e.candidate && currentVoiceTarget) {
            socket.emit('p2p_signal', {
                targetKey: currentVoiceTarget, // <--- WICHTIG: Ziel mitschicken
                type: 'candidate',
                payload: e.candidate
            });
        }
    };

    peerConnection.ontrack = e => {
        const ra = document.getElementById('remote-audio');
        if (ra.srcObject !== e.streams[0]) ra.srcObject = e.streams[0];
        ra.muted = true; // Web Audio API übernimmt Ausgabe
        startRealtimeVisualizer(e.streams[0]);
    };

    peerConnection.ondatachannel = e => {
        dataChannel = e.channel; setupDataChannelEvents();
    };
}

async function initAudioStream() {
    try {
        localStream = await navigator.mediaDevices.getUserMedia({ audio: true });
        if (!peerConnection) createPeerConnection();
        localStream.getTracks().forEach(t => peerConnection.addTrack(t, localStream));

        const offer = await peerConnection.createOffer();
        await peerConnection.setLocalDescription(offer);

        if (currentVoiceTarget) {
            socket.emit('p2p_signal', {
                targetKey: currentVoiceTarget, // <--- WICHTIG
                type: 'offer',
                payload: offer
            });
        }
    } catch(e) {
        printLine('MIC ERROR: ' + e.message, 'error-msg');
    }
}

function endAudioStream() {
    if (localStream) { localStream.getTracks().forEach(t => t.stop()); localStream = null; }
    stopRealtimeVisualizer(); updateVoiceUI('idle');
}

// Visualizer
function startRealtimeVisualizer(stream) {
    if (!audioContext) audioContext = new (window.AudioContext||window.webkitAudioContext)();

    // Quelle erstellen
    const src = audioContext.createMediaStreamSource(stream);

    // Analyzer erstellen
    analyser = audioContext.createAnalyser();
    analyser.fftSize = 64;

    // 1. Quelle -> Analyzer (für die Optik)
    src.connect(analyser);

    // 2. WICHTIG: Analyzer -> Lautsprecher (für den Sound!)
    // Das fehlte vorher, weshalb der Sound "verschluckt" wurde
    analyser.connect(audioContext.destination);

    const bars = document.querySelectorAll('.voice-visualizer .bar');
    const data = new Uint8Array(analyser.frequencyBinCount);

    function draw() {
        visualizerFrameId = requestAnimationFrame(draw);
        analyser.getByteFrequencyData(data);
        bars.forEach((bar, i) => {
            let h = (data[i+2]||0) / 255 * 100 * 1.5;
            bar.style.height = `${Math.min(100, Math.max(5, h))}%`;
            bar.style.backgroundColor = h>90?'#f00':'#0f0';
        });
    }
    draw();
}
function stopRealtimeVisualizer() {
    if (visualizerFrameId) cancelAnimationFrame(visualizerFrameId);
    document.querySelectorAll('.voice-visualizer .bar').forEach(b => b.style.height='3px');
}

// File Transfer Drop Zone
const dz = document.querySelector('.terminal-col');
const overlay = document.getElementById('drop-overlay');
let dc = 0;
dz.addEventListener('dragenter', e => { dc++; overlay.classList.add('active'); });
dz.addEventListener('dragover', e => e.preventDefault());
dz.addEventListener('dragleave', e => { dc--; if(dc===0) overlay.classList.remove('active'); });
dz.addEventListener('drop', e => {
    e.preventDefault(); dc=0; overlay.classList.remove('active');
    if(e.dataTransfer.files.length) handleFiles(e.dataTransfer.files);
});

function handleFiles(files) {
    if (appState !== 'CHATTING') return printLine('ERROR: Private Chat only.', 'error-msg');

    // Ziel setzen
    currentVoiceTarget = activeChatId;

    const f = files[0];
    printLine(`SENDING: ${f.name}`, 'system-msg');

    if (!peerConnection) createPeerConnection();
    dataChannel = peerConnection.createDataChannel("smuggle");
    setupDataChannelEvents(f);

    peerConnection.createOffer().then(o => peerConnection.setLocalDescription(o)).then(() => {
        socket.emit('p2p_signal', {
            targetKey: currentVoiceTarget, // <--- WICHTIG
            type: 'offer',
            payload: peerConnection.localDescription,
            metadata: { name: f.name, size: f.size }
        });
    });
}

// --- HELPER: Gruppen im Browser speichern ---
function updateLocalGroups(groupName, action) {
    let currentGroups = [];
    try {
        const stored = localStorage.getItem('fs_groups');
        if (stored) currentGroups = JSON.parse(stored);
    } catch (e) { console.error(e); }

    if (action === 'add') {
        if (!currentGroups.includes(groupName)) {
            currentGroups.push(groupName);
        }
    } else if (action === 'remove') {
        currentGroups = currentGroups.filter(g => g !== groupName);
    }

    localStorage.setItem('fs_groups', JSON.stringify(currentGroups));
    console.log(`[STORAGE] Groups updated:`, currentGroups);
}

function setupDataChannelEvents(fileToSend) {
    dataChannel.onopen = () => { if(fileToSend) sendFileInChunks(fileToSend); };
    dataChannel.onmessage = e => {
        receivedBuffers.push(e.data); receivedSize += e.data.byteLength;
        if(receivedSize === incomingFileInfo.size) {
            const blob = new Blob(receivedBuffers);
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a'); a.href=url; a.download=incomingFileInfo.name; a.textContent=`[ DOWNLOAD: ${incomingFileInfo.name} ]`;
            a.style.color='#0f0'; output.appendChild(a);
            receivedBuffers=[]; receivedSize=0;
        }
    };
}
function sendFileInChunks(file) {
    const chunk = 16384; const reader = new FileReader(); let off = 0;
    reader.onload = e => {
        if(dataChannel.readyState!=='open')return;
        dataChannel.send(e.target.result); off += e.target.result.byteLength;
        if(off < file.size) readSlice(off); else printLine('SENT.', 'system-msg');
    };
    const readSlice = o => reader.readAsArrayBuffer(file.slice(o, o + chunk));
    readSlice(0);
}

// --- P2P SIGNAL EVENT (Routing) ---

socket.on('p2p_signal', async d => {
    // Wir prüfen: Kommt das Signal von unserem aktuellen Gesprächspartner?
    // Falls wir noch keinen haben (bei Offer), setzen wir ihn.
    if (!currentVoiceTarget && d.senderKey) {
        currentVoiceTarget = d.senderKey;
    }

    if(!peerConnection) createPeerConnection();

    if(d.type==='offer') {
        incomingFileInfo = d.metadata; // Falls File Transfer
        await peerConnection.setRemoteDescription(d.payload);
        const ans = await peerConnection.createAnswer();
        await peerConnection.setLocalDescription(ans);

        socket.emit('p2p_signal', {
            targetKey: d.senderKey, // <--- Antworten an Sender
            type: 'answer',
            payload: ans
        });

    } else if(d.type==='answer') {
        await peerConnection.setRemoteDescription(d.payload);
    } else if(d.type==='candidate') {
        await peerConnection.addIceCandidate(d.payload);
    }
});

// Push Helper
function urlBase64ToUint8Array(base64String) {
    const padding = '='.repeat((4 - base64String.length % 4) % 4);
    const base64 = (base64String + padding).replace(/-/g, '+').replace(/_/g, '/');
    const rawData = window.atob(base64);
    const outputArray = new Uint8Array(rawData.length);
    for (let i = 0; i < rawData.length; ++i) { outputArray[i] = rawData.charCodeAt(i); }
    return outputArray;
}

async function registerSw(key) {
    if ('serviceWorker' in navigator) {
        try {
            // 1. Registrierung anstoßen
            await navigator.serviceWorker.register('/sw.js');

            // 2. WICHTIG: Warten, bis der Worker wirklich "Active" ist (Safari Fix)
            const reg = await navigator.serviceWorker.ready;

            // 3. Jetzt erst abonnieren (wo wir sicher sind, dass er aktiv ist)
            const sub = await reg.pushManager.subscribe({
                userVisibleOnly: true,
                applicationServerKey: urlBase64ToUint8Array(key)
            });

            socket.emit('save_subscription', sub);
            console.log("[Client] Push Service ready.");

        } catch (err) {
            console.error("[Client] Service Worker Error:", err);
        }
    }
}

// =============================================================================
// BLOG / SYSTEM LOGS MODULE (MASTER-DETAIL VIEW)
// =============================================================================

let viewMode = 'CHAT'; // 'CHAT' oder 'BLOG'
let activeBlogPostId = null; // ID des geöffneten Blogs (null = Liste)
let blogCache = [];

function toggleBlogView() {
    if (viewMode === 'CHAT') {
        viewMode = 'BLOG';
        activeBlogPostId = null; // Immer mit der Liste starten

        document.getElementById('btn-logs').textContent = '[ RETURN TO TERMINAL ]';
        document.getElementById('btn-logs').classList.add('danger');

        // Input auf Suche umschalten
        input.placeholder = "TYPE TO SEARCH ARCHIVES...";
        input.disabled = false;
        input.value = '';
        input.focus();

        // Prompt ändern
        promptSpan.setAttribute('data-prev-prompt', promptSpan.textContent);
        promptSpan.textContent = 'SEARCH_QUERY>';
        promptSpan.style.color = '#ffff00';

        renderBlogView();
        socket.emit('blog_list_req');
    } else {
        viewMode = 'CHAT';
        document.getElementById('btn-logs').textContent = '[ SYSTEM LOGS ]';
        document.getElementById('btn-logs').classList.remove('danger');

        // Input zurücksetzen
        input.placeholder = "";
        input.value = '';
        input.disabled = false;

        // Prompt wiederherstellen
        const oldPrompt = promptSpan.getAttribute('data-prev-prompt');
        if (oldPrompt) promptSpan.textContent = oldPrompt;

        if (appState === 'BOOTING') {
            promptSpan.className = 'prompt-error';
        } else {
            promptSpan.className = 'prompt-default';
        }

        switchChat(activeChatId);
    }
}

// Server schickt Liste
socket.on('blog_list_res', (list) => {
    blogCache = list;
    if (viewMode === 'BLOG') renderBlogView();
});

// Update Signal
socket.on('blog_update_signal', () => {
    if (viewMode === 'BLOG') socket.emit('blog_list_req');
});

// Hilfsfunktion: Suche im Cache
function filterBlogPosts(query) {
    // Wenn man sucht, muss man zwingend zurück zur Liste, sonst sieht man die Ergebnisse nicht
    if (activeBlogPostId !== null && query.length > 0) {
        activeBlogPostId = null;
    }

    if (!query) {
        renderBlogView(blogCache);
        return;
    }

    const term = query.toLowerCase();
    const filtered = blogCache.filter(post => {
        return post.title.toLowerCase().includes(term) ||
            post.content.toLowerCase().includes(term) ||
            (post.tags && post.tags.some(t => t.toLowerCase().includes(term)));
    });

    renderBlogView(filtered);
}

// Haupt-Render-Funktion (Behandelt LISTE und DETAIL)
function renderBlogView(postsToRender = blogCache) {
    output.innerHTML = '';

    // --- HEADER IMMER ANZEIGEN ---
    const header = document.createElement('div');
    header.innerHTML = `
        <div class="blog-header">
            <h2 style="color:#fff; margin:0;">/// SYSTEM ARCHIVES ///</h2>
            <div style="color:#888; font-size:0.8em;">ACCESS LEVEL: ${iamAdmin ? 'ADMINISTRATOR (WRITE ACCESS)' : 'GUEST (READ ONLY)'}</div>
        </div>
        <hr style="border-color:#333; margin: 15px 0;">
    `;
    output.appendChild(header);

    // --- FALL A: EINZELANSICHT (DETAIL) ---
    if (activeBlogPostId !== null) {
        // WICHTIG: Nur '==' benutzen, damit String "1" und Zahl 1 matchen
        const post = blogCache.find(p => p.id == activeBlogPostId);

        if (!post) {
            console.log("Post not found via ID:", activeBlogPostId); // Debug
            activeBlogPostId = null;
            renderBlogView();
            return;
        }

        // --- SICHERHEITS-CHECK ---
        // Wenn der Post geschützt ist UND wir keinen Inhalt haben (weil Server ihn zensiert hat)
        if (post.isProtected && typeof post.content === 'undefined') {
            const detailContainer = document.createElement('div');
            detailContainer.className = 'blog-detail-view';
            detailContainer.innerHTML = `
                <div style="text-align:center; padding: 40px; border: 1px solid #ff3333; background: rgba(50,0,0,0.3);">
                    <h1 style="color:#ff3333;">⚠️ ENCRYPTED DATA DETECTED ⚠️</h1>
                    <p style="color:#fff;">This log entry is protected by a high-level encryption layer.</p>
                    
                    <div style="margin: 20px auto; max-width: 300px;">
                        <input type="password" id="unlock-pass" class="terminal-input" placeholder="ENTER DECRYPTION KEY" style="text-align:center;">
                        <button class="voice-btn" style="width:100%; border-color:#ff3333; color:#ff3333;" onclick="unlockPost('${post.id}')">[ DECRYPT ]</button>
                    </div>
                    
                    <button class="voice-btn" onclick="closeBlogPost()">[ CANCEL ]</button>
                </div>
            `;
            output.appendChild(detailContainer);
            return;
        }
        // -------------------------

        const detailContainer = document.createElement('div');
        detailContainer.className = 'blog-detail-view';

        const date = new Date(post.timestamp).toLocaleString();

// Buttons: Admin ODER Besitzer des Posts
        let showControls = false;

        // 1. Admin darf alles
        if (iamAdmin) showControls = true;

        // 2. Institution darf eigene Posts bearbeiten
        // Wir vergleichen den Tag (z.B. "MI6") mit dem author_tag des Posts
        if (window.isHqLoggedIn && window.myInstitutionTag === post.author_tag) {
            showControls = true;
        }

        let adminBtns = '';
        if (showControls) {
            adminBtns = `
                <div class="blog-actions" style="margin-top:10px;">
                    <span onclick="showEditor('${post.id}')" style="cursor:pointer; color:#0f0; margin-right:15px;">[ EDIT ENTRY ]</span>
                    <span onclick="deletePost('${post.id}')" style="cursor:pointer; color:#f00;">[ DELETE ENTRY ]</span>
                </div>
            `;
        }

        // ANHANG RENDERN?
        let attachmentHtml = '';
        if (post.attachment) {
            const sizeKB = Math.round(post.attachment.size / 1024);
            attachmentHtml = `
                <div style="margin: 20px 0; padding: 10px; border: 1px dashed var(--accent-color); background: rgba(74, 246, 38, 0.05);">
                    <div style="font-weight:bold; margin-bottom:5px;">>>> ATTACHED DATA PACKET FOUND:</div>
                    <div style="color:#fff;">FILE: ${post.attachment.originalName} (${sizeKB} KB)</div>
                    <div style="margin-top:10px;">
                        <a href="${post.attachment.path}" download class="voice-btn" style="text-decoration:none; display:inline-block;">
                            [ DOWNLOAD FILE ]
                        </a>
                    </div>
                </div>
            `;
        }

        detailContainer.innerHTML = `
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:20px;">
                <div style="color:#666;">LOG_ID_${String(post.id).padStart(4, '0')} :: ${date}</div>
                <button class="voice-btn" onclick="closeBlogPost()">[ < CLOSE LOG ]</button>
            </div>

            <h1 class="blog-title-large">${post.title}</h1>
            
            ${attachmentHtml}
            
            <div class="blog-content full-content">
                ${formatContent(post.content)}
            </div>

            <div class="blog-tags" style="margin-top:30px; border-top:1px dashed #333; padding-top:10px;">
                TAGS: ${post.tags.join(' // ')}
            </div>
            ${adminBtns}
        `;

        output.appendChild(detailContainer);
        output.scrollTop = 0;
        return; // HIER STOPPEN, DAMIT DIE LISTE NICHT DARUNTER ERSCHEINT
    }


    // --- FALL B: LISTENANSICHT (DASHBOARD) ---

// Button zeigen, wenn Admin ODER eingeloggt als Institution
    if (iamAdmin || window.isHqLoggedIn) {
        const controls = document.createElement('div');
        controls.className = 'blog-admin-panel';
        controls.innerHTML = `
            <button class="voice-btn" onclick="showEditor()">[ + NEW ENTRY ]</button>
        `;
        output.appendChild(controls);
    }

    const listContainer = document.createElement('div');
    listContainer.className = 'blog-list';

    if (postsToRender.length === 0) {
        listContainer.innerHTML = '<div style="padding:20px; color:#666; text-align:center;">>>> NO ENTRIES FOUND MATCHING QUERY.</div>';
    } else {
        postsToRender.forEach(post => {
            const date = new Date(post.timestamp).toLocaleDateString(); // Nur Datum in der Liste
            const importantClass = post.important ? 'important' : '';

            // --- HIER DIE NEUE ICON LOGIK EINFÜGEN ---
            let icon = '📄';
            if (post.important) icon = '⚠️';
            else if (post.isProtected || post.password) icon = '🔒'; // Schloss Icon
            // -----------------------------------------

            const entry = document.createElement('div');
            entry.className = `blog-entry-item ${importantClass}`;

            // Klick auf das Element öffnet den Post
            entry.onclick = () => openBlogPost(post.id);

            entry.innerHTML = `
                <div class="blog-list-row">
                    <span class="blog-list-icon">${icon}</span>
                    <span class="blog-list-title">${post.title}</span>
                    <span class="blog-list-date">${date}</span>
                </div>
            `;
            listContainer.appendChild(entry);
        });
    }

    output.appendChild(listContainer);
    output.scrollTop = 0;
}

// --- NAVIGATION ACTIONS ---

window.openBlogPost = (id) => {
    activeBlogPostId = id;
    renderBlogView(); // Neu rendern (springt in Fall A)
};

window.closeBlogPost = () => {
    activeBlogPostId = null;
    renderBlogView(); // Neu rendern (springt in Fall B)
};

// Editor anzeigen (Vollständig)
window.showEditor = (editId = null) => {
    let post = { title: '', content: '', tags: [], important: false, attachment: null, password: '' };
    let attachmentInfo = '';

    // Falls wir editieren, Daten laden
    if (editId) {
        const found = blogCache.find(p => p.id == editId);
        if (found) {
            post = found;
            // Falls schon ein Anhang da ist, Info anzeigen
            if (post.attachment) {
                attachmentInfo = `<div style="color:#0f0; font-size:0.8em; margin-top:5px;">[ CURRENT FILE: ${post.attachment.originalName} ]</div>`;
            }
        }
    }

    output.innerHTML = '';

    const editor = document.createElement('div');
    editor.className = 'blog-editor';

    // Wir bauen das HTML jetzt komplett zusammen
    editor.innerHTML = `
        <h3 style="color:#0f0;">>> COMPOSING LOG ENTRY...</h3>
        
        <label>SUBJECT / TITLE:</label>
        <input type="text" id="edit-title" class="terminal-input" value="${post.title || ''}" placeholder="SYSTEM UPDATE...">
        
        <label>ENCRYPTION KEY (OPTIONAL - LEAVE EMPTY FOR PUBLIC):</label>
        <input type="text" id="edit-password" class="terminal-input" value="${post.password || ''}" placeholder="PASSWORD PROTECTION">
        
        <label>DATA CONTENT (MARKDOWN SUPPORTED):</label>
        <textarea id="edit-content" class="terminal-input" style="height:200px;">${post.content || ''}</textarea>
        
        <label>TAGS (COMMA SEPARATED):</label>
        <input type="text" id="edit-tags" class="terminal-input" value="${post.tags ? post.tags.join(', ') : ''}">
        
        <label>ATTACH FILE (OPTIONAL - MAX 5MB):</label>
        <input type="file" id="edit-file" class="terminal-input" style="padding:5px;">
        ${attachmentInfo}

        <div style="margin: 15px 0;">
            <input type="checkbox" id="edit-broadcast" ${post.important ? 'checked' : ''}>
            <label for="edit-broadcast" style="color:#f00; font-weight:bold;">INITIATE NETWORK BROADCAST (ALERT)</label>
        </div>

        <div style="margin-top: 20px;">
            <button class="voice-btn" onclick="savePost('${editId || ''}')">[ COMMIT DATA ]</button>
            <button class="voice-btn danger" onclick="renderBlogView()">[ CANCEL ]</button>
        </div>
    `;
    output.appendChild(editor);
};

// Speichern Funktion (Vollständig mit Passwort & File)
window.savePost = (id) => {
    console.log("Save Post Triggered! ID:", id);
    // 1. Alle Werte aus den Feldern holen
    const title = document.getElementById('edit-title').value.trim();
    const password = document.getElementById('edit-password').value.trim();
    const content = document.getElementById('edit-content').value;
    const tagsVal = document.getElementById('edit-tags').value;
    const tags = tagsVal ? tagsVal.split(',').map(t => t.trim()).filter(t => t) : [];
    const broadcast = document.getElementById('edit-broadcast').checked;
    const fileInput = document.getElementById('edit-file');

    if (!title || !content) {
        alert("ERROR: EMPTY DATA FIELDS.");
        return;
    }

    // Hilfsfunktion zum Senden der Daten
    const sendData = (fileObj = null) => {
        // Wenn wir editieren (id existiert) und KEIN neues File hochladen (fileObj ist null),
        // müssen wir dem Server sagen, dass er das alte Attachment behalten soll.
        let existingAttachment = null;
        if (id && !fileObj) {
            const oldPost = blogCache.find(p => p.id === id);
            if (oldPost && oldPost.attachment) {
                existingAttachment = oldPost.attachment;
            }
        }

        socket.emit('blog_post_req', {
            id: id || null,
            title,
            content,
            tags,
            broadcast,
            password,          // Passwort mitsenden
            file: fileObj,     // Neues File (oder null)
            existingAttachment // Altes File (oder null)
        });

        // Nach dem Speichern zurück zur Liste
        activeBlogPostId = null;
    };

    // Datei Verarbeitung
    if (fileInput.files.length > 0) {
        const file = fileInput.files[0];
        if (file.size > 5 * 1024 * 1024) { // 5MB Limit
            alert("ERROR: FILE TOO LARGE (MAX 5MB).");
            return;
        }

        const reader = new FileReader();
        reader.onload = function(evt) {
            sendData({
                name: file.name,
                size: file.size,
                buffer: evt.target.result // Binärdaten
            });
        };
        reader.readAsArrayBuffer(file);
    } else {
        // Keine neue Datei -> direkt speichern
        sendData(null);
    }
};

window.unlockPost = (id) => {
    const pwd = document.getElementById('unlock-pass').value;
    socket.emit('blog_unlock_req', { id: id, password: pwd });
};

// Wenn der Server das OK gibt
socket.on('blog_unlock_success', (fullPost) => {
    // Wir updaten unseren lokalen Cache mit den entschlüsselten Daten
    const idx = blogCache.findIndex(p => p.id === fullPost.id);
    if (idx >= 0) {
        blogCache[idx] = fullPost; // Jetzt haben wir content & attachment!
        renderBlogView(); // Neu rendern -> Jetzt springt er in die normale Ansicht
    }
});

// --- DIESEN BLOCK IN CLIENT.JS EINFÜGEN ---

socket.on('blog_action_success', (msg) => {
    // 1. Feedback im Chat geben
    printLine(msg, 'success-msg');

    // 2. Editor schließen (Zurück zur Liste)
    activeBlogPostId = null;

    // 3. Liste neu vom Server anfordern
    socket.emit('blog_list_req');

    // (Sobald die Liste da ist, wird renderBlogView() automatisch durch 'blog_list_res' aufgerufen)
});

window.deletePost = (id) => {
    if (confirm("CONFIRM DATA PURGE? THIS CANNOT BE UNDONE.")) {
        socket.emit('blog_delete_req', id);
        activeBlogPostId = null; // Falls wir gerade drin waren
    }
};

function formatContent(text) {
    let html = text
        .replace(/\n/g, '<br>')
        .replace(/\*\*(.*?)\*\*/g, '<b>$1</b>')
        .replace(/\*(.*?)\*/g, '<i>$1</i>')
        .replace(/`(.*?)`/g, '<code style="background:#222; padding:2px;">$1</code>');
    return html;
}

// Sidebar Search Listener
const searchInput = document.getElementById('chat-search-input');
if (searchInput) {
    searchInput.addEventListener('input', () => renderChatList());
}

window.onbeforeunload = () => {
    // Prüfen, ob wir ein Fileshare-Fenster geöffnet haben und ob es noch offen ist
    if (fileShareWindow && !fileShareWindow.closed) {
        fileShareWindow.close(); // Nur DIESES Fenster schließen
    }
};

// =============================================================================
// 7. SECURITY EXTENSIONS (SAFETY NUMBERS & ROTATION)
// =============================================================================

// A) Safety Number Berechnung
async function generateSafetyNumber(myPubKeyString, theirPubKeyString) {
    if (!myPubKeyString || !theirPubKeyString) return "UNKNOWN-KEY-ERROR";
    const keys = [myPubKeyString, theirPubKeyString].sort();
    const combinedData = keys[0] + keys[1];
    const encoder = new TextEncoder();
    const data = encoder.encode(combinedData);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));

    let numString = "";
    for (let i = 0; i < 15; i++) { // 15 Bytes für mehr Sicherheit
        numString += hashArray[i].toString().padStart(3, '0');
    }
    return numString.match(/.{1,5}/g).join('-');
}

// B) Key Rotation Auslöser
async function performKeyRotation(targetKey) {
    const chat = myChats[targetKey];
    if (!chat) return;

    // 1. Neues temporäres KeyPair nur für diese Rotation
    const newKeyPair = await generateKeyPair();
    const exportedPub = await exportPublicKey(newKeyPair.publicKey);

    // 2. Wir merken uns diesen Key, bis die Antwort kommt
    chat.pendingKeyPair = newKeyPair;

    // 3. Signal an Partner senden
    socket.emit('rekey_signal', {
        targetKey: targetKey,
        type: 'request',
        publicKey: exportedPub
    });
}

// C) Key Rotation Listener (Antworten verarbeiten)
socket.on('rekey_signal_received', async (data) => {
    const chat = myChats[data.senderKey];
    if (!chat) return;

    if (data.type === 'request') {
        printToChat(chat.id, `[SECURITY] Partner initiated Key Rotation. Updating keys...`, 'system-msg');

        // 1. Meinen neuen Key machen
        const myNewKeyPair = await generateKeyPair();
        const myExported = await exportPublicKey(myNewKeyPair.publicKey);

        // 2. Seinen Key importieren (für Shared Secret) & speichern (für Safety Number)
        chat.partnerPublicKeyString = data.publicKey; // Speichern für Safety Number
        const partnerNewKey = await importPublicKey(data.publicKey); // Importieren für Crypto

        // 3. Neues Secret berechnen
        const newSecret = await deriveSecretKey(myNewKeyPair.privateKey, data.publicKey);

        // 4. Alles überschreiben
        chat.key = newSecret;
        chat.myKeyPair = myNewKeyPair;

        // Meinen Public Key String aktualisieren (für Safety Number)
        chat.myPublicKeyString = myExported;

        chat.msgCount = 0;

        // 5. Antwort senden
        socket.emit('rekey_signal', {
            targetKey: data.senderKey,
            type: 'response',
            publicKey: myExported
        });
        printToChat(chat.id, `[SECURITY] Rotation complete. Forward Secrecy active.`, 'system-msg');

    } else if (data.type === 'response') {
        if (!chat.pendingKeyPair) return;

        // 1. Seinen Key importieren & speichern
        chat.partnerPublicKeyString = data.publicKey;
        const partnerNewKey = await importPublicKey(data.publicKey);

        // 2. Secret berechnen mit meinem PENDING Key
        const newSecret = await deriveSecretKey(chat.pendingKeyPair.privateKey, data.publicKey);

        // 3. Speichern
        chat.key = newSecret;
        chat.myKeyPair = chat.pendingKeyPair;

        // Meinen Public Key aktualisieren
        chat.myPublicKeyString = await exportPublicKey(chat.pendingKeyPair.publicKey);

        delete chat.pendingKeyPair;
        printToChat(chat.id, `[SECURITY] Key Rotation finalized.`, 'system-msg');
    }
});

// =============================================================================
// 8. HQ / SECURE DROP EXTENSIONS (RSA CRYPTO)
// =============================================================================

// RSA Keypair generieren (Nur für HQ)
async function generateRsaKeyPair() {
    return window.crypto.subtle.generateKey(
        {
            name: "RSA-OAEP",
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: "SHA-256"
        },
        true,
        ["encrypt", "decrypt"]
    );
}

// Nachricht für HQ verschlüsseln (Informant nutzt Public Key)
async function encryptForHq(text, pubKeyPem) {
    const pubKey = await importRsaPublicKey(pubKeyPem);
    const enc = new TextEncoder();
    const encoded = enc.encode(text);

    const buffer = await window.crypto.subtle.encrypt(
        { name: "RSA-OAEP" },
        pubKey,
        encoded
    );
    return arrayBufferToBase64(buffer);
}

// --- RSA ENTSCHLÜSSELUNG (FÜR INBOX) ---

// KORRIGIERTE VERSION: Nimmt direkt das CryptoKey-Objekt
async function decryptHqMessage(base64Cipher, privateKey) {
    try {
        // 1. Ciphertext von Base64 zu Binary wandeln
        const encryptedData = base64ToArrayBuffer(base64Cipher);

        // 2. Entschlüsseln
        // HIER WAR DER FEHLER: Wir müssen den Key nicht mehr importieren,
        // da 'privateKey' (window.hqPrivateKey) bereits ein fertiges Objekt ist!
        const decryptedBuffer = await window.crypto.subtle.decrypt(
            { name: "RSA-OAEP" },
            privateKey,
            encryptedData
        );

        // 3. Zu Text wandeln
        return new TextDecoder().decode(decryptedBuffer);

    } catch (e) {
        console.error("Decryption details:", e);
        throw e;
    }
}

// Helpers
async function importRsaPublicKey(pem) {
    // PEM Header entfernen falls nötig, hier vereinfacht für SPKI format
    const binaryDer = base64ToArrayBuffer(pem);
    return window.crypto.subtle.importKey(
        "spki",
        binaryDer,
        { name: "RSA-OAEP", hash: "SHA-256" },
        true,
        ["encrypt"]
    );
}

// --- RSA VERSCHLÜSSELUNG FÜR HQ TIPPS (SENDER) ---

async function encryptHqMessage(plainText, publicKeyPem) {
    try {
        // 1. PEM String bereinigen und in Binary wandeln
        // WICHTIG: Nutzt pemToArrayBuffer (entfernt Header/Footer)
        const binaryDer = pemToArrayBuffer(publicKeyPem);

        // 2. Key importieren (als SPKI für Public Keys)
        const key = await window.crypto.subtle.importKey(
            "spki",
            binaryDer,
            {
                name: "RSA-OAEP",
                hash: "SHA-256"
            },
            false,
            ["encrypt"]
        );

        // 3. Text encodieren
        const enc = new TextEncoder();
        const encodedData = enc.encode(plainText);

        // 4. Verschlüsseln
        const encryptedData = await window.crypto.subtle.encrypt(
            { name: "RSA-OAEP" },
            key,
            encodedData
        );

        // 5. Als String zurückgeben
        return arrayBufferToBase64(encryptedData);

    } catch(e) {
        console.error("Encryption failed:", e);
        throw e;
    }
}

// --- HILFSFUNKTIONEN ---

// --- HILFSFUNKTIONEN (BEREINIGT) ---

// 1. PEM String zu ArrayBuffer (Entfernt Header/Footer)
function pemToArrayBuffer(pem) {
    const b64 = pem
        .replace(/-----[^-]+-----/g, '') // Header/Footer weg
        .replace(/\s+/g, '');            // Zeilenumbrüche weg

    const str = window.atob(b64);
    const buf = new Uint8Array(str.length);
    for (let i = 0; i < str.length; i++) {
        buf[i] = str.charCodeAt(i);
    }
    return buf.buffer;
}

// 2. Base64 String zu ArrayBuffer (OHNE UNTERSTRICH)
function base64ToArrayBuffer(base64) {
    const binaryString = window.atob(base64);
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
}

// 3. ArrayBuffer zu Base64 String (OHNE UNTERSTRICH)
function arrayBufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
}

// --- HQ INBOX UI ---

function toggleInboxView() {
    if (viewMode === 'CHAT') {
        viewMode = 'INBOX';
        renderInbox([]); // Erstmal leer rendern
        socket.emit('hq_fetch_inbox'); // Daten holen
    } else {
        viewMode = 'CHAT';
        // UI Reset code... (siehe toggleBlogView logic)
        output.innerHTML = '';
        switchChat(activeChatId);
    }
}

async function renderInbox(messages) {
    output.innerHTML = '';

    const header = document.createElement('div');
    header.innerHTML = `
        <div class="blog-header" style="border-color:#f00;">
            <h2 style="color:#f00; margin:0;">/// CLASSIFIED INTEL INBOX ///</h2>
            <div style="color:#888;">IDENTITY: MI6-HQ-007</div>
        </div>
        <div style="margin:10px 0;">
            <button class="voice-btn" onclick="toggleInboxView()">[ EXIT DASHBOARD ]</button>
            <button class="voice-btn" onclick="socket.emit('hq_fetch_inbox')">[ REFRESH ]</button>
        </div>
    `;
    output.appendChild(header);

    const container = document.createElement('div');

    // Wir müssen async map nutzen wegen decrypt
    for (const msg of messages) {
        let content = "[ENCRYPTED]";
        if (window.hqPrivateKey) {
            content = await decryptHqMessage(msg.content, window.hqPrivateKey);
        }

        const div = document.createElement('div');
        div.style.border = "1px solid #333";
        div.style.margin = "10px 0";
        div.style.padding = "10px";
        div.style.background = "rgba(20,0,0,0.5)";

        div.innerHTML = `
            <div style="display:flex; justify-content:space-between; color:#f00; border-bottom:1px solid #333; padding-bottom:5px;">
                <span>RECEIVED: ${new Date(msg.timestamp).toLocaleString()}</span>
                <span onclick="socket.emit('hq_delete_msg', '${msg.id}')" style="cursor:pointer;">[ DELETE ]</span>
            </div>
            <div style="padding: 10px; color: #fff; white-space: pre-wrap; font-family: monospace;">${content}</div>
        `;
        container.appendChild(div);
    }

    output.appendChild(container);
}

// --- LIVE SEARCH FILTER (Für HQ Inbox) ---
document.getElementById('command-input').addEventListener('input', (e) => {
    // Nur aktiv, wenn wir in der Inbox sind
    if (activeChatId === 'HQ_INBOX') {
        const term = e.target.value.toLowerCase();
        // Alle Nachrichten im Chat-Fenster holen
        const messages = document.querySelectorAll('.inbox-message');

        messages.forEach(msg => {
            const text = msg.innerText.toLowerCase();
            // Anzeigen oder Verstecken basierend auf Treffer
            msg.style.display = text.includes(term) ? 'block' : 'none';
        });
    }
});

// A) Button Click Handler
window.initHqConnection = (targetId) => {
    printLine(`Checking carrier signal for Node [${targetId}]...`, 'system-msg');
    // Wir fragen den Server: "Ist der noch da?"
    socket.emit('hq_connect_req', targetId);
};

// B) Server Antwort: Ja, ist online -> Starte normalen Handshake
socket.on('hq_connect_approved', async (data) => {
    // data.targetId ist sicher online.
    const targetKey = data.targetId;

    printLine(`Target confirmed. Initiating Encryption Handshake...`, 'success-msg');

    // 1. Ephemeren Schlüssel generieren
    const ephemeralKeyPair = await generateKeyPair();
    const pubKeyPem = await exportPublicKey(ephemeralKeyPair.publicKey);

    // --- FIX: WIR SPEICHERN DAS KEYPAIR SEPARAT GLOBAL ---
    // Das ist der "VIP Parkplatz" für den HQ-Schlüssel.
    // Egal wie der Server den User später nennt, wir wissen: Das hier ist der Schlüssel.
    window.hqPendingKeyPair = ephemeralKeyPair;
    // -----------------------------------------------------

    // Wir lassen es zur Sicherheit auch im alten Speicher, falls P2P Logik greift
    outgoingConnects[targetKey] = {
        privateKey: ephemeralKeyPair.privateKey,
        publicKeyString: pubKeyPem
    };

    // 2. Request senden
    socket.emit('request_connection', {
        targetKey: targetKey,
        publicKey: pubKeyPem
    });
});

// SETUP UI HANDLER
socket.on('setup_prompt', (data) => {
    if (data.error) {
        printLine(data.msg, 'error-msg');
        return; // Oder appState resetten, je nach Wunsch
    }

    printLine(data.msg, 'system-msg');

    if (data.step === 'CONFIRM') {
        appState = 'SETUP_CONFIRM';
        promptSpan.textContent = 'CONFIRM>';
    }
    else if (data.step === 'EDIT_NAME') {
        appState = 'SETUP_EDIT_NAME';
        promptSpan.textContent = 'NEW-NAME>';
    }
    // --- DIESER TEIL MUSS VORHANDEN SEIN ---
    else if (data.step === 'EDIT_TAG') {
        appState = 'SETUP_EDIT_TAG';
        promptSpan.textContent = 'NEW-TAG>';
    }
    // ---------------------------------------
    else if (data.step === 'DESC') {
        appState = 'SETUP_DESC';
        promptSpan.textContent = 'DESC>';
    }
    else if (data.step === 'PASS') {
        appState = 'SETUP_PASS';
        promptSpan.textContent = 'PASSWORD>';
    }
    else if (data.step === '2FA') {
        appState = 'SETUP_2FA_VERIFY';
        promptSpan.textContent = '2FA-CODE>';
        if (data.secret) printLine('SECRET: ' + data.secret, 'highlight-msg');
    }
});

socket.on('setup_complete', (data) => {
    printLine('SETUP SUCCESSFUL. SYSTEM RESTARTING...', 'success-msg');
    appState = 'IDLE';
    promptSpan.textContent = '>';
    // Optional: Seite neu laden oder User zwingen sich einzuloggen
    setTimeout(() => window.location.reload(), 2000);
});

// HILFSFUNKTION: Shared AES Key aus einem String (z.B. RSA Key) generieren
async function deriveSharedGroupKey(seedString) {
    const enc = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
        "raw",
        enc.encode(seedString),
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
    );

    // Wir nutzen PBKDF2 um aus dem langen String einen sauberen AES Key zu machen
    return window.crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: enc.encode("SHARED_GROUP_SALT"), // Fester Salt für alle Mitglieder der Gruppe
            iterations: 1000,
            hash: "SHA-256"
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );
}

// =============================================================================
// AUTOCOMPLETE SYSTEM (Discord-Style)
// =============================================================================

// 1. Die Datenbank aller Befehle
const COMMAND_LIST = [
    // BASIC
    { cmd: "/connect [KEY]", desc: "Start secure P2P chat" },
    { cmd: "/accept [KEY]", desc: "Accept connection request" },
    { cmd: "/deny [KEY]", desc: "Deny connection request" },
    { cmd: "/leave", desc: "Leave current chat/group" },
    { cmd: "/whisper [ID] [MSG]", desc: "Send encrypted whisper" },

    // UTILS
    { cmd: "/help", desc: "Show command list" },
    { cmd: "/ping [QUERY]", desc: "Scan network for users" },
    { cmd: "/info [KEY]", desc: "Get details about a user" },
    { cmd: "/nudge [KEY]", desc: "Send wake-up push notification" },
    { cmd: "/ghost", desc: "Toggle visibility (Stealth Mode)" },
    { cmd: "/scan", desc: "Scan room for ghosts" },
    { cmd: "/safety", desc: "Show Safety Number fingerprint" },

    // AUTH / HQ
    { cmd: "/auth [TAG]", desc: "Login to Institution" },
    { cmd: "/setup [TOKEN]", desc: "Setup new Institution" },
    { cmd: "/request institution", desc: "Apply for Institution status" },
    { cmd: "/verify [MAIL] [CODE]", desc: "Verify email address" },
    { cmd: "/tip [TAG] [MSG]", desc: "Send anonymous intel to HQ" },
    { cmd: "/hq broadcast [MSG]", desc: "Send Global HQ Alert" },
    { cmd: "/hq description [TXT]", desc: "Update Agency profile" },

    // PUBLIC
    { cmd: "/pub list", desc: "List public sectors" },
    { cmd: "/pub join [ID]", desc: "Join public sector" },
    { cmd: "/pub create [NAME]", desc: "Create new sector" },
    { cmd: "/pub leave", desc: "Leave sector" },

    // GROUPS
    { cmd: "/group create [NAME]", desc: "Create private group" },
    { cmd: "/group join [ID]", desc: "Join a group" },
    { cmd: "/group list", desc: "Show group members" },
    { cmd: "/group leave", desc: "Leave group" },
    { cmd: "/group invite [ID]", desc: "Invite user to group" },
    { cmd: "/group kick [ID]", desc: "Kick user (Owner/Mod)" },
    { cmd: "/group ban [ID]", desc: "Ban user (Owner/Mod)" },
    { cmd: "/group promote [TXT]", desc: "List group on promo board" },
    { cmd: "/group rename [NAME]", desc: "Rename group" },
    { cmd: "/group password [PW]", desc: "Set/Remove password" },
    { cmd: "/group open", desc: "Make group public" },
    { cmd: "/group close", desc: "Make group private" },
    { cmd: "/group link", desc: "Create invite link" },
    { cmd: "/group broadcast [MSG]", desc: "Send group alert" },
    { cmd: "/group dissolve", desc: "Delete group" },

    // DROPS
    { cmd: "/drop create [MSG]", desc: "Create Dead Drop" },
    { cmd: "/drop pickup [ID]", desc: "Pickup Dead Drop" },

    // ADMIN
    { cmd: "/admin auth", desc: "System Administrator Login" },
    { cmd: "/admin requests", desc: "List applications", adminOnly: true },
    { cmd: "/admin approve [ID]", desc: "Approve application", adminOnly: true },
    { cmd: "/admin ban [ID]", desc: "Global server ban", adminOnly: true },
    { cmd: "/broadcast [MSG]", desc: "Global server alert", adminOnly: true }
];

// Variablen für Navigation
let currentFocus = -1;

function initAutocomplete() {
    const inp = document.getElementById("command-input");
    const list = document.getElementById("autocomplete-list");

    // Helper: Befehl extrahieren
    function extractCommand(fullCmd) {
        return fullCmd.split('[')[0].trim() + " ";
    }

    // --- KERN-LOGIK: LISTE BAUEN ---
    // Wir lagern das aus, damit wir es beim Tippen UND beim Reinklicken nutzen können
    function refreshAutocompleteList() {
        const val = inp.value;

        // Liste schließen, wenn leer oder kein Slash am Anfang
        if (!val || !val.startsWith("/")) {
            closeAllLists();
            return;
        }

        currentFocus = -1;
        closeAllLists();

        // Container sichtbar machen
        list.style.display = "block";

        let count = 0;
        const needle = val.toLowerCase();

        COMMAND_LIST.forEach(item => {

            if (item.adminOnly && !iamAdmin) {
                return;
            }

            // Filter: Startet mit Eingabe?
            if (item.cmd.toLowerCase().startsWith(needle)) {

                const div = document.createElement("DIV");

                // Highlight Matching Part
                const matchPart = item.cmd.substr(0, val.length);
                const restPart = item.cmd.substr(val.length);

                // Optional: Admin Befehle rot markieren für Admins
                const extraStyle = item.adminOnly ? 'color:#ff5555;' : '';

                div.innerHTML = `<span style="${extraStyle}"><strong>${matchPart}</strong>${restPart}</span> <span class="cmd-desc">${item.desc}</span>`;

                // Klick Event
                div.addEventListener("click", function() {
                    inp.value = extractCommand(item.cmd);
                    closeAllLists();
                    inp.focus();
                });

                list.appendChild(div);
                count++;
            }
        });

        if (count === 0) closeAllLists();
    }

    // EVENT 1: TIPPEN (Input)
    inp.addEventListener("input", refreshAutocompleteList);

    // EVENT 2: FOKUS (Reinklicken) - <--- DAS IST NEU
    inp.addEventListener("focus", refreshAutocompleteList);

    // EVENT 3: TASTEN (Pfeile & Enter/Tab)
    inp.addEventListener("keydown", function(e) {
        const items = list.getElementsByTagName("div");

        if (list.style.display === "none") return;

        if (e.key === "ArrowDown") {
            currentFocus++;
            addActive(items);
        }
        else if (e.key === "ArrowUp") {
            currentFocus--;
            addActive(items);
        }
        else if (e.key === "Tab" || e.key === "Enter") {
            if (currentFocus > -1 && items.length > 0) {
                e.preventDefault();
                items[currentFocus].click();
            }
            else if (items.length === 1 && e.key === "Tab") {
                e.preventDefault();
                items[0].click();
            }
        }
        else if (e.key === "Escape") {
            closeAllLists();
        }
    });

    function addActive(x) {
        if (!x) return false;
        removeActive(x);
        if (currentFocus >= x.length) currentFocus = 0;
        if (currentFocus < 0) currentFocus = x.length - 1;

        x[currentFocus].classList.add("autocomplete-active");
        x[currentFocus].scrollIntoView({ block: "nearest" });
    }

    function removeActive(x) {
        for (let i = 0; i < x.length; i++) {
            x[i].classList.remove("autocomplete-active");
        }
    }

    function closeAllLists() {
        list.innerHTML = "";
        list.style.display = "none";
    }

    // Schließen wenn man woanders hin klickt
    document.addEventListener("click", function (e) {
        if (e.target !== inp && e.target !== list) {
            closeAllLists();
        }
    });
}

// =============================================================================
// LAYOUT RESIZER (Discord Style)
// =============================================================================

function initResizers() {
    // --- 1. LINKER RESIZER (Sidebar) ---
    const resizerLeft = document.getElementById('drag-left');
    const leftCol = document.getElementById('col-left');

    createResizer(resizerLeft, (e) => {
        // Berechne neue Breite basierend auf Mausposition
        // Die Maus X-Position IST die neue Breite der linken Spalte
        const newWidth = e.clientX;

        // CSS Min/Max Werte werden vom Browser automatisch respektiert,
        // aber wir setzen style.width hart.
        if (newWidth > 180 && newWidth < 500) {
            leftCol.style.width = newWidth + 'px';
        }
    });

    // --- 2. RECHTER RESIZER (Side-Col) ---
    const resizerRight = document.getElementById('drag-right');
    const rightCol = document.getElementById('col-right');

    createResizer(resizerRight, (e) => {
        // Hier ist es umgekehrt: Je weiter wir nach links gehen, desto breiter wird die rechte Spalte.
        // Gesamtbreite des Fensters - Mausposition = Breite rechts
        const newWidth = document.body.clientWidth - e.clientX;

        if (newWidth > 200 && newWidth < 500) {
            rightCol.style.width = newWidth + 'px';
        }
    });

    // --- 3. HORIZONTALER RESIZER (Rechte Spalte: Promo vs Voice) ---
    const resizerH = document.getElementById('drag-horizontal');
    const bottomPanel = document.getElementById('info-window'); // Voice Panel
    // Wir ändern die Höhe des UNTEREN Panels, das obere passt sich dank Flex an

    // Spezial-Version für vertikales Ziehen
    if(resizerH && bottomPanel) {
        resizerH.addEventListener('mousedown', function(e) {
            e.preventDefault();
            document.body.style.cursor = 'row-resize'; // Cursor zwingen

            const startY = e.clientY;
            const startHeight = parseInt(document.defaultView.getComputedStyle(bottomPanel).height, 10);

            function onMouseMove(e) {
                // Ziehen nach unten = Höhe verringern
                // Ziehen nach oben = Höhe vergrößern
                const dy = startY - e.clientY;
                const newHeight = startHeight + dy;

                if (newHeight > 100 && newHeight < 600) {
                    bottomPanel.style.height = newHeight + 'px';
                }
            }

            function onMouseUp() {
                document.body.style.cursor = 'default';
                document.removeEventListener('mousemove', onMouseMove);
                document.removeEventListener('mouseup', onMouseUp);
            }

            document.addEventListener('mousemove', onMouseMove);
            document.addEventListener('mouseup', onMouseUp);
        });
    }
}

// Generische Funktion für Spalten-Resizing
function createResizer(resizer, resizeCallback) {
    if (!resizer) return;

    resizer.addEventListener('mousedown', function(e) {
        e.preventDefault();

        // Klasse hinzufügen für grünen Highlight-Effekt beim Ziehen
        resizer.classList.add('resizing');
        document.body.style.cursor = 'col-resize'; // Cursor überall erzwingen

        function onMouseMove(e) {
            resizeCallback(e);
        }

        function onMouseUp() {
            // Aufräumen
            resizer.classList.remove('resizing');
            document.body.style.cursor = 'default';
            document.removeEventListener('mousemove', onMouseMove);
            document.removeEventListener('mouseup', onMouseUp);
        }

        document.addEventListener('mousemove', onMouseMove);
        document.addEventListener('mouseup', onMouseUp);
    });
}

// Starten!
initResizers();

// Initialisieren
initAutocomplete();

// =============================================================================
// USER PROFILE & SETTINGS MODULE
// =============================================================================

let sessionStartTime = Date.now();
let userBio = ""; // Speichern wir lokal

// 1. UPDATE TIMER (Läuft jede Sekunde)
setInterval(() => {
    const now = Date.now();
    const diff = now - sessionStartTime;

    // Umrechnung in HH:MM:SS
    const hrs = Math.floor(diff / (1000 * 60 * 60));
    const mins = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
    const secs = Math.floor((diff % (1000 * 60)) / 1000);

    const timeStr =
        String(hrs).padStart(2, '0') + ':' +
        String(mins).padStart(2, '0') + ':' +
        String(secs).padStart(2, '0');

    // Update in der Sidebar
    const timerEl = document.getElementById('session-timer');
    if (timerEl) timerEl.textContent = timeStr;
}, 1000);

// 2. GUI UPDATE (Sidebar Footer aktualisieren)
function updateUserUI() {
    if (!myKey) return; // Noch nicht eingeloggt

    // Avatar Initiale
    const initial = (myUsername || 'U').charAt(0).toUpperCase();
    document.getElementById('current-user-avatar').innerHTML = `<span>${initial}</span>`;

    // Name
    document.getElementById('current-user-name').textContent = myUsername;

    // ID (Formatieren für Lesbarkeit)
    document.getElementById('current-user-id').textContent = `#${myKey}`;

    // Role (Optional, Farbe ändern)
    // Kann erweitert werden wenn wir window.myRole speichern
}

// 3. MODAL ÖFFNEN
window.openSettings = () => {
    const modal = document.getElementById('settings-modal');
    modal.classList.add('open');

    // Werte füllen
    document.getElementById('modal-id').textContent = myKey;
    document.getElementById('modal-username').value = myUsername;
    document.getElementById('modal-bio').value = userBio;

    // Login Time
    const date = new Date(sessionStartTime);
    document.getElementById('login-time-display').textContent = `Session started: ${date.toLocaleTimeString()}`;

    // Role Ermittlung (Visuell)
    let role = "USER";
    let color = "#888";
    if (iamAdmin) { role = "SYSTEM ADMIN"; color = "#ff3333"; }
    else if (window.myInstitutionTag) { role = `AGENT [${window.myInstitutionTag}]`; color = "#00ff00"; }

    const roleBadge = document.getElementById('modal-role');
    roleBadge.textContent = role;
    roleBadge.style.backgroundColor = color;

    // Ghost Toggle Status setzen
    // Wir prüfen, ob wir aktuell Ghost sind (Variable aus deinem bestehenden Code?)
    // Falls nicht vorhanden, fügen wir eine globale Variable hinzu oder nutzen DOM Check.
    // Wir nehmen an 'window.isGhostActive' (das bauen wir gleich ein)
    document.getElementById('modal-ghost-toggle').checked = window.isGhostActive || false;
};

window.closeSettings = () => {
    document.getElementById('settings-modal').classList.remove('open');
};

// 4. SPEICHERN
window.saveProfile = () => {
    const newName = document.getElementById('modal-username').value.trim();
    const newBio = document.getElementById('modal-bio').value.trim();

    if (!newName) {
        alert("Username cannot be empty.");
        return;
    }

    // Lokal updaten
    myUsername = newName;
    userBio = newBio;

    // Server informieren
    socket.emit('update_profile', {
        username: newName,
        bio: newBio
    });

    updateUserUI(); // Footer aktualisieren
    closeSettings();
    printLine('(i) Profile updated locally and on server.', 'system-msg');
};

// 5. GHOST TOGGLE (Vom Modal aus)
window.toggleGhostFromModal = () => {
    const toggle = document.getElementById('modal-ghost-toggle');
    // Wir nutzen den existierenden Socket Befehl
    socket.emit('toggle_ghost');
    // UI Feedback kommt über den Socket 'system_message' zurück
};

// 6. EVENT LISTENER FÜR REGISTERED (Damit UI beim Start gefüllt wird)
// Suche in deinem existierenden Code socket.on('registered'...) und füge das am Ende hinzu:
// updateUserUI();
// sessionStartTime = Date.now();

// =============================================================================
// USER POPUP SYSTEM
// =============================================================================

let currentPopupKey = null;

window.openUserPopup = (e, key) => {
    e.stopPropagation(); // Verhindert, dass der Klick das Popup sofort wieder schließt
    currentPopupKey = key;

    const popup = document.getElementById('user-popup');

    // 1. Positionieren (neben der Maus)
    // Wir justieren es etwas, damit es nicht aus dem Bild rutscht
    let x = e.clientX + 10;
    let y = e.clientY + 10;

    // Screen Rand Check (einfach)
    if (x + 280 > window.innerWidth) x = e.clientX - 290;
    if (y + 200 > window.innerHeight) y = e.clientY - 210;

    popup.style.left = x + 'px';
    popup.style.top = y + 'px';
    popup.style.display = 'block';

    // 2. Reset / Loading State
    document.getElementById('popup-name').textContent = "Loading...";
    document.getElementById('popup-name').style.color = '#fff'; // Reset Farbe
    document.getElementById('popup-id').textContent = `ID: ${key}`;
    document.getElementById('popup-bio').textContent = "...";
    document.getElementById('popup-avatar').innerText = "?";
    document.getElementById('popup-meta').style.display = 'none'; // Admin Bereich aus

    // 3. Daten vom Server anfordern
    // Wir senden auch die aktuelle ChatID mit, damit der Server weiß,
    // ob wir im selben Gruppenraum sind (für Mod-Rechte).
    socket.emit('get_profile_details', { targetKey: key, contextId: activeChatId });
};

// Antwort vom Server empfangen
socket.on('profile_details_result', (data) => {
    // data: { username, bio, isGhost, realName, joinTime, ip, isPrivilegedView }

    // Prüfen ob das Popup noch für diesen User offen ist
    if (!currentPopupKey) return;

    // 1. AVATAR LOGIK
    const initial = (data.username || '?').charAt(0).toUpperCase();
    document.getElementById('popup-avatar').innerText = initial;

    if (data.isGhost) {
        document.getElementById('popup-name').style.color = '#888'; // Grau für Ghost
        if (!data.isPrivilegedView) {
            document.getElementById('popup-avatar').style.backgroundColor = '#444';
        }
    } else {
        document.getElementById('popup-avatar').style.backgroundColor = 'var(--accent-color)';
        document.getElementById('popup-name').style.color = '#fff'; // Reset Farbe
    }

    // 2. NAME & BIO SETZEN
    document.getElementById('popup-name').textContent = data.username;
    document.getElementById('popup-bio').textContent = data.bio || "No description.";

    // --- FIX 1: ID MASKIEREN (GHOST SECURITY) ---
    // Wenn der User ein Ghost ist UND ich keine Rechte habe -> ID verstecken!
    const idSpan = document.getElementById('popup-id');
    const copyIcon = document.querySelector('.copy-icon');

    if (data.isGhost && !data.isPrivilegedView) {
        idSpan.textContent = "ID: [ENCRYPTED]";
        idSpan.style.color = "#666"; // Dunkler machen
        copyIcon.style.display = 'none'; // Kopieren verbieten!
    } else {
        idSpan.textContent = `ID: ${currentPopupKey}`;
        idSpan.style.color = ""; // Reset Farbe
        copyIcon.style.display = 'inline-block'; // Kopieren erlauben
    }
    // ---------------------------------------------

    // --- FIX 2: ADMIN BEREICH AUFRÄUMEN ---
    const metaDiv = document.getElementById('popup-meta');

    if (data.isPrivilegedView) {
        metaDiv.style.display = 'block';

        // Wir verstecken die "Real Identity" Zeile, da der Name oben schon echt ist!
        // (Wir greifen das Element direkt, falls es im HTML noch steht)
        const realNameEl = document.getElementById('popup-realname');
        if(realNameEl) realNameEl.style.display = 'none';

        const time = new Date(data.joinTime).toLocaleString();
        document.getElementById('popup-jointime').textContent = `First Seen: ${time}`;

        // IP (nur für Global Admin interessant, sonst ausblenden)
        if (iamAdmin && data.ip) {
            document.getElementById('popup-ip').textContent = `IP: ${data.ip}`;
            document.getElementById('popup-ip').style.display = 'block';
        } else {
            document.getElementById('popup-ip').style.display = 'none';
        }
    } else {
        metaDiv.style.display = 'none';
    }
});

// Copy Funktion für das Icon
window.copyPopupId = () => {
    if (currentPopupKey) {
        navigator.clipboard.writeText(currentPopupKey);
        // Kleines visuelles Feedback
        const idSpan = document.getElementById('popup-id');
        const oldText = idSpan.textContent;
        idSpan.textContent = "COPIED!";
        idSpan.style.color = "#0f0";
        setTimeout(() => {
            idSpan.textContent = oldText;
            idSpan.style.color = "";
        }, 1000);
    }
};

// Schließen beim Klick woanders
document.addEventListener('click', (e) => {
    const popup = document.getElementById('user-popup');
    // Wenn Klick NICHT im Popup war
    if (!popup.contains(e.target)) {
        popup.style.display = 'none';
        currentPopupKey = null;
    }
});

// =============================================================================
// THE WIRE (FEED SYSTEM)
// =============================================================================

let wireFeedCache = [];

// 1. View Toggler (Unified Input Version)
window.toggleWireView = () => {
    const wire = document.getElementById('wire-view');
    const output = document.getElementById('output');
    const inputField = document.getElementById('command-input'); // Das untere Feld

    if (wire.style.display === 'none') {
        // --- WIRE EINSCHALTEN ---
        viewMode = 'WIRE'; // Globaler Modus-Wechsel

        wire.style.display = 'flex';
        output.style.display = 'none';

        // Daten holen
        socket.emit('wire_load_req');

        // Button Highlight
        document.getElementById('btn-wire').classList.add('active');
        document.getElementById('btn-wire').style.borderColor = 'var(--accent-color)';

        // --- INPUT LEISTE UMBAUEN ---
        inputField.value = '';
        inputField.placeholder = "TYPE KEYWORDS TO FILTER FREQUENCIES...";
        inputField.focus();

        // Prompt anpassen
        promptSpan.setAttribute('data-prev-prompt', promptSpan.textContent);
        promptSpan.textContent = 'WIRE/SCAN>';
        promptSpan.className = 'prompt-warn'; // Gelb für "Scanner Modus"

    } else {
        // --- WIRE AUSSCHALTEN (ZURÜCK ZUM CHAT) ---
        viewMode = 'CHAT';

        wire.style.display = 'none';
        output.style.display = 'block';

        document.getElementById('btn-wire').classList.remove('active');
        document.getElementById('btn-wire').style.borderColor = '';

        // Input Reset
        inputField.value = '';
        inputField.placeholder = ""; // Standard Placeholder kommt durch switchChat wieder

        // Prompt Reset
        const oldPrompt = promptSpan.getAttribute('data-prev-prompt');
        if (oldPrompt) promptSpan.textContent = oldPrompt;
        promptSpan.className = 'prompt-default';

        // Zurück zum aktuellen Chat
        switchChat(activeChatId);
    }
};

// 2. Post Absenden
window.submitWirePost = () => {
    const content = document.getElementById('wire-content').value.trim();
    const tagsRaw = document.getElementById('wire-tags').value.trim();

    if(!content) {
        alert("Payload empty.");
        return;
    }

    const tags = tagsRaw.split(' ').filter(t => t.startsWith('#'));

    socket.emit('wire_post', { content, tags });

    closeWireModal();
    document.getElementById('wire-content').value = '';
    document.getElementById('wire-tags').value = '';
};

// 3. Feed Update Empfangen (Rendern)
socket.on('wire_update', (posts) => {
    wireFeedCache = posts; // Speichern für Suche
    renderWireFeed(posts);
});

function renderWireFeed(posts) {
    const list = document.getElementById('wire-feed-list');

    // Leeren State behandeln
    if (posts.length === 0) {
        list.innerHTML = '<div style="text-align:center; color:#666; margin-top:50px;">NO SIGNAL DETECTED.</div>';
        return;
    }
    // Falls vorher der "Empty"-Text da war, Liste leeren
    if (list.children.length > 0 && list.firstElementChild.innerText === "NO SIGNAL DETECTED.") {
        list.innerHTML = '';
    }

    const processedIds = new Set();

    posts.forEach(p => {
        processedIds.add(p.id);
        let card = document.getElementById(`post-${p.id}`);

        // --- BERECHNUNGEN ---
        const now = Date.now();
        const timeLeftMs = p.expiresAt - now;
        let ttlDisplay = "EXPIRED";
        if (timeLeftMs > 0) {
            const h = Math.floor(timeLeftMs / (1000 * 60 * 60));
            const m = Math.floor((timeLeftMs % (1000 * 60 * 60)) / (1000 * 60));
            ttlDisplay = `${h}h ${m}m`;
        }

        const isFueled = p.fuelers.includes(myKey);
        const activeFuelClass = isFueled ? 'fueled' : '';
        const fuelBtnClass = `wire-action action-fuel ${activeFuelClass}`;

        // ID Status Berechnung
        let idDisplayClass = p.isAuthorOnline ? "wire-id" : "wire-id offline";
        let idDisplayText = p.isAuthorOnline ? `ID: ${p.authorKey}` : `ID: [DISCONNECTED]`;

        // HIER WAR DER FEHLER: Wir definieren die Variable jetzt explizit!
        let idDisplay = `<span class="${idDisplayClass}">${idDisplayText}</span>`;

        // ============================================================
        // FALL A: UPDATE VORHANDENER POST (DOM Patching)
        // ============================================================
        if (card) {
            // 1. Fuel Update
            const fuelBtn = card.querySelector('.action-fuel');
            if (fuelBtn) {
                fuelBtn.className = fuelBtnClass;
                const timeSpan = fuelBtn.querySelector('.fuel-timer');
                if (timeSpan && timeSpan.innerText !== ttlDisplay) {
                    timeSpan.innerText = ttlDisplay;
                }
            }

            // 2. Comment Update
            const commentSpan = card.querySelector('.action-chat span');
            if (commentSpan && commentSpan.innerText !== String(p.commentCount)) {
                commentSpan.innerText = p.commentCount;
            }

            // 3. Online Status Update
            const idSpan = card.querySelector('.wire-id');
            if (idSpan) {
                if (idSpan.className !== idDisplayClass) idSpan.className = idDisplayClass;
                if (idSpan.innerText !== idDisplayText) idSpan.innerText = idDisplayText;
            }

            list.appendChild(card); // Position sichern
        }

            // ============================================================
            // FALL B: NEUEN POST ERSTELLEN
        // ============================================================
        else {
            card = document.createElement('div');
            card.className = 'wire-card';
            card.id = `post-${p.id}`;

            // Attachment
            let attachmentHtml = '';
            if (p.attachment) {
                const att = p.attachment;
                if (att.type.startsWith('image/')) {
                    attachmentHtml = `<div class="wire-media-container"><img src="${att.path}" class="wire-media-img" loading="lazy" onclick="window.open('${att.path}', '_blank')" title="Click to view full size"></div>`;
                } else if (att.type.startsWith('video/')) {
                    attachmentHtml = `<div class="wire-media-container"><video src="${att.path}" class="wire-media-video" controls preload="metadata"></video></div>`;
                } else {
                    const sizeKB = (att.size / 1024).toFixed(1) + ' KB';
                    attachmentHtml = `<div class="wire-file-link" onclick="window.confirmDownload('${att.originalName}', '${att.path}')"><div class="file-icon">💾</div><div class="file-info"><div class="file-name">${att.originalName}</div><div class="file-meta">DATA_PACKET // ${sizeKB} // CLICK_TO_EXTRACT</div></div></div>`;
                }
            }

            const timeDisplay = new Date(p.createdAt).toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'});

            // HTML String (Jetzt funktioniert ${idDisplay}!)
            card.innerHTML = `
                <div class="wire-header">
                    <span class="wire-name">${p.authorName}</span>
                    ${idDisplay} 
                    <span class="wire-time">${timeDisplay}</span>
                </div>
                
                <div class="wire-tags">
                    ${p.tags.map(t => `<span class="wire-tag">${t}</span>`).join(' ')}
                </div>
                
                <div class="wire-body" id="body-${p.id}" onclick="window.toggleWirePost(this)">${formatWireContent(p.content)}</div>
                
                <div class="wire-show-more" id="more-${p.id}" onclick="window.toggleWireExpansion('${p.id}')">show more ⋁</div>
                
                ${attachmentHtml}
                
                <div class="wire-footer">
                    <div class="${fuelBtnClass}" onclick="window.triggerWireFuel('${p.id}')">
                        ⚡ <span class="fuel-timer">${ttlDisplay}</span>
                    </div>
                    <div class="wire-action action-chat" onclick="window.openWireComments('${p.id}')">
                        💬 <span>${p.commentCount}</span>
                    </div>
                </div>
            `;

            list.appendChild(card);

            // Show More Logik (Nach dem Rendern messen)
            setTimeout(() => {
                const bodyEl = document.getElementById(`body-${p.id}`);
                const moreEl = document.getElementById(`more-${p.id}`);
                // Toleranz für 3 Zeilen (ca. 4.5em ~ 65px) + 10px Buffer
                if (bodyEl && bodyEl.scrollHeight > bodyEl.clientHeight + 10) {
                    moreEl.style.display = 'block';
                } else if (bodyEl) {
                    bodyEl.classList.add('fully-visible');
                    bodyEl.style.cursor = 'default';
                    if(moreEl) moreEl.style.display = 'none';
                }
            }, 0);
        }
    });

    // Cleanup: Alte Posts entfernen
    const currentCards = Array.from(list.children);
    currentCards.forEach(child => {
        if (child.id && child.id.startsWith('post-')) {
            const rawId = child.id.replace('post-', '');
            if (!processedIds.has(rawId)) {
                child.remove();
            }
        }
    });
}

// HELPER: Post ausklappen und wieder einklappen
window.toggleWireExpansion = (id) => {
    const body = document.getElementById(`body-${id}`);
    const btn = document.getElementById(`more-${id}`);

    // Prüfen: Ist er schon offen?
    const isExpanded = body.classList.contains('expanded');

    if (isExpanded) {
        // EINKLAPPEN
        body.classList.remove('expanded');
        btn.innerHTML = 'show more ⋁';
        // Optional: Nach oben scrollen, falls der Post sehr lang war?
        // body.scrollIntoView({ behavior: 'smooth', block: 'center' });
    } else {
        // AUSKLAPPEN
        body.classList.add('expanded');
        btn.innerHTML = 'show less ⋀';
    }
};

// Helper: Text Formatierung (Links, Newlines)
function formatWireContent(text) {
    return text.replace(/\n/g, '<br>');
}

// HELPER: Nur einen Post gleichzeitig ausklappen
window.toggleWirePost = (element) => {
    // --- NEU: ABBRUCH WENN NICHT ERWEITERBAR ---
    if (!element.classList.contains('expandable')) return;
    // -------------------------------------------

    // 1. Merken, ob der angeklickte Post gerade offen war
    const wasOpen = element.classList.contains('expanded');

    // 2. ALLE offenen Posts im Feed schließen (Reset)
    const allExpanded = document.querySelectorAll('.wire-body.expanded');
    allExpanded.forEach(el => el.classList.remove('expanded'));

    // 3. Öffnen
    if (!wasOpen) {
        element.classList.add('expanded');
    }
};

// 4. Interaktionen
window.triggerWireFuel = (postId) => {
    socket.emit('wire_fuel', postId);
};

window.triggerWireChat = (postId) => {
    // 1. Post im Cache finden, um die GroupID zu bekommen
    const post = wireFeedCache.find(p => p.id === postId);

    // UI Helper: Wire ausblenden, Chat einblenden
    const showChatUI = () => {
        const wire = document.getElementById('wire-view');
        const output = document.getElementById('output');
        wire.style.display = 'none';
        output.style.display = 'block';
        document.getElementById('btn-wire').classList.remove('active');
        document.getElementById('btn-wire').style.borderColor = '';
    };

    if (post && post.discussionId) {
        // CHECK: Habe ich diesen Chat schon?
        if (myChats[post.discussionId]) {
            // JA -> Einfach nur wechseln! Keine Server-Anfrage.
            showChatUI();
            switchChat(post.discussionId);
            return; // HIER STOPPEN WIR
        }
    }

    // NEIN (oder Chat existiert noch gar nicht) -> Server anfunken
    socket.emit('wire_join_chat', postId);

    // UI schon mal umschalten (der Rest passiert wenn 'group_joined_success' kommt)
    showChatUI();
};

// Modals
window.openWireModal = () => {
    const drawer = document.getElementById('wire-compose-drawer');
    drawer.classList.add('open');

    // Fokus direkt ins Textfeld setzen für schnelles Tippen
    setTimeout(() => {
        document.getElementById('wire-content').focus();
    }, 400); // Warten bis Animation fertig ist
};

window.closeWireModal = () => {
    const drawer = document.getElementById('wire-compose-drawer');
    drawer.classList.remove('open');
};

// Character Counter
document.getElementById('wire-content').addEventListener('input', function() {
    document.getElementById('char-count').textContent = this.value.length;
});

let currentCommentPostId = null;
let currentWireFile = null; // Speichert die Datei temporär

// 1. EVENT LISTENERS FÜR DIE INPUTS
// Bild Upload
document.getElementById('wire-img-upload').addEventListener('change', function(e) {
    handleWireFileSelect(e.target.files[0], 'media');
});
// File Upload
document.getElementById('wire-file-upload').addEventListener('change', function(e) {
    handleWireFileSelect(e.target.files[0], 'file');
});

// 2. DATEI VERARBEITUNG & VORSCHAU
function handleWireFileSelect(file, mode) {
    if (!file) return;

    // LIMIT CHECK
    const isVideo = file.type.startsWith('video/');
    const limit = isVideo ? 10 * 1024 * 1024 : 4 * 1024 * 1024; // 10MB Video, 4MB Rest

    if (file.size > limit) {
        alert(`ERROR: File too large. Limit: ${isVideo ? '10MB' : '4MB'}`);
        return;
    }

    currentWireFile = file; // Speichern

    // VORSCHAU BAUEN
    const previewArea = document.getElementById('wire-preview-area');
    const previewContent = document.getElementById('wire-preview-content');
    previewArea.style.display = 'block';

    if (file.type.startsWith('image/')) {
        const url = URL.createObjectURL(file);
        previewContent.innerHTML = `<img src="${url}" style="max-height: 150px; border: 1px solid #333; border-radius: 4px;">`;
    }
    else if (file.type.startsWith('video/')) {
        const url = URL.createObjectURL(file);
        previewContent.innerHTML = `<video src="${url}" style="max-height: 150px; border: 1px solid #333; border-radius: 4px;" controls></video>`;
    }
    else {
        // Generisches File
        previewContent.innerHTML = `
            <div style="background: rgba(255,255,255,0.1); padding: 10px; border: 1px dashed #666; color: #fff; font-family: monospace;">
                📄 ${file.name} <br> <span style="font-size:0.8em; color:#aaa;">(${(file.size/1024).toFixed(1)} KB)</span>
            </div>
        `;
    }
}

// 3. UPLOAD LÖSCHEN (X-Button)
window.clearWireUpload = () => {
    currentWireFile = null;
    document.getElementById('wire-preview-area').style.display = 'none';
    document.getElementById('wire-preview-content').innerHTML = '';
    // Inputs resetten, damit man dasselbe File nochmal wählen kann
    document.getElementById('wire-img-upload').value = '';
    document.getElementById('wire-file-upload').value = '';
};

// 4. SENDEN (Angepasst)
window.submitWirePost = () => {
    const content = document.getElementById('wire-content').value.trim();
    const tagsRaw = document.getElementById('wire-tags').value.trim();

    if (!content && !currentWireFile) {
        alert("Payload empty. Write text or attach data.");
        return;
    }

    const tags = tagsRaw.split(' ').filter(t => t.startsWith('#'));

    // Daten vorbereiten
    const postData = {
        content: content,
        tags: tags,
        file: null
    };

    if (currentWireFile) {
        // Wir lesen die Datei ein und senden sie als Buffer
        const reader = new FileReader();
        reader.onload = function(evt) {
            postData.file = {
                buffer: evt.target.result,
                name: currentWireFile.name,
                type: currentWireFile.type,
                size: currentWireFile.size
            };
            socket.emit('wire_post', postData);
            resetWireDrawer(); // Aufräumen
        };
        reader.readAsArrayBuffer(currentWireFile);
    } else {
        // Nur Text
        socket.emit('wire_post', postData);
        resetWireDrawer();
    }
};

function resetWireDrawer() {
    closeWireModal();
    document.getElementById('wire-content').value = '';
    document.getElementById('wire-tags').value = '';
    clearWireUpload();
}

// 5. DOWNLOAD CONFIRMATION (Security Prompt)
window.confirmDownload = (filename, path) => {
    // Custom Hacker Prompt (window.confirm ist einfach, aber wir können es stylen)
    const choice = confirm(
        `⚠ SECURITY WARNING ⚠\n\n` +
        `File: ${filename}\n\n` +
        `Downloading unknown files can compromise your terminal security.\n` +
        `Are you sure you want to proceed with the extraction?`
    );

    if (choice) {
        // Download erzwingen via unsichtbarem Link
        const link = document.createElement('a');
        link.href = path;
        link.download = filename;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    }
};

// Öffnet den Thread-View
window.openWireComments = (postId) => {
    currentCommentPostId = postId;

    // UI Switch
    document.getElementById('wire-view').style.display = 'none';
    document.getElementById('wire-comments-view').style.display = 'flex';
    document.getElementById('comments-list').innerHTML = '<div style="padding:10px; color:#666;">Loading transmission...</div>';

    // Daten holen
    socket.emit('wire_get_comments_req', postId);
};

// Schließt den Thread-View
window.closeWireComments = () => {
    currentCommentPostId = null;
    document.getElementById('wire-comments-view').style.display = 'none';
    document.getElementById('wire-view').style.display = 'flex';
};

// Character Counter (ID ist gleich geblieben, aber sicherheitshalber:)
const wireContentArea = document.getElementById('wire-content');
if (wireContentArea) {
    wireContentArea.addEventListener('input', function() {
        document.getElementById('char-count').textContent = this.value.length;
    });
}

// Comments empfangen
socket.on('wire_comments_res', (data) => {
    if (currentCommentPostId !== data.postId) return; // Falscher Thread

    const list = document.getElementById('comments-list');
    list.innerHTML = '';

    if (data.comments.length === 0) {
        list.innerHTML = '<div style="padding:20px; text-align:center; color:#444;">No replies yet. Be the first.</div>';
        return;
    }

    data.comments.forEach(c => {
        const time = new Date(c.timestamp).toLocaleTimeString();

        let idDisplay = `[ID: ${c.author_key}]`;
        if (!c.isAuthorOnline) idDisplay = `<span style="color:#ff3333;">[DISCONNECTED]</span>`;

        const item = document.createElement('div');
        item.className = 'comment-item';
        item.innerHTML = `
            <div class="comment-meta">
                <span style="font-weight:bold; color:#fff;">${c.author_name}</span> 
                ${idDisplay} 
                <span style="float:right;">${time}</span>
            </div>
            <div class="comment-text">${formatWireContent(c.content)}</div>
        `;
        list.appendChild(item);
    });

    // Automatisch nach unten scrollen
    list.scrollTop = list.scrollHeight;
});

// Comment absenden
window.submitWireComment = () => {
    const input = document.getElementById('comment-input');
    const content = input.value.trim();
    if (!content || !currentCommentPostId) return;

    socket.emit('wire_submit_comment', {
        postId: currentCommentPostId,
        content: content
    });

    input.value = '';
};

// Live Update für Comments (wenn man drin ist)
socket.on('wire_comments_update', (data) => {
    if (currentCommentPostId === data.postId) {
        socket.emit('wire_get_comments_req', data.postId);
    }
});

// --- INIT ---
runBootSequence();
updateVoiceUI('idle');