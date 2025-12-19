// =============================================================================
// TERMINAL CHAT CLIENT - COMPLETE SYSTEM
// =============================================================================

// --- DOM ELEMENTS ---
const output = document.getElementById('output');
const input = document.getElementById('command-input');
const promptSpan = document.getElementById('prompt');
const inputWrapper = document.querySelector('.input-wrapper');
const cmdMirror = document.getElementById('cmd-mirror');

// Voice / Side Panel Elements
const voiceStatus = document.getElementById('voice-status');
const voiceControls = document.getElementById('voice-controls');
const voiceVisualizer = document.querySelector('.voice-visualizer');
const remoteAudio = document.getElementById('remote-audio');
const chatList = document.getElementById('chat-list');

// --- GLOBAL VARIABLES ---
const socket = io();
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

// --- HISTORY ---
let commandHistory = [];
let historyIndex = -1;
let currentKickTarget = null; // Für Admin Entscheidungen

// --- CRYPTO KEYS (ECDH) ---
let myKeyPair = null; // Unser eigenes Schlüsselpaar

let outgoingConnects = {};
let currentVoiceTarget = null; // Speichert den Key des aktuellen Gesprächspartners

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

// Hilfsfunktion: Erzeugt einen Namen, der sich später ändern kann
function getDynamicName(name, key) {
    if (!key) return name; // Fallback ohne Key
    // Wir erstellen einen Span mit dem Key als Markierung
    return `<span class="dynamic-name" data-key="${key}">${name}</span>`;
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

function registerChat(id, name, type, cryptoKey = null) {
    if (myChats[id]) {
        if (cryptoKey) myChats[id].key = cryptoKey; // Key Update
        return;
    }
    myChats[id] = {
        id: id,
        name: name,
        type: type, // 'group', 'pub', 'private'
        history: [],
        unread: 0,
        key: cryptoKey
    };
    renderChatList();
}

function switchChat(id) {
    if (!myChats[id]) return;
    activeChatId = id;
    myChats[id].unread = 0;
    renderChatList();

    // UI Reset
    output.innerHTML = '';
    myChats[id].history.forEach(html => {
        const div = document.createElement('div');
        div.innerHTML = html;
        output.appendChild(div);
    });
    output.scrollTop = output.scrollHeight;

    // Prompt Update
    const type = myChats[id].type;
    const name = myChats[id].name;

    if (type === 'system') promptSpan.textContent = '>';
    else if (type === 'private') promptSpan.textContent = `SECURE/${name}>`;
    else if (type === 'group') promptSpan.textContent = `GRP/${name}>`;
    else if (type === 'pub') promptSpan.textContent = `PUB/${id}>`;

    // State Update für Voice
    if (type === 'private') {
        appState = 'CHATTING';
        updateVoiceUI('idle');
    } else if (type === 'group') {
        appState = 'GROUP_CHATTING';
        updateVoiceUI('idle');
    } else if (type === 'pub') {
        appState = 'PUB_CHATTING';
        updateVoiceUI('idle');
    } else {
        appState = 'IDLE';
        updateVoiceUI('idle');
    }
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

function renderChatList() {
    chatList.innerHTML = '';
    Object.values(myChats).forEach(chat => {
        const item = document.createElement('div');
        item.className = `chat-item ${chat.id === activeChatId ? 'active' : ''}`;
        item.onclick = () => switchChat(chat.id);

        let display = chat.name;
        if(chat.type === 'private') display = `[P2P] ${chat.name}`;

        item.innerHTML = `
            <span>${display}</span>
            <span class="unread-badge ${chat.unread > 0 ? 'visible' : ''}">!${chat.unread}</span>
        `;
        chatList.appendChild(item);
    });
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
    promptSpan.style.opacity = '0';
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
    promptSpan.style.color = '#ff3333';
    promptSpan.style.opacity = '1';
    input.disabled = false;
    input.focus();
    renderChatList(); // Sidebar initialisieren
}

// =============================================================================
// 4. INPUT & COMMAND HANDLER
// =============================================================================

function updateCursor() {
    const text = input.value;
    const start = input.selectionStart;
    const end = input.selectionEnd;

    cmdMirror.innerHTML = '';

    if (start !== end) {
        inputWrapper.classList.add('has-selection');
        const pre = document.createElement('span'); pre.textContent = text.slice(0, start);
        const sel = document.createElement('span'); sel.className = 'hacker-selection'; sel.textContent = text.slice(start, end);
        const post = document.createElement('span'); post.textContent = text.slice(end);
        cmdMirror.append(pre, sel, post);
    } else {
        inputWrapper.classList.remove('has-selection');
        const pre = document.createElement('span'); pre.id='mirror-text'; pre.textContent = text.slice(0, start);
        const cur = document.createElement('span'); cur.id='cursor-block'; cur.textContent = text.slice(start, start+1) || ' ';
        const post = document.createElement('span'); post.id='mirror-right'; post.textContent = text.slice(start+1);
        cmdMirror.append(pre, cur, post);
        setTimeout(() => cur.scrollIntoView({behavior:"auto", block:"nearest", inline:"nearest"}), 0);
    }
}

input.addEventListener('input', updateCursor);
input.addEventListener('click', updateCursor);
input.addEventListener('select', updateCursor);
input.addEventListener('blur', () => inputWrapper.classList.remove('focused'));
input.addEventListener('focus', () => { inputWrapper.classList.add('focused'); updateCursor(); });

input.addEventListener('keydown', async (e) => {
    if (e.key === 'Enter') {
        const val = input.value.trim();
        if (val) {
            commandHistory.push(val);
            historyIndex = commandHistory.length;
        }
        input.value = ''; updateCursor(); inputWrapper.scrollLeft = 0;
        if (!val) return;

        // Eigene Nachricht anzeigen (außer in Decision Modes)
        if (!appState.startsWith('DECIDING')) {
            printLine(`> ${val}`, 'my-msg');
        }
        await handleInput(val);
    }
    else if (e.key === 'ArrowUp') {
        e.preventDefault();
        if (historyIndex > 0) {
            historyIndex--; input.value = commandHistory[historyIndex];
            setTimeout(() => { input.selectionStart = input.selectionEnd = input.value.length; updateCursor(); }, 0);
        }
    }
    else if (e.key === 'ArrowDown') {
        e.preventDefault();
        if (historyIndex < commandHistory.length - 1) {
            historyIndex++; input.value = commandHistory[historyIndex];
        } else {
            historyIndex = commandHistory.length; input.value = '';
        }
        setTimeout(() => { input.selectionStart = input.selectionEnd = input.value.length; updateCursor(); }, 0);
    }
});

async function handleInput(text) {
    if (appState === 'BOOTING') {
        // 1. SOFORT-CHECK: Ist der Name gültig?
        if (text.startsWith('/') || text.trim().length === 0 || text.length > 20) {
            printLine('ERROR: Invalid format. No "/" allowed at start.', 'error-msg');
            printLine('Please try another CODENAME.', 'my-msg');
            return; // Wir brechen ab und bleiben im BOOTING Modus!
        }

        // 2. Wenn okay, Anfrage senden
        myUsername = text;
        myKeyPair = await generateKeyPair();
        socket.emit('register', myUsername);

        printLine('Authenticating...', 'system-msg');

        // WICHTIG: Wir setzen appState HIER NICHT auf 'IDLE'!
        // Wir warten, bis der Server uns das 'registered' Event schickt.
        // Solange bleibt der User im "Eingabe"-Modus für den Namen.
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
            promptSpan.style.color = '#0f0';
            return;
        }
        else {
            printLine('Invalid option. Type: close, random, transfer [KEY], or cancel.', 'error-msg');
            return;
        }

        // Wenn wir hier sind, wurde ein Befehl gesendet -> UI Reset
        appState = 'IDLE'; // Wird gleich durch group_left_success korrigiert oder wir landen in Local
        promptSpan.textContent = '>';
        promptSpan.style.color = '#0f0';
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

                // WICHTIG: Lokale Variable statt globale, damit wir nichts überschreiben!
                const ephemeralKeyPair = await generateKeyPair();

                // Wir speichern den Private Key spezifisch für DIESES Ziel
                outgoingConnects[targetKey] = ephemeralKeyPair.privateKey;

                const pubKeyPem = await exportPublicKey(ephemeralKeyPair.publicKey);

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
        else if (cmd === '/auth') {
            socket.emit('admin_auth', args[1]);
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
        // --- GHOST MODE ---
        else if (cmd === '/ghost') {
            printLine('Initiating Stealth Protocols...', 'system-msg');
            socket.emit('toggle_ghost');
        }
        else if (cmd === '/group') {
            const sub = args[1];
            if (sub === 'create') socket.emit('group_create', args.slice(2));
            else if (sub === 'join') socket.emit('group_join_req', args[2]);
            else if (sub === 'leave') socket.emit('group_leave');
            else if (sub === 'kick') socket.emit('group_kick', args[2]);
            else if (sub === 'invite') socket.emit('group_invite_req', args.slice(2));
            else if (sub === 'open') socket.emit('group_toggle_privacy', true);
            else if (sub === 'close') socket.emit('group_toggle_privacy', false);
            else if (sub === 'rename') socket.emit('group_rename', args.slice(2).join(' '));
            else if (sub === 'promote') socket.emit('group_promote', args.slice(2).join(' '));
            else if (sub === 'dissolve') socket.emit('group_dissolve');
            else if (sub === 'accept') socket.emit('group_decision', { targetKey: args[2], accept: true });
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
                socket.emit('group_promote', args[1]); // Nutzt das existierende Promote Event
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
        else if (cmd === '/help') {
            printLine('COMMANDS: /connect, /group, /pub, /drop, /ping, /nudge, /info, /auth', 'system-msg');
        }
        return;
    }

    // --- MESSAGING ---
    const currentChat = myChats[activeChatId];
    if (!currentChat || activeChatId === 'LOCAL') {
        printLine('SYSTEM: Local shell. Connect first.', 'error-msg');
        return;
    }
    if (!currentChat.key) {
        printLine('ERROR: Missing encryption key.', 'error-msg');
        return;
    }

// ...
    const encrypted = await encryptMessage(text, currentChat.key);

    if (currentChat.type === 'pub') socket.emit('pub_message', encrypted);
    else if (currentChat.type === 'group') socket.emit('group_message', encrypted);
    if (currentChat.type === 'private') {
        socket.emit('message', {
            targetKey: currentChat.id,
            payload: encrypted // <--- KORRIGIERT: Muss 'encrypted' heißen!
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
    myKey = data.key;       // WICHTIG: Key speichern
    myUsername = data.username;

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
    promptSpan.style.color = '#0f0';

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

// GHOST STATUS UPDATE (Deep Fix für History)
socket.on('user_ghost_update', (data) => {
    // data: { key, username, isGhost }

    const newDisplayName = data.isGhost ? 'Anonymous' : data.username;

    // 1. LIVE DOM UPDATE (Für das, was man gerade sieht)
    const elements = document.querySelectorAll(`.dynamic-name[data-key="${data.key}"]`);
    elements.forEach(el => {
        el.textContent = newDisplayName;
        el.style.opacity = '0.5';
        setTimeout(() => el.style.opacity = '1', 300);
    });

    // 2. SIDEBAR UPDATE (Für Private Chats)
    const chat = myChats[data.key];
    if (chat && chat.type === 'private') {
        chat.name = newDisplayName;
        renderChatList();

        // Wenn der Chat offen ist, auch den Prompt oben anpassen
        if (activeChatId === data.key) {
            promptSpan.textContent = `SECURE/${newDisplayName}>`;
        }
    }

    // 3. HISTORY SPEICHER UPDATE (WICHTIG!)
    // Wir müssen das gespeicherte HTML in ALLEN Chats aktualisieren,
    // sonst wird beim Tab-Wechsel der alte Name wieder geladen.
    Object.values(myChats).forEach(c => {
        if (c.history && c.history.length > 0) {
            c.history = c.history.map(line => {
                // Wir suchen nach dem Span mit diesem Key und ersetzen den Inhalt
                // Regex: Finde <span ... data-key="DER_KEY">ALTE_NAMEN</span>
                const regex = new RegExp(`(<span class="dynamic-name" data-key="${data.key}">)(.*?)(</span>)`, 'g');

                // Ersetze den inneren Teil (Gruppe 2) durch den neuen Namen
                return line.replace(regex, `$1${newDisplayName}$3`);
            });
        }
    });
});

// 4. CHAT START (P2P mit Multi-Request Fix)
socket.on('chat_start', async (data) => {
    const chatId = data.partnerKey || data.partner;

    let finalKey = null;

    // FALL A: Wir sind der Initiator (Wir haben angefragt)
    if (data.publicKey) {
        try {
            // WICHTIG: Wir holen den passenden Private Key aus unserem Speicher!
            // Falls er dort nicht ist (Notfall), nehmen wir den globalen (myKeyPair.privateKey)
            const myPrivateKey = outgoingConnects[chatId] || myKeyPair.privateKey;

            finalKey = await deriveSecretKey(myPrivateKey, data.publicKey);

            // Aufräumen: Key aus dem Speicher löschen, er wird nicht mehr gebraucht
            if (outgoingConnects[chatId]) delete outgoingConnects[chatId];

        } catch(e) {
            console.error("Key Error:", e);
            printLine("CRITICAL ERROR: Key derivation failed.", "error-msg");
        }
    }
    // FALL B: Wir sind der Akzeptierer (Haben Key in /accept berechnet)
    else if (tempDerivedKey) {
        finalKey = tempDerivedKey;
        tempDerivedKey = null;
    }

    // Chat registrieren
    if (finalKey) {
        registerChat(chatId, data.partner, 'private', finalKey);
        switchChat(chatId);

        printToChat(chatId, '----------------------------------------', 'system-msg');
        printToChat(chatId, `>>> SECURE CHANNEL ESTABLISHED WITH: ${getDynamicName(data.partner, chatId)}`, 'system-msg');
        printToChat(chatId, `>>> TARGET ID: ${chatId}`, 'system-msg');
        printToChat(chatId, '----------------------------------------', 'system-msg');

        updateVoiceUI('idle');
    } else {
        // Falls was schiefging und wir keinen Key haben (z.B. Reload während Request)
        if (!myChats[chatId]) {
            printLine(`Handshake failed for ${data.partner}. Please reconnect.`, 'error-msg');
        } else {
            // Wenn Chat schon existiert (z.B. durch Reload), ist alles gut, Key ist im RAM
            switchChat(chatId);
        }
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
        msg = `User ${nameHtml} request approved by Owner.`;
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
    let key = data.key ? await importRoomKey(data.key) : null;
    const name = data.name || `Group_${data.id}`;

    registerChat(data.id, name, 'group', key);
    switchChat(data.id);

    printToChat(data.id, '----------------------------------------');
    printToChat(data.id, `>>> SECURE GROUP ESTABLISHED: ${name} (ID: ${data.id})`, 'system-msg');
    printToChat(data.id, `>>> YOUR ROLE: ${data.role}`, 'system-msg');
    printToChat(data.id, '----------------------------------------');

    updateVoiceUI('idle'); // Voice aus in Gruppe
});

// EINLADUNG EMPFANGEN (Umgeleitet nach LOCAL)
socket.on('group_invite_received', (data) => {
    const target = 'LOCAL';

    printToChat(target, ' ', '');
    printToChat(target, '----------------------------------------', 'partner-msg');
    printToChat(target, `>>> INCOMING INVITATION DETECTED`, 'partner-msg');
    printToChat(target, `TARGET GROUP: ID ${data.groupId}`, 'system-msg');
    printToChat(target, `ORIGIN:       ${data.inviter}`, 'system-msg');
    printToChat(target, ' ', '');
    printToChat(target, `To accept, type:  /group accept ${data.groupId}`, 'my-msg');
    printToChat(target, `To decline, type: /group deny ${data.groupId}`, 'error-msg');
    printToChat(target, '----------------------------------------', 'partner-msg');

    // Kleiner Hinweis im aktuellen Chat, falls man gerade woanders liest
    if (activeChatId !== 'LOCAL') {
        printLine(`(i) New Group Invite in LOCAL_SHELL`, 'system-msg');
    }

    // Optional: Sound
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
    promptSpan.style.color = '#ff3333';

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
socket.on('group_left_success', () => {
    // Falls wir gerade entschieden haben, State resetten
    if (appState === 'DECIDING_GROUP_EXIT') {
        appState = 'IDLE';
    }
    // Chat löschen
    const currentGroupId = Object.keys(myChats).find(k => myChats[k].type === 'group' && activeChatId === k);
    if (currentGroupId) deleteChat(currentGroupId);
    else if (activeChatId !== 'LOCAL') switchChat('LOCAL');
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

// FORCED GROUP DELETION (Wenn Owner schließt)
socket.on('group_dissolved', (groupId) => {
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

        div.innerHTML = `
            <div style="color:#fff; font-weight:bold;">${g.name} [${g.count}]</div>
            <div style="color:#888; font-size:0.8em; margin-top:2px;">${g.desc}</div>
            <div style="color:#444; font-size:0.7em; margin-top:2px;">ID: ${g.id}</div>
        `;
        el.appendChild(div);
    });
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
    if('serviceWorker' in navigator) {
        const reg = await navigator.serviceWorker.register('/sw.js');
        const sub = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: urlBase64ToUint8Array(key) });
        socket.emit('save_subscription', sub);
    }
}

// --- INIT ---
runBootSequence();
updateVoiceUI('idle');