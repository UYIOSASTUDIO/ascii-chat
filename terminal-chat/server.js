require('dotenv').config();

const express = require('express');
const app = express();
const http = require('http');
const { Server } = require("socket.io");
const path = require('path');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const crypto = require('crypto');
const webpush = require('web-push');
const fs = require('fs'); // <--- WICHTIG für das Speichern der Blog-Posts
const escapeHtml = require('escape-html');
const { generateKeyPairSync } = require('crypto');
const db = require('./database'); // Unser neues Modul
const mailer = require('./mailer'); // NEU: Unser Mailer Modul


const publicVapidKey = process.env.VAPID_PUBLIC_KEY;
const privateVapidKey = process.env.VAPID_PRIVATE_KEY;

const setupSessions = {}; // Temp-Speicher für Setup-Daten

const activeGroupLinks = {};
const groups = {};

function generateKeys() {
    const { publicKey, privateKey } = generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'der' },
        privateKeyEncoding: { type: 'pkcs8', format: 'der' }
    });
    return { pub: publicKey.toString('base64'), priv: privateKey.toString('base64') };
}

// Login-Status Speicher (RAM)
// Speichert: { socketId: { step: 0-2, targetId: 'MI6', attempts: 0 } }
const authSessions = {};

if (!publicVapidKey || !privateVapidKey) {
    console.error("FATAL ERROR: VAPID Keys fehlen in der .env Datei!");
    process.exit(1);
}

// Konfiguration
webpush.setVapidDetails(
    'mailto:elias.schmolke@gmail.com',
    publicVapidKey,
    privateVapidKey
);



// --- ADMIN CONFIG ---
// WICHTIG: In einem echten Projekt würde das in einer .env Datei stehen.
// Damit dein Handy den Code behält auch wenn der Server neustartet,
// legen wir hier ein festes Secret fest (oder generieren es beim Start).
// Für diesen Test generieren wir beim Start ein NEUES und zeigen den QR Code im Terminal.
// --- ADMIN CONFIG ---

// HIER DEINEN FESTEN CODE EINTRAGEN:
const myFixedSecret = process.env.ADMIN_SECRET;

if (!myFixedSecret) {
    console.error("FATAL ERROR: ADMIN_SECRET fehlt in der .env Datei!");
    process.exit(1); // Server stoppen, wenn kein Schutz da ist
}

// Wir erstellen das Secret-Objekt manuell
const adminSecret = {
    base32: myFixedSecret,
    otpauth_url: speakeasy.otpauthURL({
        secret: myFixedSecret,
        label: "TerminalChat_Admin",
        encoding: "base32"
    })
};

// QR-Code Status einmalig anzeigen
qrcode.toDataURL(adminSecret.otpauth_url, (err, data_url) => {
    console.log("---------------------------------------------------");
    console.log("🔐 ADMIN SYSTEM READY (FIXED KEY MODE)");
    console.log("Master Key:", adminSecret.base32);
    console.log("---------------------------------------------------");
});

// --- CONFIGURATION ---
const DEBUG_MODE = true; // Setze auf FALSE für absolute Stille im Live-Betrieb

// SPEICHER FÜR RATE LIMITS
const messageRateLimit = {};
const connectionRateLimit = {};

// 1. Der "Flüster-Modus" (Anonyme Logs)
function serverLog(msg) {
    if (DEBUG_MODE) {
        const time = new Date().toLocaleTimeString();
        console.log(`[INFO ${time}] ${msg}`);
    }
}

// 2. Der "Alarm-Modus" (Kritische Fehler)
function serverError(msg) {
    const time = new Date().toLocaleTimeString();
    console.error(`[ERROR ${time}] ⚠️ ${msg}`);
}

// SECURITY HEADERS (Content Security Policy)
// Wir erlauben hier explizit Google Fonts und Flaticon Images
app.use((req, res, next) => {
    res.setHeader(
        "Content-Security-Policy",
        "default-src 'self'; " +
        "script-src 'self' 'unsafe-inline'; " +
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " + // Erlaubt Fonts CSS
        "font-src 'self' https://fonts.gstatic.com; " + // Erlaubt die Font-Dateien
        "img-src 'self' data: https://cdn-icons-png.flaticon.com; " + // Erlaubt das Push-Icon
        "connect-src 'self' ws: wss:;"
    );
    next();
});

const server = http.createServer(app);
const io = new Server(server);

app.use(express.static(path.join(__dirname, 'public')));

let users = {};
let publicRooms = {};
let privateGroups = {}; // Speicher für geschlossene Gruppen
let deadDrops = {};

let activeShares = {};

// --- PROJECT INTELLIGENCE (SECURE DROP) ---
const HQ_CONFIG = {
    id: 'MI6-HQ-007',        // Die feste ID
    username: 'INTELLIGENCE', // Der feste Name
    password: process.env.HQ_PASSWORD || 'secret_intel_pass', // Passwort für den Zugang
    storageFile: path.join(__dirname, 'secure_storage', 'hq_inbox.json')
};

let hqPublicKey = null; // Der aktuelle Public Key des HQ (wird beim Login gesetzt)
let hqInbox = [];       // Speicher für Nachrichten

// Inbox laden beim Start
if (fs.existsSync(HQ_CONFIG.storageFile)) {
    try {
        hqInbox = JSON.parse(fs.readFileSync(HQ_CONFIG.storageFile, 'utf8'));
    } catch (e) { console.error("HQ Inbox Load Error:", e); }
}

function saveHqInbox() {
    fs.writeFileSync(HQ_CONFIG.storageFile, JSON.stringify(hqInbox, null, 2));
}

// Rate Limiting für Tips (Spam Schutz)
const tipRateLimit = {};

// --- BLOG SYSTEM CONFIG ---
const DATA_DIR = path.join(__dirname, 'secure_storage');

// Falls der Ordner nicht existiert, erstellen wir ihn
if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
}

const BLOG_FILE = path.join(DATA_DIR, 'system_logs.json');
let blogPosts = [];

// Blog beim Start laden
if (fs.existsSync(BLOG_FILE)) {
    try {
        blogPosts = JSON.parse(fs.readFileSync(BLOG_FILE, 'utf8'));
        console.log(`[SYSTEM] Loaded ${blogPosts.length} log entries.`);
    } catch (e) {
        console.error("Error loading blog:", e);
    }
} else {
    // Dummy Post erstellen, falls leer
    blogPosts.push({
        id: 'INIT_SEQ',
        timestamp: Date.now(),
        title: 'SYSTEM INITIALIZATION',
        content: 'Core systems online. Encryption active. Welcome to the network.',
        author: 'SYSTEM',
        tags: ['BOOT', 'INFO']
    });
}

function saveBlog() {
    fs.writeFileSync(BLOG_FILE, JSON.stringify(blogPosts, null, 2));
}

// Upload Ordner sicherstellen
const UPLOAD_DIR = path.join(__dirname, 'public', 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) {
    fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}

// Hilfsfunktion: Verbindung sauber trennen
function disconnectPartner(userId) {
    const user = users[userId];
    if (user && user.partnerId) {
        const partnerId = user.partnerId;

        // Partner informieren
        io.to(partnerId).emit('system_message', `VERBINDUNG UNTERBROCHEN: Partner hat den Chat verlassen.`);

        // Verknüpfung beim Partner löschen
        if (users[partnerId]) {
            users[partnerId].partnerId = null;
        }
        // Eigene Verknüpfung löschen
        user.partnerId = null;
    }
}

// --- PUSH HELPER FUNCTION ---
function sendPush(targetUser, title, content) {
    if (targetUser && targetUser.pushSubscription) {
        const payload = JSON.stringify({
            title: title,
            body: content,
            icon: 'https://cdn-icons-png.flaticon.com/512/2069/2069503.png' // Oder dein Favicon
        });

        webpush.sendNotification(targetUser.pushSubscription, payload)
            .catch(err => {
                // Fehler ignorieren (passiert oft wenn Subscription abgelaufen ist)
                // console.error("Push Error:", err);
            });
    }
}

io.on('connection', (socket) => {
    // ANONYM: Wir loggen nicht die ID, nur dass eine Verbindung besteht
    serverLog(`Neue Verbindung (Socket) hergestellt.`);

    // --- FILE SYSTEM AUTHENTIFIZIERUNG ---
// --- LOGIN HANDLER (FILE SYSTEM) ---
    socket.on('fs_login', (data) => {
        socket.username = escapeHtml(data.username || 'Anonymous'); // XSS Schutz auch hier
        // Wir nehmen den User aus der Haupt-Liste, falls er eingeloggt ist
        const mainUser = Object.values(users).find(u => u.username === socket.username);

        console.log(`[LOGIN] FS User: ${socket.username} (ID: ${socket.id})`);

        // VALIDIERUNG: Gruppen beitreten
        if (data.groups && Array.isArray(data.groups)) {
            data.groups.forEach(roomName => {
                // roomName ist z.B. "group_1234" oder "pub_0001"

                // 1. Ist es eine Private Gruppe?
                if (roomName.startsWith('group_')) {
                    const groupId = roomName.replace('group_', '');
                    const group = privateGroups[groupId];

                    // PRAGMATISCHE LÖSUNG: Wir prüfen, ob es einen Haupt-User mit diesem Namen gibt, der in der Gruppe ist.
                    const isLegitMember = group && group.members.some(memberSocketId => {
                        const u = users[memberSocketId];
                        return u && u.username === socket.username;
                    });

                    if (isLegitMember) {
                        socket.join(roomName);
                        // console.log(`   -> Re-joined Room: ${roomName} (Authorized)`);
                    } else {
                        console.log(`   -> BLOCKED join attempt to ${roomName} (Unauthorized)`);
                    }
                }
                // 2. Public Rooms sind okay (da eh public)
                else if (roomName.startsWith('pub_')) {
                    socket.join(roomName);
                }
            });
        }

        // Name in aktiven Shares updaten
        if (activeShares[socket.id]) {
            activeShares[socket.id].username = socket.username;
            broadcastShares();
        }
    });

    // --- ADMIN AUTHENTICATION (TOTP) ---
    socket.on('admin_auth', (token) => {
        // Wir prüfen den Code (Token) gegen unser Secret
        const verified = speakeasy.totp.verify({
            secret: adminSecret.base32,
            encoding: 'base32',
            token: token,
            window: 1 // Erlaubt +/- 30 Sekunden Toleranz (falls Uhrzeit nicht synchron)
        });

        if (verified) {
            users[socket.id].isAdmin = true;
            serverLog(`ACHTUNG: User ${users[socket.id].username} hat sich als ADMIN authentifiziert.`);
            socket.emit('admin_success', 'ACCESS GRANTED. WELCOME, OPERATOR.');
        } else {
            // Fake Error Message zur Abschreckung
            serverLog(`Fehlgeschlagener Admin-Versuch von ${users[socket.id].username}`);
            socket.emit('system_message', 'ACCESS DENIED. INCIDENT REPORTED.');
        }
    });

// --- ADMIN COMMAND: KICK ---
    socket.on('admin_kick', (targetKey) => {
        if (!users[socket.id].isAdmin) {
            socket.emit('system_message', 'ERROR: Insufficient privileges.');
            return;
        }

        const allUsers = Object.values(users);
        const targetUser = allUsers.find(u => u.key === targetKey);

        if (targetUser) {
            // WICHTIG: Zuerst das Ban-Signal senden!
            io.to(targetUser.id).emit('ban_notification');

            // Kurze Verzögerung, damit das Signal sicher ankommt, dann trennen
            setTimeout(() => {
                const targetSocket = io.sockets.sockets.get(targetUser.id);
                if (targetSocket) {
                    targetSocket.disconnect(true);
                }
            }, 100);

            // Bestätigung an den Admin
            socket.emit('system_message', `SUCCESS: User ${targetUser.username} [${targetKey}] terminated.`);
            serverLog(`ADMIN ACTION: User ${targetUser.username} kicked by ${users[socket.id].username}`);
        } else {
            socket.emit('system_message', 'ERROR: Target not found.');
        }
    });

// --- ADMIN COMMAND: GLOBAL BROADCAST (DEBUG VERSION) ---
    socket.on('admin_broadcast', (msg) => {
        const user = users[socket.id];

        console.log(`DEBUG: Admin Broadcast Versuch von ${user ? user.username : 'Unknown'}`);

        if (!user) return;

        // Check Admin Status
        if (!user.isAdmin) {
            console.log("DEBUG: Zugriff verweigert. User ist kein Admin.");
            socket.emit('system_message', 'ERROR: ACCESS DENIED. Insufficient security clearance.');
            return;
        }

        console.log(`DEBUG: Zugriff erlaubt. Sende Nachricht: "${msg}"`);

        // Wenn JA: Nachricht an ALLE senden
        io.emit('global_broadcast_received', {
            text: msg,
            senderName: user.username,
            isGhost: !!user.isGhost
        });
    });

    // --- ADMIN COMMAND: BAN HAMMER ---
    socket.on('admin_ban', (targetKeysInput) => {
        const user = users[socket.id];
        if (!user || !user.isAdmin) {
            socket.emit('system_message', 'ERROR: ACCESS DENIED. God Mode required.');
            return;
        }

        const targets = Array.isArray(targetKeysInput) ? targetKeysInput : [targetKeysInput];
        let banCount = 0;

        targets.forEach(targetKey => {
            const targetUser = Object.values(users).find(u => u.key === targetKey);

            if (targetUser) {
                // Schutz: Admin kann sich nicht selbst oder andere Admins bannen (optional)
                if (targetUser.isAdmin) {
                    socket.emit('system_message', `WARNING: Cannot ban fellow Admin ${targetUser.username}.`);
                    return;
                }

                const targetSocket = io.sockets.sockets.get(targetUser.id);
                if (targetSocket) {
                    // 1. Dem Opfer die schlechte Nachricht überbringen
                    targetSocket.emit('ban_notification', {
                        adminName: user.username // (Optional, wenn du zeigen willst wer es war)
                    });

                    // 2. Kurz warten (damit Nachricht ankommt), dann Verbindung kappen
                    // Das Auslösen von disconnect bereinigt automatisch Gruppen & Chats im Server!
                    setTimeout(() => {
                        targetSocket.disconnect(true);
                    }, 500);

                    banCount++;
                    serverLog(`ADMIN BAN: ${targetUser.username} [${targetKey}] gebannt von ${user.username}.`);
                }
            } else {
                socket.emit('system_message', `WARNING: User ${targetKey} not found.`);
            }
        });

        if (banCount > 0) {
            socket.emit('system_message', `SUCCESS: ${banCount} target(s) neutralized.`);
        }
    });

    // --- HQ SYSTEM (SECURE DROP) ---

    // --- SECURE AUTHENTICATION FLOW (3-STAGE) ---

    // 1. AUTH START (Fix & Debug Version)
    socket.on('auth_init', async (tagRaw) => {
        if (!tagRaw) return;

        // WICHTIG: .trim() entfernt versehentliche Leerzeichen am Anfang/Ende
        const tag = tagRaw.trim().toUpperCase();

        console.log(`[AUTH] Login attempt for TAG: '${tag}'`);

        try {
            const inst = await db.getInstitutionByTag(tag);

            if (inst) {
                console.log(`[AUTH] Institution found: ${inst.name} (ID: ${inst.id})`);

                authSessions[socket.id] = {
                    step: 'PASS',
                    targetId: inst.tag, // Wir nutzen den exakten Tag aus der DB
                    attempts: 0
                };

                // Antwort an Client senden
                socket.emit('auth_step', { step: 'PASS', msg: `UPLINK ESTABLISHED: ${inst.name}` });
            } else {
                console.log(`[AUTH] ERROR: Tag '${tag}' not found in database.`);
                socket.emit('system_message', `ERROR: CONNECTION REFUSED. Gateway [${tag}] not found.`);
            }
        } catch (err) {
            console.error('[AUTH] Critical Database Error:', err);
            socket.emit('system_message', 'ERROR: Internal Server Fault.');
        }
    });

    // STUFE 2: PASSWORT CHECK
    socket.on('auth_verify_pass', async (password) => {
        const session = authSessions[socket.id];
        if (!session || session.step !== 'PASS') return;

        // NEU: Hash Vergleich über DB
        const inst = await db.getInstitutionByTag(session.targetId);

        if (!inst) {
            socket.emit('auth_fail', 'CRITICAL ERROR: Agency target lost.');
            return;
        }

        // bcrypt prüft, ob "007" zum Hash "$2b$..." passt
        const isValid = await db.verifyPassword(password, inst.password_hash);

        if (isValid) {
            session.step = '2FA';
            socket.emit('auth_step', { step: '2FA', msg: 'CREDENTIALS ACCEPTED.' });
        } else {
            session.attempts++;
            if (session.attempts >= 3) {
                delete authSessions[socket.id];
                socket.emit('auth_fail', 'SECURITY ALERT: Too many failed attempts.');
                socket.disconnect();
            } else {
                socket.emit('system_message', `ACCESS DENIED. Invalid credentials. (${session.attempts}/3)`);
            }
        }
    });

    // STUFE 3: 2FA CHECK (Google Authenticator)
    socket.on('auth_verify_2fa', async (token) => {
        const session = authSessions[socket.id];
        if (!session || session.step !== '2FA') return;

        const inst = await db.getInstitutionByTag(session.targetId);

        // Prüfen mit dem Secret aus der DB
        const verified = speakeasy.totp.verify({
            secret: inst.two_factor_secret, // Snake_case beachten!
            encoding: 'base32',
            token: token,
            window: 1
        });

        if (verified) {
            // LOGIN ERFOLGREICH
            delete authSessions[socket.id];

            users[socket.id].institution = {
                tag: inst.tag,
                name: inst.name,
                color: inst.color,
                inboxFile: inst.inbox_file
            };

            // Name Logik
            if (!users[socket.id].originalName) {
                users[socket.id].originalName = users[socket.id].username;
            }
            const newName = `[${inst.tag}] ${users[socket.id].originalName}`;
            users[socket.id].username = newName;

            // --- DEM INTERNEN RAUM BEITRETEN ---
            const internalRoom = `INTERNAL_${inst.tag}`;
            socket.join(internalRoom);
            serverLog(`[INTERNAL] ${users[socket.id].username} joined channel ${internalRoom}`);

            // Inbox laden
            let inbox = [];
            const inboxPath = path.join(DATA_DIR, inst.inbox_file);
            if (fs.existsSync(inboxPath)) {
                try { inbox = JSON.parse(fs.readFileSync(inboxPath, 'utf8')); } catch(e){}
            }

            const tempPrivKey = inst.keys ? inst.keys.priv : "";

            // 1. ERST LOGIN BESTÄTIGEN (Damit Client den Chat erstellt)
            socket.emit('hq_login_success', {
                id: session.targetId,
                username: newName,
                inboxCount: inbox.length,
                privateKey: inst.private_key
            });

            socket.join(`HQ_${session.targetId}`);
            serverLog(`[SECURITY] AUTH SUCCESS: ${users[socket.id].originalName} is active as ${session.targetId}.`);

            // 2. STATUS UPDATE AN ALLE (Institution Tag setzen)
            broadcastInstitutionUpdate(socket.id);

            // --- 3. FIX: JETZT ERST DIE SYSTEM-NACHRICHTEN SENDEN ---
            // Wir nutzen setTimeout, um sicherzugehen, dass der Client den Chat fertig gebaut hat.

            setTimeout(() => {
                // A) Liste der Aktiven berechnen
                const roomMembersSet = io.sockets.adapter.rooms.get(internalRoom);
                let onlineNames = [];

                if (roomMembersSet) {
                    roomMembersSet.forEach(memberSocketId => {
                        const memberUser = users[memberSocketId];
                        if (memberUser) {
                            // Wir nehmen den Originalnamen, das liest sich besser in der Liste
                            onlineNames.push(memberUser.originalName || memberUser.username);
                        }
                    });
                }

                // B) NACHRICHT AN MICH: Wer ist schon da?
                socket.emit('hq_internal_msg_rcv', {
                    sender: 'SYSTEM',
                    text: `ONLINE AGENTS: [ ${onlineNames.join(', ')} ]`,
                    tag: 'SYS',
                    color: '#ffff00' // Gelb
                });

                // C) NACHRICHT AN DIE KOLLEGEN: Ich bin jetzt da! (Das wolltest du)
                socket.to(internalRoom).emit('hq_internal_msg_rcv', {
                    sender: 'SYSTEM',
                    text: `AGENT CONNECTED: ${users[socket.id].originalName}`,
                    tag: 'SYS',
                    color: '#00ff00' // Grün
                });

            }, 500); // 500ms Verzögerung
            // -----------------------------------------------------------

        } else {
            socket.emit('system_message', 'ERROR: Invalid 2FA Code.');
        }
    });

// INFORMANT: Public Key anfordern (für Verschlüsselung)
    socket.on('hq_get_key_req', async (targetId) => { // async wichtig!
        const tag = targetId.toUpperCase();

        // NEU: Datenbankabfrage
        const inst = await db.getInstitutionByTag(tag);

        if (inst && inst.public_key) {
            socket.emit('hq_key_resp', {
                targetId: tag,
                publicKey: inst.public_key // Kommt jetzt aus der DB Spalte
            });
        } else {
            socket.emit('system_message', `ERROR: Secure uplink to [${tag}] failed. Target offline or unknown.`);
        }
    });

    // INFORMANT: Tipp senden
    socket.on('hq_send_tip', async (data) => { // async wichtig!
        // 1. Institution suchen
        const inst = await db.getInstitutionByTag(data.targetId);

        if (!inst) {
            socket.emit('system_message', 'ERROR: Destination not found. Drop failed.');
            return;
        }

        // 2. User Identität sicher holen
        const senderUser = users[socket.id];
        const safeSenderName = senderUser ? senderUser.username : 'Unknown';

        // 3. Speichern (in die JSON Datei der Institution)
        // Wir nutzen inst.inbox_file aus der Datenbank!
        const inboxPath = path.join(DATA_DIR, inst.inbox_file);

        let inbox = [];
        if (fs.existsSync(inboxPath)) {
            try { inbox = JSON.parse(fs.readFileSync(inboxPath, 'utf8')); } catch(e){}
        }

        const msg = {
            id: Date.now() + '-' + Math.floor(Math.random()*10000),
            timestamp: Date.now(),
            content: data.content, // Verschlüsselt
            senderId: socket.id,   // Wichtig für den Handshake-Button
            senderName: safeSenderName
        };

        inbox.push(msg);
        fs.writeFileSync(inboxPath, JSON.stringify(inbox, null, 2));

        socket.emit('system_message', `>>> INTEL DELIVERED TO ${inst.name}.`);

        // 4. Live Update an das eingeloggte HQ senden
        // Wir senden an den Raum "HQ_TAG" (z.B. HQ_KGB)
        io.to(`HQ_${inst.tag}`).emit('hq_inbox_data', inbox);
    });

    // HQ: SICHERER VERBINDUNGSAUFBAU ZUM INFORMANTEN
    socket.on('hq_connect_req', (targetSocketId) => {
        // 1. Prüfen: Ist der User im RAM registriert? (WICHTIG!)
        const targetUser = users[targetSocketId];

        if (!targetUser) {
            // User ist technisch vielleicht da, aber nicht eingeloggt/registriert
            socket.emit('system_message', 'ERROR: UPLINK UNSTABLE. Target not found in user registry (Refresh Target Client).');
            return;
        }

        // 2. Prüfen: Ist die Socket-Verbindung aktiv?
        const targetSocket = io.sockets.sockets.get(targetSocketId);
        if (!targetSocket) {
            socket.emit('system_message', 'ERROR: UPLINK LOST. Target went offline.');
            return;
        }

        // 3. Berechtigung HQ prüfen
        const me = users[socket.id];
        if (!me || !me.institution) {
            socket.emit('system_message', 'ACCESS DENIED.');
            return;
        }

        // 4. Alles grün -> Handshake freigeben
        socket.emit('hq_connect_approved', { targetId: targetSocketId });
    });

    // HQ: BROADCAST MESSAGE
    socket.on('hq_broadcast_req', (msg) => {
        const user = users[socket.id];

        // Sicherheits-Check: Ist der User eingeloggt und gehört zu einer Institution?
        if (!user || !user.institution) {
            socket.emit('system_message', 'ACCESS DENIED. Secure uplink required.');
            return;
        }

        // --- DER FIX ---
        // Vorher stand hier: instName: INSTITUTIONS[user.institution.tag].name
        // Jetzt nehmen wir den Namen direkt aus der Session (da haben wir ihn beim Login gespeichert):

        const broadcastData = {
            sender: user.institution.tag,      // z.B. "MI6"
            instName: user.institution.name,   // z.B. "Secret Intelligence Service" (Hier lag der Fehler!)
            message: msg,
            color: user.institution.color || '#fff'
        };
        // ----------------

        // An ALLE senden
        io.emit('hq_broadcast', broadcastData);

        // Bestätigung an den Sender
        socket.emit('system_message', `>>> BROADCAST SENT TO ALL SECTORS.`);
    });

    // --- HQ INTERNAL CHAT (SQUAD COMMS) ---

    socket.on('hq_internal_chat', (msg) => {
        const user = users[socket.id];

        // 1. Sicherheits-Check
        if (!user || !user.institution) {
            return socket.emit('system_message', 'ACCESS DENIED: No institutional clearance.');
        }

        // 2. Raum bestimmen
        const internalRoom = `INTERNAL_${user.institution.tag}`;

        // 3. Nachricht an alle ANDEREN im Raum senden (Sender ausgeschlossen)
        // ÄNDERUNG: 'socket.to' statt 'io.to'
        socket.to(internalRoom).emit('hq_internal_msg_rcv', {
            sender: user.originalName || user.username,
            text: msg,
            tag: user.institution.tag,
            color: user.institution.color
        });
    });

    // HQ: Nachricht löschen
    socket.on('hq_delete_msg', (msgId) => {
        // Wir müssen herausfinden, wer der User ist (via Room Hack oder Session)
        // Einfachheitshalber: Wir suchen in allen Inboxes (unschön aber wirksam für Demo)
        Object.values(INSTITUTIONS).forEach(inst => {
            const inboxPath = path.join(DATA_DIR, inst.inboxFile);
            if (fs.existsSync(inboxPath)) {
                let inbox = JSON.parse(fs.readFileSync(inboxPath, 'utf8'));
                const originalLen = inbox.length;
                inbox = inbox.filter(m => m.id !== msgId);

                if (inbox.length !== originalLen) {
                    fs.writeFileSync(inboxPath, JSON.stringify(inbox, null, 2));
                    // Update an den HQ Raum senden
                    // Wir finden den Key anhand des Values (etwas hacky, aber spart Code)
                    const key = Object.keys(INSTITUTIONS).find(k => INSTITUTIONS[k] === inst);
                    io.to(`HQ_${key}`).emit('hq_inbox_data', inbox);
                }
            }
        });
    });

    // 4. INBOX ABRUFEN (Nur für HQ)
    socket.on('hq_fetch_inbox', () => {
        // Sicherheits-Check: Ist der Socket im HQ Room?
        if (socket.rooms.has('HQ_CHANNEL')) {
            socket.emit('hq_inbox_data', hqInbox);
        }
    });

    // --- INSTITUTIONS DIRECTORY ---

    // --- GLOBAL LIST COMMANDS ---

    // LIST INSTITUTIONS
    socket.on('list_institutions_req', async () => {
        const list = await db.getPublicInstitutionList();

        if (list.length === 0) {
            socket.emit('system_message', 'REGISTRY EMPTY: No active agencies found.');
        } else {
            socket.emit('system_message', '========================================');
            socket.emit('system_message', '      GLOBAL AGENCY DIRECTORY');
            socket.emit('system_message', '========================================');

            list.forEach(inst => {
                // Header Zeile: [ID] NAME
                socket.emit('system_message', `[${inst.tag}] ${inst.name}`);

                // Beschreibung (eingerückt)
                if (inst.description) {
                    socket.emit('system_message', `      "${inst.description}"`);
                } else {
                    socket.emit('system_message', `      (No public profile established)`);
                }

                // Leerzeile für bessere Lesbarkeit
                socket.emit('system_message', ' ');
            });

            socket.emit('system_message', '========================================');
            socket.emit('system_message', `TOTAL ACTIVE NODES: ${list.length}`);
        }
    });

    // 2. BESCHREIBUNG ÄNDERN (Nur für eingeloggte Institutionen)
    socket.on('hq_update_description', async (desc) => {
        const user = users[socket.id];

        // CHECK: Ist User eingeloggt als Institution?
        if (!user || !user.institution) {
            socket.emit('system_message', 'ACCESS DENIED. Authorized personnel only.');
            return;
        }

        // Limitierung der Länge (Spam-Schutz)
        if (desc.length > 200) {
            socket.emit('system_message', 'ERROR: Description too long (max 200 chars).');
            return;
        }

        // Update in DB
        const success = await db.updateInstitutionDescription(user.institution.tag, desc);

        if (success) {
            socket.emit('system_message', 'PROFILE UPDATED: Description saved to public registry.');

            // Optional: User-Objekt im RAM updaten, falls wir es cachen
            user.institution.description = desc;
        } else {
            socket.emit('system_message', 'ERROR: Database write failed.');
        }
    });

    // --- SETUP WIZARD (Token einlösen) ---

    // --- 3. SETUP FLOW (Erweitert) ---

    // Start
    socket.on('setup_init', async (token) => {
        const tokenData = await db.getInviteToken(token);
        if (!tokenData) {
            socket.emit('system_message', 'ERROR: Invalid Token.');
            return;
        }

        // Metadaten parsen (Name & Tag aus der Bewerbung)
        let prefill = { name: 'Unknown', tag: 'TAG' };
        try { prefill = JSON.parse(tokenData.org_name_suggestion); } catch(e) { prefill.name = tokenData.org_name_suggestion; }

        setupSessions[socket.id] = {
            token: token,
            email: tokenData.approved_email,
            data: prefill, // Speichern wir hier
            step: 'CONFIRM'
        };

        socket.emit('setup_prompt', {
            step: 'CONFIRM',
            msg: `TOKEN ACCEPTED. \nRegistered Name: ${prefill.name}\nRegistered ID: ${prefill.tag}\n\nType 'yes' to confirm or 'edit' to change details.`
        });
    });

    // Bestätigen oder Editieren
    socket.on('setup_step_confirm', async (input) => {
        const session = setupSessions[socket.id];
        if (!session || session.step !== 'CONFIRM') return;

        if (input.toLowerCase() === 'yes') {
            session.step = 'DESC';
            socket.emit('setup_prompt', { step: 'DESC', msg: 'Details confirmed. \nEnter a public description for your institution:' });
        } else if (input.toLowerCase() === 'edit') {
            session.step = 'EDIT_NAME';
            socket.emit('setup_prompt', { step: 'EDIT_NAME', msg: 'Enter new Institution Name:' });
        } else {
            socket.emit('setup_prompt', { step: 'CONFIRM', msg: "Type 'yes' or 'edit'.", error: true });
        }
    });

    // Falls Edit: Name
    socket.on('setup_step_edit_name', (name) => {
        const session = setupSessions[socket.id];
        if (session.step !== 'EDIT_NAME') return;
        session.data.name = name;
        session.step = 'EDIT_TAG';
        socket.emit('setup_prompt', { step: 'EDIT_TAG', msg: 'Enter new Agency ID (TAG):' });
    });

    // Falls Edit: Tag
    socket.on('setup_step_edit_tag', (tag) => {
        const session = setupSessions[socket.id];
        if (session.step !== 'EDIT_TAG') return;
        session.data.tag = tag.toUpperCase();
        session.step = 'DESC';
        socket.emit('setup_prompt', { step: 'DESC', msg: 'Updated. Enter public description:' });
    });

    // Beschreibung
    socket.on('setup_step_desc', (desc) => {
        const session = setupSessions[socket.id];
        if (session.step !== 'DESC') return;
        session.data.desc = desc;
        session.step = 'PASS';
        socket.emit('setup_prompt', { step: 'PASS', msg: 'Description saved. Set your Access Password:' });
    });

    // 2. TAG WAHL
    socket.on('setup_step_tag', async (tagRaw) => {
        const session = setupSessions[socket.id];
        if (!session || session.step !== 'TAG') return;

        const tag = tagRaw.toUpperCase().replace(/[^A-Z0-9]/g, ''); // Nur Buchstaben/Zahlen

        const existing = await db.getInstitutionByTag(tag);
        if (existing) {
            socket.emit('setup_prompt', { step: 'TAG', msg: `ERROR: Tag '${tag}' is taken. Choose another:`, error: true });
            return;
        }

        session.tag = tag;
        session.step = 'PASS';
        socket.emit('setup_prompt', { step: 'PASS', msg: `Identity '${tag}' confirmed. Set your Access Password:` });
    });

    // 3. PASSWORT -> 2FA
    socket.on('setup_step_pass', async (pass) => {
        const session = setupSessions[socket.id];
        if (session.step !== 'PASS') return;

        session.password = pass;
        const secret = speakeasy.generateSecret({ length: 20, name: `SecureChat (${session.data.tag})` });
        session.tempSecret = secret.base32;
        session.step = '2FA';

        socket.emit('setup_prompt', { step: '2FA', msg: 'Scan QR / Enter Code:', secret: secret.base32 });
    });

    // 4. VERIFY & CREATE
    socket.on('setup_step_2fa_verify', async (token) => {
        const session = setupSessions[socket.id];
        if (!session || session.step !== '2FA') return;

        const verified = speakeasy.totp.verify({ secret: session.tempSecret, encoding: 'base32', token: token, window: 1 });

        if (verified) {
            const success = await db.createInstitution(
                session.data.tag,
                session.data.name,
                session.password,
                session.tempSecret,
                '#00ff00'
            );
            if (success) {
                // Beschreibung auch noch speichern!
                await db.updateInstitutionDescription(session.data.tag, session.data.desc);
                await db.markTokenUsed(session.token);
                socket.emit('setup_complete', { tag: session.data.tag });
                delete setupSessions[socket.id];
            }
        } else {
            socket.emit('setup_prompt', { step: '2FA', msg: 'Invalid Code.', error: true });
        }
    });

// --- REGISTRATION FLOW ---

    // --- 1. NEUER REGISTRIERUNGS-FLOW ---

    // Antrag empfangen (Jetzt mit allen Daten)
    socket.on('register_request_submit', async (data) => {
        // data = { name, tag, msg, email }
        if (!data.email || !data.name) return;

        const code = crypto.randomBytes(3).toString('hex').toUpperCase(); // 6 Zeichen Hex

        console.log(`[REGISTER] New Request: ${data.tag} (${data.email})`);

        const success = await db.createRequest(data.name, data.tag, data.msg, data.email, code);

        if (success) {
            socket.emit('system_message', 'Encrypting payload...');
            const mailSent = await mailer.sendVerificationEmail(data.email, code);

            if (mailSent) {
                socket.emit('system_message', `Verification code dispatched to [${data.email}].`);
                socket.emit('system_message', `Execute: /verify ${data.email} [CODE]`);
            } else {
                socket.emit('system_message', 'ERROR: Mail relay failed.');
            }
        }
    });

    // Verifizierung (Bleibt fast gleich, nur neuer Befehl)
    socket.on('register_verify_submit', async (data) => {
        const result = await db.verifyRequestEmail(data.email, data.code);
        if (result.success) {
            socket.emit('system_message', 'IDENTITY VERIFIED. Application forwarded to Administrator.');
        } else {
            socket.emit('system_message', `VERIFICATION FAILED: ${result.msg}`);
        }
    });

    // --- ADMIN TOOLS ---

    // --- 2. ADMIN FLOW (Automatische Mail) ---

    // Liste anzeigen (Mit neuem Layout)
    socket.on('admin_list_requests', async () => {
        if (!users[socket.id] || !users[socket.id].isAdmin) return;

        const list = await db.getPendingRequests();
        if (list.length === 0) {
            socket.emit('system_message', 'No pending applications.');
        } else {
            socket.emit('system_message', '--- PENDING REQUESTS ---');
            list.forEach(req => {
                socket.emit('system_message', `ID: [${req.id}]`);
                socket.emit('system_message', `ORG: ${req.org_name} [${req.org_tag}]`);
                socket.emit('system_message', `MSG: "${req.message}"`);
                socket.emit('system_message', `CONTACT: ${req.email}`);
                socket.emit('system_message', `TIME: ${req.request_date}`);
                socket.emit('system_message', '------------------------');
            });
        }
    });

    // Genehmigen & Mail senden
    socket.on('admin_approve_request', async (requestId) => {
        if (!users[socket.id] || !users[socket.id].isAdmin) return;

        const req = await db.getRequestById(requestId);
        if (!req || req.status !== 'PENDING') {
            socket.emit('system_message', 'ERROR: Invalid Request ID.');
            return;
        }

        const token = 'INVITE-' + crypto.randomBytes(4).toString('hex').toUpperCase();

        // Token speichern (Wir nutzen das suggestion Feld für TAG und NAME getrennt durch | oder JSON)
        // Einfacher: Wir speichern den TAG als suggestion. Der Name ist in der Request ja auch da.
        // Wir speichern hier einfach JSON in das Feld 'org_name_suggestion' damit wir beides haben.
        const metaData = JSON.stringify({ name: req.org_name, tag: req.org_tag });

        await db.createInviteToken(token, req.email, metaData);
        await db.updateRequestStatus(requestId, 'APPROVED');

        socket.emit('system_message', `APPROVED. Generating Invite Token...`);

        // AUTOMATISCHE EMAIL SENDEN
        const sent = await mailer.sendInviteTokenEmail(req.email, token, req.org_name);

        if (sent) {
            socket.emit('system_message', `SUCCESS: Token ${token} sent to ${req.email}.`);
        } else {
            socket.emit('system_message', `WARNING: Email failed. Manual send required: ${token}`);
        }
    });

    // 1. REGISTRIERUNG
    socket.on('register', (usernameInput) => { // Umbenannt zu usernameInput für Klarheit

        // 1. INPUT SANITIZATION (XSS Schutz für Namen)
        // Wir erlauben kein HTML im Namen!
        if (!usernameInput || typeof usernameInput !== 'string') return;
        const username = escapeHtml(usernameInput.trim());
        // Ab hier arbeiten wir nur noch mit dem sauberen 'username' weiter

        // --- VALIDIERUNG ---
        if (username.startsWith('/') || username.length === 0 || username.length > 20) {
            socket.emit('system_message', 'REGISTRATION ERROR: Invalid username format.');
            return;
        }

        // --- NEU: RESERVIERTER NAME CHECK ---
        if (username.toLowerCase() === 'anonymous') {
            socket.emit('system_message', 'REGISTRATION ERROR: "Anonymous" is reserved for Stealth Mode.');
            return;
        }
        // ------------------------------------

        const uniqueKey = Math.random().toString(36).substring(2, 8).toUpperCase();

        // IP & User-Agent auslesen (für /info Befehl)
        let clientIp = socket.handshake.address;
        if (clientIp.substr(0, 7) == "::ffff:") {
            clientIp = clientIp.substr(7);
        }
        const userAgent = socket.request.headers['user-agent'] || 'Unknown Device';

        users[socket.id] = {
            id: socket.id,
            username: username,
            key: uniqueKey,
            partners: [],
            loginTime: new Date(),
            isGhost: false,
            ip: clientIp,
            device: userAgent
        };

        // ANONYM: Keine Namen oder Keys im Log!
        serverLog('Neuer User im System registriert (Daten maskiert).');

        socket.emit('registered', {
            key: uniqueKey,
            username: username,
            vapidPublicKey: publicVapidKey // <--- WICHTIG: Client braucht den Key
        });
    });

    // 2. INFO / RECON COMMAND
    socket.on('info_request', (query) => {
        const requester = users[socket.id];
        if (!requester) return;

        const searchTerm = query.toLowerCase();
        const allUsers = Object.values(users);

        // Suche NUR nach Key (für Präzision)
        const targetUser = allUsers.find(u => u.key.toLowerCase() === searchTerm);

        if (targetUser) {
            // GHOST CHECK
            if (targetUser.isGhost && targetUser.id !== socket.id) {
                socket.emit('system_message', `ERROR: Target '${query}' is masked behind a proxy chain. Access denied.`);
                return;
            }

            const infoData = {
                username: targetUser.username,
                key: targetUser.key,
                ip: targetUser.ip,
                device: targetUser.device,
                loginTime: targetUser.loginTime,
                status: targetUser.partnerId ? 'ESTABLISHED CONNECTION' : 'IDLE / LISTENING'
            };

            socket.emit('info_result', infoData);
        } else {
            socket.emit('system_message', `TARGET_NOT_FOUND: Could not locate entity '${query}'.`);
        }
    });

// 3. GHOST MODE TOGGLE (Mit Broadcast)
    socket.on('toggle_ghost', () => {
        const user = users[socket.id];
        if (user) {
            user.isGhost = !user.isGhost;

            // Bestätigung an sich selbst
            socket.emit('system_message', `STEALTH MODE: ${user.isGhost ? 'ENABLED (Invisible)' : 'DISABLED (Visible)'}`);

            // Das Update-Paket
            const updateData = {
                key: user.key,
                username: user.username, // Der echte Name (wird gebraucht zum "Enttarnen")
                isGhost: user.isGhost
            };

            // 1. An alle privaten Partner senden
            if (user.partners && user.partners.length > 0) {
                user.partners.forEach(pid => {
                    io.to(pid).emit('user_ghost_update', updateData);
                });
            }

            // 2. An aktuelle Gruppe senden
            if (user.currentGroup) {
                socket.to(`group_${user.currentGroup}`).emit('user_ghost_update', updateData);
            }

            // 3. An aktuellen Public Room senden
            if (user.currentPub) {
                socket.to(`pub_${user.currentPub}`).emit('user_ghost_update', updateData);
            }
        }
    });

    // 4. PING / NETWORK SCAN
    socket.on('ping_request', (query) => {
        const searchTerm = query.toLowerCase();
        const allUsers = Object.values(users);
        let foundUsers = [];

        // Suche nach Key
        const keyMatch = allUsers.find(u => u.key.toLowerCase() === searchTerm);
        if (keyMatch) {
            foundUsers.push(keyMatch);
        } else {
            // Suche nach Name
            foundUsers = allUsers.filter(u => u.username.toLowerCase().includes(searchTerm));
        }

        // Sortieren
        foundUsers.sort((a, b) => new Date(a.loginTime) - new Date(b.loginTime));

        // Ghost Filter anwenden
        const visibleUsers = foundUsers.filter(u => !u.isGhost || u.id === socket.id);

        const results = visibleUsers.map(u => ({
            username: u.username,
            key: u.key,
            loginTime: u.loginTime,
            isOnline: true
        }));

        socket.emit('ping_result', { query: query, results: results });
    });

    // 5. VERBINDUNGSANFRAGE (Ghost Aware & HQ Compatible)
    socket.on('request_connection', (data) => {
        // Spam Schutz
        const now = Date.now();
        const lastRequestTime = connectionRateLimit[socket.id] || 0;
        const cooldown = 3000;

        if (now - lastRequestTime < cooldown) {
            const waitTime = Math.ceil((cooldown - (now - lastRequestTime)) / 1000);
            socket.emit('system_message', `SPAM PROTECTION: Please wait ${waitTime}s.`);
            return;
        }
        connectionRateLimit[socket.id] = now;

        const requester = users[socket.id];
        if (!requester) return;

        // --- LOGIK UPDATE ANFANG ---

        let targetId = null;

        // 1. Prüfen: Ist 'data.targetKey' vielleicht direkt eine Socket-ID? (HQ Button Fall)
        if (users[data.targetKey]) {
            targetId = data.targetKey;
        }
        // 2. Fallback: Ist es ein Fingerabdruck/Key? (Manueller /connect Fall)
        else {
            targetId = Object.keys(users).find(id => users[id].key === data.targetKey);
        }

        // --- LOGIK UPDATE ENDE ---

        if (targetId && targetId !== socket.id) {

            // --- GHOST LOGIK: Name maskieren ---
            const displayRequesterName = requester.isGhost ? 'Anonymous' : requester.username;

            io.to(targetId).emit('incoming_request', {
                requesterId: socket.id,
                requesterName: displayRequesterName,
                requesterKey: requester.key,
                publicKey: data.publicKey
            });

            const targetUser = users[targetId];
            sendPush(targetUser, 'INCOMING CONNECTION', `Node ${displayRequesterName} requests secure handshake.`);

            socket.emit('system_message', `SECURE HANDSHAKE: Request sent to ${users[targetId].username}...`);
        } else {
            // Hier geben wir jetzt die ID/Key aus, damit man sieht, was gesucht wurde
            socket.emit('system_message', `FEHLER: Target '${data.targetKey}' nicht gefunden oder offline.`);
        }
    });

    // 6. VERBINDUNGSANTWORT (Ghost Aware)
    socket.on('respond_connection', (data) => {
        const responder = users[socket.id];
        const requester = users[data.requesterId];

        if (!responder || !requester) return;

        if (data.accepted) {
            if (!responder.partners.includes(requester.id)) responder.partners.push(requester.id);
            if (!requester.partners.includes(responder.id)) requester.partners.push(responder.id);

            serverLog(`Verschlüsselte P2P-Sitzung gestartet.`);

            // --- GHOST LOGIK ---
            // Wie sieht der Responder (Antwortende) für den Requester aus?
            const displayResponderName = responder.isGhost ? 'Anonymous' : responder.username;

            // Wie sieht der Requester (Anfragende) für den Responder aus?
            const displayRequesterName = requester.isGhost ? 'Anonymous' : requester.username;

            // ANFRAGESTELLER bekommt Info (Maskierter Responder Name)
            io.to(requester.id).emit('chat_start', {
                partner: displayResponderName,
                partnerKey: responder.key,
                publicKey: data.publicKey
            });

            // ANTWORTENDER bekommt Info (Maskierter Requester Name)
            io.to(socket.id).emit('chat_start', {
                partner: displayRequesterName,
                partnerKey: requester.key
            });

            sendPush(requester, 'CONNECTION ESTABLISHED', `User ${displayResponderName} accepted your request.`);

        } else {
            io.to(requester.id).emit('system_message', `ANFRAGE ABGELEHNT.`);

            // Auch bei Ablehnung Ghost-Namen nutzen, falls responder Ghost ist?
            // Ja, besser konsistent bleiben:
            const displayResponderName = responder.isGhost ? 'Anonymous' : responder.username;
            sendPush(requester, 'CONNECTION DENIED', `User ${displayResponderName} declined the handshake.`);
        }
    });

    // 21. PRIVATE CHAT LEAVE (Gezielt)
    socket.on('private_leave', (targetKey) => { // Wir erwarten jetzt den Key des Partners
        const user = users[socket.id];
        if (!user) return;

        // Wir suchen den Partner mit diesem Key
        const targetPartner = Object.values(users).find(u => u.key === targetKey);

        if (targetPartner && user.partners.includes(targetPartner.id)) {
            // Dem Partner das Signal senden
            io.to(targetPartner.id).emit('private_leave_received', {
                name: user.username,
                key: user.key
            });

            // Verbindung auflösen (bei beiden aus der Liste nehmen)
            user.partners = user.partners.filter(id => id !== targetPartner.id);
            if (users[targetPartner.id]) {
                users[targetPartner.id].partners = users[targetPartner.id].partners.filter(id => id !== socket.id);
            }
        }

        socket.emit('private_leave_confirm');
    });

// 7. NACHRICHTEN TRANSFER (DIAGNOSE MODUS)
    socket.on('message', (data) => {
        // Log 1: Kommt überhaupt was an?
        console.log("--- DEBUG MESSAGE START ---");
        console.log("1. Nachricht erhalten von:", users[socket.id]?.username);
        console.log("2. Daten Paket:", data);

        // Checks
        if (!data || !data.targetKey || !data.payload) {
            console.log("FEHLER: Ungültiges Datenformat. 'targetKey' oder 'payload' fehlt!");
            return;
        }

        const user = users[socket.id];
        if (!user) {
            console.log("FEHLER: Sender nicht in User-Datenbank gefunden.");
            return;
        }

        // Ziel suchen
        const targetUser = Object.values(users).find(u => u.key === data.targetKey);

        if (!targetUser) {
            console.log(`FEHLER: Ziel-User mit Key '${data.targetKey}' nicht gefunden.`);
            socket.emit('system_message', 'ERROR: Target user offline or not found.');
            return;
        }

        console.log(`3. Ziel gefunden: ${targetUser.username} (ID: ${targetUser.id})`);
        console.log(`4. Meine Partner-Liste (${user.username}):`, user.partners);

        // Sicherheits-Check
        const isConnected = user.partners.includes(targetUser.id);
        console.log(`5. Darf senden? ${isConnected ? "JA" : "NEIN"}`);

        if (isConnected) {
            let displayName = user.username;
            if (user.isGhost) displayName = 'Anonymous';
            else if (user.isAdmin) displayName = `[ADMIN] ${user.username}`;

            // Senden
            io.to(targetUser.id).emit('message', {
                user: displayName,
                senderKey: user.key, // <--- DAS MUSS DRIN SEIN
                text: data.payload
            });
            console.log("6. ERFOLG: Nachricht an Socket gesendet.");
        } else {
            console.log("FEHLER: Verbindung nicht autorisiert. Partner nicht in Liste.");
            socket.emit('system_message', 'ERROR: No established uplink.');
        }
        console.log("--- DEBUG MESSAGE END ---");
    });

    // --- PUBLIC CHAT SYSTEM ---

    // 1. LISTE ABRUFEN (Scanner)
    socket.on('pub_list_request', () => {
        const rooms = Object.values(publicRooms).map(r => ({
            id: r.id,
            name: r.name,
            count: r.members.length
        }));
        socket.emit('pub_list_result', rooms);
    });

    // --- PUBLIC CHAT SYSTEM ---

// PUB CREATE (Sequential IDs & Limit)
    socket.on('pub_create', (nameInput) => { // <--- WICHTIG: Hier "nameInput" nennen!
        const user = users[socket.id];
        if (!user) return;

        // XSS Schutz für Raum-Namen
        // Jetzt existiert nameInput, weil wir es oben so genannt haben
        const cleanName = nameInput ? escapeHtml(nameInput.trim()) : null;

        // Temp ID für den Moment
        const tempId = "TEMP_" + Date.now();
        const roomKey = crypto.randomBytes(32).toString('hex');

        publicRooms[tempId] = {
            id: tempId,
            // Hier nutzen wir jetzt cleanName (die gesäuberte Version)
            name: cleanName || `Sector_PENDING`,
            members: [],
            key: roomKey,
            createdAt: Date.now()
        };

        // User hinzufügen
        publicRooms[tempId].members.push(socket.id);

        // Aufräumen und Nummern vergeben
        reorganizePublicRooms();

        // Neuen Raum finden (wo unser User jetzt drin ist)
        const newRoom = Object.values(publicRooms).find(r => r.members.includes(socket.id));

        if (newRoom) {
            socket.join(`pub_${newRoom.id}`);
            user.currentPub = newRoom.id;

            serverLog(`Public Sector ${newRoom.id} erstellt von ${user.username}.`);

            socket.emit('pub_joined_success', {
                id: newRoom.id,
                name: newRoom.name,
                key: newRoom.key
            });

            // WICHTIG: KEIN GLOBALER BROADCAST MEHR!
            // Wir sagen es nur dem Ersteller (System Message lokal)
            socket.emit('system_message', `UPLINK ESTABLISHED: Sector ${newRoom.id} is online.`);
        }
    });

    // PUB LEAVE (Robust & Sauber)
    socket.on('pub_leave', () => {
        const user = users[socket.id];
        if (!user || !user.currentPub) return;

        const pubId = user.currentPub;
        const room = publicRooms[pubId];

        if (room) {
            // 1. User aus dem Socket-Raum entfernen (WICHTIG!)
            socket.leave(`pub_${pubId}`);

            // 2. Aus der Mitgliederliste entfernen
            room.members = room.members.filter(id => id !== socket.id);
            user.currentPub = null;

            // 3. Leave Event an verbleibende User senden (nur wenn noch wer da ist)
            if (room.members.length > 0) {
                io.to(`pub_${pubId}`).emit('room_user_status', {
                    username: user.username,
                    key: user.key,
                    type: 'leave',
                    context: 'pub',
                    roomId: pubId
                });
            }

            // 4. CHECK: IST DER RAUM LEER?
            if (room.members.length === 0) {
                // Explizit löschen!
                delete publicRooms[pubId];
                serverLog(`Public Sector ${pubId} collapsed (Empty).`);
            }

            // 5. IMMER reorganisieren (schließt Lücken und bereinigt)
            reorganizePublicRooms();
        } else {
            // Falls Raum-Daten korrupt waren, User trotzdem resetten
            user.currentPub = null;
        }

        // 6. Bestätigung an Client senden (DAS LÖST DEIN PROBLEM ZUSAMMEN MIT SCHRITT 1)
        socket.emit('pub_left_success');
    });

// 3. RAUM BEITRETEN (Multi-Chat Fix: Kein Kickout mehr!)
    socket.on('pub_join', (roomId) => {
        const room = publicRooms[roomId];
        const user = users[socket.id];

        if (!room || !user) {
            socket.emit('system_message', `ERROR: Sector #${roomId} not found or access denied.`);
            return;
        }

        // --- FIX: BEREITS DRIN CHECK ---
        // Wir prüfen, ob deine ID schon in der Liste ist
        if (room.members.includes(socket.id)) {
            socket.emit('system_message', `INFO: Connection to Sector #${roomId} is already active.`);
            return; // WICHTIG: Hier brechen wir ab! Keine Broadcasts, kein Join-Logik.
        }

        // --- NEU: LIMIT CHECK (Max 100) ---
        if (room.members.length >= 100) {
            socket.emit('system_message', `ERROR: Sector #${roomId} is full (Max 100 nodes).`);
            return;
        }
        // -------------------------------

        // Falls man woanders war: Alten Public Room sauber verlassen (Optional, aber sauberer)
        if (user.currentPub && user.currentPub !== roomId) {
            const oldRoom = publicRooms[user.currentPub];
            if (oldRoom) {
                socket.leave(`pub_${user.currentPub}`);
                oldRoom.members = oldRoom.members.filter(id => id !== socket.id);
                // Optional: Leave Nachricht im alten Raum senden
            }
        }

        // Socket.io Room beitreten
        socket.join(`pub_${roomId}`);
        room.members.push(socket.id);

        // Status im User-Objekt updaten
        user.currentPub = roomId;

        serverLog(`User ${user.username} betritt Public Sector ${roomId}`);

        socket.emit('pub_joined_success', {
            id: room.id,
            name: room.name,
            key: room.key
        });

        // Broadcast an andere
        socket.to(`pub_${roomId}`).emit('room_user_status', {
            username: user.username,
            key: user.key,
            isGhost: !!user.isGhost,
            type: 'join',
            context: 'pub',
            roomId: roomId
        });
        // Promo Update (wegen Member Count)
        io.emit('promo_update', generatePromoList());
    });

    // 4. PUBLIC NACHRICHT (Routing Fix + Ghost)
    socket.on('pub_message', (msg) => {
        const user = users[socket.id];
        if (!user || !user.currentPub) return;

        // Rate Limit
        const now = Date.now();
        if (now - (messageRateLimit[socket.id] || 0) < 200) return;
        messageRateLimit[socket.id] = now;

        // Display Name Logik (Server-seitig für Fallback)
        let displayName = user.username;
        if (user.isGhost) displayName = 'Anonymous';
        else if (user.isAdmin) displayName = `[ADMIN] ${user.username}`;

        // SENDEN!
        // 1. An den richtigen Raum: pub_ + ID
        // 2. Mit senderKey (für Ghost Dynamik im Client)
        // 3. Mit pubId (damit Client weiß, wohin damit)
        socket.to(`pub_${user.currentPub}`).emit('pub_message_received', {
            senderName: displayName,
            senderKey: user.key, // <--- DAS BRAUCHEN WIR
            text: msg,
            pubId: user.currentPub
        });
    });

    socket.on('pub_message_received', async (data) => {
        // data: { senderName, text, pubId }

        // 1. Chat finden
        const chat = myChats[data.pubId];

        if (!chat) {
            // Falls wir die Nachricht bekommen, aber den Raum lokal noch nicht haben (selten)
            return;
        }

        // 2. Entschlüsseln mit dem Raum-Key
        const clearText = await decryptMessage(data.text, chat.key);

        // 3. Anzeigen (Unabhängig davon, wo wir gerade sind!)
        printToChat(data.pubId, `[${data.senderName}]: ${clearText}`, 'partner-msg');
    });

    // 5. PUBLIC COMMANDS (Who list)
    socket.on('pub_who_request', () => {
        const user = users[socket.id];
        if (!user || !user.currentRoom) return;

        const room = publicRooms[user.currentRoom];
        if(room) {
            // Hier prüfen wir jeden User in der Liste
            const names = room.users.map(uid => {
                const u = users[uid];
                if (!u) return 'Unknown';
                // Wenn Ghost -> Zeige "Anonymous" (oder gar nichts, aber Anonymous ist cooler)
                return u.isGhost ? 'Anonymous' : u.username;
            });

            socket.emit('system_message', `ACTIVE NODES IN SECTOR: [ ${names.join(', ')} ]`);
        }
    });

    // --- PRIVATE GROUP SYSTEM (RBAC) ---

// 1. GRUPPE ERSTELLEN (/group create [NAME])
    socket.on('group_create', (data) => {
        const creator = users[socket.id];
        if (!creator) return;

        // --- INPUT NORMALISIERUNG ---
        // data kann sein:
        // A) Ein Array (Alte Version: nur Invites)
        // B) Ein Objekt (Neue Version: { name: "...", invites: [...] })
        // C) Leer / undefined

        let invitedUserKeys = [];
        let desiredName = null;

        if (Array.isArray(data)) {
            invitedUserKeys = data;
        } else if (typeof data === 'object' && data !== null) {
            invitedUserKeys = data.invites || [];
            desiredName = data.name || null;
        }

        // ID und Schlüssel generieren
        const groupId = Math.floor(Math.random() * 9000) + 1000; // 4-stellige ID
        const groupKey = crypto.randomBytes(32).toString('hex');

        // --- NAME BESTIMMEN & SANITIZEN ---
        let finalName = `Group_${groupId}`; // Standard Fallback

        if (desiredName && typeof desiredName === 'string' && desiredName.trim().length > 0) {
            // XSS Schutz + Max Länge 20
            finalName = escapeHtml(desiredName.trim()).substring(0, 20);
        }
        // ----------------------------------

        privateGroups[groupId] = {
            id: groupId,
            name: finalName,
            ownerId: socket.id,
            members: [socket.id],
            mods: [],
            key: groupKey,
            pendingJoins: [], // Das sind Leute, die rein WOLLEN (Join Request)
            invitedUsers: [], // <--- NEU: Das sind Leute, die wir eingeladen HABEN
            isPublic: false
        };

        // Owner Status setzen
        creator.currentGroup = groupId;
        socket.join(`group_${groupId}`);

        serverLog(`Gruppe ${groupId} erstellt von ${creator.username}`);

        // Bestätigung an Owner
        socket.emit('group_joined_success', {
            id: groupId,
            name: privateGroups[groupId].name,
            key: groupKey,
            role: 'OWNER'
        });

        // Falls User eingeladen wurden:
        if (invitedUserKeys && invitedUserKeys.length > 0) {
            invitedUserKeys.forEach(targetKey => {
                const targetUser = Object.values(users).find(u => u.key === targetKey);
                if (targetUser) {
                    io.to(targetUser.id).emit('group_invite_received', {
                        groupId: groupId,
                        inviter: creator.username
                    });
                }
            });
        }
    });

    // 2. JOIN REQUEST (/group join ID)
    // 2. JOIN REQUEST (/group join ID) - ADMIN UPDATE (Skeleton Key)
    socket.on('group_join_req', (groupId) => {
        // 1. CRASH PREVENTION
        const user = users[socket.id];
        if (!user) {
            socket.emit('system_message', 'ACCESS DENIED: Authentication required.');
            return;
        }

        const group = privateGroups[groupId];

        if (!group) {
            socket.emit('system_message', 'ERROR: Group ID not found.');
            return;
        }
        if (group.members.includes(socket.id)) {
            socket.emit('system_message', 'ERROR: You are already in this group.');
            return;
        }

        // --- ENTSCHEIDUNG: SOFORT REIN ODER WARTEN? ---
        // Wenn Gruppe Public ist ODER User ein Admin ist -> Sofort rein!
        if (group.isPublic || user.isAdmin) {

            // NEU: PASSWORT CHECK (Admins ignorieren Passwort)
            if (group.password && !user.isAdmin) {
                // Stopp! Client nach Passwort fragen
                socket.emit('group_password_required', group.id);
                return;
            }

            // Socket in den Raum
            socket.join(`group_${group.id}`);

            // Daten updaten
            group.members.push(socket.id);
            user.currentGroup = group.id;

            // Erfolg an User senden
            socket.emit('group_joined_success', {
                id: group.id,
                name: group.name,
                key: group.key,
                role: user.isAdmin ? 'ADMIN' : 'MEMBER' // Rolle korrekt anzeigen
            });

            // Nachricht an die Gruppe anpassen
            if (user.isAdmin && !group.isPublic) {
                // Wenn Admin in PRIVATE Gruppe joint
                io.to(`group_${group.id}`).emit('system_message', `SECURITY ALERT: Global Admin ${user.username} has bypassed the security lock.`);
            } else {
                // Event senden
                io.to(`group_${group.id}`).emit('room_user_status', {
                    username: user.username,
                    key: user.key,
                    type: 'join',
                    context: 'group',
                    roomId: group.id
                });
            }

            // Promo-Board updaten
            io.emit('promo_update', generatePromoList());

            return; // Fertig!
        }
        // -----------------------------------------------

// Alter Code (Privat & Kein Admin -> Warteliste)
        group.pendingJoins.push(socket.id);

        // EMPFÄNGER LISTE: Owner + Alle Mods
        const alertRecipients = [group.ownerId, ...group.mods];

        // Jedem Empfänger das Alert-Paket schicken
        alertRecipients.forEach(recipientId => {
            io.to(recipientId).emit('group_join_request_alert', {
                username: user.username,
                userKey: user.key,
                groupId: group.id,
                isGhost: !!user.isGhost
            });
        });

        socket.emit('system_message', `Request sent to group leadership. Waiting for approval...`);
    });

    // 2b. JOIN WITH PASSWORD (Antwort vom Client)
    socket.on('group_join_with_password', (data) => {
        // data: { groupId, password }
        const user = users[socket.id];
        const group = privateGroups[data.groupId];

        if (!user || !group) return;

// 1. Passwort prüfen
        if (group.password !== data.password) {
            // Hinweis, dass man es nochmal versuchen kann
            socket.emit('system_message', 'ACCESS DENIED: Incorrect password. Try again or type "cancel".');
            return;
        }

        // 2. Beitritt durchführen (Copy-Paste der Join-Logik)
        if (group.members.includes(socket.id)) {
            socket.emit('system_message', 'INFO: You are already in this group.');
            return;
        }

        socket.join(`group_${group.id}`);
        group.members.push(socket.id);
        user.currentGroup = group.id;

        // Erfolg an User senden
        socket.emit('group_joined_success', {
            id: group.id,
            name: group.name,
            key: group.key,
            role: 'MEMBER'
        });

        // Nachricht an Gruppe (Dynamisch)
        io.to(`group_${group.id}`).emit('room_user_status', {
            username: user.username,
            key: user.key,
            isGhost: !!user.isGhost,
            type: 'join',
            context: 'group',
            roomId: group.id
        });

        io.emit('promo_update', generatePromoList());
    });

    // 3. INVITE (/group invite ID [ID] ...) - ENHANCED
    socket.on('group_invite_req', (targetKeysInput) => {
        const user = users[socket.id];
        if (!user || !user.currentGroup) {
            socket.emit('system_message', 'ERROR: You are not in a group.');
            return;
        }

        const group = privateGroups[user.currentGroup];
        if (!group) return;

        // Permissions Check
        const isOwner = group.ownerId === socket.id;
        const isMod = group.mods.includes(socket.id);

        if (!isOwner && !isMod) {
            socket.emit('system_message', 'ERROR: Only Owners and Mods can invite.');
            return;
        }

        // Rolle bestimmen für die Anzeige
        const myRole = isOwner ? 'OWNER' : 'MOD';

        // Sicherstellen, dass wir ein flaches Array haben (egal wie die Args kommen)
        let keysToProcess = Array.isArray(targetKeysInput) ? targetKeysInput : [targetKeysInput];
        keysToProcess = keysToProcess.flat(); // Falls verschachtelt

        let sentCount = 0;

        keysToProcess.forEach(targetKey => {
            // Leere Eingaben überspringen
            if(!targetKey || typeof targetKey !== 'string' || targetKey.trim() === "") return;

            const targetUser = Object.values(users).find(u => u.key === targetKey);

            if (targetUser) {
                if (group.members.includes(targetUser.id)) {
                    socket.emit('system_message', `INFO: User ${targetUser.username} is already in the group.`);
                } else {

                    // --- NEU: AUF DIE SERVER-LISTE SETZEN ---
                    if (!group.invitedUsers) group.invitedUsers = []; // Safety Init
                    if (!group.invitedUsers.includes(targetUser.id)) {
                        group.invitedUsers.push(targetUser.id);
                    }
                    // ----------------------------------------

                    // SEND INVITE (Bleibt gleich)
                    io.to(targetUser.id).emit('group_invite_received', {
                        groupId: group.id,
                        groupName: group.name,
                        inviterName: user.username,
                        inviterKey: user.key,
                        inviterRole: myRole,
                        isGhost: !!user.isGhost
                    });

                    sendPush(targetUser, 'GROUP INVITATION', `User ${user.username} invited you to ${group.name}.`);
                    sentCount++;
                }
            } else {
                socket.emit('system_message', `WARNING: User '${targetKey}' not found.`);
            }
        });

        if (sentCount > 0) {
            socket.emit('system_message', `SUCCESS: ${sentCount} invitation(s) sent.`);
        }
    });

    // 4. INVITE / JOIN ANNEHMEN
    socket.on('group_decision', (data) => {
        const user = users[socket.id];
        if (!user) return; // Crash Schutz

        // FALL A: User nimmt Einladung an (Hier war die Lücke!)
        if (data.groupId) {
            const group = privateGroups[data.groupId];

            // 1. Existiert die Gruppe?
            if (!group) {
                socket.emit('system_message', 'ERROR: Group not found.');
                return;
            }

            // 2. SICHERHEITS-CHECK: Wurde er wirklich eingeladen?
            // Wir prüfen, ob seine ID in der 'invitedUsers' Liste steht.
            const isInvited = group.invitedUsers && group.invitedUsers.includes(socket.id);

            // Ausnahme: Wenn die Gruppe PUBLIC ist, darf jeder rein (optional, aber logisch)
            if (!isInvited && !group.isPublic) {
                serverLog(`SECURITY ALERT: User ${user.username} tried to force-join Group ${group.id} without invite.`);
                socket.emit('system_message', 'ACCESS DENIED: You have no valid invitation for this secure channel.');
                return; // STOPP! Hier kommt niemand rein.
            }

            if (data.accept) {
                socket.join(`group_${group.id}`);
                group.members.push(socket.id);
                user.currentGroup = group.id;

                // WICHTIG: Einladung verbrauchen (löschen)
                if (group.invitedUsers) {
                    group.invitedUsers = group.invitedUsers.filter(id => id !== socket.id);
                }

                // Event senden (Status Update)
                io.to(`group_${group.id}`).emit('room_user_status', {
                    username: user.username,
                    key: user.key,
                    isGhost: !!user.isGhost,
                    type: 'join',
                    context: 'group',
                    roomId: group.id
                });

                // Bestätigung für den User
                socket.emit('group_joined_success', {
                    id: group.id,
                    name: group.name,
                    key: group.key,
                    role: 'MEMBER'
                });

                // Promo Update
                io.emit('promo_update', generatePromoList());

            } else {
                socket.emit('system_message', 'Invitation declined.');
                // Optional: Auch beim Ablehnen von der Liste nehmen?
                // Besser ja, damit die Einladung nicht ewig "schwebt".
                if (group.invitedUsers) {
                    group.invitedUsers = group.invitedUsers.filter(id => id !== socket.id);
                }
            }
        }

        // FALL B: Owner akzeptiert Join-Request (HIER WAR DAS PROBLEM)
        if (data.targetKey) {
            if (!user || !user.currentGroup) return;

            const group = privateGroups[user.currentGroup];
            // Check: Ist der User Owner ODER Mod?
            const isOwner = group.ownerId === socket.id;
            const isMod = group.mods.includes(socket.id);

            if (!group || (!isOwner && !isMod)) {
                socket.emit('system_message', 'ERROR: Insufficient permissions to accept members.');
                return;
            }

            const targetUser = Object.values(users).find(u => u.key === data.targetKey);
            if (!targetUser) return;

            const pendingIndex = group.pendingJoins.indexOf(targetUser.id);
            if (pendingIndex > -1) {
                group.pendingJoins.splice(pendingIndex, 1);

                if (data.accept) {
                    const targetSocket = io.sockets.sockets.get(targetUser.id);
                    if (targetSocket) {
                        targetSocket.join(`group_${group.id}`);
                        group.members.push(targetUser.id);
                        targetUser.currentGroup = group.id;

                        targetSocket.emit('group_joined_success', {
                            id: group.id,
                            name: group.name,
                            key: group.key,
                            role: 'MEMBER'
                        });

                        // WICHTIG: Das hier sendet die dynamische "Approved" Nachricht
                        io.to(`group_${group.id}`).emit('room_user_status', {
                            username: targetUser.username,
                            key: targetUser.key,
                            isGhost: !!targetUser.isGhost, // <--- Das muss TRUE sein wenn er Ghost ist
                            type: 'approved',
                            context: 'group',
                            roomId: group.id
                        });
                    }
                } else {
                    io.to(targetUser.id).emit('system_message', `Your request to join Group ${group.id} was DENIED.`);
                }
            }
        }
    });

    // 11b. GROUP PASSWORD SET (/group password [PW])
    socket.on('group_set_password', (password) => {
        const user = users[socket.id];
        if (!user || !user.currentGroup) return;

        const group = privateGroups[user.currentGroup];
        if (!group) return;

        // Nur Owner darf Passwort setzen
        if (group.ownerId !== socket.id && !user.isAdmin) {
            socket.emit('system_message', 'ERROR: Only the Owner can manage security protocols.');
            return;
        }

        if (!password || password.trim() === "") {
            // Passwort löschen
            delete group.password;
            io.to(`group_${group.id}`).emit('system_message', 'SECURITY UPDATE: Group password removed. Access is open.');
        } else {
            // Passwort setzen
            group.password = password.trim();
            io.to(`group_${group.id}`).emit('system_message', 'SECURITY UPDATE: Group is now password protected 🔒.');
        }
    });

    // 5. MOD SYSTEM (/mod ID) -> Nur Owner
    socket.on('group_user_promote', (targetKey) => {
        // SICHERHEITS-CHECK
        const user = users[socket.id];
        if (!user || !user.currentGroup) return;

        const group = privateGroups[user.currentGroup];

        if (!group || group.ownerId !== socket.id) {
            socket.emit('system_message', 'ERROR: Only the Group Owner can promote users.');
            return;
        }

        const targetUser = Object.values(users).find(u => u.key === targetKey);
        if (!targetUser || !group.members.includes(targetUser.id)) {
            socket.emit('system_message', 'ERROR: User must be in the group.');
            return;
        }

        if (!group.mods.includes(targetUser.id)) {
            group.mods.push(targetUser.id);
            io.to(`group_${group.id}`).emit('system_message', `PERMISSION UPDATE: ${targetUser.username} is now a MODERATOR.`);
        }
    });

    // --- GRUPPEN LINK ERSTELLEN ---
    socket.on('group_create_link_req', (data) => {
        const user = users[socket.id]; // User holen für Context-Check
        if (!user) return;

        const groupId = parseInt(data.groupId);
        const limit = parseInt(data.limit) || 0;

        const group = privateGroups[groupId];

        if (!group) return socket.emit('system_message', 'ERROR: Group not found.');

        const isOwner = group.ownerId === socket.id;
        const isMod = group.mods.includes(socket.id);

        if (!isOwner && !isMod) {
            return socket.emit('system_message', 'DENIED: Only Owner or Mods can create invite links.');
        }

        const linkId = Math.random().toString(36).substr(2, 9);

        activeGroupLinks[linkId] = {
            groupId: groupId,
            limit: limit,
            uses: 0,
            creator: socket.username
        };

        if (data.targetRoomId) {
            // --- FIX: DAS RICHTIGE ZIEL ERMITTELN ---
            let socketIoRoom = data.targetRoomId;

            // 1. Ist das Ziel meine aktuelle Gruppe? -> Prefix 'group_'
            if (user.currentGroup && user.currentGroup == data.targetRoomId) {
                socketIoRoom = `group_${data.targetRoomId}`;
            }
            // 2. Ist das Ziel mein aktueller Public Room? -> Prefix 'pub_'
            else if (user.currentPub && user.currentPub == data.targetRoomId) {
                socketIoRoom = `pub_${data.targetRoomId}`;
            }
            // 3. Ist das Ziel ein Privater Chat (User Key)? -> Socket ID suchen
            else {
                const partner = Object.values(users).find(u => u.key === data.targetRoomId);
                if (partner) {
                    socketIoRoom = partner.id; // An die Socket ID senden
                }
            }

            // An den korrekten Raum senden
            io.to(socketIoRoom).emit('group_link_display', {
                linkId: linkId,
                groupId: groupId,
                groupName: group.name,
                creator: socket.username,
                limit: limit,
                isProtected: !!group.password,
                isPrivate: !group.isPublic
            });

            // Bestätigung an den Ersteller (dich)
            socket.emit('system_message', `Link created for Group ${groupId}. Limit: ${limit === 0 ? '∞' : limit}`);
        }
    });

    // --- GRUPPEN LINK BENUTZEN (FIXED) ---
    socket.on('group_use_link_req', (linkId) => {
        const user = users[socket.id]; // 1. User Objekt holen
        if (!user) return; // Sicherheits-Check

        const link = activeGroupLinks[linkId];

        if (!link) {
            return socket.emit('system_message', 'ERROR: Link is invalid or expired.');
        }

        if (link.limit > 0 && link.uses >= link.limit) {
            return socket.emit('system_message', 'ERROR: Link limit reached.');
        }

        // Zähler hoch
        if (link.limit > 0) {
            link.uses++;
            if (link.uses >= link.limit) {
                delete activeGroupLinks[linkId];
                io.emit('group_link_expired', linkId);
            }
        }

        const group = privateGroups[link.groupId];
        if (!group) return socket.emit('system_message', 'ERROR: Group not found.');

        // 1. Check: Bereits drin?
        if (group.members.includes(socket.id)) {
            return socket.emit('system_message', `You are already in Group ${group.name}.`);
        }

        // 2. Passwort? (Links umgehen Passwort oft, aber wenn du es strikt willst:)
        if (group.password) {
            socket.emit('group_password_required', group.id);
            return;
        }

        // --- HIER WAR DER FEHLER ---

        // 1. Richtigen Raum-Namen definieren (Prefix 'group_')
        const roomName = `group_${group.id}`;

        // 2. Beitreten
        socket.join(roomName);
        group.members.push(socket.id);

        // 3. WICHTIG: Dem User sagen, wo er ist (State Update)
        user.currentGroup = group.id;

        // 4. Erfolg an User senden
        socket.emit('group_joined_success', {
            id: group.id,
            name: group.name,
            role: 'MEMBER',
            key: group.key
        });

        // 5. Nachricht an die Gruppe (An den richtigen Raum!)
        io.to(roomName).emit('room_user_status', {
            username: user.username, // Nimm den Namen aus dem User-Objekt (sicherer)
            key: user.key,
            isGhost: !!user.isGhost,
            type: 'join',
            context: 'group',
            roomId: group.id
        });

        // 6. Promo Liste updaten (damit die Member-Zahl stimmt)
        io.emit('promo_update', generatePromoList());
    });

    // 6. KICK PROCESS (Multi-Target & Reason & Admin Immunity)
    socket.on('group_kick_req', (data) => {
        // data: { targets: ['ID1', 'ID2'], reason: "Grund" }
        const user = users[socket.id];
        if (!user || !user.currentGroup) return;

        const group = privateGroups[user.currentGroup];
        if (!group) return;

        const isOwner = group.ownerId === socket.id;
        const isMod = group.mods.includes(socket.id);
        const isAdmin = user.isAdmin;

        // 1. Berechtigung prüfen (Darf der Sender überhaupt kicken?)
        if (!isOwner && !isMod && !isAdmin) {
            socket.emit('system_message', 'ERROR: Insufficient permissions (Mod/Owner required).');
            return;
        }

        let kickedCount = 0;
        const targets = Array.isArray(data.targets) ? data.targets : [data.targets];

        targets.forEach(targetKey => {
            const targetUser = Object.values(users).find(u => u.key === targetKey);

            if (!targetUser) {
                socket.emit('system_message', `WARNING: User ${targetKey} not found.`);
                return;
            }
            if (!group.members.includes(targetUser.id)) {
                socket.emit('system_message', `INFO: User ${targetUser.username} is not in the group.`);
                return;
            }

            // 2. HIERARCHIE-SCHUTZ & IMMUNITÄT

            // A) ADMIN IMMUNITÄT (Das ist neu!)
            // Wenn das Ziel ein Admin ist, und der Kicker KEIN Admin ist -> Abblocken.
            if (targetUser.isAdmin && !isAdmin) {
                socket.emit('system_message', `ERROR: ACCESS DENIED. You cannot kick a Global Administrator (${targetUser.username}).`);
                return; // Überspringt diesen User
            }

            // B) OWNER SCHUTZ
            // Owner kann nicht gekickt werden (außer er geht selbst oder Admin macht es via Force)
            if (targetUser.id === group.ownerId) {
                if (isAdmin) {
                    // ADMIN SPECIAL: Dialog starten
                    socket.emit('admin_kick_owner_start', {
                        targetName: targetUser.username,
                        targetKey: targetUser.key,
                        groupName: group.name
                    });
                    return; // Abbruch hier, Admin muss erst entscheiden
                } else {
                    socket.emit('system_message', `ERROR: You cannot kick the Owner (${targetUser.username}).`);
                    return;
                }
            }

            // C) MOD SCHUTZ
            // Mods können keine Mods kicken (nur Owner/Admin darf das)
            if (group.mods.includes(targetUser.id) && !isOwner && !isAdmin) {
                socket.emit('system_message', `ERROR: Moderators cannot kick other Moderators.`);
                return;
            }

            // 3. DER KICK (Ausführung)
            const targetSocket = io.sockets.sockets.get(targetUser.id);
            if (targetSocket) {
                targetSocket.leave(`group_${group.id}`);

                // Nachricht an Opfer
                targetSocket.emit('group_kicked_notification', {
                    groupName: group.name,
                    groupId: group.id,
                    reason: data.reason || "No reason provided.",
                    kickerName: user.isGhost ? 'Anonymous' : user.username
                });

                if (users[targetUser.id]) users[targetUser.id].currentGroup = null;
            }

            // Listen bereinigen
            group.members = group.members.filter(id => id !== targetUser.id);
            group.mods = group.mods.filter(id => id !== targetUser.id);
            kickedCount++;

            // Info an Gruppe (Dynamisch)
            io.to(`group_${group.id}`).emit('room_user_status', {
                username: targetUser.username,
                key: targetUser.key,
                isGhost: !!targetUser.isGhost,
                type: 'leave',
                context: 'group',
                roomId: group.id
            });

            // Optionaler Text
            io.to(`group_${group.id}`).emit('system_message', `${targetUser.username} was kicked.`);
        });

        if (kickedCount > 0) {
            socket.emit('system_message', `SUCCESS: ${kickedCount} user(s) removed.`);
            io.emit('promo_update', generatePromoList());
        }
    });

    // 6b. ADMIN COMPLETE OWNER KICK (Die Ausführung)
    socket.on('admin_complete_owner_kick', (data) => {
        // data: { targetKey, action, method, newOwnerKey }
        const user = users[socket.id];
        if (!user || !user.isAdmin || !user.currentGroup) return;

        const group = privateGroups[user.currentGroup];
        if (!group) return;

        // Validierung: Ist das Ziel wirklich (noch) der Owner?
        const oldOwner = Object.values(users).find(u => u.key === data.targetKey);
        if (!oldOwner || group.ownerId !== oldOwner.id) {
            socket.emit('system_message', 'ERROR: Target is not the group owner anymore.');
            return;
        }

        // OPTION A: AUFLÖSEN
        if (data.action === 'dissolve') {
            serverLog(`Admin ${user.username} löst Gruppe ${group.id} auf (Owner Kick).`);

            group.members.forEach(memberId => {
                const s = io.sockets.sockets.get(memberId);
                if (s) {
                    s.leave(`group_${group.id}`);
                    s.emit('group_dissolved', group.id); // Unser Force-Delete Event
                    if (users[memberId]) users[memberId].currentGroup = null;
                }
            });
            delete privateGroups[group.id];

            socket.emit('system_message', 'TARGET ELIMINATED. GROUP DISSOLVED.');
        }

        // OPTION B: TRANSFER
        else if (data.action === 'transfer') {
            let newOwnerId = null;

            // 1. RANDOM (MODS PREFERRED)
            if (data.method === 'random') {
                // Filtere Kandidaten (Alle außer Alter Owner und Admin selbst)
                const candidates = group.members.filter(id => id !== oldOwner.id && id !== socket.id);

                // Mods finden
                const modCandidates = candidates.filter(id => group.mods.includes(id));

                if (modCandidates.length > 0) {
                    // Nimm einen Mod
                    newOwnerId = modCandidates[Math.floor(Math.random() * modCandidates.length)];
                } else if (candidates.length > 0) {
                    // Nimm irgendwen
                    newOwnerId = candidates[Math.floor(Math.random() * candidates.length)];
                } else {
                    // Niemand da außer Admin und Owner? Admin wird Owner.
                    newOwnerId = socket.id;
                    socket.emit('system_message', 'WARNING: No suitable successor found. You are now the Owner.');
                }
            }
            // 2. SPECIFIC
            else if (data.method === 'specific') {
                const specificUser = Object.values(users).find(u => u.key === data.newOwnerKey);
                if (specificUser && group.members.includes(specificUser.id)) {
                    newOwnerId = specificUser.id;
                } else {
                    socket.emit('system_message', 'ERROR: Specific successor not found in group.');
                    return;
                }
            }

            if (!newOwnerId) return;

            // TRANSFER DURCHFÜHREN
            group.ownerId = newOwnerId;
            const newOwner = users[newOwnerId];

            // Alten Owner entfernen
            const oldSocket = io.sockets.sockets.get(oldOwner.id);
            if (oldSocket) {
                oldSocket.leave(`group_${group.id}`);
                oldSocket.emit('group_kicked_notification', {
                    groupName: group.name,
                    groupId: group.id,
                    reason: "Administrative Override / Ownership Revoked",
                    kickerName: `[ADMIN] ${user.username}`
                });
                if (users[oldOwner.id]) users[oldOwner.id].currentGroup = null;
            }

            // Listen aufräumen
            group.members = group.members.filter(id => id !== oldOwner.id);
            group.mods = group.mods.filter(id => id !== oldOwner.id);

            // NEUEN OWNER BENACHRICHTIGEN
            const newSocket = io.sockets.sockets.get(newOwnerId);
            if (newSocket) {
                newSocket.emit('you_are_promoted', { groupId: group.id, role: 'OWNER' });
            }

            // INFO AN GRUPPE
            io.to(`group_${group.id}`).emit('system_message', `ADMIN INTERVENTION: ${oldOwner.username} removed. New Owner is ${newOwner.username}.`);

            // UI Updates
            socket.emit('system_message', 'OPERATION SUCCESSFUL.');
        }

        io.emit('promo_update', generatePromoList());
    });

    // 6a. KICK PREVIEW (Namen auflösen vor dem Kick)
    socket.on('group_kick_preview_req', (targetKeys) => {
        const user = users[socket.id];
        if (!user || !user.currentGroup) return;

        const group = privateGroups[user.currentGroup];
        if (!group) return;

        // Wir sammeln die Infos für die Vorschau
        const previewList = [];
        const targets = Array.isArray(targetKeys) ? targetKeys : [targetKeys];

        targets.forEach(key => {
            const targetUser = Object.values(users).find(u => u.key === key);
            if (targetUser) {
                previewList.push({
                    username: targetUser.username,
                    key: targetUser.key,
                    isGhost: !!targetUser.isGhost // Wichtig für die Anzeige
                });
            } else {
                // Falls ID nicht gefunden wurde, zeigen wir das auch an
                previewList.push({
                    username: 'UNKNOWN/OFFLINE',
                    key: key,
                    isGhost: false
                });
            }
        });

        // Zurück an den Admin senden
        socket.emit('group_kick_preview_res', previewList);
    });

    // 17. ADMIN RESOLVE OWNER KICK (Nachfolge regeln)
    socket.on('group_admin_resolve_owner', (data) => {
        // data: { mode: 'random' | 'specific', oldOwnerKey: '...', newOwnerKey: '...' }
        const user = users[socket.id];
        if (!user || !user.isAdmin || !user.currentGroup) return; // Nur Admins!

        const group = privateGroups[user.currentGroup];
        if (!group) return;

        const oldOwnerUser = Object.values(users).find(u => u.key === data.oldOwnerKey);

        // 1. NEUEN OWNER BESTIMMEN
        let newOwnerId = null;

        if (data.mode === 'random') {
            // Zufälliges Mitglied (außer dem Admin selbst und dem alten Owner)
            const candidates = group.members.filter(id => id !== group.ownerId && id !== socket.id);
            if (candidates.length > 0) {
                newOwnerId = candidates[Math.floor(Math.random() * candidates.length)];
            } else {
                // Wenn sonst niemand da ist, wird der Admin (du) Owner
                newOwnerId = socket.id;
                socket.emit('system_message', 'WARNING: No other members found. YOU are now the Owner.');
            }
        }
        else if (data.mode === 'specific') {
            const specificUser = Object.values(users).find(u => u.key === data.newOwnerKey);
            if (specificUser && group.members.includes(specificUser.id)) {
                newOwnerId = specificUser.id;
            } else {
                socket.emit('system_message', 'ERROR: Designated successor not found in group.');
                return;
            }
        }

        if (!newOwnerId) {
            socket.emit('system_message', 'CRITICAL ERROR: Could not determine successor. Kick aborted.');
            return;
        }

        // 2. TRANSFER DURCHFÜHREN
        group.ownerId = newOwnerId;
        const newOwnerUser = users[newOwnerId];
        io.to(`group_${group.id}`).emit('system_message', `ADMINISTRATIVE OVERRIDE: Ownership transferred to ${newOwnerUser.username}.`);

        // 3. ALTEN OWNER KICKEN
        if (oldOwnerUser) {
            const targetSocket = io.sockets.sockets.get(oldOwnerUser.id);
            if (targetSocket) {
                targetSocket.leave(`group_${group.id}`);
                targetSocket.emit('system_message', `YOU HAVE BEEN KICKED AND STRIPPED OF OWNERSHIP BY GLOBAL ADMIN.`);
                targetSocket.emit('group_kicked');
            }
            group.members = group.members.filter(id => id !== oldOwnerUser.id);
            group.mods = group.mods.filter(id => id !== oldOwnerUser.id);
            oldOwnerUser.currentGroup = null;

            io.to(`group_${group.id}`).emit('system_message', `Former Owner ${oldOwnerUser.username} was removed from the group.`);
        }

        io.emit('promo_update', generatePromoList());
    });

// 7. BROADCAST (/group broadcast MSG) - HIGHLIGHTED & GHOST AWARE
    socket.on('group_broadcast', (msg) => {
        // SICHERHEITS-CHECK
        const user = users[socket.id];
        if (!user || !user.currentGroup) return;

        const group = privateGroups[user.currentGroup];
        if (!group) return;

        const isOwner = group.ownerId === socket.id;
        const isMod = group.mods.includes(socket.id);

        if (isOwner || isMod) {
            // Rolle bestimmen für die Anzeige
            const roleTitle = isOwner ? 'OWNER' : 'MODERATOR';

            // Wir senden ein spezielles Event an ALLE in der Gruppe
            io.to(`group_${group.id}`).emit('group_broadcast_received', {
                text: msg,
                senderName: user.username,
                senderKey: user.key,
                isGhost: !!user.isGhost, // Wichtig für Dynamic Name
                role: roleTitle,
                groupId: group.id
            });

            serverLog(`Broadcast in Gruppe ${group.id} von ${user.username}.`);
        } else {
            socket.emit('system_message', 'ERROR: Broadcast requires MOD or OWNER status.');
        }
    });

    // 8. GRUPPEN NACHRICHTEN (KORRIGIERT)
    socket.on('group_message', (msg) => {
        const user = users[socket.id];
        if (!user || !user.currentGroup) return;

        const group = privateGroups[user.currentGroup];
        if (!group) return;

        // --- SICHERHEITS-CHECK: Ist er noch Mitglied? ---
        if (!group.members.includes(socket.id)) {
            // Falls nicht: Status korrigieren und blockieren
            user.currentGroup = null;
            socket.emit('system_message', 'ERROR: You are no longer a member of this group.');
            return;
        }

        // TAGS SETZEN (Owner, Mod, Admin)
        let displayName = user.username;
        const isOwner = group.ownerId === user.id;
        const isMod = group.mods.includes(user.id);

        if (user.isAdmin && !user.isGhost) {
            displayName = `[ADMIN] ${user.username}`;
        } else if (user.isGhost) {
            displayName = 'Anonymous';
        } else if (isOwner) {
            displayName = `[OWNER] ${user.username}`;
        } else if (isMod) {
            displayName = `[MOD] ${user.username}`;
        }

        // WICHTIG: Event-Name muss 'group_message_received' sein!
        // Und wir müssen groupId mitschicken, damit der Client weiß, wohin damit.
        socket.to(`group_${user.currentGroup}`).emit('group_message_received', {
            user: displayName,
            senderKey: user.key,
            text: msg,          // Verschlüsselter Text
            groupId: group.id   // Damit der Client den richtigen Tab findet
        });
    });

    socket.on('group_message_received', async (data) => {
        // 1. Chat suchen
        const chat = myChats[data.groupId];

        // Falls Chat noch nicht da (z.B. Invite Auto-Join), erst registrieren?
        // Eigentlich solltest du erst 'group_joined_success' bekommen.
        // Aber sicherheitshalber:
        if (!chat) return; // Wir können ohne Key eh nicht entschlüsseln

        // 2. Entschlüsseln mit dem CHAT KEY
        const clearText = await decryptMessage(data.text, chat.key);

        // 3. Anzeigen
        printToChat(data.groupId, `[${data.user}]: ${clearText}`, 'partner-msg');
    });

    // 20. UNIVERSAL GHOST SCANNER (/scan)
    socket.on('ghost_scan_req', () => {
        const user = users[socket.id];
        if (!user) return;

        let detectedGhosts = [];
        let contextName = "";
        let hasPermission = false;

        // FALL A: PUBLIC CHAT
        if (user.currentPub) {
            contextName = `Sector ${user.currentPub}`;
            // Nur Admins dürfen Public scannen
            if (user.isAdmin) {
                hasPermission = true;
                const room = publicRooms[user.currentPub];
                if (room) {
                    room.members.forEach(mid => {
                        const u = users[mid];
                        if (u && u.isGhost) detectedGhosts.push({ realName: u.username, key: u.key });
                    });
                }
            }
        }
        // FALL B: GRUPPEN CHAT
        else if (user.currentGroup) {
            contextName = `Group ${user.currentGroup}`;
            const group = privateGroups[user.currentGroup];

            if (group) {
                const isOwner = group.ownerId === socket.id;
                const isMod = group.mods.includes(socket.id);

                // Admin, Owner oder Mod dürfen scannen
                if (user.isAdmin || isOwner || isMod) {
                    hasPermission = true;
                    group.members.forEach(mid => {
                        const u = users[mid];
                        if (u && u.isGhost) detectedGhosts.push({ realName: u.username, key: u.key });
                    });
                }
            }
        }

        // ERGEBNIS SENDEN
        if (hasPermission) {
            socket.emit('ghost_scan_result', { ghosts: detectedGhosts, context: contextName });
        } else {
            socket.emit('system_message', 'ERROR: Access denied. Insufficient clearance for spectral scan.');
        }
    });

    // 22. ROOM WHISPER SYSTEM (/whisper ID MSG)
    socket.on('room_whisper_req', (data) => {
        // data: { targetKey, message }
        const user = users[socket.id];
        if (!user) return;

        // 1. Kontext bestimmen (Wo befinden wir uns?)
        let roomId = null;
        let context = null; // 'group' oder 'pub'
        let memberList = [];

        if (user.currentGroup) {
            roomId = user.currentGroup;
            context = 'group';
            const grp = privateGroups[roomId];
            if (grp) memberList = grp.members;
        }
        else if (user.currentPub) {
            roomId = user.currentPub;
            context = 'pub';
            const pub = publicRooms[roomId];
            if (pub) memberList = pub.members;
        }

        if (!roomId || !context) {
            socket.emit('system_message', 'ERROR: You must be in a Group or Public Sector to whisper.');
            return;
        }

        // 2. Ziel finden
        const targetUser = Object.values(users).find(u => u.key === data.targetKey);

        if (!targetUser) {
            socket.emit('system_message', `ERROR: User ID ${data.targetKey} not found.`);
            return;
        }

        // 3. Prüfen, ob Ziel im SELBEN Raum ist
        if (!memberList.includes(targetUser.id)) {
            socket.emit('system_message', `ERROR: User ${targetUser.username} is not in this room.`);
            return;
        }

        // 4. Nachricht senden (An Sender UND Empfänger)
        // Wir senden an beide, damit der Sender sieht, was er geschrieben hat.

        const packet = {
            senderKey: user.key,
            senderName: user.username,
            isGhost: !!user.isGhost,
            targetKey: targetUser.key, // Damit der Empfänger weiß, dass es an IHN ging
            text: data.message,
            context: context,
            roomId: roomId
        };

        // An den Empfänger
        io.to(targetUser.id).emit('room_whisper_received', { ...packet, type: 'incoming' });

        // An den Sender (Bestätigung)
        socket.emit('room_whisper_received', { ...packet, type: 'outgoing' });
    });

    // 21. GHOST REVEAL (Einzelner Klick)
    socket.on('ghost_reveal_req', (targetKey) => {
        const requester = users[socket.id];
        if (!requester) return;

        const targetUser = Object.values(users).find(u => u.key === targetKey);
        if (!targetUser) return; // User nicht gefunden

        let hasPermission = false;

        // 1. Admin darf immer
        if (requester.isAdmin) hasPermission = true;

        // 2. Owner/Mod Check (nur wenn beide in der gleichen Gruppe sind)
        else if (requester.currentGroup && requester.currentGroup === targetUser.currentGroup) {
            const group = privateGroups[requester.currentGroup];
            if (group) {
                const isOwner = group.ownerId === requester.id;
                const isMod = group.mods.includes(requester.id);
                if (isOwner || isMod) hasPermission = true;
            }
        }

        // (In Public Chats darf nur Admin, das ist oben durch user.isAdmin abgedeckt)

        if (hasPermission) {
            // Erfolg: Wahre Daten senden
            socket.emit('ghost_reveal_result', {
                realName: targetUser.username,
                key: targetUser.key,
                isGhost: targetUser.isGhost
            });
        } else {
            // Sollte eigentlich nicht passieren, da der Client den Klick schon verhindert,
            // aber sicher ist sicher.
            socket.emit('system_message', 'ERROR: Access denied.');
        }
    });

    // 9. GROUP WHO (/group who)
    socket.on('group_who_req', () => {
        const user = users[socket.id];
        if (!user || !user.currentGroup) return;

        const group = privateGroups[user.currentGroup];
        if (!group) return;

        // Namen und Rollen auflisten
        const memberList = group.members.map(memberId => {
            const u = users[memberId];
            if (!u) return 'Unknown';

            let tag = '';
            if (group.ownerId === u.id) tag = '[OWNER] ';
            else if (group.mods.includes(u.id)) tag = '[MOD] ';

            // Geister verstecken sich auch in Gruppen (optional)
            if (u.isGhost) return `${tag}Anonymous`;

            return `${tag}${u.username}`;
        });

        socket.emit('system_message', `MEMBERS IN GROUP ${group.id}: [ ${memberList.join(', ')} ]`);
    });

    // 9b. GROUP LIST (/group list) - HIERARCHISCH
    socket.on('group_list_req', () => {
        const user = users[socket.id];
        if (!user || !user.currentGroup) return;

        const group = privateGroups[user.currentGroup];
        if (!group) return;

        // Container für die Sortierung
        const result = {
            owner: null,
            mods: [],
            members: []
        };

        // Alle Mitglieder durchgehen und sortieren
        group.members.forEach(memberId => {
            const u = users[memberId];
            if (!u) return;

            // Datenpaket für den Client (Ghost-Flag ist wichtig!)
            const userData = {
                username: u.username,
                key: u.key,
                isGhost: !!u.isGhost
            };

            if (group.ownerId === u.id) {
                result.owner = userData;
            } else if (group.mods.includes(u.id)) {
                result.mods.push(userData);
            } else {
                result.members.push(userData);
            }
        });

        // Antwort an den Anfrager senden
        socket.emit('group_list_result', result);
    });

    // 11. GROUP RENAME (/group name [NAME]) - UI UPDATE FIX
    socket.on('group_rename', (newNameInput) => { // <--- WICHTIG: Hier "Input" nennen
        // SICHERHEITS-CHECK
        const user = users[socket.id];
        if (!user || !user.currentGroup) return;

        const group = privateGroups[user.currentGroup];
        if (!group) return;

        // BERECHTIGUNG: Owner ODER Admin
        if (group.ownerId !== socket.id && !user.isAdmin) {
            socket.emit('system_message', 'ERROR: Only the Group Owner or Global Admin can rename.');
            return;
        }

        // --- XSS SCHUTZ ---
        // Wir nehmen den "Input", waschen ihn, und speichern ihn als sauberen "newName"
        const newName = escapeHtml((newNameInput || '').trim());
        // ------------------

        // Validierung (jetzt mit der sauberen Variable prüfen)
        if (newName.length === 0) {
            socket.emit('system_message', 'ERROR: Name cannot be empty.');
            return;
        }
        if (newName.length > 20) {
            socket.emit('system_message', 'ERROR: Name too long (max 20 chars).');
            return;
        }

        const oldName = group.name;
        group.name = newName; // Speichern

        serverLog(`Gruppe ${group.id} umbenannt zu '${newName}' von ${user.username}.`);

        // 1. Text-Nachricht an alle
        const suffix = user.isAdmin && group.ownerId !== socket.id ? " by Authority" : "";
        io.to(`group_${group.id}`).emit('system_message', `NETWORK UPDATE: Group renamed to '${newName}'${suffix}.`);

        // 2. LIVE UI UPDATE (Damit sich Sidebar & Prompt ändern)
        io.to(`group_${group.id}`).emit('group_name_changed', {
            id: group.id,
            newName: newName
        });

        // 3. PROMO BOARD UPDATE (Falls die Gruppe public ist, Name dort ändern)
        io.emit('promo_update', generatePromoList());
    });

// 12. GROUP PRIVACY TOGGLE - ADMIN UPDATE
    socket.on('group_toggle_privacy', (setOpen) => {
        const user = users[socket.id];
        if (!user || !user.currentGroup) return;
        const group = privateGroups[user.currentGroup];

        if (!group) return;

        // Owner ODER Admin
        if (group.ownerId !== socket.id && !user.isAdmin) {
            socket.emit('system_message', 'ERROR: Permission denied.');
            return;
        }

        group.isPublic = setOpen;
        const status = setOpen ? "PUBLIC (Open to all)" : "PRIVATE (Invite only)";
        io.to(`group_${group.id}`).emit('system_message', `SECURITY UPDATE: Group is now ${status}.`);

        // Promo Board update (Sichtbarkeit)
        io.emit('promo_update', generatePromoList());
    });

    // 13. OWNERSHIP TRANSFER (/group owner KEY) - ADMIN UPDATE
    socket.on('group_transfer_owner', (targetKey) => {
        const user = users[socket.id];
        if (!user || !user.currentGroup) return;
        const group = privateGroups[user.currentGroup];

        // ADMIN-UPDATE: Owner ODER Admin darf das
        if (!group || (group.ownerId !== socket.id && !user.isAdmin)) {
            socket.emit('system_message', 'ERROR: You are not the Owner or Global Admin.');
            return;
        }

        const targetUser = Object.values(users).find(u => u.key === targetKey);
        if (!targetUser || !group.members.includes(targetUser.id)) {
            socket.emit('system_message', 'ERROR: New owner must be in the group.');
            return;
        }

        // Transfer durchführen
        group.ownerId = targetUser.id;

        // LOGIK BEIBEHALTEN: Den Ausführenden (alter Owner oder Admin) zum Mod machen
        if (!group.mods.includes(socket.id)) {
            group.mods.push(socket.id);
        }

        // Info-Nachricht (leicht angepasst für Admins)
        const suffix = user.isAdmin && group.ownerId !== socket.id ? " by Administrative Order" : "";

        io.to(`group_${group.id}`).emit('system_message', `HIERARCHY CHANGE: Ownership transferred to ${targetUser.username}${suffix}.`);
        io.to(`group_${group.id}`).emit('system_message', `User ${user.username} is now a Moderator.`);
    });

    // 15. GROUP PROMOTE (/group promote TEXT)
    socket.on('group_promote', (desc) => {
        const user = users[socket.id];
        if (!user || !user.currentGroup) return;
        const group = privateGroups[user.currentGroup];

        // Nur Owner darf promoten
        if (!group || group.ownerId !== socket.id) {
            socket.emit('system_message', 'ERROR: Only Owner can promote.');
            return;
        }

        // Muss public sein
        if (!group.isPublic) {
            socket.emit('system_message', 'ERROR: Group must be PUBLIC (/group open) to be promoted.');
            return;
        }

        // Text speichern
        group.description = desc.substring(0, 100); // Max 100 Zeichen
        group.promotedAt = new Date();

        socket.emit('system_message', 'SUCCESS: Group is now listed on the Public Board.');

        // UPDATE AN ALLE SENDEN (Damit das Fenster rechts sich updated)
        io.emit('promo_update', generatePromoList());
    });

    // Wenn neuer User kommt: Liste schicken
    socket.on('request_promo_list', () => {
        socket.emit('promo_update', generatePromoList());
    });

    // Auch beim Erstellen/Löschen/Joinen sollte die Liste aktualisiert werden,
    // damit die "Member Count" Zahl stimmt.
    // Füge `io.emit('promo_update', generatePromoList());` am besten auch bei
    // 'group_join_req', 'group_leave' und 'group_destroy_confirm' hinzu!

// 14. GROUP DESTROY (Wenn Owner bestätigt) - ADMIN UPDATE
    socket.on('group_destroy_confirm', () => {
        const user = users[socket.id];
        if (!user || !user.currentGroup) return;
        const group = privateGroups[user.currentGroup];

        // ADMIN-UPDATE: Nur Owner ODER Admin darf zerstören
        if (!group || (group.ownerId !== socket.id && !user.isAdmin)) return;

        serverLog(`Gruppe ${group.id} von ${user.username} (Admin: ${user.isAdmin}) aufgelöst.`);

        // LOGIK BEIBEHALTEN: Alle kicken und benachrichtigen
        group.members.forEach(memberId => {
            const memberSocket = io.sockets.sockets.get(memberId);
            if (memberSocket) {
                memberSocket.leave(`group_${group.id}`);

                // Nachricht anpassen falls Admin
                const reason = user.isAdmin ? "Global Administrator" : "The Owner";
                memberSocket.emit('system_message', `GROUP DISBANDED: ${reason} dissolved the group.`);

                memberSocket.emit('group_left_success'); // Client Reset

                if (users[memberId]) users[memberId].currentGroup = null;
            }
        });

        // Gruppe aus Speicher löschen
        delete privateGroups[group.id];

        // WICHTIG: Promo Board updaten
        io.emit('promo_update', generatePromoList());
    });

    // 10. GROUP LEAVE (Mit Owner-Check Dialog)
    socket.on('group_leave', () => {
        const user = users[socket.id];
        if (!user || !user.currentGroup) return;
        const group = privateGroups[user.currentGroup];
        if (!group) return;

        // CHECK: IST ES DER OWNER?
        if (group.ownerId === socket.id) {
            // Wir lassen ihn NICHT gehen, sondern fordern Entscheidung
            socket.emit('group_owner_leave_dialog');
            return;
        }

        // --- Normaler Leave Prozess für Member ---
        socket.leave(`group_${group.id}`);
        group.members = group.members.filter(id => id !== socket.id);
        group.mods = group.mods.filter(id => id !== socket.id);
        user.currentGroup = null;

        // Dynamische Leave Nachricht
        io.to(`group_${group.id}`).emit('room_user_status', {
            username: user.username,
            key: user.key,
            isGhost: !!user.isGhost,
            type: 'leave',
            context: 'group',
            roomId: group.id
        });

        socket.emit('group_left_success');
        io.emit('promo_update', generatePromoList());
    });

    // NEU: OWNER ENTSCHEIDUNG BEIM VERLASSEN
    socket.on('group_owner_action', (data) => {
        // data: { action: 'close' | 'transfer', target: 'random' | KEY }
        const user = users[socket.id];
        if (!user || !user.currentGroup) return;
        const group = privateGroups[user.currentGroup];
        if (!group || group.ownerId !== socket.id) return; // Nur Owner!

        if (data.action === 'close') {
            // GRUPPE AUFLÖSEN (Wie Dissolve)
            serverLog(`Owner ${user.username} schließt Gruppe ${group.id} beim Verlassen.`);

            group.members.forEach(memberId => {
                const s = io.sockets.sockets.get(memberId);
                if (s) {
                    s.leave(`group_${group.id}`);
                    s.emit('group_dissolved', group.id);
                    if (users[memberId]) users[memberId].currentGroup = null;
                }
            });
            delete privateGroups[group.id];
        }
        else if (data.action === 'transfer') {
            // NACHFOLGER BESTIMMEN
            let newOwnerId = null;

            if (data.target === 'random') {
                const candidates = group.members.filter(id => id !== socket.id);
                if (candidates.length > 0) {
                    newOwnerId = candidates[Math.floor(Math.random() * candidates.length)];
                }
            } else {
                // Bestimmter Key
                const targetUser = Object.values(users).find(u => u.key === data.target);
                if (targetUser && group.members.includes(targetUser.id)) {
                    newOwnerId = targetUser.id;
                }
            }

            if (!newOwnerId) {
                socket.emit('system_message', 'ERROR: No valid successor found. Cannot leave.');
                return;
            }

            // Transfer & Leave
            group.ownerId = newOwnerId;
            const newOwner = users[newOwnerId];

            // --- NEU: DEM NEUEN CHEF BESCHEID SAGEN ---
            const newOwnerSocket = io.sockets.sockets.get(newOwnerId);
            if (newOwnerSocket) {
                newOwnerSocket.emit('you_are_promoted', {
                    groupId: group.id,
                    role: 'OWNER'
                });
            }

            // Alten Owner entfernen
            socket.leave(`group_${group.id}`);
            group.members = group.members.filter(id => id !== socket.id);
            group.mods = group.mods.filter(id => id !== socket.id);
            user.currentGroup = null;

            socket.emit('group_left_success'); // Owner ist raus

            // Info an Gruppe
            io.to(`group_${group.id}`).emit('system_message', `OWNERSHIP TRANSFER: ${newOwner.username} is the new Owner.`);

            // Ghost-Aware Leave Nachricht für den alten Owner
            io.to(`group_${group.id}`).emit('room_user_status', {
                username: user.username,
                key: user.key,
                isGhost: !!user.isGhost,
                type: 'leave',
                context: 'group',
                roomId: group.id
            });
        }

        io.emit('promo_update', generatePromoList());
    });

    // 16. GROUP DISSOLVE (/group dissolve) - Harter Reset
    socket.on('group_dissolve', () => {
        const user = users[socket.id];
        if (!user || !user.currentGroup) return;
        const group = privateGroups[user.currentGroup];
        if (!group) return;

        // Owner oder Admin
        if (group.ownerId !== socket.id && !user.isAdmin) {
            socket.emit('system_message', 'ERROR: Insufficient permissions.');
            return;
        }

        serverLog(`Gruppe ${group.id} wurde durch Befehl /dissolve aufgelöst.`);

// Alle rauswerfen (Dissolve Command)
        group.members.forEach(memberId => {
            const memberSocket = io.sockets.sockets.get(memberId);
            if (memberSocket) {
                memberSocket.leave(`group_${group.id}`);
                // NEU: Hartes Lösch-Signal
                memberSocket.emit('group_dissolved', group.id);

                if (users[memberId]) users[memberId].currentGroup = null;
            }
        });

        delete privateGroups[group.id];
        io.emit('promo_update', generatePromoList());
    });

    // 18. PUSH SUBSCRIPTION SPEICHERN
    socket.on('save_subscription', (sub) => {
        const user = users[socket.id];
        if (user) {
            // Wir speichern die Adresse nur im RAM beim User
            user.pushSubscription = sub;
            // Optional: serverLog(`Push Sub registriert für ${user.username}`);
        }
    });

    // 19. PUSH "NUDGE" (Jemanden anstupsen)
    socket.on('send_nudge', (targetKey) => {
        const sender = users[socket.id];
        if (!sender) return;

        // Ziel suchen
        const targetUser = Object.values(users).find(u => u.key === targetKey);

        if (targetUser && targetUser.pushSubscription) {
            // Payload definieren
            const payload = JSON.stringify({
                title: 'INCOMING TRANSMISSION',
                body: `Node ${sender.username} is requesting uplink...`,
                icon: '/favicon.ico' // Falls du eins hast
            });

            // Push senden (Feuer und vergessen)
            webpush.sendNotification(targetUser.pushSubscription, payload)
                .catch(err => console.error("Push Error:", err));

            socket.emit('system_message', `SIGNAL SENT: Nudge transmitted to ${targetUser.username}.`);
        } else {
            socket.emit('system_message', 'ERROR: Target has not enabled subspace comms (Push).');
        }
    });

    // --- FEATURE: DEAD DROPS ---

    // 1. DROP ERSTELLEN (/drop create [MSG] [OPTIONAL: TIMER_IN_MIN])
    socket.on('drop_create', (data) => {
        // data: { message: "Geheim", timer: 5 }
        const user = users[socket.id];
        if (!user) return;

        // Sicherheits-Check: Zu viele Drops? (Spam Schutz)
        if (Object.keys(deadDrops).length > 100) {
            socket.emit('system_message', 'ERROR: Drop storage full. Wait for burn cycles.');
            return;
        }

        // ID Generieren (Format: X9-F2-A1)
        const idPart1 = crypto.randomBytes(1).toString('hex').toUpperCase();
        const idPart2 = crypto.randomBytes(1).toString('hex').toUpperCase();
        const idPart3 = crypto.randomBytes(1).toString('hex').toUpperCase();
        const dropId = `${idPart1}-${idPart2}-${idPart3}`;

        // Standard Timer: 5 Minuten, wenn nichts angegeben
        const minutes = data.timer || 5;
        const ttl = minutes * 60 * 1000;

        // Drop speichern
        deadDrops[dropId] = {
            id: dropId,
            content: data.message,
            creator: user.username,
            created: Date.now(),
            expires: Date.now() + ttl,
            timeoutId: setTimeout(() => {
                // AUTO-BURN (Zeit abgelaufen)
                if (deadDrops[dropId]) {
                    delete deadDrops[dropId];
                    // Optional: Man könnte dem Ersteller sagen, dass er verfallen ist
                }
            }, ttl)
        };

        serverLog(`Dead Drop ${dropId} erstellt von ${user.username}. Burns in ${minutes}m.`);

        socket.emit('system_message', `DEAD DROP COORDINATES SECURED.`);
        socket.emit('system_message', `ID: [ ${dropId} ]`);
        socket.emit('system_message', `LIFESPAN: ${minutes} MINUTES. PASS THE ID.`);
    });

    // 2. DROP ABHOLEN (/drop pickup [ID])
    socket.on('drop_pickup', (dropId) => {
        const user = users[socket.id];
        if (!user) return;

        // ID bereinigen (Leerzeichen weg)
        const cleanId = dropId.trim().toUpperCase();
        const drop = deadDrops[cleanId];

        if (drop) {
            // Erfolg! Nachricht senden
            socket.emit('system_message', '----------------------------------------');
            socket.emit('system_message', `>>> DROP ${cleanId} LOCATED.`);
            socket.emit('system_message', `>>> DECRYPTING PAYLOAD...`);

            // Nachricht als spezielle "Drop-Message" senden
            socket.emit('drop_content', {
                from: drop.creator,
                text: drop.content
            });

            // WICHTIG: SOFORT LÖSCHEN (Burn on Read)
            clearTimeout(drop.timeoutId); // Timer stoppen
            delete deadDrops[cleanId]; // Daten vernichten

            serverLog(`Dead Drop ${cleanId} abgeholt von ${user.username}. Zerstört.`);

            // Dem Abholer sagen, dass es jetzt weg ist
            socket.emit('system_message', `>>> PROTOCOL: PACKAGE INCINERATED.`);
            socket.emit('system_message', '----------------------------------------');

        } else {
            // Drop existiert nicht (mehr)
            socket.emit('system_message', `ERROR: DROP ${cleanId} NOT FOUND.`);
            socket.emit('system_message', `STATUS: EXPIRED OR NEVER EXISTED.`);
        }
    });

    // --- WEBRTC SIGNALING & VOICE (Multi-Chat Update) ---

    // 1. P2P SIGNAL (Sicher & Universal)
    socket.on('p2p_signal', (data) => {
        // data: { targetKey, targetId, type, payload, ... }
        const user = users[socket.id];
        // Fileshare nutzt oft targetId (SocketID), Chat nutzt targetKey (UserKey)

        let targetSocketId = null;

        // Fall A: Ziel via Key (Chat)
        if (data.targetKey) {
            const t = Object.values(users).find(u => u.key === data.targetKey);
            if (t) targetSocketId = t.id;
        }
        // Fall B: Ziel via SocketID (Fileshare)
        else if (data.targetId) {
            targetSocketId = data.targetId;
        }

        if (!targetSocketId) return;

        // --- ZUGRIFFSKONTROLLE ---
        let allowed = false;

        // 1. Sind wir Chat-Partner? (Streng)
        if (user && user.partners.includes(targetSocketId)) {
            allowed = true;
        }

        if (!allowed && activeShares[targetSocketId]) {
            allowed = true;
        }

        // Nur senden, wenn erlaubt
        if (allowed) {
            io.to(targetSocketId).emit('p2p_signal', {
                senderKey: user ? user.key : null,
                senderId: socket.id, // Für Fileshare wichtig
                type: data.type,
                payload: data.payload,
                metadata: data.metadata
            });
        } else {
            // console.log("Blocked unauthorized P2P signal");
        }
    });

    // --- SECURITY: RE-KEYING SIGNAL (Rotation) ---
    socket.on('rekey_signal', (data) => {
        // data: { targetKey, type: 'request'|'response', publicKey, ... }
        const user = users[socket.id];
        if (!user) return;

        const targetUser = Object.values(users).find(u => u.key === data.targetKey);

        // Sicherheits-Check: Sind sie Partner?
        if (targetUser && user.partners.includes(targetUser.id)) {
            io.to(targetUser.id).emit('rekey_signal_received', {
                senderKey: user.key,
                type: data.type,
                publicKey: data.publicKey
            });
            // serverLog(`Security Rotation: ${user.username} -> ${targetUser.username}`);
        }
    });

    // 2. VOICE CALL REQUEST (Anrufen)
    socket.on('voice_request', (data) => {
        // data: { targetKey }
        const user = users[socket.id];
        if (!user || !data.targetKey) return;

        const targetUser = Object.values(users).find(u => u.key === data.targetKey);

        if (targetUser && user.partners.includes(targetUser.id)) {
            io.to(targetUser.id).emit('voice_incoming', {
                caller: user.username,
                callerKey: user.key // WICHTIG: Key mitsenden, damit der Empfänger antworten kann
            });
        }
    });

    // 3. VOICE ACCEPT (Annehmen)
    socket.on('voice_accept', (data) => {
        // data: { targetKey }
        const user = users[socket.id];
        if (!user || !data.targetKey) return;

        const targetUser = Object.values(users).find(u => u.key === data.targetKey);

        if (targetUser && user.partners.includes(targetUser.id)) {
            io.to(targetUser.id).emit('voice_connected', {
                responderKey: user.key
            });
        }
    });

    // 4. VOICE HANGUP (Auflegen)
    socket.on('voice_hangup', (data) => {
        // data: { targetKey }
        const user = users[socket.id];
        if (!user || !data.targetKey) return;

        const targetUser = Object.values(users).find(u => u.key === data.targetKey);

        if (targetUser) {
            // Wir senden es trotzdem, auch wenn sie nicht mehr in der Partner-Liste sind (für Cleanup)
            io.to(targetUser.id).emit('voice_terminated', {
                enderKey: user.key
            });
        }
    });

    // --- DISCONNECT HANDLING ---
    socket.on('disconnect', () => {
        // 1. User identifizieren
        const user = users[socket.id];

        if (user) {
            serverLog(`Verbindung getrennt: ${user.username} [${socket.id}]`);

            if (user.currentPub) {
                const pubId = user.currentPub;
                const room = publicRooms[pubId];

                if (room) {
                    room.members = room.members.filter(id => id !== socket.id);

                    // Wenn leer -> löschen
                    if (room.members.length === 0) {
                        delete publicRooms[pubId];
                        serverLog(`Public Sector ${pubId} collapsed (User disconnect).`);
                        // --- NEU: Nummern neu vergeben ---
                        reorganizePublicRooms();
                        // ---------------------------------
                    } else {
                        io.to(`pub_${pubId}`).emit('system_message', `User ${user.username} signal lost.`);
                    }
                }
            }

            // 2. War der User in einer Gruppe?
            if (user.currentGroup) {
                const group = privateGroups[user.currentGroup];

                if (group) {
                    // Entferne User aus den Listen
                    group.members = group.members.filter(id => id !== socket.id);
                    group.mods = group.mods.filter(id => id !== socket.id);

                    // FALL A: Der OWNER ist gegangen -> NACHFOLGER SUCHEN
                    if (group.ownerId === socket.id) {
                        serverLog(`Owner disconnected. Suche Nachfolger für Gruppe ${group.id}...`);

                        let newOwnerId = null;

                        // Priorität 1: Ein Moderator
                        if (group.mods.length > 0) {
                            newOwnerId = group.mods[Math.floor(Math.random() * group.mods.length)];
                        }
                        // Priorität 2: Ein normales Mitglied
                        else if (group.members.length > 0) {
                            newOwnerId = group.members[Math.floor(Math.random() * group.members.length)];
                        }

                        if (newOwnerId) {
                            // Transfer durchführen
                            group.ownerId = newOwnerId;
                            const newOwner = users[newOwnerId];

                            // Info an die Gruppe
                            io.to(`group_${group.id}`).emit('room_user_status', {
                                username: newOwner.username,
                                key: newOwner.key,
                                isGhost: !!newOwner.isGhost,
                                type: 'approved',
                                context: 'group',
                                roomId: group.id
                            });

                            io.to(`group_${group.id}`).emit('system_message', `CRITICAL: Owner signal lost. Authority transferred automatically.`);

                            // --- NEU: DEM NEUEN CHEF BESCHEID SAGEN ---
                            const newOwnerSocket = io.sockets.sockets.get(newOwnerId);
                            if (newOwnerSocket) {
                                newOwnerSocket.emit('you_are_promoted', {
                                    groupId: group.id,
                                    role: 'OWNER'
                                });
                            }
                            // ------------------------------------------
                        } else {
                            // Niemand mehr da -> Löschen
                            serverLog(`Gruppe ${group.id} leer. Wird gelöscht.`);
                            delete privateGroups[group.id];
                        }
                    }
                    // FALL B: Ein normales MITGLIED ist gegangen
                    else {
                        io.to(`group_${group.id}`).emit('room_user_status', {
                            username: user.username,
                            key: user.key,
                            isGhost: !!user.isGhost,
                            type: 'leave',
                            context: 'group',
                            roomId: group.id
                        });
                    }

                    // Promo-Board aktualisieren
                    io.emit('promo_update', generatePromoList());
                }
            }

            // 3. Partner trennen (Private Chat -> AUTO BURN ALL)
            if (user.partners && user.partners.length > 0) {
                user.partners.forEach(partnerId => {
                    // Jedem Partner das Burn-Signal schicken
                    io.to(partnerId).emit('private_leave_received', {
                        name: user.username,
                        key: user.key
                    });

                    // Uns aus der Liste des Partners entfernen
                    if (users[partnerId] && users[partnerId].partners) {
                        users[partnerId].partners = users[partnerId].partners.filter(id => id !== socket.id);
                    }
                });
                user.partners = []; // Reset
            }

            // 4. User endgültig löschen
            delete users[socket.id];
        }
    });

    // 13. PUBLIC WHISPER (FLÜSTERN)
    // 13. PUBLIC WHISPER (FLÜSTERN)
    socket.on('pub_whisper', (data) => {
        const sender = users[socket.id];

        // Checks: User muss existieren und in einem Raum sein
        if (!sender || !sender.currentRoom) return;

        // Rate Limit Check
        const now = Date.now();
        const lastTime = messageRateLimit[socket.id] || 0;
        if (now - lastTime < 200) {
            socket.emit('system_message', 'WARNING: Rate limit exceeded.');
            return;
        }
        messageRateLimit[socket.id] = now;

        // Ziel-User finden (anhand Key)
        const allUsers = Object.values(users);
        const targetUser = allUsers.find(u => u.key === data.targetKey);

        // Validierung
        if (!targetUser) {
            socket.emit('system_message', `ERROR: Target node '${data.targetKey}' not found.`);
            return;
        }

        // Sicherheits-Check: Sind beide im SELBEN Raum?
        if (targetUser.currentRoom !== sender.currentRoom) {
            socket.emit('system_message', `ERROR: Target is not in your sector. Communication impossible.`);
            return;
        }

        // --- NAMENS-LOGIK: Ghost > Admin > Normal ---
        let senderName = sender.username;

        if (sender.isGhost) {
            senderName = 'Anonymous'; // Ghost überschreibt alles
        } else if (sender.isAdmin) {
            senderName = `[ADMIN] ${sender.username}`;
        }
        // --------------------------------------------

        // Nachricht weiterleiten
        io.to(targetUser.id).emit('pub_whisper_received', {
            senderName: senderName,
            text: data.message
        });
    });

    // GLOBAL BROADCAST EMPFANGEN (Admin)
    socket.on('global_broadcast_received', (data) => {
        // data: { text, senderName, isGhost }

        const target = 'LOCAL'; // Immer in Local Shell!

        // Ghost Logik für den Admin-Namen
        const initialName = data.isGhost ? 'Anonymous' : data.senderName;
        // Wir haben hier keinen Key mitgeschickt (Global Broadcast ist oft ohne Key),
        // aber du kannst statisch [ADMIN] davor setzen.

        // Design bauen (Rot für Global Alert)
        const broadcastHtml = `
        <div style="border: 2px solid #f00; background: rgba(255, 0, 0, 0.1); padding: 15px; margin: 10px 0;">
            <div style="color: #f00; font-weight: bold; font-size: 1.1em; margin-bottom: 8px; text-align: center;">
                ⚠️ GLOBAL SYSTEM BROADCAST ⚠️
            </div>
            <div style="color: #fff; font-size: 1.1em; text-align: center;">
                "${data.text}"
            </div>
            <div style="text-align: right; font-size: 0.8em; color: #f00; margin-top: 10px;">
                — AUTHORITY: [ADMIN] ${initialName}
            </div>
        </div>
    `;

        // 1. In Local Shell drucken (auch wenn wir nicht da sind)
        // Wir greifen direkt auf den Speicher zu, um HTML zu pushen
        if (myChats[target]) {
            myChats[target].history.push(broadcastHtml);

            if (activeChatId === target) {
                // Direkt anzeigen
                const div = document.createElement('div');
                div.innerHTML = broadcastHtml;
                output.appendChild(div);
                output.scrollTop = output.scrollHeight;
            } else {
                // Ungelesen markieren
                myChats[target].unread++;
                renderChatList();
                printLine(`(i) ⚠️ GLOBAL ALERT in LOCAL_SHELL`, 'error-msg'); // Hinweis im aktuellen Chat
            }
        }
    });

    // --- FILE SYSTEM SIGNALS (Server speichert nur METADATEN, keine Dateien!) ---

    // Globale Liste der Shares im Speicher (Reset bei Server Neustart)
    // Struktur: { socketId: { folderName, username, id } }
    // HINWEIS: Diese Variable muss AUSSERHALB von io.on('connection') definiert sein!
    // Am besten ganz oben bei den anderen Variablen:
    // let activeShares = {};

    // 1. User kündigt Share an
    socket.on('fs_start_hosting', (data) => {
        activeShares[socket.id] = {
            username: data.username || socket.username || 'Anonymous',
            key: socket.id.substr(0, 5),
            folderName: data.folderName,
            allowedUsers: data.allowedUsers || [],
            allowedGroups: data.allowedGroups || [], // <--- NEU
            isProtected: data.isProtected || false,
            isSingleFile: data.isSingleFile || false
        };
        broadcastShares();
    });

    // Client fragt: In welchen Gruppen bin ich?
    socket.on('fs_request_groups', () => {
        // socket.rooms ist ein Set mit allen Räumen (inklusive eigener Socket-ID)
        // Wir filtern die Socket-ID raus, der Rest sind Gruppen
        const rooms = Array.from(socket.rooms).filter(r => r !== socket.id);
        socket.emit('fs_group_list', rooms);
    });

    // 2. User stoppt Share
    socket.on('fs_stop_hosting', () => {
        if (activeShares[socket.id]) {
            delete activeShares[socket.id];
            io.emit('fs_update_shares', activeShares);
        }
    });

    // 3. Wenn User Tab schließt / disconnect
    socket.on('disconnect', () => {
        if (activeShares[socket.id]) {
            delete activeShares[socket.id];
            // Verzögertes Update, falls es nur ein Refresh war (optional, hier direkt)
            io.emit('fs_update_shares', activeShares);
        }
        // ... dein alter Disconnect Code ...
    });

    // INTELLIGENTES BROADCASTING (Sichtbarkeit filtern)
    function broadcastShares() {
        const connectedSockets = io.sockets.sockets;

        connectedSockets.forEach((recipientSocket) => {
            const sharesVisibleToUser = {};

            Object.keys(activeShares).forEach(hostId => {
                const share = activeShares[hostId];

                // Regel 1: Eigene Shares
                if (hostId === recipientSocket.id) {
                    sharesVisibleToUser[hostId] = share;
                    return;
                }

                // Regel 2: Public Share (Keine User UND keine Gruppen definiert)
                const isPublic = (!share.allowedUsers || share.allowedUsers.length === 0) &&
                    (!share.allowedGroups || share.allowedGroups.length === 0);

                if (isPublic) {
                    sharesVisibleToUser[hostId] = share;
                    return;
                }

                // Regel 3: User ID Check
                const isUserAllowed = share.allowedUsers && share.allowedUsers.some(allowedId => recipientSocket.id.includes(allowedId));

                // Regel 4: Gruppen Check (NEU)
                // Ist der Empfänger in einer der erlaubten Gruppen?
                // recipientSocket.rooms ist ein Set
                let isGroupAllowed = false;
                if (share.allowedGroups && share.allowedGroups.length > 0) {
                    isGroupAllowed = share.allowedGroups.some(groupName => recipientSocket.rooms.has(groupName));
                }

                // ZUGRIFF?
                if (isUserAllowed || isGroupAllowed) {
                    sharesVisibleToUser[hostId] = share;
                }
            });

            recipientSocket.emit('fs_update_shares', sharesVisibleToUser);
        });
    }

    // 4. Neuer User kommt rein -> Liste anfordern
    socket.on('fs_request_update', () => {
        socket.emit('fs_update_shares', activeShares);
    });

    // --- BLOG / SYSTEM LOGS SYSTEM ---

// 1. LISTE ANFORDERN (Mit Sicherheits-Filter)
    socket.on('blog_list_req', async () => {
        const user = users[socket.id];
        try {
            const allPosts = await db.getBlogPosts();

            // ZENSUR-LOGIK:
            const sanitized = allPosts.map(p => {
                // Wenn ein Passwort existiert UND der User kein Admin ist:
                // Inhalt löschen und Flag setzen!
                if (p.password && (!user || !user.isAdmin)) {
                    return {
                        ...p,
                        content: undefined,   // Inhalt weg!
                        attachment: undefined, // Datei weg!
                        isProtected: true,    // Signal für Client: "Zeig Passwort-Feld"
                        password: null        // Passwort-Hash nicht mitsenden!
                    };
                }
                // Sonst alles zeigen
                return p;
            });

            socket.emit('blog_list_res', sanitized);

        } catch (e) {
            console.error("Error fetching blog list:", e);
            socket.emit('system_message', 'DATABASE ERROR.');
        }
    });

    // 1b. GESCHÜTZTEN INHALT ANFORDERN
// 1b. GESCHÜTZTEN INHALT ENTSPERREN
    socket.on('blog_unlock_req', async (data) => {
        // data = { id, password }
        const post = await db.getBlogPostById(data.id);

        if (!post) return socket.emit('system_message', 'ERROR: Post not found.');

        // Passwort Vergleich (Hier Klartext, für höhere Sicherheit später Hash nutzen)
        if (post.password === data.password) {
            // Erfolg: Sende den VOLLEN Post an diesen User
            socket.emit('blog_unlock_success', post);
        } else {
            socket.emit('system_message', 'ACCESS DENIED: Incorrect password.');
        }
    });

// --- BLOG SYSTEM (ADVANCED) ---

    // 1. POST ERSTELLEN ODER EDITIEREN (Kugelsichere Version)
    socket.on('blog_post_req', async (data) => {
        const user = users[socket.id];

        console.log(`[BLOG] Incoming Request from ${user ? user.username : 'Unknown'}`); // DEBUG LOG

        // --- A) IDENTITÄT & RECHTE PRÜFEN ---
        let authorTag = 'UNKNOWN';
        let authorName = 'Anonymous';
        let isEditMode = !!data.id;

        if (user && user.isAdmin) {
            // ADMINS bekommen harte Werte
            authorTag = 'ADMIN';
            authorName = 'SYSTEM ADMINISTRATOR';
        }
        else if (user && user.institution) {
            // INSTITUTIONEN
            authorTag = user.institution.tag;
            // Fallback: Wenn Name fehlt, nimm den Tag
            authorName = user.institution.name || user.institution.tag || 'Unknown Agency';
        }
        else {
            console.log('[BLOG] Access Denied: No Admin/Institution credentials.');
            return socket.emit('system_message', 'ACCESS DENIED: Insufficient permissions.');
        }

        // --- B) VALIDIERUNG ---
        if (!data.title || !data.content) {
            socket.emit('system_message', 'ERROR: Title and Content required.');
            return;
        }

        const cleanTitle = escapeHtml(data.title);
        const cleanContent = escapeHtml(data.content);

        let cleanTags = [];
        if (Array.isArray(data.tags)) {
            cleanTags = data.tags.map(t => escapeHtml(t));
        }

        // --- C) DATEI VERARBEITUNG (Safe Check) ---
        let attachmentData = null;

        if (data.file && data.file.buffer) {
            try {
                // Check ob UPLOAD_DIR existiert, sonst Fehler vermeiden
                if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

                const originalName = data.file.name || 'file';
                const cleanName = originalName.replace(/[^a-zA-Z0-9._-]/g, '_');

                const MAX_SIZE = 10 * 1024 * 1024;
                if (data.file.size > MAX_SIZE) {
                    socket.emit('system_message', 'ERROR: File too large (Max 10MB).');
                    return;
                }

                const uniquePrefix = Date.now();
                const safeFilename = `${uniquePrefix}_${cleanName}`;
                const filePath = path.join(UPLOAD_DIR, safeFilename);
                fs.writeFileSync(filePath, data.file.buffer);

                attachmentData = {
                    originalName: cleanName,
                    filename: safeFilename,
                    path: '/uploads/' + safeFilename,
                    size: data.file.size
                };
            } catch (err) {
                console.error("Upload Error:", err);
                return socket.emit('system_message', 'ERROR: Upload protocol failed.');
            }
        } else if (data.existingAttachment) {
            attachmentData = data.existingAttachment;
        }

        try {
            // --- D) DATENBANK OPERATION ---

            if (isEditMode) {
                // UPDATE
                const oldPost = await db.getBlogPostById(data.id);
                if (!oldPost) return socket.emit('system_message', 'ERROR: Post not found in DB.');

                // Rechte Check
                let allowed = false;
                if (user.isAdmin) allowed = true;
                if (user.institution && user.institution.tag === oldPost.author_tag) allowed = true;

                if (!allowed) return socket.emit('system_message', 'ACCESS DENIED: Not your post.');

                await db.updateBlogPost(data.id, {
                    title: cleanTitle,
                    content: cleanContent,
                    tags: cleanTags,
                    attachment: attachmentData,
                    important: !!data.broadcast,
                    password: data.password // <--- HINZUFÜGEN
                });

                socket.emit('blog_action_success', 'Log entry updated.');

            } else {
                // CREATE
                // Hier prüfen wir nochmal, ob alles da ist
                console.log(`[BLOG] Creating Post: ${cleanTitle} by ${authorName} (${authorTag})`);

                await db.createBlogPost({
                    title: cleanTitle,
                    content: cleanContent,
                    authorTag: authorTag,
                    authorName: authorName,
                    tags: cleanTags,
                    attachment: attachmentData,
                    important: !!data.broadcast,
                    password: data.password // <--- HINZUFÜGEN
                });

                socket.emit('blog_action_success', 'Log entry committed.');
                if (data.broadcast) io.emit('system_message', `⚠️ NEW SYSTEM LOG: ${cleanTitle}`);
            }

            // Update an alle
            const logs = await db.getBlogPosts();
            io.emit('update_system_logs', logs);

        } catch (e) {
            console.error("[BLOG] DATABASE ERROR:", e);
            socket.emit('system_message', 'DATABASE ERROR: Check server logs.');
        }
    });


    // 2. POST LÖSCHEN (Mit File Cleanup & Permission Check)
    socket.on('blog_delete_req', async (id) => {
        const user = users[socket.id];
        const post = await db.getBlogPostById(id);

        if (!post) {
            return socket.emit('system_message', 'ERROR: Entry not found.');
        }

        // --- RECHTE CHECK ---
        let allowed = false;
        // Admin darf alles
        if (user && user.isAdmin) allowed = true;
        // Institution darf nur eigene
        if (user && user.institution && user.institution.tag === post.author_tag) allowed = true;

        if (!allowed) {
            return socket.emit('system_message', 'ACCESS DENIED: You can only delete your own logs.');
        }

        // --- DATEI LÖSCHEN (Clean up) ---
        if (post.attachment && post.attachment.filename) {
            try {
                const filePath = path.join(UPLOAD_DIR, post.attachment.filename);
                if (fs.existsSync(filePath)) {
                    fs.unlinkSync(filePath); // Löscht Datei von der Festplatte
                }
            } catch (e) {
                console.error("File deletion error:", e);
            }
        }

        // --- DB LÖSCHEN ---
        await db.deleteBlogPost(id);

        socket.emit('blog_action_success', 'Entry purged.');
        const logs = await db.getBlogPosts();
        io.emit('update_system_logs', logs);
    });


});

const PORT = process.env.PORT || 3000;
// --- SERVER START & DB INIT ---
(async () => {
    // 1. Datenbank starten
    await db.initDB();

    // 2. Standard-Accounts erstellen (nur wenn sie fehlen)
    // MI6
    const mi6 = await db.getInstitutionByTag('MI6');
    if (!mi6) {
        console.log('[SETUP] Generating default MI6 access...');
        // Tag, Name, Passwort, 2FA-Secret, Farbe
        await db.createInstitution('MI6', 'Secret Intelligence Service', '007', 'KVUGK3LSMFZEQUDL', '#00ff00');
    }

    // CIA
    const cia = await db.getInstitutionByTag('CIA');
    if (!cia) {
        console.log('[SETUP] Generating default CIA access...');
        await db.createInstitution('CIA', 'Central Intelligence Agency', 'langley', 'KRUW4ZLOMVZUKZLJMVZUKZLJ', '#0088ff');
    }

    // 3. Server lauschen lassen
    server.listen(PORT, '0.0.0.0', () => {
        console.log(`\n----------------------------------------`);
        console.log(`SECURE SERVER ONLINE ON PORT ${PORT}`);
        console.log(`DATABASE SYSTEM: ONLINE (SQLite)`);

        // IP Anzeige (Dein bestehender Code hier...)
        const net = require('os').networkInterfaces();
        for (const iface of Object.values(net)) {
            for (const alias of iface) {
                if (alias.family === 'IPv4' && !alias.internal) {
                    console.log(`LOCAL ACCESS: http://${alias.address}:${PORT}`);
                }
            }
        }
        console.log(`----------------------------------------\n`);
    });
})();

// --- HELPER: PUBLIC ROOMS NEU ORGANISIEREN ---
function reorganizePublicRooms() {
    // 1. MÜLLABFUHR: Nur Räume mit Mitgliedern behalten
    const sortedRooms = Object.values(publicRooms)
        .filter(r => r && r.members && r.members.length > 0)
        .sort((a, b) => (a.createdAt || 0) - (b.createdAt || 0)); // Fallback für createdAt

    const newPublicRooms = {};
    let counter = 1;

    sortedRooms.forEach(room => {
        const oldId = room.id;
        const newId = String(counter).padStart(4, '0');
        counter++;

        // Namen korrigieren (PENDING oder alte ID im Namen)
        if (room.name.includes('PENDING') || room.name === `Sector_${oldId}`) {
            room.name = `Sector_${newId}`;
        }

        // Wenn sich die ID ändert
        if (oldId !== newId) {
            serverLog(`Renumbering Sector: ${oldId} -> ${newId}`);
            room.id = newId;

            // User & Sockets updaten
            room.members.forEach(memberId => {
                const u = users[memberId];
                if (u) u.currentPub = newId;

                const s = io.sockets.sockets.get(memberId);
                if (s) {
                    s.leave(`pub_${oldId}`);
                    s.join(`pub_${newId}`);

                    s.emit('pub_id_changed', {
                        oldId: oldId,
                        newId: newId,
                        newName: room.name
                    });
                }
            });

            // Info an den Raum
            io.to(`pub_${newId}`).emit('system_message', `SYSTEM NOTICE: Sector ID changed to #${newId} due to network reorganization.`);
        }

        // In neue Liste speichern
        newPublicRooms[newId] = room;
    });

    // Globale Liste überschreiben
    publicRooms = newPublicRooms;
}

function generatePromoList() {
    return Object.values(privateGroups)
        .filter(g => g.isPublic && g.description)
        .map(g => ({
            id: g.id,
            name: g.name,
            desc: g.description,
            count: g.members.length,
            date: g.promotedAt
        }));
}

// Hilfsfunktion: Sagt allen relevanten Usern, dass dieser User jetzt eine Institution ist
function broadcastInstitutionUpdate(userId) {
    const user = users[userId];
    if (!user || !user.institution) return;

    const updatePacket = {
        key: user.key,
        username: user.username,
        tag: user.institution.tag,
        color: user.institution.color
    };

    // 1. An alle Private Partners
    user.partners.forEach(pid => {
        io.to(pid).emit('user_institution_update', updatePacket);
    });

    // 2. An aktuelle Gruppe
    if (user.currentGroup) {
        // FEHLER BEHOBEN: Hier stand vorher 'socket.to', muss aber 'io.to' sein
        io.to(`group_${user.currentGroup}`).emit('user_institution_update', updatePacket);
    }

    // 3. An Public Room
    if (user.currentPub) {
        // FEHLER BEHOBEN: Hier stand vorher 'socket.to', muss aber 'io.to' sein
        io.to(`pub_${user.currentPub}`).emit('user_institution_update', updatePacket);
    }
}