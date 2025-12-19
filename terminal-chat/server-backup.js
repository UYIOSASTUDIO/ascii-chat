require('dotenv').config();

const express = require('express');
const http = require('http');
const { Server } = require("socket.io");
const path = require('path');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const crypto = require('crypto');
const webpush = require('web-push');

const publicVapidKey = process.env.VAPID_PUBLIC_KEY;
const privateVapidKey = process.env.VAPID_PRIVATE_KEY;

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

const app = express();

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

// --- ADMIN COMMAND: GLOBAL BROADCAST ---
    socket.on('admin_broadcast', (msg) => {
        // ZUERST PRÜFEN: Ist der User Admin?
        if (!users[socket.id].isAdmin) {
            // Wenn NEIN: Fehlermeldung zurücksenden und abbrechen
            socket.emit('system_message', 'ERROR: ACCESS DENIED. Insufficient security clearance.');
            return;
        }

        // Wenn JA: Nachricht an alle senden
        io.emit('system_message', `[GLOBAL ADMIN MESSAGE]: ${msg}`);
        serverLog(`ADMIN BROADCAST sent by ${users[socket.id].username}`);
    });

    // 1. REGISTRIERUNG
    socket.on('register', (username) => {

        // --- NEU: VALIDIERUNG ---
        // Wenn der Name ungültig ist, brechen wir sofort ab
        if (!username || username.startsWith('/') || username.trim().length === 0 || username.length > 20) {
            socket.emit('system_message', 'REGISTRATION ERROR: Invalid username format.');
            return; // WICHTIG: Hier aufhören, nicht speichern!
        }
        // ------------------------

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

    // 5. VERBINDUNGSANFRAGE (Ghost Aware)
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

        const targetId = Object.keys(users).find(id => users[id].key === data.targetKey);

        if (targetId && targetId !== socket.id) {

            // --- GHOST LOGIK: Name maskieren ---
            const displayRequesterName = requester.isGhost ? 'Anonymous' : requester.username;

            io.to(targetId).emit('incoming_request', {
                requesterId: socket.id,
                requesterName: displayRequesterName, // <--- Maskierter Name
                requesterKey: requester.key,         // Echter Key (wichtig für /accept)
                publicKey: data.publicKey
            });

            // Push auch anpassen
            const targetUser = users[targetId];
            sendPush(targetUser, 'INCOMING CONNECTION', `Node ${displayRequesterName} requests secure handshake.`);

            socket.emit('system_message', `SECURE HANDSHAKE: Request sent to ${users[targetId].username}...`);
        } else {
            socket.emit('system_message', `FEHLER: Key '${data.targetKey}' nicht gefunden.`);
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

    // PUB CREATE (Auto-Join integriert)
    socket.on('pub_create', (name) => {
        const user = users[socket.id];
        if (!user) return;

        // ID generieren (z.B. Hex Code)
        const pubId = crypto.randomBytes(2).toString('hex').toUpperCase();

        // Key generieren (AES-256 für alle in diesem Raum)
        const roomKey = crypto.randomBytes(32).toString('hex');

        publicRooms[pubId] = {
            id: pubId,
            name: name || `Sector_${pubId}`,
            members: [], // Wir fügen den Creator gleich hinzu
            key: roomKey
        };

        // --- AUTO-JOIN LOGIK ---
        socket.join(`pub_${pubId}`);
        publicRooms[pubId].members.push(socket.id);
        user.currentPub = pubId; // WICHTIG: Speichern wo der User ist

        serverLog(`Public Sector ${pubId} erstellt von ${user.username}.`);

        // Erfolg an Creator senden
        socket.emit('pub_joined_success', {
            id: pubId,
            key: roomKey
        });

        // Allen sagen, dass ein neuer Raum da ist (für /pub list)
        io.emit('system_message', `NEW SIGNAL DETECTED: Sector ${pubId} is now online.`);
    });

    // PUB LEAVE (Ohne Reload, mit Löschung wenn leer)
    socket.on('pub_leave', () => {
        const user = users[socket.id];
        if (!user || !user.currentPub) return;

        const pubId = user.currentPub;
        const room = publicRooms[pubId];

        if (room) {
            // 1. User entfernen
            socket.leave(`pub_${pubId}`);
            room.members = room.members.filter(id => id !== socket.id);
            user.currentPub = null;

            // Statt Text senden wir ein Event mit Key
            io.to(`pub_${pubId}`).emit('room_user_status', {
                username: user.username,
                key: user.key,
                type: 'leave',
                context: 'pub',
                roomId: pubId
            });

            // 2. CHECK: IST DER RAUM LEER?
            if (room.members.length === 0) {
                delete publicRooms[pubId];
                serverLog(`Public Sector ${pubId} collapsed (No users left).`);
                // Optional: Allen sagen, dass der Raum weg ist
                // io.emit('system_message', `SIGNAL LOST: Sector ${pubId} went dark.`);
            }
        }

        // 3. Bestätigung an Client senden (damit UI resettet wird)
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

        // --- HIER HABEN WIR DEN CODE GELÖSCHT, DER PRIVATE CHATS TRENNT ---
        // (Der alte if (user.partners...) Block ist weg)

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

        // Statt Text senden wir ein Event mit Key
        socket.to(`pub_${roomId}`).emit('room_user_status', {
            username: user.username,
            key: user.key,
            isGhost: !!user.isGhost,
            type: 'join',
            context: 'pub',
            roomId: roomId
        });
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

    // 1. GRUPPE ERSTELLEN (/group create [optional: UserIDs])
    socket.on('group_create', (invitedUserKeys) => {
        const creator = users[socket.id];
        if (!creator) return;

        // ID und Schlüssel generieren
        const groupId = Math.floor(Math.random() * 9000) + 1000; // 4-stellige ID
        const groupKey = crypto.randomBytes(32).toString('hex');

        privateGroups[groupId] = {
            id: groupId,
            name: `Group_${groupId}`, // <--- NEU: Standard-Name setzen!
            ownerId: socket.id,
            members: [socket.id],
            mods: [],
            key: groupKey,
            pendingJoins: [],
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

    // 3. INVITE (/group invite ID [ID] ...)
    socket.on('group_invite_req', (targetKeysInput) => {
        // SICHERHEITS-CHECK: Existiert der User?
        const user = users[socket.id];
        if (!user || !user.currentGroup) {
            socket.emit('system_message', 'ERROR: You are not in a group.');
            return;
        }

        const group = privateGroups[user.currentGroup];
        if (!group) return;

        // Rechte prüfen (Owner oder Mod)
        const isOwner = group.ownerId === socket.id;
        const isMod = group.mods.includes(socket.id);

        if (!isOwner && !isMod) {
            socket.emit('system_message', 'ERROR: Only Owners and Mods can invite.');
            return;
        }

        // Sicherstellen, dass es ein Array ist (falls ein alter Client nur einen String schickt)
        const keysToProcess = Array.isArray(targetKeysInput) ? targetKeysInput : [targetKeysInput];

        // Zusammenfassung für den Sender
        let sentCount = 0;

        // LOOP DURCH ALLE KEYS
        keysToProcess.forEach(targetKey => {
            // Ignoriere leere Strings
            if(!targetKey || targetKey.trim() === "") return;

            const targetUser = Object.values(users).find(u => u.key === targetKey);

            if (targetUser) {
                // Prüfen ob schon drin
                if (group.members.includes(targetUser.id)) {
                    socket.emit('system_message', `INFO: User ${targetUser.username} is already in the group.`);
                } else {
                    // Einladung senden
                    io.to(targetUser.id).emit('group_invite_received', {
                        groupId: group.id,
                        inviter: user.username
                    });

                    // --- NEU: PUSH SENDEN ---
                    sendPush(targetUser, 'GROUP INVITATION', `User ${user.username} invited you to Group ${group.id}.`);
                    // ------------------------

                    sentCount++;
                }
            } else {
                socket.emit('system_message', `WARNING: User with key '${targetKey}' not found.`);
            }
        });

        if (sentCount > 0) {
            socket.emit('system_message', `SUCCESS: ${sentCount} invitation(s) sent.`);
        }
    });

    // 4. INVITE / JOIN ANNEHMEN (Entscheidung - Ghost Fix Final)
    socket.on('group_decision', (data) => {
        const user = users[socket.id];

        // FALL A: User nimmt Einladung an (Hier ändert sich nichts)
        if (data.groupId) {
            const group = privateGroups[data.groupId];
            if (!group) return;

            if (data.accept) {
                socket.join(`group_${group.id}`);
                group.members.push(socket.id);
                user.currentGroup = group.id;

                // Event senden
                io.to(`group_${group.id}`).emit('room_user_status', {
                    username: user.username,
                    key: user.key,
                    isGhost: !!user.isGhost, // Force Boolean
                    type: 'join',
                    context: 'group',
                    roomId: group.id
                });

                // Bestätigung für den User selbst
                socket.emit('group_joined_success', {
                    id: group.id,
                    name: group.name,
                    key: group.key,
                    role: 'MEMBER'
                });
            } else {
                socket.emit('system_message', 'Invitation declined.');
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

    // 5. MOD SYSTEM (/mod ID) -> Nur Owner
    socket.on('group_promote', (targetKey) => {
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
    // 6. KICK (/group kick ID)
    // 6. KICK (/group kick ID) - ADMIN UPDATE
    socket.on('group_kick', (targetKey) => {
        const user = users[socket.id];
        if (!user || !user.currentGroup) return;

        const group = privateGroups[user.currentGroup];
        if (!group) return;

        const isOwner = group.ownerId === socket.id;
        const isMod = group.mods.includes(socket.id);
        const isAdmin = user.isAdmin; // <--- NEU

        // Admin darf alles, sonst nur Owner/Mod
        if (!isOwner && !isMod && !isAdmin) {
            socket.emit('system_message', 'ERROR: Insufficient permissions.');
            return;
        }

        const targetUser = Object.values(users).find(u => u.key === targetKey);
        if (!targetUser || !group.members.includes(targetUser.id)) {
            socket.emit('system_message', 'ERROR: User not found in group.');
            return;
        }

        // Schutz: Nur ein Admin darf den Owner kicken!
        if (targetUser.id === group.ownerId && !isAdmin) {
            socket.emit('system_message', 'ERROR: Treason! You cannot kick the Owner.');
            return;
        }

        // SPEZIALFALL: OWNER SOLL GEKICKT WERDEN
        if (targetUser.id === group.ownerId) {
            if (!isAdmin) {
                socket.emit('system_message', 'ERROR: Treason! You cannot kick the Owner.');
                return;
            }

            // Wenn Admin den Owner kickt -> Frontend nach Nachfolger fragen!
            // Wir brechen hier ab und warten auf die Entscheidung
            socket.emit('admin_kick_owner_dialog', {
                oldOwnerKey: targetKey,
                oldOwnerName: targetUser.username
            });
            return;
        }

        // Rauswurf
        const targetSocket = io.sockets.sockets.get(targetUser.id);
        if (targetSocket) {
            targetSocket.leave(`group_${group.id}`);
            // Spezielle Nachricht, falls es ein Admin war
            const kickerTitle = isAdmin ? "GLOBAL ADMINISTRATOR" : "Group Moderator";
            targetSocket.emit('system_message', `YOU HAVE BEEN KICKED FROM GROUP ${group.id} BY ${kickerTitle}.`);
            targetSocket.emit('group_kicked');
        }

        group.members = group.members.filter(id => id !== targetUser.id);
        group.mods = group.mods.filter(id => id !== targetUser.id);
        targetUser.currentGroup = null;

        io.to(`group_${group.id}`).emit('system_message', `User ${targetUser.username} was kicked.`);

        // Promo Board update (Member Count)
        io.emit('promo_update', generatePromoList());
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

// 7. BROADCAST (/group broadcast MSG)
    socket.on('group_broadcast', (msg) => {
        // SICHERHEITS-CHECK
        const user = users[socket.id];
        if (!user || !user.currentGroup) return;

        const group = privateGroups[user.currentGroup];
        if (!group) return;

        const isOwner = group.ownerId === socket.id;
        const isMod = group.mods.includes(socket.id);

        if (isOwner || isMod) {
            io.to(`group_${group.id}`).emit('system_message', `[GROUP BROADCAST]: ${msg}`);
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

    // 11. GROUP RENAME (/group name [NAME]) -> Nur Owner
    // 11. GROUP RENAME (/group name [NAME]) - ADMIN UPDATE
    socket.on('group_rename', (newName) => {
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

        // Validierung
        if (!newName || newName.trim().length === 0) {
            socket.emit('system_message', 'ERROR: Name cannot be empty.');
            return;
        }
        if (newName.length > 20) {
            socket.emit('system_message', 'ERROR: Name too long (max 20 chars).');
            return;
        }

        // Name speichern
        const oldName = group.name;
        group.name = newName;

        serverLog(`Gruppe ${group.id} von ${user.username} (Admin: ${user.isAdmin}) umbenannt.`);

        // Nachricht an die Gruppe (mit Hinweis, falls es "von oben" kam)
        const suffix = user.isAdmin && group.ownerId !== socket.id ? " by Authority" : "";
        io.to(`group_${group.id}`).emit('system_message', `NETWORK UPDATE: Group renamed to '${newName}'${suffix}.`);

        // Event für Prompt-Update bei den Clients
        io.to(`group_${group.id}`).emit('group_name_changed', { id: group.id, newName: newName });

        // WICHTIG: Das Promo-Board oben rechts aktualisieren (falls die Gruppe public ist)
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

    // Hilfsfunktion: Liste generieren (nur Public Groups mit Description)
    function generatePromoList() {
        return Object.values(privateGroups)
            .filter(g => g.isPublic && g.description) // Nur öffentliche mit Beschreibung
            .map(g => ({
                id: g.id,
                name: g.name,
                desc: g.description,
                count: g.members.length,
                date: g.promotedAt
            }));
    }

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

    // 1. P2P SIGNAL (Für Audio & Dateien)
    socket.on('p2p_signal', (data) => {
        // data: { targetKey, type, payload, ... }
        const user = users[socket.id];
        if (!user || !data.targetKey) return;

        const targetUser = Object.values(users).find(u => u.key === data.targetKey);

        // Sicherheits-Check: Sind wir verbunden?
        if (targetUser && user.partners.includes(targetUser.id)) {
            io.to(targetUser.id).emit('p2p_signal', {
                senderKey: user.key, // Damit der Empfänger weiß, von wem das Signal kommt
                type: data.type,
                payload: data.payload,
                metadata: data.metadata
            });
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
                                type: 'approved', // Wir nutzen 'approved' als Synonym für "Hat die Macht"
                                context: 'group',
                                roomId: group.id
                            });

                            io.to(`group_${group.id}`).emit('system_message', `CRITICAL: Owner signal lost. Authority transferred automatically.`);
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
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`🚀 SYSTEM ONLINE: Server running on port ${PORT}`);
});