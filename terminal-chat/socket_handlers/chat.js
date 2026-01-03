
// socket_handlers/chat.js
const crypto = require('crypto');
const { sanitize } = require('../utils/sanitizer');
const { serverLog, serverError } = require('../utils/logger');
const { reorganizePublicRooms, generatePromoList } = require('../utils/room_manager');
const webpush = require('web-push');
const state = require("../state");
const db = require('../database');

// Hilfsfunktion für Push (lokal)
function sendPush(targetUser, title, content) {
    if (targetUser && targetUser.pushSubscription) {
        const payload = JSON.stringify({
            title: title,
            body: content,
            icon: 'https://cdn-icons-png.flaticon.com/512/2069/2069503.png'
        });
        webpush.sendNotification(targetUser.pushSubscription, payload).catch(err => {});
    }
}

// Helper: Sagt der Gruppe Bescheid, wenn jemand joint/leaved
function broadcastRoomStatus(io, roomId, type, user, context, isGhost) {
    const roomName = context === 'pub' ? `pub_${roomId}` : `group_${roomId}`;
    io.to(roomName).emit('room_user_status', {
        username: user.username,
        key: user.key,
        isGhost: isGhost,
        type: type, // 'join', 'leave', 'approved'
        context: context,
        roomId: roomId
    });
}

module.exports = (io, socket, state) => {

    // =================================================================
    // 1. User and Network (basis)
    // =================================================================

    socket.on('info_request', (query) => {
        const requester = state.users[socket.id];
        if (!requester) return;

        const searchTerm = query.toLowerCase();
        const allUsers = Object.values(state.users);

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
                bio: targetUser.bio || 'No bio available.', // <--- NEU
                status: targetUser.partnerId ? 'ESTABLISHED CONNECTION' : 'IDLE / LISTENING'
            };

            socket.emit('info_result', infoData);
        } else {
            socket.emit('system_message', `TARGET_NOT_FOUND: Could not locate entity '${query}'.`);
        }
    });

    // 3. GHOST MODE TOGGLE (Mit Broadcast)
    socket.on('toggle_ghost', () => {
        const user = state.users[socket.id];
        if (user) {
            user.isGhost = !user.isGhost;

            // Bestätigung an sich selbst (Text)
            socket.emit('system_message', `STEALTH MODE: ${user.isGhost ? 'ENABLED (Invisible)' : 'DISABLED (Visible)'}`);

            // Das Update-Paket
            const updateData = {
                key: user.key,
                username: user.username,
                isGhost: user.isGhost
            };

            // --- DER FIX: Update auch an MICH SELBST senden! ---
            // Damit mein Client (Client.js) weiß, dass window.isGhostActive jetzt true/false ist
            socket.emit('user_ghost_update', updateData);
            // ---------------------------------------------------

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
        const allUsers = Object.values(state.users);
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

    // --- PROFILE DETAILS FETCH (Secure Context Menu) ---
    socket.on('get_profile_details', (reqData) => {
        // reqData: { targetKey, contextId }
        const requester = state.users[socket.id];
        if (!requester) return;

        const targetUser = Object.values(state.users).find(u => u.key === reqData.targetKey);

        // Default Response (Fallback / Not Found)
        let response = {
            username: "Unknown",
            bio: "Signal lost.",
            isGhost: false,
            isPrivilegedView: false
        };

        if (targetUser) {
            // Basis Daten
            let displayBio = targetUser.bio || "No status set.";
            let displayName = targetUser.username;
            let isPrivileged = false;

            // --- RECHTE CHECK ---

            // 1. Bin ich Global Admin?
            if (requester.isAdmin) {
                isPrivileged = true;
            }

                // 2. Bin ich Owner/Mod der aktuellen Gruppe?
            // Wir prüfen 'contextId', das vom Client kommt (activeChatId)
            else if (reqData.contextId && reqData.contextId !== 'LOCAL') {
                const group = state.privateGroups[reqData.contextId];

                // Wir müssen prüfen, ob BEIDE (Requester und Target) in dieser Gruppe sind.
                // Ein Mod kann keine Userdaten abfragen, wenn der User gar nicht in seiner Gruppe ist.
                if (group && group.members.includes(requester.id) && group.members.includes(targetUser.id)) {

                    const isOwner = group.ownerId === requester.id;
                    const isMod = group.mods.includes(requester.id);

                    if (isOwner || isMod) {
                        isPrivileged = true;
                    }
                }
            }

            // --- DATEN ZUSAMMENSTELLEN ---

            // FALL A: GHOST MODE AKTIV?
            if (targetUser.isGhost) {
                if (isPrivileged) {
                    // Chef darf alles sehen
                    response = {
                        username: `[GHOST] ${targetUser.username}`, // Zeige den echten Namen
                        bio: displayBio,
                        isGhost: true,
                        isPrivilegedView: true,
                        realName: targetUser.username,
                        joinTime: targetUser.loginTime, // Oder wann er in die Gruppe kam (haben wir aktuell nicht gespeichert, also LoginTime)
                        ip: targetUser.ip // Nur für Admin
                    };
                } else {
                    // Normaler User sieht nur Maske
                    response = {
                        username: "Anonymous",
                        bio: "[ENCRYPTED DATA]", // Bio verstecken bei Ghost? Meistens ja.
                        isGhost: true,
                        isPrivilegedView: false
                    };
                }
            }
            // FALL B: KEIN GHOST (Normaler User)
            else {
                response = {
                    username: targetUser.username,
                    bio: displayBio,
                    isGhost: false,
                    isPrivilegedView: isPrivileged, // Auch hier dürfen Admins mehr sehen (IP etc)
                    realName: targetUser.username,
                    joinTime: targetUser.loginTime,
                    ip: targetUser.ip
                };
            }
        }

        socket.emit('profile_details_result', response);
    });

    // 18. PUSH SUBSCRIPTION SPEICHERN
    socket.on('save_subscription', (sub) => {
        const user = state.users[socket.id];
        if (user) {
            // Wir speichern die Adresse nur im RAM beim User
            user.pushSubscription = sub;
            // Optional: serverLog(`Push Sub registriert für ${user.username}`);
        }
    });

    // 19. PUSH "NUDGE" (Jemanden anstupsen)
    socket.on('send_nudge', (targetKey) => {
        const sender = state.users[socket.id];
        if (!sender) return;

        // Ziel suchen
        const targetUser = Object.values(state.users).find(u => u.key === targetKey);

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

    // =================================================================
    // 2. Private Chat (P2P)
    // =================================================================

    // 5. VERBINDUNGSANFRAGE (Ghost Aware & VIP Privacy Shield)
    socket.on('request_connection', (data) => {
        // Spam Schutz
        const now = Date.now();
        const lastRequestTime = state.connectionRateLimit[socket.id] || 0;
        const cooldown = 3000;

        if (now - lastRequestTime < cooldown) {
            const waitTime = Math.ceil((cooldown - (now - lastRequestTime)) / 1000);
            socket.emit('system_message', `SPAM PROTECTION: Please wait ${waitTime}s.`);
            return;
        }
        state.connectionRateLimit[socket.id] = now;

        const requester = state.users[socket.id];
        if (!requester) return;

        // --- ZIEL ERMITTELN ---
        let targetId = null;

        // 1. Ist 'data.targetKey' direkt eine Socket-ID?
        if (state.users[data.targetKey]) {
            targetId = data.targetKey;
        }
        // 2. Fallback: Suche nach Key ODER Handle (@name)
        else {
            targetId = Object.keys(state.users).find(id => state.users[id].key === data.targetKey);
        }

        if (targetId && targetId !== socket.id) {
            const targetUser = state.users[targetId];

            // --- VIP PRIVACY SHIELD (DER NEUE CODE) ---
            if (targetUser && targetUser.isVIP) {
                // Ausnahme: Wenn ICH (Sender) auch ein VIP bin, darf ich durch
                const amIVip = requester.isVIP;

                if (targetUser.vipPrivacy === 'SILENT' && !amIVip) {
                    socket.emit('system_message', 'ERROR: UPLINK REFUSED. TARGET IS IN SILENT MODE.');
                    return; // STOPP! Hier wird abgebrochen.
                }
            }
            // ------------------------------------------

            // --- GHOST LOGIK ---
            const displayRequesterName = requester.isGhost ? 'Anonymous' : requester.username;

            // SENDEN (NUR EINMAL!)
            io.to(targetId).emit('incoming_request', {
                requesterId: socket.id,
                requesterName: displayRequesterName,
                requesterKey: requester.key,
                publicKey: data.publicKey
            });

            // Push Notification
            sendPush(targetUser, 'INCOMING CONNECTION', `Node ${displayRequesterName} requests secure handshake.`);

            socket.emit('system_message', `SECURE HANDSHAKE: Request sent to ${targetUser.username}...`);
        } else {
            socket.emit('system_message', `ERROR: Target '${data.targetKey}' not found or offline.`);
        }
    });

    // 6. VERBINDUNGSANTWORT (Ghost Aware)
    socket.on('respond_connection', (data) => {
        const responder = state.users[socket.id];
        const requester = state.users[data.requesterId];

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
        const user = state.users[socket.id];
        if (!user) return;

        // Wir suchen den Partner mit diesem Key
        const targetPartner = Object.values(state.users).find(u => u.key === targetKey);

        if (targetPartner && user.partners.includes(targetPartner.id)) {
            // Dem Partner das Signal senden
            io.to(targetPartner.id).emit('private_leave_received', {
                name: user.username,
                key: user.key
            });

            // Verbindung auflösen (bei beiden aus der Liste nehmen)
            user.partners = user.partners.filter(id => id !== targetPartner.id);
            if (state.users[targetPartner.id]) {
                state.users[targetPartner.id].partners = state.users[targetPartner.id].partners.filter(id => id !== socket.id);
            }
        }

        socket.emit('private_leave_confirm');
    });

// 7. NACHRICHTEN TRANSFER (DIAGNOSE MODUS)
    socket.on('message', (data) => {
        // Log 1: Kommt überhaupt was an?
        console.log("--- DEBUG MESSAGE START ---");
        console.log("1. Nachricht erhalten von:", state.users[socket.id]?.username);
        console.log("2. Daten Paket:", data);

        // Checks
        if (!data || !data.targetKey || !data.payload) {
            console.log("FEHLER: Ungültiges Datenformat. 'targetKey' oder 'payload' fehlt!");
            return;
        }

        const user = state.users[socket.id];
        if (!user) {
            console.log("FEHLER: Sender nicht in User-Datenbank gefunden.");
            return;
        }

        // Ziel suchen
        const targetUser = Object.values(state.users).find(u => u.key === data.targetKey);

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

    // --- SECURITY: RE-KEYING SIGNAL (Rotation) ---
    socket.on('rekey_signal', (data) => {
        // data: { targetKey, type: 'request'|'response', publicKey, ... }
        const user = state.users[socket.id];
        if (!user) return;

        const targetUser = Object.values(state.users).find(u => u.key === data.targetKey);

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

    // 22. ROOM WHISPER SYSTEM (/whisper ID MSG)
    socket.on('room_whisper_req', (data) => {
        // data: { targetKey, message }
        const user = state.users[socket.id];
        if (!user) return;

        // 1. Kontext bestimmen (Wo befinden wir uns?)
        let roomId = null;
        let context = null; // 'group' oder 'pub'
        let memberList = [];

        if (user.currentGroup) {
            roomId = user.currentGroup;
            context = 'group';
            const grp = state.privateGroups[roomId];
            if (grp) memberList = grp.members;
        }
        else if (user.currentPub) {
            roomId = user.currentPub;
            context = 'pub';
            const pub = state.publicRooms[roomId];
            if (pub) memberList = pub.members;
        }

        if (!roomId || !context) {
            socket.emit('system_message', 'ERROR: You must be in a Group or Public Sector to whisper.');
            return;
        }

        // 2. Ziel finden
        const targetUser = Object.values(state.users).find(u => u.key === data.targetKey);

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

    // =================================================================
    // 3. Public Rooms (Sectors)
    // =================================================================

    // --- PUBLIC CHAT SYSTEM ---

    // 1. LISTE ABRUFEN (Scanner)
    socket.on('pub_list_request', () => {
        const rooms = Object.values(state.publicRooms).map(r => ({
            id: r.id,
            name: r.name,
            count: r.members.length
        }));
        socket.emit('pub_list_result', rooms);
    });

    // --- PUBLIC CHAT SYSTEM ---

// PUB CREATE (Sequential IDs & Limit)
    socket.on('pub_create', (nameInput) => { // <--- WICHTIG: Hier "nameInput" nennen!
        const user = state.users[socket.id];
        if (!user) return;

        // XSS Schutz für Raum-Namen
        // Jetzt existiert nameInput, weil wir es oben so genannt haben
        const cleanName = sanitize(nameInput, 30);

        // Temp ID für den Moment
        const tempId = "TEMP_" + Date.now();
        const roomKey = crypto.randomBytes(32).toString('hex');

        state.publicRooms[tempId] = {
            id: tempId,
            // Hier nutzen wir jetzt cleanName (die gesäuberte Version)
            name: cleanName || `Sector_PENDING`,
            members: [],
            key: roomKey,
            createdAt: Date.now()
        };

        // User hinzufügen
        state.publicRooms[tempId].members.push(socket.id);

        // Aufräumen und Nummern vergeben
        reorganizePublicRooms(io, state);

        // Neuen Raum finden (wo unser User jetzt drin ist)
        const newRoom = Object.values(state.publicRooms).find(r => r.members.includes(socket.id));

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
        const user = state.users[socket.id];
        if (!user || !user.currentPub) return;

        const pubId = user.currentPub;
        const room = state.publicRooms[pubId];

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
                delete state.publicRooms[pubId];
                serverLog(`Public Sector ${pubId} collapsed (Empty).`);
            }

            // 5. IMMER reorganisieren (schließt Lücken und bereinigt)
            reorganizePublicRooms(io, state);
        } else {
            // Falls Raum-Daten korrupt waren, User trotzdem resetten
            user.currentPub = null;
        }

        // 6. Bestätigung an Client senden (DAS LÖST DEIN PROBLEM ZUSAMMEN MIT SCHRITT 1)
        socket.emit('pub_left_success');
    });

// 3. RAUM BEITRETEN (Multi-Chat Fix: Kein Kickout mehr!)
    socket.on('pub_join', (roomId) => {
        const room = state.publicRooms[roomId];
        const user = state.users[socket.id];

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
            const oldRoom = state.publicRooms[user.currentPub];
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
        io.emit('promo_update', generatePromoList(state));
    });

    // 4. PUBLIC NACHRICHT (Routing Fix + Ghost)
    socket.on('pub_message', (msg) => {
        const user = state.users[socket.id];
        if (!user || !user.currentPub) return;

        // Rate Limit
        const now = Date.now();
        if (now - (state.messageRateLimit[socket.id] || 0) < 200) return;
        state.messageRateLimit[socket.id] = now;

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

    // 13. PUBLIC WHISPER (FLÜSTERN)
    socket.on('pub_whisper', (data) => {
        const sender = state.users[socket.id];

        // Checks: User muss existieren und in einem Raum sein
        if (!sender || !sender.currentRoom) return;

        // Rate Limit Check
        const now = Date.now();
        const lastTime = state.messageRateLimit[socket.id] || 0;
        if (now - lastTime < 200) {
            socket.emit('system_message', 'WARNING: Rate limit exceeded.');
            return;
        }
        state.messageRateLimit[socket.id] = now;

        // Ziel-User finden (anhand Key)
        const allUsers = Object.values(state.users);
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

    // 5. PUBLIC COMMANDS (Who list)
    socket.on('pub_who_request', () => {
        const user = state.users[socket.id];
        if (!user || !user.currentRoom) return;

        const room = state.publicRooms[user.currentRoom];
        if(room) {
            // Hier prüfen wir jeden User in der Liste
            const names = room.users.map(uid => {
                const u = state.users[uid];
                if (!u) return 'Unknown';
                // Wenn Ghost -> Zeige "Anonymous" (oder gar nichts, aber Anonymous ist cooler)
                return u.isGhost ? 'Anonymous' : u.username;
            });

            socket.emit('system_message', `ACTIVE NODES IN SECTOR: [ ${names.join(', ')} ]`);
        }
    });

    // =================================================================
    // 4. Private Groups (Management)
    // =================================================================

    // --- PRIVATE GROUP SYSTEM (RBAC) ---

// 1. GRUPPE ERSTELLEN (/group create [NAME])
    socket.on('group_create', (data) => {
        const creator = state.users[socket.id];
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
            finalName = sanitize(desiredName, 20);
        }
        // ----------------------------------

        state.privateGroups[groupId] = {
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
            name: state.privateGroups[groupId].name,
            key: groupKey,
            role: 'OWNER'
        });

        // Falls User eingeladen wurden:
        if (invitedUserKeys && invitedUserKeys.length > 0) {
            invitedUserKeys.forEach(targetKey => {
                const targetUser = Object.values(state.users).find(u => u.key === targetKey);
                if (targetUser) {
                    io.to(targetUser.id).emit('group_invite_received', {
                        groupId: groupId,
                        inviter: creator.username
                    });
                }
            });
        }
    });

    // 2. JOIN REQUEST (/group join ID) - ADMIN UPDATE (Skeleton Key)
    socket.on('group_join_req', (groupId) => {
        // 1. CRASH PREVENTION
        const user = state.users[socket.id];
        if (!user) {
            socket.emit('system_message', 'ACCESS DENIED: Authentication required.');
            return;
        }

        const group = state.privateGroups[groupId];

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
                role: user.isAdmin ? 'ADMIN' : 'MEMBER', // Rolle korrekt anzeigen
                rendezvousKey: group.rendezvousKey || null
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
            io.emit('promo_update', generatePromoList(state));

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
        const user = state.users[socket.id];
        const group = state.privateGroups[data.groupId];

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
            role: 'MEMBER',
            rendezvousKey: group.rendezvousKey || null
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

        io.emit('promo_update', generatePromoList(state));
    });

    // 3. INVITE (/group invite ID [ID] ...) - ENHANCED
    socket.on('group_invite_req', (targetKeysInput) => {
        const user = state.users[socket.id];
        if (!user || !user.currentGroup) {
            socket.emit('system_message', 'ERROR: You are not in a group.');
            return;
        }

        const group = state.privateGroups[user.currentGroup];
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

            const targetUser = Object.values(state.users).find(u => u.key === targetKey);

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
        const user = state.users[socket.id];
        if (!user) return; // Crash Schutz

        // FALL A: User nimmt Einladung an (Hier war die Lücke!)
        if (data.groupId) {
            const group = state.privateGroups[data.groupId];

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
                    role: 'MEMBER',
                    rendezvousKey: group.rendezvousKey || null
                });

                // Promo Update
                io.emit('promo_update', generatePromoList(state));

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

            const group = state.privateGroups[user.currentGroup];
            // Check: Ist der User Owner ODER Mod?
            const isOwner = group.ownerId === socket.id;
            const isMod = group.mods.includes(socket.id);

            if (!group || (!isOwner && !isMod)) {
                socket.emit('system_message', 'ERROR: Insufficient permissions to accept members.');
                return;
            }

            const targetUser = Object.values(state.users).find(u => u.key === data.targetKey);
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
                            role: 'MEMBER',
                            rendezvousKey: group.rendezvousKey || null
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
        const user = state.users[socket.id];
        if (!user || !user.currentGroup) return;

        const group = state.privateGroups[user.currentGroup];
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

    // --- GRUPPEN LINK ERSTELLEN ---
    socket.on('group_create_link_req', (data) => {
        const user = state.users[socket.id]; // User holen für Context-Check
        if (!user) return;

        const groupId = parseInt(data.groupId);
        const limit = parseInt(data.limit) || 0;

        const group = state.privateGroups[groupId];

        if (!group) return socket.emit('system_message', 'ERROR: Group not found.');

        const isOwner = group.ownerId === socket.id;
        const isMod = group.mods.includes(socket.id);

        if (!isOwner && !isMod) {
            return socket.emit('system_message', 'DENIED: Only Owner or Mods can create invite links.');
        }

        const linkId = Math.random().toString(36).substr(2, 9);

        state.activeGroupLinks[linkId] = {
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
                const partner = Object.values(state.users).find(u => u.key === data.targetRoomId);
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
        const user = state.users[socket.id]; // 1. User Objekt holen
        if (!user) return; // Sicherheits-Check

        const link = state.activeGroupLinks[linkId];

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
                delete state.activeGroupLinks[linkId];
                io.emit('group_link_expired', linkId);
            }
        }

        const group = state.privateGroups[link.groupId];
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
            key: group.key,
            rendezvousKey: group.rendezvousKey || null
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
        io.emit('promo_update', generatePromoList(state));
    });

    // 15. GROUP PROMOTE (/group promote TEXT)
    socket.on('group_promote', (desc) => {
        const user = state.users[socket.id];
        if (!user || !user.currentGroup) return;
        const group = state.privateGroups[user.currentGroup];

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
        io.emit('promo_update', generatePromoList(state));
    });

    // Wenn neuer User kommt: Liste schicken
    socket.on('request_promo_list', () => {
        socket.emit('promo_update', generatePromoList(state));
    });

    // =================================================================
    // 5. Private Groups (Interaction & Admin)
    // =================================================================

    // 8. GRUPPEN NACHRICHTEN (KORRIGIERT)
    socket.on('group_message', (msg) => {
        const user = state.users[socket.id];
        if (!user || !user.currentGroup) return;

        const group = state.privateGroups[user.currentGroup];
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



    // 11. GROUP RENAME (/group name [NAME]) - UI UPDATE FIX
    socket.on('group_rename', (newNameInput) => { // <--- WICHTIG: Hier "Input" nennen
        // SICHERHEITS-CHECK
        const user = state.users[socket.id];
        if (!user || !user.currentGroup) return;

        const group = state.privateGroups[user.currentGroup];
        if (!group) return;

        // BERECHTIGUNG: Owner ODER Admin
        if (group.ownerId !== socket.id && !user.isAdmin) {
            socket.emit('system_message', 'ERROR: Only the Group Owner or Global Admin can rename.');
            return;
        }

        // --- XSS SCHUTZ ---
        // Wir nehmen den "Input", waschen ihn, und speichern ihn als sauberen "newName"
        const newName = sanitize(newNameInput, 20);
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
        io.emit('promo_update', generatePromoList(state));
    });

// 12. GROUP PRIVACY TOGGLE - ADMIN UPDATE
    socket.on('group_toggle_privacy', (setOpen) => {
        const user = state.users[socket.id];
        if (!user || !user.currentGroup) return;
        const group = state.privateGroups[user.currentGroup];

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
        io.emit('promo_update', generatePromoList(state));
    });

    // 13. OWNERSHIP TRANSFER (/group owner KEY) - ADMIN UPDATE
    socket.on('group_transfer_owner', (targetKey) => {
        const user = state.users[socket.id];
        if (!user || !user.currentGroup) return;
        const group = state.privateGroups[user.currentGroup];

        // ADMIN-UPDATE: Owner ODER Admin darf das
        if (!group || (group.ownerId !== socket.id && !user.isAdmin)) {
            socket.emit('system_message', 'ERROR: You are not the Owner or Global Admin.');
            return;
        }

        const targetUser = Object.values(state.users).find(u => u.key === targetKey);
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

    // 14. GROUP DESTROY (Wenn Owner bestätigt) - ADMIN UPDATE
    socket.on('group_destroy_confirm', () => {
        const user = state.users[socket.id];
        if (!user || !user.currentGroup) return;
        const group = state.privateGroups[user.currentGroup];

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

                if (state.users[memberId]) state.users[memberId].currentGroup = null;
            }
        });

        // Gruppe aus Speicher löschen
        delete state.privateGroups[group.id];

        // WICHTIG: Promo Board updaten
        io.emit('promo_update', generatePromoList(state));
    });

    // 7. BROADCAST (/group broadcast MSG) - HIGHLIGHTED & GHOST AWARE
    socket.on('group_broadcast', (msg) => {
        // SICHERHEITS-CHECK
        const user = state.users[socket.id];
        if (!user || !user.currentGroup) return;

        const group = state.privateGroups[user.currentGroup];
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

    // 10. GROUP LEAVE (Mit Owner-Check Dialog)
    socket.on('group_leave', () => {
        const user = state.users[socket.id];
        if (!user || !user.currentGroup) return;
        const group = state.privateGroups[user.currentGroup];
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
        io.emit('promo_update', generatePromoList(state));
    });

    // NEU: OWNER ENTSCHEIDUNG BEIM VERLASSEN
    socket.on('group_owner_action', (data) => {
        // data: { action: 'close' | 'transfer', target: 'random' | KEY }
        const user = state.users[socket.id];
        if (!user || !user.currentGroup) return;
        const group = state.privateGroups[user.currentGroup];
        if (!group || group.ownerId !== socket.id) return; // Nur Owner!

        if (data.action === 'close') {
            // GRUPPE AUFLÖSEN (Wie Dissolve)
            serverLog(`Owner ${user.username} schließt Gruppe ${group.id} beim Verlassen.`);

            group.members.forEach(memberId => {
                const s = io.sockets.sockets.get(memberId);
                if (s) {
                    s.leave(`group_${group.id}`);
                    s.emit('group_dissolved', group.id);
                    if (state.users[memberId]) state.users[memberId].currentGroup = null;
                }
            });
            delete state.privateGroups[group.id];
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
                const targetUser = Object.values(state.users).find(u => u.key === data.target);
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
            const newOwner = state.users[newOwnerId];

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

        io.emit('promo_update', generatePromoList(state));
    });

    // 16. GROUP DISSOLVE (/group dissolve) - Harter Reset
    socket.on('group_dissolve', () => {
        const user = state.users[socket.id];
        if (!user || !user.currentGroup) return;
        const group = state.privateGroups[user.currentGroup];
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

                if (state.users[memberId]) state.users[memberId].currentGroup = null;
            }
        });

        delete state.privateGroups[group.id];
        io.emit('promo_update', generatePromoList(state));
    });

    // 6. KICK PROCESS (Multi-Target & Reason & Admin Immunity)
    socket.on('group_kick_req', (data) => {
        // data: { targets: ['ID1', 'ID2'], reason: "Grund" }
        const user = state.users[socket.id];
        if (!user || !user.currentGroup) return;

        const group = state.privateGroups[user.currentGroup];
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
            const targetUser = Object.values(state.users).find(u => u.key === targetKey);

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

                if (state.users[targetUser.id]) state.users[targetUser.id].currentGroup = null;
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
            io.emit('promo_update', generatePromoList(state));
        }
    });

    // 6a. KICK PREVIEW (Namen auflösen vor dem Kick)
    socket.on('group_kick_preview_req', (targetKeys) => {
        const user = state.users[socket.id];
        if (!user || !user.currentGroup) return;

        const group = state.privateGroups[user.currentGroup];
        if (!group) return;

        // Wir sammeln die Infos für die Vorschau
        const previewList = [];
        const targets = Array.isArray(targetKeys) ? targetKeys : [targetKeys];

        targets.forEach(key => {
            const targetUser = Object.values(state.users).find(u => u.key === key);
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

    // 5. MOD SYSTEM (/mod ID) -> Nur Owner
    socket.on('group_user_promote', (targetKey) => {
        // SICHERHEITS-CHECK
        const user = state.users[socket.id];
        if (!user || !user.currentGroup) return;

        const group = state.privateGroups[user.currentGroup];

        if (!group || group.ownerId !== socket.id) {
            socket.emit('system_message', 'ERROR: Only the Group Owner can promote users.');
            return;
        }

        const targetUser = Object.values(state.users).find(u => u.key === targetKey);
        if (!targetUser || !group.members.includes(targetUser.id)) {
            socket.emit('system_message', 'ERROR: User must be in the group.');
            return;
        }

        if (!group.mods.includes(targetUser.id)) {
            group.mods.push(targetUser.id);
            io.to(`group_${group.id}`).emit('system_message', `PERMISSION UPDATE: ${targetUser.username} is now a MODERATOR.`);
        }
    });

    // 9. GROUP WHO (/group who)
    socket.on('group_who_req', () => {
        const user = state.users[socket.id];
        if (!user || !user.currentGroup) return;

        const group = state.privateGroups[user.currentGroup];
        if (!group) return;

        // Namen und Rollen auflisten
        const memberList = group.members.map(memberId => {
            const u = state.users[memberId];
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
        const user = state.users[socket.id];
        if (!user || !user.currentGroup) return;

        const group = state.privateGroups[user.currentGroup];
        if (!group) return;

        // Container für die Sortierung
        const result = {
            owner: null,
            mods: [],
            members: []
        };

        // Alle Mitglieder durchgehen und sortieren
        group.members.forEach(memberId => {
            const u = state.users[memberId];
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

    // 6b. ADMIN COMPLETE OWNER KICK (Die Ausführung)
    socket.on('admin_complete_owner_kick', (data) => {
        // data: { targetKey, action, method, newOwnerKey }
        const user = state.users[socket.id];
        if (!user || !user.isAdmin || !user.currentGroup) return;

        const group = state.privateGroups[user.currentGroup];
        if (!group) return;

        // Validierung: Ist das Ziel wirklich (noch) der Owner?
        const oldOwner = Object.values(state.users).find(u => u.key === data.targetKey);
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
                    if (state.users[memberId]) state.users[memberId].currentGroup = null;
                }
            });
            delete state.privateGroups[group.id];

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
                const specificUser = Object.values(state.users).find(u => u.key === data.newOwnerKey);
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
            const newOwner = state.users[newOwnerId];

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
                if (state.users[oldOwner.id]) state.users[oldOwner.id].currentGroup = null;
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

        io.emit('promo_update', generatePromoList(state));
    });



    // 17. ADMIN RESOLVE OWNER KICK (Nachfolge regeln)
    socket.on('group_admin_resolve_owner', (data) => {
        // data: { mode: 'random' | 'specific', oldOwnerKey: '...', newOwnerKey: '...' }
        const user = state.users[socket.id];
        if (!user || !user.isAdmin || !user.currentGroup) return; // Nur Admins!

        const group = state.privateGroups[user.currentGroup];
        if (!group) return;

        const oldOwnerUser = Object.values(state.users).find(u => u.key === data.oldOwnerKey);

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
            const specificUser = Object.values(state.users).find(u => u.key === data.newOwnerKey);
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
        const newOwnerUser = state.users[newOwnerId];
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

        io.emit('promo_update', generatePromoList(state));
    });

    // =================================================================
    // 6. Features (Ghost, Drops, Voice)
    // =================================================================

    // 20. UNIVERSAL GHOST SCANNER (/scan)
    socket.on('ghost_scan_req', () => {
        const user = state.users[socket.id];
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
                const room = state.publicRooms[user.currentPub];
                if (room) {
                    room.members.forEach(mid => {
                        const u = state.users[mid];
                        if (u && u.isGhost) detectedGhosts.push({ realName: u.username, key: u.key });
                    });
                }
            }
        }
        // FALL B: GRUPPEN CHAT
        else if (user.currentGroup) {
            contextName = `Group ${user.currentGroup}`;
            const group = state.privateGroups[user.currentGroup];

            if (group) {
                const isOwner = group.ownerId === socket.id;
                const isMod = group.mods.includes(socket.id);

                // Admin, Owner oder Mod dürfen scannen
                if (user.isAdmin || isOwner || isMod) {
                    hasPermission = true;
                    group.members.forEach(mid => {
                        const u = state.users[mid];
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



    // 21. GHOST REVEAL (Einzelner Klick)
    socket.on('ghost_reveal_req', (targetKey) => {
        const requester = state.users[socket.id];
        if (!requester) return;

        const targetUser = Object.values(state.users).find(u => u.key === targetKey);
        if (!targetUser) return; // User nicht gefunden

        let hasPermission = false;

        // 1. Admin darf immer
        if (requester.isAdmin) hasPermission = true;

        // 2. Owner/Mod Check (nur wenn beide in der gleichen Gruppe sind)
        else if (requester.currentGroup && requester.currentGroup === targetUser.currentGroup) {
            const group = state.privateGroups[requester.currentGroup];
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

    // --- FEATURE: DEAD DROPS ---

    // 1. DROP ERSTELLEN (/drop create [MSG] [OPTIONAL: TIMER_IN_MIN])
    socket.on('drop_create', (data) => {
        // data: { message: "Geheim", timer: 5 }
        const user = state.users[socket.id];
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
        state.deadDrops[dropId] = {
            id: dropId,
            content: data.message,
            creator: user.username,
            created: Date.now(),
            expires: Date.now() + ttl,
            timeoutId: setTimeout(() => {
                // AUTO-BURN (Zeit abgelaufen)
                if (state.deadDrops[dropId]) {
                    delete state.deadDrops[dropId];
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
        const user = state.users[socket.id];
        if (!user) return;

        // ID bereinigen (Leerzeichen weg)
        const cleanId = dropId.trim().toUpperCase();
        const drop = state.deadDrops[cleanId];

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
            delete state.deadDrops[cleanId]; // Daten vernichten

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
        const user = state.users[socket.id];
        // Fileshare nutzt oft targetId (SocketID), Chat nutzt targetKey (UserKey)

        let targetSocketId = null;

        // Fall A: Ziel via Key (Chat)
        if (data.targetKey) {
            const t = Object.values(state.users).find(u => u.key === data.targetKey);
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

    // 2. VOICE CALL REQUEST (Anrufen)
    socket.on('voice_request', (data) => {
        // data: { targetKey }
        const user = state.users[socket.id];
        if (!user || !data.targetKey) return;

        const targetUser = Object.values(state.users).find(u => u.key === data.targetKey);

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
        const user = state.users[socket.id];
        if (!user || !data.targetKey) return;

        const targetUser = Object.values(state.users).find(u => u.key === data.targetKey);

        if (targetUser && user.partners.includes(targetUser.id)) {
            io.to(targetUser.id).emit('voice_connected', {
                responderKey: user.key
            });
        }
    });

    // 4. VOICE HANGUP (Auflegen)
    socket.on('voice_hangup', (data) => {
        // data: { targetKey }
        const user = state.users[socket.id];
        if (!user || !data.targetKey) return;

        const targetUser = Object.values(state.users).find(u => u.key === data.targetKey);

        if (targetUser) {
            // Wir senden es trotzdem, auch wenn sie nicht mehr in der Partner-Liste sind (für Cleanup)
            io.to(targetUser.id).emit('voice_terminated', {
                enderKey: user.key
            });
        }
    });

    // =================================================================
    // 7. Admin & HQ (Secure Drop & Institutionen)
    // =================================================================

    // --- ADMIN COMMAND: KICK ---
    socket.on('admin_kick', (targetKey) => {
        if (!state.users[socket.id].isAdmin) {
            socket.emit('system_message', 'ERROR: Insufficient privileges.');
            return;
        }

        const allUsers = Object.values(state.users);
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
            serverLog(`ADMIN ACTION: User ${targetUser.username} kicked by ${state.users[socket.id].username}`);
        } else {
            socket.emit('system_message', 'ERROR: Target not found.');
        }
    });

// --- ADMIN COMMAND: GLOBAL BROADCAST (DEBUG VERSION) ---
    socket.on('admin_broadcast', (msg) => {
        const user = state.users[socket.id];

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
        const user = state.users[socket.id];
        if (!user || !user.isAdmin) {
            socket.emit('system_message', 'ERROR: ACCESS DENIED. God Mode required.');
            return;
        }

        const targets = Array.isArray(targetKeysInput) ? targetKeysInput : [targetKeysInput];
        let banCount = 0;

        targets.forEach(targetKey => {
            const targetUser = Object.values(state.users).find(u => u.key === targetKey);

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

    // INFORMANT: Tipp senden (JETZT VIA DB)
    socket.on('hq_send_tip', async (data) => {
        // data: { targetId, content }
        const inst = await db.getInstitutionByTag(data.targetId);

        if (!inst) {
            socket.emit('system_message', 'ERROR: Destination not found.');
            return;
        }

        const senderUser = state.users[socket.id];
        const safeSenderName = senderUser ? senderUser.username : 'Unknown';
        const senderKey = senderUser ? senderUser.key : 'UNKNOWN';

        // 1. In DB speichern
        await db.addInboxMessage(inst.tag, safeSenderName, senderKey, data.content);

        socket.emit('system_message', `>>> INTEL DELIVERED TO ${inst.name}.`);

        // 2. Live Update an das eingeloggte HQ senden
        // Wir holen die frische Liste direkt aus der DB
        const freshInbox = await db.getInboxMessages(inst.tag);
        io.to(`HQ_${inst.tag}`).emit('hq_inbox_data', freshInbox);
    });

    // HQ: Nachricht löschen (JETZT VIA DB)
    socket.on('hq_delete_msg', async (msgId) => {
        const user = state.users[socket.id];
        // Security: Ist User eine Institution?
        if (!user || !user.institution) return;

        // Löschen
        await db.deleteInboxMessage(msgId);

        // Update senden
        const freshInbox = await db.getInboxMessages(user.institution.tag);
        socket.emit('hq_inbox_data', freshInbox);
    });

    // HQ: Inbox manuell laden
    socket.on('hq_fetch_inbox', async () => {
        const user = state.users[socket.id];
        if (user && user.institution) {
            const inbox = await db.getInboxMessages(user.institution.tag);
            socket.emit('hq_inbox_data', inbox);
        }
    });

    // HQ: SICHERER VERBINDUNGSAUFBAU ZUM INFORMANTEN
    socket.on('hq_connect_req', (targetSocketId) => {
        // 1. Prüfen: Ist der User im RAM registriert? (WICHTIG!)
        const targetUser = state.users[targetSocketId];

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
        const me = state.users[socket.id];
        if (!me || !me.institution) {
            socket.emit('system_message', 'ACCESS DENIED.');
            return;
        }

        // 4. Alles grün -> Handshake freigeben
        socket.emit('hq_connect_approved', { targetId: targetSocketId });
    });

    // HQ: BROADCAST MESSAGE
    socket.on('hq_broadcast_req', (msg) => {
        const user = state.users[socket.id];

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
        const user = state.users[socket.id];

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
        const user = state.users[socket.id];

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







};