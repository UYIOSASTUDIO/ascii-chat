// socket_handlers/rendezvous.js
const crypto = require('crypto');
const { serverLog } = require('../utils/logger');
const { generatePromoList } = require('../utils/room_manager');
const state = require("../state"); // Promo Update nötig!

// Helper
async function serverHash(key) {
    return crypto.createHash('sha256').update(key).digest('hex');
}

module.exports = (io, socket, state) => {


    // =================================================================
    // RENDEZVOUS SYSTEM (ZERO KNOWLEDGE RE-ENTRY)
    // =================================================================

    // A) PRIVATE CHAT: VORSCHLAG SENDEN
    socket.on('rendezvous_propose_req', (data) => {
        const user = state.users[socket.id];
        // data.targetKey ist der User-Key des Partners
        const targetUser = Object.values(state.users).find(u => u.key === data.targetKey);

        if (targetUser && user.partners.includes(targetUser.id)) {
            io.to(targetUser.id).emit('rendezvous_proposal_rcv', {
                senderKey: user.key,
                senderName: user.isGhost ? 'Anonymous' : user.username
            });
        }
    });

    // B) PRIVATE CHAT: VORSCHLAG ANTWORT
    socket.on('rendezvous_proposal_response', (data) => {
        const user = state.users[socket.id];
        const targetUser = Object.values(state.users).find(u => u.key === data.targetKey);

        if (targetUser) {
            if (data.accepted) {
                // Beide bekommen das Signal zum Generieren/Anzeigen
                // Wir sagen dem Initiator (Target), dass er loslegen darf
                io.to(targetUser.id).emit('rendezvous_key_reveal', { isInitiator: true });
                // Dem Akzeptierer sagen wir nur "Accepted" (er wartet auf den Key im Chat)
                socket.emit('system_message', 'Rendezvous protocols accepted. Waiting for secure key transmission...');
            } else {
                io.to(targetUser.id).emit('system_message', 'Rendezvous proposal rejected by partner.');
            }
        }
    });

    // C) GROUP CHAT: KEY REGISTRIEREN
    socket.on('rendezvous_group_create', async (data) => {
        // data: { groupId, key }
        const user = state.users[socket.id];
        const group = privateGroups[data.groupId];

        if (!user || !group) return;
        if (group.ownerId !== socket.id && !group.mods.includes(socket.id)) return;

        // --- LIMIT CHECK ---
        // Wenn die Gruppe schon einen Key hat, senden wir diesen zurück, statt einen neuen zu machen!
        if (group.rendezvousKey) {
            socket.emit('system_message', 'INFO: Group already has an active Rendezvous Key.');

            // Dem User, der gefragt hat, den existierenden Key nochmal zeigen (privat)
            // Wir "faken" einen Broadcast nur an ihn
            socket.emit('group_broadcast_received', {
                text: `:::RENDEZVOUS_KEY:::${group.rendezvousKey}`, // Den GESPEICHERTEN Key nehmen
                senderName: "SYSTEM",
                senderKey: null,
                isGhost: false,
                role: 'SYSTEM',
                groupId: group.id
            });
            return;
        }
        // -------------------

        // 1. Key Hashen (für Wiederherstellung)
        const hash = await serverHash(data.key);

        // 2. Mapping speichern
        rendezvousGroups[hash] = {
            groupId: group.id,
            groupName: group.name,
            created: Date.now()
        };

        // 3. WICHTIG: Key in der Gruppe speichern (Klartext im RAM)
        // Damit wir ihn neuen Usern zeigen können.
        group.rendezvousKey = data.key;

        // 4. Bestätigung an die Gruppe (Alle sehen den neuen Key)
        const role = group.ownerId === socket.id ? 'OWNER' : 'MOD';
        io.to(`group_${group.id}`).emit('group_broadcast_received', {
            text: `:::RENDEZVOUS_KEY:::${data.key}`,
            senderName: user.username,
            senderKey: user.key,
            isGhost: !!user.isGhost,
            role: role,
            groupId: group.id
        });

        serverLog(`Rendezvous Point erstellt für Gruppe ${group.id}`);
    });

    // D) ENTER RENDEZVOUS (DER KERN - FIXED OWNER)
    socket.on('rendezvous_enter_req', (data) => {
        const user = state.users[socket.id];
        const hash = data.hash;

        if (!user || !hash) return;

        console.log(`[RENDEZVOUS] User ${user.username} scannt Hash: ${hash.substring(0, 10)}...`);

        // --- CHECK 1: IST ES EINE GRUPPE? ---
        if (rendezvousGroups[hash]) {
            const rGroup = rendezvousGroups[hash];

            // Wir prüfen, ob die *alte* ID noch aktiv ist
            let activeGroup = privateGroups[rGroup.groupId];
            let targetGroupId = rGroup.groupId;
            let role = 'MEMBER'; // Standard
            let statusMsg = "";

            // FALL 1: Gruppe existiert noch (lebt im RAM)
            if (activeGroup) {
                // User hinzufügen, falls noch nicht drin
                if (!activeGroup.members.includes(socket.id)) {
                    activeGroup.members.push(socket.id);
                    socket.join(`group_${targetGroupId}`);
                    user.currentGroup = targetGroupId;
                }

                // --- OWNER CHECK (WICHTIG!) ---
                // Wenn die Gruppe leer war (wir sind der erste Rückkehrer)
                // oder der alte Owner-Socket nicht mehr existiert:
                const currentOwnerOnline = io.sockets.sockets.get(activeGroup.ownerId);

                if (!currentOwnerOnline) {
                    // Wir übernehmen die Führung!
                    activeGroup.ownerId = socket.id;
                    role = 'OWNER';
                    statusMsg = `Frequency matched. You have claimed ownership of active cell #${targetGroupId}.`;
                } else if (activeGroup.ownerId === socket.id) {
                    role = 'OWNER'; // Wir sind schon der Boss
                    statusMsg = `Welcome back, Commander.`;
                } else {
                    role = 'MEMBER'; // Jemand anderes ist schon Boss
                    statusMsg = `Frequency matched. Joining active cell #${targetGroupId}.`;
                }
            }

            // FALL 2: Gruppe war gelöscht ("Sleeper Cell") -> WIEDERBELEBEN
            else {
                // --- FREQUENCY HOPPING (Neue ID generieren) ---
                const newGroupId = Math.floor(Math.random() * 9000) + 1000;

                // Mapping aktualisieren
                rendezvousGroups[hash].groupId = newGroupId;
                targetGroupId = newGroupId;

                serverLog(`[RENDEZVOUS] Sleeper Cell '${rGroup.groupName}' restored on new freq #${newGroupId}`);

                // Gruppe neu erstellen
                privateGroups[newGroupId] = {
                    id: newGroupId,
                    name: rGroup.groupName, // Alter Name
                    ownerId: socket.id,     // <--- WICHTIG: DU BIST OWNER
                    members: [socket.id],
                    mods: [],
                    key: "RESTORED_" + Date.now(),
                    rendezvousKey: null, // Key liegt ja im Hash-Mapping
                    pendingJoins: [],
                    invitedUsers: [],
                    isPublic: false
                };

                socket.join(`group_${newGroupId}`);
                user.currentGroup = newGroupId;

                role = 'OWNER'; // <--- EXPLIZIT SETZEN

                statusMsg = `>>> SLEEPER CELL ACTIVATED. FREQUENCY SHIFTED TO #${newGroupId}.`;
            }

            // Erfolg an Client senden (Hier wird die Rolle übergeben!)
            socket.emit('rendezvous_group_restored', {
                groupId: targetGroupId,
                name: rendezvousGroups[hash].groupName,
                role: role,
                // --- DER FIX: DEN ECHTEN GRUPPEN-KEY MITSENDEN ---
                key: (activeGroup || privateGroups[targetGroupId]).key
                // -------------------------------------------------
            });

            // Status an Gruppe
            io.to(`group_${targetGroupId}`).emit('room_user_status', {
                username: user.username,
                key: user.key,
                isGhost: !!user.isGhost,
                type: 'join',
                context: 'group',
                roomId: targetGroupId
            });

            // System Info senden (Verzögert für Effekt)
            setTimeout(() => {
                io.to(`group_${targetGroupId}`).emit('system_message', statusMsg);
                // Promo Update
                io.emit('promo_update', generatePromoList(state));
            }, 500);

            return;
        }

        // --- CHECK 2: PRIVATE CHAT (Code bleibt gleich) ---
        if (rendezvousWaiting[hash]) {
            // ... (Hier nichts ändern am Private Chat Code) ...
            const waiter = rendezvousWaiting[hash];
            const waiterSocket = io.sockets.sockets.get(waiter.socketId);

            if (waiterSocket) {
                serverLog(`[RENDEZVOUS] Match found: ${user.username} <-> Waiting Socket`);
                socket.emit('rendezvous_match_found', { peerSocketId: waiter.socketId, role: 'peer', type: 'private' });
                waiterSocket.emit('rendezvous_match_found', { peerSocketId: socket.id, role: 'initiator', type: 'private' });
                delete rendezvousWaiting[hash];
            } else {
                rendezvousWaiting[hash] = { socketId: socket.id, timestamp: Date.now() };
            }
        } else {
            rendezvousWaiting[hash] = { socketId: socket.id, timestamp: Date.now() };
        }
    });

    // In server.js
    socket.on('rendezvous_cancel_req', () => {
        // User aus der Warteliste suchen und löschen
        for (const [hash, waiter] of Object.entries(rendezvousWaiting)) {
            if (waiter.socketId === socket.id) {
                delete rendezvousWaiting[hash];
                break;
            }
        }
    });

    // E) P2P HANDSHAKE TUNNEL
    socket.on('rendezvous_handshake_init', (data) => {
        // data: { targetSocketId, publicKey }

        // Wir leiten das einfach als normalen Request weiter,
        // aber der Client empfängt es als 'incoming_request',
        // welches er automatisch akzeptieren wird (da er im Warte-Modus war?
        // Nein, Client Logic muss das handhaben, oder wir triggern ein normales connect)

        // Wir nutzen den existierenden 'incoming_request' Kanal,
        // da der Client dort schon die Logik hat.

        const sender = state.users[socket.id];

        io.to(data.targetSocketId).emit('incoming_request', {
            requesterId: socket.id,
            requesterName: sender.isGhost ? 'Anonymous' : sender.username,
            requesterKey: sender.key,
            publicKey: data.publicKey
        });

        // Der Trick: Da der User A gerade "CONNECTING" sieht, muss er manuell annehmen?
        // Besser: Wir vertrauen darauf, dass der User "Accept" drückt, da er ja drauf wartet.
        // Oder wir erweitern den Client, dass er bei Rendezvous-Matches automatisch annimmt.
    });


};