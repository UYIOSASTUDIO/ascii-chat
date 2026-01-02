require('dotenv').config();

const express = require('express');
const app = express();
const http = require('http');
const { Server } = require("socket.io");
const path = require('path');
const db = require('./database');
const state = require('./state'); // <--- WICHTIG: Unser RAM Speicher
const { serverLog, serverError } = require('./utils/logger');

// --- HELPER IMPORTS (Damit wir sie nicht unten definieren müssen) ---
const { reorganizePublicRooms, generatePromoList } = require('./utils/room_manager');

// --- MODULE HANDLER IMPORTS ---
const authHandler = require('./socket_handlers/auth');
const chatHandler = require('./socket_handlers/chat');
const blogHandler = require('./socket_handlers/blogpost'); // Falls du das Modul so genannt hast
const fsHandler = require('./socket_handlers/filesystem');
const rendezvousHandler = require('./socket_handlers/rendezvous');
const wireModule = require('./socket_handlers/wire'); // Exportiert { handleWire, broadcastWireFeed }

// --- CONFIG CHECKS ---
if (!process.env.VAPID_PUBLIC_KEY || !process.env.VAPID_PRIVATE_KEY) {
    console.error("FATAL: VAPID Keys missing in .env");
    process.exit(1);
}
if (!process.env.ADMIN_SECRET) {
    console.error("FATAL: ADMIN_SECRET missing in .env");
    process.exit(1);
}

// --- SECURITY HEADERS ---
app.use((req, res, next) => {
    res.setHeader(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: https://cdn-icons-png.flaticon.com; connect-src 'self' ws: wss:;"
    );
    next();
});

const server = http.createServer(app);
const io = new Server(server, {
    maxHttpBufferSize: 1e8 // 100 MB Upload Limit
});

app.use(express.static(path.join(__dirname, 'public')));

// --- INTERVALL JOBS ---
// Wire Feed & Cleanup alle 60 Sekunden
setInterval(async () => {
    // Wir nutzen die exportierte Funktion aus dem Wire-Modul
    await wireModule.broadcastWireFeed(io, state);
    await db.cleanupOrphanedComments();
}, 60000);

// --- SOCKET CONNECTION ---
io.on('connection', (socket) => {
    serverLog(`Neue Verbindung: ${socket.id}`);

    // --- ALLE MODULE LADEN ---
    // Wir injizieren io, socket und den globalen state in jedes Modul
    authHandler(io, socket, state);
    chatHandler(io, socket, state);
    blogHandler(io, socket, state);
    fsHandler(io, socket, state);
    rendezvousHandler(io, socket, state);
    wireModule.handleWire(io, socket, state); // Achtung: Hier .handleWire aufrufen

    // --- DISCONNECT HANDLING (GLOBAL CLEANUP) ---
    // Da hier viele Module betroffen sind, lassen wir die Logik zentral hier.
    socket.on('disconnect', () => {
        const user = state.users[socket.id];

        // 1. Fileshares entfernen (FS Module Cleanup)
        if (state.activeShares && state.activeShares[socket.id]) {
            delete state.activeShares[socket.id];
            io.emit('fs_update_shares', state.activeShares);
        }

        // 2. Rendezvous Cleanup
        for (const [hash, waiter] of Object.entries(state.rendezvousWaiting)) {
            if (waiter.socketId === socket.id) {
                delete state.rendezvousWaiting[hash];
                break;
            }
        }

        // 3. User Cleanup (Wenn eingeloggt)
        if (user) {
            serverLog(`Disconnect: ${user.username}`);

            // A) Aus Public Room entfernen
            if (user.currentPub && state.publicRooms[user.currentPub]) {
                const pubId = user.currentPub;
                const room = state.publicRooms[pubId];

                // Aus Liste löschen
                room.members = room.members.filter(id => id !== socket.id);

                // Wenn leer -> Löschen & Reorganisieren
                if (room.members.length === 0) {
                    delete state.publicRooms[pubId];
                    // Hier nutzen wir die importierte Helper-Funktion!
                    reorganizePublicRooms(io, state);
                } else {
                    io.to(`pub_${pubId}`).emit('system_message', `User ${user.username} signal lost.`);
                }
            }

            // B) Aus Private Group entfernen
            if (user.currentGroup && state.privateGroups[user.currentGroup]) {
                const grp = state.privateGroups[user.currentGroup];

                // Aus Listen löschen
                grp.members = grp.members.filter(id => id !== socket.id);
                grp.mods = grp.mods.filter(id => id !== socket.id);

                // Owner Logic (Nachfolger suchen)
                if (grp.ownerId === socket.id) {
                    let newOwnerId = null;
                    if (grp.mods.length > 0) newOwnerId = grp.mods[Math.floor(Math.random() * grp.mods.length)];
                    else if (grp.members.length > 0) newOwnerId = grp.members[Math.floor(Math.random() * grp.members.length)];

                    if (newOwnerId) {
                        grp.ownerId = newOwnerId;
                        const newOwner = state.users[newOwnerId];
                        io.to(`group_${grp.id}`).emit('room_user_status', {
                            username: newOwner.username, key: newOwner.key, isGhost: !!newOwner.isGhost,
                            type: 'approved', context: 'group', roomId: grp.id
                        });
                        io.to(`group_${grp.id}`).emit('system_message', `CRITICAL: Owner signal lost. Authority transferred.`);

                        // Bescheid geben
                        const ns = io.sockets.sockets.get(newOwnerId);
                        if(ns) ns.emit('you_are_promoted', { groupId: grp.id, role: 'OWNER' });
                    } else {
                        // Niemand mehr da -> Löschen
                        delete state.privateGroups[grp.id];
                    }
                } else {
                    // Normaler Member Leave
                    io.to(`group_${grp.id}`).emit('room_user_status', {
                        username: user.username, key: user.key, isGhost: !!user.isGhost,
                        type: 'leave', context: 'group', roomId: grp.id
                    });
                }
                // Promo Board updaten (Importierte Funktion!)
                io.emit('promo_update', generatePromoList(state));
            }

            // C) Private Partner trennen (Auto-Burn)
            if (user.partners && user.partners.length > 0) {
                user.partners.forEach(partnerId => {
                    io.to(partnerId).emit('private_leave_received', {
                        name: user.username, key: user.key
                    });
                    if (state.users[partnerId]) {
                        state.users[partnerId].partners = state.users[partnerId].partners.filter(id => id !== socket.id);
                    }
                });
            }

            // D) User endgültig löschen
            delete state.users[socket.id];
        }
    });
});

// --- SERVER START ---
const PORT = process.env.PORT || 3000;

(async () => {
    // DB Init
    await db.initDB();

    // Standard Accounts
    const mi6 = await db.getInstitutionByTag('MI6');
    if (!mi6) await db.createInstitution('MI6', 'Secret Intelligence Service', '007', 'KVUGK3LSMFZEQUDL', '#00ff00');

    const cia = await db.getInstitutionByTag('CIA');
    if (!cia) await db.createInstitution('CIA', 'Central Intelligence Agency', 'langley', 'KRUW4ZLOMVZUKZLJMVZUKZLJ', '#0088ff');

    server.listen(PORT, '0.0.0.0', () => {
        console.log(`\n----------------------------------------`);
        console.log(`SECURE SERVER ONLINE ON PORT ${PORT}`);
        console.log(`MODULAR ARCHITECTURE: ACTIVE`);

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