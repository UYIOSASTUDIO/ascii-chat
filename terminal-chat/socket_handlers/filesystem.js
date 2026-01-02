// socket_handlers/filesystem.js
const { sanitize } = require('../utils/sanitizer');

// --- HELPER: INTELLIGENTES BROADCASTING ---
// Diese Funktion filtert Shares basierend auf Sichtbarkeit (Privat/Gruppe/Public)
function broadcastShares(io, state) {
    const connectedSockets = io.sockets.sockets;

    connectedSockets.forEach((recipientSocket) => {
        const sharesVisibleToUser = {};

        // Wir iterieren über alle aktiven Shares im State
        if (state.activeShares) {
            Object.keys(state.activeShares).forEach(hostId => {
                const share = state.activeShares[hostId];

                // Regel 1: Eigene Shares immer sehen
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

                // Regel 3: User ID Check (Ist der Empfänger direkt erlaubt?)
                const isUserAllowed = share.allowedUsers && share.allowedUsers.some(allowedId => recipientSocket.id.includes(allowedId));

                // Regel 4: Gruppen Check (Ist der Empfänger in einer erlaubten Gruppe?)
                // recipientSocket.rooms ist ein Set mit Raum-Namen
                let isGroupAllowed = false;
                if (share.allowedGroups && share.allowedGroups.length > 0) {
                    isGroupAllowed = share.allowedGroups.some(groupName => recipientSocket.rooms.has(groupName));
                }

                // ZUGRIFF GEWÄHRT?
                if (isUserAllowed || isGroupAllowed) {
                    sharesVisibleToUser[hostId] = share;
                }
            });
        }

        recipientSocket.emit('fs_update_shares', sharesVisibleToUser);
    });
}

module.exports = (io, socket, state) => {

    // 1. User kündigt Share an
    socket.on('fs_start_hosting', (data) => {
        state.activeShares[socket.id] = {
            username: data.username || socket.username || 'Anonymous',
            key: socket.id.substr(0, 5),
            folderName: data.folderName,
            allowedUsers: data.allowedUsers || [],
            allowedGroups: data.allowedGroups || [], // <--- NEU
            isProtected: data.isProtected || false,
            isSingleFile: data.isSingleFile || false
        };
        broadcastShares(io, state);
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
        if (state.activeShares[socket.id]) {
            delete state.activeShares[socket.id];
            io.emit('fs_update_shares', state.activeShares);
        }
    });

    // 4. Neuer User kommt rein -> Liste anfordern
    socket.on('fs_request_update', () => {
        socket.emit('fs_update_shares', state.activeShares);
    });

};