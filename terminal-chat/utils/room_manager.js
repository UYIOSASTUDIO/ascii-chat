// utils/room_manager.js
const { serverLog } = require('./logger');

/**
 * Räumt leere Public Rooms auf und nummeriert sie neu.
 * @param {Object} io - Socket.io Instanz
 * @param {Object} state - Der globale State
 */
function reorganizePublicRooms(io, state) {
    const sortedRooms = Object.values(state.publicRooms)
        .filter(r => r && r.members && r.members.length > 0)
        .sort((a, b) => (a.createdAt || 0) - (b.createdAt || 0));

    const newPublicRooms = {};
    let counter = 1;

    sortedRooms.forEach(room => {
        const oldId = room.id;
        const newId = String(counter).padStart(4, '0');
        counter++;

        if (room.name.includes('PENDING') || room.name === `Sector_${oldId}`) {
            room.name = `Sector_${newId}`;
        }

        if (oldId !== newId) {
            serverLog(`Renumbering Sector: ${oldId} -> ${newId}`);
            room.id = newId;

            // User & Sockets updaten
            room.members.forEach(memberId => {
                const u = state.users[memberId];
                if (u) u.currentPub = newId;

                const s = io.sockets.sockets.get(memberId);
                if (s) {
                    s.leave(`pub_${oldId}`);
                    s.join(`pub_${newId}`);
                    s.emit('pub_id_changed', { oldId, newId, newName: room.name });
                }
            });

            io.to(`pub_${newId}`).emit('system_message', `SYSTEM NOTICE: Sector ID changed to #${newId}.`);
        }
        newPublicRooms[newId] = room;
    });

    state.publicRooms = newPublicRooms;
}

/**
 * Generiert die Liste für das Promo-Board (Rechte Seite)
 * @param {Object} state - Der globale State
 */
function generatePromoList(state) {
    return Object.values(state.privateGroups)
        .filter(g => g.isPublic && g.description)
        .map(g => ({
            id: g.id,
            name: g.name,
            desc: g.description,
            count: g.members.length,
            date: g.promotedAt
        }));
}

module.exports = { reorganizePublicRooms, generatePromoList };