// state.js
// ZENTRALER SPEICHER (RAM)
// Hier liegen alle Daten, die einen Neustart NICHT überleben sollen (Privacy Feature).

const state = {
    users: {},              // Alle verbundenen User
    publicRooms: {},        // Öffentliche Chaträume
    privateGroups: {},      // Private Gruppen & VIP-Zellen
    deadDrops: {},          // Dead Drops
    activeShares: {},       // File Shares

    // Auth & Security
    authSessions: {},       // Laufende Logins (2FA Schritte)
    setupSessions: {},      // Laufende Setups
    activeGroupLinks: {},   // Einladungslinks

    // Rendezvous
    rendezvousWaiting: {},
    rendezvousGroups: {},

    // Rate Limits
    messageRateLimit: {},
    connectionRateLimit: {},
    tipRateLimit: {}
};

module.exports = state;