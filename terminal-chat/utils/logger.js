// utils/logger.js
const DEBUG_MODE = true; // Setze auf FALSE für absolute Stille

function serverLog(msg) {
    if (DEBUG_MODE) {
        const time = new Date().toLocaleTimeString();
        console.log(`[INFO ${time}] ${msg}`);
    }
}

function serverError(msg) {
    const time = new Date().toLocaleTimeString();
    console.error(`[ERROR ${time}] ⚠️ ${msg}`);
}

module.exports = { serverLog, serverError };