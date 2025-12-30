const { app, BrowserWindow } = require('electron');
const path = require('path');

function createWindow() {
    const win = new BrowserWindow({
        width: 1200,
        height: 800,
        backgroundColor: '#1a1a1a', // Passend zu deinem CSS Background

        // --- DAS IST NEU ---
        titleBarStyle: 'hidden', // Versteckt die Standard-Leiste (Mac & Windows)

        // Für Windows Nutzer (färbt die - [] X Buttons ein):
        titleBarOverlay: {
            color: '#1a1a1a',      // Hintergrundfarbe der Leiste
            symbolColor: '#e0e0e0', // Farbe der Symbole (Weiß/Grau)
            height: 40             // Höhe der Leiste
        },
        // -------------------

        webPreferences: {
            nodeIntegration: true,
            contextIsolation: false
        }
    });

    // Lade deine index.html
    win.loadFile('index.html');

    // Menüleiste ausblenden (optional)
    // win.setMenuBarVisibility(false);
}

app.whenReady().then(() => {
    createWindow();

    app.on('activate', () => {
        if (BrowserWindow.getAllWindows().length === 0) createWindow();
    });
});

app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') app.quit();
});