const { app, BrowserWindow } = require('electron');
const path = require('path');

function createWindow() {
    const win = new BrowserWindow({
        width: 1200,
        height: 800,
        backgroundColor: '#000000', // Terminal Schwarz
        webPreferences: {
            nodeIntegration: true,
            contextIsolation: false, // Erlaubt require() im Client, falls nötig
            // Wichtig für Sicherheit später, aber für den Start ok
        },
        // Optional: Rahmenloses Fenster für echten Hacker-Look
        // frame: false,
        // titleBarStyle: 'hidden'
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