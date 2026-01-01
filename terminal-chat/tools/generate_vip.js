// tools/generate_vip.js
const crypto = require('crypto');
const db = require('../database');

const args = process.argv.slice(2);
const handle = args[0];
const displayName = args[1];

if (!handle || !displayName) {
    console.log("USAGE: node tools/generate_vip.js @handle 'Display Name'");
    process.exit(1);
}

// 1. RSA Schlüsselpaar generieren
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 4096,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});

(async () => {
    // --- DER FIX: NUR DEN BODY SPEICHERN ---
    // Wir entfernen Header, Footer und Zeilenumbrüche
    const cleanPubKey = publicKey
        .replace('-----BEGIN PUBLIC KEY-----', '')
        .replace('-----END PUBLIC KEY-----', '')
        .replace(/(\r\n|\n|\r)/gm, "")
        .trim();

    // Private Key für den VIP (Base64 kodiert für einfachen Transport)
    const secretIdentityString = Buffer.from(privateKey).toString('base64');

    console.log("\n---------------------------------------------------");
    console.log(`>>> GENERATING IDENTITY FOR: ${displayName} (${handle})`);
    console.log("---------------------------------------------------");

    await db.initDB();

    // Alten Eintrag löschen falls vorhanden (damit du den Befehl wiederholen kannst)
    // Das geht nur, wenn wir direkt SQL nutzen, oder wir verlassen uns auf addVip Fehler
    // Wir probieren es einfach.

    const success = await db.addVip(handle, displayName, cleanPubKey);

    if (success) {
        console.log("✅ PUBLIC KEY SAVED TO DATABASE (Clean Format).");
        console.log("\n⬇️  GIVE THIS SECRET KEY TO THE VIP (SECURELY!) ⬇️\n");
        console.log(secretIdentityString);
        console.log("\n---------------------------------------------------");
        console.log(`LOGIN COMMAND: /identify ${handle} [KEY]`);
        console.log("---------------------------------------------------");
    } else {
        console.log("❌ ERROR: Handle likely already exists.");
        console.log("TIP: Delete the database file or use a new handle.");
    }
})();