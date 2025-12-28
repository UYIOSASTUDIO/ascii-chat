// database.js - Persistence Layer & Key Management
const sqlite3 = require('sqlite3').verbose();
const { open } = require('sqlite');
const bcrypt = require('bcrypt');
const path = require('path');
const crypto = require('crypto'); // WICHTIG: Für Key-Generierung

const DB_PATH = path.join(__dirname, 'secure_storage.sqlite');

let db;

// --- 1. DATENBANK INIT ---
async function initDB() {
    db = await open({
        filename: DB_PATH,
        driver: sqlite3.Database
    });

    console.log('[DB] Connected to SQLite Storage.');

    // Institutionen Tabelle (JETZT MIT KEYS!)
    await db.exec(`
        CREATE TABLE IF NOT EXISTS institutions (
                                                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                                                    tag TEXT UNIQUE NOT NULL,
                                                    name TEXT NOT NULL,
                                                    email TEXT UNIQUE,
                                                    description TEXT,   -- NEU: Die Beschreibung
                                                    password_hash TEXT NOT NULL,
                                                    two_factor_secret TEXT,
                                                    color TEXT DEFAULT '#00ff00',
                                                    inbox_file TEXT,
                                                    public_key TEXT,
                                                    private_key TEXT,
                                                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    `);

    // Tabelle für Bewerbungen (Requests)
    await db.exec(`
        CREATE TABLE IF NOT EXISTS registration_requests (
                                                             id INTEGER PRIMARY KEY AUTOINCREMENT,
                                                             org_name TEXT NOT NULL,
                                                             org_tag TEXT NOT NULL,           -- NEU: Die gewünschte ID (z.B. CIA)
                                                             message TEXT,                    -- NEU: Die Bewerbungsnachricht
                                                             email TEXT NOT NULL UNIQUE,
                                                             status TEXT DEFAULT 'UNVERIFIED',
                                                             verification_code TEXT,
                                                             request_date DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    `);

    // Tabelle für Einladungen (Tokens)
    await db.exec(`
        CREATE TABLE IF NOT EXISTS invite_tokens (
            token TEXT PRIMARY KEY,
            approved_email TEXT NOT NULL,
            org_name_suggestion TEXT,
            is_used BOOLEAN DEFAULT 0
        );
    `);

    await db.exec(`
        CREATE TABLE IF NOT EXISTS system_blogs (
                                                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                                                    title TEXT,                     -- NEU
                                                    content TEXT NOT NULL,
                                                    author_tag TEXT NOT NULL,
                                                    author_name TEXT NOT NULL,
                                                    tags TEXT,                      -- Speichern wir als JSON-String
                                                    attachment_data TEXT,           -- Speichern wir als JSON-String (Pfad, Größe, Name)
                                                    is_important INTEGER DEFAULT 0, -- 0 oder 1
                                                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    `);

    console.log('[DB] Schema synchronized (Keys enabled).');
}

// --- 2. CORE FUNCTIONS ---

// Neue Institution erstellen (Inklusive Key-Generierung!)
async function createInstitution(tag, name, plainPassword, twoFactorSecret, color) {
    const saltRounds = 10;
    const hash = await bcrypt.hash(plainPassword, saltRounds);
    const inboxFile = `inbox_${tag.toLowerCase()}.json`;

    // A) RSA SCHLÜSSEL PAAR GENERIEREN
    // Wir machen das hier synchron, da es nur einmal beim Setup passiert.
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });

    try {
        // B) ALLES SPEICHERN
        await db.run(`
            INSERT INTO institutions (tag, name, password_hash, two_factor_secret, color, inbox_file, public_key, private_key)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `, [tag, name, hash, twoFactorSecret, color, inboxFile, publicKey, privateKey]);

        console.log(`[DB] Institution [${tag}] created with 2048-bit RSA keys.`);
        return true;
    } catch (e) {
        console.error(`[DB] Error creating ${tag}:`, e.message);
        return false;
    }
}

async function getInstitutionByTag(tag) {
    return await db.get('SELECT * FROM institutions WHERE tag = ?', [tag]);
}

async function verifyPassword(inputPassword, storedHash) {
    return await bcrypt.compare(inputPassword, storedHash);
}

// 1. Request erstellen (Erweitert)
async function createRequest(orgName, orgTag, message, email, verifyCode) {
    try {
        await db.run("DELETE FROM registration_requests WHERE email = ?", [email]);

        await db.run(`
            INSERT INTO registration_requests (org_name, org_tag, message, email, verification_code)
            VALUES (?, ?, ?, ?, ?)
        `, [orgName, orgTag, message, email, verifyCode]);
        return true;
    } catch(e) {
        console.error(e);
        return false;
    }
}

async function verifyRequestEmail(email, code) {
    const req = await db.get("SELECT * FROM registration_requests WHERE email = ?", [email]);

    if (!req) return { success: false, msg: "Email not found." };
    if (req.status !== 'UNVERIFIED') return { success: false, msg: "Already verified." };
    if (req.verification_code !== code) return { success: false, msg: "Wrong code." };

    // Code stimmt -> Status auf PENDING (Sichtbar für Admin)
    await db.run("UPDATE registration_requests SET status = 'PENDING' WHERE email = ?", [email]);
    return { success: true };
}

async function getPendingRequests() {
    return await db.all("SELECT * FROM registration_requests WHERE status = 'PENDING'");
}

// --- NEU: ADMIN FUNKTIONEN ---

// Holt eine einzelne Anfrage per ID
async function getRequestById(id) {
    return await db.get("SELECT * FROM registration_requests WHERE id = ?", [id]);
}

// Status update (z.B. auf APPROVED)
async function updateRequestStatus(id, status) {
    await db.run("UPDATE registration_requests SET status = ? WHERE id = ?", [status, id]);
}

// Token erstellen
async function createInviteToken(token, approvedEmail, orgNameSuggestion) {
    try {
        await db.run(`
            INSERT INTO invite_tokens (token, approved_email, org_name_suggestion)
            VALUES (?, ?, ?)
        `, [token, approvedEmail, orgNameSuggestion]);
        return true;
    } catch(e) { return false; }
}

// Token prüfen (für später beim /setup)
async function getInviteToken(token) {
    return await db.get("SELECT * FROM invite_tokens WHERE token = ? AND is_used = 0", [token]);
}

// Token als benutzt markieren
async function markTokenUsed(token) {
    await db.run("UPDATE invite_tokens SET is_used = 1 WHERE token = ?", [token]);
}

// --- NEU: INSTITUTION LISTING & EDITING ---

// 1. Öffentliche Liste abrufen (OHNE Passwörter/Keys!)
// Liste aller Institutionen holen (ID, Name, Description, Color)
async function getPublicInstitutionList() {
    return await db.all("SELECT tag, name, description, color FROM institutions ORDER BY tag ASC");
}

// 2. Beschreibung updaten
async function updateInstitutionDescription(tag, newDescription) {
    try {
        await db.run("UPDATE institutions SET description = ? WHERE tag = ?", [newDescription, tag]);
        return true;
    } catch (e) {
        return false;
    }
}

// --- BLOG / SYSTEM LOGS ---

// 1. Erweitertes Erstellen
async function createBlogPost(data) {
    // data ist ein Objekt mit allen Infos
    await db.run(`
        INSERT INTO system_blogs (title, content, author_tag, author_name, tags, attachment_data, is_important) 
        VALUES (?, ?, ?, ?, ?, ?, ?)
    `, [
        data.title,
        data.content,
        data.authorTag,
        data.authorName,
        JSON.stringify(data.tags || []),            // Array zu String
        JSON.stringify(data.attachment || null),    // Objekt zu String
        data.important ? 1 : 0
    ]);
}

// 2. Abrufen (muss JSON parsen)
async function getBlogPosts() {
    const rows = await db.all("SELECT * FROM system_blogs ORDER BY id DESC LIMIT 50");
    // Wir müssen die JSON-Strings wieder in Objekte umwandeln, damit der Client sie versteht
    return rows.map(row => ({
        ...row,
        tags: JSON.parse(row.tags || '[]'),
        attachment: JSON.parse(row.attachment_data || 'null'),
        important: row.is_important === 1
    }));
}

// 3. Einzeln holen (für Lösch-Check)
async function getBlogPostById(id) {
    const row = await db.get("SELECT * FROM system_blogs WHERE id = ?", [id]);
    if (!row) return null;
    return {
        ...row,
        tags: JSON.parse(row.tags || '[]'),
        attachment: JSON.parse(row.attachment_data || 'null')
    };
}

// 4. Löschen
async function deleteBlogPost(id) {
    await db.run("DELETE FROM system_blogs WHERE id = ?", [id]);
}

// VERGISS NICHT, DIE NEUEN FUNKTIONEN HIER HINZUZUFÜGEN:
module.exports = {
    initDB,
    createInstitution,
    getInstitutionByTag,
    verifyPassword,
    createRequest,
    verifyRequestEmail,
    getPendingRequests,
    // --- NEU ---
    getRequestById,
    updateRequestStatus,
    createInviteToken,
    getInviteToken,
    markTokenUsed,
    getPublicInstitutionList,
    updateInstitutionDescription,
    createBlogPost,
    getBlogPosts,
    getBlogPostById,
    deleteBlogPost
};
