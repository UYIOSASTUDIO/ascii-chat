// database.js - Enterprise Persistence Layer
require('dotenv').config();
const sqlite3 = require('sqlite3').verbose();
const { open } = require('sqlite');
const bcrypt = require('bcrypt');
const path = require('path');
const crypto = require('crypto');

// --- SECURITY: FIELD ENCRYPTION (AES-256-CBC) ---
// Sensible Daten (2FA Secrets, Private Keys) werden verschlüsselt gespeichert.

const ENCRYPTION_KEY = process.env.DB_SECRET_KEY; // Muss 32 Zeichen lang sein!
const IV_LENGTH = 16; // AES block size

if (!ENCRYPTION_KEY || ENCRYPTION_KEY.length < 32) {
    console.error("FATAL ERROR: DB_SECRET_KEY in .env is missing or too short (must be 32+ chars).");
    process.exit(1);
}

function encrypt(text) {
    if (!text) return null;
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY.substring(0,32)), iv);
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function decrypt(text) {
    if (!text) return null;
    try {
        const textParts = text.split(':');
        const iv = Buffer.from(textParts.shift(), 'hex');
        const encryptedText = Buffer.from(textParts.join(':'), 'hex');
        const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY.substring(0,32)), iv);
        let decrypted = decipher.update(encryptedText);
        decrypted = Buffer.concat([decrypted, decipher.final()]);
        return decrypted.toString();
    } catch (e) {
        console.error("[DB] Decryption failed (Key mismatch?):", e.message);
        return null; // Im Fehlerfall lieber null zurückgeben als crashen
    }
}

// --- DATABASE CONNECTION ---

const dbPath = path.join(__dirname, 'secure_storage', 'chat.db');

const dbPromise = open({
    filename: dbPath,
    driver: sqlite3.Database
}).then(async (db) => {
    // --- PERFORMANCE TUNING (Enterprise Grade) ---
    // WAL Mode erlaubt gleichzeitiges Lesen und Schreiben (Wichtig für Skalierung)
    await db.exec('PRAGMA journal_mode = WAL;');
    // Synchronous NORMAL ist sicher genug für die meisten Server, aber viel schneller
    await db.exec('PRAGMA synchronous = NORMAL;');
    // Foreign Keys aktivieren (Datenintegrität)
    await db.exec('PRAGMA foreign_keys = ON;');

    return db;
});

// --- 1. SCHEMA INITIALIZATION ---

async function initDB() {
    const db = await dbPromise;
    console.log('[DB] Connecting to Enterprise Storage...');

    // 1. INSTITUTIONS
    await db.exec(`
        CREATE TABLE IF NOT EXISTS institutions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tag TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            email TEXT UNIQUE,
            description TEXT,
            password_hash TEXT NOT NULL,
            two_factor_secret TEXT, -- ENCRYPTED
            color TEXT DEFAULT '#00ff00',
            inbox_file TEXT,
            public_key TEXT,
            private_key TEXT,       -- ENCRYPTED
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_inst_tag ON institutions(tag);
    `);

    // 2. REGISTRATION REQUESTS
    await db.exec(`
        CREATE TABLE IF NOT EXISTS registration_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_name TEXT NOT NULL,
            org_tag TEXT NOT NULL,
            message TEXT,
            email TEXT NOT NULL UNIQUE,
            status TEXT DEFAULT 'UNVERIFIED', -- UNVERIFIED, PENDING, APPROVED, REJECTED
            verification_code TEXT,
            request_date DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_req_email ON registration_requests(email);
        CREATE INDEX IF NOT EXISTS idx_req_status ON registration_requests(status);
    `);

    // 3. INVITE TOKENS
    await db.exec(`
        CREATE TABLE IF NOT EXISTS invite_tokens (
            token TEXT PRIMARY KEY,
            approved_email TEXT NOT NULL,
            org_name_suggestion TEXT,
            is_used BOOLEAN DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_tokens_token ON invite_tokens(token);
    `);

    // 4. BLOGS
    await db.exec(`
        CREATE TABLE IF NOT EXISTS system_blogs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT,
            content TEXT NOT NULL,
            author_tag TEXT NOT NULL,
            author_name TEXT NOT NULL,
            tags TEXT, -- JSON Array
            attachment_data TEXT, -- JSON Object
            is_important INTEGER DEFAULT 0,
            password TEXT, -- Optionaler Schutz
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_blog_created ON system_blogs(created_at DESC);
    `);

    // 5. THE WIRE (Posts)
    await db.exec(`
        CREATE TABLE IF NOT EXISTS wire_posts (
            id TEXT PRIMARY KEY,
            author_name TEXT,
            author_key TEXT,
            content TEXT,
            tags TEXT, -- JSON Array
            created_at INTEGER,
            expires_at INTEGER,
            max_expires_at INTEGER,
            fuelers TEXT, -- JSON Array
            discussion_id TEXT,
            attachment TEXT -- JSON Object
        );
        CREATE INDEX IF NOT EXISTS idx_wire_expires ON wire_posts(expires_at);
        CREATE INDEX IF NOT EXISTS idx_wire_created ON wire_posts(created_at DESC);
    `);

    // 6. THE WIRE (Comments)
    await db.exec(`
        CREATE TABLE IF NOT EXISTS wire_comments (
            id TEXT PRIMARY KEY,
            post_id TEXT,
            author_name TEXT,
            author_key TEXT,
            content TEXT,
            timestamp INTEGER,
            FOREIGN KEY(post_id) REFERENCES wire_posts(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_comments_post ON wire_comments(post_id);
    `);

    // 7. VIPS
    await db.exec(`
        CREATE TABLE IF NOT EXISTS vips (
            handle TEXT PRIMARY KEY,
            display_name TEXT,
            public_key TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_vip_handle ON vips(handle);
    `);

    console.log('[DB] Schema synchronized. Encryption Active. WAL Mode Active.');
}

// --- 2. CORE FUNCTIONS (SECURE) ---

async function createInstitution(tag, name, plainPassword, twoFactorSecret, color) {
    const db = await dbPromise;
    const saltRounds = 10;
    const hash = await bcrypt.hash(plainPassword, saltRounds);
    const inboxFile = `inbox_${tag.toLowerCase()}.json`;

    // RSA Keypair generieren
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });

    // --- ENCRYPTION STEP ---
    const encrypted2FA = encrypt(twoFactorSecret);
    const encryptedPrivKey = encrypt(privateKey);

    try {
        await db.run(`
            INSERT INTO institutions (tag, name, password_hash, two_factor_secret, color, inbox_file, public_key, private_key)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `, [tag, name, hash, encrypted2FA, color, inboxFile, publicKey, encryptedPrivKey]);

        console.log(`[DB] Institution [${tag}] created (Secure).`);
        return true;
    } catch (e) {
        console.error(`[DB] Error creating ${tag}:`, e.message);
        return false;
    }
}

async function getInstitutionByTag(tag) {
    const db = await dbPromise;
    const row = await db.get('SELECT * FROM institutions WHERE tag = ?', [tag]);

    if (row) {
        // --- DECRYPTION STEP ---
        // Wir entschlüsseln die Daten on-the-fly, bevor wir sie zurückgeben
        row.two_factor_secret = decrypt(row.two_factor_secret);
        row.private_key = decrypt(row.private_key);
    }
    return row;
}

// Passwort Verify bleibt gleich (Hash Vergleich)
async function verifyPassword(inputPassword, storedHash) {
    return await bcrypt.compare(inputPassword, storedHash);
}

// --- REQUESTS & TOKENS ---

async function createRequest(orgName, orgTag, message, email, verifyCode) {
    const db = await dbPromise;
    try {
        // Transaction: Sicherstellen, dass alte Requests gelöscht werden bevor neue kommen
        await db.run('BEGIN');
        await db.run("DELETE FROM registration_requests WHERE email = ?", [email]);
        await db.run(`
            INSERT INTO registration_requests (org_name, org_tag, message, email, verification_code)
            VALUES (?, ?, ?, ?, ?)
        `, [orgName, orgTag, message, email, verifyCode]);
        await db.run('COMMIT');
        return true;
    } catch(e) {
        await db.run('ROLLBACK');
        console.error("[DB] Create Request Failed:", e);
        return false;
    }
}

async function verifyRequestEmail(email, code) {
    const db = await dbPromise;
    const req = await db.get("SELECT * FROM registration_requests WHERE email = ?", [email]);

    if (!req) return { success: false, msg: "Email not found." };
    if (req.status !== 'UNVERIFIED') return { success: false, msg: "Already verified/processed." };
    if (req.verification_code !== code) return { success: false, msg: "Wrong code." };

    await db.run("UPDATE registration_requests SET status = 'PENDING' WHERE email = ?", [email]);
    return { success: true };
}

async function getPendingRequests() {
    const db = await dbPromise;
    return await db.all("SELECT * FROM registration_requests WHERE status = 'PENDING' ORDER BY request_date ASC");
}

async function getRequestById(id) {
    const db = await dbPromise;
    return await db.get("SELECT * FROM registration_requests WHERE id = ?", [id]);
}

async function updateRequestStatus(id, status) {
    const db = await dbPromise;
    await db.run("UPDATE registration_requests SET status = ? WHERE id = ?", [status, id]);
}

async function createInviteToken(token, approvedEmail, orgNameSuggestion) {
    const db = await dbPromise;
    try {
        await db.run(`
            INSERT INTO invite_tokens (token, approved_email, org_name_suggestion)
            VALUES (?, ?, ?)
        `, [token, approvedEmail, orgNameSuggestion]);
        return true;
    } catch(e) { return false; }
}

async function getInviteToken(token) {
    const db = await dbPromise;
    return await db.get("SELECT * FROM invite_tokens WHERE token = ? AND is_used = 0", [token]);
}

async function markTokenUsed(token) {
    const db = await dbPromise;
    await db.run("UPDATE invite_tokens SET is_used = 1 WHERE token = ?", [token]);
}

async function getPublicInstitutionList() {
    const db = await dbPromise;
    return await db.all("SELECT tag, name, description, color FROM institutions ORDER BY tag ASC");
}

async function updateInstitutionDescription(tag, newDescription) {
    const db = await dbPromise;
    try {
        await db.run("UPDATE institutions SET description = ? WHERE tag = ?", [newDescription, tag]);
        return true;
    } catch (e) { return false; }
}

// --- BLOG SYSTEM ---

async function createBlogPost(data) {
    const db = await dbPromise;
    await db.run(`
        INSERT INTO system_blogs (title, content, author_tag, author_name, tags, attachment_data, is_important, password)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `, [
        data.title,
        data.content,
        data.authorTag,
        data.authorName,
        JSON.stringify(data.tags || []),
        JSON.stringify(data.attachment || null),
        data.important ? 1 : 0,
        data.password || null
    ]);
}

async function getBlogPosts() {
    const db = await dbPromise;
    const rows = await db.all("SELECT * FROM system_blogs ORDER BY created_at DESC LIMIT 50");
    return rows.map(row => ({
        id: row.id,
        title: row.title,
        content: row.content,
        author: row.author_name,
        author_tag: row.author_tag,
        tags: JSON.parse(row.tags || '[]'),
        attachment: JSON.parse(row.attachment_data || 'null'),
        important: row.is_important === 1,
        password: row.password,
        timestamp: row.created_at
    }));
}

async function getBlogPostById(id) {
    const db = await dbPromise;
    const row = await db.get("SELECT * FROM system_blogs WHERE id = ?", [id]);
    if (!row) return null;
    return {
        id: row.id,
        title: row.title,
        content: row.content,
        author: row.author_name,
        author_tag: row.author_tag,
        tags: JSON.parse(row.tags || '[]'),
        attachment: JSON.parse(row.attachment_data || 'null'),
        important: row.is_important === 1,
        password: row.password,
        timestamp: row.created_at
    };
}

async function updateBlogPost(id, data) {
    const db = await dbPromise;
    await db.run(`
        UPDATE system_blogs 
        SET title = ?, content = ?, tags = ?, attachment_data = ?, is_important = ?, password = ?
        WHERE id = ?
    `, [
        data.title,
        data.content,
        JSON.stringify(data.tags || []),
        JSON.stringify(data.attachment || null),
        data.important ? 1 : 0,
        data.password || null,
        id
    ]);
}

async function deleteBlogPost(id) {
    const db = await dbPromise;
    await db.run("DELETE FROM system_blogs WHERE id = ?", [id]);
}

// --- THE WIRE (Optimized) ---

async function createWirePost(post) {
    const db = await dbPromise;
    await db.run(`
        INSERT INTO wire_posts (
            id, author_name, author_key, content, tags,
            created_at, expires_at, max_expires_at, fuelers, discussion_id, attachment
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, [
        post.id,
        post.authorName,
        post.authorKey,
        post.content,
        JSON.stringify(post.tags),
        post.createdAt,
        post.expiresAt,
        post.maxExpiresAt,
        JSON.stringify([]),
        null,
        post.attachment ? JSON.stringify(post.attachment) : null
    ]);
}

async function getActiveWirePosts() {
    const db = await dbPromise;
    const now = Date.now();

    // 1. Lösche abgelaufene Posts (Autoburn)
    await db.run('DELETE FROM wire_posts WHERE expires_at < ?', [now]);

    // 2. Hole aktive Posts (Mit Index geht das schnell)
    const rows = await db.all('SELECT * FROM wire_posts ORDER BY created_at DESC');

    // 3. Hole Kommentare Counts (Optimierte Subquery könnte hier besser sein, aber so ists ok für SQLite)
    const enrichedRows = [];
    for (const row of rows) {
        const count = await getCommentCount(row.id);
        enrichedRows.push({
            id: row.id,
            authorName: row.author_name,
            authorKey: row.author_key,
            content: row.content,
            tags: JSON.parse(row.tags || '[]'),
            createdAt: row.created_at,
            expiresAt: row.expires_at,
            maxExpiresAt: row.max_expires_at,
            fuelers: JSON.parse(row.fuelers || '[]'),
            discussionId: row.discussion_id,
            commentCount: count,
            attachment: row.attachment ? JSON.parse(row.attachment) : null
        });
    }
    return enrichedRows;
}

async function updateWirePost(post) {
    const db = await dbPromise;
    await db.run(`
        UPDATE wire_posts SET 
            expires_at = ?,
            fuelers = ?,
            discussion_id = ?
        WHERE id = ?
    `, [
        post.expiresAt,
        JSON.stringify(post.fuelers),
        post.discussionId,
        post.id
    ]);
}

async function addWireComment(data) {
    const db = await dbPromise;
    await db.run(`
        INSERT INTO wire_comments (id, post_id, author_name, author_key, content, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)
    `, [data.id, data.postId, data.authorName, data.authorKey, data.content, Date.now()]);
}

async function getWireComments(postId) {
    const db = await dbPromise;
    // Dank Index auf post_id ist das sehr schnell
    return await db.all('SELECT * FROM wire_comments WHERE post_id = ? ORDER BY timestamp ASC', [postId]);
}

async function getCommentCount(postId) {
    const db = await dbPromise;
    const result = await db.get('SELECT COUNT(*) as count FROM wire_comments WHERE post_id = ?', [postId]);
    return result ? result.count : 0;
}

async function cleanupOrphanedComments() {
    const db = await dbPromise;
    // Dank Foreign Key Constraint (ON DELETE CASCADE) passiert das eigentlich automatisch,
    // aber als Backup lassen wir es drin.
    await db.run(`
        DELETE FROM wire_comments 
        WHERE post_id NOT IN (SELECT id FROM wire_posts)
    `);
}

// --- VIP SYSTEM ---

async function addVip(handle, displayName, publicKey) {
    const db = await dbPromise;
    try {
        await db.run(
            `INSERT INTO vips (handle, display_name, public_key) VALUES (?, ?, ?)`,
            [handle, displayName, publicKey]
        );
        return true;
    } catch (e) {
        console.error("Error adding VIP:", e);
        return false;
    }
}

async function getVipByHandle(handle) {
    const db = await dbPromise;
    return await db.get('SELECT * FROM vips WHERE handle = ?', [handle]);
}

module.exports = {
    initDB,
    // Institutions
    createInstitution,
    getInstitutionByTag,
    verifyPassword,
    getPublicInstitutionList,
    updateInstitutionDescription,
    // Requests
    createRequest,
    verifyRequestEmail,
    getPendingRequests,
    getRequestById,
    updateRequestStatus,
    // Tokens
    createInviteToken,
    getInviteToken,
    markTokenUsed,
    // Blog
    createBlogPost,
    getBlogPosts,
    getBlogPostById,
    deleteBlogPost,
    updateBlogPost,
    // Wire
    createWirePost,
    getActiveWirePosts,
    updateWirePost,
    addWireComment,
    getWireComments,
    cleanupOrphanedComments,
    // VIP
    addVip,
    getVipByHandle
};