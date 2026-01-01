// database.js - Persistence Layer & Key Management
const sqlite3 = require('sqlite3').verbose();
const { open } = require('sqlite');
const bcrypt = require('bcrypt');
const path = require('path');
const crypto = require('crypto');

// --- WICHTIG: EINE ZENTRALE VERBINDUNG ---
// Wir definieren das Promise global, damit ALLE Funktionen (auch addVip) darauf zugreifen können.
const dbPromise = open({
    filename: path.join(__dirname, 'secure_storage', 'chat.db'),
    driver: sqlite3.Database
});

// --- 1. DATENBANK INIT ---
async function initDB() {
    // Wir warten auf die oben definierte Verbindung
    const db = await dbPromise;

    console.log('[DB] Connected to SQLite Storage.');

    // Institutionen Tabelle
    await db.exec(`
        CREATE TABLE IF NOT EXISTS institutions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tag TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            email TEXT UNIQUE,
            description TEXT,
            password_hash TEXT NOT NULL,
            two_factor_secret TEXT,
            color TEXT DEFAULT '#00ff00',
            inbox_file TEXT,
            public_key TEXT,
            private_key TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    `);

    // Tabelle für Bewerbungen
    await db.exec(`
        CREATE TABLE IF NOT EXISTS registration_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_name TEXT NOT NULL,
            org_tag TEXT NOT NULL,
            message TEXT,
            email TEXT NOT NULL UNIQUE,
            status TEXT DEFAULT 'UNVERIFIED',
            verification_code TEXT,
            request_date DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    `);

    // Tabelle für Einladungen
    await db.exec(`
        CREATE TABLE IF NOT EXISTS invite_tokens (
            token TEXT PRIMARY KEY,
            approved_email TEXT NOT NULL,
            org_name_suggestion TEXT,
            is_used BOOLEAN DEFAULT 0
        );
    `);

    // Blog
    await db.exec(`
        CREATE TABLE IF NOT EXISTS system_blogs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT,
            content TEXT NOT NULL,
            author_tag TEXT NOT NULL,
            author_name TEXT NOT NULL,
            tags TEXT,
            attachment_data TEXT,
            is_important INTEGER DEFAULT 0,
            password TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    `);

    // The Wire Posts
    await db.exec(`
        CREATE TABLE IF NOT EXISTS wire_posts (
            id TEXT PRIMARY KEY,
            author_name TEXT,
            author_key TEXT,
            content TEXT,
            tags TEXT,
            created_at INTEGER,
            expires_at INTEGER,
            max_expires_at INTEGER,
            fuelers TEXT,
            discussion_id TEXT,
            attachment TEXT
        )
    `);

    // The Wire Comments
    await db.exec(`
        CREATE TABLE IF NOT EXISTS wire_comments (
            id TEXT PRIMARY KEY,
            post_id TEXT,
            author_name TEXT,
            author_key TEXT,
            content TEXT,
            timestamp INTEGER
        )
    `);

    // VIP TABLE (Das neue Feature!)
    await db.exec(`
        CREATE TABLE IF NOT EXISTS vips (
            handle TEXT PRIMARY KEY,
            display_name TEXT,
            public_key TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    `);

    console.log('[DB] Schema synchronized (Keys enabled).');
}

// --- 2. CORE FUNCTIONS ---

async function createInstitution(tag, name, plainPassword, twoFactorSecret, color) {
    const db = await dbPromise; // Zugriff auf globale Verbindung
    const saltRounds = 10;
    const hash = await bcrypt.hash(plainPassword, saltRounds);
    const inboxFile = `inbox_${tag.toLowerCase()}.json`;

    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });

    try {
        await db.run(`
            INSERT INTO institutions (tag, name, password_hash, two_factor_secret, color, inbox_file, public_key, private_key)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `, [tag, name, hash, twoFactorSecret, color, inboxFile, publicKey, privateKey]);

        console.log(`[DB] Institution [${tag}] created.`);
        return true;
    } catch (e) {
        console.error(`[DB] Error creating ${tag}:`, e.message);
        return false;
    }
}

async function getInstitutionByTag(tag) {
    const db = await dbPromise;
    return await db.get('SELECT * FROM institutions WHERE tag = ?', [tag]);
}

async function verifyPassword(inputPassword, storedHash) {
    return await bcrypt.compare(inputPassword, storedHash);
}

async function createRequest(orgName, orgTag, message, email, verifyCode) {
    const db = await dbPromise;
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
    const db = await dbPromise;
    const req = await db.get("SELECT * FROM registration_requests WHERE email = ?", [email]);

    if (!req) return { success: false, msg: "Email not found." };
    if (req.status !== 'UNVERIFIED') return { success: false, msg: "Already verified." };
    if (req.verification_code !== code) return { success: false, msg: "Wrong code." };

    await db.run("UPDATE registration_requests SET status = 'PENDING' WHERE email = ?", [email]);
    return { success: true };
}

async function getPendingRequests() {
    const db = await dbPromise;
    return await db.all("SELECT * FROM registration_requests WHERE status = 'PENDING'");
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
    } catch (e) {
        return false;
    }
}

// --- BLOG ---

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
    const rows = await db.all("SELECT * FROM system_blogs ORDER BY id DESC LIMIT 50");
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

// --- WIRE ---

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

    await db.run('DELETE FROM wire_posts WHERE expires_at < ?', [now]);

    const rows = await db.all('SELECT * FROM wire_posts ORDER BY created_at DESC');
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
    return await db.all('SELECT * FROM wire_comments WHERE post_id = ? ORDER BY timestamp ASC', [postId]);
}

async function getCommentCount(postId) {
    const db = await dbPromise;
    const result = await db.get('SELECT COUNT(*) as count FROM wire_comments WHERE post_id = ?', [postId]);
    return result ? result.count : 0;
}

async function cleanupOrphanedComments() {
    const db = await dbPromise;
    await db.run(`
        DELETE FROM wire_comments 
        WHERE post_id NOT IN (SELECT id FROM wire_posts)
    `);
}

// --- VIP SYSTEM (NEU) ---

async function addVip(handle, displayName, publicKey) {
    const db = await dbPromise; // Greift auf die globale Variable zu
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
    try {
        return await db.get('SELECT * FROM vips WHERE handle = ?', [handle]);
    } catch (e) {
        console.error("Error getting VIP:", e);
        return null;
    }
}

module.exports = {
    initDB,
    createInstitution,
    getInstitutionByTag,
    verifyPassword,
    createRequest,
    verifyRequestEmail,
    getPendingRequests,
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
    deleteBlogPost,
    updateBlogPost,
    createWirePost,
    getActiveWirePosts,
    updateWirePost,
    addWireComment,
    getWireComments,
    cleanupOrphanedComments,
    // NEU
    addVip,
    getVipByHandle
};