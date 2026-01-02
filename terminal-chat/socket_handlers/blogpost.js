// socket_handlers/blogpost.js
const fs = require('fs');
const path = require('path');
const escapeHtml = require('escape-html'); // oder { sanitize } from utils nutzen
const db = require('../database');

// WICHTIG: Pfad zum Upload-Ordner definieren (gleicher wie in server.js)
const UPLOAD_DIR = path.join(__dirname, '../public/uploads');

module.exports = (io, socket, state) => {

// --- BLOG / SYSTEM LOGS SYSTEM ---

// 1. LISTE ANFORDERN (Mit Sicherheits-Filter)
    socket.on('blog_list_req', async () => {
        const user = state.users[socket.id];
        try {
            const allPosts = await db.getBlogPosts();

            // ZENSUR-LOGIK:
            const sanitized = allPosts.map(p => {
                // Wenn ein Passwort existiert UND der User kein Admin ist:
                // Inhalt löschen und Flag setzen!
                if (p.password && (!user || !user.isAdmin)) {
                    return {
                        ...p,
                        content: undefined,   // Inhalt weg!
                        attachment: undefined, // Datei weg!
                        isProtected: true,    // Signal für Client: "Zeig Passwort-Feld"
                        password: null        // Passwort-Hash nicht mitsenden!
                    };
                }
                // Sonst alles zeigen
                return p;
            });

            socket.emit('blog_list_res', sanitized);

        } catch (e) {
            console.error("Error fetching blog list:", e);
            socket.emit('system_message', 'DATABASE ERROR.');
        }
    });

// 1b. GESCHÜTZTEN INHALT ENTSPERREN
    socket.on('blog_unlock_req', async (data) => {
        // data = { id, password }
        const post = await db.getBlogPostById(data.id);

        if (!post) return socket.emit('system_message', 'ERROR: Post not found.');

        // Passwort Vergleich (Hier Klartext, für höhere Sicherheit später Hash nutzen)
        if (post.password === data.password) {
            // Erfolg: Sende den VOLLEN Post an diesen User
            socket.emit('blog_unlock_success', post);
        } else {
            socket.emit('system_message', 'ACCESS DENIED: Incorrect password.');
        }
    });

// --- BLOG SYSTEM (ADVANCED) ---

// 1. POST ERSTELLEN ODER EDITIEREN (Kugelsichere Version)
    socket.on('blog_post_req', async (data) => {
        const user = state.users[socket.id];

        console.log(`[BLOG] Incoming Request from ${user ? user.username : 'Unknown'}`); // DEBUG LOG

        // --- A) IDENTITÄT & RECHTE PRÜFEN ---
        let authorTag = 'UNKNOWN';
        let authorName = 'Anonymous';
        let isEditMode = !!data.id;

        if (user && user.isAdmin) {
            // ADMINS bekommen harte Werte
            authorTag = 'ADMIN';
            authorName = 'SYSTEM ADMINISTRATOR';
        } else if (user && user.institution) {
            // INSTITUTIONEN
            authorTag = user.institution.tag;
            // Fallback: Wenn Name fehlt, nimm den Tag
            authorName = user.institution.name || user.institution.tag || 'Unknown Agency';
        } else {
            console.log('[BLOG] Access Denied: No Admin/Institution credentials.');
            return socket.emit('system_message', 'ACCESS DENIED: Insufficient permissions.');
        }

        // --- B) VALIDIERUNG ---
        if (!data.title || !data.content) {
            socket.emit('system_message', 'ERROR: Title and Content required.');
            return;
        }

        const cleanTitle = escapeHtml(data.title);
        const cleanContent = escapeHtml(data.content);

        let cleanTags = [];
        if (Array.isArray(data.tags)) {
            cleanTags = data.tags.map(t => escapeHtml(t));
        }

        // --- C) DATEI VERARBEITUNG (Safe Check) ---
        let attachmentData = null;

        if (data.file && data.file.buffer) {
            try {
                // Check ob UPLOAD_DIR existiert, sonst Fehler vermeiden
                if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, {recursive: true});

                const originalName = data.file.name || 'file';
                const cleanName = originalName.replace(/[^a-zA-Z0-9._-]/g, '_');

                const MAX_SIZE = 10 * 1024 * 1024;
                if (data.file.size > MAX_SIZE) {
                    socket.emit('system_message', 'ERROR: File too large (Max 10MB).');
                    return;
                }

                const uniquePrefix = Date.now();
                const safeFilename = `${uniquePrefix}_${cleanName}`;
                const filePath = path.join(UPLOAD_DIR, safeFilename);
                fs.writeFileSync(filePath, data.file.buffer);

                attachmentData = {
                    originalName: cleanName,
                    filename: safeFilename,
                    path: '/uploads/' + safeFilename,
                    size: data.file.size
                };
            } catch (err) {
                console.error("Upload Error:", err);
                return socket.emit('system_message', 'ERROR: Upload protocol failed.');
            }
        } else if (data.existingAttachment) {
            attachmentData = data.existingAttachment;
        }

        try {
            // --- D) DATENBANK OPERATION ---

            if (isEditMode) {
                // UPDATE
                const oldPost = await db.getBlogPostById(data.id);
                if (!oldPost) return socket.emit('system_message', 'ERROR: Post not found in DB.');

                // Rechte Check
                let allowed = false;
                if (user.isAdmin) allowed = true;
                if (user.institution && user.institution.tag === oldPost.author_tag) allowed = true;

                if (!allowed) return socket.emit('system_message', 'ACCESS DENIED: Not your post.');

                await db.updateBlogPost(data.id, {
                    title: cleanTitle,
                    content: cleanContent,
                    tags: cleanTags,
                    attachment: attachmentData,
                    important: !!data.broadcast,
                    password: data.password // <--- HINZUFÜGEN
                });

                socket.emit('blog_action_success', 'Log entry updated.');

            } else {
                // CREATE
                // Hier prüfen wir nochmal, ob alles da ist
                console.log(`[BLOG] Creating Post: ${cleanTitle} by ${authorName} (${authorTag})`);

                await db.createBlogPost({
                    title: cleanTitle,
                    content: cleanContent,
                    authorTag: authorTag,
                    authorName: authorName,
                    tags: cleanTags,
                    attachment: attachmentData,
                    important: !!data.broadcast,
                    password: data.password // <--- HINZUFÜGEN
                });

                socket.emit('blog_action_success', 'Log entry committed.');
                if (data.broadcast) io.emit('system_message', `⚠️ NEW SYSTEM LOG: ${cleanTitle}`);
            }

            // Update an alle
            const logs = await db.getBlogPosts();
            io.emit('update_system_logs', logs);

        } catch (e) {
            console.error("[BLOG] DATABASE ERROR:", e);
            socket.emit('system_message', 'DATABASE ERROR: Check server logs.');
        }
    });


// 2. POST LÖSCHEN (Mit File Cleanup & Permission Check)
    socket.on('blog_delete_req', async (id) => {
        const user = state.users[socket.id];
        const post = await db.getBlogPostById(id);

        if (!post) {
            return socket.emit('system_message', 'ERROR: Entry not found.');
        }

        // --- RECHTE CHECK ---
        let allowed = false;
        // Admin darf alles
        if (user && user.isAdmin) allowed = true;
        // Institution darf nur eigene
        if (user && user.institution && user.institution.tag === post.author_tag) allowed = true;

        if (!allowed) {
            return socket.emit('system_message', 'ACCESS DENIED: You can only delete your own logs.');
        }

        // --- DATEI LÖSCHEN (Clean up) ---
        if (post.attachment && post.attachment.filename) {
            try {
                const filePath = path.join(UPLOAD_DIR, post.attachment.filename);
                if (fs.existsSync(filePath)) {
                    fs.unlinkSync(filePath); // Löscht Datei von der Festplatte
                }
            } catch (e) {
                console.error("File deletion error:", e);
            }
        }

        // --- DB LÖSCHEN ---
        await db.deleteBlogPost(id);

        socket.emit('blog_action_success', 'Entry purged.');
        const logs = await db.getBlogPosts();
        io.emit('update_system_logs', logs);
    });

};