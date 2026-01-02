// socket_handlers/wire.js
const crypto = require('crypto');
const db = require('../database');
const { sanitize } = require('../utils/sanitizer'); // Nutze unseren Sanitizer!
const path = require('path');
const fs = require('fs');

// --- HELPER FUNKTIONEN ---

// Broadcast an ALLE (Wird auch in server.js genutzt)
async function broadcastWireFeed(io, state) {
    if (!io) { console.error("WIRE ERROR: 'io' missing in broadcastWireFeed"); return; }
    if (!state) { console.error("WIRE ERROR: 'state' missing in broadcastWireFeed"); return; }

    const dbPosts = await db.getActiveWirePosts();
    const sockets = await io.fetchSockets(); // <--- Hier stürzte es ab, wenn io fehlt

    for (const socket of sockets) {
        const targetUser = state.users[socket.id];

        const enrichedPosts = dbPosts.map(p => {
            const isOnline = Object.values(state.users).some(u => u.key === p.authorKey);
            return {
                ...p,
                isAuthorOnline: isOnline,
                myFuel: targetUser ? p.fuelers.includes(targetUser.key) : false
            };
        });
        socket.emit('wire_update', enrichedPosts);
    }
}

// Feed an EINEN User senden
async function sendWireFeedTo(socket, state) {
    if (!state) return; // Silent fail

    const dbPosts = await db.getActiveWirePosts();
    const targetUser = state.users[socket.id];

    const enrichedPosts = dbPosts.map(p => {
        const isOnline = Object.values(state.users).some(u => u.key === p.authorKey);
        return {
            ...p,
            isAuthorOnline: isOnline,
            myFuel: targetUser ? p.fuelers.includes(targetUser.key) : false
        };
    });

    socket.emit('wire_update', enrichedPosts);
}


// --- HANDLER ---
module.exports = {
    // 1. Der Socket-Handler für server.js
    handleWire: (io, socket, state) => {

        // --- THE WIRE (PERSISTENT VIA SQLITE) ---

        // 1. Post erstellen (Mit File Support FIX)
        socket.on('wire_post', async (data) => {
            const user = state.users[socket.id];
            if (!user) return;

            // Content Validierung
            // Wenn kein Text UND kein File da ist -> Abbruch
            if (!data.content && !data.file) return;

            if (data.content && data.content.length > 5000) return;

            let attachment = null;

            // --- DATEI VERARBEITUNG ---
            if (data.file && data.file.buffer) {
                try {
                    // 1. Größe prüfen (Backend Check)
                    const isVideo = data.file.type.startsWith('video/');
                    const limit = isVideo ? 10 * 1024 * 1024 : 4 * 1024 * 1024; // 10MB Video, 4MB Rest

                    if (data.file.size > limit) {
                        socket.emit('system_message', `ERROR: File too large (Limit: ${isVideo ? '10MB' : '4MB'}).`);
                        return;
                    }

                    // 2. Speichern
                    if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

                    const uniquePrefix = Date.now();
                    // Dateinamen säubern (Sicherheit)
                    const cleanName = data.file.name.replace(/[^a-zA-Z0-9._-]/g, '_');
                    const safeFilename = `WIRE_${uniquePrefix}_${cleanName}`;
                    const filePath = path.join(UPLOAD_DIR, safeFilename);

                    // --- DER FIX IST HIER: Buffer.from(...) ---
                    // Wir müssen den ArrayBuffer vom Client in einen Node-Buffer umwandeln
                    fs.writeFileSync(filePath, Buffer.from(data.file.buffer));

                    // 3. Metadaten erstellen
                    attachment = {
                        originalName: cleanName,
                        filename: safeFilename,
                        path: '/uploads/' + safeFilename,
                        size: data.file.size,
                        type: data.file.type,
                        isMedia: data.file.type.startsWith('image/') || data.file.type.startsWith('video/')
                    };

                } catch (err) {
                    console.error("Wire Upload Error:", err);
                    socket.emit('system_message', 'ERROR: Server upload failed.');
                    return;
                }
            }

            const newPost = {
                id: crypto.randomBytes(8).toString('hex'),
                authorName: user.username,
                authorKey: user.key,
                content: sanitize(data.content || ""),
                tags: (data.tags || []).map(t => sanitize(t)),
                createdAt: Date.now(),
                expiresAt: Date.now() + (6 * 60 * 60 * 1000),
                maxExpiresAt: Date.now() + (24 * 60 * 60 * 1000),
                attachment: attachment // <--- Wird gespeichert
            };

            // In DB speichern
            try {
                await db.createWirePost(newPost);
                broadcastWireFeed();
            } catch (e) {
                console.error("DB Error creating wire post:", e);
                socket.emit('system_message', 'ERROR: Database rejected the post.');
            }
        });

        // 2. Feed anfordern
        socket.on('wire_load_req', () => {
            sendWireFeedTo(socket);
        });

        // 3. Fuel Action
        socket.on('wire_fuel', async (postId) => {
            const user = state.users[socket.id];
            if (!user) return;

            // Post aus DB holen
            // Wir nutzen getActiveWirePosts und filtern dann im RAM (einfacher als neue SQL Query)
            const posts = await db.getActiveWirePosts();
            const post = posts.find(p => p.id === postId);

            if (post) {
                const hasFueled = post.fuelers.includes(user.key);
                const FUEL_TIME = 15 * 60 * 1000;

                if (hasFueled) {
                    post.fuelers = post.fuelers.filter(k => k !== user.key);
                    post.expiresAt -= FUEL_TIME;
                } else {
                    if (post.expiresAt < post.maxExpiresAt) {
                        post.expiresAt += FUEL_TIME;
                        post.fuelers.push(user.key);
                    }
                }

                // Zurück in DB speichern
                await db.updateWirePost(post);

                broadcastWireFeed();
            }
        });

        // 4. Kommentare laden (Wenn User auf das Icon klickt)
        socket.on('wire_get_comments_req', async (postId) => {
            const comments = await db.getWireComments(postId);
            // Wir müssen prüfen, ob die Autoren noch online sind (für das [DISCONNECTED] Label)
            const enrichedComments = comments.map(c => {
                // Online Check
                const isOnline = Object.values(state.users).some(u => u.key === c.author_key);
                return {
                    ...c,
                    isAuthorOnline: isOnline
                };
            });

            socket.emit('wire_comments_res', { postId, comments: enrichedComments });
        });

        // 5. Kommentar posten
        socket.on('wire_submit_comment', async (data) => {
            // data: { postId, content }
            const user = state.users[socket.id];
            if (!user || !data.content.trim()) return;

            const commentData = {
                id: crypto.randomBytes(8).toString('hex'),
                postId: data.postId,
                authorName: user.username,
                authorKey: user.key,
                content: sanitize(data.content)
            };

            await db.addWireComment(commentData);

            // Feed updaten (damit die Zahl hochgeht)
            broadcastWireFeed();

            // Dem User (und allen die gerade in den Comments sind) das Update schicken
            // (Einfachheitshalber laden wir neu)
            const comments = await db.getWireComments(data.postId);
            // ... (selbe Logik wie oben für Online-Status könnte man hier nutzen, oder Client lädt nach)
            io.emit('wire_comments_update', { postId: data.postId });
        });

    },

    // 2. Export der Broadcast Funktion für das Interval
    broadcastWireFeed
};