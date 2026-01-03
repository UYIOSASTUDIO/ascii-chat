// socket_handlers/auth.js
const speakeasy = require('speakeasy');
const crypto = require('crypto');
const db = require('../database');
const mailer = require('../mailer');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcrypt'); // Falls für HQ PW Verify nötig
const { sanitize } = require('../utils/sanitizer');
const { serverLog, serverError } = require('../utils/logger');

// --- KONFIGURATION LADEN ---
const publicVapidKey = process.env.VAPID_PUBLIC_KEY;
const DATA_DIR = path.join(__dirname, '../secure_storage'); // Pfad anpassen (../)

// Admin Secret neu generieren/laden (Kopie aus server.js Logic)
const myFixedSecret = process.env.ADMIN_SECRET;
const adminSecret = {
    base32: myFixedSecret,
    // otpauth_url brauchen wir hier nicht zwingend für den Verify
};

// --- HELPER FUNKTIONEN (Lokal oder Importieren) ---
// Wir brauchen diese Funktion hier, also definieren wir sie lokal oder lagern sie in utils aus.
// Für jetzt kopieren wir sie kurz rein, um Fehler zu vermeiden.
function broadcastInstitutionUpdate(io, state, userId) {
    const user = state.users[userId];
    if (!user || !user.institution) return;

    const updatePacket = {
        key: user.key,
        username: user.username,
        tag: user.institution.tag,
        color: user.institution.color
    };

    // 1. An alle Private Partners
    if(user.partners) {
        user.partners.forEach(pid => {
            io.to(pid).emit('user_institution_update', updatePacket);
        });
    }

    // 2. An aktuelle Gruppe
    if (user.currentGroup) {
        io.to(`group_${user.currentGroup}`).emit('user_institution_update', updatePacket);
    }

    // 3. An Public Room
    if (user.currentPub) {
        io.to(`pub_${user.currentPub}`).emit('user_institution_update', updatePacket);
    }
}

// =================================================================
// MAIN HANDLER
// =================================================================

module.exports = (io, socket, state) => {

    // 1. REGISTRIERUNG
    socket.on('register', (usernameInput) => { // Umbenannt zu usernameInput für Klarheit

        // 1. INPUT SANITIZATION (XSS Schutz für Namen)
        // Wir erlauben kein HTML im Namen!
        if (!usernameInput || typeof usernameInput !== 'string') return;
        const username = sanitize(usernameInput, 20);
        // Ab hier arbeiten wir nur noch mit dem sauberen 'username' weiter

        // --- VALIDIERUNG ---
        if (username.startsWith('/') || username.length === 0 || username.length > 20) {
            socket.emit('system_message', 'REGISTRATION ERROR: Invalid username format.');
            return;
        }

        // --- NEU: RESERVIERTER NAME CHECK ---
        if (username.toLowerCase() === 'anonymous') {
            socket.emit('system_message', 'REGISTRATION ERROR: "Anonymous" is reserved for Stealth Mode.');
            return;
        }
        // ------------------------------------

        const uniqueKey = Math.random().toString(36).substring(2, 8).toUpperCase();

        // IP & User-Agent auslesen (für /info Befehl)
        let clientIp = socket.handshake.address;
        if (clientIp.substr(0, 7) == "::ffff:") {
            clientIp = clientIp.substr(7);
        }
        const userAgent = socket.request.headers['user-agent'] || 'Unknown Device';

        state.users[socket.id] = {
            id: socket.id,
            username: username,
            key: uniqueKey,
            partners: [],
            loginTime: new Date(),
            isGhost: false,
            ip: clientIp,
            device: userAgent
        };

        // ANONYM: Keine Namen oder Keys im Log!
        serverLog('Neuer User im System registriert (Daten maskiert).');

        socket.emit('registered', {
            key: uniqueKey,
            username: username,
            vapidPublicKey: publicVapidKey // <--- WICHTIG: Client braucht den Key
        });
    });

    // --- PROFILE UPDATE (Name & Bio) ---
    socket.on('update_profile', (data) => {
        const user = state.users[socket.id];
        if (!user) return;

        const cleanName = sanitize(data.username, 20);
        const cleanBio = sanitize(data.bio, 100);

        if (cleanName.length > 0) {
            const oldName = user.username;
            user.username = cleanName;

            // Wenn User Teil einer Institution ist, Tag behalten!
            if (user.institution) {
                user.username = `[${user.institution.tag}] ${cleanName}`;
                user.originalName = cleanName; // Basis-Name speichern
            }

            // Bio speichern (neu)
            user.bio = cleanBio;

            serverLog(`User ${oldName} hat sich umbenannt in ${user.username}`);

            // Optional: Broadcast an Räume, dass sich der Name geändert hat?
            // Fürs erste reicht es, wenn es bei neuen Nachrichten verwendet wird.
        }
    });

    // --- SETUP WIZARD (Token einlösen) ---

    // --- 3. SETUP FLOW (Erweitert) ---

    // Start
    socket.on('setup_init', async (token) => {
        const tokenData = await db.getInviteToken(token);
        if (!tokenData) {
            socket.emit('system_message', 'ERROR: Invalid Token.');
            return;
        }

        // Metadaten parsen (Name & Tag aus der Bewerbung)
        let prefill = { name: 'Unknown', tag: 'TAG' };
        try { prefill = JSON.parse(tokenData.org_name_suggestion); } catch(e) { prefill.name = tokenData.org_name_suggestion; }

        setupSessions[socket.id] = {
            token: token,
            email: tokenData.approved_email,
            data: prefill, // Speichern wir hier
            step: 'CONFIRM'
        };

        socket.emit('setup_prompt', {
            step: 'CONFIRM',
            msg: `TOKEN ACCEPTED. \nRegistered Name: ${prefill.name}\nRegistered ID: ${prefill.tag}\n\nType 'yes' to confirm or 'edit' to change details.`
        });
    });

    // Bestätigen oder Editieren
    socket.on('setup_step_confirm', async (input) => {
        const session = setupSessions[socket.id];
        if (!session || session.step !== 'CONFIRM') return;

        if (input.toLowerCase() === 'yes') {
            session.step = 'DESC';
            socket.emit('setup_prompt', { step: 'DESC', msg: 'Details confirmed. \nEnter a public description for your institution:' });
        } else if (input.toLowerCase() === 'edit') {
            session.step = 'EDIT_NAME';
            socket.emit('setup_prompt', { step: 'EDIT_NAME', msg: 'Enter new Institution Name:' });
        } else {
            socket.emit('setup_prompt', { step: 'CONFIRM', msg: "Type 'yes' or 'edit'.", error: true });
        }
    });

    // Falls Edit: Name
    socket.on('setup_step_edit_name', (name) => {
        const session = setupSessions[socket.id];
        if (session.step !== 'EDIT_NAME') return;
        session.data.name = name;
        session.step = 'EDIT_TAG';
        socket.emit('setup_prompt', { step: 'EDIT_TAG', msg: 'Enter new Agency ID (TAG):' });
    });

    // Falls Edit: Tag
    socket.on('setup_step_edit_tag', (tag) => {
        const session = setupSessions[socket.id];
        if (session.step !== 'EDIT_TAG') return;
        session.data.tag = tag.toUpperCase();
        session.step = 'DESC';
        socket.emit('setup_prompt', { step: 'DESC', msg: 'Updated. Enter public description:' });
    });

    // Beschreibung
    socket.on('setup_step_desc', (desc) => {
        const session = setupSessions[socket.id];
        if (session.step !== 'DESC') return;
        session.data.desc = desc;
        session.step = 'PASS';
        socket.emit('setup_prompt', { step: 'PASS', msg: 'Description saved. Set your Access Password:' });
    });

    // 2. TAG WAHL
    socket.on('setup_step_tag', async (tagRaw) => {
        const session = setupSessions[socket.id];
        if (!session || session.step !== 'TAG') return;

        const tag = tagRaw.toUpperCase().replace(/[^A-Z0-9]/g, ''); // Nur Buchstaben/Zahlen

        const existing = await db.getInstitutionByTag(tag);
        if (existing) {
            socket.emit('setup_prompt', { step: 'TAG', msg: `ERROR: Tag '${tag}' is taken. Choose another:`, error: true });
            return;
        }

        session.tag = tag;
        session.step = 'PASS';
        socket.emit('setup_prompt', { step: 'PASS', msg: `Identity '${tag}' confirmed. Set your Access Password:` });
    });

    // 3. PASSWORT -> 2FA
    socket.on('setup_step_pass', async (pass) => {
        const session = setupSessions[socket.id];
        if (session.step !== 'PASS') return;

        session.password = pass;
        const secret = speakeasy.generateSecret({ length: 20, name: `SecureChat (${session.data.tag})` });
        session.tempSecret = secret.base32;
        session.step = '2FA';

        socket.emit('setup_prompt', { step: '2FA', msg: 'Scan QR / Enter Code:', secret: secret.base32 });
    });

    // 4. VERIFY & CREATE
    socket.on('setup_step_2fa_verify', async (token) => {
        const session = setupSessions[socket.id];
        if (!session || session.step !== '2FA') return;

        const verified = speakeasy.totp.verify({ secret: session.tempSecret, encoding: 'base32', token: token, window: 1 });

        if (verified) {
            const success = await db.createInstitution(
                session.data.tag,
                session.data.name,
                session.password,
                session.tempSecret,
                '#00ff00'
            );
            if (success) {
                // Beschreibung auch noch speichern!
                await db.updateInstitutionDescription(session.data.tag, session.data.desc);
                await db.markTokenUsed(session.token);
                socket.emit('setup_complete', { tag: session.data.tag });
                delete setupSessions[socket.id];
            }
        } else {
            socket.emit('setup_prompt', { step: '2FA', msg: 'Invalid Code.', error: true });
        }
    });

    // --- ADMIN AUTHENTICATION (NEU: 2-STUFIG) ---

    // STUFE 1: MASTER PASSWORT CHECK
    socket.on('admin_verify_pass', (password) => {
        // WICHTIG: Definiere das Admin-Passwort in deiner .env Datei!
        // Fallback 'admin123' nur nutzen, wenn du es vergessen hast einzutragen.
        const ADMIN_PASS = process.env.ADMIN_PASSWORD || 'admin123';

        if (password === ADMIN_PASS) {
            // Session merken: Dieser User hat das Passwort richtig, jetzt fehlt 2FA
            state.authSessions[socket.id] = {
                type: 'ADMIN_LOGIN',
                step: '2FA'
            };

            // Client auffordern, den Code einzugeben
            socket.emit('admin_step_2fa_req');
        } else {
            // Fake Delay gegen Brute Force
            setTimeout(() => {
                socket.emit('auth_fail', 'ACCESS DENIED: Invalid Administrative Credentials.');
            }, 1000);
            serverLog(`Fehlgeschlagener Admin-Passwort-Versuch von ${state.users[socket.id].username}`);
        }
    });

    // STUFE 2: TOTP (2FA) CHECK
    socket.on('admin_verify_2fa', (token) => {
        // 1. Prüfen: Hat der User überhaupt das Passwort vorher eingegeben?
        const session = state.authSessions[socket.id];

        if (!session || session.type !== 'ADMIN_LOGIN' || session.step !== '2FA') {
            socket.emit('auth_fail', 'SECURITY VIOLATION: Authentication flow bypassed.');
            return;
        }

        // 2. Code prüfen
        const verified = speakeasy.totp.verify({
            secret: adminSecret.base32,
            encoding: 'base32',
            token: token,
            window: 1
        });

        if (verified) {
            // ERFOLG!
            state.users[socket.id].isAdmin = true;
            delete state.authSessions[socket.id]; // Session aufräumen

            serverLog(`ACHTUNG: User ${state.users[socket.id].username} hat sich als GLOBAL ADMIN authentifiziert.`);
            socket.emit('admin_success', 'ROOT ACCESS GRANTED. WELCOME, OPERATOR.');

            // Optional: User-Objekt aktualisieren (Name ändern?)
            // state.users[socket.id].username = `[ROOT] ${state.users[socket.id].username}`;

        } else {
            socket.emit('system_message', 'ERROR: Invalid 2FA Code.');
        }
    });

    // --- ADMIN TOOLS ---

    // --- 2. ADMIN FLOW (Automatische Mail) ---

    // Liste anzeigen (Mit neuem Layout)
    socket.on('admin_list_requests', async () => {
        if (!state.users[socket.id] || !state.users[socket.id].isAdmin) return;

        const list = await db.getPendingRequests();
        if (list.length === 0) {
            socket.emit('system_message', 'No pending applications.');
        } else {
            socket.emit('system_message', '--- PENDING REQUESTS ---');
            list.forEach(req => {
                socket.emit('system_message', `ID: [${req.id}]`);
                socket.emit('system_message', `ORG: ${req.org_name} [${req.org_tag}]`);
                socket.emit('system_message', `MSG: "${req.message}"`);
                socket.emit('system_message', `CONTACT: ${req.email}`);
                socket.emit('system_message', `TIME: ${req.request_date}`);
                socket.emit('system_message', '------------------------');
            });
        }
    });

    // Genehmigen & Mail senden
    socket.on('admin_approve_request', async (requestId) => {
        if (!state.users[socket.id] || !state.users[socket.id].isAdmin) return;

        const req = await db.getRequestById(requestId);
        if (!req || req.status !== 'PENDING') {
            socket.emit('system_message', 'ERROR: Invalid Request ID.');
            return;
        }

        const token = 'INVITE-' + crypto.randomBytes(4).toString('hex').toUpperCase();

        // Token speichern (Wir nutzen das suggestion Feld für TAG und NAME getrennt durch | oder JSON)
        // Einfacher: Wir speichern den TAG als suggestion. Der Name ist in der Request ja auch da.
        // Wir speichern hier einfach JSON in das Feld 'org_name_suggestion' damit wir beides haben.
        const metaData = JSON.stringify({ name: req.org_name, tag: req.org_tag });

        await db.createInviteToken(token, req.email, metaData);
        await db.updateRequestStatus(requestId, 'APPROVED');

        socket.emit('system_message', `APPROVED. Generating Invite Token...`);

        // AUTOMATISCHE EMAIL SENDEN
        const sent = await mailer.sendInviteTokenEmail(req.email, token, req.org_name);

        if (sent) {
            socket.emit('system_message', `SUCCESS: Token ${token} sent to ${req.email}.`);
        } else {
            socket.emit('system_message', `WARNING: Email failed. Manual send required: ${token}`);
        }
    });

    // --- REGISTRATION FLOW ---

    // --- 1. NEUER REGISTRIERUNGS-FLOW ---

    // Antrag empfangen (Jetzt mit allen Daten)
    socket.on('register_request_submit', async (data) => {
        // data = { name, tag, msg, email }
        if (!data.email || !data.name) return;

        const code = crypto.randomBytes(3).toString('hex').toUpperCase(); // 6 Zeichen Hex

        console.log(`[REGISTER] New Request: ${data.tag} (${data.email})`);

        const success = await db.createRequest(data.name, data.tag, data.msg, data.email, code);

        if (success) {
            socket.emit('system_message', 'Encrypting payload...');
            const mailSent = await mailer.sendVerificationEmail(data.email, code);

            if (mailSent) {
                socket.emit('system_message', `Verification code dispatched to [${data.email}].`);
                socket.emit('system_message', `Execute: /verify ${data.email} [CODE]`);
            } else {
                socket.emit('system_message', 'ERROR: Mail relay failed.');
            }
        }
    });

    // Verifizierung (Bleibt fast gleich, nur neuer Befehl)
    socket.on('register_verify_submit', async (data) => {
        const result = await db.verifyRequestEmail(data.email, data.code);
        if (result.success) {
            socket.emit('system_message', 'IDENTITY VERIFIED. Application forwarded to Administrator.');
        } else {
            socket.emit('system_message', `VERIFICATION FAILED: ${result.msg}`);
        }
    });

    // --- VIP IDENTITY PROTOCOL ---

    // 1. User startet Identifizierung
    socket.on('vip_identify_init', async (data) => {
        console.log(`[VIP] Auth attempt for handle: ${data.handle}`); // LOG

        try {
            const vip = await db.getVipByHandle(data.handle);

            if (!vip) {
                console.log(`[VIP] Handle ${data.handle} not found in DB.`);
                socket.emit('system_message', 'ERROR: Identity record not found.');
                return;
            }

            const nonce = crypto.randomBytes(32).toString('hex');

            authChallenges[socket.id] = {
                handle: vip.handle,
                publicKey: vip.public_key,
                displayName: vip.display_name,
                nonce: nonce,
                ts: Date.now()
            };

            socket.emit('vip_auth_challenge', nonce);

        } catch (err) {
            console.error("[VIP] DB Error:", err);
            socket.emit('system_message', 'ERROR: Internal Identity Server Fault.');
        }
    });

    // 2. User sendet Unterschrift
    socket.on('vip_identify_verify', (signatureHex) => {
        const session = authChallenges[socket.id];
        if (!session) {
            socket.emit('system_message', 'ERROR: Auth session expired.');
            return;
        }

        try {
            const verifier = crypto.createVerify('SHA256');
            verifier.update(session.nonce);
            verifier.end();

            // --- KEY REKONSTRUKTION ---
            // Wir fügen die Header wieder hinzu und sorgen für 64-Zeichen Zeilenumbrüche (Standard PEM)
            // Node.js akzeptiert oft auch Einzeiler, aber wir machen es sauber.
            const rawBody = session.publicKey;
            const match = rawBody.match(/.{1,64}/g);
            const bodyFormatted = match ? match.join('\n') : rawBody;

            const pemKey = `-----BEGIN PUBLIC KEY-----\n${bodyFormatted}\n-----END PUBLIC KEY-----`;

            // Verifizieren
            const isValid = verifier.verify(pemKey, signatureHex, 'hex');

            if (isValid) {
                // ERFOLG!
                const user = state.users[socket.id];

                user.isVIP = true;
                user.vipHandle = session.handle;
                user.username = session.displayName;
                user.vipPrivacy = 'SILENT';

                // WICHTIG: Key überschreiben, damit der neue Name überall angezeigt wird
                user.key = session.handle;

                socket.emit('vip_login_success', {
                    handle: session.handle,
                    username: session.displayName
                });

                serverLog(`VIP LOGIN SUCCESS: ${session.handle}`);
            } else {
                console.log(`[VIP AUTH FAIL] Signature mismatch for ${session.handle}`);
                socket.emit('system_message', 'ACCESS DENIED: Cryptographic signature invalid.');
            }
        } catch (e) {
            console.error("[VIP AUTH CRASH]", e); // Das zeigt uns den wahren Fehler im Terminal!
            socket.emit('system_message', 'ERROR: Verification protocol crashed (Check Server Logs).');
        }

        delete authChallenges[socket.id];
    });

    // 3. Privacy Shield Toggle (/comms)
    socket.on('vip_privacy_toggle', (state) => {
        const user = state.users[socket.id];
        if (!user || !user.isVIP) return;

        // state: 'OPEN' oder 'SILENT'
        user.vipPrivacy = state;
        const color = state === 'OPEN' ? '#0f0' : '#f00';
        socket.emit('system_message', `COMMS STATUS: <span style="color:${color}">${state}</span>. Incoming requests are ${state === 'OPEN' ? 'ALLOWED' : 'BLOCKED'}.`);
    });

    // --- FILE SYSTEM AUTHENTIFIZIERUNG ---
    // --- FS LOGIN (FILESYSTEM) ---
    socket.on('fs_login', (data) => {
        const rawName = (data && data.username) ? String(data.username) : 'Anonymous';
        socket.username = sanitize(rawName); // Nutzung von sanitize!

        // Gruppen Logik
        if (data && data.groups && Array.isArray(data.groups)) {
            data.groups.forEach(roomName => {
                if (typeof roomName !== 'string') return;

                if (roomName.startsWith('group_')) {
                    const groupId = roomName.replace('group_', '');
                    const group = state.privateGroups[groupId]; // <--- state.privateGroups

                    const isLegitMember = group && group.members.some(memberSocketId => {
                        const u = state.users[memberSocketId]; // <--- state.users
                        return u && u.username === socket.username;
                    });

                    if (isLegitMember) socket.join(roomName);
                }
                else if (roomName.startsWith('pub_')) {
                    socket.join(roomName);
                }
            });
        }

        // Name Update in Shares
        if (state.activeShares && state.activeShares[socket.id]) { // <--- state.activeShares
            state.activeShares[socket.id].username = socket.username;
            io.emit('fs_update_shares', state.activeShares); // <--- Manuelles Update
        }
    });

    // --- HQ SYSTEM (SECURE DROP) ---

    // --- SECURE AUTHENTICATION FLOW (3-STAGE) ---

    // 1. AUTH START (Fix & Debug Version)
    socket.on('auth_init', async (tagRaw) => {
        if (!tagRaw) return;

        // WICHTIG: .trim() entfernt versehentliche Leerzeichen am Anfang/Ende
        const tag = tagRaw.trim().toUpperCase();

        console.log(`[AUTH] Login attempt for TAG: '${tag}'`);

        try {
            const inst = await db.getInstitutionByTag(tag);

            if (inst) {
                console.log(`[AUTH] Institution found: ${inst.name} (ID: ${inst.id})`);

                state.authSessions[socket.id] = {
                    step: 'PASS',
                    targetId: inst.tag, // Wir nutzen den exakten Tag aus der DB
                    attempts: 0
                };

                // Antwort an Client senden
                socket.emit('auth_step', { step: 'PASS', msg: `UPLINK ESTABLISHED: ${inst.name}` });
            } else {
                console.log(`[AUTH] ERROR: Tag '${tag}' not found in database.`);
                socket.emit('system_message', `ERROR: CONNECTION REFUSED. Gateway [${tag}] not found.`);
            }
        } catch (err) {
            console.error('[AUTH] Critical Database Error:', err);
            socket.emit('system_message', 'ERROR: Internal Server Fault.');
        }
    });

    // STUFE 2: PASSWORT CHECK
    socket.on('auth_verify_pass', async (password) => {
        const session = state.authSessions[socket.id];
        if (!session || session.step !== 'PASS') return;

        // NEU: Hash Vergleich über DB
        const inst = await db.getInstitutionByTag(session.targetId);

        if (!inst) {
            socket.emit('auth_fail', 'CRITICAL ERROR: Agency target lost.');
            return;
        }

        // bcrypt prüft, ob "007" zum Hash "$2b$..." passt
        const isValid = await db.verifyPassword(password, inst.password_hash);

        if (isValid) {
            session.step = '2FA';
            socket.emit('auth_step', { step: '2FA', msg: 'CREDENTIALS ACCEPTED.' });
        } else {
            session.attempts++;
            if (session.attempts >= 3) {
                delete state.authSessions[socket.id];
                socket.emit('auth_fail', 'SECURITY ALERT: Too many failed attempts.');
                socket.disconnect();
            } else {
                socket.emit('system_message', `ACCESS DENIED. Invalid credentials. (${session.attempts}/3)`);
            }
        }
    });

    // STUFE 3: 2FA CHECK (Google Authenticator)
    socket.on('auth_verify_2fa', async (token) => {
        const session = state.authSessions[socket.id];
        if (!session || session.step !== '2FA') return;

        const inst = await db.getInstitutionByTag(session.targetId);

        // Prüfen mit dem Secret aus der DB
        const verified = speakeasy.totp.verify({
            secret: inst.two_factor_secret, // Snake_case beachten!
            encoding: 'base32',
            token: token,
            window: 1
        });

        if (verified) {
            // LOGIN ERFOLGREICH
            delete state.authSessions[socket.id];

            state.users[socket.id].institution = {
                tag: inst.tag,
                name: inst.name,
                color: inst.color,
                inboxFile: inst.inbox_file
            };

            // Name Logik
            if (!state.users[socket.id].originalName) {
                state.users[socket.id].originalName = state.users[socket.id].username;
            }
            const newName = `[${inst.tag}] ${state.users[socket.id].originalName}`;
            state.users[socket.id].username = newName;

            // --- DEM INTERNEN RAUM BEITRETEN ---
            const internalRoom = `INTERNAL_${inst.tag}`;
            socket.join(internalRoom);
            serverLog(`[INTERNAL] ${state.users[socket.id].username} joined channel ${internalRoom}`);

            // Inbox aus DB laden
            const inbox = await db.getInboxMessages(inst.tag);

            const tempPrivKey = inst.keys ? inst.keys.priv : "";

            // 1. ERST LOGIN BESTÄTIGEN (Damit Client den Chat erstellt)
            socket.emit('hq_login_success', {
                id: session.targetId,
                username: newName,
                inboxCount: inbox.length,
                privateKey: inst.private_key
            });

            socket.join(`HQ_${session.targetId}`);
            serverLog(`[SECURITY] AUTH SUCCESS: ${state.users[socket.id].originalName} is active as ${session.targetId}.`);

            // 2. STATUS UPDATE AN ALLE (Institution Tag setzen)
            broadcastInstitutionUpdate(socket.id);

            // --- 3. FIX: JETZT ERST DIE SYSTEM-NACHRICHTEN SENDEN ---
            // Wir nutzen setTimeout, um sicherzugehen, dass der Client den Chat fertig gebaut hat.

            setTimeout(() => {
                // A) Liste der Aktiven berechnen
                const roomMembersSet = io.sockets.adapter.rooms.get(internalRoom);
                let onlineNames = [];

                if (roomMembersSet) {
                    roomMembersSet.forEach(memberSocketId => {
                        const memberUser = state.users[memberSocketId];
                        if (memberUser) {
                            // Wir nehmen den Originalnamen, das liest sich besser in der Liste
                            onlineNames.push(memberUser.originalName || memberUser.username);
                        }
                    });
                }

                // B) NACHRICHT AN MICH: Wer ist schon da?
                socket.emit('hq_internal_msg_rcv', {
                    sender: 'SYSTEM',
                    text: `ONLINE AGENTS: [ ${onlineNames.join(', ')} ]`,
                    tag: 'SYS',
                    color: '#ffff00' // Gelb
                });

                // C) NACHRICHT AN DIE KOLLEGEN: Ich bin jetzt da! (Das wolltest du)
                socket.to(internalRoom).emit('hq_internal_msg_rcv', {
                    sender: 'SYSTEM',
                    text: `AGENT CONNECTED: ${state.users[socket.id].originalName}`,
                    tag: 'SYS',
                    color: '#00ff00' // Grün
                });

            }, 500); // 500ms Verzögerung
            // -----------------------------------------------------------

        } else {
            socket.emit('system_message', 'ERROR: Invalid 2FA Code.');
        }
    });


};