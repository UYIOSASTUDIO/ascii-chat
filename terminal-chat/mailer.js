// mailer.js - E-Mail Versand System
require('dotenv').config(); // Lädt die Zugangsdaten
const nodemailer = require('nodemailer');

// 1. Transporter konfigurieren (Hier für GMAIL)
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// 2. Funktion zum Senden
async function sendVerificationEmail(targetEmail, code) {
    const mailOptions = {
        from: `"Secure Uplink" <${process.env.EMAIL_USER}>`,
        to: targetEmail,
        subject: '🔐 IDENTITY VERIFICATION REQUIRED',
        text: `
SECURE TERMINAL UPLINK
------------------------------------------------
A registration request was initiated for this email address.

VERIFICATION TOKEN:
${code}

ACTION REQUIRED:
Return to the terminal and execute:
/register verify ${targetEmail} ${code}

If you did not initiate this request, ignore this transmission.
------------------------------------------------
        `,
        html: `
            <div style="font-family: monospace; background: #000; color: #0f0; padding: 20px; border-radius: 5px;">
                <h2 style="border-bottom: 1px solid #0f0;">SECURE TERMINAL UPLINK</h2>
                <p>A registration request was initiated for this email address.</p>
                <br>
                <h1 style="color: #fff; background: #222; padding: 10px; display: inline-block;">${code}</h1>
                <br><br>
                <p><strong>ACTION REQUIRED:</strong></p>
                <p>Return to the terminal and execute:</p>
                <code style="background: #333; color: #fff; padding: 5px;">/register verify ${targetEmail} ${code}</code>
                <br><br>
                <hr style="border-color: #333;">
                <small style="color: #666;">If you did not initiate this request, ignore this transmission.</small>
            </div>
        `
    };

    try {
        const info = await transporter.sendMail(mailOptions);
        console.log(`[MAILER] Message sent: ${info.messageId}`);
        return true;
    } catch (error) {
        console.error('[MAILER] Error sending email:', error);
        return false;
    }
}

async function sendInviteTokenEmail(targetEmail, token, orgName) {
    const mailOptions = {
        from: `"Secure Uplink" <${process.env.EMAIL_USER}>`,
        to: targetEmail,
        subject: 'ACCESS GRANTED: Terminal Uplink Authorized',
        html: `
            <div style="font-family: monospace; background: #000; color: #0f0; padding: 20px;">
                <h2 style="color: #0f0; border-bottom: 1px solid #0f0;">APPLICATION APPROVED</h2>
                <p>Attention <strong>${orgName}</strong>,</p>
                <p>Your request for secure terminal access has been granted by the Administrator.</p>
                <br>
                <p><strong>YOUR ACCESS TOKEN:</strong></p>
                <h1 style="background: #222; color: #fff; padding: 10px; display: inline-block;">${token}</h1>
                <br><br>
                <p><strong>INITIALIZATION PROTOCOL:</strong></p>
                <code style="background: #333; color: #fff; padding: 5px;">/setup ${token}</code>
                <br><br>
                <hr style="border-color: #333;">
                <small>Do not share this token. It is a one-time cryptographic key.</small>
            </div>
        `
    };

    try {
        await transporter.sendMail(mailOptions);
        return true;
    } catch (error) {
        console.error('[MAILER] Error sending invite:', error);
        return false;
    }
}

module.exports = {
    sendVerificationEmail,
    sendInviteTokenEmail // <--- NICHT VERGESSEN
};