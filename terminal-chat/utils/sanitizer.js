// utils/sanitizer.js
const escapeHtml = require('escape-html');

/**
 * Reinigt Inputs von gefährlichen HTML-Tags.
 * @param {string} input - Der rohe Text vom User
 * @param {number} maxLength - Maximale Länge (optional)
 * @returns {string} - Der sichere String
 */
function sanitize(input, maxLength = 0) {
    if (typeof input !== 'string') return '';

    let clean = escapeHtml(input.trim());

    if (maxLength > 0 && clean.length > maxLength) {
        clean = clean.substring(0, maxLength);
    }

    return clean;
}

module.exports = { sanitize };