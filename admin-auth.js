// Shared admin password check for every sign-up page.
//
// Only a SHA-256 fingerprint of the password is stored here, never the password itself.
// To change the password, generate a new fingerprint and paste it below:
//   printf '%s' 'your-new-password' | shasum -a 256
// (or run: read -s p && printf '%s' "$p" | shasum -a 256   to avoid it showing on screen)
//
// Note: this only hides the admin buttons from visitors. The Google Sheets script
// itself still accepts changes from anyone who knows its URL.
const ADMIN_PASSWORD_HASH = 'f46d953cbc403c2f3c40dfb3ef621d583172f9be32a8756da1c8e32050b7c0e1';

let isAdminAuthenticated = false;

async function sha256Hex(text) {
    const bytes = new TextEncoder().encode(text);
    const digest = await crypto.subtle.digest('SHA-256', bytes);
    return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Returns true once the admin has entered the correct password (asked once per page load).
async function requireAdmin(promptText) {
    if (isAdminAuthenticated) return true;
    const password = prompt(promptText || '🔒 Enter admin password:');
    if (password === null) return false;
    if ((await sha256Hex(password)) !== ADMIN_PASSWORD_HASH) {
        alert('❌ Incorrect password. Access denied.');
        return false;
    }
    isAdminAuthenticated = true;
    return true;
}
