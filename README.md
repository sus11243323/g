# Private Invite-Only Forum

A polished Node.js invite-only forum with Google OAuth sign-in, single-use invites, a member dashboard, searchable/categorized posts, likes, member directory, and admin controls.

## Requirements
- Node.js 20+
- A Google Cloud project with OAuth consent configured
- HTTPS when deployed publicly

## Local setup (Windows PowerShell)
1. Extract the ZIP and open PowerShell in this folder.
2. Install dependencies:
   ```powershell
   npm install
   ```
3. Copy `.env.example` to `.env` and edit it:
   ```powershell
   Copy-Item .env.example .env
   notepad .env
   ```
4. In Google Cloud Console, create an OAuth Client ID of type **Web application**.
   - Authorized JavaScript origins: `http://localhost:3000`
   - Authorized redirect URI: `http://localhost:3000/auth/google/callback`
   - Put the Client ID and Client Secret in `.env`.
   - For public deployment, add your real HTTPS origin and callback URI to Google Cloud too.
5. Set a long random `SESSION_SECRET`. Set `ADMIN_EMAILS` to the Google email address that will administer the forum.
6. Start the server:
   ```powershell
   npm start
   ```
7. In a second PowerShell window, create a single-use invite (default expiry 7 days):
   ```powershell
   npm run invite
   ```
   Optional expiry hours: `npm run invite -- 24`
8. Open the printed invite URL in your browser. The invite recipient clicks **Continue with Google** and, after successful verification, becomes a member. The invitation is consumed after the account is accepted.

## Admin
- The email(s) in `ADMIN_EMAILS` can create invitation links in the forum sidebar and delete posts.
- Each invite can be used once and expires after the chosen duration (1–720 hours).
- `forum.sqlite` stores member records, hashed invitation tokens, and posts. Back it up securely.

## Deploying
Use a Node.js host that supports a persistent disk/volume for `forum.sqlite`. Set environment variables from `.env` in the host dashboard. Set `BASE_URL` to the public HTTPS URL, configure Google OAuth redirect URI as `${BASE_URL}/auth/google/callback`, and set `COOKIE_SECURE=true`. If the host's filesystem is ephemeral, configure persistent storage or the database/invites will be lost on redeploy.

## Security notes
- This project uses Google's OAuth flow; it never asks for or stores Google passwords.
- The invitation token is stored as a SHA-256 hash in SQLite and the invite is single-use.
- Anyone holding an invite URL can use it once, so share it privately.
- Before a large/public launch, add CSRF protection to all state-changing form routes, email verification/abuse controls, backups, and a production-grade persistent session store (the default Express MemoryStore is only suitable for a small demo).
- Use your own branding and do not present this as an official Google, Steam, or VACNet service.
