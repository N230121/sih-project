# TraceMail AI — Gmail OAuth setup

1. In Google Cloud, enable Gmail API.
2. Configure Google Auth Platform / OAuth consent screen as External and add test users.
3. Add the scope `https://www.googleapis.com/auth/gmail.readonly`.
4. Create a Web application OAuth client.
5. Add `http://localhost:3000/auth/google/callback` as an Authorized redirect URI.
6. Copy `.env.example` to `.env` and fill in GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET and SESSION_SECRET.
7. Run `npm install` then `npm start`.
8. Open `http://localhost:3000` and choose Link Your Mail.

The backend stores OAuth tokens in the server session for this demo. For production, encrypt tokens at rest, use HTTPS, secure cookies, a persistent session store, CSRF/state validation, token rotation/revocation, and least-privilege scopes.
