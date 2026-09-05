# TraceMail AI Backend — Google Login Starter

This is the first backend for TraceMail AI.

It currently provides:

- FastAPI backend
- Google OAuth / OpenID Connect login
- Secure server-side Google client secret storage
- Session-based TraceMail login
- SQLite user database
- Default `viewer` role
- `/auth/me` endpoint
- `/auth/logout` endpoint
- Example analyst/admin protected endpoint

## 1. Install Python

Use Python 3.10+.

Check:

```bash
python --version
```

## 2. Create a virtual environment

Windows:

```bash
python -m venv .venv
.venv\Scripts\activate
```

macOS/Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

## 3. Install packages

```bash
pip install -r requirements.txt
```

## 4. Create `.env`

Copy `.env.example` to `.env`.

Windows CMD:

```bash
copy .env.example .env
```

Then fill in:

```text
GOOGLE_CLIENT_ID=...
GOOGLE_CLIENT_SECRET=...
GOOGLE_REDIRECT_URI=http://localhost:8000/auth/google/callback
SESSION_SECRET=some-long-random-secret
FRONTEND_URL=http://localhost:5500
```

NEVER commit `.env` to GitHub.

## 5. Google Cloud configuration

Create a Google Cloud project.

Enable the Google identity/OpenID functionality needed for Google Sign-In.

Create an OAuth Client ID for a Web application.

Add this Authorized redirect URI:

```text
http://localhost:8000/auth/google/callback
```

The URI must match `GOOGLE_REDIRECT_URI` exactly.

For production, add your real HTTPS callback URI too.

## 6. Run the backend

```bash
uvicorn app.main:app --reload --port 8000
```

Open:

```text
http://localhost:8000
```

You should see:

```json
{
  "app": "TraceMail AI Backend",
  "status": "running",
  "message": "Backend is working."
}
```

## 7. Test Google Login

Open:

```text
http://localhost:8000/auth/google/login
```

Google should open.

After login/consent, Google redirects to:

```text
http://localhost:8000/auth/google/callback
```

The backend creates a TraceMail user with the default role:

```text
viewer
```

Then it redirects to your frontend.

## 8. Check logged-in user

Open:

```text
http://localhost:8000/auth/me
```

You should receive the logged-in user's basic information.

## 9. Important security rules

Do NOT put these in frontend JavaScript:

- GOOGLE_CLIENT_SECRET
- session secret
- future AI API keys
- database passwords

Do NOT commit `.env`.

Add `.env` to `.gitignore`.

## 10. Current architecture

```text
TraceMail Frontend
       |
       | HTTP
       v
TraceMail FastAPI Backend
       |
       +---- Google OAuth
       |
       +---- SQLite users
       |
       +---- Sessions
       |
       +---- Role authorization
```

## 11. What we add next

After Google login works, we should add these one at a time:

1. Connect your existing TraceMail frontend login button.
2. Proper role management for viewer / analyst / admin.
3. EML upload endpoint.
4. EML parser.
5. Investigation/case database.
6. Email security analysis.
7. AI analysis.
8. Replace the frontend's hardcoded demo data with API data.
9. Gmail read access using a separate/expanded OAuth scope.
10. Production deployment.
