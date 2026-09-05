from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse, JSONResponse
from starlette.middleware.sessions import SessionMiddleware
from authlib.integrations.starlette_client import OAuth
from contextlib import asynccontextmanager

from .config import (
    GOOGLE_CLIENT_ID,
    GOOGLE_CLIENT_SECRET,
    GOOGLE_REDIRECT_URI,
    SESSION_SECRET,
    FRONTEND_URL,
)
from .database import init_db, upsert_user, get_user_by_id

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

app = FastAPI(title="TraceMail AI Backend", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_URL],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Session cookie is used to remember the logged-in TraceMail user.
app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    same_site="lax",
    https_only=False,  # Change to True when deployed over HTTPS.
)

oauth = OAuth()

oauth.register(
    name="google",
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={
        "scope": "openid email profile",
    },
)

@app.get("/")
async def root():
    return {
        "app": "TraceMail AI Backend",
        "status": "running",
        "message": "Backend is working."
    }

@app.get("/health")
async def health():
    return {"status": "ok"}

@app.get("/auth/google/login")
async def google_login(request: Request):
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        raise HTTPException(
            status_code=500,
            detail="Google OAuth is not configured. Create a .env file first."
        )

    redirect_uri = GOOGLE_REDIRECT_URI
    return await oauth.google.authorize_redirect(request, redirect_uri)

@app.get("/auth/google/callback")
async def google_callback(request: Request):
    try:
        token = await oauth.google.authorize_access_token(request)
        userinfo = token.get("userinfo")

        if not userinfo:
            userinfo = await oauth.google.parse_id_token(request, token)

        google_sub = userinfo["sub"]
        email = userinfo.get("email")
        name = userinfo.get("name", "")
        picture = userinfo.get("picture", "")

        if not email:
            raise HTTPException(
                status_code=400,
                detail="Google did not return an email address."
            )

        user = upsert_user(
            google_sub=google_sub,
            email=email,
            name=name,
            picture=picture,
        )

        request.session["user_id"] = user["id"]

        # For now we return to the frontend home page.
        # Later this can be changed to your real dashboard URL.
        return RedirectResponse(url=FRONTEND_URL)

    except Exception as exc:
        return JSONResponse(
            status_code=400,
            content={
                "error": "Google login failed",
                "detail": str(exc),
            },
        )

@app.get("/auth/me")
async def me(request: Request):
    user_id = request.session.get("user_id")

    if not user_id:
        return JSONResponse(
            status_code=401,
            content={"authenticated": False}
        )

    user = get_user_by_id(user_id)

    if not user:
        request.session.clear()
        return JSONResponse(
            status_code=401,
            content={"authenticated": False}
        )

    return {
        "authenticated": True,
        "user": user,
    }

@app.post("/auth/logout")
async def logout(request: Request):
    request.session.clear()
    return {"success": True}

# Simple role-protected example endpoint.
@app.get("/api/analyst-area")
async def analyst_area(request: Request):
    user_id = request.session.get("user_id")
    if not user_id:
        raise HTTPException(status_code=401, detail="Not logged in.")

    user = get_user_by_id(user_id)

    if user["role"] not in ("analyst", "admin"):
        raise HTTPException(
            status_code=403,
            detail="Analyst or admin role required."
        )

    return {
        "message": "You can access the analyst area.",
        "user": user,
    }
