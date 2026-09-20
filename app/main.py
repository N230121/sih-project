import json
from fastapi import FastAPI, Request, HTTPException, Depends
from pydantic import BaseModel, EmailStr
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from authlib.integrations.starlette_client import OAuth
from contextlib import asynccontextmanager

from .config import (
    GOOGLE_CLIENT_ID,
    GOOGLE_CLIENT_SECRET,
    GOOGLE_REDIRECT_URI,
    GOOGLE_GMAIL_REDIRECT_URI,
    SESSION_SECRET,
    FRONTEND_URL,
)
from .database import (
    init_db,
    create_user,
    create_google_user,
    link_google_identity,
    authenticate_user,
    get_user_by_email,
    get_user_by_id,
    get_google_token_by_user_id,
    update_google_token_for_user_id,
    validate_role,
    create_investigation,
    get_investigation_by_id,
    get_investigations_for_user,
    add_investigation_evidence,
    add_investigation_ioc,
    add_infrastructure,
    add_infrastructure,
    get_infrastructure_for_investigation,
)
from .intelligence.infrastructure import (
    extract_public_ips,
)
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from .forensic.parser import parse_email_message
from .forensic.analyzer import analyze_email

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
    https_only=True,  # Change to True when deployed over HTTPS.
)
class RegisterRequest(BaseModel):
    name: str
    email: EmailStr
    password: str
    role: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str
class GoogleRoleRequest(BaseModel):
    role: str
class InvestigationRequest(BaseModel):
    gmail_message_id: str
# ---------------------------------------------------------
# RBAC ROLE HIERARCHY
# ---------------------------------------------------------

ROLE_LEVELS = {
    "viewer": 1,
    "analyst": 2,
    "admin": 3,
}
# ---------------------------------------------------------
# AUTHENTICATION / RBAC HELPERS
# ---------------------------------------------------------

def get_current_user(request: Request):
    """
    Return the authenticated TraceMail user.

    The user ID comes from the server-side session.
    The role comes from the database.
    """

    user_id = request.session.get("user_id")

    if not user_id:
        raise HTTPException(
            status_code=401,
            detail="Not logged in."
        )

    user = get_user_by_id(user_id)

    if not user:
        request.session.clear()

        raise HTTPException(
            status_code=401,
            detail="Authentication session is invalid."
        )

    return user


def require_role(required_role: str):
    """
    Create a reusable dependency that requires
    the authenticated user to have at least
    the specified role level.
    """

    if required_role not in ROLE_LEVELS:
        raise ValueError(
            f"Invalid required role: {required_role}"
        )

    required_level = ROLE_LEVELS[required_role]

    def role_checker(user=Depends(get_current_user)):
        user_role = user.get("role")

        if user_role not in ROLE_LEVELS:
            raise HTTPException(
                status_code=403,
                detail="User has an invalid or missing role."
            )

        user_level = ROLE_LEVELS[user_role]

        if user_level < required_level:
            raise HTTPException(
                status_code=403,
                detail=f"{required_role.capitalize()} role or higher required."
            )

        return user

    return role_checker

oauth = OAuth()

# ---------------------------------------------------------
# GOOGLE LOGIN OAUTH
# ---------------------------------------------------------
# Used ONLY for signing into TraceMail.
# Do NOT request Gmail access here.
oauth.register(
    name="google_login",
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={
        "scope": "openid email profile"
    },
)


# ---------------------------------------------------------
# GOOGLE GMAIL OAUTH
# ---------------------------------------------------------
# Used ONLY when an already-authenticated TraceMail user
# chooses "Connect Gmail".
oauth.register(
    name="google_gmail",
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={
        "scope": "openid email profile https://www.googleapis.com/auth/gmail.readonly"
    },
)

@app.get("/")
async def root():
    return FileResponse("site/index.html")

@app.get("/health")
async def health():
    return {"status": "ok"}
@app.post("/auth/register")
async def register(
    request: Request,
    credentials: RegisterRequest,
):

    name = credentials.name.strip()
    email = credentials.email.strip().lower()
    password = credentials.password
    role = credentials.role.strip().lower()

    if not name:
        raise HTTPException(
            status_code=400,
            detail="Name is required."
        )

    if len(password) < 8:
        raise HTTPException(
            status_code=400,
            detail="Password must be at least 8 characters."
        )

    try:
        validate_role(role)
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc)
        )

    existing_user = get_user_by_email(email)

    if existing_user:
        raise HTTPException(
            status_code=409,
            detail="An account with this email already exists."
        )

    try:
        user = create_user(
            email=email,
            name=name,
            password=password,
            role=role,
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=409,
            detail=str(exc)
        )

    # Automatically log the newly created user in.
    request.session["user_id"] = user["id"]

    return {
        "success": True,
        "authenticated": True,
        "user": user,
    }


@app.post("/auth/login")
async def login(
    request: Request,
    credentials: LoginRequest,
):

    email = credentials.email.strip().lower()
    password = credentials.password

    user = authenticate_user(
        email=email,
        password=password,
    )

    if not user:
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password."
        )

    request.session["user_id"] = user["id"]

    return {
        "success": True,
        "authenticated": True,
        "user": user,
    }   

@app.get("/auth/google/login")
async def google_login(request: Request):

    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        raise HTTPException(
            status_code=500,
            detail="Google OAuth is not configured."
        )

    redirect_uri = GOOGLE_REDIRECT_URI

    return await oauth.google_login.authorize_redirect(
        request,
        redirect_uri,
        prompt="select_account",
    )
@app.get("/auth/google/gmail/login")
async def google_gmail_login(request: Request):

    # Gmail connection is allowed only for an already
    # authenticated TraceMail user.
    user_id = request.session.get("user_id")

    if not user_id:
        raise HTTPException(
            status_code=401,
            detail="You must be logged into TraceMail before connecting Gmail."
        )

    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        raise HTTPException(
            status_code=500,
            detail="Google OAuth is not configured."
        )

    # The email entered on the Connect Gmail page is only
    # used as a Google login hint.
    email = request.query_params.get("email", "").strip()

    redirect_uri = GOOGLE_GMAIL_REDIRECT_URI

    auth_kwargs = {
        "access_type": "offline",
        "prompt": "consent",
        "include_granted_scopes": "true",
    }

    if email:
        auth_kwargs["login_hint"] = email

    return await oauth.google_gmail.authorize_redirect(
        request,
        redirect_uri,
        **auth_kwargs,
    )
@app.get("/auth/google/gmail/callback")
async def google_gmail_callback(request: Request):

    try:

        # The user must already be authenticated in TraceMail.
        user_id = request.session.get("user_id")

        if not user_id:
            raise HTTPException(
                status_code=401,
                detail="TraceMail session is not valid."
            )

        token = await oauth.google_gmail.authorize_access_token(
            request
        )

        userinfo = token.get("userinfo")

        if not userinfo:
            userinfo = await oauth.google_gmail.parse_id_token(
                request,
                token
            )

        gmail_email = userinfo.get("email")

        if not gmail_email:
            raise HTTPException(
                status_code=400,
                detail="Google did not return the Gmail account email."
            )

        # Store the Gmail OAuth token against the CURRENT
        # TraceMail user.
        #
        # We do NOT create a new TraceMail account here.
        update_google_token_for_user_id(
            user_id=user_id,
            google_token=json.dumps(token),
        )

        return RedirectResponse(
            url=FRONTEND_URL
        )

    except Exception as exc:

        return JSONResponse(
            status_code=400,
            content={
                "error": "Gmail connection failed",
                "detail": str(exc),
            },
        )
 
@app.get("/auth/google/callback")
async def google_callback(request: Request):
    try:
        # --------------------------------------------------
        # 1. Complete Google authentication
        # --------------------------------------------------
        token = await oauth.google_login.authorize_access_token(request)

        userinfo = token.get("userinfo")

        if not userinfo:
            userinfo = await oauth.google_login.parse_id_token(
                request,
                token,
            )

        # --------------------------------------------------
        # 2. Read Google identity
        # --------------------------------------------------
        google_sub = userinfo.get("sub")
        email = userinfo.get("email")
        name = userinfo.get("name", "")
        picture = userinfo.get("picture", "")

        if not google_sub:
            raise HTTPException(
                status_code=400,
                detail="Google did not return a user ID."
            )

        if not email:
            raise HTTPException(
                status_code=400,
                detail="Google did not return an email address."
            )

        email = email.strip().lower()

        # --------------------------------------------------
        # 3. Check whether this email already exists
        # --------------------------------------------------
        existing_user = get_user_by_email(email)

        # --------------------------------------------------
        # 4. EXISTING TRACEMAIL ACCOUNT
        # --------------------------------------------------
        if existing_user:

            existing_google_sub = existing_user.get(
                "google_sub"
            )

            # The email is already connected to a
            # different Google identity.
            if (
                existing_google_sub
                and existing_google_sub != google_sub
            ):
                raise HTTPException(
                    status_code=409,
                    detail=(
                        "This email is already linked "
                        "to another Google account."
                    ),
                )

            # Existing email/password account that has
            # not yet been connected to Google.
            if not existing_google_sub:
                user = link_google_identity(
                    user_id=existing_user["id"],
                    google_sub=google_sub,
                    name=name,
                    picture=picture,
                )
            else:
                user = get_user_by_id(
                    existing_user["id"]
                )

            # Login the existing TraceMail account.
            request.session["user_id"] = user["id"]

            return RedirectResponse(
                url=FRONTEND_URL
            )

        # --------------------------------------------------
        # 5. BRAND-NEW GOOGLE ACCOUNT
        # --------------------------------------------------
        # DO NOT create the database account yet.
        #
        # Store only the Google identity temporarily.
        # The user must choose a TraceMail role first.
        # --------------------------------------------------

        request.session["pending_google_user"] = {
            "google_sub": google_sub,
            "email": email,
            "name": name,
            "picture": picture,
        }

        return RedirectResponse(
            url=f"{FRONTEND_URL}?google_role=required"
        )

    except HTTPException:
        raise

    except Exception as exc:
        return JSONResponse(
            status_code=400,
            content={
                "error": "Google login failed",
                "detail": str(exc),
            },
        )
@app.get("/auth/google/pending")
async def get_pending_google_user(request: Request):
    pending_user = request.session.get(
        "pending_google_user"
    )

    if not pending_user:
        return {
            "pending": False
        }

    return {
        "pending": True,
        "email": pending_user.get("email"),
        "name": pending_user.get("name"),
    }
@app.post("/auth/google/complete-role")
async def complete_google_role(
    request: Request,
    credentials: GoogleRoleRequest,
):
    pending_user = request.session.get(
        "pending_google_user"
    )

    if not pending_user:
        raise HTTPException(
            status_code=400,
            detail="No pending Google account setup found."
        )

    role = credentials.role.strip().lower()

    try:
        validate_role(role)
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc)
        )

    try:
        user = create_google_user(
            google_sub=pending_user["google_sub"],
            email=pending_user["email"],
            name=pending_user["name"],
            picture=pending_user["picture"],
            role=role,
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=409,
            detail=str(exc)
        )

    # Remove the temporary Google identity.
    request.session.pop(
        "pending_google_user",
        None,
    )

    # Log the newly created user in.
    request.session["user_id"] = user["id"]

    return {
        "success": True,
        "authenticated": True,
        "user": user,
    }
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
async def analyst_area(
    user=Depends(require_role("analyst"))
):
    return {
        "message": "You can access the analyst area.",
        "user": user,
    }
@app.get("/api/emails")
async def get_emails(
    user=Depends(get_current_user)
):

    user_id = user["id"]

    google_token = get_google_token_by_user_id(
        user_id
    )

    if not google_token:
        raise HTTPException(
            status_code=401,
            detail="Google account is not connected."
        )

    token_data = json.loads(
        google_token
    )

    credentials = Credentials(
        token=token_data.get("access_token"),
        refresh_token=token_data.get("refresh_token"),
        token_uri="https://oauth2.googleapis.com/token",
        client_id=GOOGLE_CLIENT_ID,
        client_secret=GOOGLE_CLIENT_SECRET,
        scopes=[
            "https://www.googleapis.com/auth/gmail.readonly"
        ],
    )

    gmail = build(
        "gmail",
        "v1",
        credentials=credentials
    )

    results = (
        gmail.users()
        .messages()
        .list(
            userId="me",
            maxResults=5
        )
        .execute()
    )

    messages = results.get(
        "messages",
        []
    )

    emails = []

    for message in messages:

        # -------------------------------------------------
        # Fetch FULL Gmail message
        # -------------------------------------------------

        email = (
            gmail.users()
            .messages()
            .get(
                userId="me",
                id=message["id"],
                format="full"
            )
            .execute()
        )

        # -------------------------------------------------
        # FORENSIC PARSING
        # -------------------------------------------------

        forensic = parse_email_message(
            email
        )

        # -------------------------------------------------
        # DETERMINISTIC ANALYSIS
        # -------------------------------------------------

        analysis = analyze_email(
            forensic
        )

        # -------------------------------------------------
        # FRONTEND RESPONSE
        # -------------------------------------------------

        emails.append({

            "id": email.get("id"),

            "threadId": email.get(
                "threadId"
            ),

            "from": forensic["headers"].get(
                "from",
                ""
            ),

            "to": forensic["headers"].get(
                "to",
                ""
            ),

            "subject": forensic.get(
                "subject",
                ""
            ),

            "date": forensic.get(
                "date",
                ""
            ),

            "snippet": email.get(
                "snippet",
                ""
            ),

            # -----------------------------
            # NEW FORENSIC INFORMATION
            # -----------------------------

            "forensic": forensic,

            "analysis": analysis,

            "threat": analysis["threat"],

            "riskScore": analysis[
                "risk_score"
            ],

            "riskLevel": analysis[
                "risk_level"
            ],

            "findings": analysis[
                "findings"
            ],
        })

    return {
        "emails": emails
    }
# =========================================================
# INVESTIGATION API
# =========================================================

@app.post("/api/investigations")
async def create_investigation_api(
    request: Request,
    user=Depends(get_current_user)
):
    """
    Create a persistent forensic investigation
    from a Gmail message.
    """

    body = await request.json()

    message_id = body.get("message_id")

    if not message_id:
        raise HTTPException(
            status_code=400,
            detail="message_id is required."
        )

    user_id = user["id"]

    # -----------------------------------------------------
    # 1. Get the user's stored Gmail OAuth token
    # -----------------------------------------------------

    google_token = get_google_token_by_user_id(
        user_id
    )

    if not google_token:
        raise HTTPException(
            status_code=401,
            detail="Google account is not connected."
        )

    token_data = json.loads(
        google_token
    )

    # -----------------------------------------------------
    # 2. Build Gmail credentials
    # -----------------------------------------------------

    credentials = Credentials(
        token=token_data.get("access_token"),
        refresh_token=token_data.get("refresh_token"),
        token_uri="https://oauth2.googleapis.com/token",
        client_id=GOOGLE_CLIENT_ID,
        client_secret=GOOGLE_CLIENT_SECRET,
        scopes=[
            "https://www.googleapis.com/auth/gmail.readonly"
        ],
    )

    # -----------------------------------------------------
    # 3. Connect to Gmail API
    # -----------------------------------------------------

    gmail = build(
        "gmail",
        "v1",
        credentials=credentials
    )

    # -----------------------------------------------------
    # 4. Fetch the selected Gmail message
    # -----------------------------------------------------

    try:

        email = (
            gmail.users()
            .messages()
            .get(
                userId="me",
                id=message_id,
                format="full"
            )
            .execute()
        )

    except Exception as exc:

        raise HTTPException(
            status_code=404,
            detail=f"Unable to fetch Gmail message: {exc}"
        )

    # -----------------------------------------------------
    # 5. Parse the email
    # -----------------------------------------------------

    forensic = parse_email_message(
        email
    )

    # -----------------------------------------------------
    # 6. Run deterministic forensic analysis
    # -----------------------------------------------------

    analysis = analyze_email(
        forensic
    )

    # -----------------------------------------------------
    # 7. Create persistent investigation
    # -----------------------------------------------------

    investigation = create_investigation(
        user_id=user_id,
        gmail_message_id=message_id,
        thread_id=email.get("threadId"),
        sender=forensic["headers"].get(
            "from",
            ""
        ),
        recipient=forensic["headers"].get(
            "to",
            ""
        ),
        subject=forensic.get(
            "subject",
            ""
        ),
        threat=analysis["threat"],
        risk_score=analysis["risk_score"],
        risk_level=analysis["risk_level"],
        findings=json.dumps(
            analysis["findings"]
        ),
    )

    investigation_id = investigation["id"]

    # -----------------------------------------------------
    # 8. Save forensic evidence
    # -----------------------------------------------------

    add_investigation_evidence(
        investigation_id=investigation_id,
        evidence_type="headers",
        evidence=json.dumps(
            forensic.get("headers", {})
        ),
    )

    add_investigation_evidence(
        investigation_id=investigation_id,
        evidence_type="authentication",
        evidence=json.dumps(
            forensic.get(
                "authentication",
                {}
            )
        ),
    )

    add_investigation_evidence(
    investigation_id=investigation_id,
    evidence_type="body",
    evidence=json.dumps(
        forensic
        ),
    )
    add_investigation_evidence(
        investigation_id=investigation_id,
        evidence_type="attachments",
        evidence=json.dumps(
            forensic.get(
                "attachments",
                []
            )
        ),
    )

    # -----------------------------------------------------
    # 9. Save extracted URLs as IOCs
    # -----------------------------------------------------

    urls = forensic.get(
        "urls",
        []
    )

    for url in urls:

        add_investigation_ioc(
            investigation_id=investigation_id,
            ioc_type="url",
            value=url,
        )
        # -----------------------------------------------------
        # 9B. Infrastructure intelligence
        # -----------------------------------------------------

        infrastructure_items = extract_public_ips(
            urls
        )

    # -----------------------------------------------------
    # 10. Return investigation
    # -----------------------------------------------------

    return {
        "success": True,
        "investigation": investigation,
        "forensic": forensic,
        "analysis": analysis,
        "ioc_count": len(urls),
    }


# =========================================================
# GET SINGLE INVESTIGATION
# =========================================================

@app.get("/api/investigations/{investigation_id}")
async def get_investigation_api(
    investigation_id: int,
    user=Depends(get_current_user)
):

    investigation = get_investigation_by_id(
        investigation_id
    )

    if not investigation:
        raise HTTPException(
            status_code=404,
            detail="Investigation not found."
        )

    # -----------------------------------------------------
    # SECURITY:
    # Only allow the owner of the investigation
    # to retrieve it.
    # -----------------------------------------------------

    if investigation["user_id"] != user["id"]:
        raise HTTPException(
            status_code=403,
            detail="You do not have access to this investigation."
        )

    return {
        "success": True,
        "investigation": investigation,
    }

# =========================================================
# GET INFRASTRUCTURE INTELLIGENCE
# =========================================================

@app.get(
    "/api/investigations/{investigation_id}/infrastructure"
)
async def get_infrastructure_api(
    investigation_id: int,
    user=Depends(get_current_user)
):

    investigation = get_investigation_by_id(
        investigation_id
    )

    if not investigation:
        raise HTTPException(
            status_code=404,
            detail="Investigation not found."
        )

    if investigation["user_id"] != user["id"]:
        raise HTTPException(
            status_code=403,
            detail="You do not have access to this investigation."
        )

    infrastructure = (
        get_infrastructure_for_investigation(
            investigation_id
        )
    )

    return {
        "success": True,
        "investigation_id": investigation_id,
        "infrastructure": infrastructure,
    }
# =========================================================
# LIST USER INVESTIGATIONS
# =========================================================

@app.get("/api/investigations")
async def list_investigations_api(
    user=Depends(get_current_user)
):

    investigations = get_investigations_for_user(
        user["id"]
    )

    return {
        "success": True,
        "investigations": investigations,
    }
app.mount(
    "/",
    StaticFiles(directory="site"),
    name="site"
    )


