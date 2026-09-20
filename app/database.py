import sqlite3
from pathlib import Path

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError


DB_PATH = Path(__file__).resolve().parent.parent / "tracemail.db"

password_hasher = PasswordHasher()


VALID_ROLES = {
    "viewer",
    "analyst",
    "admin",
}


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_connection()

    # Create the users table for new installations.
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            google_sub TEXT UNIQUE,
            email TEXT NOT NULL UNIQUE,
            name TEXT,
            picture TEXT,
            password_hash TEXT,
            role TEXT NOT NULL DEFAULT 'viewer',
            google_token TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            last_login TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()

    # ---------------------------------------------------------
    # DATABASE MIGRATION
    # ---------------------------------------------------------
    #
    # Your existing database was created with:
    #
    # google_sub TEXT UNIQUE NOT NULL
    # email TEXT NOT NULL
    #
    # SQLite cannot directly ALTER an existing column to make
    # it nullable/unique in the way we need.
    #
    # Therefore we inspect the existing table and migrate it
    # safely if necessary.
    # ---------------------------------------------------------

    columns = {
        row["name"]
        for row in conn.execute("PRAGMA table_info(users)").fetchall()
    }

    # Add password_hash to an existing database.
    if "password_hash" not in columns:
        conn.execute("""
            ALTER TABLE users
            ADD COLUMN password_hash TEXT
        """)
    if "google_token" not in columns:
        conn.execute("""
            ALTER TABLE users
            ADD COLUMN google_token TEXT
        """)
    # Check whether the existing schema still has the old
    # google_sub NOT NULL / email-not-unique structure.
    table_info = conn.execute(
        "PRAGMA table_info(users)"
    ).fetchall()

    google_sub_not_null = False
    email_not_null = False

    for column in table_info:
        if column["name"] == "google_sub":
            google_sub_not_null = bool(column["notnull"])

        if column["name"] == "email":
            email_not_null = bool(column["notnull"])

    # The existing database needs a full table rebuild if
    # google_sub is still NOT NULL.
    if google_sub_not_null:

        conn.execute("PRAGMA foreign_keys=OFF")

        conn.execute("""
            CREATE TABLE users_new (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                google_sub TEXT UNIQUE,
                email TEXT NOT NULL UNIQUE,
                name TEXT,
                picture TEXT,
                password_hash TEXT,
                role TEXT NOT NULL DEFAULT 'viewer',
                google_token TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                last_login TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)

        conn.execute("""
            INSERT INTO users_new (
                id,
                google_sub,
                email,
                name,
                picture,
                password_hash,
                role,
                google_token,
                created_at,
                last_login
            )
            SELECT
                id,
                google_sub,
                email,
                name,
                picture,
                password_hash,
                role,
                google_token,
                created_at,
                last_login
            FROM users
        """)

        conn.execute("DROP TABLE users")

        conn.execute("""
            ALTER TABLE users_new
            RENAME TO users
        """)

        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("""
                CREATE TABLE IF NOT EXISTS investigations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id TEXT NOT NULL UNIQUE,
                    user_id INTEGER NOT NULL,
                    gmail_message_id TEXT,
                    thread_id TEXT,
                    sender TEXT,
                    subject TEXT,
                    threat TEXT,
                    risk_score INTEGER,
                    risk_level TEXT,
                    status TEXT NOT NULL DEFAULT 'ACTIVE',
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                )
            """)
        conn.execute("""
                CREATE TABLE IF NOT EXISTS investigation_evidence (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    investigation_id INTEGER NOT NULL,
                    evidence_type TEXT NOT NULL,
                    evidence_key TEXT,
                    evidence_value TEXT,
                    source TEXT,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(investigation_id)
                        REFERENCES investigations(id)
                        ON DELETE CASCADE
                )
            """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS investigation_iocs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                investigation_id INTEGER NOT NULL,
                ioc_type TEXT NOT NULL,
                value TEXT NOT NULL,
                source TEXT,
                confidence INTEGER DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(investigation_id)
                    REFERENCES investigations(id)
                    ON DELETE CASCADE
            )
        """)
        conn.execute("""
                CREATE TABLE IF NOT EXISTS infrastructure (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    investigation_id INTEGER NOT NULL,
                    ioc_type TEXT NOT NULL,
                    value TEXT NOT NULL,
                    ip TEXT,
                    domain TEXT,
                    country TEXT,
                    region TEXT,
                    city TEXT,
                    isp TEXT,
                    organization TEXT,
                    asn TEXT,
                    latitude REAL,
                    longitude REAL,
                    vpn BOOLEAN,
                    proxy BOOLEAN,
                    tor BOOLEAN,
                    confidence INTEGER DEFAULT 0,
                    provider TEXT,
                    raw_json TEXT,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(investigation_id)
                        REFERENCES investigations(id)
                        ON DELETE CASCADE
                )
            """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_investigations_user
            ON investigations(user_id)
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_investigations_gmail
            ON investigations(gmail_message_id)
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_iocs_value
            ON investigation_iocs(value)
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_infrastructure_value
            ON infrastructure(value)
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS infrastructure (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                investigation_id INTEGER NOT NULL,
                hostname TEXT,
                ip TEXT,
                country TEXT,
                region TEXT,
                city TEXT,
                isp TEXT,
                organization TEXT,
                asn TEXT,
                latitude REAL,
                longitude REAL,
                vpn TEXT,
                proxy TEXT,
                tor TEXT,
                confidence REAL,
                provider TEXT,
                raw_json TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,

                FOREIGN KEY(investigation_id)
                    REFERENCES investigations(id)
                    ON DELETE CASCADE
            )
        """)

    conn.commit()
    conn.close()
    

def generate_case_id():
    conn = get_connection()

    row = conn.execute("""
        SELECT case_id
        FROM investigations
        ORDER BY id DESC
        LIMIT 1
    """).fetchone()

    conn.close()

    if not row:
        number = 142
    else:
        try:
            number = int(row["case_id"].split("-")[-1]) + 1
        except Exception:
            number = 142

    return f"TM-2026-{number:05d}"

def create_investigation(
    user_id,
    gmail_message_id,
    thread_id,
    sender,
    subject,
    threat,
    risk_score,
    risk_level,
):
    case_id = generate_case_id()

    conn = get_connection()

    cursor = conn.execute("""
        INSERT INTO investigations (
            case_id,
            user_id,
            gmail_message_id,
            thread_id,
            sender,
            subject,
            threat,
            risk_score,
            risk_level,
            status
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        case_id,
        user_id,
        gmail_message_id,
        thread_id,
        sender,
        subject,
        threat,
        risk_score,
        risk_level,
        "ACTIVE",
    ))

    investigation_id = cursor.lastrowid

    conn.commit()
    conn.close()

    return get_investigation_by_id(
        investigation_id
    )

def get_investigation_by_id(
    investigation_id
):
    conn = get_connection()

    row = conn.execute("""
        SELECT
            id,
            case_id,
            user_id,
            gmail_message_id,
            thread_id,
            sender,
            subject,
            threat,
            risk_score,
            risk_level,
            status,
            created_at,
            updated_at
        FROM investigations
        WHERE id = ?
    """, (
        investigation_id,
    )).fetchone()

    conn.close()

    return dict(row) if row else None

def get_investigations_for_user(user_id):
    conn = get_connection()

    rows = conn.execute("""
        SELECT
            id,
            case_id,
            gmail_message_id,
            thread_id,
            sender,
            subject,
            threat,
            risk_score,
            risk_level,
            status,
            created_at,
            updated_at
        FROM investigations
        WHERE user_id = ?
        ORDER BY id DESC
    """, (
        user_id,
    )).fetchall()

    conn.close()

    return [
        dict(row)
        for row in rows
    ]

def add_investigation_evidence(
    investigation_id,
    evidence_type,
    evidence_key,
    evidence_value,
    source,
):
    conn = get_connection()

    conn.execute("""
        INSERT INTO investigation_evidence (
            investigation_id,
            evidence_type,
            evidence_key,
            evidence_value,
            source
        )
        VALUES (?, ?, ?, ?, ?)
    """, (
        investigation_id,
        evidence_type,
        evidence_key,
        evidence_value,
        source,
    ))

    conn.commit()
    conn.close()

def add_investigation_ioc(
    investigation_id,
    ioc_type,
    value,
    source,
    confidence=0,
):
    conn = get_connection()

    conn.execute("""
        INSERT INTO investigation_iocs (
            investigation_id,
            ioc_type,
            value,
            source,
            confidence
        )
        VALUES (?, ?, ?, ?, ?)
    """, (
        investigation_id,
        ioc_type,
        value,
        source,
        confidence,
    ))

    conn.commit()
    conn.close()
def add_infrastructure(
    investigation_id,
    ioc_type,
    value,
    ip=None,
    domain=None,
    country=None,
    region=None,
    city=None,
    isp=None,
    organization=None,
    asn=None,
    latitude=None,
    longitude=None,
    vpn=None,
    proxy=None,
    tor=None,
    confidence=0,
    provider=None,
    raw_json=None,
):
    conn = get_connection()

    conn.execute("""
        INSERT INTO infrastructure (
            investigation_id,
            ioc_type,
            value,
            ip,
            domain,
            country,
            region,
            city,
            isp,
            organization,
            asn,
            latitude,
            longitude,
            vpn,
            proxy,
            tor,
            confidence,
            provider,
            raw_json
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        investigation_id,
        ioc_type,
        value,
        ip,
        domain,
        country,
        region,
        city,
        isp,
        organization,
        asn,
        latitude,
        longitude,
        vpn,
        proxy,
        tor,
        confidence,
        provider,
        raw_json,
    ))

    conn.commit()
    conn.close()
def validate_role(role):
    """
    Validate that a role is one of the roles supported
    by TraceMail.
    """

    if role not in VALID_ROLES:
        raise ValueError(
            "Invalid role. Allowed roles: viewer, analyst, admin."
        )

    return role


def hash_password(password):
    """
    Convert a plaintext password into a secure Argon2id hash.
    """

    return password_hasher.hash(password)


def verify_password(password, password_hash):
    """
    Verify a plaintext password against the stored hash.
    """

    if not password_hash:
        return False

    try:
        return password_hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError):
        return False


def create_user(
    email,
    name,
    password,
    role,
):
    """
    Create a normal TraceMail email/password account.
    """

    role = validate_role(role)

    password_hash = hash_password(password)

    conn = get_connection()

    try:
        existing = conn.execute(
            """
            SELECT id
            FROM users
            WHERE LOWER(email) = LOWER(?)
            """,
            (email,),
        ).fetchone()

        if existing:
            raise ValueError(
                "An account with this email already exists."
            )

        cursor = conn.execute(
            """
            INSERT INTO users (
                google_sub,
                email,
                name,
                picture,
                password_hash,
                role,
                google_token
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                None,
                email,
                name,
                None,
                password_hash,
                role,
                None,
            ),
        )

        user_id = cursor.lastrowid

        conn.commit()

        return get_user_by_id(user_id)

    finally:
        conn.close()


def get_user_by_email(email):
    """
    Find a TraceMail account using its email address.
    """

    conn = get_connection()

    row = conn.execute(
        """
        SELECT
            id,
            google_sub,
            email,
            name,
            picture,
            password_hash,
            role,
            google_token,
            created_at,
            last_login
        FROM users
        WHERE LOWER(email) = LOWER(?)
        """,
        (email,),
    ).fetchone()

    conn.close()

    return dict(row) if row else None


def authenticate_user(email, password):
    """
    Authenticate an email/password account.

    Returns the complete user row if the credentials are valid.
    Returns None otherwise.
    """

    user = get_user_by_email(email)

    if not user:
        return None

    # Google-only accounts may not have a password yet.
    if not user["password_hash"]:
        return None

    if not verify_password(password, user["password_hash"]):
        return None

    conn = get_connection()

    conn.execute(
        """
        UPDATE users
        SET last_login=CURRENT_TIMESTAMP
        WHERE id=?
        """,
        (user["id"],),
    )

    conn.commit()
    conn.close()

    user["last_login"] = None

    return get_user_by_id(user["id"])


def upsert_user(
    google_sub,
    email,
    name,
    picture,
    google_token=None,
):
    """
    Create/update a Google-authenticated user.

    IMPORTANT:
    Existing TraceMail role is preserved.

    Google login does NOT allow the user to choose
    a different role.
    """

    conn = get_connection()

    # First identify the account by Google subject.
    existing = conn.execute(
        """
        SELECT id, role
        FROM users
        WHERE google_sub = ?
        """,
        (google_sub,),
    ).fetchone()

    if existing:

        conn.execute(
            """
            UPDATE users
            SET
                email=?,
                name=?,
                picture=?,
                google_token=COALESCE(?, google_token),
                last_login=CURRENT_TIMESTAMP
            WHERE google_sub=?
            """,
            (
                email,
                name,
                picture,
                google_token,
                google_sub,
            ),
        )

        user_id = existing["id"]

    else:

        # A Google account may already exist under the same email.
        # In that case, attach the Google identity to that
        # existing TraceMail account rather than creating
        # a second account.
        existing_email = conn.execute(
            """
            SELECT id, role, google_sub
            FROM users
            WHERE LOWER(email) = LOWER(?)
            """,
            (email,),
        ).fetchone()

        if existing_email:

            if existing_email["google_sub"] not in (None, google_sub):
                conn.close()
                raise ValueError(
                    "This email is already linked to another Google account."
                )

            conn.execute(
                """
                UPDATE users
                SET
                    google_sub=?,
                    name=?,
                    picture=?,
                    google_token=COALESCE(?, google_token),
                    last_login=CURRENT_TIMESTAMP
                WHERE id=?
                """,
                (
                    google_sub,
                    name,
                    picture,
                    google_token,
                    existing_email["id"],
                ),
            )

            user_id = existing_email["id"]

        else:

            # New Google account.
            #
            # For now we create it as viewer.
            # Later, if you want first-time Google users to
            # explicitly choose their role during account setup,
            # we will add that onboarding flow.
            cursor = conn.execute(
                """
                INSERT INTO users (
                    google_sub,
                    email,
                    name,
                    picture,
                    password_hash,
                    role,
                    google_token
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    google_sub,
                    email,
                    name,
                    picture,
                    None,
                    "viewer",
                    google_token,
                ),
            )

            user_id = cursor.lastrowid

    conn.commit()
    conn.close()

    return get_user_by_id(user_id)
def create_google_user(
    google_sub,
    email,
    name,
    picture,
    role,
):
    """
    Create a new TraceMail account after a first-time
    Google user has explicitly selected a role.
    """

    role = validate_role(role)

    email = email.strip().lower()

    conn = get_connection()

    try:
        # Never create a duplicate account.
        existing = conn.execute(
            """
            SELECT id
            FROM users
            WHERE LOWER(email) = LOWER(?)
            """,
            (email,),
        ).fetchone()

        if existing:
            raise ValueError(
                "An account with this email already exists."
            )

        # Also make sure this Google identity is not already registered.
        existing_google = conn.execute(
            """
            SELECT id
            FROM users
            WHERE google_sub = ?
            """,
            (google_sub,),
        ).fetchone()

        if existing_google:
            raise ValueError(
                "This Google account is already registered."
            )

        cursor = conn.execute(
            """
            INSERT INTO users (
                google_sub,
                email,
                name,
                picture,
                password_hash,
                role,
                google_token
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                google_sub,
                email,
                name,
                picture,
                None,
                role,
                None,
            ),
        )

        user_id = cursor.lastrowid

        conn.commit()

        return get_user_by_id(user_id)

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()

def update_google_token_for_user_id(user_id, google_token):
    """
    Store the Gmail OAuth token for an already-authenticated
    TraceMail user.
    """

    conn = get_connection()

    conn.execute(
        """
        UPDATE users
        SET
            google_token=?,
            last_login=CURRENT_TIMESTAMP
        WHERE id=?
        """,
        (
            google_token,
            user_id,
        ),
    )

    conn.commit()
    conn.close()

    return get_user_by_id(user_id)

def get_user_by_id(user_id):
    conn = get_connection()

    row = conn.execute(
        """
        SELECT
            id,
            email,
            name,
            picture,
            role
        FROM users
        WHERE id=?
        """,
        (user_id,),
    ).fetchone()

    conn.close()

    return dict(row) if row else None


def get_google_token_by_user_id(user_id):
    conn = get_connection()

    row = conn.execute(
        """
        SELECT google_token
        FROM users
        WHERE id=?
        """,
        (user_id,),
    ).fetchone()

    conn.close()

    return row["google_token"] if row else None
def link_google_identity(
    user_id,
    google_sub,
    name,
    picture,
):
    """
    Attach a Google identity to an existing TraceMail account.
    The existing TraceMail role is preserved.
    """

    conn = get_connection()

    try:
        existing_google = conn.execute(
            """
            SELECT id
            FROM users
            WHERE google_sub = ?
            AND id != ?
            """,
            (google_sub, user_id),
        ).fetchone()

        if existing_google:
            raise ValueError(
                "This Google account is already linked "
                "to another TraceMail account."
            )

        conn.execute(
            """
            UPDATE users
            SET
                google_sub=?,
                name=?,
                picture=?,
                last_login=CURRENT_TIMESTAMP
            WHERE id=?
            """,
            (
                google_sub,
                name,
                picture,
                user_id,
            ),
        )

        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()

    return get_user_by_id(user_id)
def add_infrastructure(
    investigation_id,
    hostname,
    ip,
    country=None,
    region=None,
    city=None,
    isp=None,
    organization=None,
    asn=None,
    latitude=None,
    longitude=None,
    vpn=None,
    proxy=None,
    tor=None,
    confidence=None,
    provider=None,
    raw_json=None,
):
    conn = get_connection()

    cursor = conn.execute(
        """
        INSERT INTO infrastructure (
            investigation_id,
            hostname,
            ip,
            country,
            region,
            city,
            isp,
            organization,
            asn,
            latitude,
            longitude,
            vpn,
            proxy,
            tor,
            confidence,
            provider,
            raw_json
        )
        VALUES (
            ?, ?, ?, ?, ?, ?, ?, ?, ?,
            ?, ?, ?, ?, ?, ?, ?, ?
        )
        """,
        (
            investigation_id,
            hostname,
            ip,
            country,
            region,
            city,
            isp,
            organization,
            asn,
            latitude,
            longitude,
            vpn,
            proxy,
            tor,
            confidence,
            provider,
            raw_json,
        )
    )

    infrastructure_id = cursor.lastrowid

    conn.commit()
    conn.close()

    return infrastructure_id
def get_infrastructure_for_investigation(
    investigation_id
):
    conn = get_connection()

    rows = conn.execute(
        """
        SELECT *
        FROM infrastructure
        WHERE investigation_id = ?
        ORDER BY created_at ASC
        """,
        (investigation_id,)
    ).fetchall()

    conn.close()

    return [
        dict(row)
        for row in rows
    ]