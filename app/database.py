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
                google_token=?,
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
                    google_token=?,
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