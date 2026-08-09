import os
import secrets
import sqlite3
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, jsonify, request, render_template_string
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash


# ============================================================
# CONFIG
# ============================================================

APP_NAME = "SpookChat"

DATABASE = os.environ.get(
    "SPOOKCHAT_DATABASE",
    "spookchat.db"
)

OWNER_USERNAME = os.environ.get(
    "SPOOKCHAT_OWNER_USERNAME",
    "JAYDEN"
)

# IMPORTANT:
# Your old script had:
#
# os.environ.get("2011BeT20211", "")
#
# which was incorrect.
#
# This uses SPOOKCHAT_OWNER_PASSWORD correctly.
OWNER_PASSWORD = os.environ.get(
    "SPOOKCHAT_OWNER_PASSWORD",
    ""
)

ONLINE_SECONDS = 60

app = Flask(__name__)
CORS(app)

ROLES = {
    "user": 0,
    "moderator": 1,
    "admin": 2,
    "owner": 3
}


# ============================================================
# DATABASE
# ============================================================

def now():
    return datetime.now(timezone.utc).isoformat()


def db():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def add_column_if_missing(connection, table, column, definition):
    columns = connection.execute(
        f"PRAGMA table_info({table})"
    ).fetchall()

    existing = {
        row["name"]
        for row in columns
    }

    if column not in existing:
        connection.execute(
            f"ALTER TABLE {table} ADD COLUMN {column} {definition}"
        )


def init_database():
    connection = db()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            ip TEXT NOT NULL DEFAULT 'unknown',
            role TEXT NOT NULL DEFAULT 'user',
            show_role_tag INTEGER NOT NULL DEFAULT 1,
            banned INTEGER NOT NULL DEFAULT 0,
            pfp TEXT DEFAULT '',
            description TEXT DEFAULT '',
            pronouns TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            last_seen TEXT NOT NULL
        )
    """)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            message TEXT NOT NULL,
            edited INTEGER DEFAULT 0,
            edited_at TEXT DEFAULT '',
            created_at TEXT NOT NULL
        )
    """)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS friendships (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            friend_id INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            UNIQUE(user_id, friend_id)
        )
    """)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS private_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER NOT NULL,
            receiver_id INTEGER NOT NULL,
            message TEXT NOT NULL,
            edited INTEGER DEFAULT 0,
            edited_at TEXT DEFAULT '',
            created_at TEXT NOT NULL
        )
    """)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS ip_bans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT UNIQUE NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            reporter_id INTEGER NOT NULL,
            reported_user_id INTEGER,
            message_id INTEGER,
            reason TEXT NOT NULL,
            details TEXT DEFAULT '',
            status TEXT NOT NULL DEFAULT 'open',
            created_at TEXT NOT NULL,
            resolved_at TEXT DEFAULT '',
            resolved_by INTEGER,
            moderator_note TEXT DEFAULT ''
        )
    """)

    # -------------------------
    # Migrations
    # -------------------------

    add_column_if_missing(
        connection,
        "users",
        "ip",
        "TEXT DEFAULT 'unknown'"
    )

    add_column_if_missing(
        connection,
        "users",
        "role",
        "TEXT DEFAULT 'user'"
    )

    add_column_if_missing(
        connection,
        "users",
        "show_role_tag",
        "INTEGER DEFAULT 1"
    )

    add_column_if_missing(
        connection,
        "users",
        "banned",
        "INTEGER DEFAULT 0"
    )

    add_column_if_missing(
        connection,
        "users",
        "pfp",
        "TEXT DEFAULT ''"
    )

    add_column_if_missing(
        connection,
        "users",
        "description",
        "TEXT DEFAULT ''"
    )

    add_column_if_missing(
        connection,
        "users",
        "pronouns",
        "TEXT DEFAULT ''"
    )

    add_column_if_missing(
        connection,
        "users",
        "created_at",
        "TEXT DEFAULT ''"
    )

    add_column_if_missing(
        connection,
        "users",
        "last_seen",
        "TEXT DEFAULT ''"
    )

    add_column_if_missing(
        connection,
        "messages",
        "edited",
        "INTEGER DEFAULT 0"
    )

    add_column_if_missing(
        connection,
        "messages",
        "edited_at",
        "TEXT DEFAULT ''"
    )

    add_column_if_missing(
        connection,
        "reports",
        "moderator_note",
        "TEXT DEFAULT ''"
    )

    connection.execute("""
        UPDATE users
        SET role='user'
        WHERE role IS NULL OR role=''
    """)

    connection.execute("""
        UPDATE users
        SET show_role_tag=1
        WHERE show_role_tag IS NULL
    """)

    connection.execute("""
        UPDATE users
        SET banned=0
        WHERE banned IS NULL
    """)

    # -------------------------
    # Ensure owner exists
    # -------------------------

    owner = connection.execute("""
        SELECT *
        FROM users
        WHERE LOWER(username)=LOWER(?)
    """, (
        OWNER_USERNAME,
    )).fetchone()

    if owner:

        connection.execute("""
            UPDATE users
            SET
                role='owner',
                banned=0,
                show_role_tag=1
            WHERE id=?
        """, (
            owner["id"],
        ))

        # If the supplied owner password is set,
        # make sure the owner can actually log in.
        if OWNER_PASSWORD:
            connection.execute("""
                UPDATE users
                SET password=?
                WHERE id=?
            """, (
                generate_password_hash(
                    OWNER_PASSWORD
                ),
                owner["id"]
            ))

    else:

        connection.execute("""
            INSERT INTO users (
                username,
                password,
                ip,
                role,
                show_role_tag,
                banned,
                pfp,
                description,
                pronouns,
                created_at,
                last_seen
            )
            VALUES (
                ?,
                ?,
                'server',
                'owner',
                1,
                0,
                '',
                '',
                '',
                ?,
                ?
            )
        """, (
            OWNER_USERNAME,
            generate_password_hash(
                OWNER_PASSWORD
            ),
            now(),
            now()
        ))

    # -------------------------
    # Indexes
    # -------------------------

    connection.execute("""
        CREATE INDEX IF NOT EXISTS idx_messages_user
        ON messages(user_id)
    """)

    connection.execute("""
        CREATE INDEX IF NOT EXISTS idx_reports_status
        ON reports(status)
    """)

    connection.execute("""
        CREATE INDEX IF NOT EXISTS idx_friendships_user
        ON friendships(user_id)
    """)

    connection.execute("""
        CREATE INDEX IF NOT EXISTS idx_friendships_friend
        ON friendships(friend_id)
    """)

    connection.commit()
    connection.close()


# ============================================================
# AUTH
# ============================================================

def current_ip():
    forwarded = request.headers.get(
        "X-Forwarded-For"
    )

    if forwarded:
        return forwarded.split(",")[0].strip()

    return request.remote_addr or "unknown"


def get_user():
    token = request.headers.get(
        "Authorization",
        ""
    ).strip()

    if not token:
        return None

    connection = db()

    user = connection.execute("""
        SELECT u.*
        FROM users u
        JOIN sessions s
            ON s.user_id=u.id
        WHERE s.token=?
    """, (
        token,
    )).fetchone()

    connection.close()

    return user


def is_online(last_seen):
    if not last_seen:
        return False

    try:
        timestamp = datetime.fromisoformat(
            last_seen.replace("Z", "+00:00")
        )

        age = (
            datetime.now(timezone.utc)
            - timestamp
        ).total_seconds()

        return age <= ONLINE_SECONDS

    except Exception:
        return False


def require_user(function):

    @wraps(function)
    def wrapper(*args, **kwargs):

        user = get_user()

        if not user:
            return jsonify(
                error="Not logged in"
            ), 401

        if user["banned"]:
            return jsonify(
                error="Your account is banned"
            ), 403

        connection = db()

        ip_banned = connection.execute("""
            SELECT id
            FROM ip_bans
            WHERE ip=?
        """, (
            current_ip(),
        )).fetchone()

        if (
            ip_banned
            and user["role"] != "owner"
        ):
            connection.close()

            return jsonify(
                error="Your IP address is banned"
            ), 403

        connection.execute("""
            UPDATE users
            SET
                ip=?,
                last_seen=?
            WHERE id=?
        """, (
            current_ip(),
            now(),
            user["id"]
        ))

        connection.commit()
        connection.close()

        return function(
            user,
            *args,
            **kwargs
        )

    return wrapper


def require_role(required_role):

    def decorator(function):

        @wraps(function)
        def wrapper(*args, **kwargs):

            user = get_user()

            if not user:
                return jsonify(
                    error="Not logged in"
                ), 401

            if user["banned"]:
                return jsonify(
                    error="Banned"
                ), 403

            if (
                ROLES.get(
                    user["role"],
                    0
                )
                <
                ROLES[required_role]
            ):
                return jsonify(
                    error="Insufficient permissions"
                ), 403

            return function(
                user,
                *args,
                **kwargs
            )

        return wrapper

    return decorator


# ============================================================
# HELPERS
# ============================================================

def public_user(user):
    return {
        "id": user["id"],
        "username": user["username"],
        "role": user["role"],
        "show_role_tag": bool(
            user["show_role_tag"]
        ),
        "pfp": user["pfp"] or "",
        "description": user["description"] or "",
        "pronouns": user["pronouns"] or "",
        "online": is_online(
            user["last_seen"]
        ),
        "last_seen": user["last_seen"]
    }


def user_json(row):

    if not row:
        return None

    return {
        "id": row["id"],
        "username": row["username"],
        "role": row["role"],
        "show_role_tag": bool(
            row["show_role_tag"]
        ),
        "pfp": row["pfp"] or "",
        "description": row["description"] or "",
        "pronouns": row["pronouns"] or "",
        "online": is_online(
            row["last_seen"]
        ),
        "last_seen": row["last_seen"]
    }


def are_friends(connection, first, second):

    result = connection.execute("""
        SELECT id
        FROM friendships
        WHERE status='accepted'
        AND (
            (user_id=? AND friend_id=?)
            OR
            (user_id=? AND friend_id=?)
        )
    """, (
        first,
        second,
        second,
        first
    )).fetchone()

    return bool(result)


def get_friend_status(
    connection,
    first,
    second
):

    friendship = connection.execute("""
        SELECT *
        FROM friendships
        WHERE
            (user_id=? AND friend_id=?)
            OR
            (user_id=? AND friend_id=?)
        ORDER BY id DESC
        LIMIT 1
    """, (
        first,
        second,
        second,
        first
    )).fetchone()

    if not friendship:
        return "none"

    if friendship["status"] == "accepted":
        return "friends"

    if friendship["user_id"] == first:
        return "sent"

    return "received"


# ============================================================
# AUTH API
# ============================================================

@app.post("/api/register")
def register():

    data = request.get_json(
        silent=True
    ) or {}

    username = str(
        data.get("username", "")
    ).strip()

    password = str(
        data.get("password", "")
    )

    if len(username) < 3:
        return jsonify(
            error="Username must be at least 3 characters"
        ), 400

    if len(username) > 32:
        return jsonify(
            error="Username is too long"
        ), 400

    if len(password) < 6:
        return jsonify(
            error="Password must be at least 6 characters"
        ), 400

    connection = db()

    if connection.execute("""
        SELECT id
        FROM ip_bans
        WHERE ip=?
    """, (
        current_ip(),
    )).fetchone():

        connection.close()

        return jsonify(
            error="This IP address is banned"
        ), 403

    try:

        cursor = connection.execute("""
            INSERT INTO users (
                username,
                password,
                ip,
                role,
                show_role_tag,
                banned,
                pfp,
                description,
                pronouns,
                created_at,
                last_seen
            )
            VALUES (
                ?,
                ?,
                ?,
                'user',
                1,
                0,
                '',
                '',
                '',
                ?,
                ?
            )
        """, (
            username,
            generate_password_hash(
                password
            ),
            current_ip(),
            now(),
            now()
        ))

        user_id = cursor.lastrowid

        token = secrets.token_urlsafe(
            32
        )

        connection.execute("""
            INSERT INTO sessions (
                token,
                user_id,
                created_at
            )
            VALUES (?, ?, ?)
        """, (
            token,
            user_id,
            now()
        ))

        connection.commit()

        user = connection.execute("""
            SELECT *
            FROM users
            WHERE id=?
        """, (
            user_id,
        )).fetchone()

        connection.close()

        return jsonify({
            "token": token,
            "user": public_user(user)
        })

    except sqlite3.IntegrityError:

        connection.close()

        return jsonify(
            error="Username already exists"
        ), 409


@app.post("/api/login")
def login():

    data = request.get_json(
        silent=True
    ) or {}

    username = str(
        data.get("username", "")
    ).strip()

    password = str(
        data.get("password", "")
    )

    connection = db()

    if connection.execute("""
        SELECT id
        FROM ip_bans
        WHERE ip=?
    """, (
        current_ip(),
    )).fetchone():

        connection.close()

        return jsonify(
            error="Your IP address is banned"
        ), 403

    user = connection.execute("""
        SELECT *
        FROM users
        WHERE LOWER(username)=LOWER(?)
    """, (
        username,
    )).fetchone()

    if not user:

        connection.close()

        return jsonify(
            error="Invalid username or password"
        ), 401

    if not check_password_hash(
        user["password"],
        password
    ):

        connection.close()

        return jsonify(
            error="Invalid username or password"
        ), 401

    if user["banned"]:

        connection.close()

        return jsonify(
            error="Your account is banned"
        ), 403

    token = secrets.token_urlsafe(
        32
    )

    connection.execute("""
        INSERT INTO sessions (
            token,
            user_id,
            created_at
        )
        VALUES (?, ?, ?)
    """, (
        token,
        user["id"],
        now()
    ))

    connection.execute("""
        UPDATE users
        SET
            ip=?,
            last_seen=?
        WHERE id=?
    """, (
        current_ip(),
        now(),
        user["id"]
    ))

    connection.commit()

    user = connection.execute("""
        SELECT *
        FROM users
        WHERE id=?
    """, (
        user["id"],
    )).fetchone()

    connection.close()

    return jsonify({
        "token": token,
        "user": public_user(user)
    })


@app.post("/api/logout")
@require_user
def logout(user):

    token = request.headers.get(
        "Authorization",
        ""
    )

    connection = db()

    connection.execute("""
        DELETE FROM sessions
        WHERE token=?
    """, (
        token,
    ))

    connection.commit()
    connection.close()

    return jsonify(
        success=True
    )


@app.get("/api/me")
@require_user
def me(user):

    connection = db()

    fresh = connection.execute("""
        SELECT *
        FROM users
        WHERE id=?
    """, (
        user["id"],
    )).fetchone()

    connection.close()

    return jsonify(
        public_user(fresh)
    )


# ============================================================
# PROFILES
# ============================================================

@app.get("/api/users/<int:user_id>")
@require_user
def get_profile(user, user_id):

    connection = db()

    target = connection.execute("""
        SELECT
            id,
            username,
            role,
            show_role_tag,
            pfp,
            description,
            pronouns,
            created_at,
            last_seen
        FROM users
        WHERE id=?
    """, (
        user_id,
    )).fetchone()

    if not target:

        connection.close()

        return jsonify(
            error="User not found"
        ), 404

    result = dict(target)

    result["show_role_tag"] = bool(
        result["show_role_tag"]
    )

    result["online"] = is_online(
        result["last_seen"]
    )

    result["friend_status"] = get_friend_status(
        connection,
        user["id"],
        user_id
    )

    connection.close()

    return jsonify(result)


@app.put("/api/profile")
@require_user
def update_profile(user):

    data = request.get_json(
        silent=True
    ) or {}

    username = data.get("username")
    pfp = data.get("pfp")
    description = data.get("description")
    pronouns = data.get("pronouns")

    connection = db()

    if username is not None:

        username = str(
            username
        ).strip()

        if len(username) < 3:
            connection.close()

            return jsonify(
                error="Username must be at least 3 characters"
            ), 400

        if len(username) > 32:
            connection.close()

            return jsonify(
                error="Username is too long"
            ), 400

        exists = connection.execute("""
            SELECT id
            FROM users
            WHERE LOWER(username)=LOWER(?)
            AND id != ?
        """, (
            username,
            user["id"]
        )).fetchone()

        if exists:
            connection.close()

            return jsonify(
                error="Username already exists"
            ), 409

    if pfp is not None:

        pfp = str(pfp)

        if len(pfp) > 200000:
            connection.close()

            return jsonify(
                error="PFP is too large"
            ), 400

    if description is not None:

        description = str(
            description
        )

        if len(description) > 500:
            connection.close()

            return jsonify(
                error="Description is too long"
            ), 400

    if pronouns is not None:

        pronouns = str(
            pronouns
        )

        if len(pronouns) > 50:
            connection.close()

            return jsonify(
                error="Pronouns are too long"
            ), 400

    fields = []
    values = []

    if username is not None:
        fields.append(
            "username=?"
        )
        values.append(username)

    if pfp is not None:
        fields.append(
            "pfp=?"
        )
        values.append(pfp)

    if description is not None:
        fields.append(
            "description=?"
        )
        values.append(description)

    if pronouns is not None:
        fields.append(
            "pronouns=?"
        )
        values.append(pronouns)

    if not fields:

        connection.close()

        return jsonify(
            error="Nothing to update"
        ), 400

    values.append(
        user["id"]
    )

    connection.execute(
        f"""
        UPDATE users
        SET {", ".join(fields)}
        WHERE id=?
        """,
        values
    )

    connection.commit()

    updated = connection.execute("""
        SELECT *
        FROM users
        WHERE id=?
    """, (
        user["id"],
    )).fetchone()

    connection.close()

    return jsonify({
        "success": True,
        "user": public_user(updated)
    })


@app.post("/api/role-tag")
@require_user
def role_tag(user):

    data = request.get_json(
        silent=True
    ) or {}

    enabled = bool(
        data.get(
            "show",
            True
        )
    )

    connection = db()

    connection.execute("""
        UPDATE users
        SET show_role_tag=?
        WHERE id=?
    """, (
        int(enabled),
        user["id"]
    ))

    connection.commit()
    connection.close()

    return jsonify(
        success=True
    )


# ============================================================
# PUBLIC CHAT
# ============================================================

@app.get("/api/messages")
@require_user
def get_messages(user):

    connection = db()

    rows = connection.execute("""
        SELECT
            messages.id,
            messages.user_id,
            users.username,
            users.role,
            users.show_role_tag,
            users.pfp,
            users.last_seen,
            messages.message,
            messages.edited,
            messages.edited_at,
            messages.created_at
        FROM messages
        JOIN users
            ON users.id=messages.user_id
        ORDER BY messages.id DESC
        LIMIT 100
    """).fetchall()

    connection.close()

    result = []

    for row in reversed(rows):

        item = dict(row)

        item["online"] = is_online(
            row["last_seen"]
        )

        item["is_owner"] = (
            row["user_id"]
            == user["id"]
        )

        result.append(item)

    return jsonify(result)


@app.post("/api/messages")
@require_user
def send_message(user):

    data = request.get_json(
        silent=True
    ) or {}

    message = str(
        data.get(
            "message",
            ""
        )
    ).strip()

    if not message:
        return jsonify(
            error="Message cannot be empty"
        ), 400

    if len(message) > 4000:
        return jsonify(
            error="Message is too long"
        ), 400

    connection = db()

    cursor = connection.execute("""
        INSERT INTO messages (
            user_id,
            message,
            edited,
            edited_at,
            created_at
        )
        VALUES (
            ?,
            ?,
            0,
            '',
            ?
        )
    """, (
        user["id"],
        message,
        now()
    ))

    message_id = cursor.lastrowid

    connection.commit()

    row = connection.execute("""
        SELECT
            messages.id,
            messages.user_id,
            users.username,
            users.role,
            users.show_role_tag,
            users.pfp,
            users.last_seen,
            messages.message,
            messages.edited,
            messages.edited_at,
            messages.created_at
        FROM messages
        JOIN users
            ON users.id=messages.user_id
        WHERE messages.id=?
    """, (
        message_id,
    )).fetchone()

    connection.close()

    result = dict(row)

    result["online"] = is_online(
        row["last_seen"]
    )

    result["is_owner"] = True

    return jsonify(result)


# ============================================================
# EDIT MESSAGE
# ============================================================

@app.put("/api/messages/<int:message_id>")
@require_user
def edit_message(
    user,
    message_id
):

    data = request.get_json(
        silent=True
    ) or {}

    message = str(
        data.get(
            "message",
            ""
        )
    ).strip()

    if not message:
        return jsonify(
            error="Message cannot be empty"
        ), 400

    if len(message) > 4000:
        return jsonify(
            error="Message is too long"
        ), 400

    connection = db()

    existing = connection.execute("""
        SELECT *
        FROM messages
        WHERE id=?
    """, (
        message_id,
    )).fetchone()

    if not existing:

        connection.close()

        return jsonify(
            error="Message not found"
        ), 404

    if existing["user_id"] != user["id"]:

        connection.close()

        return jsonify(
            error="You can only edit your own messages"
        ), 403

    connection.execute("""
        UPDATE messages
        SET
            message=?,
            edited=1,
            edited_at=?
        WHERE id=?
    """, (
        message,
        now(),
        message_id
    ))

    connection.commit()
    connection.close()

    return jsonify(
        success=True
    )


# ============================================================
# DELETE MESSAGE
# ============================================================

@app.delete("/api/messages/<int:message_id>")
@require_user
def delete_message(
    user,
    message_id
):

    connection = db()

    message = connection.execute("""
        SELECT *
        FROM messages
        WHERE id=?
    """, (
        message_id,
    )).fetchone()

    if not message:

        connection.close()

        return jsonify(
            error="Message not found"
        ), 404

    # Normal users can only delete
    # their own messages.
    if message["user_id"] != user["id"]:

        connection.close()

        return jsonify(
            error="You can only delete your own messages"
        ), 403

    connection.execute("""
        DELETE FROM messages
        WHERE id=?
    """, (
        message_id,
    ))

    connection.commit()
    connection.close()

    return jsonify(
        success=True
    )


# ============================================================
# FRIENDS
# ============================================================

@app.get("/api/friends/search")
@require_user
def search_friends(user):

    query = str(
        request.args.get(
            "q",
            ""
        )
    ).strip()

    if not query:
        return jsonify([])

    connection = db()

    rows = connection.execute("""
        SELECT
            id,
            username,
            role,
            show_role_tag,
            pfp,
            description,
            pronouns,
            last_seen
        FROM users
        WHERE username LIKE ?
        AND id != ?
        AND banned=0
        ORDER BY username COLLATE NOCASE
        LIMIT 25
    """, (
        f"%{query}%",
        user["id"]
    )).fetchall()

    connection.close()

    return jsonify([
        user_json(row)
        for row in rows
    ])


@app.post("/api/friends/add")
@require_user
def add_friend_by_username(user):

    data = request.get_json(
        silent=True
    ) or {}

    username = str(
        data.get(
            "username",
            ""
        )
    ).strip()

    if not username:

        return jsonify(
            error="Enter a username"
        ), 400

    connection = db()

    target = connection.execute("""
        SELECT *
        FROM users
        WHERE LOWER(username)=LOWER(?)
    """, (
        username,
    )).fetchone()

    if not target:

        connection.close()

        return jsonify(
            error="User not found"
        ), 404

    if target["id"] == user["id"]:

        connection.close()

        return jsonify(
            error="You cannot add yourself"
        ), 400

    if target["banned"]:

        connection.close()

        return jsonify(
            error="That user is unavailable"
        ), 404

    existing = connection.execute("""
        SELECT *
        FROM friendships
        WHERE
            (user_id=? AND friend_id=?)
            OR
            (user_id=? AND friend_id=?)
        ORDER BY id DESC
        LIMIT 1
    """, (
        user["id"],
        target["id"],
        target["id"],
        user["id"]
    )).fetchone()

    if existing:

        if existing["status"] == "accepted":

            connection.close()

            return jsonify(
                error="You are already friends"
            ), 409

        # If the other person sent us
        # a request, accept it.
        if (
            existing["user_id"]
            == target["id"]
            and
            existing["friend_id"]
            == user["id"]
            and
            existing["status"]
            == "pending"
        ):

            connection.execute("""
                UPDATE friendships
                SET status='accepted'
                WHERE id=?
            """, (
                existing["id"],
            ))

            connection.commit()
            connection.close()

            return jsonify(
                success=True,
                status="accepted"
            )

        connection.close()

        return jsonify(
            error="A friend request already exists"
        ), 409

    connection.execute("""
        INSERT INTO friendships (
            user_id,
            friend_id,
            status
        )
        VALUES (
            ?,
            ?,
            'pending'
        )
    """, (
        user["id"],
        target["id"]
    ))

    connection.commit()
    connection.close()

    return jsonify(
        success=True,
        status="sent"
    )


@app.get("/api/friends")
@require_user
def get_friends(user):

    connection = db()

    rows = connection.execute("""
        SELECT
            u.id,
            u.username,
            u.role,
            u.show_role_tag,
            u.pfp,
            u.description,
            u.pronouns,
            u.last_seen
        FROM friendships f
        JOIN users u
            ON u.id =
                CASE
                    WHEN f.user_id=?
                    THEN f.friend_id
                    ELSE f.user_id
                END
        WHERE
            (f.user_id=? OR f.friend_id=?)
            AND f.status='accepted'
        ORDER BY
            u.username COLLATE NOCASE
    """, (
        user["id"],
        user["id"],
        user["id"]
    )).fetchall()

    connection.close()

    return jsonify([
        user_json(row)
        for row in rows
    ])


@app.get("/api/friends/requests")
@require_user
def friend_requests(user):

    connection = db()

    rows = connection.execute("""
        SELECT
            f.id AS request_id,
            u.id,
            u.username,
            u.role,
            u.show_role_tag,
            u.pfp,
            u.description,
            u.pronouns,
            u.last_seen
        FROM friendships f
        JOIN users u
            ON u.id=f.user_id
        WHERE
            f.friend_id=?
            AND f.status='pending'
        ORDER BY f.id DESC
    """, (
        user["id"],
    )).fetchall()

    connection.close()

    return jsonify([
        {
            **user_json(row),
            "request_id": row["request_id"]
        }
        for row in rows
    ])


@app.post("/api/friends/accept/<int:request_id>")
@require_user
def accept_friend(
    user,
    request_id
):

    connection = db()

    request_row = connection.execute("""
        SELECT *
        FROM friendships
        WHERE
            id=?
            AND friend_id=?
            AND status='pending'
    """, (
        request_id,
        user["id"]
    )).fetchone()

    if not request_row:

        connection.close()

        return jsonify(
            error="Request not found"
        ), 404

    connection.execute("""
        UPDATE friendships
        SET status='accepted'
        WHERE id=?
    """, (
        request_id,
    ))

    connection.commit()
    connection.close()

    return jsonify(
        success=True
    )


@app.delete("/api/friends/<int:user_id>")
@require_user
def remove_friend(
    user,
    user_id
):

    connection = db()

    connection.execute("""
        DELETE FROM friendships
        WHERE
            (user_id=? AND friend_id=?)
            OR
            (user_id=? AND friend_id=?)
    """, (
        user["id"],
        user_id,
        user_id,
        user["id"]
    ))

    connection.commit()
    connection.close()

    return jsonify(
        success=True
    )


# ============================================================
# PRIVATE MESSAGES
# ============================================================

@app.get("/api/dm/<int:user_id>")
@require_user
def get_dm(
    user,
    user_id
):

    connection = db()

    if not are_friends(
        connection,
        user["id"],
        user_id
    ):

        connection.close()

        return jsonify(
            error="You must be friends to DM"
        ), 403

    rows = connection.execute("""
        SELECT
            pm.id,
            pm.sender_id,
            pm.receiver_id,
            pm.message,
            pm.edited,
            pm.edited_at,
            pm.created_at,
            u.username,
            u.pfp,
            u.role,
            u.last_seen
        FROM private_messages pm
        JOIN users u
            ON u.id=pm.sender_id
        WHERE
            (pm.sender_id=? AND pm.receiver_id=?)
            OR
            (pm.sender_id=? AND pm.receiver_id=?)
        ORDER BY pm.id ASC
        LIMIT 200
    """, (
        user["id"],
        user_id,
        user_id,
        user["id"]
    )).fetchall()

    connection.close()

    result = []

    for row in rows:

        item = dict(row)

        item["online"] = is_online(
            row["last_seen"]
        )

        result.append(item)

    return jsonify(result)


@app.post("/api/dm/<int:user_id>")
@require_user
def send_dm(
    user,
    user_id
):

    data = request.get_json(
        silent=True
    ) or {}

    message = str(
        data.get(
            "message",
            ""
        )
    ).strip()

    if not message:
        return jsonify(
            error="Message cannot be empty"
        ), 400

    if len(message) > 4000:
        return jsonify(
            error="Message is too long"
        ), 400

    connection = db()

    if not are_friends(
        connection,
        user["id"],
        user_id
    ):

        connection.close()

        return jsonify(
            error="You must be friends"
        ), 403

    target = connection.execute("""
        SELECT id
        FROM users
        WHERE id=? AND banned=0
    """, (
        user_id,
    )).fetchone()

    if not target:

        connection.close()

        return jsonify(
            error="User not found"
        ), 404

    connection.execute("""
        INSERT INTO private_messages (
            sender_id,
            receiver_id,
            message,
            edited,
            edited_at,
            created_at
        )
        VALUES (
            ?,
            ?,
            ?,
            0,
            '',
            ?
        )
    """, (
        user["id"],
        user_id,
        message,
        now()
    ))

    connection.commit()
    connection.close()

    return jsonify(
        success=True
    )


# ============================================================
# REPORTS
# ============================================================

@app.post("/api/reports")
@require_user
def create_report(user):

    data = request.get_json(
        silent=True
    ) or {}

    message_id = data.get(
        "message_id"
    )

    reported_user_id = data.get(
        "user_id"
    )

    reason = str(
        data.get(
            "reason",
            "Other"
        )
    ).strip()

    details = str(
        data.get(
            "details",
            ""
        )
    ).strip()

    if not message_id and not reported_user_id:

        return jsonify(
            error="Nothing to report"
        ), 400

    connection = db()

    if message_id:

        try:
            message_id = int(
                message_id
            )

        except (
            TypeError,
            ValueError
        ):

            connection.close()

            return jsonify(
                error="Invalid message ID"
            ), 400

        message = connection.execute("""
            SELECT user_id
            FROM messages
            WHERE id=?
        """, (
            message_id,
        )).fetchone()

        if not message:

            connection.close()

            return jsonify(
                error="Message not found"
            ), 404

        reported_user_id = (
            message["user_id"]
        )

    if reported_user_id:

        try:
            reported_user_id = int(
                reported_user_id
            )

        except (
            TypeError,
            ValueError
        ):

            connection.close()

            return jsonify(
                error="Invalid user ID"
            ), 400

    if reported_user_id == user["id"]:

        connection.close()

        return jsonify(
            error="You cannot report yourself"
        ), 400

    duplicate = connection.execute("""
        SELECT id
        FROM reports
        WHERE
            reporter_id=?
            AND status='open'
            AND (
                (
                    message_id IS NOT NULL
                    AND message_id=?
                )
                OR
                (
                    message_id IS NULL
                    AND reported_user_id=?
                )
            )
        LIMIT 1
    """, (
        user["id"],
        message_id
        if message_id
        else -1,
        reported_user_id
        if reported_user_id
        else -1
    )).fetchone()

    if duplicate:

        connection.close()

        return jsonify(
            error="You already have an open report for this"
        ), 409

    connection.execute("""
        INSERT INTO reports (
            reporter_id,
            reported_user_id,
            message_id,
            reason,
            details,
            status,
            created_at,
            moderator_note
        )
        VALUES (
            ?,
            ?,
            ?,
            ?,
            ?,
            'open',
            ?,
            ''
        )
    """, (
        user["id"],
        reported_user_id,
        message_id,
        reason[:100],
        details[:2000],
        now()
    ))

    connection.commit()
    connection.close()

    return jsonify(
        success=True
    )


@app.get("/api/reports")
@require_role("moderator")
def get_reports(user):

    status = request.args.get(
        "status",
        "all"
    ).lower()

    if status not in {
        "all",
        "open",
        "resolved",
        "dismissed"
    }:

        return jsonify(
            error="Invalid status"
        ), 400

    connection = db()

    base_query = """
        SELECT
            r.*,
            reporter.username AS reporter_username,
            reported.username AS reported_username,
            m.message AS reported_message,
            resolver.username AS resolver_username
        FROM reports r
        JOIN users reporter
            ON reporter.id=r.reporter_id
        LEFT JOIN users reported
            ON reported.id=r.reported_user_id
        LEFT JOIN users resolver
            ON resolver.id=r.resolved_by
        LEFT JOIN messages m
            ON m.id=r.message_id
    """

    if status == "all":

        rows = connection.execute(
            base_query
            + """
                ORDER BY
                    CASE
                        WHEN r.status='open'
                        THEN 0
                        ELSE 1
                    END,
                    r.id DESC
                LIMIT 500
            """
        ).fetchall()

    else:

        rows = connection.execute(
            base_query
            + """
                WHERE r.status=?
                ORDER BY r.id DESC
                LIMIT 500
            """,
            (
                status,
            )
        ).fetchall()

    connection.close()

    return jsonify([
        dict(row)
        for row in rows
    ])


@app.post("/api/reports/<int:report_id>/resolve")
@require_role("moderator")
def resolve_report(
    user,
    report_id
):

    data = request.get_json(
        silent=True
    ) or {}

    note = str(
        data.get(
            "note",
            ""
        )
    ).strip()[:2000]

    connection = db()

    report = connection.execute("""
        SELECT id
        FROM reports
        WHERE id=?
    """, (
        report_id,
    )).fetchone()

    if not report:

        connection.close()

        return jsonify(
            error="Report not found"
        ), 404

    connection.execute("""
        UPDATE reports
        SET
            status='resolved',
            resolved_at=?,
            resolved_by=?,
            moderator_note=?
        WHERE id=?
    """, (
        now(),
        user["id"],
        note,
        report_id
    ))

    connection.commit()
    connection.close()

    return jsonify(
        success=True
    )


@app.post("/api/reports/<int:report_id>/dismiss")
@require_role("moderator")
def dismiss_report(
    user,
    report_id
):

    data = request.get_json(
        silent=True
    ) or {}

    note = str(
        data.get(
            "note",
            ""
        )
    ).strip()[:2000]

    connection = db()

    report = connection.execute("""
        SELECT id
        FROM reports
        WHERE id=?
    """, (
        report_id,
    )).fetchone()

    if not report:

        connection.close()

        return jsonify(
            error="Report not found"
        ), 404

    connection.execute("""
        UPDATE reports
        SET
            status='dismissed',
            resolved_at=?,
            resolved_by=?,
            moderator_note=?
        WHERE id=?
    """, (
        now(),
        user["id"],
        note,
        report_id
    ))

    connection.commit()
    connection.close()

    return jsonify(
        success=True
    )


# ============================================================
# MODERATION
# ============================================================

@app.post("/api/mod/ban/<int:user_id>")
@require_role("moderator")
def ban_user(
    user,
    user_id
):

    connection = db()

    target = connection.execute("""
        SELECT *
        FROM users
        WHERE id=?
    """, (
        user_id,
    )).fetchone()

    if not target:

        connection.close()

        return jsonify(
            error="User not found"
        ), 404

    if target["role"] == "owner":

        connection.close()

        return jsonify(
            error="Owner cannot be banned"
        ), 403

    if (
        user["role"] == "moderator"
        and target["role"]
        in (
            "admin",
            "owner"
        )
    ):

        connection.close()

        return jsonify(
            error="Moderators cannot ban admins"
        ), 403

    connection.execute("""
        UPDATE users
        SET banned=1
        WHERE id=?
    """, (
        user_id,
    ))

    connection.execute("""
        DELETE FROM sessions
        WHERE user_id=?
    """, (
        user_id,
    ))

    connection.commit()
    connection.close()

    return jsonify(
        success=True
    )


@app.post("/api/mod/unban/<int:user_id>")
@require_role("moderator")
def unban_user(
    user,
    user_id
):

    connection = db()

    target = connection.execute("""
        SELECT role
        FROM users
        WHERE id=?
    """, (
        user_id,
    )).fetchone()

    if not target:

        connection.close()

        return jsonify(
            error="User not found"
        ), 404

    connection.execute("""
        UPDATE users
        SET banned=0
        WHERE id=?
    """, (
        user_id,
    ))

    connection.commit()
    connection.close()

    return jsonify(
        success=True
    )


@app.delete("/api/mod/message/<int:message_id>")
@require_role("moderator")
def mod_delete_message(
    user,
    message_id
):

    connection = db()

    message = connection.execute("""
        SELECT id
        FROM messages
        WHERE id=?
    """, (
        message_id,
    )).fetchone()

    if not message:

        connection.close()

        return jsonify(
            error="Message not found"
        ), 404

    connection.execute("""
        DELETE FROM messages
        WHERE id=?
    """, (
        message_id,
    ))

    connection.commit()
    connection.close()

    return jsonify(
        success=True
    )


@app.get("/api/mod/users")
@require_role("moderator")
def mod_users(user):

    connection = db()

    rows = connection.execute("""
        SELECT
            id,
            username,
            role,
            banned,
            show_role_tag,
            pfp,
            description,
            pronouns,
            created_at,
            last_seen
        FROM users
        ORDER BY id DESC
        LIMIT 1000
    """).fetchall()

    connection.close()

    result = []

    for row in rows:

        item = dict(row)

        item["online"] = is_online(
            row["last_seen"]
        )

        result.append(item)

    return jsonify(result)


# ============================================================
# ADMIN ROLE MANAGEMENT
# ============================================================

@app.post("/api/admin/role/<int:user_id>")
@require_role("admin")
def change_role(
    user,
    user_id
):

    data = request.get_json(
        silent=True
    ) or {}

    new_role = str(
        data.get(
            "role",
            "user"
        )
    ).lower()

    if new_role not in ROLES:

        return jsonify(
            error="Invalid role"
        ), 400

    if new_role == "owner":

        return jsonify(
            error="Owner role cannot be assigned through this endpoint"
        ), 403

    connection = db()

    target = connection.execute("""
        SELECT *
        FROM users
        WHERE id=?
    """, (
        user_id,
    )).fetchone()

    if not target:

        connection.close()

        return jsonify(
            error="User not found"
        ), 404

    if target["role"] == "owner":

        connection.close()

        return jsonify(
            error="Owner role cannot be changed"
        ), 403

    if (
        user["role"] == "admin"
        and target["role"] == "admin"
        and target["id"] != user["id"]
    ):

        connection.close()

        return jsonify(
            error="Admins cannot change another admin"
        ), 403

    connection.execute("""
        UPDATE users
        SET role=?
        WHERE id=?
    """, (
        new_role,
        user_id
    ))

    connection.commit()
    connection.close()

    return jsonify(
        success=True
    )


# ============================================================
# OWNER API
# ============================================================

@app.post("/api/owner/ip-ban/<int:user_id>")
@require_role("owner")
def owner_ip_ban(
    user,
    user_id
):

    connection = db()

    target = connection.execute("""
        SELECT *
        FROM users
        WHERE id=?
    """, (
        user_id,
    )).fetchone()

    if not target:

        connection.close()

        return jsonify(
            error="User not found"
        ), 404

    if target["role"] == "owner":

        connection.close()

        return jsonify(
            error="Cannot IP ban owner"
        ), 403

    ip = target["ip"]

    if not ip or ip == "unknown":

        connection.close()

        return jsonify(
            error="No usable IP is recorded"
        ), 400

    connection.execute("""
        INSERT OR IGNORE INTO ip_bans (
            ip,
            created_at
        )
        VALUES (?, ?)
    """, (
        ip,
        now()
    ))

    connection.execute("""
        UPDATE users
        SET banned=1
        WHERE id=?
    """, (
        user_id,
    ))

    connection.execute("""
        DELETE FROM sessions
        WHERE user_id=?
    """, (
        user_id,
    ))

    connection.commit()
    connection.close()

    return jsonify(
        success=True
    )


@app.get("/api/owner/ip-bans")
@require_role("owner")
def owner_ip_bans(user):

    connection = db()

    rows = connection.execute("""
        SELECT *
        FROM ip_bans
        ORDER BY id DESC
    """).fetchall()

    connection.close()

    return jsonify([
        dict(row)
        for row in rows
    ])


@app.delete("/api/owner/ip-ban/<int:ban_id>")
@require_role("owner")
def owner_remove_ip_ban(
    user,
    ban_id
):

    connection = db()

    connection.execute("""
        DELETE FROM ip_bans
        WHERE id=?
    """, (
        ban_id,
    ))

    connection.commit()
    connection.close()

    return jsonify(
        success=True
    )


@app.delete("/api/owner/account/<int:user_id>")
@require_role("owner")
def owner_delete_account(
    user,
    user_id
):

    connection = db()

    target = connection.execute("""
        SELECT *
        FROM users
        WHERE id=?
    """, (
        user_id,
    )).fetchone()

    if not target:

        connection.close()

        return jsonify(
            error="User not found"
        ), 404

    if target["role"] == "owner":

        connection.close()

        return jsonify(
            error="Cannot delete owner"
        ), 403

    connection.execute("""
        DELETE FROM sessions
        WHERE user_id=?
    """, (
        user_id,
    ))

    connection.execute("""
        DELETE FROM friendships
        WHERE user_id=?
           OR friend_id=?
    """, (
        user_id,
        user_id
    ))

    connection.execute("""
        DELETE FROM private_messages
        WHERE sender_id=?
           OR receiver_id=?
    """, (
        user_id,
        user_id
    ))

    connection.execute("""
        DELETE FROM reports
        WHERE reporter_id=?
           OR reported_user_id=?
    """, (
        user_id,
        user_id
    ))

    connection.execute("""
        DELETE FROM messages
        WHERE user_id=?
    """, (
        user_id,
    ))

    connection.execute("""
        DELETE FROM users
        WHERE id=?
    """, (
        user_id,
    ))

    connection.commit()
    connection.close()

    return jsonify(
        success=True
    )


# ============================================================
# WEB CLIENT
# ============================================================

HTML = r"""
<!DOCTYPE html>
<html>
<head>

<meta charset="UTF-8">

<meta
    name="viewport"
    content="width=device-width, initial-scale=1.0"
>

<title>SpookChat</title>

<style>

* {
    box-sizing: border-box;
}

body {
    margin: 0;
    background: #08080d;
    color: #eeeeF5;
    font-family: Arial, Helvetica, sans-serif;
    height: 100vh;
    overflow: hidden;
}

button,
input,
textarea {
    font-family: inherit;
}

button {
    cursor: pointer;
}

.hidden {
    display: none !important;
}

/* ============================================================
   AUTH
   ============================================================ */

#auth {
    width: 100%;
    height: 100vh;
    display: flex;
    justify-content: center;
    align-items: center;
}

.auth-box {
    width: 380px;
    background: #111118;
    border: 1px solid #292936;
    border-radius: 15px;
    padding: 30px;
    box-shadow: 0 20px 60px rgba(0,0,0,.45);
}

.brand {
    font-size: 26px;
    font-weight: bold;
}

.brand span {
    color: #8c52ff;
}

.auth-box h1 {
    margin-top: 0;
}

.auth-box input {
    width: 100%;
    margin-top: 10px;
    padding: 13px;
    background: #0b0b10;
    color: white;
    border: 1px solid #292936;
    border-radius: 8px;
    outline: none;
}

.primary {
    width: 100%;
    margin-top: 15px;
    padding: 13px;
    background: #7d45e8;
    border: none;
    border-radius: 8px;
    color: white;
    font-weight: bold;
}

.switch {
    margin-top: 15px;
    color: #a979ff;
    cursor: pointer;
    text-align: center;
}

.error {
    color: #ff6b6b;
    margin-bottom: 8px;
}


/* ============================================================
   APP
   ============================================================ */

#app {
    display: flex;
    height: 100vh;
}

.sidebar {
    width: 240px;
    flex-shrink: 0;
    border-right: 1px solid #292936;
    background: #101016;
    padding: 20px;
}

.sidebar .brand {
    margin-bottom: 25px;
}

.nav button {
    display: block;
    width: 100%;
    text-align: left;
    background: transparent;
    color: #a5a5b1;
    border: none;
    padding: 12px;
    border-radius: 7px;
    margin-bottom: 4px;
}

.nav button:hover {
    background: #191922;
    color: white;
}

.friends-title {
    margin-top: 35px;
    font-size: 11px;
    color: #777783;
    text-transform: uppercase;
}

#friendList {
    margin-top: 10px;
}

.dm-friend {
    padding: 9px;
    color: #aaa;
    cursor: pointer;
    border-radius: 7px;
}

.dm-friend:hover {
    background: #191922;
    color: white;
}

.main {
    flex: 1;
    min-width: 0;
    display: flex;
    flex-direction: column;
}

.topbar {
    height: 60px;
    border-bottom: 1px solid #292936;
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 0 22px;
}

.channel {
    font-weight: bold;
}

.channel span {
    color: #8c52ff;
}

#currentUser {
    color: #aaa;
}

.messages {
    flex: 1;
    overflow-y: auto;
    padding: 20px;
}

.composer {
    border-top: 1px solid #292936;
    padding: 14px;
}

.composer-inner {
    display: flex;
    gap: 8px;
}

.composer input {
    flex: 1;
    background: #111118;
    color: white;
    border: 1px solid #292936;
    border-radius: 9px;
    padding: 13px;
    outline: none;
}

.composer button {
    width: 50px;
    border: none;
    border-radius: 9px;
    background: #7d45e8;
    color: white;
}

.right {
    width: 280px;
    border-left: 1px solid #292936;
    background: #101016;
    padding: 20px;
}


/* ============================================================
   MESSAGES
   ============================================================ */

.message {
    display: flex;
    gap: 12px;
    padding: 10px;
    border-radius: 8px;
    position: relative;
}

.message:hover {
    background: #101017;
}

.avatar {
    width: 40px;
    height: 40px;
    flex-shrink: 0;
    border-radius: 50%;
    background: #24242e;
    display: flex;
    justify-content: center;
    align-items: center;
    overflow: hidden;
}

.avatar img {
    width: 100%;
    height: 100%;
    object-fit: cover;
}

.message-content {
    min-width: 0;
}

.message-header {
    display: flex;
    align-items: center;
    gap: 8px;
}

.username {
    font-weight: bold;
    color: white;
    cursor: pointer;
}

.timestamp {
    color: #666673;
    font-size: 11px;
}

.message-text {
    margin-top: 4px;
    color: #d8d8e0;
    white-space: pre-wrap;
    word-break: break-word;
}

.edited {
    color: #666673;
    font-size: 11px;
    margin-left: 6px;
}


/* ============================================================
   CONTEXT MENU
   ============================================================ */

.context-menu {
    position: fixed;
    z-index: 9999;
    width: 190px;
    background: #15151d;
    border: 1px solid #30303d;
    border-radius: 9px;
    padding: 6px;
    box-shadow: 0 15px 40px rgba(0,0,0,.5);
}

.context-menu button {
    width: 100%;
    border: none;
    background: transparent;
    color: #ddd;
    text-align: left;
    padding: 10px;
    border-radius: 6px;
}

.context-menu button:hover {
    background: #24242f;
}

.context-menu .danger {
    color: #ff7373;
}


/* ============================================================
   PROFILES
   ============================================================ */

.profile-card {
    text-align: center;
}

.big-avatar {
    width: 90px;
    height: 90px;
    border-radius: 50%;
    background: #24242e;
    margin: 0 auto 12px;
    display: flex;
    justify-content: center;
    align-items: center;
    overflow: hidden;
    font-size: 35px;
}

.big-avatar img {
    width: 100%;
    height: 100%;
    object-fit: cover;
}

.profile-name {
    font-size: 20px;
    font-weight: bold;
}

.role-tag {
    font-size: 10px;
    background: #7d45e8;
    border-radius: 4px;
    padding: 3px 5px;
    margin-left: 4px;
}

.status {
    margin-top: 7px;
    color: #888;
}

.status-dot {
    display: inline-block;
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: #666;
    margin-right: 5px;
}

.status-dot.online {
    background: #45d483;
}

.profile-description {
    color: #999;
    margin: 15px 0;
    line-height: 1.4;
}

.action-button {
    border: none;
    background: #7d45e8;
    color: white;
    padding: 9px 13px;
    border-radius: 7px;
}


/* ============================================================
   PANELS
   ============================================================ */

.panel {
    max-width: 900px;
    margin: 0 auto;
    width: 100%;
}

.panel-card {
    background: #111118;
    border: 1px solid #292936;
    border-radius: 10px;
    padding: 15px;
    margin-bottom: 10px;
}

.panel-row {
    display: flex;
    justify-content: space-between;
    gap: 15px;
}

.small-button {
    border: 1px solid #343440;
    background: #191922;
    color: white;
    padding: 7px 10px;
    border-radius: 6px;
    margin: 2px;
}

.small-button:hover {
    background: #252530;
}

.small-button.danger {
    color: #ff7777;
}


/* ============================================================
   FRIENDS
   ============================================================ */

.friend-search {
    display: flex;
    gap: 8px;
    margin-bottom: 20px;
}

.friend-search input {
    flex: 1;
    padding: 11px;
    background: #0c0c11;
    color: white;
    border: 1px solid #292936;
    border-radius: 7px;
}

.friend-card {
    display: flex;
    align-items: center;
    justify-content: space-between;
    background: #111118;
    border: 1px solid #292936;
    padding: 12px;
    border-radius: 9px;
    margin-bottom: 8px;
}

.friend-left {
    display: flex;
    align-items: center;
    gap: 10px;
}


/* ============================================================
   MODAL
   ============================================================ */

.modal {
    position: fixed;
    inset: 0;
    background: rgba(0,0,0,.7);
    display: flex;
    justify-content: center;
    align-items: center;
    z-index: 10000;
}

.modal-box {
    width: 500px;
    max-width: calc(100% - 30px);
    background: #111118;
    border: 1px solid #292936;
    border-radius: 12px;
    padding: 20px;
}

.modal-box input,
.modal-box textarea {
    width: 100%;
    background: #09090d;
    color: white;
    border: 1px solid #292936;
    border-radius: 7px;
    padding: 10px;
    margin-bottom: 10px;
}

.modal-box textarea {
    min-height: 120px;
}

.modal-actions {
    display: flex;
    justify-content: flex-end;
    gap: 8px;
    margin-top: 12px;
}

</style>
</head>

<body>

<!-- ==========================================================
     AUTH
     ========================================================== -->

<div id="auth">

    <div class="auth-box">

        <div class="brand">
            Spook<span>Chat</span>
        </div>

        <h2 id="authTitle">
            Login
        </h2>

        <div
            id="authError"
            class="error"
        ></div>

        <input
            id="authUsername"
            placeholder="Username"
        >

        <input
            id="authPassword"
            placeholder="Password"
            type="password"
        >

        <button
            class="primary"
            onclick="authAction()"
        >
            <span id="authButton">
                Login
            </span>
        </button>

        <div
            class="switch"
            onclick="toggleAuth()"
            id="authSwitch"
        >
            Need an account? Register
        </div>

    </div>

</div>


<!-- ==========================================================
     APP
     ========================================================== -->

<div
    id="app"
    class="hidden"
>

    <aside class="sidebar">

        <div class="brand">
            Spook<span>Chat</span>
        </div>

        <div class="nav">

            <button
                onclick="showHome()"
            >
                💬 Chat
            </button>

            <button
                onclick="showFriends()"
            >
                👥 Friends
            </button>

            <button
                onclick="showProfile()"
            >
                👤 Profile
            </button>

            <button
                id="moderationButton"
                class="hidden"
                onclick="showModeration()"
            >
                🛡️ Moderation
            </button>

            <button
                id="ownerButton"
                class="hidden"
                onclick="showOwner()"
            >
                ⚙️ Owner
            </button>

            <button
                onclick="logout()"
            >
                🚪 Logout
            </button>

        </div>

        <div class="friends-title">
            Direct Messages
        </div>

        <div id="friendList"></div>

    </aside>


    <main class="main">

        <div class="topbar">

            <div
                class="channel"
                id="channelName"
            >
                <span>#</span>
                general
            </div>

            <div id="currentUser"></div>

        </div>

        <div
            id="mainContent"
            class="messages"
        ></div>

        <div
            id="composer"
            class="composer"
        >

            <div class="composer-inner">

                <input
                    id="messageInput"
                    placeholder="Message #general"
                    onkeydown="
                        if(event.key==='Enter')
                        sendMessage()
                    "
                >

                <button
                    onclick="sendMessage()"
                >
                    ➤
                </button>

            </div>

        </div>

    </main>


    <aside
        class="right"
        id="rightPanel"
    ></aside>

</div>


<!-- ==========================================================
     MODAL
     ========================================================== -->

<div
    id="modal"
    class="modal hidden"
>

    <div
        class="modal-box"
        id="modalContent"
    ></div>

</div>


<!-- ==========================================================
     JAVASCRIPT
     ========================================================== -->

<script>

let token =
    localStorage.getItem(
        "spookchat_token"
    );

let currentUser = null;

let currentDM = null;

let currentPage = "chat";

let registerMode = false;

let contextMessage = null;


/* ============================================================
   HELPERS
   ============================================================ */

function escapeHtml(value) {

    return String(
        value ?? ""
    )
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}


function escapeAttr(value) {
    return escapeHtml(value);
}


async function api(
    url,
    options = {}
) {

    options.headers = {
        ...(options.headers || {}),
        "Content-Type":
            "application/json"
    };

    if (token) {
        options.headers[
            "Authorization"
        ] = token;
    }

    const response =
        await fetch(
            url,
            options
        );

    const data =
        await response
            .json()
            .catch(() => ({}));

    if (!response.ok) {

        if (
            response.status === 401
            &&
            token
        ) {

            localStorage.removeItem(
                "spookchat_token"
            );

            token = null;

            location.reload();
        }

        throw new Error(
            data.error ||
            "Request failed"
        );
    }

    return data;
}


/* ============================================================
   AUTH
   ============================================================ */

function toggleAuth() {

    registerMode =
        !registerMode;

    document.getElementById(
        "authTitle"
    ).textContent =
        registerMode
        ? "Register"
        : "Login";

    document.getElementById(
        "authButton"
    ).textContent =
        registerMode
        ? "Register"
        : "Login";

    document.getElementById(
        "authSwitch"
    ).textContent =
        registerMode
        ? "Already have an account? Login"
        : "Need an account? Register";

    document.getElementById(
        "authError"
    ).textContent =
        "";
}


async function authAction() {

    const username =
        document.getElementById(
            "authUsername"
        ).value.trim();

    const password =
        document.getElementById(
            "authPassword"
        ).value;

    const error =
        document.getElementById(
            "authError"
        );

    error.textContent = "";

    try {

        const result =
            await api(
                registerMode
                ? "/api/register"
                : "/api/login",
                {
                    method: "POST",
                    body: JSON.stringify({
                        username,
                        password
                    })
                }
            );

        token =
            result.token;

        localStorage.setItem(
            "spookchat_token",
            token
        );

        currentUser =
            result.user;

        startApp();

    } catch (err) {

        error.textContent =
            err.message;
    }
}


/* ============================================================
   APP START
   ============================================================ */

async function startApp() {

    try {

        currentUser =
            await api(
                "/api/me"
            );

    } catch {

        localStorage.removeItem(
            "spookchat_token"
        );

        token = null;

        document.getElementById(
            "auth"
        ).classList.remove(
            "hidden"
        );

        document.getElementById(
            "app"
        ).classList.add(
            "hidden"
        );

        return;
    }

    document.getElementById(
        "auth"
    ).classList.add(
        "hidden"
    );

    document.getElementById(
        "app"
    ).classList.remove(
        "hidden"
    );

    document.getElementById(
        "currentUser"
    ).textContent =
        currentUser.username;

    updateRoleButtons();

    await showHome();

    await loadFriendList();
}


function updateRoleButtons() {

    const moderation =
        document.getElementById(
            "moderationButton"
        );

    const owner =
        document.getElementById(
            "ownerButton"
        );

    if (
        currentUser.role === "moderator"
        ||
        currentUser.role === "admin"
        ||
        currentUser.role === "owner"
    ) {
        moderation.classList.remove(
            "hidden"
        );
    } else {
        moderation.classList.add(
            "hidden"
        );
    }

    if (
        currentUser.role === "owner"
    ) {
        owner.classList.remove(
            "hidden"
        );
    } else {
        owner.classList.add(
            "hidden"
        );
    }
}


/* ============================================================
   LOGOUT
   ============================================================ */

async function logout() {

    try {
        await api(
            "/api/logout",
            {
                method: "POST"
            }
        );
    } catch {}

    localStorage.removeItem(
        "spookchat_token"
    );

    token = null;

    location.reload();
}


/* ============================================================
   CHAT
   ============================================================ */

async function showHome() {

    currentPage = "chat";

    currentDM = null;

    document.getElementById(
        "channelName"
    ).innerHTML =
        "<span>#</span> general";

    document.getElementById(
        "composer"
    ).classList.remove(
        "hidden"
    );

    document.getElementById(
        "messageInput"
    ).placeholder =
        "Message #general";

    await loadMessages();

    renderSelfProfile();
}


async function loadMessages() {

    const messages =
        await api(
            "/api/messages"
        );

    const container =
        document.getElementById(
            "mainContent"
        );

    container.innerHTML = "";

    for (
        const message
        of messages
    ) {

        renderMessage(
            message,
            container
        );
    }

    container.scrollTop =
        container.scrollHeight;
}


/* ============================================================
   MESSAGE RENDERING
   ============================================================ */

function renderMessage(
    message,
    container
) {

    const wrapper =
        document.createElement(
            "div"
        );

    wrapper.className =
        "message";

    wrapper.dataset.messageId =
        message.id;

    wrapper.innerHTML = `

        <div class="avatar">

            ${
                message.pfp
                ?
                `<img src="${escapeAttr(message.pfp)}">`
                :
                escapeHtml(
                    message.username
                        .charAt(0)
                        .toUpperCase()
                )
            }

        </div>

        <div class="message-content">

            <div class="message-header">

                <span
                    class="username"
                    onclick="
                        viewProfile(
                            ${message.user_id}
                        )
                    "
                >
                    ${escapeHtml(
                        message.username
                    )}
                </span>

                ${
                    message.role !== "user"
                    ?
                    `<span class="role-tag">
                        ${escapeHtml(
                            message.role.toUpperCase()
                        )}
                    </span>`
                    :
                    ""
                }

                <span class="timestamp">
                    ${new Date(
                        message.created_at
                    ).toLocaleTimeString()}
                </span>

            </div>

            <div class="message-text">
                ${escapeHtml(
                    message.message
                )}

                ${
                    message.edited
                    ?
                    `<span class="edited">
                        (edited)
                    </span>`
                    :
                    ""
                }

            </div>

        </div>
    `;


    /*
     * THIS IS THE RIGHT-CLICK FEATURE.
     */
    wrapper.addEventListener(
        "contextmenu",
        function(event) {

            event.preventDefault();

            openMessageMenu(
                event,
                message
            );
        }
    );


    container.appendChild(
        wrapper
    );
}


/* ============================================================
   RIGHT CLICK MESSAGE MENU
   ============================================================ */

function openMessageMenu(
    event,
    message
) {

    closeContextMenu();

    contextMessage =
        message;

    const menu =
        document.createElement(
            "div"
        );

    menu.id =
        "messageContextMenu";

    menu.className =
        "context-menu";

    /*
     * EVERYONE can view profile
     * and copy the message.
     */

    menu.innerHTML = `

        <button
            onclick="
                viewProfile(
                    ${message.user_id}
                );
                closeContextMenu();
            "
        >
            👤 View Profile
        </button>

        <button
            onclick="
                copyMessage(
                    ${message.id}
                );
                closeContextMenu();
            "
        >
            📋 Copy Message
        </button>

        ${
            message.user_id
            === currentUser.id
            ?
            `

                <button
                    onclick="
                        editMessage(
                            ${message.id},
                            ${JSON.stringify(
                                message.message
                            )}
                        );
                        closeContextMenu();
                    "
                >
                    ✏️ Edit Message
                </button>

                <button
                    class="danger"
                    onclick="
                        deleteOwnMessage(
                            ${message.id}
                        );
                        closeContextMenu();
                    "
                >
                    🗑️ Delete Message
                </button>

            `
            :
            `

                <button
                    class="danger"
                    onclick="
                        reportMessage(
                            ${message.id}
                        );
                        closeContextMenu();
                    "
                >
                    🚩 Report Message
                </button>

            `
        }

    `;

    document.body.appendChild(
        menu
    );

    let x = event.clientX;
    let y = event.clientY;

    const width =
        menu.offsetWidth;

    const height =
        menu.offsetHeight;

    if (
        x + width
        >
        window.innerWidth
    ) {
        x =
            window.innerWidth
            - width
            - 8;
    }

    if (
        y + height
        >
        window.innerHeight
    ) {
        y =
            window.innerHeight
            - height
            - 8;
    }

    menu.style.left =
        x + "px";

    menu.style.top =
        y + "px";
}


function closeContextMenu() {

    const menu =
        document.getElementById(
            "messageContextMenu"
        );

    if (menu) {
        menu.remove();
    }

    contextMessage =
        null;
}


document.addEventListener(
    "click",
    function(event) {

        const menu =
            document.getElementById(
                "messageContextMenu"
            );

        if (
            menu
            &&
            !menu.contains(
                event.target
            )
        ) {
            closeContextMenu();
        }
    }
);


document.addEventListener(
    "keydown",
    function(event) {

        if (
            event.key === "Escape"
        ) {
            closeContextMenu();
        }
    }
);


/* ============================================================
   COPY MESSAGE
   ============================================================ */

async function copyMessage(
    messageId
) {

    try {

        const messages =
            await api(
                "/api/messages"
            );

        const message =
            messages.find(
                x =>
                    x.id
                    ===
                    messageId
            );

        if (!message) {
            throw new Error(
                "Message not found"
            );
        }

        await navigator.clipboard.writeText(
            message.message
        );

    } catch (err) {

        alert(
            err.message
        );
    }
}


/* ============================================================
   EDIT MESSAGE
   ============================================================ */

async function editMessage(
    messageId,
    oldMessage
) {

    const newMessage =
        prompt(
            "Edit message:",
            oldMessage
        );

    if (
        newMessage === null
    ) {
        return;
    }

    try {

        await api(
            "/api/messages/"
            + messageId,
            {
                method: "PUT",
                body: JSON.stringify({
                    message:
                        newMessage
                })
            }
        );

        await loadMessages();

    } catch (err) {

        alert(
            err.message
        );
    }
}


/* ============================================================
   DELETE OWN MESSAGE
   ============================================================ */

async function deleteOwnMessage(
    messageId
) {

    if (
        !confirm(
            "Delete this message?"
        )
    ) {
        return;
    }

    try {

        await api(
            "/api/messages/"
            + messageId,
            {
                method: "DELETE"
            }
        );

        await loadMessages();

    } catch (err) {

        alert(
            err.message
        );
    }
}


/* ============================================================
   REPORT MESSAGE
   ============================================================ */

async function reportMessage(
    messageId
) {

    const reason =
        prompt(
            "Why are you reporting this message?",
            "Other"
        );

    if (
        reason === null
    ) {
        return;
    }

    const details =
        prompt(
            "Additional details (optional):",
            ""
        );

    if (
        details === null
    ) {
        return;
    }

    try {

        await api(
            "/api/reports",
            {
                method: "POST",
                body: JSON.stringify({
                    message_id:
                        messageId,
                    reason:
                        reason,
                    details:
                        details
                })
            }
        );

        alert(
            "Report submitted."
        );

    } catch (err) {

        alert(
            err.message
        );
    }
}


/* ============================================================
   PROFILE
   ============================================================ */

async function viewProfile(
    userId
) {

    try {

        const profile =
            await api(
                "/api/users/"
                + userId
            );

        renderProfileCard(
            profile
        );

    } catch (err) {

        alert(
            err.message
        );
    }
}


function renderSelfProfile() {

    renderProfileCard(
        currentUser
    );
}


function renderProfileCard(
    user
) {

    const panel =
        document.getElementById(
            "rightPanel"
        );

    panel.innerHTML = `

        <div class="profile-card">

            <div class="big-avatar">

                ${
                    user.pfp
                    ?
                    `<img src="${escapeAttr(user.pfp)}">`
                    :
                    escapeHtml(
                        user.username
                            .charAt(0)
                            .toUpperCase()
                    )
                }

            </div>

            <div class="profile-name">

                ${escapeHtml(
                    user.username
                )}

                ${
                    user.role !== "user"
                    ?
                    `<span class="role-tag">
                        ${escapeHtml(
                            user.role.toUpperCase()
                        )}
                    </span>`
                    :
                    ""
                }

            </div>

            <div class="status">

                <span
                    class="status-dot ${
                        user.online
                        ? "online"
                        : ""
                    }"
                ></span>

                ${
                    user.online
                    ? "Online"
                    : "Offline"
                }

            </div>

            ${
                user.pronouns
                ?
                `<div style="color:#888">
                    ${escapeHtml(
                        user.pronouns
                    )}
                </div>`
                :
                ""
            }

            <div class="profile-description">

                ${escapeHtml(
                    user.description
                    ||
                    "No description."
                )}

            </div>

            ${
                user.id
                ===
                currentUser.id
                ?
                `
                    <button
                        class="action-button"
                        onclick="editProfile()"
                    >
                        Edit Profile
                    </button>
                `
                :
                ""
            }

        </div>
    `;
}


/* ============================================================
   EDIT PROFILE
   ============================================================ */

function editProfile() {

    openModal(`
        <h2>Edit Profile</h2>

        <input
            id="editUsername"
            value="${escapeAttr(
                currentUser.username
            )}"
            placeholder="Username"
        >

        <input
            id="editPfp"
            value="${escapeAttr(
                currentUser.pfp
            )}"
            placeholder="Profile picture URL"
        >

        <input
            id="editPronouns"
            value="${escapeAttr(
                currentUser.pronouns
            )}"
            placeholder="Pronouns"
        >

        <textarea
            id="editDescription"
            placeholder="Description"
        >${escapeHtml(
            currentUser.description
        )}</textarea>

        <label>
            <input
                type="checkbox"
                id="showRoleTag"
                ${
                    currentUser.show_role_tag
                    ? "checked"
                    : ""
                }
            >
            Show role tag
        </label>

        <div class="modal-actions">

            <button
                class="small-button"
                onclick="closeModal()"
            >
                Cancel
            </button>

            <button
                class="action-button"
                onclick="saveProfile()"
            >
                Save
            </button>

        </div>
    `);
}


async function saveProfile() {

    try {

        await api(
            "/api/profile",
            {
                method: "PUT",
                body: JSON.stringify({

                    username:
                        document.getElementById(
                            "editUsername"
                        ).value,

                    pfp:
                        document.getElementById(
                            "editPfp"
                        ).value,

                    pronouns:
                        document.getElementById(
                            "editPronouns"
                        ).value,

                    description:
                        document.getElementById(
                            "editDescription"
                        ).value
                })
            }
        );

        await api(
            "/api/role-tag",
            {
                method: "POST",
                body: JSON.stringify({
                    show:
                        document.getElementById(
                            "showRoleTag"
                        ).checked
                })
            }
        );

        currentUser =
            await api(
                "/api/me"
            );

        document.getElementById(
            "currentUser"
        ).textContent =
            currentUser.username;

        closeModal();

        renderSelfProfile();

        updateRoleButtons();

    } catch (err) {

        alert(
            err.message
        );
    }
}


/* ============================================================
   FRIENDS PAGE
   ============================================================ */

async function showFriends() {

    currentPage =
        "friends";

    currentDM = null;

    document.getElementById(
        "channelName"
    ).innerHTML =
        "👥 Friends";

    document.getElementById(
        "composer"
    ).classList.add(
        "hidden"
    );

    const main =
        document.getElementById(
            "mainContent"
        );

    main.innerHTML = `

        <div class="panel">

            <h2>Friends</h2>

            <div class="friend-search">

                <input
                    id="friendUsername"
                    placeholder="Enter username"
                    onkeydown="
                        if(event.key==='Enter')
                        addFriend()
                    "
                >

                <button
                    class="action-button"
                    onclick="addFriend()"
                >
                    Add Friend
                </button>

            </div>

            <h3>Friend Requests</h3>

            <div id="friendRequests">
                Loading...
            </div>

            <h3>My Friends</h3>

            <div id="friends">
                Loading...
            </div>

        </div>
    `;

    await loadFriends();
}


async function addFriend() {

    const input =
        document.getElementById(
            "friendUsername"
        );

    const username =
        input.value.trim();

    if (!username) {
        alert(
            "Enter a username."
        );
        return;
    }

    try {

        const result =
            await api(
                "/api/friends/add",
                {
                    method: "POST",
                    body: JSON.stringify({
                        username
                    })
                }
            );

        if (
            result.status
            ===
            "accepted"
        ) {
            alert(
                "Friend request accepted."
            );
        } else {
            alert(
                "Friend request sent."
            );
        }

        input.value = "";

        await loadFriends();

        await loadFriendList();

    } catch (err) {

        alert(
            err.message
        );
    }
}


async function loadFriends() {

    try {

        const friends =
            await api(
                "/api/friends"
            );

        const requests =
            await api(
                "/api/friends/requests"
            );

        const friendsContainer =
            document.getElementById(
                "friends"
            );

        const requestsContainer =
            document.getElementById(
                "friendRequests"
            );

        if (
            !friendsContainer
            ||
            !requestsContainer
        ) {
            return;
        }

        requestsContainer.innerHTML = "";

        if (!requests.length) {

            requestsContainer.innerHTML =
                "<div style='color:#777'>No requests.</div>";

        } else {

            for (
                const request
                of requests
            ) {

                const card =
                    document.createElement(
                        "div"
                    );

                card.className =
                    "friend-card";

                card.innerHTML = `

                    <div class="friend-left">

                        <div class="avatar">
                            ${
                                request.pfp
                                ?
                                `<img src="${escapeAttr(request.pfp)}">`
                                :
                                escapeHtml(
                                    request.username
                                        .charAt(0)
                                        .toUpperCase()
                                )
                            }
                        </div>

                        <div>
                            <b>
                                ${escapeHtml(
                                    request.username
                                )}
                            </b>

                            <div>
                                ${
                                    request.online
                                    ? "🟢 Online"
                                    : "⚫ Offline"
                                }
                            </div>
                        </div>

                    </div>

                    <button
                        class="small-button"
                        onclick="
                            acceptFriend(
                                ${request.request_id}
                            )
                        "
                    >
                        Accept
                    </button>
                `;

                requestsContainer.appendChild(
                    card
                );
            }
        }

        friendsContainer.innerHTML = "";

        if (!friends.length) {

            friendsContainer.innerHTML =
                "<div style='color:#777'>No friends yet.</div>";

        } else {

            for (
                const friend
                of friends
            ) {

                const card =
                    document.createElement(
                        "div"
                    );

                card.className =
                    "friend-card";

                card.innerHTML = `

                    <div
                        class="friend-left"
                        onclick="
                            viewProfile(
                                ${friend.id}
                            )
                        "
                        style="cursor:pointer"
                    >

                        <div class="avatar">

                            ${
                                friend.pfp
                                ?
                                `<img src="${escapeAttr(friend.pfp)}">`
                                :
                                escapeHtml(
                                    friend.username
                                        .charAt(0)
                                        .toUpperCase()
                                )
                            }

                        </div>

                        <div>

                            <b>
                                ${escapeHtml(
                                    friend.username
                                )}
                            </b>

                            <div>

                                <span
                                    class="status-dot ${
                                        friend.online
                                        ? "online"
                                        : ""
                                    }"
                                ></span>

                                ${
                                    friend.online
                                    ? "Online"
                                    : "Offline"
                                }

                            </div>

                        </div>

                    </div>

                    <button
                        class="small-button"
                        onclick="
                            loadDM(
                                ${friend.id}
                            )
                        "
                    >
                        Message
                    </button>

                `;

                friendsContainer.appendChild(
                    card
                );
            }
        }

    } catch (err) {

        console.error(
            err
        );
    }
}


async function acceptFriend(
    requestId
) {

    try {

        await api(
            "/api/friends/accept/"
            + requestId,
            {
                method: "POST"
            }
        );

        await loadFriends();

        await loadFriendList();

    } catch (err) {

        alert(
            err.message
        );
    }
}


async function loadFriendList() {

    try {

        const friends =
            await api(
                "/api/friends"
            );

        const container =
            document.getElementById(
                "friendList"
            );

        container.innerHTML = "";

        for (
            const friend
            of friends
        ) {

            const item =
                document.createElement(
                    "div"
                );

            item.className =
                "dm-friend";

            item.innerHTML = `

                <span
                    class="status-dot ${
                        friend.online
                        ? "online"
                        : ""
                    }"
                ></span>

                ${escapeHtml(
                    friend.username
                )}

            `;

            item.onclick =
                () => loadDM(
                    friend.id
                );

            container.appendChild(
                item
            );
        }

    } catch {}
}


/* ============================================================
   DM
   ============================================================ */

async function loadDM(
    userId
) {

    currentPage =
        "chat";

    currentDM =
        userId;

    const profile =
        await api(
            "/api/users/"
            + userId
        );

    document.getElementById(
        "channelName"
    ).innerHTML =
        "💬 "
        +
        escapeHtml(
            profile.username
        );

    document.getElementById(
        "composer"
    ).classList.remove(
        "hidden"
    );

    document.getElementById(
        "messageInput"
    ).placeholder =
        "Message "
        +
        profile.username;

    const messages =
        await api(
            "/api/dm/"
            + userId
        );

    const container =
        document.getElementById(
            "mainContent"
        );

    container.innerHTML = "";

    for (
        const message
        of messages
    ) {

        const wrapper =
            document.createElement(
                "div"
            );

        wrapper.className =
            "message";

        wrapper.innerHTML = `

            <div class="avatar">

                ${
                    message.pfp
                    ?
                    `<img src="${escapeAttr(message.pfp)}">`
                    :
                    escapeHtml(
                        message.username
                            .charAt(0)
                            .toUpperCase()
                    )
                }

            </div>

            <div class="message-content">

                <div class="message-header">

                    <span class="username">
                        ${escapeHtml(
                            message.username
                        )}
                    </span>

                    <span class="timestamp">
                        ${new Date(
                            message.created_at
                        ).toLocaleTimeString()}
                    </span>

                </div>

                <div class="message-text">

                    ${escapeHtml(
                        message.message
                    )}

                    ${
                        message.edited
                        ?
                        `<span class="edited">
                            (edited)
                        </span>`
                        :
                        ""
                    }

                </div>

            </div>
        `;

        container.appendChild(
            wrapper
        );
    }

    container.scrollTop =
        container.scrollHeight;

    renderProfileCard(
        profile
    );
}


async function sendMessage() {

    const input =
        document.getElementById(
            "messageInput"
        );

    const message =
        input.value.trim();

    if (!message) {
        return;
    }

    try {

        if (currentDM) {

            await api(
                "/api/dm/"
                + currentDM,
                {
                    method: "POST",
                    body: JSON.stringify({
                        message
                    })
                }
            );

            input.value = "";

            await loadDM(
                currentDM
            );

        } else {

            await api(
                "/api/messages",
                {
                    method: "POST",
                    body: JSON.stringify({
                        message
                    })
                }
            );

            input.value = "";

            await loadMessages();
        }

    } catch (err) {

        alert(
            err.message
        );
    }
}


/* ============================================================
   MODERATION
   ============================================================ */

async function showModeration() {

    currentPage =
        "moderation";

    currentDM = null;

    document.getElementById(
        "channelName"
    ).innerHTML =
        "🛡️ Moderation";

    document.getElementById(
        "composer"
    ).classList.add(
        "hidden"
    );

    const main =
        document.getElementById(
            "mainContent"
        );

    main.innerHTML = `

        <div class="panel">

            <h2>Reports</h2>

            <div
                style="
                    display:flex;
                    gap:8px;
                    margin-bottom:15px
                "
            >

                <button
                    class="small-button"
                    onclick="
                        loadReports('open')
                    "
                >
                    Open
                </button>

                <button
                    class="small-button"
                    onclick="
                        loadReports('resolved')
                    "
                >
                    Resolved
                </button>

                <button
                    class="small-button"
                    onclick="
                        loadReports('dismissed')
                    "
                >
                    Dismissed
                </button>

                <button
                    class="small-button"
                    onclick="
                        loadReports('all')
                    "
                >
                    All
                </button>

            </div>

            <div id="reports">
                Loading...
            </div>

        </div>
    `;

    await loadReports(
        "open"
    );
}


async function loadReports(
    status
) {

    try {

        const reports =
            await api(
                "/api/reports?status="
                +
                encodeURIComponent(
                    status
                )
            );

        const container =
            document.getElementById(
                "reports"
            );

        if (!container) {
            return;
        }

        container.innerHTML = "";

        if (!reports.length) {

            container.innerHTML =
                `
                    <div class="panel-card">
                        No reports found.
                    </div>
                `;

            return;
        }

        for (
            const report
            of reports
        ) {

            const card =
                document.createElement(
                    "div"
                );

            card.className =
                "panel-card";

            card.innerHTML = `

                <div class="panel-row">

                    <strong>
                        Report #${report.id}
                    </strong>

                    <span>
                        ${escapeHtml(
                            report.status
                        )}
                    </span>

                </div>

                <hr
                    style="
                        border-color:#292936
                    "
                >

                <div>
                    <b>Reporter:</b>
                    ${escapeHtml(
                        report.reporter_username
                    )}
                </div>

                <div>
                    <b>Reported:</b>
                    ${escapeHtml(
                        report.reported_username
                        ||
                        "Unknown"
                    )}
                </div>

                <div>
                    <b>Reason:</b>
                    ${escapeHtml(
                        report.reason
                    )}
                </div>

                <div
                    style="margin-top:8px"
                >
                    <b>Details:</b><br>
                    ${escapeHtml(
                        report.details
                        ||
                        "None"
                    )}
                </div>

                ${
                    report.reported_message
                    ?
                    `
                        <div
                            style="
                                margin-top:10px;
                                padding:10px;
                                background:#0c0c11;
                                border-radius:8px
                            "
                        >

                            <b>
                                Reported message:
                            </b>

                            <br>

                            ${escapeHtml(
                                report.reported_message
                            )}

                        </div>
                    `
                    :
                    ""
                }

                ${
                    report.moderator_note
                    ?
                    `
                        <div
                            style="
                                margin-top:8px
                            "
                        >
                            <b>
                                Moderator note:
                            </b>

                            ${escapeHtml(
                                report.moderator_note
                            )}
                        </div>
                    `
                    :
                    ""
                }

                ${
                    report.status
                    ===
                    "open"
                    ?
                    `

                        <div
                            class="modal-actions"
                        >

                            ${
                                report.message_id
                                ?
                                `
                                    <button
                                        class="
                                            small-button
                                            danger
                                        "
                                        onclick="
                                            deleteReported(
                                                ${report.message_id}
                                            )
                                        "
                                    >
                                        Delete Message
                                    </button>
                                `
                                :
                                ""
                            }

                            ${
                                report.reported_user_id
                                ?
                                `
                                    <button
                                        class="
                                            small-button
                                            danger
                                        "
                                        onclick="
                                            banReported(
                                                ${report.reported_user_id}
                                            )
                                        "
                                    >
                                        Ban User
                                    </button>
                                `
                                :
                                ""
                            }

                            <button
                                class="small-button"
                                onclick="
                                    resolveReport(
                                        ${report.id}
                                    )
                                "
                            >
                                Resolve
                            </button>

                            <button
                                class="small-button"
                                onclick="
                                    dismissReport(
                                        ${report.id}
                                    )
                                "
                            >
                                Dismiss
                            </button>

                        </div>
                    `
                    :
                    ""
                }

            `;

            container.appendChild(
                card
            );
        }

    } catch (err) {

        alert(
            err.message
        );
    }
}


async function deleteReported(
    id
) {

    try {

        await api(
            "/api/mod/message/"
            + id,
            {
                method: "DELETE"
            }
        );

        await showModeration();

    } catch (err) {

        alert(
            err.message
        );
    }
}


async function banReported(
    id
) {

    if (
        !confirm(
            "Ban this user?"
        )
    ) {
        return;
    }

    try {

        await api(
            "/api/mod/ban/"
            + id,
            {
                method: "POST"
            }
        );

        await showModeration();

    } catch (err) {

        alert(
            err.message
        );
    }
}


async function resolveReport(
    id
) {

    const note =
        prompt(
            "Optional moderator note:",
            ""
        );

    if (
        note === null
    ) {
        return;
    }

    try {

        await api(
            "/api/reports/"
            + id
            + "/resolve",
            {
                method: "POST",
                body: JSON.stringify({
                    note
                })
            }
        );

        await showModeration();

    } catch (err) {

        alert(
            err.message
        );
    }
}


async function dismissReport(
    id
) {

    const note =
        prompt(
            "Optional dismissal note:",
            ""
        );

    if (
        note === null
    ) {
        return;
    }

    try {

        await api(
            "/api/reports/"
            + id
            + "/dismiss",
            {
                method: "POST",
                body: JSON.stringify({
                    note
                })
            }
        );

        await showModeration();

    } catch (err) {

        alert(
            err.message
        );
    }
}


/* ============================================================
   OWNER
   ============================================================ */

async function showOwner() {

    currentPage =
        "owner";

    currentDM = null;

    document.getElementById(
        "channelName"
    ).innerHTML =
        "⚙️ Owner Panel";

    document.getElementById(
        "composer"
    ).classList.add(
        "hidden"
    );

    const main =
        document.getElementById(
            "mainContent"
        );

    main.innerHTML = `

        <div class="panel">

            <h2>Users</h2>

            <div id="ownerUsers">
                Loading...
            </div>

        </div>
    `;

    const users =
        await api(
            "/api/mod/users"
        );

    const container =
        document.getElementById(
            "ownerUsers"
        );

    container.innerHTML = "";

    for (
        const user
        of users
    ) {

        const card =
            document.createElement(
                "div"
            );

        card.className =
            "panel-card";

        card.innerHTML = `

            <div class="panel-row">

                <div>

                    <strong>
                        ${escapeHtml(
                            user.username
                        )}
                    </strong>

                    <div>
                        Role:
                        ${escapeHtml(
                            user.role
                        )}
                    </div>

                    <div
                        style="
                            color:${
                                user.online
                                ? "#45d483"
                                : "#666"
                            }
                        "
                    >
                        ●
                        ${
                            user.online
                            ? "Online"
                            : "Offline"
                        }
                    </div>

                    <div>
                        ${
                            user.banned
                            ? "🔴 Banned"
                            : "🟢 Active"
                        }
                    </div>

                </div>

                ${
                    user.role
                    !==
                    "owner"
                    ?
                    `

                        <div>

                            <button
                                class="small-button"
                                onclick="
                                    changeRole(
                                        ${user.id}
                                    )
                                "
                            >
                                Role
                            </button>

                            <button
                                class="small-button"
                                onclick="
                                    toggleBan(
                                        ${user.id},
                                        ${user.banned}
                                    )
                                "
                            >
                                ${
                                    user.banned
                                    ? "Unban"
                                    : "Ban"
                                }
                            </button>

                            <button
                                class="
                                    small-button
                                    danger
                                "
                                onclick="
                                    ipBan(
                                        ${user.id}
                                    )
                                "
                            >
                                IP Ban
                            </button>

                            <button
                                class="
                                    small-button
                                    danger
                                "
                                onclick="
                                    deleteAccount(
                                        ${user.id}
                                    )
                                "
                            >
                                Delete
                            </button>

                        </div>

                    `
                    :
                    "<b>OWNER</b>"
                }

            </div>
        `;

        container.appendChild(
            card
        );
    }
}


async function changeRole(
    id
) {

    const role =
        prompt(
            "Role: user, moderator, admin",
            "moderator"
        );

    if (
        !role
        ||
        ![
            "user",
            "moderator",
            "admin"
        ].includes(
            role.toLowerCase()
        )
    ) {
        return;
    }

    try {

        await api(
            "/api/admin/role/"
            + id,
            {
                method: "POST",
                body: JSON.stringify({
                    role:
                        role.toLowerCase()
                })
            }
        );

        await showOwner();

    } catch (err) {

        alert(
            err.message
        );
    }
}


async function toggleBan(
    id,
    banned
) {

    try {

        await api(
            banned
            ?
            "/api/mod/unban/"
            + id
            :
            "/api/mod/ban/"
            + id,
            {
                method: "POST"
            }
        );

        await showOwner();

    } catch (err) {

        alert(
            err.message
        );
    }
}


async function ipBan(
    id
) {

    if (
        !confirm(
            "IP ban this user?"
        )
    ) {
        return;
    }

    try {

        await api(
            "/api/owner/ip-ban/"
            + id,
            {
                method: "POST"
            }
        );

        await showOwner();

    } catch (err) {

        alert(
            err.message
        );
    }
}


async function deleteAccount(
    id
) {

    if (
        !confirm(
            "PERMANENTLY delete this account?"
        )
    ) {
        return;
    }

    try {

        await api(
            "/api/owner/account/"
            + id,
            {
                method: "DELETE"
            }
        );

        await showOwner();

    } catch (err) {

        alert(
            err.message
        );
    }
}


/* ============================================================
   PROFILE PAGE
   ============================================================ */

async function showProfile() {

    currentPage =
        "profile";

    currentDM = null;

    document.getElementById(
        "channelName"
    ).innerHTML =
        "👤 Profile";

    document.getElementById(
        "composer"
    ).classList.add(
        "hidden"
    );

    const main =
        document.getElementById(
            "mainContent"
        );

    main.innerHTML = `

        <div class="panel">

            <h2>Your Profile</h2>

            <div class="panel-card">

                <button
                    class="action-button"
                    onclick="editProfile()"
                >
                    Edit Profile
                </button>

            </div>

        </div>
    `;

    renderSelfProfile();
}


/* ============================================================
   MODAL
   ============================================================ */

function openModal(
    content
) {

    document.getElementById(
        "modalContent"
    ).innerHTML =
        content;

    document.getElementById(
        "modal"
    ).classList.remove(
        "hidden"
    );
}


function closeModal() {

    document.getElementById(
        "modal"
    ).classList.add(
        "hidden"
    );
}


document.getElementById(
    "modal"
).addEventListener(
    "click",
    function(event) {

        if (
            event.target === this
        ) {
            closeModal();
        }
    }
);


/* ============================================================
   AUTO REFRESH
   ============================================================ */

setInterval(
    async function() {

        if (
            !token
            ||
            !currentUser
        ) {
            return;
        }

        try {

            /*
             * Only refresh the page that
             * is currently being viewed.
             */

            if (
                currentPage
                ===
                "chat"
            ) {

                if (
                    currentDM
                ) {

                    await loadDM(
                        currentDM
                    );

                } else {

                    await loadMessages();
                }
            }

            else if (
                currentPage
                ===
                "friends"
            ) {

                await loadFriends();

                await loadFriendList();
            }

            /*
             * Moderation and Owner are
             * intentionally NOT replaced
             * every few seconds.
             */

        } catch (error) {

            console.error(
                "Auto refresh:",
                error
            );
        }

    },
    15000
);


/* ============================================================
   START IF ALREADY LOGGED IN
   ============================================================ */

if (token) {
    startApp();
}

</script>

</body>
</html>
"""


# ============================================================
# WEB ROUTE
# ============================================================

@app.get("/")
def index():
    return render_template_string(
        HTML
    )


# ============================================================
# START
# ============================================================

init_database()


if __name__ == "__main__":

    print()
    print("=" * 60)
    print("SPOOKCHAT")
    print("=" * 60)
    print(
        "Website: http://127.0.0.1:5000"
    )
    print(
        "Owner:",
        OWNER_USERNAME
    )
    print(
        "Owner password:",
        OWNER_PASSWORD
    )
    print("=" * 60)
    print()

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False
    )
