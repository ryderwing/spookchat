import os
import secrets
import sqlite3
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, jsonify, request, render_template_string
from flask_cors import CORS
from flask_socketio import SocketIO, join_room, leave_room
from werkzeug.security import generate_password_hash, check_password_hash


# ============================================================
# CONFIG
# ============================================================

APP_NAME = "SpookChat"

DATABASE = os.environ.get(
    "SPOOKCHAT_DATABASE",
    "/tmp/spookchat.db"
)

OWNER_USERNAME = os.environ.get(
    "SPOOKCHAT_OWNER_USERNAME",
    "JAYDEN"
)

OWNER_PASSWORD = os.environ.get(
    "SPOOKCHAT_OWNER_PASSWORD",
    ""
)

ONLINE_SECONDS = 60

app = Flask(__name__)

CORS(
    app,
    resources={
        r"/api/*": {
            "origins": "*"
        }
    }
)

socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode="threading"
)

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
    connection = sqlite3.connect(
        DATABASE,
        timeout=30
    )

    connection.row_factory = sqlite3.Row

    connection.execute(
        "PRAGMA foreign_keys = ON"
    )

    return connection


def add_column_if_missing(
    connection,
    table,
    column,
    definition
):
    columns = connection.execute(
        f"PRAGMA table_info({table})"
    ).fetchall()

    existing = {
        row["name"]
        for row in columns
    }

    if column not in existing:
        connection.execute(
            f"""
            ALTER TABLE {table}
            ADD COLUMN {column} {definition}
            """
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

    # Migrations
    migrations = [
        ("users", "ip", "TEXT DEFAULT 'unknown'"),
        ("users", "role", "TEXT DEFAULT 'user'"),
        ("users", "show_role_tag", "INTEGER DEFAULT 1"),
        ("users", "banned", "INTEGER DEFAULT 0"),
        ("users", "pfp", "TEXT DEFAULT ''"),
        ("users", "description", "TEXT DEFAULT ''"),
        ("users", "pronouns", "TEXT DEFAULT ''"),
        ("users", "created_at", "TEXT DEFAULT ''"),
        ("users", "last_seen", "TEXT DEFAULT ''"),
        ("messages", "edited", "INTEGER DEFAULT 0"),
        ("messages", "edited_at", "TEXT DEFAULT ''"),
        ("reports", "moderator_note", "TEXT DEFAULT ''")
    ]

    for migration in migrations:
        add_column_if_missing(
            connection,
            *migration
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

    # Owner
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

    connection.execute("""
        CREATE INDEX IF NOT EXISTS idx_messages_user
        ON messages(user_id)
    """)

    connection.execute("""
        CREATE INDEX IF NOT EXISTS idx_private_messages_sender
        ON private_messages(sender_id)
    """)

    connection.execute("""
        CREATE INDEX IF NOT EXISTS idx_private_messages_receiver
        ON private_messages(receiver_id)
    """)

    connection.execute("""
        CREATE INDEX IF NOT EXISTS idx_friendships_user
        ON friendships(user_id)
    """)

    connection.execute("""
        CREATE INDEX IF NOT EXISTS idx_friendships_friend
        ON friendships(friend_id)
    """)

    connection.execute("""
        CREATE INDEX IF NOT EXISTS idx_reports_status
        ON reports(status)
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
            last_seen.replace(
                "Z",
                "+00:00"
            )
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


def are_friends(
    connection,
    first,
    second
):

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


def message_object(connection, message_id, owner_id=None):

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

    if not row:
        return None

    result = dict(row)

    result["online"] = is_online(
        row["last_seen"]
    )

    if owner_id is not None:
        result["is_owner"] = (
            row["user_id"] == owner_id
        )

    return result


# ============================================================
# SOCKET.IO
# ============================================================

@socketio.on("connect")
def socket_connect(auth=None):

    print(
        "SpookChat realtime connection"
    )


@socketio.on("disconnect")
def socket_disconnect():

    print(
        "SpookChat realtime disconnected"
    )


@socketio.on("join_dm")
def socket_join_dm(data):

    try:

        user_id = int(
            data.get("user_id")
        )

        join_room(
            f"dm_{user_id}"
        )

    except Exception:
        pass


@socketio.on("leave_dm")
def socket_leave_dm(data):

    try:

        user_id = int(
            data.get("user_id")
        )

        leave_room(
            f"dm_{user_id}"
        )

    except Exception:
        pass


# ============================================================
# AUTH API
# ============================================================

@app.post("/api/register")
def register():

    data = request.get_json(
        silent=True
    ) or {}

    username = str(
        data.get(
            "username",
            ""
        )
    ).strip()

    password = str(
        data.get(
            "password",
            ""
        )
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
        data.get(
            "username",
            ""
        )
    ).strip()

    password = str(
        data.get(
            "password",
            ""
        )
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

    socketio.emit(
        "profile_updated",
        public_user(updated)
    )

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
        VALUES (?, ?, 0, '', ?)
    """, (
        user["id"],
        message,
        now()
    ))

    message_id = cursor.lastrowid

    connection.commit()

    result = message_object(
        connection,
        message_id,
        user["id"]
    )

    connection.close()

    socketio.emit(
        "new_public_message",
        result
    )

    return jsonify(result)


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

    result = message_object(
        connection,
        message_id,
        user["id"]
    )

    connection.close()

    socketio.emit(
        "message_edited",
        result
    )

    return jsonify(
        success=True,
        message=result
    )


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

    socketio.emit(
        "message_deleted",
        {
            "id": message_id
        }
    )

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
def add_friend(user):

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

            socketio.emit(
                "friend_updated",
                {
                    "user_id": user["id"],
                    "friend_id": target["id"]
                },
                room=f"user_{target['id']}"
            )

            socketio.emit(
                "friend_updated",
                {
                    "user_id": user["id"],
                    "friend_id": target["id"]
                },
                room=f"user_{user['id']}"
            )

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
        VALUES (?, ?, 'pending')
    """, (
        user["id"],
        target["id"]
    ))

    connection.commit()
    connection.close()

    socketio.emit(
        "friend_request",
        {
            "from": public_user(user)
        },
        room=f"user_{target['id']}"
    )

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

    socketio.emit(
        "friend_updated",
        {
            "user_id": user["id"],
            "friend_id": request_row["user_id"]
        },
        room=f"user_{user['id']}"
    )

    socketio.emit(
        "friend_updated",
        {
            "user_id": user["id"],
            "friend_id": request_row["user_id"]
        },
        room=f"user_{request_row['user_id']}"
    )

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

    socketio.emit(
        "friend_updated",
        {
            "user_id": user["id"],
            "friend_id": user_id
        },
        room=f"user_{user_id}"
    )

    socketio.emit(
        "friend_updated",
        {
            "user_id": user["id"],
            "friend_id": user_id
        },
        room=f"user_{user['id']}"
    )

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
        SELECT *
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

    cursor = connection.execute("""
        INSERT INTO private_messages (
            sender_id,
            receiver_id,
            message,
            edited,
            edited_at,
            created_at
        )
        VALUES (?, ?, ?, 0, '', ?)
    """, (
        user["id"],
        user_id,
        message,
        now()
    ))

    message_id = cursor.lastrowid

    connection.commit()

    row = connection.execute("""
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
        WHERE pm.id=?
    """, (
        message_id,
    )).fetchone()

    connection.close()

    result = dict(row)

    result["online"] = is_online(
        row["last_seen"]
    )

    socketio.emit(
        "new_dm_message",
        result,
        room=f"user_{user['id']}"
    )

    socketio.emit(
        "new_dm_message",
        result,
        room=f"user_{user_id}"
    )

    return jsonify({
        "success": True,
        "message": result
    })


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
        VALUES (?, ?, ?, ?, ?, 'open', ?, '')
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

    socketio.emit(
        "new_report",
        {
            "created": True
        }
    )

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

    socketio.emit(
        "user_banned",
        {
            "user_id": user_id
        },
        room=f"user_{user_id}"
    )

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

    socketio.emit(
        "message_deleted",
        {
            "id": message_id
        }
    )

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
            error="Owner role cannot be assigned"
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

    socketio.emit(
        "role_changed",
        {
            "user_id": user_id,
            "role": new_role
        }
    )

    return jsonify(
        success=True
    )


# ============================================================
# OWNER
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

    socketio.emit(
        "user_banned",
        {
            "user_id": user_id
        },
        room=f"user_{user_id}"
    )

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

    socketio.emit(
        "account_deleted",
        {
            "user_id": user_id
        }
    )

    return jsonify(
        success=True
    )


# ============================================================
# HTML
# ============================================================

HTML = r"""
<!DOCTYPE html>
<html lang="en">

<head>

<meta charset="UTF-8">

<meta
    name="viewport"
    content="
        width=device-width,
        initial-scale=1.0,
        viewport-fit=cover
    "
>

<meta
    name="theme-color"
    content="#0b0b11"
>

<title>SpookChat</title>

<script src="https://cdn.socket.io/4.8.1/socket.io.min.js"></script>

<style>

* {
    box-sizing: border-box;
}

html,
body {
    margin: 0;
    padding: 0;
    width: 100%;
    height: 100%;
}

body {
    background: #09090f;
    color: #f4f4f7;
    font-family:
        Inter,
        system-ui,
        -apple-system,
        BlinkMacSystemFont,
        "Segoe UI",
        sans-serif;
    overflow: hidden;
}

button,
input,
textarea {
    font: inherit;
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

#authScreen {
    width: 100%;
    height: 100dvh;

    display: flex;
    align-items: center;
    justify-content: center;

    padding: 20px;

    background:
        radial-gradient(
            circle at top,
            #241139 0,
            #0b0b11 45%
        );
}

.auth-box {
    width: 100%;
    max-width: 420px;

    padding: 32px;

    border: 1px solid #292936;

    border-radius: 18px;

    background: rgba(
        18,
        18,
        27,
        .95
    );

    box-shadow:
        0 20px 80px
        rgba(0,0,0,.5);
}

.brand {
    font-size: 24px;
    font-weight: 900;
    letter-spacing: -.5px;
}

.brand span {
    color: #9d5cff;
}

.auth-box h2 {
    margin-top: 30px;
}

.auth-box input {
    width: 100%;

    margin-top: 12px;

    padding: 13px 14px;

    border:
        1px solid #30303d;

    border-radius: 10px;

    outline: none;

    background: #111119;

    color: white;
}

.auth-box input:focus {
    border-color: #9d5cff;
}

.primary {
    width: 100%;

    margin-top: 16px;

    padding: 13px;

    border: 0;

    border-radius: 10px;

    background: #8d4fff;

    color: white;

    font-weight: 800;
}

.primary:hover {
    background: #9d62ff;
}

.switch {
    margin-top: 18px;

    text-align: center;

    color: #9d5cff;

    cursor: pointer;
}

.error {
    color: #ff5f70;

    margin-top: 10px;

    min-height: 20px;
}

/* ============================================================
   APP
   ============================================================ */

#app {
    display: flex;

    width: 100%;
    height: 100dvh;
}

/* ============================================================
   SIDEBAR
   ============================================================ */

.sidebar {
    width: 250px;

    flex-shrink: 0;

    display: flex;
    flex-direction: column;

    background: #0d0d14;

    border-right:
        1px solid #24242e;
}

.sidebar .brand {
    padding: 20px;
}

.nav {
    padding: 8px;
}

.nav button {
    width: 100%;

    padding: 11px 13px;

    margin-bottom: 5px;

    border: 0;

    border-radius: 8px;

    text-align: left;

    color: #c9c9d3;

    background: transparent;
}

.nav button:hover {
    background: #191923;
    color: white;
}

.friends-title {
    padding:
        18px
        14px
        8px;

    color: #777783;

    font-size: 11px;

    text-transform: uppercase;

    font-weight: 800;
}

#friendList {
    overflow-y: auto;

    padding: 0 8px;
}

.dm-friend {
    padding: 9px 10px;

    border-radius: 7px;

    color: #aaaab5;

    cursor: pointer;

    display: flex;

    align-items: center;

    gap: 8px;
}

.dm-friend:hover {
    background: #181821;

    color: white;
}

/* ============================================================
   MAIN
   ============================================================ */

.main {
    min-width: 0;

    flex: 1;

    position: relative;

    background: #0b0b12;
}

.topbar {
    height: 58px;

    display: flex;

    align-items: center;

    padding:
        0 18px;

    border-bottom:
        1px solid #24242e;

    background: #101018;

    position: relative;

    z-index: 5;
}

.channel {
    font-weight: 800;
}

.channel span {
    color: #777783;
}

#currentUser {
    margin-left: auto;

    color: #9999a6;

    font-size: 13px;
}

.messages {
    position: absolute;

    left: 0;
    right: 0;
    top: 58px;
    bottom: 72px;

    overflow-y: auto;

    padding: 15px;

    scroll-behavior: smooth;

    -webkit-overflow-scrolling: touch;
}

.message {
    display: flex;

    gap: 10px;

    padding: 8px;

    border-radius: 8px;
}

.message:hover {
    background: #11111a;
}

.message-content {
    min-width: 0;

    flex: 1;
}

.message-header {
    display: flex;

    align-items: baseline;

    gap: 8px;

    flex-wrap: wrap;
}

.username {
    font-weight: 800;
}

.timestamp {
    color: #656572;

    font-size: 11px;
}

.message-text {
    margin-top: 2px;

    color: #dedee5;

    white-space: pre-wrap;

    overflow-wrap: anywhere;

    word-break: break-word;

    line-height: 1.45;
}

.edited {
    margin-left: 5px;

    color: #666673;

    font-size: 10px;
}

.avatar {
    width: 40px;
    height: 40px;

    min-width: 40px;

    display: flex;

    align-items: center;

    justify-content: center;

    overflow: hidden;

    border-radius: 50%;

    background:
        linear-gradient(
            135deg,
            #6d3bc1,
            #a65cff
        );

    font-weight: 900;
}

.avatar img {
    width: 100%;
    height: 100%;

    object-fit: cover;
}

/* ============================================================
   COMPOSER
   ============================================================ */

.composer {
    position: absolute;

    left: 0;
    right: 0;
    bottom: 0;

    padding:
        8px
        15px
        calc(
            8px +
            env(
                safe-area-inset-bottom
            )
        );

    background: #101018;

    z-index: 10;
}

.composer-inner {
    display: flex;

    gap: 8px;

    padding: 5px 7px 5px 14px;

    background: #1a1a24;

    border-radius: 12px;

    border:
        1px solid #292936;
}

.composer input {
    min-width: 0;

    flex: 1;

    border: 0;

    outline: 0;

    background: transparent;

    color: white;

    font-size: 15px;
}

.composer button {
    width: 42px;
    height: 42px;

    border: 0;

    border-radius: 9px;

    background: #8d4fff;

    color: white;

    font-size: 19px;
}

/* ============================================================
   RIGHT PANEL
   ============================================================ */

.right {
    width: 250px;

    flex-shrink: 0;

    border-left:
        1px solid #24242e;

    background: #0d0d14;

    overflow-y: auto;
}

/* ============================================================
   PANELS
   ============================================================ */

.panel {
    width: min(
        900px,
        100%
    );

    margin: auto;

    padding: 25px;
}

.panel-card {
    padding: 15px;

    margin-bottom: 10px;

    border:
        1px solid #292936;

    border-radius: 12px;

    background: #111119;
}

.panel-row {
    display: flex;

    align-items: center;

    justify-content: space-between;

    gap: 10px;
}

.action-button,
.small-button {
    border: 0;

    border-radius: 8px;

    padding: 9px 13px;

    background: #8d4fff;

    color: white;

    font-weight: 700;
}

.small-button {
    padding: 7px 10px;

    background: #272733;
}

.small-button:hover {
    background: #343442;
}

.danger {
    background: #7e2635 !important;
}

.friend-search {
    display: flex;

    gap: 8px;

    margin-bottom: 20px;
}

.friend-search input {
    flex: 1;

    min-width: 0;

    padding: 11px;

    border:
        1px solid #30303d;

    border-radius: 8px;

    background: #111119;

    color: white;

    outline: none;
}

.friend-card {
    display: flex;

    align-items: center;

    justify-content: space-between;

    gap: 10px;

    padding: 12px;

    margin-bottom: 8px;

    border-radius: 10px;

    background: #15151e;
}

.friend-left {
    display: flex;

    align-items: center;

    gap: 10px;

    min-width: 0;
}

.status-dot {
    width: 9px;
    height: 9px;

    min-width: 9px;

    border-radius: 50%;

    background: #555562;
}

.status-dot.online {
    background: #43dc83;

    box-shadow:
        0 0 8px
        rgba(
            67,
            220,
            131,
            .6
        );
}

/* ============================================================
   MODAL
   ============================================================ */

#modal {
    position: fixed;

    inset: 0;

    z-index: 500;

    display: flex;

    align-items: center;

    justify-content: center;

    padding: 15px;

    background:
        rgba(
            0,
            0,
            0,
            .72
        );
}

.modal-box {
    width: min(
        550px,
        100%
    );

    max-height: 90dvh;

    overflow-y: auto;

    padding: 22px;

    border:
        1px solid #30303d;

    border-radius: 15px;

    background: #111119;
}

.modal-box input,
.modal-box textarea {
    width: 100%;

    margin-top: 8px;
    margin-bottom: 12px;

    padding: 11px;

    border:
        1px solid #30303d;

    border-radius: 8px;

    background: #0c0c12;

    color: white;

    outline: none;
}

.modal-box textarea {
    min-height: 120px;

    resize: vertical;
}

.modal-actions {
    display: flex;

    justify-content: flex-end;

    gap: 8px;

    margin-top: 15px;
}

/* ============================================================
   MOBILE NAV
   ============================================================ */

.mobile-nav {
    display: none;
}


/* ============================================================
   MOBILE
   ============================================================ */

@media (max-width: 768px) {

    body {
        height: 100dvh;
    }

    #app {
        height: 100dvh;
    }

    .sidebar {
        display: none;

        position: fixed;

        left: 0;
        top: 0;

        width: 100%;

        height:
            calc(
                100dvh - 65px
            );

        z-index: 100;

        box-shadow:
            0 20px 60px
            rgba(0,0,0,.6);
    }

    .sidebar.mobile-open {
        display: flex;
    }

    .sidebar .brand {
        padding: 18px;
    }

    .nav {
        display: block;

        padding: 10px;
    }

    .nav button {
        padding: 14px;

        font-size: 15px;
    }

    .friends-title {
        padding-left: 18px;
    }

    #friendList {
        padding: 0 12px;

        overflow-y: auto;
    }

    .main {
        position: fixed;

        inset: 0;

        bottom: 65px;

        height:
            calc(
                100dvh - 65px
            );

        width: 100%;
    }

    .topbar {
        height: 56px;

        padding:
            0 12px;
    }

    .messages {
        top: 56px;

        bottom: 68px;

        padding:
            8px 5px;
    }

    .message {
        padding:
            7px 5px;
    }

    .avatar {
        width: 36px;
        height: 36px;

        min-width: 36px;
    }

    .message-text {
        font-size: 14px;
    }

    .composer {
        bottom: 0;

        padding:
            7px
            7px
            calc(
                7px +
                env(
                    safe-area-inset-bottom
                )
            );
    }

    .composer-inner {
        padding-left: 11px;
    }

    .composer input {
        font-size: 16px;
    }

    .right {
        display: none !important;
    }

    .mobile-nav {
        position: fixed;

        display: flex;

        left: 0;
        right: 0;
        bottom: 0;

        height: 65px;

        z-index: 200;

        padding-bottom:
            env(
                safe-area-inset-bottom
            );

        background: #0d0d14;

        border-top:
            1px solid #292936;
    }

    .mobile-nav button {
        flex: 1;

        border: 0;

        background: transparent;

        color: #777783;

        font-size: 21px;

        display: flex;

        align-items: center;

        justify-content: center;

        flex-direction: column;

        gap: 1px;
    }

    .mobile-nav button span {
        font-size: 10px;
    }

    .mobile-nav button.active {
        color: #a65cff;
    }

    .panel {
        padding: 15px 10px;
    }

    .panel h2 {
        margin-top: 5px;
    }

    .friend-search {
        flex-direction: row;
    }

    .friend-search button {
        white-space: nowrap;
    }

    .friend-card {
        padding: 10px;
    }

    .panel-row {
        align-items: flex-start;

        flex-direction: column;
    }

    .panel-row > div:last-child {
        width: 100%;
    }

    .modal-box {
        width: calc(
            100% - 20px
        );

        max-height: 90dvh;

        border-radius: 14px;
    }
}

</style>

</head>

<body>

<!-- ==========================================================
     AUTH
     ========================================================== -->

<div id="authScreen">

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
            autocomplete="username"
        >

        <input
            id="authPassword"
            placeholder="Password"
            type="password"
            autocomplete="current-password"
            onkeydown="
                if(event.key === 'Enter')
                    authAction()
            "
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

            <button onclick="showHome()">
                💬 Chat
            </button>

            <button onclick="showFriends()">
                👥 Friends
            </button>

            <button onclick="showProfile()">
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

            <button onclick="logout()">
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
                    autocomplete="off"
                    onkeydown="
                        if(event.key === 'Enter' && !event.shiftKey) {
                            event.preventDefault();
                            sendMessage();
                        }
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


    <nav class="mobile-nav">

        <button
            onclick="showHome()"
            id="mobileChatButton"
        >
            💬
            <span>Chat</span>
        </button>

        <button
            onclick="showFriends()"
            id="mobileFriendsButton"
        >
            👥
            <span>Friends</span>
        </button>

        <button
            onclick="showProfile()"
            id="mobileProfileButton"
        >
            👤
            <span>Profile</span>
        </button>

        <button
            onclick="toggleMobileSidebar()"
        >
            ☰
            <span>More</span>
        </button>

    </nav>

</div>


<!-- ==========================================================
     MODAL
     ========================================================== -->

<div
    id="modal"
    class="hidden"
>

    <div
        class="modal-box"
        id="modalContent"
    ></div>

</div>


<script>

/* ============================================================
   STATE
   ============================================================ */

let token =
    localStorage.getItem(
        "spookchat_token"
    );

let currentUser = null;

let currentPage =
    "chat";

let currentDM = null;

let authMode =
    "login";

let socket = null;


/* ============================================================
   API
   ============================================================ */

async function api(
    url,
    options = {}
) {

    options.headers =
        options.headers || {};

    options.headers[
        "Content-Type"
    ] =
        "application/json";

    if (token) {

        options.headers[
            "Authorization"
        ] =
            token;
    }

    const response =
        await fetch(
            url,
            options
        );

    let data = {};

    try {
        data =
            await response.json();
    } catch {}

    if (!response.ok) {

        throw new Error(
            data.error
            ||
            "Request failed"
        );
    }

    return data;
}


/* ============================================================
   ESCAPING
   ============================================================ */

function escapeHtml(value) {

    const div =
        document.createElement(
            "div"
        );

    div.textContent =
        value ?? "";

    return div.innerHTML;
}


function escapeAttr(value) {

    return String(
        value ?? ""
    )
    .replace(
        /&/g,
        "&amp;"
    )
    .replace(
        /"/g,
        "&quot;"
    )
    .replace(
        /</g,
        "&lt;"
    )
    .replace(
        />/g,
        "&gt;"
    );
}


/* ============================================================
   AUTH
   ============================================================ */

function toggleAuth() {

    authMode =
        authMode === "login"
        ? "register"
        : "login";

    document.getElementById(
        "authTitle"
    ).textContent =
        authMode === "login"
        ? "Login"
        : "Register";

    document.getElementById(
        "authButton"
    ).textContent =
        authMode === "login"
        ? "Login"
        : "Create Account";

    document.getElementById(
        "authSwitch"
    ).textContent =
        authMode === "login"
        ? "Need an account? Register"
        : "Already have an account? Login";

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

    error.textContent =
        "";

    try {

        const data =
            await api(
                authMode === "login"
                ? "/api/login"
                : "/api/register",
                {
                    method: "POST",

                    body:
                        JSON.stringify({
                            username,
                            password
                        })
                }
            );

        token =
            data.token;

        currentUser =
            data.user;

        localStorage.setItem(
            "spookchat_token",
            token
        );

        await startApp();

    } catch (err) {

        error.textContent =
            err.message;
    }
}


/* ============================================================
   START APP
   ============================================================ */

async function startApp() {

    try {

        currentUser =
            await api(
                "/api/me"
            );

    } catch {

        token = null;

        localStorage.removeItem(
            "spookchat_token"
        );

        return;
    }

    document.getElementById(
        "authScreen"
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

    connectRealtime();

    await loadFriendList();

    await showHome();
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
   REALTIME
   ============================================================ */

function connectRealtime() {

    if (!token) {
        return;
    }

    if (socket) {
        socket.disconnect();
    }

    socket =
        io({
            transports: [
                "websocket",
                "polling"
            ]
        });

    socket.on(
        "connect",
        () => {

            console.log(
                "SpookChat realtime connected"
            );

            socket.emit(
                "join_user",
                {
                    user_id:
                        currentUser.id
                }
            );

            if (currentDM) {

                socket.emit(
                    "join_dm",
                    {
                        user_id:
                            currentDM
                    }
                );
            }
        }
    );

    socket.on(
        "disconnect",
        () => {

            console.log(
                "Realtime disconnected"
            );
        }
    );

    socket.on(
        "new_public_message",
        message => {

            if (
                currentPage === "chat"
                &&
                currentDM === null
            ) {

                appendMessage(
                    message
                );
            }
        }
    );

    socket.on(
        "new_dm_message",
        message => {

            const belongs =
                currentDM !== null
                &&
                (
                    (
                        message.sender_id
                        ===
                        currentDM
                    )
                    ||
                    (
                        message.receiver_id
                        ===
                        currentDM
                    )
                );

            if (
                currentPage === "chat"
                &&
                belongs
            ) {

                appendMessage(
                    message
                );

            } else {

                showNotification(
                    "New message",
                    message.username
                    +
                    ": "
                    +
                    message.message
                );
            }
        }
    );

    socket.on(
        "message_deleted",
        data => {

            const element =
                document.querySelector(
                    `[data-message-id="${data.id}"]`
                );

            if (element) {
                element.remove();
            }
        }
    );

    socket.on(
        "message_edited",
        message => {

            const element =
                document.querySelector(
                    `[data-message-id="${message.id}"]`
                );

            if (!element) {
                return;
            }

            const text =
                element.querySelector(
                    ".message-text"
                );

            if (!text) {
                return;
            }

            text.innerHTML =
                escapeHtml(
                    message.message
                )
                +
                `
                <span class="edited">
                    (edited)
                </span>
                `;
        }
    );

    socket.on(
        "friend_request",
        () => {

            showNotification(
                "SpookChat",
                "You received a friend request."
            );

            loadFriendList();
        }
    );

    socket.on(
        "friend_updated",
        () => {

            loadFriendList();

            if (
                currentPage === "friends"
            ) {
                loadFriends();
            }
        }
    );

    socket.on(
        "profile_updated",
        user => {

            if (
                currentUser
                &&
                user.id === currentUser.id
            ) {

                currentUser =
                    user;

                document.getElementById(
                    "currentUser"
                ).textContent =
                    user.username;

                updateRoleButtons();
            }

            loadFriendList();
        }
    );

    socket.on(
        "role_changed",
        data => {

            if (
                currentUser
                &&
                data.user_id
                ===
                currentUser.id
            ) {

                currentUser.role =
                    data.role;

                updateRoleButtons();
            }
        }
    );

    socket.on(
        "user_banned",
        data => {

            if (
                currentUser
                &&
                data.user_id
                ===
                currentUser.id
            ) {

                alert(
                    "Your account has been banned."
                );

                logout();
            }
        }
    );

    socket.on(
        "account_deleted",
        data => {

            if (
                currentUser
                &&
                data.user_id
                ===
                currentUser.id
            ) {

                logout();
            }
        }
    );

    socket.on(
        "new_report",
        () => {

            if (
                currentUser
                &&
                (
                    currentUser.role
                    === "moderator"
                    ||
                    currentUser.role
                    === "admin"
                    ||
                    currentUser.role
                    === "owner"
                )
            ) {

                if (
                    currentPage
                    ===
                    "moderation"
                ) {

                    loadReports(
                        "open"
                    );
                }
            }
        }
    );
}


/* ============================================================
   NOTIFICATIONS
   ============================================================ */

function showNotification(
    title,
    body
) {

    if (
        "Notification"
        in window
    ) {

        if (
            Notification.permission
            ===
            "granted"
        ) {

            new Notification(
                title,
                {
                    body
                }
            );

        } else if (
            Notification.permission
            !==
            "denied"
        ) {

            Notification.requestPermission();
        }
    }
}


/* ============================================================
   HOME
   ============================================================ */

async function showHome() {

    closeMobileSidebar();

    currentPage =
        "chat";

    if (
        socket
        &&
        currentDM
    ) {

        socket.emit(
            "leave_dm",
            {
                user_id:
                    currentDM
            }
        );
    }

    currentDM =
        null;

    document.getElementById(
        "channelName"
    ).innerHTML =
        "<span>#</span> general";

    document.getElementById(
        "messageInput"
    ).placeholder =
        "Message #general";

    document.getElementById(
        "composer"
    ).classList.remove(
        "hidden"
    );

    setMobileActive(
        "mobileChatButton"
    );

    await loadMessages();
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

    container.innerHTML =
        "";

    for (
        const message
        of messages
    ) {

        appendMessage(
            message,
            false
        );
    }

    container.scrollTop =
        container.scrollHeight;
}


/* ============================================================
   MESSAGE RENDER
   ============================================================ */

function appendMessage(
    message,
    scroll = true
) {

    const container =
        document.getElementById(
            "mainContent"
        );

    if (!container) {
        return;
    }

    if (
        container.querySelector(
            `[data-message-id="${message.id}"]`
        )
    ) {
        return;
    }

    const wrapper =
        document.createElement(
            "div"
        );

    wrapper.className =
        "message";

    wrapper.dataset.messageId =
        message.id;

    const avatar =
        message.pfp
        ?
        `
        <img
            src="${escapeAttr(
                message.pfp
            )}"
        >
        `
        :
        escapeHtml(
            (
                message.username
                ||
                "?"
            )
            .charAt(0)
            .toUpperCase()
        );

    wrapper.innerHTML = `

        <div class="avatar">
            ${avatar}
        </div>

        <div class="message-content">

            <div class="message-header">

                <span class="username">
                    ${escapeHtml(
                        message.username
                    )}
                </span>

                ${
                    message.role
                    &&
                    message.show_role_tag
                    ?
                    `
                    <span
                        style="
                            color:#a65cff;
                            font-size:10px;
                            font-weight:800;
                        "
                    >
                        ${escapeHtml(
                            message.role
                        ).toUpperCase()}
                    </span>
                    `
                    :
                    ""
                }

                <span class="timestamp">
                    ${new Date(
                        message.created_at
                    ).toLocaleTimeString(
                        [],
                        {
                            hour:
                                "numeric",
                            minute:
                                "2-digit"
                        }
                    )}
                </span>

            </div>

            <div class="message-text">

                ${escapeHtml(
                    message.message
                )}

                ${
                    message.edited
                    ?
                    `
                    <span class="edited">
                        (edited)
                    </span>
                    `
                    :
                    ""
                }

            </div>

        </div>
    `;

    container.appendChild(
        wrapper
    );

    if (scroll) {

        container.scrollTop =
            container.scrollHeight;
    }
}


/* ============================================================
   FRIENDS
   ============================================================ */

async function showFriends() {

    closeMobileSidebar();

    currentPage =
        "friends";

    currentDM =
        null;

    if (socket) {
        socket.emit(
            "leave_dm",
            {
                user_id:
                    currentDM
            }
        );
    }

    document.getElementById(
        "channelName"
    ).textContent =
        "👥 Friends";

    document.getElementById(
        "composer"
    ).classList.add(
        "hidden"
    );

    setMobileActive(
        "mobileFriendsButton"
    );

    document.getElementById(
        "mainContent"
    ).innerHTML = `

        <div class="panel">

            <h2>Friends</h2>

            <div class="friend-search">

                <input
                    id="friendUsername"
                    placeholder="Username"
                    onkeydown="
                        if(event.key === 'Enter')
                            addFriend()
                    "
                >

                <button
                    class="action-button"
                    onclick="addFriend()"
                >
                    Add
                </button>

            </div>

            <h3>
                Friend Requests
            </h3>

            <div id="friendRequests">
                Loading...
            </div>

            <h3>
                My Friends
            </h3>

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

    if (!input) {
        return;
    }

    const username =
        input.value.trim();

    if (!username) {
        return;
    }

    try {

        const result =
            await api(
                "/api/friends/add",
                {
                    method: "POST",

                    body:
                        JSON.stringify({
                            username
                        })
                }
            );

        input.value =
            "";

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

        requestsContainer.innerHTML =
            "";

        if (!requests.length) {

            requestsContainer.innerHTML =
                `
                <div
                    style="
                        color:#777783;
                        padding:10px 0;
                    "
                >
                    No pending requests.
                </div>
                `;

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
                                `<img
                                    src="${escapeAttr(
                                        request.pfp
                                    )}"
                                >`
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

                            <div
                                style="
                                    color:#777783;
                                    font-size:12px;
                                "
                            >
                                Friend request
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

        friendsContainer.innerHTML =
            "";

        if (!friends.length) {

            friendsContainer.innerHTML =
                `
                <div
                    style="
                        color:#777783;
                        padding:10px 0;
                    "
                >
                    No friends yet.
                </div>
                `;

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
                                `<img
                                    src="${escapeAttr(
                                        friend.pfp
                                    )}"
                                >`
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
            +
            requestId,
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

        if (!container) {
            return;
        }

        container.innerHTML =
            "";

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

                <span
                    style="
                        overflow:hidden;
                        text-overflow:ellipsis;
                        white-space:nowrap;
                    "
                >
                    ${escapeHtml(
                        friend.username
                    )}
                </span>
            `;

            item.onclick =
                () => loadDM(
                    friend.id
                );

            container.appendChild(
                item
            );
        }

    } catch (err) {

        console.error(
            err
        );
    }
}


/* ============================================================
   DM
   ============================================================ */

async function loadDM(
    userId
) {

    closeMobileSidebar();

    currentPage =
        "chat";

    if (
        socket
        &&
        currentDM
        &&
        currentDM !== userId
    ) {

        socket.emit(
            "leave_dm",
            {
                user_id:
                    currentDM
            }
        );
    }

    currentDM =
        userId;

    const profile =
        await api(
            "/api/users/"
            +
            userId
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
            +
            userId
        );

    const container =
        document.getElementById(
            "mainContent"
        );

    container.innerHTML =
        "";

    for (
        const message
        of messages
    ) {

        appendMessage(
            message,
            false
        );
    }

    container.scrollTop =
        container.scrollHeight;

    if (socket) {

        socket.emit(
            "join_dm",
            {
                user_id:
                    userId
            }
        );
    }

    setMobileActive(
        "mobileChatButton"
    );

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

    input.disabled =
        true;

    try {

        if (currentDM) {

            await api(
                "/api/dm/"
                +
                currentDM,
                {
                    method: "POST",

                    body:
                        JSON.stringify({
                            message
                        })
                }
            );

        } else {

            await api(
                "/api/messages",
                {
                    method: "POST",

                    body:
                        JSON.stringify({
                            message
                        })
                }
            );
        }

        input.value =
            "";

    } catch (err) {

        alert(
            err.message
        );

    } finally {

        input.disabled =
            false;

        input.focus();
    }
}


/* ============================================================
   PROFILE
   ============================================================ */

async function showProfile() {

    closeMobileSidebar();

    currentPage =
        "profile";

    currentDM =
        null;

    document.getElementById(
        "channelName"
    ).textContent =
        "👤 Profile";

    document.getElementById(
        "composer"
    ).classList.add(
        "hidden"
    );

    setMobileActive(
        "mobileProfileButton"
    );

    document.getElementById(
        "mainContent"
    ).innerHTML = `

        <div class="panel">

            <h2>Your Profile</h2>

            <div
                id="selfProfile"
                class="panel-card"
            >
                Loading...
            </div>

            <button
                class="action-button"
                onclick="editProfile()"
            >
                Edit Profile
            </button>

        </div>
    `;

    renderSelfProfile();
}


function renderSelfProfile() {

    const container =
        document.getElementById(
            "selfProfile"
        );

    if (!container || !currentUser) {
        return;
    }

    const avatar =
        currentUser.pfp
        ?
        `
        <img
            src="${escapeAttr(
                currentUser.pfp
            )}"
        >
        `
        :
        escapeHtml(
            currentUser.username
                .charAt(0)
                .toUpperCase()
        );

    container.innerHTML = `

        <div
            style="
                display:flex;
                gap:15px;
                align-items:center;
            "
        >

            <div
                class="avatar"
                style="
                    width:70px;
                    height:70px;
                    min-width:70px;
                "
            >
                ${avatar}
            </div>

            <div>

                <h2
                    style="
                        margin:0;
                    "
                >
                    ${escapeHtml(
                        currentUser.username
                    )}
                </h2>

                <div
                    style="
                        color:#a65cff;
                        font-size:12px;
                        font-weight:800;
                    "
                >
                    ${escapeHtml(
                        currentUser.role
                    ).toUpperCase()}
                </div>

                ${
                    currentUser.pronouns
                    ?
                    `
                    <div
                        style="
                            color:#777783;
                            margin-top:4px;
                        "
                    >
                        ${escapeHtml(
                            currentUser.pronouns
                        )}
                    </div>
                    `
                    :
                    ""
                }

            </div>

        </div>

        <p>
            ${escapeHtml(
                currentUser.description
                ||
                "No description."
            )}
        </p>
    `;
}


function renderProfileCard(
    profile
) {

    const right =
        document.getElementById(
            "rightPanel"
        );

    if (!right) {
        return;
    }

    right.innerHTML = `

        <div
            style="
                padding:20px;
            "
        >

            <div
                class="avatar"
                style="
                    width:80px;
                    height:80px;
                "
            >

                ${
                    profile.pfp
                    ?
                    `<img
                        src="${escapeAttr(
                            profile.pfp
                        )}"
                    >`
                    :
                    escapeHtml(
                        profile.username
                            .charAt(0)
                            .toUpperCase()
                    )
                }

            </div>

            <h2>
                ${escapeHtml(
                    profile.username
                )}
            </h2>

            <div>

                <span
                    class="status-dot ${
                        profile.online
                        ? "online"
                        : ""
                    }"
                ></span>

                ${
                    profile.online
                    ? "Online"
                    : "Offline"
                }

            </div>

            ${
                profile.pronouns
                ?
                `
                <p>
                    ${escapeHtml(
                        profile.pronouns
                    )}
                </p>
                `
                :
                ""
            }

            <p
                style="
                    color:#9999a6;
                "
            >
                ${escapeHtml(
                    profile.description
                    ||
                    "No description."
                )}
            </p>

        </div>
    `;
}


async function viewProfile(
    userId
) {

    try {

        const profile =
            await api(
                "/api/users/"
                +
                userId
            );

        openModal(`
            <div
                class="avatar"
                style="
                    width:80px;
                    height:80px;
                "
            >
                ${
                    profile.pfp
                    ?
                    `<img
                        src="${escapeAttr(
                            profile.pfp
                        )}"
                    >`
                    :
                    escapeHtml(
                        profile.username
                            .charAt(0)
                            .toUpperCase()
                    )
                }
            </div>

            <h2>
                ${escapeHtml(
                    profile.username
                )}
            </h2>

            <div>
                <span
                    class="status-dot ${
                        profile.online
                        ? "online"
                        : ""
                    }"
                ></span>
                ${
                    profile.online
                    ? "Online"
                    : "Offline"
                }
            </div>

            <p>
                ${escapeHtml(
                    profile.description
                    ||
                    "No description."
                )}
            </p>

            <button
                class="action-button"
                onclick="
                    closeModal();
                    loadDM(${profile.id});
                "
            >
                Message
            </button>
        `);

    } catch (err) {

        alert(
            err.message
        );
    }
}


function editProfile() {

    openModal(`

        <h2>
            Edit Profile
        </h2>

        <label>
            Username
        </label>

        <input
            id="editUsername"
            value="${escapeAttr(
                currentUser.username
            )}"
        >

        <label>
            Profile Picture URL
        </label>

        <input
            id="editPfp"
            value="${escapeAttr(
                currentUser.pfp
            )}"
            placeholder="https://..."
        >

        <label>
            Pronouns
        </label>

        <input
            id="editPronouns"
            value="${escapeAttr(
                currentUser.pronouns
            )}"
        >

        <label>
            Description
        </label>

        <textarea
            id="editDescription"
        >${escapeHtml(
            currentUser.description
        )}</textarea>

        <label>

            <input
                type="checkbox"
                id="showRoleTag"
                ${
                    currentUser.show_role_tag
                    ?
                    "checked"
                    :
                    ""
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

                body:
                    JSON.stringify({

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

                body:
                    JSON.stringify({
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
   MODERATION
   ============================================================ */

async function showModeration() {

    closeMobileSidebar();

    currentPage =
        "moderation";

    currentDM =
        null;

    document.getElementById(
        "channelName"
    ).textContent =
        "🛡️ Moderation";

    document.getElementById(
        "composer"
    ).classList.add(
        "hidden"
    );

    document.getElementById(
        "mainContent"
    ).innerHTML = `

        <div class="panel">

            <h2>Reports</h2>

            <div
                style="
                    display:flex;
                    flex-wrap:wrap;
                    gap:8px;
                    margin-bottom:15px;
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

        container.innerHTML =
            "";

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
                        border-color:#292936;
                        margin:12px 0;
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
                    <b>Details:</b>
                    <br>
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
                            border-radius:8px;
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
            +
            id,
            {
                method: "DELETE"
            }
        );

        await loadReports(
            "open"
        );

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
            +
            id,
            {
                method: "POST"
            }
        );

        await loadReports(
            "open"
        );

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
            +
            id
            +
            "/resolve",
            {
                method: "POST",

                body:
                    JSON.stringify({
                        note
                    })
            }
        );

        await loadReports(
            "open"
        );

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
            +
            id
            +
            "/dismiss",
            {
                method: "POST",

                body:
                    JSON.stringify({
                        note
                    })
            }
        );

        await loadReports(
            "open"
        );

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

    closeMobileSidebar();

    currentPage =
        "owner";

    currentDM =
        null;

    document.getElementById(
        "channelName"
    ).textContent =
        "⚙️ Owner Panel";

    document.getElementById(
        "composer"
    ).classList.add(
        "hidden"
    );

    document.getElementById(
        "mainContent"
    ).innerHTML = `

        <div class="panel">

            <h2>
                Users
            </h2>

            <div id="ownerUsers">
                Loading...
            </div>

        </div>
    `;

    try {

        const users =
            await api(
                "/api/mod/users"
            );

        const container =
            document.getElementById(
                "ownerUsers"
            );

        container.innerHTML =
            "";

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

                        <div>
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
                        <div
                            style="
                                display:flex;
                                flex-wrap:wrap;
                                gap:5px;
                            "
                        >

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

    } catch (err) {

        alert(
            err.message
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
            +
            id,
            {
                method: "POST",

                body:
                    JSON.stringify({
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
            +
            id
            :
            "/api/mod/ban/"
            +
            id,
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
            +
            id,
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
            +
            id,
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
            event.target
            ===
            this
        ) {

            closeModal();
        }
    }
);


/* ============================================================
   MOBILE
   ============================================================ */

function toggleMobileSidebar() {

    document.querySelector(
        ".sidebar"
    ).classList.toggle(
        "mobile-open"
    );
}


function closeMobileSidebar() {

    const sidebar =
        document.querySelector(
            ".sidebar"
        );

    if (sidebar) {

        sidebar.classList.remove(
            "mobile-open"
        );
    }
}


function setMobileActive(
    id
) {

    document
        .querySelectorAll(
            ".mobile-nav button"
        )
        .forEach(
            button => {
                button.classList.remove(
                    "active"
                );
            }
        );

    const button =
        document.getElementById(
            id
        );

    if (button) {
        button.classList.add(
            "active"
        );
    }
}


/* ============================================================
   LOGOUT
   ============================================================ */

async function logout() {

    try {

        if (token) {

            await api(
                "/api/logout",
                {
                    method: "POST"
                }
            );
        }

    } catch {}

    if (socket) {

        socket.disconnect();

        socket =
            null;
    }

    token =
        null;

    currentUser =
        null;

    currentDM =
        null;

    localStorage.removeItem(
        "spookchat_token"
    );

    document.getElementById(
        "app"
    ).classList.add(
        "hidden"
    );

    document.getElementById(
        "authScreen"
    ).classList.remove(
        "hidden"
    );
}


/* ============================================================
   INITIAL LOAD
   ============================================================ */

if (token) {

    startApp();

} else {

    document.getElementById(
        "authScreen"
    ).classList.remove(
        "hidden"
    );
}


/* ============================================================
   REQUEST NOTIFICATIONS
   ============================================================ */

setTimeout(
    () => {

        if (
            "Notification"
            in window
            &&
            Notification.permission
            ===
            "default"
        ) {

            Notification.requestPermission();
        }

    },
    3000
);

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
