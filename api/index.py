
import os
import re
import secrets
import sqlite3
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, jsonify, request, render_template_string
from flask_cors import CORS
from flask_socketio import SocketIO, join_room
from werkzeug.security import generate_password_hash, check_password_hash

APP_NAME = "SpookChat"
DATABASE = os.environ.get("SPOOKCHAT_DATABASE", "spookchat.db")
OWNER_USERNAME = os.environ.get("SPOOKCHAT_OWNER_USERNAME", "JAYDEN")
OWNER_PASSWORD = os.environ.get("SPOOKCHAT_OWNER_PASSWORD", "CHANGE_ME_NOW")
ONLINE_SECONDS = 60

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", secrets.token_hex(32))
CORS(app, resources={r"/api/*": {"origins": "*"}})
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

ROLES = {"user": 0, "moderator": 1, "admin": 2, "owner": 3}


def now():
    return datetime.now(timezone.utc).isoformat()


def db():
    connection = sqlite3.connect(DATABASE, timeout=30)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def add_column_if_missing(connection, table, column, definition):
    columns = connection.execute(f"PRAGMA table_info({table})").fetchall()
    existing = {row["name"] for row in columns}
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
        ("reports", "moderator_note", "TEXT DEFAULT ''"),
    ]

    for migration in migrations:
        add_column_if_missing(connection, *migration)

    connection.execute(
        "UPDATE users SET role='user' WHERE role IS NULL OR role=''"
    )
    connection.execute(
        "UPDATE users SET show_role_tag=1 WHERE show_role_tag IS NULL"
    )
    connection.execute(
        "UPDATE users SET banned=0 WHERE banned IS NULL"
    )

    owner = connection.execute(
        "SELECT * FROM users WHERE LOWER(username)=LOWER(?)",
        (OWNER_USERNAME,),
    ).fetchone()

    if owner:
        connection.execute(
            """
            UPDATE users
            SET role='owner', banned=0, show_role_tag=1
            WHERE id=?
            """,
            (owner["id"],),
        )
        if OWNER_PASSWORD and OWNER_PASSWORD != "CHANGE_ME_NOW":
            connection.execute(
                "UPDATE users SET password=? WHERE id=?",
                (generate_password_hash(OWNER_PASSWORD), owner["id"]),
            )
    else:
        # If the environment variable was not set, generate a random password
        # instead of creating an owner account with a known public password.
        password = OWNER_PASSWORD
        if not password or password == "CHANGE_ME_NOW":
            password = secrets.token_urlsafe(18)
            print("=" * 60)
            print("SPOOKCHAT OWNER ACCOUNT")
            print("Username:", OWNER_USERNAME)
            print("Generated password:", password)
            print("Set SPOOKCHAT_OWNER_PASSWORD in your hosting environment")
            print("to use your own permanent owner password.")
            print("=" * 60)

        connection.execute(
            """
            INSERT INTO users (
                username, password, ip, role, show_role_tag, banned,
                pfp, description, pronouns, created_at, last_seen
            )
            VALUES (?, ?, 'server', 'owner', 1, 0, '', '', '', ?, ?)
            """,
            (
                OWNER_USERNAME,
                generate_password_hash(password),
                now(),
                now(),
            ),
        )

    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_messages_user ON messages(user_id)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_pm_sender ON private_messages(sender_id)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_pm_receiver ON private_messages(receiver_id)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_friend_user ON friendships(user_id)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_friend_friend ON friendships(friend_id)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status)"
    )

    connection.commit()
    connection.close()


def current_ip():
    # On a reverse proxy, the first X-Forwarded-For address is normally the client.
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def get_user():
    token = request.headers.get("Authorization", "").strip()
    if not token:
        return None

    connection = db()
    user = connection.execute(
        """
        SELECT u.*
        FROM users u
        JOIN sessions s ON s.user_id=u.id
        WHERE s.token=?
        """,
        (token,),
    ).fetchone()
    connection.close()
    return user


def is_online(last_seen):
    if not last_seen:
        return False
    try:
        timestamp = datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
        age = (datetime.now(timezone.utc) - timestamp).total_seconds()
        return age <= ONLINE_SECONDS
    except Exception:
        return False


def require_user(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        user = get_user()
        if not user:
            return jsonify(error="Not logged in"), 401
        if user["banned"]:
            return jsonify(error="Your account is banned"), 403

        connection = db()
        ip_banned = connection.execute(
            "SELECT id FROM ip_bans WHERE ip=?",
            (current_ip(),),
        ).fetchone()

        if ip_banned and user["role"] != "owner":
            connection.close()
            return jsonify(error="Your IP address is banned"), 403

        connection.execute(
            "UPDATE users SET ip=?, last_seen=? WHERE id=?",
            (current_ip(), now(), user["id"]),
        )
        connection.commit()
        connection.close()
        return function(user, *args, **kwargs)

    return wrapper


def require_role(required_role):
    def decorator(function):
        @wraps(function)
        def wrapper(*args, **kwargs):
            user = get_user()
            if not user:
                return jsonify(error="Not logged in"), 401
            if user["banned"]:
                return jsonify(error="Banned"), 403
            if ROLES.get(user["role"], 0) < ROLES[required_role]:
                return jsonify(error="Insufficient permissions"), 403
            return function(user, *args, **kwargs)

        return wrapper
    return decorator


def public_user(user):
    return {
        "id": user["id"],
        "username": user["username"],
        "role": user["role"],
        "show_role_tag": bool(user["show_role_tag"]),
        "pfp": user["pfp"] or "",
        "description": user["description"] or "",
        "pronouns": user["pronouns"] or "",
        "online": is_online(user["last_seen"]),
        "last_seen": user["last_seen"],
    }


def user_json(row):
    if not row:
        return None
    return {
        "id": row["id"],
        "username": row["username"],
        "role": row["role"],
        "show_role_tag": bool(row["show_role_tag"]),
        "pfp": row["pfp"] or "",
        "description": row["description"] or "",
        "pronouns": row["pronouns"] or "",
        "online": is_online(row["last_seen"]),
        "last_seen": row["last_seen"],
    }


def are_friends(connection, first, second):
    result = connection.execute(
        """
        SELECT id FROM friendships
        WHERE status='accepted'
        AND ((user_id=? AND friend_id=?) OR (user_id=? AND friend_id=?))
        """,
        (first, second, second, first),
    ).fetchone()
    return bool(result)


def get_friend_status(connection, first, second):
    friendship = connection.execute(
        """
        SELECT * FROM friendships
        WHERE (user_id=? AND friend_id=?) OR (user_id=? AND friend_id=?)
        ORDER BY id DESC LIMIT 1
        """,
        (first, second, second, first),
    ).fetchone()

    if not friendship:
        return "none"
    if friendship["status"] == "accepted":
        return "friends"
    if friendship["user_id"] == first:
        return "sent"
    return "received"


def message_object(connection, message_id, owner_id=None):
    row = connection.execute(
        """
        SELECT
            messages.id, messages.user_id, users.username, users.role,
            users.show_role_tag, users.pfp, users.last_seen,
            messages.message, messages.edited, messages.edited_at,
            messages.created_at
        FROM messages
        JOIN users ON users.id=messages.user_id
        WHERE messages.id=?
        """,
        (message_id,),
    ).fetchone()

    if not row:
        return None

    result = dict(row)
    result["online"] = is_online(row["last_seen"])
    if owner_id is not None:
        result["is_owner"] = row["user_id"] == owner_id
    return result


# ---------------- SOCKET.IO ----------------

@socketio.on("connect")
def socket_connect(auth=None):
    token = ""
    if isinstance(auth, dict):
        token = str(auth.get("token", "")).strip()

    if not token:
        return False

    connection = db()
    user = connection.execute(
        """
        SELECT u.id, u.banned
        FROM users u
        JOIN sessions s ON s.user_id=u.id
        WHERE s.token=?
        """,
        (token,),
    ).fetchone()
    connection.close()

    if not user or user["banned"]:
        return False

    join_room(f"user_{user['id']}")
    print("SpookChat realtime connection:", user["id"])


@socketio.on("disconnect")
def socket_disconnect():
    print("SpookChat realtime disconnected")


# ---------------- AUTH ----------------

@app.post("/api/register")
def register():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))

    if not re.fullmatch(r"[A-Za-z0-9_.-]{3,32}", username):
        return jsonify(
            error="Username must be 3-32 characters and use letters, numbers, _, . or -"
        ), 400
    if len(password) < 6:
        return jsonify(error="Password must be at least 6 characters"), 400

    connection = db()
    if connection.execute(
        "SELECT id FROM ip_bans WHERE ip=?", (current_ip(),)
    ).fetchone():
        connection.close()
        return jsonify(error="This IP address is banned"), 403

    try:
        cursor = connection.execute(
            """
            INSERT INTO users (
                username,password,ip,role,show_role_tag,banned,pfp,
                description,pronouns,created_at,last_seen
            )
            VALUES (?,?,'unknown','user',1,0,'','','',?,?)
            """,
            (
                username,
                generate_password_hash(password),
                now(),
                now(),
            ),
        )
        user_id = cursor.lastrowid
        token = secrets.token_urlsafe(32)
        connection.execute(
            "INSERT INTO sessions(token,user_id,created_at) VALUES(?,?,?)",
            (token, user_id, now()),
        )
        connection.execute(
            "UPDATE users SET ip=?, last_seen=? WHERE id=?",
            (current_ip(), now(), user_id),
        )
        connection.commit()
        user = connection.execute(
            "SELECT * FROM users WHERE id=?", (user_id,)
        ).fetchone()
        connection.close()
        return jsonify(token=token, user=public_user(user))
    except sqlite3.IntegrityError:
        connection.close()
        return jsonify(error="Username already exists"), 409


@app.post("/api/login")
def login():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))

    connection = db()

    if connection.execute(
        "SELECT id FROM ip_bans WHERE ip=?", (current_ip(),)
    ).fetchone():
        connection.close()
        return jsonify(error="Your IP address is banned"), 403

    user = connection.execute(
        "SELECT * FROM users WHERE LOWER(username)=LOWER(?)",
        (username,),
    ).fetchone()

    if not user or not check_password_hash(user["password"], password):
        connection.close()
        return jsonify(error="Invalid username or password"), 401

    if user["banned"]:
        connection.close()
        return jsonify(error="Your account is banned"), 403

    token = secrets.token_urlsafe(32)
    connection.execute(
        "INSERT INTO sessions(token,user_id,created_at) VALUES(?,?,?)",
        (token, user["id"], now()),
    )
    connection.execute(
        "UPDATE users SET ip=?,last_seen=? WHERE id=?",
        (current_ip(), now(), user["id"]),
    )
    connection.commit()

    user = connection.execute(
        "SELECT * FROM users WHERE id=?", (user["id"],)
    ).fetchone()
    connection.close()
    return jsonify(token=token, user=public_user(user))


@app.post("/api/logout")
@require_user
def logout(user):
    token = request.headers.get("Authorization", "").strip()
    connection = db()
    connection.execute("DELETE FROM sessions WHERE token=?", (token,))
    connection.commit()
    connection.close()
    return jsonify(success=True)


@app.get("/api/me")
@require_user
def me(user):
    connection = db()
    fresh = connection.execute(
        "SELECT * FROM users WHERE id=?", (user["id"],)
    ).fetchone()
    connection.close()
    return jsonify(public_user(fresh))


# ---------------- PROFILES ----------------

@app.get("/api/users/<int:user_id>")
@require_user
def get_profile(user, user_id):
    connection = db()
    target = connection.execute(
        """
        SELECT id,username,role,show_role_tag,pfp,description,pronouns,
               created_at,last_seen
        FROM users WHERE id=?
        """,
        (user_id,),
    ).fetchone()

    if not target:
        connection.close()
        return jsonify(error="User not found"), 404

    result = dict(target)
    result["show_role_tag"] = bool(result["show_role_tag"])
    result["online"] = is_online(result["last_seen"])
    result["friend_status"] = get_friend_status(connection, user["id"], user_id)
    connection.close()
    return jsonify(result)


@app.put("/api/profile")
@require_user
def update_profile(user):
    data = request.get_json(silent=True) or {}
    username = data.get("username")
    pfp = data.get("pfp")
    description = data.get("description")
    pronouns = data.get("pronouns")

    connection = db()

    if username is not None:
        username = str(username).strip()
        if not re.fullmatch(r"[A-Za-z0-9_.-]{3,32}", username):
            connection.close()
            return jsonify(error="Invalid username"), 400
        exists = connection.execute(
            """
            SELECT id FROM users
            WHERE LOWER(username)=LOWER(?) AND id != ?
            """,
            (username, user["id"]),
        ).fetchone()
        if exists:
            connection.close()
            return jsonify(error="Username already exists"), 409

    if pfp is not None:
        pfp = str(pfp)
        if len(pfp) > 300000:
            connection.close()
            return jsonify(error="PFP is too large"), 400

    if description is not None:
        description = str(description)
        if len(description) > 500:
            connection.close()
            return jsonify(error="Description is too long"), 400

    if pronouns is not None:
        pronouns = str(pronouns)
        if len(pronouns) > 50:
            connection.close()
            return jsonify(error="Pronouns are too long"), 400

    fields, values = [], []
    for field, value in (
        ("username", username),
        ("pfp", pfp),
        ("description", description),
        ("pronouns", pronouns),
    ):
        if value is not None:
            fields.append(f"{field}=?")
            values.append(value)

    if not fields:
        connection.close()
        return jsonify(error="Nothing to update"), 400

    values.append(user["id"])
    connection.execute(
        f"UPDATE users SET {', '.join(fields)} WHERE id=?", values
    )
    connection.commit()

    updated = connection.execute(
        "SELECT * FROM users WHERE id=?", (user["id"],)
    ).fetchone()
    connection.close()

    socketio.emit("profile_updated", public_user(updated))
    return jsonify(success=True, user=public_user(updated))


@app.post("/api/role-tag")
@require_user
def role_tag(user):
    data = request.get_json(silent=True) or {}
    enabled = bool(data.get("show", True))
    connection = db()
    connection.execute(
        "UPDATE users SET show_role_tag=? WHERE id=?",
        (int(enabled), user["id"]),
    )
    connection.commit()
    connection.close()
    return jsonify(success=True)


# ---------------- PUBLIC CHAT ----------------

@app.get("/api/messages")
@require_user
def get_messages(user):
    connection = db()
    rows = connection.execute(
        """
        SELECT messages.id,messages.user_id,users.username,users.role,
               users.show_role_tag,users.pfp,users.last_seen,
               messages.message,messages.edited,messages.edited_at,
               messages.created_at
        FROM messages
        JOIN users ON users.id=messages.user_id
        ORDER BY messages.id DESC
        LIMIT 100
        """
    ).fetchall()
    connection.close()

    result = []
    for row in reversed(rows):
        item = dict(row)
        item["online"] = is_online(row["last_seen"])
        item["is_owner"] = row["user_id"] == user["id"]
        result.append(item)
    return jsonify(result)


@app.post("/api/messages")
@require_user
def send_message(user):
    data = request.get_json(silent=True) or {}
    message = str(data.get("message", "")).strip()

    if not message:
        return jsonify(error="Message cannot be empty"), 400
    if len(message) > 4000:
        return jsonify(error="Message is too long"), 400

    connection = db()
    cursor = connection.execute(
        """
        INSERT INTO messages(user_id,message,edited,edited_at,created_at)
        VALUES(?,?,0,'',?)
        """,
        (user["id"], message, now()),
    )
    message_id = cursor.lastrowid
    connection.commit()
    result = message_object(connection, message_id, user["id"])
    connection.close()

    socketio.emit("new_public_message", result)
    return jsonify(result)


@app.put("/api/messages/<int:message_id>")
@require_user
def edit_message(user, message_id):
    data = request.get_json(silent=True) or {}
    message = str(data.get("message", "")).strip()

    if not message:
        return jsonify(error="Message cannot be empty"), 400
    if len(message) > 4000:
        return jsonify(error="Message is too long"), 400

    connection = db()
    existing = connection.execute(
        "SELECT * FROM messages WHERE id=?", (message_id,)
    ).fetchone()

    if not existing:
        connection.close()
        return jsonify(error="Message not found"), 404
    if existing["user_id"] != user["id"] and ROLES.get(user["role"], 0) < ROLES["moderator"]:
        connection.close()
        return jsonify(error="You cannot edit this message"), 403

    connection.execute(
        """
        UPDATE messages SET message=?,edited=1,edited_at=? WHERE id=?
        """,
        (message, now(), message_id),
    )
    connection.commit()
    result = message_object(connection, message_id, user["id"])
    connection.close()

    socketio.emit("message_edited", result)
    return jsonify(success=True, message=result)


@app.delete("/api/messages/<int:message_id>")
@require_user
def delete_message(user, message_id):
    connection = db()
    message = connection.execute(
        "SELECT * FROM messages WHERE id=?", (message_id,)
    ).fetchone()

    if not message:
        connection.close()
        return jsonify(error="Message not found"), 404

    if message["user_id"] != user["id"] and ROLES.get(user["role"], 0) < ROLES["moderator"]:
        connection.close()
        return jsonify(error="You cannot delete this message"), 403

    connection.execute("DELETE FROM messages WHERE id=?", (message_id,))
    connection.commit()
    connection.close()

    socketio.emit("message_deleted", {"id": message_id})
    return jsonify(success=True)


# ---------------- FRIENDS ----------------

@app.get("/api/friends/search")
@require_user
def search_friends(user):
    query = str(request.args.get("q", "")).strip()
    if not query:
        return jsonify([])

    connection = db()
    rows = connection.execute(
        """
        SELECT id,username,role,show_role_tag,pfp,description,pronouns,last_seen
        FROM users
        WHERE username LIKE ? AND id != ? AND banned=0
        ORDER BY username COLLATE NOCASE
        LIMIT 25
        """,
        (f"%{query}%", user["id"]),
    ).fetchall()
    connection.close()
    return jsonify([user_json(row) for row in rows])


@app.post("/api/friends/add")
@require_user
def add_friend(user):
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()

    if not username:
        return jsonify(error="Enter a username"), 400

    connection = db()
    target = connection.execute(
        "SELECT * FROM users WHERE LOWER(username)=LOWER(?)",
        (username,),
    ).fetchone()

    if not target:
        connection.close()
        return jsonify(error="User not found"), 404
    if target["id"] == user["id"]:
        connection.close()
        return jsonify(error="You cannot add yourself"), 400
    if target["banned"]:
        connection.close()
        return jsonify(error="That user is unavailable"), 404

    existing = connection.execute(
        """
        SELECT * FROM friendships
        WHERE (user_id=? AND friend_id=?) OR (user_id=? AND friend_id=?)
        ORDER BY id DESC LIMIT 1
        """,
        (user["id"], target["id"], target["id"], user["id"]),
    ).fetchone()

    if existing:
        if existing["status"] == "accepted":
            connection.close()
            return jsonify(error="You are already friends"), 409

        if (
            existing["user_id"] == target["id"]
            and existing["friend_id"] == user["id"]
            and existing["status"] == "pending"
        ):
            connection.execute(
                "UPDATE friendships SET status='accepted' WHERE id=?",
                (existing["id"],),
            )
            connection.commit()
            connection.close()

            payload = {"user_id": user["id"], "friend_id": target["id"]}
            socketio.emit("friend_updated", payload, room=f"user_{target['id']}")
            socketio.emit("friend_updated", payload, room=f"user_{user['id']}")
            return jsonify(success=True, status="accepted")

        connection.close()
        return jsonify(error="A friend request already exists"), 409

    connection.execute(
        """
        INSERT INTO friendships(user_id,friend_id,status)
        VALUES(?,?, 'pending')
        """,
        (user["id"], target["id"]),
    )
    connection.commit()
    connection.close()

    socketio.emit(
        "friend_request",
        {"from": public_user(user)},
        room=f"user_{target['id']}",
    )
    return jsonify(success=True, status="sent")


@app.get("/api/friends")
@require_user
def get_friends(user):
    connection = db()
    rows = connection.execute(
        """
        SELECT u.id,u.username,u.role,u.show_role_tag,u.pfp,
               u.description,u.pronouns,u.last_seen
        FROM friendships f
        JOIN users u ON u.id=CASE
            WHEN f.user_id=? THEN f.friend_id
            ELSE f.user_id END
        WHERE (f.user_id=? OR f.friend_id=?) AND f.status='accepted'
        ORDER BY u.username COLLATE NOCASE
        """,
        (user["id"], user["id"], user["id"]),
    ).fetchall()
    connection.close()
    return jsonify([user_json(row) for row in rows])


@app.get("/api/friends/requests")
@require_user
def friend_requests(user):
    connection = db()
    rows = connection.execute(
        """
        SELECT f.id AS request_id,u.id,u.username,u.role,u.show_role_tag,
               u.pfp,u.description,u.pronouns,u.last_seen
        FROM friendships f
        JOIN users u ON u.id=f.user_id
        WHERE f.friend_id=? AND f.status='pending'
        ORDER BY f.id DESC
        """,
        (user["id"],),
    ).fetchall()
    connection.close()
    return jsonify([
        {**user_json(row), "request_id": row["request_id"]}
        for row in rows
    ])


@app.post("/api/friends/accept/<int:request_id>")
@require_user
def accept_friend(user, request_id):
    connection = db()
    request_row = connection.execute(
        """
        SELECT * FROM friendships
        WHERE id=? AND friend_id=? AND status='pending'
        """,
        (request_id, user["id"]),
    ).fetchone()

    if not request_row:
        connection.close()
        return jsonify(error="Request not found"), 404

    connection.execute(
        "UPDATE friendships SET status='accepted' WHERE id=?",
        (request_id,),
    )
    connection.commit()
    connection.close()

    payload = {"user_id": user["id"], "friend_id": request_row["user_id"]}
    socketio.emit("friend_updated", payload, room=f"user_{user['id']}")
    socketio.emit("friend_updated", payload, room=f"user_{request_row['user_id']}")
    return jsonify(success=True)


@app.delete("/api/friends/<int:user_id>")
@require_user
def remove_friend(user, user_id):
    connection = db()
    connection.execute(
        """
        DELETE FROM friendships
        WHERE (user_id=? AND friend_id=?) OR (user_id=? AND friend_id=?)
        """,
        (user["id"], user_id, user_id, user["id"]),
    )
    connection.commit()
    connection.close()

    payload = {"user_id": user["id"], "friend_id": user_id}
    socketio.emit("friend_updated", payload, room=f"user_{user_id}")
    socketio.emit("friend_updated", payload, room=f"user_{user['id']}")
    return jsonify(success=True)


# ---------------- DMS ----------------

@app.get("/api/dm/<int:user_id>")
@require_user
def get_dm(user, user_id):
    connection = db()
    if not are_friends(connection, user["id"], user_id):
        connection.close()
        return jsonify(error="You must be friends to DM"), 403

    rows = connection.execute(
        """
        SELECT pm.id,pm.sender_id,pm.receiver_id,pm.message,pm.edited,
               pm.edited_at,pm.created_at,u.username,u.pfp,u.role,u.last_seen
        FROM private_messages pm
        JOIN users u ON u.id=pm.sender_id
        WHERE (pm.sender_id=? AND pm.receiver_id=?)
           OR (pm.sender_id=? AND pm.receiver_id=?)
        ORDER BY pm.id ASC LIMIT 200
        """,
        (user["id"], user_id, user_id, user["id"]),
    ).fetchall()
    connection.close()

    result = []
    for row in rows:
        item = dict(row)
        item["online"] = is_online(row["last_seen"])
        result.append(item)
    return jsonify(result)


@app.post("/api/dm/<int:user_id>")
@require_user
def send_dm(user, user_id):
    data = request.get_json(silent=True) or {}
    message = str(data.get("message", "")).strip()

    if not message:
        return jsonify(error="Message cannot be empty"), 400
    if len(message) > 4000:
        return jsonify(error="Message is too long"), 400

    connection = db()
    if not are_friends(connection, user["id"], user_id):
        connection.close()
        return jsonify(error="You must be friends"), 403

    target = connection.execute(
        "SELECT * FROM users WHERE id=? AND banned=0", (user_id,)
    ).fetchone()

    if not target:
        connection.close()
        return jsonify(error="User not found"), 404

    cursor = connection.execute(
        """
        INSERT INTO private_messages(
            sender_id,receiver_id,message,edited,edited_at,created_at
        )
        VALUES(?,?,?,0,'',?)
        """,
        (user["id"], user_id, message, now()),
    )
    message_id = cursor.lastrowid
    connection.commit()

    row = connection.execute(
        """
        SELECT pm.id,pm.sender_id,pm.receiver_id,pm.message,pm.edited,
               pm.edited_at,pm.created_at,u.username,u.pfp,u.role,u.last_seen
        FROM private_messages pm
        JOIN users u ON u.id=pm.sender_id
        WHERE pm.id=?
        """,
        (message_id,),
    ).fetchone()
    connection.close()

    result = dict(row)
    result["online"] = is_online(row["last_seen"])

    socketio.emit("new_dm_message", result, room=f"user_{user['id']}")
    socketio.emit("new_dm_message", result, room=f"user_{user_id}")
    return jsonify(success=True, message=result)


# ---------------- REPORTS ----------------

@app.post("/api/reports")
@require_user
def create_report(user):
    data = request.get_json(silent=True) or {}
    message_id = data.get("message_id")
    reported_user_id = data.get("user_id")
    reason = str(data.get("reason", "Other")).strip()[:100]
    details = str(data.get("details", "")).strip()[:2000]

    if message_id is None and reported_user_id is None:
        return jsonify(error="Nothing to report"), 400

    connection = db()

    if message_id is not None:
        try:
            message_id = int(message_id)
        except (TypeError, ValueError):
            connection.close()
            return jsonify(error="Invalid message ID"), 400

        message = connection.execute(
            "SELECT user_id FROM messages WHERE id=?", (message_id,)
        ).fetchone()

        if not message:
            connection.close()
            return jsonify(error="Message not found"), 404

        reported_user_id = message["user_id"]

    if reported_user_id is not None:
        try:
            reported_user_id = int(reported_user_id)
        except (TypeError, ValueError):
            connection.close()
            return jsonify(error="Invalid user ID"), 400

    if reported_user_id == user["id"]:
        connection.close()
        return jsonify(error="You cannot report yourself"), 400

    connection.execute(
        """
        INSERT INTO reports(
            reporter_id,reported_user_id,message_id,reason,details,
            status,created_at,moderator_note
        )
        VALUES(?,?,?,?,?,'open',?,'')
        """,
        (
            user["id"],
            reported_user_id,
            message_id,
            reason or "Other",
            details,
            now(),
        ),
    )
    connection.commit()
    connection.close()

    socketio.emit("new_report", {"created": True})
    return jsonify(success=True)


@app.get("/api/reports")
@require_role("moderator")
def get_reports(user):
    status = request.args.get("status", "all").lower()
    if status not in {"all", "open", "resolved", "dismissed"}:
        return jsonify(error="Invalid status"), 400

    connection = db()
    base_query = """
        SELECT r.*,reporter.username AS reporter_username,
               reported.username AS reported_username,
               m.message AS reported_message,
               resolver.username AS resolver_username
        FROM reports r
        JOIN users reporter ON reporter.id=r.reporter_id
        LEFT JOIN users reported ON reported.id=r.reported_user_id
        LEFT JOIN users resolver ON resolver.id=r.resolved_by
        LEFT JOIN messages m ON m.id=r.message_id
    """

    if status == "all":
        rows = connection.execute(
            base_query
            + """
                ORDER BY CASE WHEN r.status='open' THEN 0 ELSE 1 END,
                         r.id DESC LIMIT 500
            """
        ).fetchall()
    else:
        rows = connection.execute(
            base_query
            + " WHERE r.status=? ORDER BY r.id DESC LIMIT 500",
            (status,),
        ).fetchall()

    connection.close()
    return jsonify([dict(row) for row in rows])


def update_report_status(report_id, status, user):
    data = request.get_json(silent=True) or {}
    note = str(data.get("note", "")).strip()[:2000]

    connection = db()
    report = connection.execute(
        "SELECT id FROM reports WHERE id=?", (report_id,)
    ).fetchone()

    if not report:
        connection.close()
        return jsonify(error="Report not found"), 404

    connection.execute(
        """
        UPDATE reports
        SET status=?,resolved_at=?,resolved_by=?,moderator_note=?
        WHERE id=?
        """,
        (status, now(), user["id"], note, report_id),
    )
    connection.commit()
    connection.close()
    socketio.emit("reports_updated", {"id": report_id, "status": status})
    return jsonify(success=True)


@app.post("/api/reports/<int:report_id>/resolve")
@require_role("moderator")
def resolve_report(user, report_id):
    return update_report_status(report_id, "resolved", user)


@app.post("/api/reports/<int:report_id>/dismiss")
@require_role("moderator")
def dismiss_report(user, report_id):
    return update_report_status(report_id, "dismissed", user)


# ---------------- MODERATION ----------------

@app.post("/api/mod/ban/<int:user_id>")
@require_role("moderator")
def ban_user(user, user_id):
    connection = db()
    target = connection.execute(
        "SELECT * FROM users WHERE id=?", (user_id,)
    ).fetchone()

    if not target:
        connection.close()
        return jsonify(error="User not found"), 404
    if target["role"] == "owner":
        connection.close()
        return jsonify(error="Owner cannot be banned"), 403
    if user["role"] == "moderator" and target["role"] in {"admin", "owner"}:
        connection.close()
        return jsonify(error="Moderators cannot ban admins"), 403

    connection.execute("UPDATE users SET banned=1 WHERE id=?", (user_id,))
    connection.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
    connection.commit()
    connection.close()

    socketio.emit("user_banned", {"user_id": user_id}, room=f"user_{user_id}")
    return jsonify(success=True)


@app.post("/api/mod/unban/<int:user_id>")
@require_role("moderator")
def unban_user(user, user_id):
    connection = db()
    target = connection.execute(
        "SELECT role FROM users WHERE id=?", (user_id,)
    ).fetchone()

    if not target:
        connection.close()
        return jsonify(error="User not found"), 404

    connection.execute("UPDATE users SET banned=0 WHERE id=?", (user_id,))
    connection.commit()
    connection.close()
    return jsonify(success=True)


@app.delete("/api/mod/message/<int:message_id>")
@require_role("moderator")
def mod_delete_message(user, message_id):
    connection = db()
    message = connection.execute(
        "SELECT id FROM messages WHERE id=?", (message_id,)
    ).fetchone()

    if not message:
        connection.close()
        return jsonify(error="Message not found"), 404

    connection.execute("DELETE FROM messages WHERE id=?", (message_id,))
    connection.commit()
    connection.close()
    socketio.emit("message_deleted", {"id": message_id})
    return jsonify(success=True)


@app.get("/api/mod/users")
@require_role("moderator")
def mod_users(user):
    connection = db()
    rows = connection.execute(
        """
        SELECT id,username,role,banned,show_role_tag,pfp,description,
               pronouns,created_at,last_seen
        FROM users ORDER BY id DESC LIMIT 1000
        """
    ).fetchall()
    connection.close()

    result = []
    for row in rows:
        item = dict(row)
        item["online"] = is_online(row["last_seen"])
        result.append(item)
    return jsonify(result)


# ---------------- ADMIN / OWNER ----------------

@app.post("/api/admin/role/<int:user_id>")
@require_role("admin")
def change_role(user, user_id):
    data = request.get_json(silent=True) or {}
    new_role = str(data.get("role", "user")).lower()

    if new_role not in {"user", "moderator", "admin"}:
        return jsonify(error="Invalid role"), 400

    connection = db()
    target = connection.execute(
        "SELECT * FROM users WHERE id=?", (user_id,)
    ).fetchone()

    if not target:
        connection.close()
        return jsonify(error="User not found"), 404
    if target["role"] == "owner":
        connection.close()
        return jsonify(error="Owner role cannot be changed"), 403
    if user["role"] == "admin" and target["role"] == "admin" and target["id"] != user["id"]:
        connection.close()
        return jsonify(error="Admins cannot change another admin"), 403

    connection.execute(
        "UPDATE users SET role=? WHERE id=?", (new_role, user_id)
    )
    connection.commit()
    connection.close()

    socketio.emit("role_changed", {"user_id": user_id, "role": new_role})
    return jsonify(success=True)


@app.post("/api/owner/ip-ban/<int:user_id>")
@require_role("owner")
def owner_ip_ban(user, user_id):
    connection = db()
    target = connection.execute(
        "SELECT * FROM users WHERE id=?", (user_id,)
    ).fetchone()

    if not target:
        connection.close()
        return jsonify(error="User not found"), 404
    if target["role"] == "owner":
        connection.close()
        return jsonify(error="Cannot IP ban owner"), 403

    ip = target["ip"]
    if not ip or ip in {"unknown", "server"}:
        connection.close()
        return jsonify(error="No usable IP is recorded"), 400

    connection.execute(
        "INSERT OR IGNORE INTO ip_bans(ip,created_at) VALUES(?,?)",
        (ip, now()),
    )
    connection.execute("UPDATE users SET banned=1 WHERE id=?", (user_id,))
    connection.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
    connection.commit()
    connection.close()

    socketio.emit("user_banned", {"user_id": user_id}, room=f"user_{user_id}")
    return jsonify(success=True)


@app.get("/api/owner/ip-bans")
@require_role("owner")
def owner_ip_bans(user):
    connection = db()
    rows = connection.execute(
        "SELECT * FROM ip_bans ORDER BY id DESC"
    ).fetchall()
    connection.close()
    return jsonify([dict(row) for row in rows])


@app.delete("/api/owner/ip-ban/<int:ban_id>")
@require_role("owner")
def owner_remove_ip_ban(user, ban_id):
    connection = db()
    connection.execute("DELETE FROM ip_bans WHERE id=?", (ban_id,))
    connection.commit()
    connection.close()
    return jsonify(success=True)


@app.delete("/api/owner/account/<int:user_id>")
@require_role("owner")
def owner_delete_account(user, user_id):
    connection = db()
    target = connection.execute(
        "SELECT * FROM users WHERE id=?", (user_id,)
    ).fetchone()

    if not target:
        connection.close()
        return jsonify(error="User not found"), 404
    if target["role"] == "owner":
        connection.close()
        return jsonify(error="Cannot delete owner"), 403

    connection.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
    connection.execute(
        "DELETE FROM friendships WHERE user_id=? OR friend_id=?",
        (user_id, user_id),
    )
    connection.execute(
        "DELETE FROM private_messages WHERE sender_id=? OR receiver_id=?",
        (user_id, user_id),
    )
    connection.execute(
        "DELETE FROM reports WHERE reporter_id=? OR reported_user_id=?",
        (user_id, user_id),
    )
    connection.execute("DELETE FROM messages WHERE user_id=?", (user_id,))
    connection.execute("DELETE FROM users WHERE id=?", (user_id,))
    connection.commit()
    connection.close()

    socketio.emit("account_deleted", {"user_id": user_id})
    return jsonify(success=True)


# ---------------- FRONTEND ----------------

HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="theme-color" content="#0b0b11">
<title>SpookChat</title>
<script src="https://cdn.socket.io/4.8.1/socket.io.min.js"></script>
<style>
*{box-sizing:border-box}
:root{--bg:#09090d;--panel:#111119;--panel2:#171721;--border:#272733;--purple:#8b5cf6;--purple2:#a78bfa;--text:#f4f4f5;--muted:#a1a1aa;--danger:#ef4444;--green:#22c55e}
body{margin:0;background:var(--bg);color:var(--text);font-family:Inter,system-ui,Arial,sans-serif;height:100vh;overflow:hidden}
button,input,textarea{font:inherit}
button{cursor:pointer}
.hidden{display:none!important}
#authScreen{height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.auth-box{width:min(420px,100%);background:var(--panel);border:1px solid var(--border);border-radius:18px;padding:30px;box-shadow:0 20px 70px #0008}
.brand{font-weight:900;font-size:28px;letter-spacing:-1px;margin-bottom:22px}.brand span{color:var(--purple2)}
.auth-box h2{margin:0 0 16px}.auth-box input{width:100%;margin:7px 0;padding:13px 14px;background:#0c0c12;border:1px solid var(--border);border-radius:10px;color:white;outline:none}.auth-box input:focus,.composer input:focus,.search input:focus{border-color:var(--purple)}
.primary,.action-button{border:0;background:var(--purple);color:#fff;border-radius:10px;padding:12px 16px;font-weight:800}.primary{width:100%;margin-top:10px}.switch{color:var(--purple2);text-align:center;margin-top:16px;cursor:pointer}.error{color:#f87171;min-height:20px;font-size:14px}
#app{display:grid;grid-template-columns:240px 1fr 280px;height:100vh}
.sidebar{background:#0d0d13;border-right:1px solid var(--border);padding:18px 12px;overflow:auto}.nav button{width:100%;background:transparent;border:0;color:#c4c4cc;text-align:left;padding:11px 12px;border-radius:9px;margin:2px 0}.nav button:hover{background:#1a1a24;color:#fff}.friends-title{color:#777783;font-size:12px;text-transform:uppercase;font-weight:800;margin:22px 10px 8px}
.friend-item{padding:9px 10px;border-radius:9px;display:flex;align-items:center;gap:9px;cursor:pointer}.friend-item:hover{background:#1a1a24}
.avatar{width:34px;height:34px;border-radius:50%;background:#242432;display:flex;align-items:center;justify-content:center;overflow:hidden;flex:none}.avatar img{width:100%;height:100%;object-fit:cover}.dot{width:8px;height:8px;border-radius:50%;background:#666}.dot.online{background:var(--green)}
.main{min-width:0;display:flex;flex-direction:column;background:#0b0b10}.topbar{height:62px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;padding:0 18px}.channel{font-weight:800}.channel span{color:var(--muted);margin-right:6px}.messages{flex:1;overflow-y:auto;padding:20px}.message{display:flex;gap:11px;padding:8px 5px;border-radius:9px}.message:hover{background:#101017}.message-body{min-width:0;flex:1}.message-head{display:flex;gap:8px;align-items:center}.username{font-weight:800}.role{font-size:10px;background:#2b2148;color:#c4b5fd;border-radius:5px;padding:2px 5px}.time{font-size:11px;color:#686873}.message-text{white-space:pre-wrap;overflow-wrap:anywhere;margin-top:3px;color:#dedee3}.edited{font-size:10px;color:#777;margin-left:4px}.msg-actions{float:right;display:none;gap:3px}.message:hover .msg-actions{display:flex}.tiny{border:1px solid var(--border);background:#171720;color:#ccc;border-radius:6px;padding:3px 6px;font-size:11px}.composer{padding:12px 18px;border-top:1px solid var(--border)}.composer-inner{display:flex;gap:8px}.composer input{flex:1;background:#15151d;border:1px solid var(--border);border-radius:11px;color:#fff;padding:13px;outline:none}.composer button{width:48px;border:0;border-radius:10px;background:var(--purple);color:#fff;font-size:20px}.right{border-left:1px solid var(--border);background:#0d0d13;padding:18px;overflow:auto}.panel{max-width:900px;margin:auto;background:var(--panel);border:1px solid var(--border);border-radius:14px;padding:20px}.panel h2{margin-top:0}.panel-card{background:#15151d;border:1px solid var(--border);border-radius:11px;padding:13px;margin:9px 0}.panel-row{display:flex;justify-content:space-between;gap:10px;align-items:center}.small-button{border:1px solid var(--border);background:#1a1a24;color:#ddd;border-radius:8px;padding:7px 10px}.small-button:hover{border-color:#4b4b60}.danger{color:#fca5a5;border-color:#5a2525}.search{display:flex;gap:8px;margin-bottom:12px}.search input{flex:1;background:#0d0d13;border:1px solid var(--border);border-radius:9px;color:#fff;padding:10px;outline:none}.profile-card{text-align:center}.profile-big{width:90px;height:90px;border-radius:50%;margin:0 auto 12px;background:#292938;display:flex;align-items:center;justify-content:center;overflow:hidden;font-size:30px}.profile-big img{width:100%;height:100%;object-fit:cover}.muted{color:var(--muted)}.status{font-size:12px}.mobile-nav{display:none}.modal{position:fixed;inset:0;background:#0009;display:flex;align-items:center;justify-content:center;padding:18px;z-index:20}.modal-box{width:min(520px,100%);background:#12121a;border:1px solid var(--border);border-radius:14px;padding:20px}.modal-box input,.modal-box textarea{width:100%;background:#0b0b10;border:1px solid var(--border);color:#fff;border-radius:9px;padding:10px;margin:6px 0 12px;outline:none}.modal-box textarea{min-height:110px;resize:vertical}.modal-actions{display:flex;justify-content:flex-end;gap:8px;margin-top:14px}
@media(max-width:1000px){#app{grid-template-columns:220px 1fr}.right{display:none}}
@media(max-width:700px){body{overflow:hidden}#app{display:block;height:100dvh}.sidebar{position:fixed;z-index:10;left:-270px;top:0;bottom:0;width:260px;transition:left .2s;box-shadow:15px 0 40px #0009}.sidebar.mobile-open{left:0}.main{height:100dvh}.messages{padding:12px}.topbar{height:56px}.composer{padding:9px}.mobile-nav{position:fixed;bottom:0;left:0;right:0;height:64px;background:#101018;border-top:1px solid var(--border);display:flex;z-index:9;padding-bottom:env(safe-area-inset-bottom)}.mobile-nav button{flex:1;background:transparent;border:0;color:#888;font-size:18px}.mobile-nav button span{display:block;font-size:10px;margin-top:2px}.mobile-nav button.active{color:#c4b5fd}.main{padding-bottom:64px}}
</style>
</head>
<body>
<div id="authScreen">
  <div class="auth-box">
    <div class="brand">Spook<span>Chat</span></div>
    <h2 id="authTitle">Login</h2>
    <div id="authError" class="error"></div>
    <input id="authUsername" placeholder="Username" autocomplete="username">
    <input id="authPassword" placeholder="Password" type="password" autocomplete="current-password">
    <button class="primary" onclick="authAction()"><span id="authButton">Login</span></button>
    <div class="switch" onclick="toggleAuth()" id="authSwitch">Need an account? Register</div>
  </div>
</div>

<div id="app" class="hidden">
  <aside class="sidebar">
    <div class="brand">Spook<span>Chat</span></div>
    <div class="nav">
      <button onclick="showHome()">💬 Chat</button>
      <button onclick="showFriends()">👥 Friends</button>
      <button onclick="showProfile()">👤 Profile</button>
      <button id="moderationButton" class="hidden" onclick="showModeration()">🛡️ Moderation</button>
      <button id="ownerButton" class="hidden" onclick="showOwner()">⚙️ Owner</button>
      <button onclick="logout()">🚪 Logout</button>
    </div>
    <div class="friends-title">Direct Messages</div>
    <div id="friendList"></div>
  </aside>

  <main class="main">
    <div class="topbar">
      <div class="channel" id="channelName"><span>#</span>general</div>
      <div id="currentUser"></div>
    </div>
    <div id="mainContent" class="messages"></div>
    <div id="composer" class="composer">
      <div class="composer-inner">
        <input id="messageInput" placeholder="Message #general" autocomplete="off">
        <button onclick="sendMessage()">➤</button>
      </div>
    </div>
  </main>

  <aside class="right" id="rightPanel"></aside>
</div>

<div id="modal" class="modal hidden">
  <div class="modal-box" id="modalContent"></div>
</div>

<nav class="mobile-nav">
  <button onclick="showHome()" id="mobileChatButton">💬<span>Chat</span></button>
  <button onclick="showFriends()" id="mobileFriendsButton">👥<span>Friends</span></button>
  <button onclick="showProfile()" id="mobileProfileButton">👤<span>Profile</span></button>
  <button onclick="toggleMobileSidebar()">☰<span>More</span></button>
</nav>

<script>
let token = localStorage.getItem("spookchat_token") || "";
let currentUser = null;
let socket = null;
let currentPage = "home";
let currentDM = null;
let registerMode = false;

const $ = id => document.getElementById(id);

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, c => ({
    "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"
  }[c]));
}

async function api(path, options={}) {
  const headers = {...(options.headers || {})};
  if (token) headers.Authorization = token;
  if (options.body && !headers["Content-Type"]) headers["Content-Type"] = "application/json";

  const response = await fetch(path, {...options, headers});
  let data = {};
  try { data = await response.json(); } catch {}
  if (!response.ok) {
    if (response.status === 401 && path !== "/api/login" && path !== "/api/register") {
      logoutLocal();
    }
    throw new Error(data.error || `Request failed (${response.status})`);
  }
  return data;
}

function toggleAuth() {
  registerMode = !registerMode;
  $("authTitle").textContent = registerMode ? "Register" : "Login";
  $("authButton").textContent = registerMode ? "Register" : "Login";
  $("authSwitch").textContent = registerMode
    ? "Already have an account? Login"
    : "Need an account? Register";
  $("authError").textContent = "";
}

async function authAction() {
  $("authError").textContent = "";
  try {
    const data = await api(registerMode ? "/api/register" : "/api/login", {
      method:"POST",
      body:JSON.stringify({
        username:$("authUsername").value.trim(),
        password:$("authPassword").value
      })
    });
    token = data.token;
    currentUser = data.user;
    localStorage.setItem("spookchat_token", token);
    $("authPassword").value = "";
    startApp();
  } catch (e) {
    $("authError").textContent = e.message;
  }
}

$("authPassword").addEventListener("keydown", e => {
  if (e.key === "Enter") authAction();
});

async function startApp() {
  try {
    currentUser = await api("/api/me");
  } catch {
    logoutLocal();
    return;
  }

  $("authScreen").classList.add("hidden");
  $("app").classList.remove("hidden");
  updateRoleButtons();
  connectSocket();
  await loadFriends();
  await showHome();
}

function connectSocket() {
  if (socket) socket.disconnect();
  socket = io({auth:{token}});
  socket.on("connect", () => console.log("Realtime connected"));
  socket.on("new_public_message", message => {
    if (currentPage === "home" && !currentDM) appendOrReplaceMessage(message);
    else notify("New message", `${message.username}: ${message.message}`);
  });
  socket.on("message_edited", message => {
    if (currentPage === "home" && !currentDM) appendOrReplaceMessage(message, true);
  });
  socket.on("message_deleted", data => {
    const el = document.querySelector(`[data-message-id="${data.id}"]`);
    if (el) el.remove();
  });
  socket.on("new_dm_message", message => {
    if (currentDM && Number(currentDM.id) === Number(message.sender_id === currentUser.id ? message.receiver_id : message.sender_id)) {
      appendDM(message);
    } else {
      notify("New DM", `${message.username}: ${message.message}`);
    }
  });
  socket.on("friend_request", async () => {
    notify("Friend request", "You received a friend request.");
    await loadFriends();
  });
  socket.on("friend_updated", async () => {
    await loadFriends();
    if (currentPage === "friends") showFriends();
  });
  socket.on("profile_updated", user => {
    if (currentUser && user.id === currentUser.id) {
      currentUser = user;
      renderCurrentUser();
    }
  });
  socket.on("role_changed", data => {
    if (currentUser && Number(data.user_id) === Number(currentUser.id)) {
      currentUser.role = data.role;
      updateRoleButtons();
    }
  });
  socket.on("user_banned", data => {
    if (currentUser && Number(data.user_id) === Number(currentUser.id)) {
      alert("Your account was banned.");
      logoutLocal();
    }
  });
  socket.on("account_deleted", data => {
    if (currentUser && Number(data.user_id) === Number(currentUser.id)) logoutLocal();
  });
  socket.on("reports_updated", () => {
    if (currentPage === "moderation") loadReports("open");
  });
}

function notify(title, body) {
  if ("Notification" in window && Notification.permission === "granted") {
    try { new Notification(title, {body}); } catch {}
  }
}

function renderCurrentUser() {
  $("currentUser").innerHTML = `<span class="muted">${escapeHtml(currentUser.username)}</span>`;
}

function updateRoleButtons() {
  renderCurrentUser();
  $("moderationButton").classList.toggle("hidden",
    !currentUser || !["moderator","admin","owner"].includes(currentUser.role));
  $("ownerButton").classList.toggle("hidden",
    !currentUser || currentUser.role !== "owner");
}

async function showHome() {
  closeMobileSidebar();
  currentPage = "home";
  currentDM = null;
  setMobileActive("mobileChatButton");
  $("channelName").innerHTML = "<span>#</span>general";
  $("composer").classList.remove("hidden");
  $("messageInput").placeholder = "Message #general";
  $("mainContent").innerHTML = "";
  const messages = await api("/api/messages");
  messages.forEach(appendOrReplaceMessage);
  scrollBottom();
}

function messageHtml(message) {
  const roleTag = message.show_role_tag && message.role !== "user"
    ? `<span class="role">${escapeHtml(message.role)}</span>` : "";
  const avatar = message.pfp
    ? `<img src="${escapeHtml(message.pfp)}" onerror="this.remove()">`
    : escapeHtml((message.username || "?")[0].toUpperCase());

  return `
  <div class="message" data-message-id="${message.id}">
    <div class="avatar">${avatar}</div>
    <div class="message-body">
      <div class="message-head">
        <span class="username">${escapeHtml(message.username)}</span>
        ${roleTag}
        <span class="time">${formatTime(message.created_at)}</span>
        ${message.edited ? `<span class="edited">(edited)</span>` : ""}
        <span class="msg-actions">
          ${Number(message.user_id) === Number(currentUser.id) || ["moderator","admin","owner"].includes(currentUser.role)
            ? `<button class="tiny" onclick="editMessage(${message.id})">Edit</button><button class="tiny" onclick="deleteMessage(${message.id})">Delete</button>` : ""}
          ${Number(message.user_id) !== Number(currentUser.id)
            ? `<button class="tiny" onclick="reportMessage(${message.id})">Report</button>` : ""}
        </span>
      </div>
      <div class="message-text">${escapeHtml(message.message)}</div>
    </div>
  </div>`;
}

function appendOrReplaceMessage(message, replace=false) {
  const existing = document.querySelector(`[data-message-id="${message.id}"]`);
  if (existing) {
    existing.outerHTML = messageHtml(message);
    return;
  }
  const container = $("mainContent");
  const nearBottom = container.scrollHeight - container.scrollTop - container.clientHeight < 100;
  container.insertAdjacentHTML("beforeend", messageHtml(message));
  if (nearBottom || replace) scrollBottom();
}

async function sendMessage() {
  if (!currentUser || currentDM) return sendDM();
  const input = $("messageInput");
  const message = input.value.trim();
  if (!message) return;
  try {
    await api("/api/messages", {method:"POST", body:JSON.stringify({message})});
    input.value = "";
  } catch(e) { alert(e.message); }
}

async function editMessage(id) {
  const text = prompt("Edit message:");
  if (text === null) return;
  try { await api(`/api/messages/${id}`, {method:"PUT",body:JSON.stringify({message:text})}); }
  catch(e){alert(e.message)}
}

async function deleteMessage(id) {
  if (!confirm("Delete this message?")) return;
  try { await api(`/api/messages/${id}`, {method:"DELETE"}); }
  catch(e){alert(e.message)}
}

async function reportMessage(id) {
  const reason = prompt("Reason for report:", "Harassment");
  if (reason === null) return;
  const details = prompt("Additional details:", "") ?? "";
  try {
    await api("/api/reports", {
      method:"POST",
      body:JSON.stringify({message_id:id,reason,details})
    });
    alert("Report submitted.");
  } catch(e){alert(e.message)}
}

async function loadFriends() {
  try {
    const friends = await api("/api/friends");
    $("friendList").innerHTML = friends.length ? friends.map(f => `
      <div class="friend-item" onclick='openDM(${JSON.stringify(f).replace(/'/g,"&#39;")})'>
        <div class="avatar">${f.pfp ? `<img src="${escapeHtml(f.pfp)}">` : escapeHtml(f.username[0].toUpperCase())}</div>
        <div style="min-width:0;flex:1">
          <div style="white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${escapeHtml(f.username)}</div>
          <div class="status"><span class="dot ${f.online ? "online":""}" style="display:inline-block"></span> ${f.online?"Online":"Offline"}</div>
        </div>
      </div>`).join("") : `<div class="muted" style="padding:10px">No friends yet.</div>`;
  } catch {}
}

async function openDM(friend) {
  closeMobileSidebar();
  currentPage = "dm";
  currentDM = friend;
  $("channelName").innerHTML = `💬 ${escapeHtml(friend.username)}`;
  $("composer").classList.remove("hidden");
  $("messageInput").placeholder = `Message ${friend.username}`;
  $("mainContent").innerHTML = "";
  setMobileActive("mobileChatButton");
  try {
    const messages = await api(`/api/dm/${friend.id}`);
    messages.forEach(appendDM);
    scrollBottom();
  } catch(e){alert(e.message)}
}

function appendDM(message) {
  if (!currentDM) return;
  const id = `dm-${message.id}`;
  if (document.getElementById(id)) return;
  const mine = Number(message.sender_id) === Number(currentUser.id);
  const div = document.createElement("div");
  div.className = "message";
  div.id = id;
  div.innerHTML = `
    <div class="avatar">${message.pfp ? `<img src="${escapeHtml(message.pfp)}">` : escapeHtml(message.username[0].toUpperCase())}</div>
    <div class="message-body">
      <div class="message-head"><span class="username">${escapeHtml(mine ? "You" : message.username)}</span><span class="time">${formatTime(message.created_at)}</span></div>
      <div class="message-text">${escapeHtml(message.message)}</div>
    </div>`;
  $("mainContent").appendChild(div);
  scrollBottom();
}

async function sendDM() {
  if (!currentDM) return;
  const input = $("messageInput");
  const message = input.value.trim();
  if (!message) return;
  try {
    await api(`/api/dm/${currentDM.id}`, {method:"POST",body:JSON.stringify({message})});
    input.value = "";
  } catch(e){alert(e.message)}
}

async function showFriends() {
  closeMobileSidebar();
  currentPage = "friends";
  currentDM = null;
  setMobileActive("mobileFriendsButton");
  $("channelName").innerHTML = "👥 Friends";
  $("composer").classList.add("hidden");
  $("mainContent").innerHTML = `
    <div class="panel">
      <h2>Friends</h2>
      <div class="search"><input id="friendSearch" placeholder="Search username"><button class="small-button" onclick="searchFriends()">Search</button></div>
      <div id="friendResults"></div>
      <hr style="border-color:#272733">
      <h3>Friend Requests</h3>
      <div id="friendRequests">Loading...</div>
      <h3>Your Friends</h3>
      <div id="friendsCards">Loading...</div>
    </div>`;
  await renderFriendsPage();
}

async function renderFriendsPage() {
  const requests = await api("/api/friends/requests");
  $("friendRequests").innerHTML = requests.length ? requests.map(r => `
    <div class="panel-card panel-row">
      <span>${escapeHtml(r.username)}</span>
      <button class="small-button" onclick="acceptFriend(${r.request_id})">Accept</button>
    </div>`).join("") : `<div class="muted">No pending requests.</div>`;

  const friends = await api("/api/friends");
  $("friendsCards").innerHTML = friends.length ? friends.map(f => `
    <div class="panel-card panel-row">
      <span>${escapeHtml(f.username)} <span class="status">● ${f.online?"Online":"Offline"}</span></span>
      <div><button class="small-button" onclick='openDM(${JSON.stringify(f).replace(/'/g,"&#39;")})'>Message</button>
      <button class="small-button danger" onclick="removeFriend(${f.id})">Remove</button></div>
    </div>`).join("") : `<div class="muted">No friends yet.</div>`;
}

async function searchFriends() {
  const q = $("friendSearch").value.trim();
  if (!q) return;
  try {
    const users = await api(`/api/friends/search?q=${encodeURIComponent(q)}`);
    $("friendResults").innerHTML = users.length ? users.map(u => `
      <div class="panel-card panel-row">
        <span>${escapeHtml(u.username)}</span>
        <button class="small-button" onclick="addFriend(${JSON.stringify(u.username)})">Add</button>
      </div>`).join("") : `<div class="muted">No users found.</div>`;
  } catch(e){alert(e.message)}
}

async function addFriend(username) {
  try { await api("/api/friends/add",{method:"POST",body:JSON.stringify({username})}); alert("Friend request sent."); renderFriendsPage(); }
  catch(e){alert(e.message)}
}

async function acceptFriend(id) {
  try { await api(`/api/friends/accept/${id}`,{method:"POST"}); await renderFriendsPage(); await loadFriends(); }
  catch(e){alert(e.message)}
}

async function removeFriend(id) {
  if (!confirm("Remove this friend?")) return;
  try { await api(`/api/friends/${id}`,{method:"DELETE"}); await renderFriendsPage(); await loadFriends(); }
  catch(e){alert(e.message)}
}

async function showProfile() {
  closeMobileSidebar();
  currentPage = "profile";
  currentDM = null;
  setMobileActive("mobileProfileButton");
  $("channelName").innerHTML = "👤 Profile";
  $("composer").classList.add("hidden");
  renderSelfProfile();
}

function renderSelfProfile() {
  const u = currentUser;
  $("mainContent").innerHTML = `
    <div class="panel profile-card">
      <div class="profile-big">${u.pfp ? `<img src="${escapeHtml(u.pfp)}">` : escapeHtml(u.username[0].toUpperCase())}</div>
      <h2>${escapeHtml(u.username)}</h2>
      <div>${u.show_role_tag && u.role !== "user" ? `<span class="role">${escapeHtml(u.role)}</span>` : ""}</div>
      <p class="muted">${escapeHtml(u.description || "No description.")}</p>
      ${u.pronouns ? `<div class="muted">${escapeHtml(u.pronouns)}</div>` : ""}
      <p class="status"><span class="dot online" style="display:inline-block"></span> Online</p>
      <button class="action-button" onclick="editProfile()">Edit Profile</button>
    </div>`;
}

function editProfile() {
  const u = currentUser;
  openModal(`
    <h2>Edit Profile</h2>
    <label>Username</label><input id="editUsername" value="${escapeHtml(u.username)}">
    <label>Profile picture URL</label><input id="editPfp" value="${escapeHtml(u.pfp || "")}">
    <label>Pronouns</label><input id="editPronouns" value="${escapeHtml(u.pronouns || "")}">
    <label>Description</label><textarea id="editDescription">${escapeHtml(u.description || "")}</textarea>
    <label><input type="checkbox" id="showRoleTag" ${u.show_role_tag ? "checked":""}> Show role tag</label>
    <div class="modal-actions"><button class="small-button" onclick="closeModal()">Cancel</button><button class="action-button" onclick="saveProfile()">Save</button></div>`);
}

async function saveProfile() {
  try {
    await api("/api/profile",{method:"PUT",body:JSON.stringify({
      username:$("editUsername").value,pfp:$("editPfp").value,
      pronouns:$("editPronouns").value,description:$("editDescription").value
    })});
    await api("/api/role-tag",{method:"POST",body:JSON.stringify({show:$("showRoleTag").checked})});
    currentUser = await api("/api/me");
    closeModal(); renderSelfProfile(); updateRoleButtons(); loadFriends();
  } catch(e){alert(e.message)}
}

async function showModeration() {
  closeMobileSidebar();
  currentPage = "moderation"; currentDM = null;
  $("channelName").textContent = "🛡️ Moderation";
  $("composer").classList.add("hidden");
  $("mainContent").innerHTML = `<div class="panel"><h2>Reports</h2>
    <div style="display:flex;gap:7px;flex-wrap:wrap;margin-bottom:12px">
      <button class="small-button" onclick="loadReports('open')">Open</button>
      <button class="small-button" onclick="loadReports('resolved')">Resolved</button>
      <button class="small-button" onclick="loadReports('dismissed')">Dismissed</button>
      <button class="small-button" onclick="loadReports('all')">All</button>
    </div><div id="reports">Loading...</div></div>`;
  await loadReports("open");
}

async function loadReports(status) {
  try {
    const reports = await api(`/api/reports?status=${encodeURIComponent(status)}`);
    const c = $("reports"); if (!c) return;
    c.innerHTML = reports.length ? reports.map(r => `
      <div class="panel-card">
        <div class="panel-row"><strong>Report #${r.id}</strong><span>${escapeHtml(r.status)}</span></div>
        <p><b>Reporter:</b> ${escapeHtml(r.reporter_username)}</p>
        <p><b>Reported:</b> ${escapeHtml(r.reported_username || "Unknown")}</p>
        <p><b>Reason:</b> ${escapeHtml(r.reason)}</p>
        <p><b>Details:</b><br>${escapeHtml(r.details || "None")}</p>
        ${r.reported_message ? `<p><b>Message:</b><br>${escapeHtml(r.reported_message)}</p>`:""}
        ${r.status === "open" ? `<div class="modal-actions">
          ${r.message_id ? `<button class="small-button danger" onclick="deleteReported(${r.message_id})">Delete Message</button>`:""}
          ${r.reported_user_id ? `<button class="small-button danger" onclick="banReported(${r.reported_user_id})">Ban User</button>`:""}
          <button class="small-button" onclick="resolveReport(${r.id})">Resolve</button>
          <button class="small-button" onclick="dismissReport(${r.id})">Dismiss</button>
        </div>`:""}
      </div>`).join("") : `<div class="panel-card">No reports found.</div>`;
  } catch(e){alert(e.message)}
}

async function deleteReported(id){try{await api(`/api/mod/message/${id}`,{method:"DELETE"});loadReports("open")}catch(e){alert(e.message)}}
async function banReported(id){if(!confirm("Ban this user?"))return;try{await api(`/api/mod/ban/${id}`,{method:"POST"});loadReports("open")}catch(e){alert(e.message)}}
async function resolveReport(id){const note=prompt("Optional moderator note:","");if(note===null)return;try{await api(`/api/reports/${id}/resolve`,{method:"POST",body:JSON.stringify({note})});loadReports("open")}catch(e){alert(e.message)}}
async function dismissReport(id){const note=prompt("Optional dismissal note:","");if(note===null)return;try{await api(`/api/reports/${id}/dismiss`,{method:"POST",body:JSON.stringify({note})});loadReports("open")}catch(e){alert(e.message)}}

async function showOwner() {
  closeMobileSidebar();
  currentPage = "owner"; currentDM = null;
  $("channelName").textContent = "⚙️ Owner Panel";
  $("composer").classList.add("hidden");
  $("mainContent").innerHTML = `<div class="panel"><h2>Owner Panel</h2><div id="ownerUsers">Loading...</div></div>`;
  try {
    const users = await api("/api/mod/users");
    $("ownerUsers").innerHTML = users.map(u => `
      <div class="panel-card panel-row">
        <div>
          <strong>${escapeHtml(u.username)}</strong>
          <div>Role: ${escapeHtml(u.role)}</div>
          <div><span class="dot ${u.online?"online":""}" style="display:inline-block"></span> ${u.online?"Online":"Offline"}</div>
          <div>${u.banned?"🔴 Banned":"🟢 Active"}</div>
        </div>
        ${u.role !== "owner" ? `<div style="display:flex;flex-wrap:wrap;gap:5px;justify-content:flex-end">
          <button class="small-button" onclick="changeRole(${u.id})">Role</button>
          <button class="small-button" onclick="toggleBan(${u.id},${u.banned})">${u.banned?"Unban":"Ban"}</button>
          <button class="small-button danger" onclick="ipBan(${u.id})">IP Ban</button>
          <button class="small-button danger" onclick="deleteAccount(${u.id})">Delete</button>
        </div>`:"<b>OWNER</b>"}
      </div>`).join("");
  } catch(e){alert(e.message)}
}

async function changeRole(id) {
  const role = prompt("Role: user, moderator, admin","moderator");
  if (!role || !["user","moderator","admin"].includes(role.toLowerCase())) return;
  try{await api(`/api/admin/role/${id}`,{method:"POST",body:JSON.stringify({role:role.toLowerCase()})});showOwner()}catch(e){alert(e.message)}
}
async function toggleBan(id,banned){try{await api(banned?`/api/mod/unban/${id}`:`/api/mod/ban/${id}`,{method:"POST"});showOwner()}catch(e){alert(e.message)}}
async function ipBan(id){if(!confirm("IP ban this user?"))return;try{await api(`/api/owner/ip-ban/${id}`,{method:"POST"});showOwner()}catch(e){alert(e.message)}}
async function deleteAccount(id){if(!confirm("PERMANENTLY delete this account?"))return;try{await api(`/api/owner/account/${id}`,{method:"DELETE"});showOwner()}catch(e){alert(e.message)}}

function openModal(content){$("modalContent").innerHTML=content;$("modal").classList.remove("hidden")}
function closeModal(){$("modal").classList.add("hidden")}
$("modal").addEventListener("click",e=>{if(e.target===$("modal"))closeModal()});

function toggleMobileSidebar(){$(".sidebar")?.classList.toggle("mobile-open")}
function closeMobileSidebar(){document.querySelector(".sidebar")?.classList.remove("mobile-open")}
function setMobileActive(id){document.querySelectorAll(".mobile-nav button").forEach(b=>b.classList.remove("active"));$(id)?.classList.add("active")}

function scrollBottom(){requestAnimationFrame(()=>{$("mainContent").scrollTop=$("mainContent").scrollHeight})}
function formatTime(value){try{return new Date(value).toLocaleTimeString([], {hour:"2-digit",minute:"2-digit"})}catch{return ""}}

async function logout() {
  try { if(token) await api("/api/logout",{method:"POST"}); } catch {}
  logoutLocal();
}
function logoutLocal(){
  if(socket){socket.disconnect();socket=null}
  token="";currentUser=null;currentDM=null;
  localStorage.removeItem("spookchat_token");
  $("app").classList.add("hidden");$("authScreen").classList.remove("hidden");
}

if ("Notification" in window && Notification.permission === "default") {
  setTimeout(()=>Notification.requestPermission().catch(()=>{}),3000);
}

if (token) startApp();
else $("authScreen").classList.remove("hidden");
</script>
</body>
</html>"""


@app.get("/")
def index():
    return render_template_string(HTML)


@app.get("/health")
def health():
    return jsonify(status="ok", app=APP_NAME)


init_database()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    socketio.run(app, host="0.0.0.0", port=port, allow_unsafe_werkzeug=True)
