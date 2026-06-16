import hashlib
import hmac
import os
import re
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

import streamlit as st

st.set_page_config(
    page_title="DKE Chapter Dashboard",
    page_icon="🛡️",
    layout="wide",
)

DB_PATH = Path(__file__).parent / "dke.db"

USERS_TABLE_SQL = """
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL,
        position TEXT,
        access_status TEXT NOT NULL DEFAULT 'active'
    )
"""

TASKS_TABLE_SQL = """
    CREATE TABLE IF NOT EXISTS tasks (
        id INTEGER PRIMARY KEY,
        title TEXT NOT NULL,
        description TEXT,
        assigned_role TEXT,
        assigned_user_id INTEGER,
        due_date TEXT,
        status TEXT NOT NULL DEFAULT 'todo',
        created_by INTEGER,
        created_at TEXT NOT NULL,
        FOREIGN KEY (assigned_user_id) REFERENCES users (id)
    )
"""

EBOARD_ROLES = [
    "President",
    "Vice President",
    "VP Finance",
    "VP Health and Safety",
    "VP Administration",
    "VP Member Development",
    "VP Recruitment",
]

EBOARD_ROLE_ALIASES = {
    "Vice President": ["Vice President", "Executive Vice President"],
}

AUXILIARY_ROLES = [
    "Philanthropy Chairman",
    "Brotherhood Chairman",
    "Alumni Chairman",
    "Social Chairman",
]

JBOARD_ROLES = ["J-Board"]

ALL_ROLES = ["Brother"] + EBOARD_ROLES + AUXILIARY_ROLES + JBOARD_ROLES


def _turso_config():
    try:
        cfg = st.secrets.get("turso", {})
        url = (cfg.get("database_url") or "").strip()
        token = (cfg.get("auth_token") or "").strip()
        if url and token:
            return url, token
    except Exception:
        pass
    return None, None


def _use_shared_db():
    return _turso_config()[0] is not None


def _likely_streamlit_cloud():
    return os.environ.get("STREAMLIT_RUNTIME_ENVIRONMENT") == "cloud"


def _open_connection():
    turso_url, turso_token = _turso_config()
    if turso_url and turso_token:
        import libsql_experimental as libsql

        return libsql.connect(turso_url, auth_token=turso_token)

    conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def _prepare_connection(conn):
    if not isinstance(conn, sqlite3.Connection):
        return conn
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
    except Exception:
        pass
    return conn


def _row_to_mapping(row, cursor=None):
    if row is None:
        return None
    if isinstance(row, sqlite3.Row):
        return row
    if hasattr(row, "keys"):
        return row
    if cursor is not None and cursor.description:
        columns = [col[0] for col in cursor.description]
        return {columns[i]: row[i] for i in range(len(columns))}
    return row


def _fetchone(cursor):
    return _row_to_mapping(cursor.fetchone(), cursor)


def _fetchall(cursor):
    rows = cursor.fetchall()
    if not rows:
        return []
    if isinstance(rows[0], sqlite3.Row) or hasattr(rows[0], "keys"):
        return rows
    columns = [col[0] for col in cursor.description]
    return [{columns[i]: row[i] for i in range(len(columns))} for row in rows]


def migrate_local_sqlite_to_shared_if_needed(conn):
    if not _use_shared_db() or not DB_PATH.exists():
        return

    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] > 0:
        return

    local = sqlite3.connect(DB_PATH)
    local.row_factory = sqlite3.Row
    try:
        local_users = local.execute("SELECT * FROM users").fetchall()
        local_tasks = local.execute("SELECT * FROM tasks").fetchall()
    finally:
        local.close()

    for user in local_users:
        cursor.execute(
            "INSERT OR IGNORE INTO users (id, name, email, password, role, position, access_status) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                user["id"],
                user["name"],
                user["email"],
                user["password"],
                user["role"],
                user["position"],
                user["access_status"],
            ),
        )

    for task in local_tasks:
        cursor.execute(
            """
            INSERT OR IGNORE INTO tasks (
                id, title, description, assigned_role, assigned_user_id,
                due_date, status, created_by, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                task["id"],
                task["title"],
                task["description"],
                task["assigned_role"],
                task["assigned_user_id"],
                task["due_date"],
                task["status"],
                task["created_by"],
                task["created_at"],
            ),
        )


@contextmanager
def get_db():
    conn = _prepare_connection(_open_connection())
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(USERS_TABLE_SQL)
        cursor.execute(TASKS_TABLE_SQL)

        cursor.execute("PRAGMA table_info(tasks)")
        existing_columns = [row[1] for row in cursor.fetchall()]
        if "due_date" not in existing_columns:
            cursor.execute("ALTER TABLE tasks ADD COLUMN due_date TEXT")

        migrate_local_sqlite_to_shared_if_needed(conn)
        seed_defaults(conn)


PBKDF2_ITERATIONS = 180_000
PBKDF2_DIGEST = "sha256"


def hash_password(password: str) -> str:
    salt = os.urandom(16).hex()
    digest = hashlib.pbkdf2_hmac(
        PBKDF2_DIGEST,
        password.encode("utf-8"),
        bytes.fromhex(salt),
        PBKDF2_ITERATIONS,
    )
    return f"{salt}${digest.hex()}"


def verify_password(password: str, stored_password: str) -> bool:
    if "$" not in stored_password:
        return hmac.compare_digest(
            stored_password,
            hashlib.sha256(password.encode("utf-8")).hexdigest(),
        )

    salt, digest = stored_password.split("$", 1)
    computed = hashlib.pbkdf2_hmac(
        PBKDF2_DIGEST,
        password.encode("utf-8"),
        bytes.fromhex(salt),
        PBKDF2_ITERATIONS,
    )
    return hmac.compare_digest(computed.hex(), digest)


def seed_defaults(conn):
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] > 0:
        return

    # No default users or accounts are seeded automatically.
    conn.commit()


def format_username(name: str, position: str) -> str:
    name = (name or "").strip().lower()
    position = (position or "").strip().lower()
    if not name or not position or position == "select a position":
        return ""
    position_slug = re.sub(r"[^a-z0-9]+", "_", position).strip("_")
    name_slug = re.sub(r"[^a-z0-9]+", "_", name).strip("_")
    suggested = f"{position_slug}_{name_slug}"
    return suggested


def get_user_by_username(username):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = ?", (username.strip().lower(),))
        return _fetchone(cursor)


def get_user_by_id(user_id):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        return _fetchone(cursor)


def get_users():
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users ORDER BY role, name")
        return _fetchall(cursor)


def get_tasks():
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT tasks.*, users.name AS assigned_user_name
            FROM tasks
            LEFT JOIN users ON users.id = tasks.assigned_user_id
            ORDER BY tasks.status, tasks.created_at
            """
        )
        return _fetchall(cursor)


def resolve_assigned_user_name(task, users):
    if task["assigned_user_name"]:
        return task["assigned_user_name"]
    if task["assigned_user_id"] is None:
        return None
    for u in users:
        if u["id"] == task["assigned_user_id"] or str(u["id"]) == str(task["assigned_user_id"]):
            return u["name"]
    return None


def user_matches_assigned_role(user, assigned_role):
    aliases = EBOARD_ROLE_ALIASES.get(assigned_role, [assigned_role])
    return (
        user["role"] in aliases
        or (user["position"] and user["position"] in aliases)
        or (assigned_role == "Brother" and user["role"] == "Brother")
    )


def task_applies_to_user(task, user):
    if task["assigned_user_id"] is not None:
        return task["assigned_user_id"] == user["id"] or str(task["assigned_user_id"]) == str(user["id"])
    if task["assigned_role"]:
        return user_matches_assigned_role(user, task["assigned_role"])
    return True


def tasks_for_user(tasks, user):
    if user["role"] == "President":
        return list(tasks)
    return [task for task in tasks if task_applies_to_user(task, user)]


def add_task(title, assigned_role, assigned_user_id, due_date, created_by):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO tasks (title, assigned_role, assigned_user_id, due_date, status, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (title.strip(), assigned_role, assigned_user_id, due_date, "todo", created_by, datetime.utcnow().isoformat()),
        )
        return cursor.lastrowid


def update_task_status(task_id, status):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE tasks SET status = ? WHERE id = ?", (status, task_id))


def delete_task(task_id):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM tasks WHERE id = ?", (task_id,))


def update_user_access(user_id, access_status):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET access_status = ? WHERE id = ?", (access_status, user_id))


def update_user_position(user_id, position):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET position = ? WHERE id = ?", (position, user_id))


def user_exists(username):
    return get_user_by_username(username) is not None


def create_user(name, username, password, role, position, access_status="pending"):
    if user_exists(username):
        return False
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (name, email, password, role, position, access_status) VALUES (?, ?, ?, ?, ?, ?)",
                (name.strip(), username.strip().lower(), hash_password(password), role, position, access_status),
            )
        return True
    except sqlite3.IntegrityError:
        return False
    except Exception:
        return False


def president_exists():
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users WHERE role = ?", ("President",))
        return cursor.fetchone()[0] > 0


def update_user_account(user_id, name, username, role, position, access_status):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET name = ?, email = ?, role = ?, position = ?, access_status = ? WHERE id = ?",
            (name.strip(), username.strip().lower(), role, position, access_status, user_id),
        )


def reset_user_password(user_id, password):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET password = ? WHERE id = ?",
            (hash_password(password), user_id),
        )


def transfer_position(current_user_id, new_user_id):
    current = get_user_by_id(current_user_id)
    new_user = get_user_by_id(new_user_id)
    if not current or not new_user:
        return False

    old_role = current["role"]
    old_position = current["position"]
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET role = ?, position = ? WHERE id = ?",
            ("Brother", None, current_user_id),
        )
        cursor.execute(
            "UPDATE users SET role = ?, position = ? WHERE id = ?",
            (old_role, old_position, new_user_id),
        )
    return True


def authenticate(username, password):
    user = get_user_by_username(username)
    if not user:
        return None
    if not verify_password(password, user["password"]):
        return None
    if user["access_status"] != "active":
        return None
    return user


def app_header():
    st.title("Delta Kappa Epsilon Chapter Dashboard")
    st.write("Friends From the Heart Forever")


def login_header():
    st.markdown(
        """
        <style>
        .login-container {
            padding: 1.75rem;
            border-radius: 1.5rem;
            background: linear-gradient(135deg, #0d3b7f 0%, #c99700 45%, #8b0000 100%);
            color: white;
            text-align: center;
            margin-bottom: 1.25rem;
        }
        .login-title {
            font-size: 2.4rem;
            font-weight: 900;
            margin: 0.25rem 0;
            letter-spacing: 0.12rem;
        }
        .login-subtitle {
            font-size: 1.1rem;
            opacity: 0.92;
            margin-bottom: 1.1rem;
        }
        .logo-circle {
            margin: 0 auto 1rem auto;
            width: 120px;
            height: 120px;
            border-radius: 50%;
            background: rgba(255,255,255,0.2);
            border: 2px solid rgba(255,255,255,0.8);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 2.8rem;
            font-weight: 900;
            color: white;
            box-shadow: 0 18px 36px rgba(0,0,0,0.25);
        }
        .login-note {
            font-size: 0.95rem;
            margin-top: 0.75rem;
            color: rgba(255,255,255,0.95);
        }
        </style>
        <div class="login-container">
            <div class="logo-circle">ΔΚΕ</div>
            <div class="login-title">Delta Kappa Epsilon</div>
            <div class="login-subtitle">Kappa Chi Chapter Login</div>
            <div class="login-note">No usernames or passwords are stored by this app. Use your browser or device passkey manager to save credentials securely if you choose.</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def inject_theme_styles():
    st.markdown(
        """
        <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');
        html, body {
            font-family: 'Inter', sans-serif !important;
            background: linear-gradient(135deg, #0c2b6f 0%, #1760b0 45%, #720000 100%) !important;
        }
        [data-testid="stAppViewContainer"] {
            background: #000000 !important;
            color: #ffffff !important;
        }
        [data-testid="stAppViewContainer"] .main,
        .block-container,
        .css-18e3th9.e16nr0p30 {
            background: #000000 !important;
            color: #ffffff !important;
        }
        [data-testid="stSidebar"] {
            background: linear-gradient(180deg, #071f4a 0%, #0d3b7f 65%, #500000 100%) !important;
            color: #f8e7b2 !important;
        }
        [data-testid="stSidebar"] .css-1d391kg,
        [data-testid="stSidebar"] .css-1v0mb1 {
            color: #f8e7b2 !important;
        }
        .stButton>button {
            background-color: #c99700 !important;
            color: #071f4a !important;
            border-radius: 14px !important;
            border: 1px solid rgba(13, 59, 127, 0.9) !important;
            box-shadow: 0 12px 24px rgba(13, 59, 127, 0.18) !important;
        }
        .stButton>button:hover {
            background-color: #e0b542 !important;
            color: #071f4a !important;
        }
        input, textarea, select,
        .stTextInput>div>input,
        .stTextInput>div>textarea {
            border-radius: 12px !important;
            border: 1px solid rgba(255,255,255,0.18) !important;
            background: rgba(20,20,20,0.95) !important;
            color: #ffffff !important;
        }
        input::placeholder,
        textarea::placeholder {
            color: rgba(255,255,255,0.65) !important;
            opacity: 1 !important;
        }
        .stTextInput>label,
        .stSelectbox>label,
        .stTextArea>label {
            color: #ffffff !important;
        }
        .stExpanderHeader {
            border-radius: 18px !important;
            background: rgba(201,151,0,0.12) !important;
        }
        .app-header {
            border-radius: 24px;
            padding: 1.6rem 1.8rem;
            background: linear-gradient(135deg, rgba(13,59,127,0.98), rgba(201,151,0,0.95), rgba(139,0,0,0.9));
            color: white;
            box-shadow: 0 24px 60px rgba(13, 59, 127, 0.22);
            margin-bottom: 1.5rem;
        }
        .app-header h1 {
            margin: 0;
            font-size: 2.5rem;
            letter-spacing: 0.08rem;
        }
        .app-header p {
            margin: 0.35rem 0 0;
            opacity: 0.92;
            font-size: 1rem;
        }
        .app-pill-row {
            margin-top: 1rem;
        }
        .app-pill {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            padding: 0.55rem 1rem;
            border-radius: 999px;
            margin-right: 0.7rem;
            font-weight: 700;
            letter-spacing: 0.04rem;
            color: #061c3d;
        }
        .pill-blue { background: #4d7bd1; }
        .pill-gold { background: #f0b429; }
        .task-badge {
            display: inline-block;
            background: rgba(201,151,0,0.8);
            color: #071f4a;
            padding: 0.3rem 0.65rem;
            border-radius: 8px;
            font-size: 0.85rem;
            font-weight: 600;
            margin-left: 0.5rem;
            vertical-align: middle;
        }
        .task-badge-unassigned {
            background: rgba(200,200,200,0.5);
            color: #ffffff;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def app_header():
    st.markdown(
        """
        <div class="app-header">
            <h1>Delta Kappa Epsilon Chapter Dashboard</h1>
            <p>Friends From the Heart Forever</p>
            <div class="app-pill-row">
                <span class="app-pill pill-blue">Gentlemen</span>
                <span class="app-pill pill-gold">Scholars</span>
                <span class="app-pill pill-crimson">Jolly Good Fellows</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def login_page():
    login_header()
    st.session_state.pop("remembered_username", None)
    if not president_exists():
        st.warning("No President account exists yet. Create the first President account below. There is no default President login.")
        with st.form("create_president_form"):
            name = st.text_input("President name")
            suggested_username = format_username(name, "President")
            username = st.text_input("President username", placeholder=suggested_username)
            password = st.text_input("Password", type="password")
            submitted = st.form_submit_button("Create President account")
            if submitted:
                if not name or not username or not password:
                    st.error("Name, username, and password are required.")
                elif user_exists(username):
                    st.error("An account with this username already exists.")
                else:
                    created = create_user(name, username, password, "President", "President", access_status="active")
                    if created:
                        st.success("President account created. Please sign in.")
                        st.rerun()
                    else:
                        st.error("Could not create president account. Please try again.")
        return

    mode = st.radio("Choose action", ["Login", "Create account", "Reset credentials"])

    if mode == "Login":
        active_users = [u["email"] for u in get_users() if u["access_status"] == "active"]
        if not active_users:
            st.warning("No active user accounts are available to sign in yet.")
        username = st.selectbox("Username", ["Select your username"] + active_users)
        password = st.text_input("Password", type="password")
        if st.button("Sign In"):
            if username == "Select your username":
                st.error("Select your username from the list.")
            else:
                user = authenticate(username, password)
                if user:
                    st.session_state["current_user"] = dict(user)
                    st.success(f"Welcome, {user['name']}!")
                    st.rerun()
                else:
                    st.error("Invalid credentials or your account is disabled.")

    if mode == "Create account":
        st.info("New account requests are created with pending access and require President approval.")
        with st.form("create_account_form"):
            name = st.text_input("Name")

            position_options = [
                "Select a position",
                "President",
                "Vice President",
                "VP Finance",
                "VP Health and Safety",
                "VP Administration",
                "VP Member Development",
                "VP Recruitment",
                "Philanthropy Chairman",
                "Social Chairman",
                "Alumni Chairman",
                "Brotherhood Chairman",
                "J-Board",
            ]
            position = st.selectbox("Position", position_options)

            username_suggestion = format_username(name, position)
            username = st.text_input("Username", placeholder=username_suggestion)
            if username_suggestion:
                st.caption(f"Suggested username: {username_suggestion}")
            password = st.text_input("Password", type="password")
            submitted = st.form_submit_button("Request account")
            if submitted:
                if not name or not username or not password or position == "Select a position":
                    st.error("Name, username, password, and position are required.")
                elif user_exists(username):
                    st.error("An account with this username already exists.")
                else:
                    created = create_user(name, username, password, "Brother", position, access_status="pending")
                    if created:
                        st.success("Account request submitted. The President will approve access.")
                    else:
                        # Re-check whether username exists to give a clearer message
                        if user_exists(username):
                            st.error("An account with this username already exists.")
                        else:
                            st.error("Could not create account. Please try a different username or contact the President.")

    if mode == "Reset credentials":
        st.info("Reset a username or password if you cannot log in. This will replace the existing account credentials.")
        users = get_users()
        if not users:
            st.warning("No accounts exist yet. Create the first President account instead.")
        else:
            selected_username = st.selectbox("Username", [u["email"] for u in users])
            new_username = st.text_input("New username (optional)")
            new_password = st.text_input("New password (optional)", type="password")
            confirm_password = st.text_input("Confirm new password", type="password")
            if st.button("Reset account credentials"):
                if not new_username and not new_password:
                    st.error("Enter a new username, password, or both.")
                elif new_password and new_password != confirm_password:
                    st.error("Passwords do not match.")
                else:
                    user_record = next((u for u in users if u["email"] == selected_username), None)
                    if user_record:
                        if new_username and new_username != selected_username:
                            if user_exists(new_username):
                                st.error("That username already exists.")
                                return
                            update_user_account(
                                user_record["id"],
                                user_record["name"],
                                new_username,
                                user_record["role"],
                                user_record["position"],
                                user_record["access_status"],
                            )
                        if new_password:
                            reset_user_password(user_record["id"], new_password)
                        if not new_username and not new_password:
                            st.error("No changes were entered.")
                        else:
                            st.success("Account credentials have been updated. Use the new login information to sign in.")
                            st.rerun()

    st.info("If this is your first time running the app, create the first President account above.")


def logout():
    st.session_state.pop("current_user", None)
    st.rerun()


def sidebar_navigation():
    st.sidebar.title("Navigation")
    st.sidebar.write(f"Signed in as: {st.session_state['current_user']['name']}")
    page = st.sidebar.radio("Go to", ["Home", "Task Board", "Roster", "Admin"])
    if st.sidebar.button("Sign Out"):
        logout()
    return page


def home_page():
    st.header("Home")
    st.markdown(
        "### Welcome to the DKE chapter dashboard.\n"
        "Friends From the Heart Forever."
    )
    user = st.session_state["current_user"]
    tasks = get_tasks()
    my_tasks = tasks_for_user(tasks, user)
    open_tasks = [task for task in tasks if task["status"] != "done"]
    my_open_tasks = [task for task in my_tasks if task["status"] != "done"]
    st.metric("Chapter open tasks", len(open_tasks))
    if user["role"] != "President":
        st.caption(f"{len(my_open_tasks)} assigned to you")

    if my_open_tasks:
        st.subheader("Your current assignments")
        users = get_users()
        for task in my_open_tasks:
            assigned_user_name = resolve_assigned_user_name(task, users)
            assignment = (
                f"Assigned to {assigned_user_name}"
                if assigned_user_name
                else (f"Assigned to {task['assigned_role']}" if task["assigned_role"] else "Chapter-wide")
            )
            due = f" — due {task['due_date']}" if task["due_date"] else ""
            status_label = task["status"].replace("_", " ").title()
            st.write(f"- **{task['title']}** ({status_label}) — {assignment}{due}")
    elif tasks:
        st.info("No open tasks are assigned to you right now. Check the Task Board for all chapter tasks.")
    else:
        st.info("No tasks have been created yet.")

    if user["role"] == "President":
        st.success("You have President access to manage members and tasks.")


def task_list_page():
    st.header("Task Board")
    user = st.session_state["current_user"]
    st.markdown("View all chapter tasks and update their status.")

    if not _use_shared_db() and _likely_streamlit_cloud():
        st.warning(
            "Tasks are not shared across devices until Turso is configured. "
            "Add `[turso]` secrets in Streamlit Cloud (see `.streamlit/secrets.toml.example`)."
        )

    if "show_create_task_form" not in st.session_state:
        st.session_state["show_create_task_form"] = False

    # Create Task Button (President only)
    if user["role"] == "President":
        cols = st.columns([5, 1])
        with cols[1]:
            if st.button("➕ Create Task"):
                st.session_state["show_create_task_form"] = True

    # Create Task Form (President only)
    if user["role"] == "President" and st.session_state["show_create_task_form"]:
        with st.form("create_task_form"):
            title = st.text_input("Task title")
            position_options = ["Any"] + EBOARD_ROLES + AUXILIARY_ROLES + JBOARD_ROLES + ["Brother"]
            assigned_role = st.selectbox("Assign position", position_options)
            if assigned_role == "Any":
                assignable_users = [u["name"] for u in get_users() if u["access_status"] == "active"]
            else:
                aliases = EBOARD_ROLE_ALIASES.get(assigned_role, [assigned_role])
                assignable_users = [
                    u["name"]
                    for u in get_users()
                    if u["access_status"] == "active"
                    and (
                        u["role"] in aliases
                        or u["position"] in aliases
                        or (assigned_role == "Brother" and u["role"] == "Brother")
                    )
                ]
            assigned_user = st.selectbox("Assign person", ["None"] + assignable_users)
            assigned_user_id = None
            if assigned_user != "None":
                selected_user = next((u for u in get_users() if u["name"] == assigned_user), None)
                assigned_user_id = selected_user["id"] if selected_user else None
            due_date = st.text_input("Due date (MM-DD-YYYY)")
            if not due_date:
                due_date = None
            col1, col2 = st.columns([1, 1])
            submit = col1.form_submit_button("Create task")
            cancel = col2.form_submit_button("Cancel")
            if submit:
                valid = True
                if not title:
                    st.error("Task title is required.")
                    valid = False
                elif due_date:
                    try:
                        datetime.strptime(due_date, "%m-%d-%Y")
                    except ValueError:
                        st.error("Due date must be in MM-DD-YYYY format.")
                        valid = False
                if valid:
                    try:
                        task_id = add_task(
                            title,
                            assigned_role if assigned_role != "Any" else None,
                            assigned_user_id,
                            due_date,
                            user["id"],
                        )
                    except Exception as exc:
                        st.error(f"Could not save task to the database: {exc}")
                    else:
                        st.success(f"Task added. ID: {task_id}")
                        st.session_state["show_create_task_form"] = False
                        st.rerun()
            if cancel:
                st.session_state["show_create_task_form"] = False
                st.rerun()

    # Get Tasks — all chapter tasks are visible to every signed-in member.
    tasks = get_tasks()
    if not tasks:
        st.info("No tasks available yet.")
        return

    users = get_users()

    st.subheader("📋 Chapter Task Board")
    
    # Filter into status groups
    status_columns = {
        "todo": "To Do",
        "in_progress": "In Progress",
        "done": "Done",
    }
    
    # Create three columns for Kanban view
    cols = st.columns([1, 1, 1])
    
    for idx, status in enumerate(["todo", "in_progress", "done"]):
        status_tasks = [t for t in tasks if t["status"] == status]
        with cols[idx]:
            st.markdown(f"**{status_columns[status]}** ({len(status_tasks)})")
            st.divider()
            
            if not status_tasks:
                st.info("No tasks")
            else:
                for task in status_tasks:
                    assigned_user_name = resolve_assigned_user_name(task, users)
                    
                    # Task card with assignment info
                    with st.container(border=True):
                        st.write(f"**{task['title']}**")
                        
                        # Show assignment
                        if assigned_user_name:
                            st.caption(f"👤 **Assigned to:** {assigned_user_name}")
                        elif task["assigned_role"]:
                            st.caption(f"📌 **Assigned role:** {task['assigned_role']}")
                        else:
                            st.caption("⚠️ **Not assigned**")
                        
                        # Show due date if exists
                        if task["due_date"]:
                            st.caption(f"📅 **Due:** {task['due_date']}")
                        
                        # Action buttons
                        can_edit = True  # All signed-in users can update shared task status.
                        if can_edit:
                            action_cols = st.columns([1, 1])
                            
                            if status == "todo":
                                if action_cols[0].button("▶️ Start", key=f"move_{task['id']}_in_progress"):
                                    update_task_status(task["id"], "in_progress")
                                    st.rerun()
                            elif status == "in_progress":
                                if action_cols[0].button("✅ Done", key=f"move_{task['id']}_done"):
                                    update_task_status(task["id"], "done")
                                    st.rerun()
                                if action_cols[1].button("↩️ Back", key=f"move_{task['id']}_todo"):
                                    update_task_status(task["id"], "todo")
                                    st.rerun()
                            else:
                                if action_cols[0].button("🔄 Reopen", key=f"move_{task['id']}_todo_done"):
                                    update_task_status(task["id"], "todo")
                                    st.rerun()
                            
                            if user["role"] == "President" and len(action_cols) > 1:
                                if action_cols[1].button("🗑️ Delete", key=f"delete_{task['id']}"):
                                    delete_task(task["id"])
                                    st.success("Task deleted.")
                                    st.rerun()
                            elif user["role"] == "President" and len(action_cols) == 1:
                                if st.button("🗑️ Delete", key=f"delete_{task['id']}"):
                                    delete_task(task["id"])
                                    st.success("Task deleted.")
                                    st.rerun()


def roster_page():
    st.header("Roster")
    users = [u for u in get_users() if u["access_status"] == "active"]
    st.subheader("E-Board")
    for role in EBOARD_ROLES:
        aliases = EBOARD_ROLE_ALIASES.get(role, [role])
        members = [u for u in users if u["role"] in aliases or u["position"] in aliases]
        if members:
            member_names = ", ".join([u["name"] for u in members])
            st.write(f"{role} — {member_names}")
        else:
            st.write(f"{role} — _Vacant_")

    st.subheader("Auxiliary Officers")
    for position in AUXILIARY_ROLES:
        members = [u for u in users if u["position"] == position]
        if members:
            member_names = ", ".join([u["name"] for u in members])
            st.write(f"{position} — {member_names}")
        else:
            st.write(f"{position} — _Vacant_")

    st.subheader("J-Board")
    jboard_members = [u for u in users if u["position"] == "J-Board"]
    if jboard_members:
        member_names = ", ".join([u["name"] for u in jboard_members])
        st.write(f"J-Board — {member_names}")
    else:
        st.write("J-Board — _Vacant_")

    current_user = st.session_state["current_user"]
    if current_user["role"] != "Brother" or current_user["position"]:
        eligible_successors = [
            u for u in users
            if u["id"] != current_user["id"]
            and u["access_status"] == "active"
        ]
        if eligible_successors:
            with st.expander("Transfer your office to a successor"):
                position_label = f" ({current_user['position']})" if current_user['position'] else ""
                st.write(f"You currently hold: **{current_user['role']}**{position_label}")
                successor_name = st.selectbox("Select successor", [u["name"] for u in eligible_successors], key="successor_select")
                if st.button("Transfer office"):
                    successor = next((u for u in eligible_successors if u["name"] == successor_name), None)
                    if successor and transfer_position(current_user["id"], successor["id"]):
                        st.success(f"Role transferred to {successor['name']}.")
                        st.rerun()
        else:
            st.info("No eligible active members are available to succeed your role.")

    if current_user["role"] == "President":
        st.info("As President, you can edit member accounts and positions here.")
        with st.expander("Edit existing account"):
            selected = st.selectbox("Select brother", [u["name"] for u in users])
            user_record = next((u for u in users if u["name"] == selected), None)
            if user_record:
                edit_name = st.text_input("Name", user_record["name"])
                edit_username = st.text_input("Username", user_record["email"])
                edit_role = st.selectbox("Role", ALL_ROLES, index=ALL_ROLES.index(user_record["role"]) if user_record["role"] in ALL_ROLES else 0)
                edit_position = st.selectbox("Position", [""] + EBOARD_ROLES + AUXILIARY_ROLES + JBOARD_ROLES, index=( [""] + EBOARD_ROLES + AUXILIARY_ROLES + JBOARD_ROLES ).index(user_record["position"]) if user_record["position"] in [""] + EBOARD_ROLES + AUXILIARY_ROLES + JBOARD_ROLES else 0)
                edit_status = st.selectbox("Access status", ["active", "disabled"], index=0 if user_record["access_status"] == "active" else 1)
                new_password = st.text_input("Reset password", type="password")
                if st.button("Save account changes"):
                    update_user_account(user_record["id"], edit_name, edit_username, edit_role, edit_position, edit_status)
                    if new_password:
                        reset_user_password(user_record["id"], new_password)
                    st.success(f"Updated account for {edit_name}.")
                    st.rerun()


def admin_page():
    st.header("Admin")
    user = st.session_state["current_user"]
    if user["role"] != "President":
        st.warning("Only the President can access admin controls.")
        return

    users = get_users()
    pending_requests = [u for u in users if u["access_status"] == "pending"]
    if pending_requests:
        st.subheader("Pending account requests")
        for member in pending_requests:
            cols = st.columns([3, 1, 1])
            member_position = member["position"] or "Brother"
            cols[0].write(f"{member['name']} — {member_position} — pending")
            if cols[1].button("Approve", key=f"approve_{member['id']}"):
                update_user_access(member["id"], "active")
                st.success(f"Approved {member['name']}.")
                st.rerun()
            if cols[2].button("Reject", key=f"reject_{member['id']}"):
                update_user_access(member["id"], "disabled")
                st.error(f"Rejected {member['name']}.")
                st.rerun()
    else:
        st.info("No pending account requests.")

    st.subheader("Member access")
    active_disabled_users = [u for u in users if u["access_status"] != "pending"]
    for member in active_disabled_users:
        status = member["access_status"]
        cols = st.columns([3, 1, 1])
        member_position = member["position"] or "Brother"
        cols[0].write(f"{member['name']} — {member_position} — {status}")
        if cols[1].button("Activate", key=f"activate_{member['id']}"):
            update_user_access(member["id"], "active")
            st.success(f"Activated {member['name']}.")
            st.rerun()
        if cols[2].button("Disable", key=f"disable_{member['id']}"):
            update_user_access(member["id"], "disabled")
            st.success(f"Disabled {member['name']}.")
            st.rerun()




def main():
    init_db()
    inject_theme_styles()
    if "current_user" not in st.session_state:
        st.session_state["current_user"] = None

    if not st.session_state["current_user"]:
        login_page()
        return

    app_header()
    page = sidebar_navigation()
    if page == "Home":
        home_page()
    elif page == "Task Board":
        task_list_page()
    elif page == "Roster":
        roster_page()
    elif page == "Admin":
        admin_page()


if __name__ == "__main__":
    main()
