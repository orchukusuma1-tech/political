
import streamlit as st
import sqlite3, os, io, smtplib, traceback
from datetime import datetime, timedelta
from passlib.hash import bcrypt
import pandas as pd
from collections import Counter
import base64
import tempfile
import mimetypes
import json

# -----------------------------
# Configuration & helpers
# -----------------------------
DB_PATH = "people_connect.db"
UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Optional SMTP config for OTP (set as env vars for production)
SMTP_HOST = os.environ.get("SMTP_HOST")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587")) if os.environ.get("SMTP_PORT") else None
SMTP_USER = os.environ.get("SMTP_USER")
SMTP_PASS = os.environ.get("SMTP_PASS")
OTP_FROM  = os.environ.get("OTP_FROM", SMTP_USER or "otp@example.com")

# Streamlit page
st.set_page_config(page_title="People Connect (All features)", layout="wide")
st.title("People Connect — Citizens ↔ Politicians (Prototype)")

# -----------------------------
# DB
# -----------------------------
def get_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    return conn

conn = get_conn()
def init_db():
    c = conn.cursor()
    # users: roles = citizen, politician, admin
    c.execute("""CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        email TEXT UNIQUE,
        password BLOB,
        role TEXT,
        region TEXT,
        ward TEXT,
        created_at TEXT
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS issues(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT,
        description TEXT,
        region TEXT,
        ward TEXT,
        priority TEXT,
        location TEXT,
        status TEXT,
        created_by INTEGER,
        created_at TEXT,
        assigned_to INTEGER
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS files(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        issue_id INTEGER,
        filename TEXT,
        filepath TEXT,
        uploaded_at TEXT
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS comments(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        issue_id INTEGER,
        author_id INTEGER,
        body TEXT,
        created_at TEXT,
        private INTEGER DEFAULT 0
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS otps(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT,
        otp TEXT,
        expires_at TEXT
    )""")
    conn.commit()

init_db()

# -----------------------------
# Utility functions
# -----------------------------
def hash_password(pw: str) -> str:
    # returns the hashed password string
    return bcrypt.hash(pw)

def check_password(pw: str, hashed: str) -> bool:
    try:
        return bcrypt.verify(pw, hashed)
    except Exception:
        return False

def send_otp_email(to_email: str, otp: str):
    # If SMTP is configured, send. Otherwise log in Streamlit (for testing).
    msg = f"Your PeopleConnect OTP is: {otp}\nIt expires in 5 minutes."
    if SMTP_HOST and SMTP_PORT and SMTP_USER and SMTP_PASS:
        try:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as s:
                s.starttls()
                s.login(SMTP_USER, SMTP_PASS)
                body = f"From: {OTP_FROM}\nTo: {to_email}\nSubject: PeopleConnect OTP\n\n{msg}"
                s.sendmail(OTP_FROM, [to_email], body)
        except Exception as e:
            st.error("Failed to send OTP email (check SMTP settings). OTP shown below for testing.")
            st.write(msg)
            st.write("SMTP error:", e)
    else:
        st.info("SMTP not configured — printing OTP for testing (set SMTP_* env vars to enable).")
        st.write(msg)

def save_file_streamlit(uploaded_file, issue_id):
    # Save to UPLOAD_DIR with unique name
    ts = datetime.utcnow().strftime("%Y%m%d%H%M%S%f")
    safe_name = uploaded_file.name.replace("/", "_").replace("\\", "_")
    filename = f"{ts}_{safe_name}"
    filepath = os.path.join(UPLOAD_DIR, filename)
    with open(filepath, "wb") as f:
        f.write(uploaded_file.getbuffer())
    c = conn.cursor()
    c.execute("INSERT INTO files(issue_id, filename, filepath, uploaded_at) VALUES (?,?,?,?)",
              (issue_id, uploaded_file.name, filepath, datetime.utcnow().isoformat()))
    conn.commit()
    return filepath

def create_user(name, email, password, role="citizen", region=None, ward=None):
    hashed = hash_password(password)
    c = conn.cursor()
    try:
        c.execute("INSERT INTO users(name,email,password,role,region,ward,created_at) VALUES (?,?,?,?,?,?,?)",
                  (name, email.lower(), hashed, role, region, ward, datetime.utcnow().isoformat()))
        conn.commit()
        return True
    except Exception as e:
        # Optionally log traceback for debugging
        # st.write("Create user error:", e)
        return False

def authenticate(email, password):
    c = conn.cursor()
    c.execute("SELECT id,name,email,password,role,region,ward FROM users WHERE email=?", (email.lower(),))
    row = c.fetchone()
    if row and row[3] is not None and check_password(password, row[3]):
        return {"id": row[0], "name": row[1], "email": row[2], "role": row[4], "region": row[5], "ward": row[6]}
    return None

def get_user_by_email(email):
    c = conn.cursor()
    c.execute("SELECT id,name,email,role,region,ward FROM users WHERE email=?", (email.lower(),))
    r = c.fetchone()
    return r

def create_issue(title, description, region, ward, priority, location, created_by):
    c = conn.cursor()
    c.execute("""INSERT INTO issues(title,description,region,ward,priority,location,status,created_by,created_at,assigned_to)
                 VALUES (?,?,?,?,?,?,?,?,?,?)""",
              (title, description, region, ward, priority, location, "Open", created_by, datetime.utcnow().isoformat(), None))
    conn.commit()
    return c.lastrowid

def list_issues(filters=None, for_user=None):
    """
    filters: dict with keys region, ward, status, priority, assigned_only (bool), q
    for_user: dict of current user (to limit view for politicians if assigned)
    """
    c = conn.cursor()
    base = "SELECT id,title,description,region,ward,priority,location,status,created_by,created_at,assigned_to FROM issues"
    where = []
    params = []
    if filters:
        if filters.get("region"):
            where.append("region=?"); params.append(filters["region"])
        if filters.get("ward"):
            where.append("ward=?"); params.append(filters["ward"])
        if filters.get("status"):
            where.append("status=?"); params.append(filters["status"])
        if filters.get("priority"):
            where.append("priority=?"); params.append(filters["priority"])
        if filters.get("q"):
            where.append("(title LIKE ? OR description LIKE ?)"); params.extend([f"%{filters['q']}%"]*2)
        if filters.get("assigned_only"):
            where.append("assigned_to IS NOT NULL")
    # Politician sees only assigned issues by default; admin sees all; citizen sees own issues
    if for_user:
        if for_user["role"] == "politician" and not (filters and filters.get("show_all_for_politician")):
            where.append("(assigned_to=? OR created_by=?)"); params.extend([for_user["id"], for_user["id"]])
        elif for_user["role"] == "citizen":
            where.append("created_by=?"); params.append(for_user["id"])
        # admin sees all
    q = base + (" WHERE " + " AND ".join(where) if where else "") + " ORDER BY id DESC"
    c.execute(q, tuple(params) if params else ())
    return c.fetchall()

def assign_issue(issue_id, politician_id):
    c = conn.cursor()
    c.execute("UPDATE issues SET assigned_to=? WHERE id=?", (politician_id, issue_id))
    conn.commit()

def update_issue_status(issue_id, status):
    c = conn.cursor()
    c.execute("UPDATE issues SET status=? WHERE id=?", (status, issue_id))
    conn.commit()

def add_comment(issue_id, author_id, body, private=False):
    c = conn.cursor()
    c.execute("INSERT INTO comments(issue_id, author_id, body, created_at, private) VALUES (?,?,?,?,?)",
              (issue_id, author_id, body, datetime.utcnow().isoformat(), 1 if private else 0))
    conn.commit()

def get_comments(issue_id, for_user=None):
    c = conn.cursor()
    # If for_user is politician or admin show all; if citizen hide private comments not by them
    if for_user and for_user.get("role") in ("politician","admin"):
        c.execute("""SELECT comments.id,comments.body,users.name,comments.created_at,comments.private,users.id 
                     FROM comments JOIN users ON comments.author_id = users.id WHERE issue_id=? ORDER BY id""", (issue_id,))
    elif for_user:
        # show only non-private comments or comments authored by this user
        c.execute("""SELECT comments.id,comments.body,users.name,comments.created_at,comments.private,users.id 
                     FROM comments JOIN users ON comments.author_id = users.id 
                     WHERE issue_id=? AND (private=0 OR comments.author_id=?) ORDER BY id""",
                  (issue_id, for_user["id"]))
    else:
        c.execute("""SELECT comments.id,comments.body,users.name,comments.created_at,comments.private,users.id 
                     FROM comments JOIN users ON comments.author_id = users.id WHERE issue_id=? AND private=0 ORDER BY id""", (issue_id,))
    return c.fetchall()

def get_files_for_issue(issue_id):
    c = conn.cursor()
    c.execute("SELECT id,filename,filepath,uploaded_at FROM files WHERE issue_id=?", (issue_id,))
    return c.fetchall()

# OTP functions
def create_and_send_otp(email):
    otp = str(int.from_bytes(os.urandom(3), "big") % 1000000).zfill(6)
    expires_at = (datetime.utcnow() + timedelta(minutes=5)).isoformat()
    c = conn.cursor()
    c.execute("INSERT INTO otps(email,otp,expires_at) VALUES (?,?,?)", (email.lower(), otp, expires_at))
    conn.commit()
    send_otp_email(email, otp)
    return otp

def verify_otp(email, otp):
    c = conn.cursor()
    c.execute("SELECT id,otp,expires_at FROM otps WHERE email=? ORDER BY id DESC LIMIT 1", (email.lower(),))
    r = c.fetchone()
    if not r:
        return False
    stored_otp = r[1]
    expires = datetime.fromisoformat(r[2])
    if datetime.utcnow() > expires:
        return False
    return str(otp).strip() == stored_otp

# -----------------------------
# Session & Auth UI
# -----------------------------
if "user" not in st.session_state:
    st.session_state.user = None
if "last_refresh" not in st.session_state:
    st.session_state.last_refresh = datetime.utcnow().isoformat()

def logout():
    st.session_state.user = None
    st.experimental_rerun()

# Simple left column for login/register when not logged in
if not st.session_state.user:
    st.sidebar.header("Sign in / Register")
    mode = st.sidebar.selectbox("Mode", ["Login", "Register", "Login with OTP"])
    if mode == "Register":
        with st.sidebar.form("reg"):
            st.write("Create a new account")
            name = st.text_input("Full name", key="reg_name")
            email = st.text_input("Email", key="reg_email")
            pw = st.text_input("Password", type="password", key="reg_pw")
            role = st.selectbox("Role", ["citizen", "politician"], key="reg_role")
            region = st.text_input("Region", key="reg_region")
            ward = st.text_input("Ward", key="reg_ward")
            if st.form_submit_button("Create account"):
                ok = create_user(name, email, pw, role, region or None, ward or None)
                if ok:
                    st.success("Account created. Please log in.")
                else:
                    st.error("Unable to create account — email may already exist.")
    elif mode == "Login":
        with st.sidebar.form("login"):
            st.write("Email + Password")
            email = st.text_input("Email", key="login_email")
            pw = st.text_input("Password", key="login_pw", type="password")
            if st.form_submit_button("Login"):
                u = authenticate(email, pw)
                if u:
                    st.session_state.user = u
                    st.success(f"Welcome back, {u['name']}!")
                    st.experimental_rerun()
                else:
                    st.error("Invalid credentials.")
    else:
        # OTP flow
        with st.sidebar.form("otp"):
            st.write("Login with One-Time Password (OTP)")
            email_otp = st.text_input("Email for OTP", key="otp_email")
            col1, col2 = st.columns(2)
            with col1:
                if st.form_submit_button("Send OTP"):
                    if email_otp:
                        create_and_send_otp(email_otp)
                        st.success("OTP sent (check SMTP or app output).")
            with col2:
                otp_input = st.text_input("Enter OTP", key="otp_code")
                if st.form_submit_button("Verify OTP"):
                    if verify_otp(email_otp, otp_input):
                        # create or fetch user automatically as citizen (convenience)
                        urow = get_user_by_email(email_otp)
                        if not urow:
                            # create a minimal account
                            create_user("Anonymous", email_otp, "temporary-password", role="citizen")
                        urow = get_user_by_email(email_otp)
                        st.session_state.user = {"id": urow[0], "name": urow[1], "email": urow[2], "role": urow[3], "region": urow[4], "ward": urow[5]}
                        st.success("Logged in via OTP.")
                        st.experimental_rerun()
                    else:
                        st.error("Invalid or expired OTP.")

    st.sidebar.write("---")
    st.sidebar.write("Demo notes: Admin user can be created by registering then editing the DB role to 'admin' or create via register and then run the SQL in a sqlite client to set role='admin' for your email.")
    st.stop()

# -----------------------------
# Main app (logged in)
# -----------------------------
user = st.session_state.user
st.sidebar.write(f"Logged in: **{user['name']}** ({user['role']})")
if st.sidebar.button("Logout"):
    logout()

st.sidebar.markdown("---")
st.sidebar.header("Filters")
regions = [r[0] for r in conn.execute("SELECT DISTINCT region FROM issues WHERE region IS NOT NULL").fetchall() if r[0]]
wards = [r[0] for r in conn.execute("SELECT DISTINCT ward FROM issues WHERE ward IS NOT NULL").fetchall() if r[0]]
status_options = ["Open","In Progress","Resolved"]
priority_options = ["Low","Medium","High"]

f_region = st.sidebar.selectbox("Region (filter)", [""] + regions, key="f_region")
f_ward = st.sidebar.selectbox("Ward (filter)", [""] + wards, key="f_ward")
f_status = st.sidebar.selectbox("Status (filter)", [""] + status_options, key="f_status")
f_priority = st.sidebar.selectbox("Priority (filter)", [""] + priority_options, key="f_priority")
f_q = st.sidebar.text_input("Search text", key="f_q")
f_assigned_only = st.sidebar.checkbox("Assigned only", key="f_assigned")

st.sidebar.markdown("---")
if user["role"] == "admin":
    st.sidebar.markdown("**Admin controls**")
    if st.sidebar.button("Create sample admin account"):
        # create admin quickly for demo (will fail silently if exists)
        create_user("Admin", "admin@example.com", "adminpass", "admin")
        st.sidebar.success("Admin created (admin@example.com / adminpass).")
st.sidebar.markdown("---")
# -----------------------------
# Layout: Two columns (left: listing, right: details / new issue / dashboard)
# -----------------------------
left, right = st.columns([2, 1])

with left:
    st.header("Issues")
    filters = {}
    if f_region: filters["region"] = f_region
    if f_ward: filters["ward"] = f_ward
    if f_status: filters["status"] = f_status
    if f_priority: filters["priority"] = f_priority
    if f_q: filters["q"] = f_q
    if f_assigned_only: filters["assigned_only"] = True
    # allow politician to show all issues if they want checkbox
    if user["role"] == "politician":
        show_all_politician = st.checkbox("Politician: show all issues (not only assigned)", key="show_all_politician")
        if show_all_politician:
            filters["show_all_for_politician"] = True

    issues = list_issues(filters=filters or None, for_user=user)
    if not issues:
        st.info("No issues found with current filters.")
    else:
        # Sort by priority first (High -> Low) then id desc (newer first)
        priority_rank = {"High": 0, "Medium": 1, "Low": 2}
        issues_sorted = sorted(issues, key=lambda r: (priority_rank.get(r[5] or "Medium"), -int(r[0])))
        for issue in issues_sorted:
            (iid, title, desc, region, ward, priority, location, status, created_by, created_at, assigned_to) = issue
            # load creator name safely
            c = conn.cursor()
            c.execute("SELECT name FROM users WHERE id=?", (created_by,))
            creator_row = c.fetchone()
            creator_name = creator_row[0] if creator_row else "Unknown"
            # card-like display
            st.markdown("---")
            cols = st.columns([0.9, 2.5, 1.2, 0.6])
            with cols[0]:
                st.write(f"**#{iid} {title}**")
                st.write(f"_{region or '—'} / {ward or '—'}")
                st.write(f"Priority: **{priority or 'Medium'}**")
            with cols[1]:
                st.write(desc if len(desc) < 300 else desc[:300] + "...")
                st.write(f"Location: {location or '—'}")
                # files
                files = get_files_for_issue(iid)
                if files:
                    for fid, fname, fpath, futc in files:
                        try:
                            with open(fpath, "rb") as f:
                                data = f.read()
                                b64 = base64.b64encode(data).decode()
                                href = f'<a href="data:application/octet-stream;base64,{b64}" download="{fname}">Download {fname}</a>'
                                st.markdown(href, unsafe_allow_html=True)
                        except Exception:
                            st.write("File unavailable")
            with cols[2]:
                st.write(f"Status: **{status}**")
                st.write(f"By: {creator_name}")
                st.write(f"Date: {created_at.split('T')[0] if created_at else '—'}")
                # assignment info
                if assigned_to:
                    c.execute("SELECT name FROM users WHERE id=?", (assigned_to,))
                    an = c.fetchone()
                    assigned_name = an[0] if an else "—"
                    st.write(f"Assigned: {assigned_name}")
                else:
                    st.write("Assigned: —")
            with cols[3]:
                if st.button("Open", key=f"open_{iid}"):
                    st.session_state["open_issue"] = iid
                    st.experimental_rerun()

with right:
    st.header("Actions / New Issue")
    if st.button("Refresh list"):
        st.experimental_rerun()

    # New Issue form
    with st.form("new_issue"):
        st.subheader("Report a new problem")
        n_title = st.text_input("Title", key="n_title")
        n_desc = st.text_area("Description", key="n_desc")
        n_region = st.text_input("Region", value=user.get("region") or "", key="n_region")
        n_ward = st.text_input("Ward", value=user.get("ward") or "", key="n_ward")
        n_priority = st.selectbox("Priority", priority_options, index=1, key="n_priority")
        n_location = st.text_input("Location (optional)", key="n_location")
        n_files = st.file_uploader("Attach files (images, docs)", accept_multiple_files=True, key="n_files")
        if st.form_submit_button("Submit Issue"):
            if not n_title.strip() or not n_desc.strip():
                st.error("Title and description required.")
            else:
                issue_id = create_issue(n_title.strip(), n_desc.strip(), n_region or None, n_ward or None, n_priority, n_location or None, user["id"])
                if n_files:
                    for f in n_files:
                        try:
                            save_file_streamlit(f, issue_id)
                        except Exception as e:
                            st.warning("Failed saving an uploaded file: " + str(e))
                st.success(f"Issue #{issue_id} created.")
                st.experimental_rerun()

    st.markdown("---")
    # Admin dashboard
    if user["role"] == "admin":
        st.header("Admin Dashboard")
        # quick metrics
        df_issues = pd.read_sql_query("SELECT id,priority,status,region,ward,created_at FROM issues", conn)
        total = len(df_issues)
        by_status = df_issues['status'].value_counts().to_dict() if not df_issues.empty else {}
        by_priority = df_issues['priority'].value_counts().to_dict() if not df_issues.empty else {}
        st.metric("Total issues", total)
        st.write("By status")
        st.bar_chart(pd.Series(by_status))
        st.write("By priority")
        st.bar_chart(pd.Series(by_priority))
        # list users & quick promote to politician/admin
        st.write("---")
        st.subheader("Users")
        users_df = pd.read_sql_query("SELECT id,name,email,role,region,ward,created_at FROM users", conn)
        st.dataframe(users_df)
        st.write("Assign role to user (by email)")
        with st.form("assign_role"):
            ae = st.text_input("User email")
            newrole = st.selectbox("Role", ["citizen","politician","admin"])
            if st.form_submit_button("Update role"):
                c = conn.cursor()
                c.execute("UPDATE users SET role=? WHERE email=?", (newrole, ae.lower()))
                conn.commit()
                st.success("Updated")
                st.experimental_rerun()

# -----------------------------
# Issue detail view (if selected)
# -----------------------------
if "open_issue" in st.session_state:
    iid = st.session_state["open_issue"]
    c = conn.cursor()
    c.execute("SELECT id,title,description,region,ward,priority,location,status,created_by,created_at,assigned_to FROM issues WHERE id=?", (iid,))
    row = c.fetchone()
    if not row:
        st.error("Issue not found.")
    else:
        st.markdown("---")
        st.header(f"Issue #{row[0]}: {row[1]}")
        st.write("**Status:**", row[7], " | **Priority:**", row[5])
        st.write("**Region / Ward:**", row[3] or "-", "/", row[4] or "-")
        st.write("**Location:**", row[6] or "-")
        st.write("**Description:**")
        st.write(row[2])
        # files
        files = get_files_for_issue(iid)
        if files:
            st.subheader("Files")
            for fid,fname,fpath,fut in files:
                try:
                    with open(fpath, "rb") as f:
                        st.download_button(f"Download {fname}", data=f.read(), file_name=fname)
                except Exception:
                    st.write("Unavailable:", fname)
        st.write("---")
        # Assignment & status (politician & admin)
        if user["role"] in ("politician","admin"):
            st.subheader("Manage")
            # assign
            all_pols = conn.execute("SELECT id,name,email FROM users WHERE role='politician'").fetchall()
            pol_map = {str(r[0]): f"{r[1]} ({r[2]})" for r in all_pols}
            assigned_to = row[10]
            options = [""] + list(pol_map.keys())
            sel = st.selectbox("Assign to politician", options, index=0 if not assigned_to else (options.index(str(assigned_to)) if str(assigned_to) in options else 0))
            if st.button("Save assignment"):
                if sel:
                    assign_issue(iid, int(sel))
                    st.success("Assigned.")
                    st.experimental_rerun()
            # status update
            new_status = st.selectbox("Update status", status_options, index=status_options.index(row[7]) if row[7] in status_options else 0)
            if st.button("Save status", key=f"status_save_{iid}"):
                update_issue_status(iid, new_status)
                st.success("Status updated.")
                st.experimental_rerun()
        # Comments (chat-style)
        st.subheader("Comments / Chat")
        comments = get_comments(iid, for_user=user)
        for cid, body, author_name, created_at, private, author_id in comments:
            if private:
                st.info(f"(Private) **{author_name}** — {created_at}\n\n{body}")
            else:
                st.write(f"**{author_name}** — {created_at}")
                st.write(body)
        st.write("---")
        with st.form(f"comment_form_{iid}"):
            c_body = st.text_area("Add a comment")
            c_private = st.checkbox("Private (politicians/admin only)", value=False) if user["role"] in ("politician","admin") else False
            if st.form_submit_button("Post comment"):
                if not c_body.strip():
                    st.error("Cannot post empty comment.")
                else:
                    if c_private and user["role"] not in ("politician","admin"):
                        st.error("Only politicians/admins can post private comments.")
                    else:
                        add_comment(iid, user["id"], c_body.strip(), private=c_private)
                        st.success("Comment added.")
                        st.experimental_rerun()
        if st.button("Close issue view"):
            del st.session_state["open_issue"]
            st.experimental_rerun()

# -----------------------------
# Bottom: quick stats for any user
# -----------------------------
st.sidebar.markdown("---")
st.sidebar.header("Quick Stats")
ct = conn.cursor()
ct.execute("SELECT COUNT(*) FROM issues")
total_issues = ct.fetchone()[0]
ct.execute("SELECT COUNT(*) FROM issues WHERE status='Resolved'")
resolved = ct.fetchone()[0]
st.sidebar.metric("Total issues", total_issues)
st.sidebar.metric("Resolved", resolved)

# End of file
