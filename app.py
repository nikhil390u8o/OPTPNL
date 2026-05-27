import os, re, bcrypt, secrets, requests, asyncio, threading, time
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_socketio import SocketIO, join_room, emit
import psycopg2
from datetime import datetime

try:
    from dotenv import load_dotenv
    load_dotenv()
except: pass

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
socketio = SocketIO(app, cors_allowed_origins="*")

# ── Config ────────────────────────────────────────────────
DB_HOST  = os.environ.get("DB_HOST", "")
DB_PORT  = os.environ.get("DB_PORT", "6543")
DB_NAME  = os.environ.get("DB_NAME", "postgres")
DB_USER  = os.environ.get("DB_USER", "")
DB_PASS  = os.environ.get("DB_PASS", "")
API_ID   = int(os.environ.get("API_ID", 0))
API_HASH = os.environ.get("API_HASH", "")
FAMPAY_API_URL = os.environ.get("FAMPAY_API_URL", "")
FAMPAY_API_KEY = os.environ.get("FAMPAY_API_KEY", "")
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")

otp_store = {}  # order_id: otp

# ── DB ────────────────────────────────────────────────────
def get_db():
    return psycopg2.connect(
        host=DB_HOST, port=int(DB_PORT), dbname=DB_NAME,
        user=DB_USER, password=DB_PASS,
        sslmode="require", connect_timeout=15
    )

def db_query(sql, params=(), fetch=None):
    conn = get_db()
    cur  = conn.cursor()
    cur.execute(sql, params)
    result = None
    if fetch == "one":   result = cur.fetchone()
    elif fetch == "all": result = cur.fetchall()
    else: conn.commit()
    cur.close(); conn.close()
    return result

# ── Auth Helpers ──────────────────────────────────────────
def hash_pass(p): return bcrypt.hashpw(p.encode(), bcrypt.gensalt()).decode()
def check_pass(p, h): return bcrypt.checkpw(p.encode(), h.encode())
def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect("/")
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session or not session.get("is_admin"):
            return redirect("/")
        return f(*args, **kwargs)
    return decorated

def get_user(user_id):
    return db_query("SELECT id,username,balance,total_deposited,total_spent,is_admin FROM users WHERE id=%s",
                    (user_id,), fetch="one")

# ── OTP System (Pyrogram) ─────────────────────────────────
def start_otp_listener(order_id, string_session, phone):
    def run():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(_otp_task(order_id, string_session, phone))
    threading.Thread(target=run, daemon=True).start()

async def _otp_task(order_id, string_session, phone):
    try:
        from pyrogram import Client, filters
        client = Client(
            f"otp_{order_id}",
            api_id=API_ID,
            api_hash=API_HASH,
            session_string=string_session,
            in_memory=True
        )
        await client.start()

        @client.on_message(filters.private & filters.incoming)
        async def on_msg(c, m):
            text = m.text or m.caption or ""
            match = re.search(r'\b(\d{5})\b', text)
            if match:
                otp = match.group(1)
                otp_store[str(order_id)] = otp
                db_query("UPDATE orders SET otp=%s WHERE id=%s", (otp, order_id))
                socketio.emit("otp_received", {"otp": otp}, room=str(order_id))
                await client.stop()

        # Wait 5 min
        for _ in range(300):
            await asyncio.sleep(1)
            if str(order_id) in otp_store:
                break

        try: await client.stop()
        except: pass
    except Exception as e:
        print(f"OTP error: {e}")

# ── Routes: Auth ──────────────────────────────────────────
@app.route("/")
def login_page():
    if "user_id" in session:
        return redirect("/dashboard")
    return render_template("login.html")

@app.route("/register", methods=["GET","POST"])
def register_page():
    if request.method == "GET":
        return render_template("register.html")
    data = request.get_json(silent=True) or request.form
    username = str(data.get("username","")).strip().lower()
    password = str(data.get("password","")).strip()
    if not username or not password or len(username) < 3:
        return jsonify({"success": False, "error": "Invalid username/password"}), 400
    existing = db_query("SELECT id FROM users WHERE username=%s", (username,), fetch="one")
    if existing:
        return jsonify({"success": False, "error": "Username already taken"}), 400
    db_query("INSERT INTO users (username, password_hash) VALUES (%s,%s)",
             (username, hash_pass(password)))
    return jsonify({"success": True})

@app.route("/login", methods=["POST"])
def do_login():
    data = request.get_json(silent=True) or request.form
    username = str(data.get("username","")).strip().lower()
    password = str(data.get("password","")).strip()
    user = db_query("SELECT id,password_hash,is_admin FROM users WHERE username=%s",
                    (username,), fetch="one")
    if not user or not check_pass(password, user[1]):
        return jsonify({"success": False, "error": "Wrong username or password"}), 401
    session["user_id"]  = user[0]
    session["username"] = username
    session["is_admin"] = user[2]
    return jsonify({"success": True, "is_admin": user[2]})

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

# ── Routes: Dashboard ─────────────────────────────────────
@app.route("/dashboard")
@login_required
def dashboard():
    user = get_user(session["user_id"])
    return render_template("dashboard.html", user=user)

@app.route("/api/deposit/verify", methods=["POST"])
@login_required
def deposit_verify():
    data       = request.get_json(silent=True)
    utr        = str(data.get("utr","")).strip().upper()
    amount     = data.get("amount")
    pay_type   = data.get("pay_type","")

    if not utr or not amount:
        return jsonify({"success": False, "error": "UTR/TXN ID aur amount required"}), 400
    try: amount = float(amount)
    except: return jsonify({"success": False, "error": "Invalid amount"}), 400

    # Check duplicate in local DB too
    exists = db_query("SELECT 1 FROM used_utrs WHERE utr=%s", (utr,), fetch="one")
    if exists:
        return jsonify({"success": False, "error": "UTR already used! Duplicate payment."})

    try:
        resp = requests.post(f"{FAMPAY_API_URL}/verify",
                             json={"api_key": FAMPAY_API_KEY, "utr": utr, "amount": amount},
                             timeout=60)
        result = resp.json()
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

    if result.get("verified"):
        uid = session["user_id"]
        db_query("UPDATE users SET balance=balance+%s, total_deposited=total_deposited+%s WHERE id=%s",
                 (amount, amount, uid))
        db_query("INSERT INTO used_utrs (user_id, utr, amount) VALUES (%s,%s,%s)",
                 (uid, utr, amount))
        user = get_user(uid)
        return jsonify({"success": True, "verified": True, "balance": float(user[2])})

    if "already used" in str(result.get("error","")).lower():
        return jsonify({"success": False, "error": "UTR already used! Duplicate payment."})

    return jsonify({"success": True, "verified": False,
                    "message": "Payment nahi mila. UTR/TXN ID check karo."})

# ── Routes: Buy ───────────────────────────────────────────
@app.route("/buy")
@login_required
def buy_page():
    user = get_user(session["user_id"])
    countries = db_query("""
        SELECT country, COUNT(*) as cnt, MIN(price) as min_price
        FROM accounts WHERE is_sold=FALSE
        GROUP BY country ORDER BY country
    """, fetch="all")
    return render_template("buy.html", user=user, countries=countries or [])

@app.route("/api/accounts/<country>")
@login_required
def get_accounts(country):
    accounts = db_query("""
        SELECT id, phone, country, price, created_at
        FROM accounts WHERE country=%s AND is_sold=FALSE
        ORDER BY created_at DESC
    """, (country,), fetch="all")
    result = []
    for a in (accounts or []):
        num = a[1]
        masked = num[:4] + "****" + num[-3:] if len(num) > 7 else num
        result.append({"id": a[0], "phone": masked, "country": a[2],
                       "price": float(a[3])})
    return jsonify({"success": True, "accounts": result})

@app.route("/purchase/<int:account_id>", methods=["POST"])
@login_required
def purchase_account(account_id):
    uid  = session["user_id"]
    user = get_user(uid)

    acc = db_query("SELECT id,phone,country,price,string_session,is_sold FROM accounts WHERE id=%s",
                   (account_id,), fetch="one")
    if not acc:
        return jsonify({"success": False, "error": "Account not found"}), 404
    if acc[5]:
        return jsonify({"success": False, "error": "Account already sold"}), 400

    price = float(acc[3])
    if float(user[2]) < price:
        return jsonify({"success": False, "error": f"Insufficient balance! Need ₹{price}, have ₹{float(user[2]):.2f}"}), 400

    # Deduct balance + mark sold
    db_query("UPDATE users SET balance=balance-%s, total_spent=total_spent+%s WHERE id=%s",
             (price, price, uid))
    db_query("UPDATE accounts SET is_sold=TRUE, sold_to=%s, sold_at=NOW() WHERE id=%s",
             (uid, account_id))

    # Create order
    db_query("INSERT INTO orders (user_id, account_id, amount, phone) VALUES (%s,%s,%s,%s)",
             (uid, account_id, price, acc[1]))
    order = db_query("SELECT id FROM orders WHERE user_id=%s AND account_id=%s ORDER BY id DESC LIMIT 1",
                     (uid, account_id), fetch="one")
    order_id = order[0]

    # Start OTP listener in background
    start_otp_listener(order_id, acc[4], acc[1])

    return jsonify({"success": True, "order_id": order_id,
                    "phone": acc[1], "country": acc[2]})

# ── Routes: OTP ───────────────────────────────────────────
@app.route("/otp/<int:order_id>")
@login_required
def otp_page(order_id):
    order = db_query("SELECT o.id, o.phone, o.otp, a.country, o.user_id FROM orders o JOIN accounts a ON o.account_id=a.id WHERE o.id=%s",
                     (order_id,), fetch="one")
    if not order or order[4] != session["user_id"]:
        return redirect("/dashboard")
    user = get_user(session["user_id"])
    return render_template("otp.html", order=order, user=user)

@app.route("/api/otp/<int:order_id>")
@login_required
def get_otp(order_id):
    # Check memory first
    otp = otp_store.get(str(order_id))
    if not otp:
        # Check DB
        row = db_query("SELECT otp FROM orders WHERE id=%s AND user_id=%s",
                       (order_id, session["user_id"]), fetch="one")
        if row: otp = row[0]
    return jsonify({"success": True, "otp": otp})

# ── Routes: Admin ─────────────────────────────────────────
@app.route("/admin")
@admin_required
def admin_page():
    user     = get_user(session["user_id"])
    users    = db_query("SELECT id,username,balance,total_deposited,total_spent,created_at FROM users ORDER BY id DESC", fetch="all")
    accounts = db_query("SELECT id,phone,country,price,is_sold,created_at FROM accounts ORDER BY id DESC LIMIT 50", fetch="all")
    stats    = db_query("""
        SELECT
            (SELECT COUNT(*) FROM users) as total_users,
            (SELECT COUNT(*) FROM accounts) as total_accounts,
            (SELECT COUNT(*) FROM accounts WHERE is_sold=TRUE) as sold,
            (SELECT COALESCE(SUM(amount),0) FROM orders) as revenue
    """, fetch="one")
    return render_template("admin.html", user=user, users=users or [],
                           accounts=accounts or [], stats=stats)

@app.route("/admin/add-account", methods=["POST"])
@admin_required
def add_account():
    data   = request.get_json(silent=True)
    phone  = str(data.get("phone","")).strip()
    country= str(data.get("country","")).strip()
    price  = data.get("price")
    sess   = str(data.get("string_session","")).strip()
    if not all([phone, country, price, sess]):
        return jsonify({"success": False, "error": "All fields required"}), 400
    db_query("INSERT INTO accounts (phone,country,price,string_session) VALUES (%s,%s,%s,%s)",
             (phone, country, float(price), sess))
    return jsonify({"success": True})

@app.route("/admin/add-balance", methods=["POST"])
@admin_required
def admin_add_balance():
    data   = request.get_json(silent=True)
    uid    = data.get("user_id")
    amount = data.get("amount")
    if not uid or not amount:
        return jsonify({"success": False, "error": "user_id aur amount required"}), 400
    db_query("UPDATE users SET balance=balance+%s WHERE id=%s", (float(amount), int(uid)))
    return jsonify({"success": True})

@app.route("/admin/delete-account", methods=["POST"])
@admin_required
def delete_account():
    data = request.get_json(silent=True)
    acc_id = data.get("account_id")
    db_query("DELETE FROM accounts WHERE id=%s AND is_sold=FALSE", (int(acc_id),))
    return jsonify({"success": True})

# ── SocketIO ──────────────────────────────────────────────
@socketio.on("join_otp_room")
def on_join(data):
    room = str(data.get("order_id",""))
    join_room(room)
    # Send immediately if OTP already received
    otp = otp_store.get(room)
    if otp:
        emit("otp_received", {"otp": otp})

# ── Keep Alive ────────────────────────────────────────────
SELF_URL = os.environ.get("RENDER_EXTERNAL_URL","")
def keep_alive():
    while True:
        time.sleep(600)
        if SELF_URL:
            try: requests.get(f"{SELF_URL}/", timeout=10)
            except: pass

if __name__ == "__main__":
    if SELF_URL:
        threading.Thread(target=keep_alive, daemon=True).start()
    port = int(os.environ.get("PORT", 5000))
    print(f"🚀 TG Account Store — port {port}")
    socketio.run(app, host="0.0.0.0", port=port, debug=False)
