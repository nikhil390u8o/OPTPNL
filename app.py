import os, re, bcrypt, secrets, requests, asyncio, threading, time
from flask import Flask, render_template, request, jsonify, session, redirect
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

# In-memory Pyrogram clients store
tg_clients = {}  # order_id: {"client": ..., "loop": ...}

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

# ── Auth ──────────────────────────────────────────────────
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

def get_user(uid):
    return db_query("SELECT id,username,balance,total_deposited,total_spent,is_admin FROM users WHERE id=%s",
                    (uid,), fetch="one")

# ── Pyrogram Helpers ──────────────────────────────────────
def run_async(coro):
    """Run async coroutine in new thread with new event loop"""
    result = {}
    def runner():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            result["value"] = loop.run_until_complete(coro)
        except Exception as e:
            result["error"] = str(e)
        finally:
            loop.close()
    t = threading.Thread(target=runner)
    t.start()
    t.join(timeout=30)
    if "error" in result:
        raise Exception(result["error"])
    return result.get("value")

async def _send_code(phone):
    from pyrogram import Client
    client = Client(f"login_{phone.replace('+','')}", api_id=API_ID, api_hash=API_HASH, in_memory=True)
    await client.connect()
    sent = await client.send_code(phone)
    tg_clients[phone] = {"client": client, "hash": sent.phone_code_hash}
    return sent.phone_code_hash

async def _sign_in(phone, code, phone_code_hash):
    from pyrogram import Client
    from pyrogram.errors import SessionPasswordNeeded
    data = tg_clients.get(phone, {})
    client = data.get("client")
    if not client:
        raise Exception("Session expired. Dobara buy karo.")
    try:
        user = await client.sign_in(phone, phone_code_hash, code)
        string_session = await client.export_session_string()
        await client.disconnect()
        tg_clients.pop(phone, None)
        return {"success": True, "session": string_session, "needs_2fa": False}
    except SessionPasswordNeeded:
        return {"success": True, "needs_2fa": True}

async def _check_2fa(phone, password):
    data = tg_clients.get(phone, {})
    client = data.get("client")
    if not client:
        raise Exception("Session expired. Dobara buy karo.")
    await client.check_password(password)
    string_session = await client.export_session_string()
    await client.disconnect()
    tg_clients.pop(phone, None)
    return string_session

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

# ── Dashboard ─────────────────────────────────────────────
@app.route("/dashboard")
@login_required
def dashboard():
    user = get_user(session["user_id"])
    return render_template("dashboard.html", user=user)

@app.route("/api/deposit/verify", methods=["POST"])
@login_required
def deposit_verify():
    data   = request.get_json(silent=True)
    utr    = str(data.get("utr","")).strip().upper()
    amount = data.get("amount")
    if not utr or not amount:
        return jsonify({"success": False, "error": "UTR/TXN ID aur amount required"}), 400
    try: amount = float(amount)
    except: return jsonify({"success": False, "error": "Invalid amount"}), 400
    exists = db_query("SELECT 1 FROM used_utrs WHERE utr=%s", (utr,), fetch="one")
    if exists:
        return jsonify({"success": False, "error": "UTR already used!"})
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
        db_query("INSERT INTO used_utrs (user_id, utr, amount) VALUES (%s,%s,%s)", (uid, utr, amount))
        user = get_user(uid)
        return jsonify({"success": True, "verified": True, "balance": float(user[2])})
    if "already used" in str(result.get("error","")).lower():
        return jsonify({"success": False, "error": "UTR already used!"})
    return jsonify({"success": True, "verified": False, "message": "Payment nahi mila."})

# ── Buy ───────────────────────────────────────────────────
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
        SELECT id, phone, country, price FROM accounts
        WHERE country=%s AND is_sold=FALSE ORDER BY created_at DESC
    """, (country,), fetch="all")
    result = []
    for a in (accounts or []):
        num = a[1]
        masked = num[:4] + "****" + num[-3:] if len(num) > 7 else num
        result.append({"id": a[0], "phone": masked, "country": a[2], "price": float(a[3])})
    return jsonify({"success": True, "accounts": result})

@app.route("/purchase/<int:account_id>", methods=["POST"])
@login_required
def purchase_account(account_id):
    uid  = session["user_id"]
    user = get_user(uid)
    acc  = db_query("SELECT id,phone,country,price,is_sold FROM accounts WHERE id=%s",
                    (account_id,), fetch="one")
    if not acc:
        return jsonify({"success": False, "error": "Account not found"}), 404
    if acc[4]:
        return jsonify({"success": False, "error": "Account already sold"}), 400

    price    = float(acc[3])
    is_admin = session.get("is_admin", False)

    if not is_admin and float(user[2]) < price:
        return jsonify({"success": False, "error": f"Balance kam hai! ₹{price} chahiye, tumhare paas ₹{float(user[2]):.2f}"}), 400

    # Deduct balance (admin ke liye nahi)
    if not is_admin:
        db_query("UPDATE users SET balance=balance-%s, total_spent=total_spent+%s WHERE id=%s",
                 (price, price, uid))

    # Mark account sold
    db_query("UPDATE accounts SET is_sold=TRUE, sold_to=%s, sold_at=NOW() WHERE id=%s", (uid, account_id))

    # Create order
    db_query("INSERT INTO orders (user_id, account_id, amount, phone, status) VALUES (%s,%s,%s,%s,'pending')",
             (uid, account_id, price, acc[1]))
    order = db_query("SELECT id FROM orders WHERE user_id=%s AND account_id=%s ORDER BY id DESC LIMIT 1",
                     (uid, account_id), fetch="one")
    order_id = order[0]

    # Send OTP to phone via Pyrogram
    try:
        phone_code_hash = run_async(_send_code(acc[1]))
        db_query("UPDATE orders SET phone_code_hash=%s WHERE id=%s", (phone_code_hash, order_id))
        return jsonify({"success": True, "order_id": order_id, "phone": acc[1], "country": acc[2]})
    except Exception as e:
        return jsonify({"success": False, "error": f"OTP send nahi hua: {str(e)}"}), 500

# ── OTP Page ──────────────────────────────────────────────
@app.route("/otp/<int:order_id>")
@login_required
def otp_page(order_id):
    order = db_query("""
        SELECT o.id, o.phone, o.status, a.country, o.user_id, o.phone_code_hash
        FROM orders o JOIN accounts a ON o.account_id=a.id WHERE o.id=%s
    """, (order_id,), fetch="one")
    if not order or order[4] != session["user_id"]:
        return redirect("/dashboard")
    user = get_user(session["user_id"])
    return render_template("otp.html", order=order, user=user)

@app.route("/api/otp/submit", methods=["POST"])
@login_required
def submit_otp():
    data     = request.get_json(silent=True)
    order_id = data.get("order_id")
    code     = str(data.get("code","")).strip()
    if not order_id or not code:
        return jsonify({"success": False, "error": "Order ID aur OTP do"}), 400

    order = db_query("SELECT phone, phone_code_hash FROM orders WHERE id=%s AND user_id=%s",
                     (order_id, session["user_id"]), fetch="one")
    if not order:
        return jsonify({"success": False, "error": "Order not found"}), 404

    phone, phone_code_hash = order
    try:
        result = run_async(_sign_in(phone, code, phone_code_hash))
        if result.get("needs_2fa"):
            db_query("UPDATE orders SET status='needs_2fa' WHERE id=%s", (order_id,))
            return jsonify({"success": True, "needs_2fa": True})
        # Save session string
        db_query("UPDATE accounts SET string_session=%s WHERE phone=%s", (result["session"], phone))
        db_query("UPDATE orders SET status='completed' WHERE id=%s", (order_id,))
        return jsonify({"success": True, "needs_2fa": False, "done": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/otp/submit2fa", methods=["POST"])
@login_required
def submit_2fa():
    data     = request.get_json(silent=True)
    order_id = data.get("order_id")
    password = str(data.get("password","")).strip()
    if not order_id or not password:
        return jsonify({"success": False, "error": "Password do"}), 400

    order = db_query("SELECT phone FROM orders WHERE id=%s AND user_id=%s",
                     (order_id, session["user_id"]), fetch="one")
    if not order:
        return jsonify({"success": False, "error": "Order not found"}), 404

    try:
        session_str = run_async(_check_2fa(order[0], password))
        db_query("UPDATE accounts SET string_session=%s WHERE phone=%s", (session_str, order[0]))
        db_query("UPDATE orders SET status='completed' WHERE id=%s", (order_id,))
        return jsonify({"success": True, "done": True})
    except Exception as e:
        return jsonify({"success": False, "error": f"Wrong password: {str(e)}"}), 500

# ── Admin ─────────────────────────────────────────────────
@app.route("/admin")
@admin_required
def admin_page():
    user     = get_user(session["user_id"])
    users    = db_query("SELECT id,username,balance,total_deposited,total_spent FROM users ORDER BY id DESC", fetch="all")
    accounts = db_query("SELECT id,phone,country,price,is_sold FROM accounts ORDER BY id DESC LIMIT 50", fetch="all")
    stats    = db_query("""SELECT
        (SELECT COUNT(*) FROM users),
        (SELECT COUNT(*) FROM accounts),
        (SELECT COUNT(*) FROM accounts WHERE is_sold=TRUE),
        (SELECT COALESCE(SUM(amount),0) FROM orders)
    """, fetch="one")
    return render_template("admin.html", user=user, users=users or [], accounts=accounts or [], stats=stats)

@app.route("/admin/add-account", methods=["POST"])
@admin_required
def add_account():
    data    = request.get_json(silent=True)
    phone   = str(data.get("phone","")).strip()
    country = str(data.get("country","")).strip()
    price   = data.get("price")
    if not all([phone, country, price]):
        return jsonify({"success": False, "error": "Phone, country aur price required"}), 400
    db_query("INSERT INTO accounts (phone,country,price,string_session) VALUES (%s,%s,%s,'')",
             (phone, country, float(price)))
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
    db_query("DELETE FROM accounts WHERE id=%s AND is_sold=FALSE", (int(data.get("account_id")),))
    return jsonify({"success": True})

# ── SocketIO ──────────────────────────────────────────────
@socketio.on("join_otp_room")
def on_join(data):
    join_room(str(data.get("order_id","")))

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
    socketio.run(app, host="0.0.0.0", port=port, debug=False)
