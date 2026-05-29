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

DB_HOST  = os.environ.get("DB_HOST", "")
DB_PORT  = os.environ.get("DB_PORT", "6543")
DB_NAME  = os.environ.get("DB_NAME", "postgres")
DB_USER  = os.environ.get("DB_USER", "")
DB_PASS  = os.environ.get("DB_PASS", "")
API_ID   = int(os.environ.get("API_ID", 0))
API_HASH = os.environ.get("API_HASH", "")
FAMPAY_API_URL = os.environ.get("FAMPAY_API_URL", "")
FAMPAY_API_KEY = os.environ.get("FAMPAY_API_KEY", "")

# Dedicated event loop
tg_clients = {}
_loop = asyncio.new_event_loop()
threading.Thread(target=_loop.run_forever, daemon=True).start()

def run_async(coro, timeout=30):
    future = asyncio.run_coroutine_threadsafe(coro, _loop)
    return future.result(timeout=timeout)

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
    def d(*a, **k):
        if "user_id" not in session: return redirect("/")
        return f(*a, **k)
    return d

def admin_required(f):
    from functools import wraps
    @wraps(f)
    def d(*a, **k):
        if "user_id" not in session or not session.get("is_admin"): return redirect("/")
        return f(*a, **k)
    return d

def get_user(uid):
    return db_query("SELECT id,username,balance,total_deposited,total_spent,is_admin FROM users WHERE id=%s", (uid,), fetch="one")

# ── Pyrogram ──────────────────────────────────────────────
async def _send_code(phone):
    from pyrogram import Client
    client = Client(f"adm_{phone.replace('+','')}", api_id=API_ID, api_hash=API_HASH, in_memory=True)
    await client.connect()
    sent = await client.send_code(phone)
    tg_clients[phone] = {"client": client, "hash": sent.phone_code_hash}
    return sent.phone_code_hash

async def _sign_in(phone, code, phone_code_hash):
    from pyrogram import Client
    from pyrogram.errors import SessionPasswordNeeded
    # Check both keys
    data = tg_clients.get(phone) or tg_clients.get(f"usr_{phone}", {})
    client = data.get("client")
    # Client nahi mila memory me — recreate karo
    if not client:
        client = Client(f"usr_{phone.replace('+','')}", api_id=API_ID, api_hash=API_HASH, in_memory=True)
        await client.connect()
        tg_clients[f"usr_{phone}"] = {"client": client, "hash": phone_code_hash}
    try:
        await client.sign_in(phone, phone_code_hash, code)
        string_session = await client.export_session_string()
        await client.disconnect()
        tg_clients.pop(f"usr_{phone}", None)
        return {"needs_2fa": False, "session": string_session}
    except SessionPasswordNeeded:
        return {"needs_2fa": True}

async def _check_2fa(phone, password):
    data   = tg_clients.get(f"usr_{phone}", {})
    client = data.get("client")
    if not client:
        raise Exception("Session expired. Page reload karo aur dobara buy karo.")
    await client.check_password(password)
    string_session = await client.export_session_string()
    await client.disconnect()
    tg_clients.pop(phone, None)
    return string_session

async def _send_code_user(phone):
    """User ke liye OTP send — fresh client"""
    from pyrogram import Client
    client = Client(f"usr_{phone.replace('+','')}", api_id=API_ID, api_hash=API_HASH, in_memory=True)
    await client.connect()
    sent = await client.send_code(phone)
    tg_clients[f"usr_{phone}"] = {"client": client, "hash": sent.phone_code_hash}
    return sent.phone_code_hash

async def _listen_for_otp(order_id, string_session, phone):
    """Listen for OTP using saved string_session"""
    try:
        from pyrogram import Client, filters
        client = Client(
            f"listen_{order_id}",
            api_id=API_ID,
            api_hash=API_HASH,
            session_string=string_session,
            in_memory=True
        )
        await client.start()

        otp_found = False

        @client.on_message(filters.private & filters.incoming)
        async def on_msg(c, m):
            nonlocal otp_found
            text = m.text or m.caption or ""
            import re
            # Telegram login code format: "Login code: 12345" or just 5 digits
            match = re.search(r'(\d{5})', text)
            if match and not otp_found:
                otp = match.group(1)
                otp_found = True
                # Save to DB
                db_query("UPDATE orders SET otp=%s, status='otp_received' WHERE id=%s", (otp, order_id))
                # Emit to browser via SocketIO
                socketio.emit("otp_received", {"otp": otp}, room=str(order_id))
                await client.stop()

        # Wait 5 minutes for OTP
        await asyncio.sleep(300)
        if not otp_found:
            try: await client.stop()
            except: pass
    except Exception as e:
        print(f"OTP listener error: {e}")

# ── Auth Routes ───────────────────────────────────────────
@app.route("/")
def login_page():
    if "user_id" in session: return redirect("/dashboard")
    return render_template("login.html")

@app.route("/register", methods=["GET","POST"])
def register_page():
    if request.method == "GET": return render_template("register.html")
    data     = request.get_json(silent=True) or request.form
    username = str(data.get("username","")).strip().lower()
    password = str(data.get("password","")).strip()
    if not username or not password or len(username) < 3:
        return jsonify({"success": False, "error": "Invalid username/password"}), 400
    if db_query("SELECT id FROM users WHERE username=%s", (username,), fetch="one"):
        return jsonify({"success": False, "error": "Username already taken"}), 400
    db_query("INSERT INTO users (username, password_hash) VALUES (%s,%s)", (username, hash_pass(password)))
    return jsonify({"success": True})

@app.route("/login", methods=["POST"])
def do_login():
    data     = request.get_json(silent=True) or request.form
    username = str(data.get("username","")).strip().lower()
    password = str(data.get("password","")).strip()
    user     = db_query("SELECT id,password_hash,is_admin FROM users WHERE username=%s", (username,), fetch="one")
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
    return render_template("dashboard.html", user=get_user(session["user_id"]))

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
    if db_query("SELECT 1 FROM used_utrs WHERE utr=%s", (utr,), fetch="one"):
        return jsonify({"success": False, "error": "UTR already used!"})
    try:
        resp   = requests.post(f"{FAMPAY_API_URL}/verify", json={"api_key": FAMPAY_API_KEY, "utr": utr, "amount": amount}, timeout=60)
        result = resp.json()
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
    if result.get("verified"):
        uid = session["user_id"]
        db_query("UPDATE users SET balance=balance+%s, total_deposited=total_deposited+%s WHERE id=%s", (amount, amount, uid))
        db_query("INSERT INTO used_utrs (user_id, utr, amount) VALUES (%s,%s,%s)", (uid, utr, amount))
        return jsonify({"success": True, "verified": True, "balance": float(get_user(uid)[2])})
    if "already used" in str(result.get("error","")).lower():
        return jsonify({"success": False, "error": "UTR already used!"})
    return jsonify({"success": True, "verified": False, "message": "Payment nahi mila."})

# ── Buy ───────────────────────────────────────────────────
@app.route("/buy")
@login_required
def buy_page():
    countries = db_query("SELECT country, COUNT(*) as cnt, MIN(price) as min_price FROM accounts WHERE is_sold=FALSE GROUP BY country ORDER BY country", fetch="all")
    return render_template("buy.html", user=get_user(session["user_id"]), countries=countries or [])

@app.route("/api/accounts/<country>")
@login_required
def get_accounts(country):
    accounts = db_query("SELECT id, phone, country, price FROM accounts WHERE country=%s AND is_sold=FALSE ORDER BY created_at DESC", (country,), fetch="all")
    result   = []
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
    acc  = db_query("SELECT id,phone,country,price,is_sold,string_session,twofa_password FROM accounts WHERE id=%s", (account_id,), fetch="one")
    if not acc: return jsonify({"success": False, "error": "Account not found"}), 404
    if acc[4]: return jsonify({"success": False, "error": "Account already sold"}), 400

    price    = float(acc[3])
    is_admin = session.get("is_admin", False)
    if not is_admin and float(user[2]) < price:
        return jsonify({"success": False, "error": f"Balance kam hai! ₹{price} chahiye"}), 400

    if not is_admin:
        db_query("UPDATE users SET balance=balance-%s, total_spent=total_spent+%s WHERE id=%s", (price, price, uid))

    db_query("UPDATE accounts SET is_sold=TRUE, sold_to=%s, sold_at=NOW() WHERE id=%s", (uid, account_id))
    db_query("INSERT INTO orders (user_id, account_id, amount, phone, status) VALUES (%s,%s,%s,%s,'pending')", (uid, account_id, price, acc[1]))
    order = db_query("SELECT id FROM orders WHERE user_id=%s AND account_id=%s ORDER BY id DESC LIMIT 1", (uid, account_id), fetch="one")
    order_id = order[0]

    # Start OTP listener using saved string_session
    string_session = acc[5]
    if string_session:
        asyncio.run_coroutine_threadsafe(
            _listen_for_otp(order_id, string_session, acc[1]),
            _loop
        )
    return jsonify({"success": True, "order_id": order_id, "phone": acc[1], "country": acc[2]})

# ── OTP Page ──────────────────────────────────────────────
@app.route("/otp/<int:order_id>")
@login_required
def otp_page(order_id):
    order = db_query("""
        SELECT o.id, o.phone, o.status, a.country, o.user_id, o.phone_code_hash, a.twofa_password
        FROM orders o JOIN accounts a ON o.account_id=a.id WHERE o.id=%s
    """, (order_id,), fetch="one")
    if not order or order[4] != session["user_id"]: return redirect("/dashboard")
    return render_template("otp.html", order=order, user=get_user(session["user_id"]))

@app.route("/api/otp/submit", methods=["POST"])
@login_required
def submit_otp():
    data     = request.get_json(silent=True)
    order_id = data.get("order_id")
    code     = str(data.get("code","")).strip()
    order    = db_query("SELECT phone, phone_code_hash FROM orders WHERE id=%s AND user_id=%s", (order_id, session["user_id"]), fetch="one")
    if not order: return jsonify({"success": False, "error": "Order not found"}), 404

    phone, hash_code = order
    key = f"usr_{phone}"
    if key not in tg_clients:
        return jsonify({"success": False, "error": "Session expired. Page reload karo aur dobara buy karo."}), 400
    try:
        result = run_async(_sign_in(phone, code, hash_code))
        if result.get("needs_2fa"):
            db_query("UPDATE orders SET status='needs_2fa' WHERE id=%s", (order_id,))
            # Get saved 2FA password if admin had set it
            acc_pass = db_query("SELECT twofa_password FROM accounts WHERE phone=%s", (phone,), fetch="one")
            saved_pass = acc_pass[0] if acc_pass else None
            return jsonify({"success": True, "needs_2fa": True, "saved_pass": saved_pass})
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
    order    = db_query("SELECT phone FROM orders WHERE id=%s AND user_id=%s", (order_id, session["user_id"]), fetch="one")
    if not order: return jsonify({"success": False, "error": "Order not found"}), 404
    phone = order[0]
    key   = f"usr_{phone}"
    if key not in tg_clients:
        return jsonify({"success": False, "error": "Session expired. Page reload karo."}), 400
    try:
        run_async(_check_2fa(phone, password))
        db_query("UPDATE orders SET status='completed' WHERE id=%s", (order_id,))
        return jsonify({"success": True, "done": True})
    except Exception as e:
        return jsonify({"success": False, "error": f"Wrong password: {str(e)}"}), 500

# ── Admin: Send OTP for account setup ────────────────────
@app.route("/admin/send-otp", methods=["POST"])
@admin_required
def admin_send_otp():
    data  = request.get_json(silent=True)
    phone = str(data.get("phone","")).strip()
    if not phone: return jsonify({"success": False, "error": "Phone number do"}), 400
    try:
        hash_code = run_async(_send_code(phone))
        return jsonify({"success": True, "hash": hash_code})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/admin/verify-otp", methods=["POST"])
@admin_required
def admin_verify_otp():
    data      = request.get_json(silent=True)
    phone     = str(data.get("phone","")).strip()
    code      = str(data.get("code","")).strip()
    hash_code = str(data.get("hash","")).strip()
    if not all([phone, code, hash_code]):
        return jsonify({"success": False, "error": "Phone, OTP aur hash do"}), 400
    try:
        result = run_async(_sign_in(phone, code, hash_code), timeout=60)
        if result.get("needs_2fa"):
            return jsonify({"success": True, "needs_2fa": True})
        db_query("UPDATE accounts SET string_session=%s WHERE phone=%s", (result["session"], phone))
        return jsonify({"success": True, "needs_2fa": False, "done": True})
    except Exception as e:
        error = str(e)
        if "PHONE_CODE_EXPIRED" in error:
            return jsonify({"success": False, "error": "OTP expire ho gaya! Dobara Send OTP karo."}), 400
        if "PHONE_CODE_INVALID" in error:
            return jsonify({"success": False, "error": "OTP galat hai! Check karke dobara daalo."}), 400
        return jsonify({"success": False, "error": error}), 500

@app.route("/admin/verify-2fa", methods=["POST"])
@admin_required
def admin_verify_2fa():
    data     = request.get_json(silent=True)
    phone    = str(data.get("phone","")).strip()
    password = str(data.get("password","")).strip()
    if not phone or not password:
        return jsonify({"success": False, "error": "Phone aur password do"}), 400
    try:
        session_str = run_async(_check_2fa(phone, password))
        db_query("UPDATE accounts SET string_session=%s, twofa_password=%s WHERE phone=%s", (session_str, password, phone))
        return jsonify({"success": True, "done": True})
    except Exception as e:
        return jsonify({"success": False, "error": f"Wrong password: {str(e)}"}), 500

# ── Admin CRUD ────────────────────────────────────────────
@app.route("/admin")
@admin_required
def admin_page():
    user     = get_user(session["user_id"])
    users    = db_query("SELECT id,username,balance,total_deposited,total_spent FROM users ORDER BY id DESC", fetch="all")
    accounts = db_query("SELECT id,phone,country,price,is_sold FROM accounts ORDER BY id DESC LIMIT 50", fetch="all")
    stats    = db_query("SELECT (SELECT COUNT(*) FROM users),(SELECT COUNT(*) FROM accounts),(SELECT COUNT(*) FROM accounts WHERE is_sold=TRUE),(SELECT COALESCE(SUM(amount),0) FROM orders)", fetch="one")
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
    db_query("INSERT INTO accounts (phone,country,price,string_session) VALUES (%s,%s,%s,'')", (phone, country, float(price)))
    return jsonify({"success": True})

@app.route("/admin/add-balance", methods=["POST"])
@admin_required
def admin_add_balance():
    data   = request.get_json(silent=True)
    uid    = data.get("user_id")
    amount = data.get("amount")
    if not uid or not amount: return jsonify({"success": False, "error": "user_id aur amount required"}), 400
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

SELF_URL = os.environ.get("RENDER_EXTERNAL_URL","")
def keep_alive():
    while True:
        time.sleep(600)
        if SELF_URL:
            try: requests.get(f"{SELF_URL}/", timeout=10)
            except: pass

if __name__ == "__main__":
    if SELF_URL: threading.Thread(target=keep_alive, daemon=True).start()
    port = int(os.environ.get("PORT", 5000))
    socketio.run(app, host="0.0.0.0", port=port, debug=False)
