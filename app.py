import os, re, secrets, sqlite3, time
from datetime import datetime, timedelta
from decimal import Decimal, InvalidOperation
from functools import wraps
from dotenv import load_dotenv
from flask import Flask, abort, flash, g, jsonify, redirect, render_template, request, session, url_for
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

load_dotenv()
PROD = os.environ.get("APP_ENV", "").lower() == "production"
if os.environ.get("TIMEZONE") and hasattr(time, "tzset"):  # Linux hosts default to UTC; this keeps receipts in local time
    os.environ["TZ"] = os.environ["TIMEZONE"]; time.tzset()
SECRET = os.environ["SECRET_KEY"]
if PROD and (len(SECRET) < 32 or SECRET.lower().startswith(("replace", "change", "type"))):
    raise SystemExit("Production needs a long random SECRET_KEY (32+ characters) in .env")
app = Flask(__name__)
if PROD: app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)  # correct client IP / https behind the host's proxy
app.config.update(SECRET_KEY=SECRET, SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                  SESSION_COOKIE_SECURE=PROD, PERMANENT_SESSION_LIFETIME=28800, MAX_CONTENT_LENGTH=3 * 1024 * 1024)
DB = os.environ.get("DATABASE", "cafeana.db")

# ---------- helpers ----------
def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB); g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys=ON"); g.db.execute("PRAGMA busy_timeout=5000")
    return g.db
@app.teardown_appcontext
def _close(e):
    d = g.pop("db", None)
    if d: d.close()
def q(sql, a=()): return db().execute(sql, a).fetchall()
def q1(sql, a=()): return db().execute(sql, a).fetchone()
def log(action, detail=""):
    db().execute("INSERT INTO audit_logs(user_id,action,detail) VALUES(?,?,?)", (session.get("uid"), action, detail))
def cents(v):
    try: d = Decimal(str(v).strip())
    except InvalidOperation: return None
    if not d.is_finite() or d < 0 or d > 1000000 or d != d.quantize(Decimal("0.01")): return None
    return int((d * 100).to_integral_value())
@app.template_filter("peso")
def peso(c): return "₱{:,.2f}".format((c or 0) / 100)
def cur_shift(): return q1("SELECT * FROM shifts WHERE user_id=? AND status='open'", (g.user["id"],))
def totals(s):
    def t(sql): return q1(sql, (s["id"],))["v"]
    cash = t("SELECT COALESCE(SUM(p.amount),0) v FROM payments p JOIN orders o ON o.id=p.order_id WHERE o.shift_id=? AND p.method='cash'")
    gc = t("SELECT COALESCE(SUM(p.amount),0) v FROM payments p JOIN orders o ON o.id=p.order_id WHERE o.shift_id=? AND p.method='gcash'")
    ex = t("SELECT COALESCE(SUM(amount),0) v FROM expenses WHERE shift_id=?")
    rm = t("SELECT COALESCE(SUM(amount),0) v FROM remittances WHERE shift_id=?")
    # GCash is NOT physical cash: only cash sales enter the drawer
    return dict(cash=cash, gcash=gc, exp=ex, rem=rm, total=cash + gc, expected=s["opening_cash"] + cash - ex - rm)
def split_pay(total, method, cash_in, gcash_in):
    """Returns ([(method, amount, cash_received, change)], error). Mixed = cash part + GCash part."""
    if method == "gcash": return [("gcash", total, None, None)], None
    rec = cents(cash_in)
    if method == "cash":
        if rec is None or rec < total: return None, "Cash received is less than the total."
        return [("cash", total, rec, rec - total)], None
    if method == "mixed":
        g = cents(gcash_in)
        if g is None or not 0 < g < total: return None, "GCash part must be more than 0 and less than the total."
        part = total - g
        if rec is None or rec < part: return None, "Cash received is less than the cash part."
        return [("cash", part, rec, rec - part), ("gcash", g, None, None)], None
    return None, "Choose a payment method."
def pretty(t):  # show cents in the audit trail as pesos, e.g. 11900 -> ₱119.00
    return re.sub(r"\b((?:total|amount|opening|over_short|discount)(?:_was)?)=(-?\d+)", lambda m: f"{m[1]}=₱{int(m[2]) / 100:,.2f}", t or "")
def resync(sid):  # keep a CLOSED shift's expected cash / over-short correct after an edit
    s = q1("SELECT * FROM shifts WHERE id=?", (sid,))
    if s and s["status"] == "closed":
        e = totals(s)["expected"]; db().execute("UPDATE shifts SET expected_cash=?,over_short=? WHERE id=?", (e, s["closing_cash"] - e, sid))
def duration(s):
    a = datetime.fromisoformat(s["start_at"]); b = datetime.fromisoformat(s["end_at"]) if s["end_at"] else datetime.now()
    m = int((b - a).total_seconds() // 60); return f"{m // 60}h {m % 60}m"

# ---------- rate limiting ----------
DUMMY = generate_password_hash("not-a-real-password")  # equalises timing for unknown usernames
def ip(): return request.remote_addr or "?"
def blocked(kind, key, limit, mins):
    return q1("SELECT COUNT(*) n FROM attempts WHERE kind=? AND key=? AND at>=datetime('now','localtime',?)", (kind, key, f"-{mins} minutes"))["n"] >= limit
def hit(kind, key):
    db().execute("DELETE FROM attempts WHERE at<datetime('now','localtime','-1 day')")
    db().execute("INSERT INTO attempts(kind,key) VALUES(?,?)", (kind, key))

# ---------- security ----------
@app.before_request
def load():
    g.user = None
    if session.get("uid"):
        g.user = q1("SELECT * FROM users WHERE id=? AND status='active'", (session["uid"],))
        if not g.user: session.clear()
    if request.method == "POST":
        t = request.form.get("csrf") or request.headers.get("X-CSRF") or ""
        if not secrets.compare_digest(t, session.get("csrf", "")): abort(400)
@app.after_request
def headers(r):
    r.headers["X-Frame-Options"] = "DENY"; r.headers["X-Content-Type-Options"] = "nosniff"; r.headers["Referrer-Policy"] = "same-origin"
    r.headers["Content-Security-Policy"] = "default-src 'self'; img-src 'self' https: data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; frame-ancestors 'none'; form-action 'self'"
    if not request.path.startswith("/static/"): r.headers["Cache-Control"] = "no-store"  # no cached financial pages after logout
    if PROD: r.headers["Strict-Transport-Security"] = "max-age=31536000"
    return r
@app.context_processor
def ctx():
    session.setdefault("csrf", secrets.token_hex(16)); u = getattr(g, "user", None); sh = None
    if u:
        try: sh = q1("SELECT 1 FROM shifts WHERE user_id=? AND status='open'", (u["id"],))
        except sqlite3.Error: pass
    return dict(csrf=session["csrf"], user=u, my_shift=sh)
def login_required(f):
    @wraps(f)
    def w(*a, **k):
        if not g.user: return redirect(url_for("login"))
        return f(*a, **k)
    return w
def admin_required(f):
    @wraps(f)
    @login_required
    def w(*a, **k):
        if g.user["role"] != "admin": abort(403)
        return f(*a, **k)
    return w
MSGS = {400: "Your session may have expired. Refresh the page and try again.", 403: "You don't have access to this page.", 404: "Page not found.",
        405: "That action isn't allowed.", 413: "That file is too large (max 3 MB).", 429: "Too many attempts. Please wait and try again.", 500: "Something went wrong. Nothing was lost. Please try again."}
for _c in MSGS:
    @app.errorhandler(_c)
    def err(e):
        code = getattr(e, "code", 500); msg = MSGS.get(code, MSGS[500])
        if request.path.startswith("/api/"): return jsonify(error=msg), code
        if request.headers.get("X-Requested-With") == "fetch": return jsonify(ok=False, title="Something went wrong", messages=[msg]), code
        return render_template("table.html", title="Error", headers=[], rows=[], msg=msg), code

# ---------- validation (one place, used by register / profile / admin reset) ----------
NAME_RE = re.compile(r"[^\W\d_]+(?:[ '.\-]{1,2}[^\W\d_]+)*\.?")  # letters (incl. ñ, é) with space - ' . between
def check_name(v, label):
    if not v: return [f"{label} is required."]
    if not 2 <= len(v) <= 40 or not NAME_RE.fullmatch(v):
        return [f"{label} must be 2-40 letters. No numbers or special characters (spaces, hyphens, apostrophes and periods are fine)."]
    return []
def check_username(v):
    if not v: return ["Username is required."]
    if not re.fullmatch(r"[A-Za-z0-9]+", v): return ["Username can have letters and numbers only. No spaces or special characters."]
    if not 3 <= len(v) <= 30: return ["Username must be 3-30 characters."]
    return []
def pw_error(pw):
    if not pw: return "Password is required."
    if len(pw) < 8: return "Password must be at least 8 characters."
    if len(pw) > 128: return "Password must be 128 characters or fewer."
    return None

# ---------- auth ----------
@app.route("/")
def index():
    if g.user: return redirect(url_for("dashboard" if g.user["role"] == "admin" else "pos"))
    return render_template("landing.html")
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        un = request.form.get("username", "").strip()[:60]; k = f"{ip()}|{un.lower()}"
        if blocked("login", k, 5, 15) or blocked("login", ip(), 30, 15):
            flash("Too many failed attempts. Please wait 15 minutes and try again.")
            return render_template("auth.html", mode="login"), 429
        u = q1("SELECT * FROM users WHERE username=?", (un,))
        if check_password_hash(u["password_hash"] if u else DUMMY, request.form.get("password", "")[:200]) and u:
            if u["status"] != "active":
                flash("Your account is not active. Contact an administrator.")
            else:
                db().execute("DELETE FROM attempts WHERE kind='login' AND key=?", (k,))
                session.clear(); session["uid"] = u["id"]; session.permanent = True
                g.user = u; log("login"); db().commit(); return redirect(url_for("index"))
        else:
            hit("login", k); hit("login", ip()); log("login_failed", un); db().commit()
            flash("Invalid username or password.")
    return render_template("auth.html", mode="login")
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        f = request.form; use_modal = request.headers.get("X-Requested-With") == "fetch"
        first, last = " ".join(f.get("first_name", "").split()), " ".join(f.get("last_name", "").split())
        un, pw = f.get("username", "").strip(), f.get("password", ""); errs, code = [], 200
        if blocked("register", ip(), 5, 60): errs, code = ["Too many registrations from this device. Try again later."], 429
        else:
            errs = check_name(first, "Name") + check_name(last, "Last name") + check_username(un) + ([pw_error(pw)] if pw_error(pw) else [])
            if not errs:
                try:
                    db().execute("INSERT INTO users(username,full_name,password_hash,role,status) VALUES(?,?,?,'staff','pending')", (un, f"{first} {last}", generate_password_hash(pw)))
                    hit("register", ip()); log("register", un); db().commit()
                except sqlite3.IntegrityError: errs = ["That username is already taken. Please choose another."]
        res = dict(ok=not errs, title="Registration failed" if errs else "Registration successful",
                   messages=errs or ["Your account was created. An admin must approve it before you can log in."])
        if use_modal: return jsonify(res), code
        for m in res["messages"]: flash(m)  # no-JavaScript fallback
        return render_template("auth.html", mode="register"), code
    return render_template("auth.html", mode="register")
@app.post("/logout")
@login_required
def logout():
    log("logout"); db().commit(); session.clear(); return redirect(url_for("login"))
@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    if request.method == "POST":
        f = request.form
        if not check_password_hash(g.user["password_hash"], f.get("current", "")): flash("Current password is wrong.")
        elif pw_error(f.get("new", "")) or f.get("new") != f.get("confirm"): flash(pw_error(f.get("new", "")) or "New passwords must match.")
        else:
            db().execute("UPDATE users SET password_hash=? WHERE id=?", (generate_password_hash(f["new"]), g.user["id"]))
            log("password_change"); db().commit(); flash("Password updated successfully."); return redirect(url_for("profile"))
    return render_template("auth.html", mode="profile")

# ---------- shifts ----------
@app.route("/shift", methods=["GET", "POST"])
@login_required
def shift():
    s = cur_shift()
    if request.method == "POST":
        c = cents(request.form.get("cash"))
        if c is None: flash("Enter a valid amount."); return redirect(url_for("shift"))
        if not s:
            try:
                db().execute("INSERT INTO shifts(user_id,opening_cash) VALUES(?,?)", (g.user["id"], c))
                log("shift_start", f"opening={c}"); db().commit()
            except sqlite3.IntegrityError: db().rollback()
            return redirect(url_for("pos"))
        if not request.form.get("confirm"): flash("Please confirm the shift closing."); return redirect(url_for("shift"))
        t = totals(s); over = c - t["expected"]
        db().execute("UPDATE shifts SET end_at=datetime('now','localtime'),closing_cash=?,expected_cash=?,over_short=?,status='closed' WHERE id=?", (c, t["expected"], over, s["id"]))
        log("shift_end", f"shift={s['id']} over_short={over}"); db().commit()
        return redirect(url_for("shift_view", sid=s["id"]))
    return render_template("shift.html", s=s, t=totals(s) if s else None, dur=duration(s) if s else "", who=g.user["full_name"])
@app.route("/shift/<int:sid>")
@login_required
def shift_view(sid):
    s = q1("SELECT s.*,u.full_name FROM shifts s JOIN users u ON u.id=s.user_id WHERE s.id=?", (sid,))
    if not s or (g.user["role"] != "admin" and s["user_id"] != g.user["id"]): abort(404)
    return render_template("shift.html", s=s, t=totals(s), dur=duration(s), who=s["full_name"], view=True)
@app.route("/admin/shifts")
@admin_required
def admin_shifts():
    rows = [[f"#{r['id']}", r["full_name"], r["start_at"], r["end_at"] or "OPEN", peso(r["opening_cash"]), peso(r["closing_cash"]) if r["closing_cash"] is not None else "-", peso(r["over_short"]) if r["over_short"] is not None else "-", f"/shift/{r['id']}"]
            for r in q("SELECT s.*,u.full_name FROM shifts s JOIN users u ON u.id=s.user_id ORDER BY s.id DESC LIMIT 200")]
    return render_template("table.html", title="Shifts", headers=["#", "Staff", "Start", "End", "Opening", "Actual", "Over/Short"], rows=rows)

# ---------- POS ----------
@app.route("/pos")
@login_required
def pos():
    if not cur_shift(): flash("Start your shift first."); return redirect(url_for("shift"))
    prods = [dict(id=p["id"], name=p["name"], price=p["price"], cat=p["cat"], img=p["image_url"] or "")
             for p in q("SELECT p.*,c.name cat FROM products p JOIN categories c ON c.id=p.category_id WHERE p.active=1 ORDER BY c.name,p.name")]
    return render_template("pos.html", prods=prods, cats=[c["name"] for c in q("SELECT name FROM categories ORDER BY id")])
@app.post("/api/checkout")
@login_required
def checkout():
    s = cur_shift(); d = request.get_json(silent=True); d = d if isinstance(d, dict) else {}
    bad = lambda m: (jsonify(error=m), 400)
    if not s: return jsonify(error="Start a shift first."), 403
    tok = str(d.get("token", ""))[:64]
    if not tok: return bad("Invalid request.")
    ex = q1("SELECT id FROM orders WHERE token=? AND user_id=?", (tok, g.user["id"]))
    if ex: return jsonify(id=ex["id"])  # duplicate submission -> same order
    items = d.get("items")
    if not isinstance(items, list) or not 0 < len(items) <= 50: return bad("Cart is empty.")
    sub, lines = 0, []
    for it in items:
        try: pid, qty = int(it["id"]), it["qty"]
        except (KeyError, TypeError, ValueError): return bad("Invalid cart.")
        if type(qty) is not int: return bad("Invalid quantity.")
        p = q1("SELECT * FROM products WHERE id=? AND active=1", (pid,))
        if not p or not 1 <= qty <= 99: return bad("Invalid cart item.")
        sub += p["price"] * qty; lines.append((pid, p["name"], p["price"], qty))
    disc = cents(d.get("discount") or 0)
    if disc is None or disc >= sub: return bad("Discount must be less than the subtotal.")
    total, method = sub - disc, d.get("method")
    pays, e = split_pay(total, method, d.get("cash_received"), d.get("gcash_amount"))
    if e: return bad(e)
    try:
        oid = db().execute("INSERT INTO orders(user_id,shift_id,token,subtotal,discount,total) VALUES(?,?,?,?,?,?)", (g.user["id"], s["id"], tok, sub, disc, total)).lastrowid
        db().executemany("INSERT INTO order_items(order_id,product_id,name,price,qty) VALUES(?,?,?,?,?)", [(oid, *l) for l in lines])
        db().executemany("INSERT INTO payments(order_id,method,amount,cash_received,change_given) VALUES(?,?,?,?,?)", [(oid, *p) for p in pays])
        log("order", f"order={oid} total={total} discount={disc} {method}"); db().commit()
    except sqlite3.IntegrityError:  # same token submitted twice at once: return the order that won
        db().rollback(); ex = q1("SELECT id FROM orders WHERE token=? AND user_id=?", (tok, g.user["id"]))
        if ex: return jsonify(id=ex["id"])
        return jsonify(error="Could not save the order."), 500
    except sqlite3.Error:
        db().rollback(); return jsonify(error="Could not save the order."), 500
    return jsonify(id=oid)
@app.route("/receipt/<int:oid>")
@login_required
def receipt(oid):
    o = q1("SELECT o.*,u.full_name cashier FROM orders o JOIN users u ON u.id=o.user_id WHERE o.id=?", (oid,))
    if not o or (g.user["role"] != "admin" and o["user_id"] != g.user["id"]): abort(404)
    return render_template("receipt.html", o=o, items=q("SELECT * FROM order_items WHERE order_id=?", (oid,)), pays=q("SELECT * FROM payments WHERE order_id=? ORDER BY method", (oid,)))
@app.post("/cash/<kind>")
@login_required
def cash_entry(kind):
    if kind not in ("expense", "remittance"): abort(404)
    s = cur_shift(); a = cents(request.form.get("amount")); note = request.form.get("note", "").strip()[:200]
    if not s or not a or (kind == "expense" and not note): flash("Enter a valid amount and description.")
    elif a > totals(s)["expected"]: flash("Amount is more than the cash expected in the drawer.")
    else:
        if kind == "expense": db().execute("INSERT INTO expenses(shift_id,user_id,description,amount) VALUES(?,?,?,?)", (s["id"], g.user["id"], note, a))
        else: db().execute("INSERT INTO remittances(shift_id,user_id,note,amount) VALUES(?,?,?,?)", (s["id"], g.user["id"], note, a))
        log(kind, f"amount={a} {note}"); db().commit(); flash(f"{kind.title()} recorded.")
    return redirect(url_for("pos"))
def order_list(title, own):
    s = f"%{request.args.get('q', '').strip()}%"
    sql = "SELECT o.*,u.full_name cashier,(SELECT GROUP_CONCAT(method,' + ') FROM (SELECT method FROM payments WHERE order_id=o.id ORDER BY method)) method FROM orders o JOIN users u ON u.id=o.user_id WHERE (printf('CAF-%06d',o.id) LIKE ? OR u.full_name LIKE ? OR o.created_at LIKE ?)"
    a = [s, s, s]
    if own: sql += " AND o.user_id=?"; a.append(g.user["id"])
    rows = [[f"CAF-{r['id']:06d}", r["created_at"], r["cashier"], r["method"].upper(), peso(r["total"]), f"/receipt/{r['id']}"] + ([] if own else [f"Edit|/admin/sales/{r['id']}/edit"]) for r in q(sql + " ORDER BY o.id DESC LIMIT 200", a)]
    return render_template("table.html", title=title, headers=["Receipt", "Date/Time", "Cashier", "Payment", "Total"], rows=rows, search=True)
@app.route("/orders")
@login_required
def orders(): return order_list("Order History", g.user["role"] != "admin")
@app.route("/admin/sales")
@admin_required
def admin_sales(): return order_list("All Sales", False)

# ---------- admin ----------
RANGES = {"day": "date({c})=date('now','localtime')", "week": "date({c})>=date('now','localtime','-6 days')", "month": "date({c})>=date('now','localtime','-29 days')"}
@app.route("/admin/dashboard")
@admin_required
def dashboard():
    r = request.args.get("range", "day"); r = r if r in RANGES else "day"
    c = lambda col: RANGES[r].format(c=col)
    st = q1(f"SELECT COUNT(DISTINCT o.id) n,COALESCE(SUM(p.amount),0) total,COALESCE(SUM(CASE WHEN p.method='cash' THEN p.amount END),0) cash,COALESCE(SUM(CASE WHEN p.method='gcash' THEN p.amount END),0) gcash FROM orders o JOIN payments p ON p.order_id=o.id WHERE {c('o.created_at')}")
    ex = q1(f"SELECT COALESCE(SUM(amount),0) v FROM expenses WHERE {c('created_at')}")["v"]
    rm = q1(f"SELECT COALESCE(SUM(amount),0) v FROM remittances WHERE {c('created_at')}")["v"]
    os_ = q1(f"SELECT COALESCE(SUM(over_short),0) v FROM shifts WHERE status='closed' AND {c('end_at')}")["v"]
    grp = "strftime('%H:00',o.created_at)" if r == "day" else "date(o.created_at)"
    rows = {x["k"]: x["v"] / 100 for x in q(f"SELECT {grp} k,SUM(o.total) v FROM orders o WHERE {c('o.created_at')} GROUP BY k")}
    if r == "day":
        hrs = sorted(rows); keys = [f"{h:02d}:00" for h in range(int(hrs[0][:2]), max(int(hrs[-1][:2]), datetime.now().hour) + 1)] if hrs else []
    else:
        today = datetime.now().date(); keys = [(today - timedelta(days=i)).isoformat() for i in range((7 if r == "week" else 30) - 1, -1, -1)]
    chart = [[k, rows.get(k, 0)] for k in keys] if rows else []
    return render_template("dashboard.html", st=st, ex=ex, rm=rm, os=os_, r=r, chart=chart,
        active=q("SELECT s.*,u.full_name FROM shifts s JOIN users u ON u.id=s.user_id WHERE s.status='open'"),
        recent=q("SELECT o.*,u.full_name FROM orders o JOIN users u ON u.id=o.user_id ORDER BY o.id DESC LIMIT 8"))
@app.route("/admin/users", methods=["GET", "POST"])
@admin_required
def users():
    if request.method == "POST":
        if request.form.get("action") == "reset":
            uid, pw = request.form.get("id", type=int), request.form.get("pw", "")
            if uid and uid != g.user["id"] and not pw_error(pw):
                db().execute("UPDATE users SET password_hash=? WHERE id=?", (generate_password_hash(pw), uid)); log("admin_reset_password", f"user={uid}"); db().commit(); flash("Password reset.")
            else: flash("Enter a new password of at least 8 characters.")
            return redirect(url_for("users"))
        m = {"approve": "active", "reject": "rejected", "deactivate": "inactive", "activate": "active"}
        act, uid = request.form.get("action"), request.form.get("id", type=int)
        if act in m and uid and uid != g.user["id"]:
            db().execute("UPDATE users SET status=? WHERE id=?", (m[act], uid)); log("user_" + act, f"user={uid}"); db().commit()
        return redirect(url_for("users"))
    return render_template("users.html", rows=q("SELECT * FROM users ORDER BY status='pending' DESC,id"))
@app.route("/admin/products", methods=["GET", "POST"])
@admin_required
def products():
    if request.method == "POST":
        f = request.form
        if f.get("toggle", type=int):
            db().execute("UPDATE products SET active=1-active WHERE id=?", (f.get("toggle", type=int),)); log("product_toggle", f["toggle"])
        else:
            pr, img = cents(f.get("price")), f.get("image_url", "").strip()
            if not f.get("name", "").strip() or not pr or not q1("SELECT 1 FROM categories WHERE id=?", (f.get("category", type=int),)) or (img and not re.match(r"^(https?://|/static/)", img)):
                flash("Check name, price, category and image URL.")
            else:
                db().execute("INSERT INTO products(category_id,name,price,image_url) VALUES(?,?,?,?)", (f.get("category", type=int), f["name"].strip()[:60], pr, img or None)); log("product_add", f["name"])
        db().commit(); return redirect(url_for("products"))
    return render_template("products.html", rows=q("SELECT p.*,c.name cat FROM products p JOIN categories c ON c.id=p.category_id ORDER BY p.id DESC"), cats=q("SELECT * FROM categories"))
@app.post("/admin/products/<int:pid>/image")
@admin_required
def product_image(pid):
    f = request.files.get("photo"); head = f.read(12) if f else b""
    ext = "jpg" if head[:2] == b"\xff\xd8" else "png" if head[:4] == b"\x89PNG" else "webp" if head[:4] == b"RIFF" and head[8:12] == b"WEBP" else None
    if not q1("SELECT 1 FROM products WHERE id=?", (pid,)) or not ext: flash("Choose a JPG, PNG or WEBP photo (max 3 MB).")
    else:
        folder = os.path.join(app.static_folder, "products"); os.makedirs(folder, exist_ok=True)
        f.seek(0); f.save(os.path.join(folder, f"{pid}.{ext}"))
        db().execute("UPDATE products SET image_url=? WHERE id=?", (f"/static/products/{pid}.{ext}?v={int(datetime.now().timestamp())}", pid))
        log("product_image", str(pid)); db().commit(); flash("Photo saved.")
    return redirect(url_for("products"))
@app.route("/admin/expenses")
@admin_required
def admin_expenses():
    rows = [[r["created_at"], r["kind"], r["full_name"], r["note"] or "", peso(r["amount"]), f"Edit|/admin/expenses/{r['k']}/{r['id']}/edit"] for r in q("SELECT 'Expense' kind,'expense' k,e.id,e.created_at,u.full_name,e.description note,e.amount FROM expenses e JOIN users u ON u.id=e.user_id UNION ALL SELECT 'Remittance','remittance',r.id,r.created_at,u.full_name,r.note,r.amount FROM remittances r JOIN users u ON u.id=r.user_id ORDER BY 4 DESC LIMIT 300")]
    return render_template("table.html", title="Expenses & Remittances", headers=["Date/Time", "Type", "Staff", "Description", "Amount"], rows=rows)
@app.route("/admin/expenses/<kind>/<int:eid>/edit", methods=["GET", "POST"])
@admin_required
def edit_cash(kind, eid):
    if kind not in ("expense", "remittance"): abort(404)
    t, col = ("expenses", "description") if kind == "expense" else ("remittances", "note")
    r = q1(f"SELECT * FROM {t} WHERE id=?", (eid,))
    if not r: abort(404)
    if request.method == "POST":
        amt, note = cents(request.form.get("amount")), request.form.get("note", "").strip()[:200]
        if not amt or (kind == "expense" and not note): flash("Enter a valid amount and description.")
        else:
            db().execute(f"UPDATE {t} SET amount=?,{col}=? WHERE id=?", (amt, note, eid))
            log(kind + "_edit", f"id={eid} amount_was={r['amount']} amount={amt}"); resync(r["shift_id"]); db().commit()
            flash("Saved."); return redirect(url_for("admin_expenses"))
    return render_template("edit.html", c=r, kind=kind, note=r[col])
@app.route("/admin/sales/<int:oid>/edit", methods=["GET", "POST"])
@admin_required
def edit_order(oid):
    o = q1("SELECT * FROM orders WHERE id=?", (oid,))
    if not o: abort(404)
    pays = {p["method"]: p for p in q("SELECT * FROM payments WHERE order_id=?", (oid,))}
    cur = "mixed" if len(pays) == 2 else next(iter(pays), "cash")
    items = q("SELECT * FROM order_items WHERE order_id=?", (oid,))
    if request.method == "POST":
        f, qty = request.form, {}
        for i in items:
            n = f.get(f"q{i['id']}", type=int)
            if n is None or not 0 <= n <= 99: flash("Invalid quantity."); return redirect(request.url)
            qty[i["id"]] = n
        sub = sum(i["price"] * qty[i["id"]] for i in items); disc = cents(f.get("discount") or 0); method = f.get("method")
        if sub == 0 or disc is None or disc >= sub or method not in ("cash", "gcash", "mixed"): flash("Keep at least one item, a valid discount and a payment method."); return redirect(request.url)
        total = sub - disc
        rows, e = split_pay(total, method, f.get("cash_received"), f.get("gcash_amount"))
        if e: flash(e); return redirect(request.url)
        try:
            for i in items:
                if qty[i["id"]] == 0: db().execute("DELETE FROM order_items WHERE id=?", (i["id"],))
                else: db().execute("UPDATE order_items SET qty=? WHERE id=?", (qty[i["id"]], i["id"]))
            db().execute("UPDATE orders SET subtotal=?,discount=?,total=? WHERE id=?", (sub, disc, total, oid))
            db().execute("DELETE FROM payments WHERE order_id=?", (oid,))
            db().executemany("INSERT INTO payments(order_id,method,amount,cash_received,change_given) VALUES(?,?,?,?,?)", [(oid, *p) for p in rows])
            log("order_edit", f"order={oid} total_was={o['total']} total={total} method={method}"); resync(o["shift_id"]); db().commit()
        except sqlite3.Error:
            db().rollback(); flash("Could not save changes."); return redirect(request.url)
        flash("Sale updated."); return redirect(url_for("admin_sales"))
    return render_template("edit.html", o=o, items=items, cur=cur,
        cashrec=pays["cash"]["cash_received"] if "cash" in pays else None, gc=pays["gcash"]["amount"] if "gcash" in pays else 0)
@app.route("/admin/reports")
@admin_required
def reports():
    rows = [[r["d"], r["n"], peso(r["cash"]), peso(r["gc"]), peso(r["t"])] for r in q("SELECT date(o.created_at) d,COUNT(DISTINCT o.id) n,SUM(CASE WHEN p.method='cash' THEN p.amount ELSE 0 END) cash,SUM(CASE WHEN p.method='gcash' THEN p.amount ELSE 0 END) gc,SUM(p.amount) t FROM orders o JOIN payments p ON p.order_id=o.id GROUP BY d ORDER BY d DESC LIMIT 90")]
    audit = [[a["created_at"], a["action"], pretty(a["detail"])] for a in q("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 30")]
    return render_template("table.html", title="Daily Sales Report", headers=["Date", "Orders", "Cash", "GCash", "Total"], rows=rows, audit=audit)

# ---------- setup ----------
def init():
    with sqlite3.connect(DB) as c:
        c.execute("PRAGMA journal_mode=WAL")  # safer concurrent reads/writes and crash recovery
        c.executescript(open(os.path.join(os.path.dirname(__file__), "schema.sql")).read())
        try: c.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_open_shift ON shifts(user_id) WHERE status='open'")
        except sqlite3.IntegrityError: pass
        if not c.execute("SELECT 1 FROM users WHERE role='admin'").fetchone():
            if PROD and (len(os.environ["ADMIN_PASSWORD"]) < 10 or os.environ["ADMIN_PASSWORD"] == "ChangeMe123!"):
                raise SystemExit("Production needs a strong ADMIN_PASSWORD (10+ characters) in .env before the first run")
            c.execute("INSERT INTO users(username,full_name,password_hash,role,status) VALUES(?,?,?,'admin','active')",
                      (os.environ["ADMIN_USERNAME"], os.environ.get("ADMIN_NAME", "Admin"), generate_password_hash(os.environ["ADMIN_PASSWORD"])))
        if not c.execute("SELECT 1 FROM categories").fetchone():
            from seed_menu import seed; seed(c)
init()
if __name__ == "__main__":
    host, port = os.environ.get("HOST", "127.0.0.1"), int(os.environ.get("PORT", 5000))
    try:
        from waitress import serve  # production-grade server (works on Windows too)
        serve(app, host=host, port=port)
    except ImportError:
        app.run(host=host, port=port, debug=False)