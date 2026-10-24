CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,username TEXT UNIQUE NOT NULL,full_name TEXT NOT NULL,password_hash TEXT NOT NULL,
 role TEXT NOT NULL DEFAULT 'staff' CHECK(role IN('admin','staff')),status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN('pending','active','rejected','inactive')),
 created_at TEXT NOT NULL DEFAULT(datetime('now','localtime')));
CREATE TABLE IF NOT EXISTS categories(id INTEGER PRIMARY KEY,name TEXT UNIQUE NOT NULL);
CREATE TABLE IF NOT EXISTS products(id INTEGER PRIMARY KEY,category_id INTEGER NOT NULL REFERENCES categories(id),name TEXT NOT NULL,price INTEGER NOT NULL CHECK(price>=0),
 image_url TEXT,active INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS shifts(id INTEGER PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES users(id),start_at TEXT NOT NULL DEFAULT(datetime('now','localtime')),end_at TEXT,
 opening_cash INTEGER NOT NULL,closing_cash INTEGER,expected_cash INTEGER,over_short INTEGER,status TEXT NOT NULL DEFAULT 'open' CHECK(status IN('open','closed')));
CREATE TABLE IF NOT EXISTS orders(id INTEGER PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES users(id),shift_id INTEGER NOT NULL REFERENCES shifts(id),token TEXT UNIQUE NOT NULL,
 subtotal INTEGER NOT NULL,discount INTEGER NOT NULL DEFAULT 0,total INTEGER NOT NULL,created_at TEXT NOT NULL DEFAULT(datetime('now','localtime')));
CREATE TABLE IF NOT EXISTS order_items(id INTEGER PRIMARY KEY,order_id INTEGER NOT NULL REFERENCES orders(id),product_id INTEGER NOT NULL REFERENCES products(id),
 name TEXT NOT NULL,price INTEGER NOT NULL,qty INTEGER NOT NULL CHECK(qty>0));
CREATE TABLE IF NOT EXISTS payments(id INTEGER PRIMARY KEY,order_id INTEGER NOT NULL REFERENCES orders(id),method TEXT NOT NULL CHECK(method IN('cash','gcash')),
 amount INTEGER NOT NULL,cash_received INTEGER,change_given INTEGER);
CREATE TABLE IF NOT EXISTS expenses(id INTEGER PRIMARY KEY,shift_id INTEGER NOT NULL REFERENCES shifts(id),user_id INTEGER NOT NULL REFERENCES users(id),
 description TEXT NOT NULL,amount INTEGER NOT NULL CHECK(amount>0),created_at TEXT NOT NULL DEFAULT(datetime('now','localtime')));
CREATE TABLE IF NOT EXISTS remittances(id INTEGER PRIMARY KEY,shift_id INTEGER NOT NULL REFERENCES shifts(id),user_id INTEGER NOT NULL REFERENCES users(id),
 note TEXT,amount INTEGER NOT NULL CHECK(amount>0),created_at TEXT NOT NULL DEFAULT(datetime('now','localtime')));
CREATE TABLE IF NOT EXISTS audit_logs(id INTEGER PRIMARY KEY,user_id INTEGER REFERENCES users(id),action TEXT NOT NULL,detail TEXT,created_at TEXT NOT NULL DEFAULT(datetime('now','localtime')));
CREATE INDEX IF NOT EXISTS ix_orders_created ON orders(created_at);CREATE INDEX IF NOT EXISTS ix_orders_shift ON orders(shift_id);
CREATE INDEX IF NOT EXISTS ix_pay_order ON payments(order_id);CREATE INDEX IF NOT EXISTS ix_items_order ON order_items(order_id);
CREATE TABLE IF NOT EXISTS attempts(id INTEGER PRIMARY KEY,kind TEXT NOT NULL,key TEXT NOT NULL,at TEXT NOT NULL DEFAULT(datetime('now','localtime')));
CREATE INDEX IF NOT EXISTS ix_attempts_lookup ON attempts(kind,key,at);
CREATE INDEX IF NOT EXISTS ix_shift_user ON shifts(user_id,status);CREATE INDEX IF NOT EXISTS ix_audit_created ON audit_logs(created_at);
