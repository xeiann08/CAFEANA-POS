"""Copy all data from cafeana.db (SQLite) into MySQL (XAMPP).

Before running:
  1. Start MySQL in XAMPP.
  2. Run cafeana_mysql.sql in phpMyAdmin (tables must exist and be empty).
  3. pip install pymysql
Run ONCE:  python migrate_to_mysql.py
"""
import sqlite3
import pymysql

SQLITE_FILE = "cafeana.db"
MYSQL = dict(host="localhost", user="root", password="",
             database="cafeana", charset="utf8mb4")

# Parent tables first
TABLES = ["users", "categories", "products", "shifts", "orders",
          "order_items", "payments", "expenses", "remittances", "audit_logs"]

src = sqlite3.connect(SQLITE_FILE)
dst = pymysql.connect(**MYSQL)
cur = dst.cursor()
cur.execute("SET FOREIGN_KEY_CHECKS=0")

for t in TABLES:
    c = src.execute(f"SELECT * FROM {t}")
    rows = c.fetchall()
    cols = [d[0] for d in c.description]
    if not rows:
        print(f"{t}: 0 rows")
        continue
    col_sql = ",".join(f"`{x}`" for x in cols)
    ph = ",".join(["%s"] * len(cols))
    cur.executemany(f"INSERT INTO `{t}` ({col_sql}) VALUES ({ph})", rows)
    print(f"{t}: {len(rows)} rows copied")

cur.execute("SET FOREIGN_KEY_CHECKS=1")
dst.commit()
dst.close()
src.close()
print("Done.")