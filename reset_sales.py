"""Clears sales history (and the dashboard graph). Keeps users, products and photos."""
import os, sqlite3
from dotenv import load_dotenv
load_dotenv()
c = sqlite3.connect(os.environ.get("DATABASE", "cafeana.db"))
n = c.execute("SELECT COUNT(*) FROM orders").fetchone()[0]
print(f"This permanently deletes ALL sales ({n} orders), shifts, expenses and remittances.\nUsers and products are kept.")
if input("Type RESET to continue: ").strip() != "RESET":
    raise SystemExit("Cancelled. Nothing was deleted.")
for t in ("order_items", "payments", "orders", "expenses", "remittances", "shifts"):
    c.execute(f"DELETE FROM {t}")
c.execute("INSERT INTO audit_logs(action,detail) VALUES('sales_reset',?)", (f"{n} orders deleted",))
c.commit(); print("Done. The graph and receipts numbering start fresh.")