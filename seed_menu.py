"""Loads the Caféana/BBC menu. Safe to re-run: skips existing items, hides the old sample items."""
import os, sqlite3
from dotenv import load_dotenv
MENU = {
 "Coffee": [("Vanilla",119),("Caramel Latte",119),("French Vanilla",119),("Hazelnut",119),("Americano",99),("Spanish Latte",119),("Dirty Matcha",119),("Cafe Latte",99),("Cappuccino",99),
   ("Espresso Katipunero",148),("Toffee Nut Latte",135),("Creme Brulee Latte",135),("Chocodamia",140),("Toasty Almonds Latte",135),("Caradamia Latte",140),("Biscoffee",150),
   ("Caramel Macchiato",125),("Mocha",125),("White Mocha",125),("Choco Hazelnut",125),("Salted Caramel",125),("Choco Peppermint",125),("Biscoff Latte",150),("Butterscotch Latte",135)],
 "Non-Coffee": [("Strawberry Milk",109),("Mango Milk",109),("Blueberry Milk",109),("Mixed Berries Milk",109),("Ube Oatmilk",109),("Butterscotch",109),("Cookies N' Cream",109),("Matcha",109),
   ("Strawberry Matcha",119),("Choco Matcha",119),("Strawberry Creme Brulee",150),("Iced Chocolate",109),("Biscoff",150)],
 "Fizzy Drinks": [(n,109) for n in ("Strawberry Lemonade","Watermelon Lemonade","Blue Ocean Breeze","Chillin Berry Limeade","Purple Berry Wave","Pineapple Mango")],
 "Loaded Spud": [("Chili Con Carne",188),("Garlic Bacon Bomb",188),("Bacon Cheese Melt",188)],
 "Add-ons": [("Espresso Shot",25),("Oatmilk",50),("Syrup",25),("Sauce",20)],
}
OLD = ("Iced Latte","Spanish Latte","Americano","Matcha","Chocolate","Croissant","Fries")
def seed(c):
    for cat, items in MENU.items():
        c.execute("INSERT OR IGNORE INTO categories(name) VALUES(?)", (cat,))
        cid = c.execute("SELECT id FROM categories WHERE name=?", (cat,)).fetchone()[0]
        for n, p in items:
            if not c.execute("SELECT 1 FROM products WHERE name=? AND category_id=?", (n, cid)).fetchone():
                c.execute("INSERT INTO products(category_id,name,price) VALUES(?,?,?)", (cid, n, p * 100))
if __name__ == "__main__":
    load_dotenv(); c = sqlite3.connect(os.environ.get("DATABASE", "cafeana.db"))
    seed(c)
    c.executemany("UPDATE products SET active=0 WHERE name=? AND id<=7 AND price IN (12000,13000,10000,14000,12000,9000,8500)", [(n,) for n in OLD])
    c.commit(); print("Menu loaded.")
