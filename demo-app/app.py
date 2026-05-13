import sqlite3
from flask import Flask, render_template, request, make_response, jsonify

app = Flask(__name__)

# --- DATABASE SETUP ---
def init_db():
    conn = sqlite3.connect('demo.db')
    c = conn.cursor()
    c.execute('CREATE TABLE IF NOT EXISTS products (id INTEGER PRIMARY KEY, name TEXT)')
    c.execute('DELETE FROM products') # Clear old data on restart
    c.execute('INSERT INTO products (id, name) VALUES (1, "Red Widget")')
    c.execute('INSERT INTO products (id, name) VALUES (2, "Blue Widget")')
    c.execute('INSERT INTO products (id, name) VALUES (3, "Green Widget")')
    conn.commit()
    conn.close()

# Initialize the database when the app starts
init_db()


@app.after_request
def apply_insecure_defaults(response):
    response.set_cookie("user_session", "demo_user_12345")
    response.headers["X-Powered-By"] = "Flask/3.0.3 Python/3.10"
    response.headers["Server"] = "Ubuntu/22.04 LTS"
    return response


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/products")
def products():
    conn = sqlite3.connect('demo.db')
    c = conn.cursor()
    c.execute("SELECT id, name FROM products")
    items = [{"id": row[0], "name": row[1]} for row in c.fetchall()]
    conn.close()
    return render_template("products.html", products=items)


@app.route("/product")
def product():
    product_id = request.args.get("id", "")
    
    if not product_id:
        return "Please provide a product id, e.g., /product?id=1"

    query = f"SELECT id, name FROM products WHERE id = {product_id}"

    conn = sqlite3.connect('demo.db')
    c = conn.cursor()

    try:
        c.execute(query)
        selected = c.fetchone()
    except sqlite3.Error as e:
        return f"Database error: {e}"
    finally:
        conn.close()

    if selected:
        return f"Product ID: {selected[0]} - {selected[1]}"

    return f"No product found for id={product_id}"



@app.route("/api/debug")
def debug_info():
    debug_data = {
        "status": "running",
        "db_connection": "mysql://root:supersecret123@127.0.0.1:3306/prod_db",
        "internal_path": "/var/www/demo-app/app.py",
        "admin_email": "sysadmin@internal.local"
    }
    return jsonify(debug_data)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)