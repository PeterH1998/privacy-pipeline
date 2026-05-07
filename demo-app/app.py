from flask import Flask, render_template, request, make_response, jsonify

app = Flask(__name__)

# Fake product data used for the demo pages.
PRODUCTS = [
    {"id": 1, "name": "Red Widget"},
    {"id": 2, "name": "Blue Widget"},
    {"id": 3, "name": "Green Widget"},
]

@app.after_request
def apply_insecure_defaults(response):
    # VULNERABILITY 1: Cookie Problems
    # Setting a tracking cookie without 'Secure', 'HttpOnly', or 'SameSite' flags.
    response.set_cookie("user_session", "demo_user_12345")

    # VULNERABILITY 2: Header Problems / Info Disclosure
    # Explicitly revealing the backend technology stack versions.
    response.headers["X-Powered-By"] = "Flask/3.0.3 Python/3.10"
    response.headers["Server"] = "Ubuntu/22.04 LTS"

    # Note: ZAP will also flag the *missing* headers here (Content-Security-Policy, 
    # X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security)
    return response


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/products")
def products():
    return render_template("products.html", products=PRODUCTS)


@app.route("/product")
def product():
    product_id = request.args.get("id", "")
    selected = next(
        (item for item in PRODUCTS if str(item["id"]) == product_id),
        None,
    )
    if selected:
        return f"Product ID: {selected['id']} - {selected['name']}"
    return f"No product found for id={product_id}"


@app.route("/login", methods=["GET", "POST"])
def login():
    # VULNERABILITY 3: Passive Web Risks
    # A simple login form missing CSRF protection and allowing password autocomplete.
    if request.method == "POST":
        return "Login attempted (but not implemented)!"
    return render_template("login.html")


@app.route("/api/debug")
def debug_info():
    # VULNERABILITY 4: Information Disclosure
    # A junior developer left a debug endpoint exposed that leaks internal paths and configs.
    debug_data = {
        "status": "running",
        "db_connection": "mysql://root:supersecret123@127.0.0.1:3306/prod_db",
        "internal_path": "/var/www/demo-app/app.py",
        "admin_email": "sysadmin@internal.local"
    }
    return jsonify(debug_data)


if __name__ == "__main__":
    # Binding to 0.0.0.0 is slightly more realistic for a dev trying to access from another machine
    app.run(host="0.0.0.0", port=5000, debug=False)