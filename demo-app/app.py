from flask import Flask, render_template, request

app = Flask(__name__)

# Fake product data used for the demo pages.
PRODUCTS = [
    {"id": 1, "name": "Red Widget"},
    {"id": 2, "name": "Blue Widget"},
    {"id": 3, "name": "Green Widget"},
]


@app.route("/")
def index():
    # Homepage with links for scanner crawling.
    return render_template("index.html")


@app.route("/about")
def about():
    # Simple static page.
    return render_template("about.html")


@app.route("/products")
def products():
    # Shows a small hardcoded product list.
    return render_template("products.html", products=PRODUCTS)


@app.route("/product")
def product():
    # Reads the id query parameter for simple local testing.
    product_id = request.args.get("id", "")

    selected = next(
        (item for item in PRODUCTS if str(item["id"]) == product_id),
        None,
    )

    if selected:
        return f"Product ID: {selected['id']} - {selected['name']}"

    return f"No product found for id={product_id}"


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
