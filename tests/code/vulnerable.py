from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route("/user")
def user():
    username = request.args.get("name", "")
    conn = sqlite3.connect("test.db")
    cursor = conn.cursor()

    query = "SELECT * FROM users WHERE name = '" + username + "'"
    cursor.execute(query)

    return "done"