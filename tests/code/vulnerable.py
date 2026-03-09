import sqlite3

conn = sqlite3.connect("test.db")
cursor = conn.cursor()

username = input("Enter username: ")

query = "SELECT * FROM users WHERE name = '" + username + "'"
cursor.execute(query)