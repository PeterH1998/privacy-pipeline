import sqlite3

conn = sqlite3.connect("test.db")
cursor = conn.cursor()

user = input("username: ")
query = "SELECT * FROM users WHERE name='" + user + "'"

cursor.execute(query)