from flask import *
from flask_cors import *
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3

app = Flask(__name__)
CORS(app)
conn = sqlite3.connect("main.db", check_same_thread=False)
c = conn.cursor()

def init_db():
    c.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL)
""")

@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json()
    username = data["username"]
    password = data["password"]
    hashed_password = generate_password_hash(password)
    c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
    conn.commit()
    return jsonify({"message": "User registered successfully!"}), 201

@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data["username"]
    password = data["password"]
    c.execute("SELECT password FROM users WHERE username = ?", (username,))
    result = c.fetchone()
    if result and check_password_hash(result[0], password):
        return jsonify({"message": "Login successful!"}), 200
    else:
        return jsonify({"message": "Invalid username or password!"}), 401
    
@app.route("/api/delete-user", methods=["POST"])
def delete_user():
    data = request.get_json()
    username = data["username"]
    c.execute("DELETE FROM users WHERE username = ?", (username,))
    conn.commit()
    return jsonify({"message": "User deleted successfully!"}), 200

if __name__ == "__main__":
    init_db()
    app.run(debug=True)