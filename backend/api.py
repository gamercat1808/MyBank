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
        points INTEGER DEFAULT 0,
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

@app.route("/api/give", methods=["POST"])
def give_points():
    data = request.get_json()
    from_user = data["from_user"]
    to_user = data["to_user"]
    points = data["points"]
    
    c.execute("SELECT points FROM users WHERE username = ?", (from_user,))
    from_points = c.fetchone()
    
    if from_points and from_points[0] >= points:
        c.execute("UPDATE users SET points = points - ? WHERE username = ?", (points, from_user))
        c.execute("UPDATE users SET points = points + ? WHERE username = ?", (points, to_user))
        conn.commit()
        return jsonify({"message": "Points transferred successfully!"}), 200
    else:
        return jsonify({"message": "Insufficient points!"}), 400
    
@app.route("/api/admin/give", methods=["POST"])
def admin_give_points():
    data = request.get_json()
    to_user = data["to_user"]
    points = data["points"]
    
    c.execute("UPDATE users SET points = points + ? WHERE username = ?", (points, to_user))
    conn.commit()
    return jsonify({"message": "Points added successfully!"}), 200

@app.route("/api/admin/balance/<username>")
def admin_balance(username):
    c.execute("SELECT points FROM users WHERE username = ?", (username,))
    result = c.fetchone()
    if result:
        return jsonify({"username": username, "points": result[0]}), 200
    else:
        return jsonify({"message": "User not found!"}), 404
    

if __name__ == "__main__":
    init_db()
    app.run(debug=True)
