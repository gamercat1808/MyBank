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
    c.execute("""
    CREATE TABLE IF NOT EXISTS cofres (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user TEXT NOT NULL,
        name TEXT NOT NULL,
        points INTEGER DEFAULT 0)
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
    
@app.route("/api/cofre", methods=["POST"])
def cofre():
    data = request.get_json()
    name = data["name"]
    username = data["username"]
    points_to_move = data["points"]

    if points_to_move <= 0:
        return jsonify({"message": "Quantidade inválida!"}), 400

    # 1. Verificar se o usuário tem pontos suficientes
    c.execute("SELECT points FROM users WHERE username = ?", (username,))
    user_result = c.fetchone()

    if not user_result or user_result[0] < points_to_move:
        return jsonify({"message": "Saldo insuficiente para depositar no cofre!"}), 400

    # 2. Verificar se o cofre existe e pertence ao usuário (ou se deve ser criado)
    c.execute("SELECT * FROM cofres WHERE name = ? AND user = ?", (name, username))
    cofre_result = c.fetchone()

    try:
        # 3. Subtrair pontos do usuário
        c.execute("UPDATE users SET points = points - ? WHERE username = ?", (points_to_move, username))

        if cofre_result:
            # Atualiza cofre existente
            c.execute("UPDATE cofres SET points = points + ? WHERE name = ? AND user = ?", 
                      (points_to_move, name, username))
        else:
            # Cria novo cofre com os pontos iniciais
            c.execute("INSERT INTO cofres (name, user, points) VALUES (?, ?, ?)", 
                      (name, username, points_to_move))

        conn.commit()
        return jsonify({"message": f"{points_to_move} pontos movidos para o cofre com sucesso!"}), 200
    
    except Exception as e:
        conn.rollback()
        return jsonify({"message": "Erro ao processar transação."}), 500

@app.route("/api/new-cofre", methods=["POST"])
def new_cofre():
    data = request.get_json()
    name = data["name"]
    username = data["username"]
    c.execute("INSERT INTO cofres (name, user) VALUES (?, ?)", (name, username))
    conn.commit()
    return jsonify({"message": "Cofre created successfully!"}), 201

if __name__ == "__main__":
    init_db()
    app.run(debug=True)
