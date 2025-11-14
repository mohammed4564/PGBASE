from flask import Flask, request, jsonify
from flask_cors import CORS
import pyodbc
import os
from datetime import datetime
from dotenv import load_dotenv
import base64

# Load .env
load_dotenv()

app = Flask(__name__)
CORS(app)

# Database credentials
DB_SERVER = os.getenv('DB_SERVER')
DB_DATABASE = os.getenv('DB_DATABASE')
DB_USERNAME = os.getenv('DB_USERNAME')
DB_PASSWORD = os.getenv('DB_PASSWORD')

# --- DB connection ---
def get_connection():
    conn = pyodbc.connect(
        f"DRIVER={{ODBC Driver 17 for SQL Server}};"
        f"SERVER={DB_SERVER};"
        f"DATABASE={DB_DATABASE};"
        f"UID={DB_USERNAME};"
        f"PWD={DB_PASSWORD};"
    )
    return conn


# -----------------------------
# REGISTER API
# -----------------------------
@app.route('/register', methods=['POST'])
def register():
    try:
        # Required fields
        name = request.form.get('name')
        phone_number = request.form.get('phone_number')
        email = request.form.get('email')
        password = request.form.get('password')
        print(password)
        user_type = request.form.get('user_type')

        if not all([name, phone_number, email, password, user_type]):
            return jsonify({"error": "Missing required fields"}), 400

        # Optional fields
        pg_name = request.form.get('pg_name')
        address = request.form.get('address')
        profession = request.form.get('profession')
        aadhaar_number = request.form.get('aadhaar_number')

    
        # --- Handle Photo ---
        photo_file = request.files.get('photo')
        photo_data = photo_file.read() if photo_file else None

        # DB INSERT
        conn = get_connection()
        cursor = conn.cursor()

        # Check duplicate email
        cursor.execute("SELECT COUNT(*) FROM USERS_REGISTER WHERE EMAIL = ?", email)
        if cursor.fetchone()[0] > 0:
            return jsonify({"error": "Email already registered"}), 400

        cursor.execute("""
            INSERT INTO USERS_REGISTER
            (NAME, PHONE_NUMBER, EMAIL, PASSWORD_HASH, USER_TYPE, STATUS, CREATED_AT,
             PG_NAME, ADDRESS, PROFESSION, AADHAAR_NUMBER, PHOTO)
            VALUES (?, ?, ?, ?, ?, ?, GETDATE(), ?, ?, ?, ?, ?)
        """, (
            name, phone_number, email, password,
            user_type, "ACTIVE", pg_name, address, profession,
            aadhaar_number, photo_data
        ))

        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({"message": "User registered successfully"}), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# -----------------------------
# LOGIN API (NO HASHING)
# -----------------------------
@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.json
        email = data.get("email")
        password = data.get("password")  # plain password

        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT USER_ID, NAME, PHONE_NUMBER, EMAIL, USER_TYPE, PG_NAME, PHOTO,
                   ADDRESS, PROFESSION, AADHAAR_NUMBER, PASSWORD_HASH, STATUS
            FROM USERS_REGISTER
            WHERE EMAIL = ?
        """, (email,))
        user = cursor.fetchone()

        if not user:
            return jsonify({"error": "User not found"}), 404

        (user_id, name, phone_number, email, user_type, pg_name, photo,
         address, profession, aadhaar_number, stored_password, status) = user

        # Check account status
        if status.lower() != "active":
            return jsonify({"error": "Account not active"}), 403

        # ----------------------------
        #  Plain password comparison
        # ----------------------------
        if password != stored_password:
            return jsonify({"error": "Invalid password"}), 401

        # Convert photo to base64
        photo_base64 = base64.b64encode(photo).decode() if photo else None

        cursor.close()
        conn.close()

        return jsonify({
            "message": "Login successful",
            "user_id": user_id,
            "name": name,
            "phone_number": phone_number,
            "email": email,
            "user_type": user_type,
            "pg_name": pg_name,
            "photo_base64": photo_base64,
            "address": address,
            "profession": profession,
            "aadhaar_number": aadhaar_number,
            "status": status,
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# -----------------------------
# RUN SERVER
# -----------------------------
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
