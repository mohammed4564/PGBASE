from flask import Flask, request, jsonify
from flask_cors import CORS
import pyodbc
import bcrypt
import os
from datetime import datetime
from dotenv import load_dotenv
from werkzeug.utils import secure_filename
import base64

# Load .env
load_dotenv()

app = Flask(__name__)
CORS(app)

# Secret key
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

# Upload folder
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# --------------------
# Database connection
# --------------------
def get_connection():
    db_server = os.getenv('DB_SERVER')
    db_database = os.getenv('DB_DATABASE')
    db_username = os.getenv('DB_USERNAME')
    db_password = os.getenv('DB_PASSWORD')
    trust_cert = os.getenv('TRUST_SERVER_CERTIFICATE', 'yes')

    if not all([db_server, db_database, db_username, db_password]):
        raise ValueError("Database configuration is missing in .env")

    conn = pyodbc.connect(
        f"DRIVER={{ODBC Driver 17 for SQL Server}};"
        f"SERVER={db_server};"
        f"DATABASE={db_database};"
        f"UID={db_username};"
        f"PWD={db_password};"
        f"TrustServerCertificate={trust_cert};"
    )
    return conn


# --------------------
# Register API
# --------------------
@app.route('/register', methods=['POST'])
def register():
    try:
        name = request.form.get('name')
        phone_number = request.form.get('phone_number')
        email = request.form.get('email')
        user_type = request.form.get('user_type')
        pg_name = request.form.get('pg_name')
        address = request.form.get('address')
        profession = request.form.get('profession')
        aadhaar_number = request.form.get('aadhaar_number')
        password = request.form.get('password')
        status = "Active"  # Default status value

        # Handle photo
        photo_file = request.files.get('photo')
        photo_data = None
        if photo_file:
            filename = secure_filename(photo_file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            photo_file.save(file_path)
            with open(file_path, 'rb') as f:
                photo_data = f.read()

        # Hash password
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Insert into DB
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO USER_REGISTER
            (NAME, PHONE_NUMBER, EMAIL, USER_TYPE, PG_NAME, PHOTO, ADDRESS, PROFESSION, AADHAAR_NUMBER, PASSWORD_HASH, STATUS)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (name, phone_number, email, user_type, pg_name, photo_data, address, profession, aadhaar_number, password_hash, status))
        
        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({'message': 'User registered successfully!'}), 201

    except pyodbc.IntegrityError:
        return jsonify({'error': 'Email or Aadhaar already exists!'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# --------------------
# Login API
# --------------------
@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.json
        email = data.get('email')
        password = data.get('password')

        conn = get_connection()
        cursor = conn.cursor()

        # Fetch user (no IMAGE_PATH now)
        cursor.execute("""
            SELECT USER_ID, NAME, PHONE_NUMBER, EMAIL, USER_TYPE, PG_NAME, PHOTO,
                   ADDRESS, PROFESSION, AADHAAR_NUMBER, PASSWORD_HASH, STATUS
            FROM USER_REGISTER
            WHERE EMAIL = ?
        """, (email,))
        user = cursor.fetchone()

        if not user:
            cursor.close()
            conn.close()
            return jsonify({'error': 'User not found!'}), 404

        (user_id, name, phone_number, email, user_type, pg_name, photo,
         address, profession, aadhaar_number, password_hash, status) = user

        # ✅ Check if account is active
        if status.lower() != 'active':
            cursor.close()
            conn.close()
            return jsonify({'error': 'Your account is not active. Please contact the administrator.'}), 403

        # Check password
        if not bcrypt.checkpw(password.encode('utf-8'), password_hash):
            cursor.close()
            conn.close()
            return jsonify({'error': 'Invalid password!'}), 401

        # Encode photo if exists
        photo_base64 = base64.b64encode(photo).decode('utf-8') if photo else None

        # Insert login history
        cursor.execute("""
            INSERT INTO LOGIN_HISTORY (USER_ID, LOGIN_TIME, IP_ADDRESS, DEVICE_INFO)
            VALUES (?, ?, ?, ?)
        """, (user_id, datetime.now(), None, None))
        conn.commit()

        cursor.close()
        conn.close()

        return jsonify({
            'message': 'Login successful!',
            'user_id': user_id,
            'name': name,
            'phone_number': phone_number,
            'email': email,
            'user_type': user_type,
            'pg_name': pg_name,
            'photo_base64': photo_base64,
            'address': address,
            'profession': profession,
            'aadhaar_number': aadhaar_number,
            'status': status
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


# --------------------
# Run app
# --------------------
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
