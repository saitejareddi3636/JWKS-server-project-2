from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import base64
import jwt
import datetime
import sqlite3
import uuid

app = Flask(__name__)

# Database path and connection
DB_PATH = "totally_not_my_privateKeys.db"
conn = sqlite3.connect(DB_PATH, check_same_thread=False)
cursor = conn.cursor()

# Ensure the database table exists
cursor.execute('''
    CREATE TABLE IF NOT EXISTS keys (
        kid TEXT PRIMARY KEY,
        key BLOB NOT NULL,
        exp INTEGER NOT NULL
    )
''')
conn.commit()

def generate_and_store_key(expiration_hours):
    """Generate an RSA private key and store it in the database with expiration and kid."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Calculate expiration time as a UNIX timestamp
    exp_time = int((datetime.datetime.now() + datetime.timedelta(hours=expiration_hours)).timestamp())
    kid = str(uuid.uuid4())  # Generate a unique key ID (kid)

    # Store the key in the database
    cursor.execute("INSERT INTO keys (kid, key, exp) VALUES (?, ?, ?)", (kid, sqlite3.Binary(pem), exp_time))
    conn.commit()
    return private_key, kid

# Generate and store initial keys for testing
generate_and_store_key(expiration_hours=1)   # Valid key
generate_and_store_key(expiration_hours=-1)  # Expired key

@app.route('/auth', methods=['POST'])
def auth():
    """Authenticate and generate JWT token."""
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Authorization header missing or malformed"}), 401

    token = auth_header.split(" ")[1]
    try:
        decoded_token = jwt.decode(token, options={"verify_signature": False})
        if "exp" in decoded_token and datetime.datetime.fromtimestamp(decoded_token["exp"]) < datetime.datetime.now():
            return jsonify({"error": "Token expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid JWT token"}), 401

    return jsonify({"message": "Token is valid"}), 200

@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks():
    """Return JSON Web Key Set (JWKS) with all valid keys."""
    current_time = int(datetime.datetime.now().timestamp())
    cursor.execute("SELECT key, kid FROM keys WHERE exp > ?", (current_time,))
    keys = cursor.fetchall()

    jwks = {"keys": []}
    for (key_pem, kid) in keys:
        private_key = serialization.load_pem_private_key(key_pem, password=None)
        public_key = private_key.public_key()
        public_numbers = public_key.public_numbers()

        jwks["keys"].append({
            "alg": "RS256",
            "kty": "RSA",
            "use": "sig",
            "kid": kid,
            "n": base64.urlsafe_b64encode(public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, 'big')).decode('utf-8'),
            "e": base64.urlsafe_b64encode(public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, 'big')).decode('utf-8')
        })

    return jsonify(jwks), 200

if __name__ == '__main__':
    app.run(host="localhost", port=5000, debug=True)
