import sqlite3
import time
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# Connect to the database
conn = sqlite3.connect('totally_not_my_privateKeys.db')
cursor = conn.cursor()

def generate_and_store_key(expiration_hours):
    """Generate an RSA private key and store it in the database with expiration."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    exp_time = int((time.time() + expiration_hours * 3600))  # Convert hours to seconds
    cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (pem, exp_time))
    conn.commit()
    print(f"Inserted key with expiration time: {exp_time}")  # Feedback on insertion

# Generate and store keys
print("Generating and storing valid key...")
generate_and_store_key(expiration_hours=1)   # Valid key
print("Generating and storing expired key...")
generate_and_store_key(expiration_hours=-1)  # Expired key

# Close the connection
conn.close()
print("Keys inserted successfully. Database connection closed.")
