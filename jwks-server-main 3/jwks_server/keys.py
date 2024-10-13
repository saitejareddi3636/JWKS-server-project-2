import time
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_key():
    # Generate a private key
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Assign a key ID and expiry timestamp
    kid = "key_" + str(int(time.time()))
    expiry = time.time() + 3600  # 1 hour expiration

    # Convert keys to PEM format
    private_key = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_key = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return {
        "kid": kid,
        "private_key": private_key.decode('utf-8'),
        "public_key": public_key.decode('utf-8'),
        "expiry": expiry
    }

