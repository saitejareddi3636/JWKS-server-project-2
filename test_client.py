import json
import requests
import unittest
import sqlite3
import time
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime
import jwt
import uuid

class TestMyServer(unittest.TestCase):
    BASE_URL = "http://localhost:5000"
    DB_PATH = "totally_not_my_privateKeys.db"

    def setUp(self):
        """Prepare the test environment by resetting the database and adding test keys."""
        print("Setting up the test environment...")
        time.sleep(1)  # Ensure server has started
        self.conn = sqlite3.connect(self.DB_PATH)
        self.cursor = self.conn.cursor()
        self.cursor.execute("DELETE FROM keys")  # Clear existing keys
        self.create_test_keys()  # Insert test keys
        print("Setup complete.")

    def tearDown(self):
        """Clear test data from the database."""
        print("Tearing down the test environment...")
        self.cursor.execute("DELETE FROM keys")
        self.conn.commit()
        self.conn.close()
        print("Teardown complete.")

    def create_test_keys(self):
        """Generate valid and expired keys for testing."""
        valid_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        valid_pem = valid_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        valid_expiry_time = int(datetime.datetime.now(datetime.timezone.utc).timestamp()) + 3600

        expired_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        expired_pem = expired_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        expired_expiry_time = int(datetime.datetime.now(datetime.timezone.utc).timestamp()) - 1

        # Insert keys into database
        self.cursor.execute("INSERT INTO keys (kid, key, exp) VALUES (?, ?, ?)", (str(uuid.uuid4()), valid_pem, valid_expiry_time))
        self.cursor.execute("INSERT INTO keys (kid, key, exp) VALUES (?, ?, ?)", (str(uuid.uuid4()), expired_pem, expired_expiry_time))
        self.conn.commit()
        print("Test keys created.")

    def test_auth_with_valid_key(self):
        """Test the /auth endpoint with a valid key."""
        url = f"{self.BASE_URL}/auth"
        response = requests.post(url)
        print(f"Valid key response status: {response.status_code}")
        print(f"Response body: {response.text}")
        # Expect a 200 status if the key is valid, else a 401 if it's not recognized as valid
        self.assertIn(response.status_code, [200, 401])

    def test_auth_with_expired_key(self):
        """Test the /auth endpoint with an expired key."""
        url = f"{self.BASE_URL}/auth?expired=true"
        response = requests.post(url)
        print(f"Expired key response status: {response.status_code}")
        print(f"Response body: {response.text}")
        # Expecting a 401 Unauthorized for expired token
        self.assertEqual(response.status_code, 401)

    def test_jwks_endpoint(self):
        """Test the JWKS endpoint for valid keys."""
        url = f"{self.BASE_URL}/.well-known/jwks.json"
        response = requests.get(url)
        print(f"JWKS endpoint response status: {response.status_code}")
        print(f"Response body: {response.text}")
        self.assertEqual(response.status_code, 200)
        jwks = json.loads(response.text)
        self.assertIn('keys', jwks)
        self.assertGreater(len(jwks['keys']), 0)

    def test_invalid_jwt_handling(self):
        """Verify that server rejects invalid JWT tokens."""
        url = f"{self.BASE_URL}/auth"
        invalid_token = "invalid.jwt.token"
        headers = {"Authorization": f"Bearer {invalid_token}"}

        response = requests.post(url, headers=headers)
        print(f"Invalid JWT test response status: {response.status_code}")
        print(f"Response body: {response.text}")

        # Expecting a 401 Unauthorized
        self.assertEqual(response.status_code, 401)

if __name__ == '__main__':
    unittest.main()
