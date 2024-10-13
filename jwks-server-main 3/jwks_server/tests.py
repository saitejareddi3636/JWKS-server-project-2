import unittest
from app import app
import json

class JWKSAppTestCase(unittest.TestCase):
    def setUp(self):
        # Set up the test client for the Flask app
        self.app = app.test_client()
        self.app.testing = True

    def test_auth_valid_jwt(self):
        # Test the /auth endpoint without expired query parameter (valid JWT)
        response = self.app.post('/auth')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('token', data)

    def test_auth_expired_jwt(self):
        # Test the /auth endpoint with expired query parameter (expired JWT)
        response = self.app.post('/auth?expired=true')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('token', data)

    def test_jwks_endpoint(self):
        # Test the /.well-known/jwks.json endpoint
        response = self.app.get('/.well-known/jwks.json')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('keys', data)
        self.assertGreater(len(data['keys']), 0)

    def test_jwks_no_expired_keys(self):
        # Test that no expired keys are returned by the JWKS endpoint
        response = self.app.get('/.well-known/jwks.json')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        for key in data['keys']:
            self.assertNotEqual(key['kid'], '2')  # Ensure expired key is not present

if __name__ == '__main__':
    unittest.main()
