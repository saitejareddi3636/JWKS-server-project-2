from flask import Flask, request, jsonify
import jwt
import datetime

app = Flask(__name__)

# Secret key for JWT signing
SECRET_KEY = 'your_secret_key'

# In-memory key store (for demonstration purposes)
# You may replace this with actual key storage logic
KEYS = [
    {
        'kid': '1',
        'n': 'some_public_key_n_value',
        'e': 'AQAB',
        'exp': (datetime.datetime.utcnow() + datetime.timedelta(hours=1)).timestamp()
    },
    {
        'kid': '2',
        'n': 'some_expired_key_n_value',
        'e': 'AQAB',
        'exp': (datetime.datetime.utcnow() - datetime.timedelta(hours=1)).timestamp()
    }
]

# Route for issuing JWTs
@app.route('/auth', methods=['POST'])
def auth():
    expired = request.args.get('expired') == 'true'
    
    # Expiration time for the JWT
    if expired:
        exp_time = datetime.datetime.utcnow() - datetime.timedelta(seconds=10)  # Expired JWT
    else:
        exp_time = datetime.datetime.utcnow() + datetime.timedelta(hours=1)  # Valid JWT
    
    # Create the JWT token
    token = jwt.encode({'exp': exp_time, 'user': 'userABC'}, SECRET_KEY, algorithm='HS256')
    
    # Return the token as JSON
    return jsonify({'token': token})

# JWKS endpoint for serving public keys in JWKS format
@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks():
    # Filter valid keys (unexpired)
    valid_keys = [key for key in KEYS if key['exp'] > datetime.datetime.utcnow().timestamp()]
    
    # Create JWKS response
    jwks_response = {
        'keys': [
            {
                'kid': key['kid'],
                'kty': 'RSA',
                'use': 'sig',
                'alg': 'RS256',
                'n': key['n'],
                'e': key['e']
            } for key in valid_keys
        ]
    }
    
    # Return JWKS response as JSON
    return jsonify(jwks_response)

# Start the server
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8081)  # Changed the port to 8081
