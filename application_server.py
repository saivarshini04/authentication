# application_server.py
from flask import Flask, request, jsonify
import requests
from shared import deserialize_public_key, verify_signature
import pyotp

app = Flask(__name__)
REG_SERVER_URL = 'http://localhost:5000'  # Registration Server URL

# Route for user authentication
@app.route('/authenticate', methods=['POST'])
def authenticate():
    data = request.json
    user_id = data['user_id']
    challenge = bytes.fromhex(data['challenge'])
    signature = bytes.fromhex(data['signature'])
    totp_code = data['totp_code']

    # Fetch public key and TOTP secret from the registration server
    user_data = requests.get(f'{REG_SERVER_URL}/get_user/{user_id}').json()
    if 'error' in user_data:
        return jsonify({'success': False, 'message': 'User not found'})

    public_key = deserialize_public_key(user_data['public_key'])
    totp = pyotp.TOTP(user_data['totp_secret'])

    # Verify the signature
    if not verify_signature(public_key, challenge, signature):
        return jsonify({'success': False, 'message': 'Invalid signature'})

    # Verify the TOTP code
    if not totp.verify(str(totp_code)):
        return jsonify({'success': False, 'message': 'Invalid TOTP'})

    return jsonify({'success': True, 'message': 'Authentication successful'})

if __name__ == '__main__':
    app.run(port=6000)  # Run on port 6000
