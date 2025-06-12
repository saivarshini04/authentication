# registration_server.py
from flask import Flask, request, jsonify
from shared import generate_key_pair, serialize_key
import pyotp

app = Flask(__name__)
user_db = {}

# Route for registering a user
@app.route('/register', methods=['POST'])
def register():
    user_id = request.json['user_id']
    private_key, public_key = generate_key_pair()
    totp_secret = pyotp.random_base32()

    # Save user data (for simplicity, in-memory db)
    user_db[user_id] = {
        'public_key': serialize_key(public_key),
        'totp_secret': totp_secret
    }

    return jsonify({
        'private_key': serialize_key(private_key, private=True),
        'public_key': serialize_key(public_key),
        'totp_secret': totp_secret
    })

# Route to fetch user data (for authentication)
@app.route('/get_user/<user_id>', methods=['GET'])
def get_user(user_id):
    user = user_db.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    return jsonify(user)

if __name__ == '__main__':
    app.run(port=5000)  # Run on port 5000
