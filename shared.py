# shared.py
import os
import pyotp
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

# Generate RSA key pair
def generate_key_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

# Serialize the RSA keys
def serialize_key(key, private=False):
    if private:
        return key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        ).decode()
    else:
        return key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

# Deserialize the public key
def deserialize_public_key(pem_str):
    return serialization.load_pem_public_key(pem_str.encode())

# Deserialize the private key
def deserialize_private_key(pem_str):
    return serialization.load_pem_private_key(pem_str.encode(), password=None)

# Sign data using the private key
def sign_data(private_key, data):
    return private_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

# Verify the signature of the data
def verify_signature(public_key, data, signature):
    try:
        public_key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
        return True
    except:
        return False
