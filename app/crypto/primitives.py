"""Library-backed algorithms. Never persist an unwrapped content key."""
import base64
import hashlib
import json
import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH)
OAEP = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)

def keypair():
    return rsa.generate_private_key(public_exponent=65537, key_size=3072)

def protect(key, passphrase):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.BestAvailableEncryption(passphrase.encode()))

def unlock(data, passphrase):
    return serialization.load_pem_private_key(data, password=passphrase.encode())

def digest(data):
    return hashlib.sha256(data).hexdigest()

def sign(key, data):
    return key.sign(data, PSS, hashes.SHA256())

def verify(key, signature, data):
    key.verify(signature, data, PSS, hashes.SHA256())

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()

def b64(data):
    return base64.b64encode(data).decode()

def unb64(value):
    return base64.b64decode(value, validate=True)

def encrypt(public_key, data, metadata):
    header = dict(metadata, version=1, content_algorithm='AES-256-GCM', wrap_algorithm='RSA-OAEP-SHA256')
    key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    return dict(header=header, wrapped_key=b64(public_key.encrypt(key, OAEP)), nonce=b64(nonce),
                ciphertext=b64(AESGCM(key).encrypt(nonce, data, canonical(header))))

def decrypt(private_key, package, expected_metadata):
    if set(package) != {'header', 'wrapped_key', 'nonce', 'ciphertext'}:
        raise ValueError('Invalid package')
    header = package['header']
    expected = dict(expected_metadata, version=1, content_algorithm='AES-256-GCM', wrap_algorithm='RSA-OAEP-SHA256')
    if header != expected:
        raise ValueError('Package identity or algorithm mismatch')
    nonce = unb64(package['nonce'])
    if len(nonce) != 12:
        raise ValueError('Invalid nonce')
    key = private_key.decrypt(unb64(package['wrapped_key']), OAEP)
    if len(key) != 32:
        raise ValueError('Invalid content key')
    return AESGCM(key).decrypt(nonce, unb64(package['ciphertext']), canonical(header))
