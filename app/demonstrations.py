"""Run actual negative cryptographic cases with ephemeral keys and data."""
import copy
from cryptography.exceptions import InvalidSignature, InvalidTag
from .crypto.primitives import keypair, sign, verify, encrypt, decrypt, unb64, b64

def run_demonstrations():
    alice, bob = keypair(), keypair()
    content = b'CertiVault fictional transcript: grade A'
    signature = sign(alice, content)
    metadata = {'recipient':1,'sender':2}
    package = encrypt(alice.public_key(), content, metadata)
    tampered = copy.deepcopy(package)
    raw = bytearray(unb64(tampered['ciphertext']))
    raw[0] ^= 1
    tampered['ciphertext'] = b64(bytes(raw))
    results = []
    def rejected(label, operation, exceptions):
        try:
            operation()
            results.append((label, False))
        except exceptions:
            results.append((label, True))
    rejected('Document tampering detected', lambda:verify(alice.public_key(), signature, content+b' modified'), (InvalidSignature,))
    rejected('Wrong signer rejected', lambda:verify(bob.public_key(), signature, content), (InvalidSignature,))
    rejected('Wrong private key rejected', lambda:decrypt(bob, package, metadata), (ValueError,))
    rejected('Ciphertext tampering detected', lambda:decrypt(alice, tampered, metadata), (InvalidTag,))
    rejected('Recipient metadata substitution detected', lambda:decrypt(alice, package, {'recipient':3,'sender':2}), (ValueError,))
    results.append(('Original encryption round trip', decrypt(alice, package, metadata) == content))
    return results
