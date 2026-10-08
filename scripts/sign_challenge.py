"""Offline signer: no private key or passphrase is sent to the server."""
import argparse
import base64
import getpass
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--key', required=True, help='Encrypted PKCS#8 PEM file')
parser.add_argument('--challenge-id', required=True)
parser.add_argument('--nonce', required=True)
args = parser.parse_args()
key = serialization.load_pem_private_key(Path(args.key).read_bytes(), getpass.getpass('Key passphrase: ').encode())
message = ('CertiVault certificate authentication v1\n'+args.challenge_id+'\n'+args.nonce).encode()
signature = key.sign(message, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())
print(base64.b64encode(signature).decode())
