# Student guide

## Follow one request

Flask receives a URL and selects its route. The route checks login and ownership, validates a Flask-WTF form, calls a service and renders a Jinja template or returns a download. A Blueprint groups related routes: accounts, certificates, documents and general pages. The application factory creates an app with its own configuration so tests can use isolated databases and keys.

SQLAlchemy maps Python objects to SQLite rows. The database stores who owns a document and which certificate signed it; it does not magically provide authorization. Every protected route must enforce those associations. Flask-Migrate records schema changes so another installation can reproduce the tables.

## Understand the primitives

A password is a remembered secret. Argon2id turns it into a slow, salted verification hash; login compares through the library. Hashing is not reversible encryption. The private-key file is separately encrypted with a passphrase: knowing the login hash does not directly unlock that file.

An asymmetric pair has a public key that can be shared and a private key that must be protected. RSA-PSS uses the private key to sign and public key to verify. RSA-OAEP uses the public key to wrap a small secret and private key to unwrap it. RSA-3072 is the key size, not the maximum document size.

AES is symmetric: the same secret key encrypts and decrypts. GCM also checks an authentication tag. A nonce is a unique-per-key input that must never repeat with that key. This application generates a fresh AES key and nonce for every package. The tag is included at the end of the library's ciphertext. A changed bit fails authentication.

SHA-256 is a fingerprint of bytes. It detects change only if the expected fingerprint is trusted. A signature is stronger evidence because it requires a protected private key. CertiVault signs actual bytes using the library; it does not manually implement RSA or “encrypt a hash.”

## Understand certificates

PKI is the system connecting identities and keys through certificates, issuers and lifecycle rules. A CA signs a certificate containing a public key and identity attributes. X.509 is the certificate format. A trusted issuer name alone is not enough: the issuer's cryptographic signature must verify against the pinned CA.

CertiVault's root is educational. Registration binds a self-declared local account to a generated key; there is no real university identity investigation. The leaf certificate includes account ID, username, email, validity, random serial, public key and permitted usages. Its serial identifies the issuance; its SHA-256 fingerprint identifies the exact DER certificate bytes.

Validation checks trust, dates, account binding, usages and revocation. Expiry occurs automatically at the validity end. Revocation is an early permanent rejection recorded with a reason and actor. This prototype checks a local database instead of publishing OCSP or CRLs. Password login still works after revocation; certificate-based operations do not.

## Why hybrid encryption?

RSA is unsuitable for directly encrypting a large file. Generate a fresh AES key, encrypt the file with AES-GCM, then wrap only that key with recipient RSA-OAEP. The recipient unlocks the private key, unwraps AES and authenticates/decrypts the data. The package header binds recipient, certificate, file name and algorithms as authenticated metadata. Authorization checks happen before cryptography to prevent unnecessary access and attempts.

## Why a challenge?

A certificate is public, so uploading it proves nothing about possession of a secret. The server issues fresh random bytes; a local client signs them. The server verifies with the public key. A challenge expires after three minutes and is consumed atomically before verification, so a captured response cannot simply be replayed. Browser binding prevents use in a different session. Ordinary signing happens on the server after key unlocking; this certificate-auth flow signs locally.

## Explain security honestly

TLS protects communication. File encryption protects package contents. Ephemeral TLS key exchange can provide forward secrecy, but recorded RSA-wrapped files may be decrypted after later private-key theft. A digital signature does not provide confidentiality, and encryption alone does not independently prove the sender's identity.

Auditing records actions, outcomes and safe identifiers, never passwords or secret keys. Logs aid investigation but are ordinary database rows, not tamper-proof evidence. Application admins can revoke certificates and inspect events; they cannot use that role to read another user's private files through the UI. Host administrators are more powerful and remain trusted.

## Study and demonstrate

Start with README setup and fake seed identities. Trace registration in `services.py` and `pki.py`, signing in `documents.py`, algorithms in `crypto/primitives.py` and challenge handling in `services.py`. Read tests alongside the code: each negative case should fail for a specific reason, not because of an unrelated setup error.

Use `docs/video-demo.md` for a narrative and `docs/viva-questions.md` for practice. Be ready to distinguish implemented protection from future work: offline roots, HSMs, renewal, email proofing, malware scanning and independently audited production deployment are not present.
