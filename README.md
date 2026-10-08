# CertiVault

**Secure. Sign. Verify. Protect.**

Design and Development of an Open-Source PKI-Based Platform for Secure Document Authentication, Digital Signatures, Hybrid Encryption and Certificate Lifecycle Management.

CertiVault is a working Flask application for a Practical Cryptography university project. It demonstrates secure university document exchange: signed transcripts, confidential coursework and verifiable recommendation letters. An internal educational CA connects account identities to RSA public keys. Real cryptographic operations run through the Python `cryptography` library.

## Problem and objectives

A document's appearance does not establish its author, integrity or intended audience. CertiVault demonstrates three distinct properties: **confidentiality** through recipient encryption, **integrity** through signature verification, and **authentication** through password login or a private-key challenge. It provides inspectable evidence rather than implying that one property supplies all three.

## Features

- Registration and Argon2id password authentication; Flask-Login sessions and CSRF-protected forms.
- RSA-3072 identities, signed CSRs, X.509 issuance, encrypted PKCS#8 key custody, public certificate export.
- Pinned local CA, cryptographic issuer-signature checks, dates, identity, extensions and persistent revocation.
- Three-minute, browser-bound challenges with atomic single-use consumption; local offline challenge signing.
- Private document uploads, owner authorization, SHA-256 fingerprints and signature history.
- RSA-PSS signing, detached evidence export and independent verifier uploads with an expected signer.
- Fresh AES-256-GCM keys and 96-bit nonces, RSA-OAEP key wrapping, authenticated package metadata.
- Recipient-only decryption and download; no decrypted temporary files.
- USER / ADMIN roles, password-confirmed revocation, security audit history and isolated demonstrations.
- Responsive Jinja/Bootstrap interface, local assets, security headers and sensitive-route rate limits.
- Flask-Migrate schema, development-only seed command, automated security tests and academic guides.

## Technology and algorithms

Python 3.12+, Flask application factory and Blueprints, Jinja2, locally vendored Bootstrap 5.3.8, minimal vanilla JavaScript, SQLAlchemy, SQLite, Flask-Migrate, Flask-WTF, Flask-Login, Flask-Limiter, python-dotenv, cryptography, argon2-cffi and pytest. No Node runtime is needed.

| Purpose | Algorithm / policy |
| --- | --- |
| Passwords | Argon2id; 64 MiB memory, 3 iterations, 4 lanes |
| Identity | RSA-3072, public exponent 65537 |
| Signatures | RSA-PSS, SHA-256, MGF1-SHA-256, 32-byte salt |
| File encryption | AES-256-GCM, fresh key and 12-byte nonce per package, full 128-bit tag |
| Key wrapping | RSA-OAEP, SHA-256 and MGF1-SHA-256 |
| Fingerprints | SHA-256 |
| Certificates | X.509, RSA-PSS CA signatures, usage and identity extensions |
| Private keys | Password-encrypted PKCS#8 using library BestAvailableEncryption |

## Docker deployment

Docker Compose runs CertiVault with Gunicorn and persistent database/key storage:

```bash
test -f .env || python scripts/configure.py
docker compose up -d --build --wait
docker compose exec web flask --app run seed-demo
```

Open **http://localhost:8000**. See [Docker deployment](docs/docker.md) for CachyOS installation, optional Caddy HTTPS, backups and updates. Docker was unavailable in the authoring environment; bootstrap tests and Gunicorn configuration were verified, but container execution remains to be checked on your host.

## CachyOS / Arch Linux installation

Run these commands in a terminal. Do not use the system Python environment for pip dependencies.

```bash
sudo pacman -Syu --needed git python python-pip
git clone https://github.com/kali-guru/CertiVault.git
cd CertiVault
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python scripts/configure.py
flask --app run db upgrade
flask --app run init-ca
flask --app run verify-security-config
flask --app run seed-demo
flask --app run run --host 127.0.0.1 --port 5000
```

Open **http://127.0.0.1:5000**. The repeated `run` is intentional: the first selects `run.py`; the second is Flask's server command. Debugging is off by default. `init-ca` refuses to replace an existing CA. Run it only once. `configure.py` creates mode-0600 `.env` with fresh random secrets and refuses to overwrite an existing file. `.env.example` documents settings; do not run with its empty placeholders.

Python wheels are normally sufficient. If your Arch Python release is too new for available binary wheels, use a supported Python 3.12–3.14 environment or install the required compiler/build dependencies for the package reporting the failure.

For the exact dependency versions used in the recorded Python 3.12 test run, install `requirements-lock.txt`. The main requirements file allows compatible updates; re-run tests after dependency changes.

### Configuration and storage

`SECRET_KEY` signs sessions. `CA_PASSPHRASE` encrypts the CA private key. Keep both random, independent and backed up securely. Changing the CA passphrase does not re-encrypt an existing CA key. `APP_ENV=production` requires `SESSION_COOKIE_SECURE=true`; serve only through HTTPS. `MAX_CONTENT_LENGTH` defaults to 16 MiB for the entire multipart request. `CERTIVAULT_INSTANCE` may select an absolute private instance directory.

SQLite and runtime files live under ignored `instance/`: `certivault.db`, `ca/`, `key_vault/`, `uploads/`, `encrypted/`. Do not serve this directory. Originals are stored unencrypted behind application and filesystem authorization. Encrypted recipient packages are a separate artifact, not a replacement for the original. Back up the database and private instance files as a consistent set, with encryption and access controls.

### Demo accounts

`flask --app run seed-demo` prompts for a password you choose (at least 12 characters). No preset password is shipped. It is disabled outside development.

| Username | Fictional identity | Role |
| --- | --- | --- |
| alice | alice.student@example.test | USER |
| bob | bob.lecturer@example.test | USER |
| carol | carol.admin@example.test | ADMIN |
| employer | employer.verifier@example.test | USER |

Use `flask --app run create-admin` for a separately configured administrator. Roles represent application authorization; persona labels do not prove real institutional employment. Registration uses self-declared identities without email or university identity verification.

## Demo workflow

1. Log in as Carol; upload `examples/official_transcript.txt`; sign it with your chosen key password.
2. Download the original and signature evidence JSON. Log in as Employer, choose Verify signature, upload both and enter expected signer `carol`.
3. Modify a copy of the transcript and verify again: the signature fails. The original remains unchanged.
4. Log in as Alice; upload `examples/coursework.txt`; encrypt it for Bob. Alice can download the ciphertext package but cannot decrypt it through the app.
5. Log in as Bob; open Encrypted exchange, decrypt and download. Tampered ciphertext or wrong passwords fail safely.
6. As Bob, sign `examples/recommendation.txt`. Employer verifies it with expected signer `bob`.
7. Inspect the certificate's issuer, dates, usage, serial, fingerprint and status. Validate an exported public certificate.
8. Run Security laboratory. Run `pytest -v` for additional database-backed attacks.
9. Revoke a demonstration certificate only after completing encryption/decryption: revocation is permanent and blocks its decryption workflow too.

### Certificate authentication

While signed in, export your **encrypted** private key (password confirmation required) and public certificate. Log out and visit Certificate login. Request a challenge using your username. In a terminal on your own machine:

```bash
python scripts/sign_challenge.py \
  --key /path/to/certivault-encrypted-key.pem \
  --challenge-id COPY_THE_CHALLENGE_ID \
  --nonce COPY_THE_NONCE
```

Enter the key passphrase at the hidden prompt. Paste the printed base64 signature and challenge ID into the proof form and attach the public certificate. Keep the requesting browser session open. No private key is uploaded by this flow. A successful proof establishes a session. An invalid attempt also consumes its challenge; request another. Expired, replayed, foreign-browser, revoked or mismatched proofs are rejected.

### Lifecycle and verification semantics

Registration generates a key, signs a CSR, issues a one-year leaf certificate and stores it. Validation returns VALID, EXPIRED, REVOKED, UNTRUSTED ISSUER, INVALID SIGNATURE, IDENTITY MISMATCH or INVALID CERTIFICATE. Certificates are never deleted to erase their history. Revocation records the actor, time and reason. There is no automated renewal or key recovery: preserve keys and finish demo decryptions before revocation/expiry.

Signature verification checks **current** certificate status; it does not establish that the certificate was valid at some historical signing time. Displayed signing time is metadata, not a trusted timestamp. The detached evidence digest and labels are not separately signed; the actual RSA-PSS signature over exact document bytes and the pinned certificate determine acceptance. Signed evidence proves control of a key associated with an account, not independently vetted real-world identity.

## Testing

```bash
pytest -v
pytest --cov=app --cov-report=term-missing
```

Tests use temporary databases, CAs and keys. Never point testing at a live instance. See [testing evidence](docs/testing.md), [security review](docs/security-review.md) and [demonstration script](docs/video-demo.md). Test results reflect executed checks, not a production security certification.

## Architecture and repository

```text
app/
  __init__.py          application factory and headers
  extensions.py       database, migration, login, CSRF and limiter
  models.py           eight persistent domain models
  auth.py             account and certificate authentication routes
  documents.py        upload, signature and encryption workflows
  certificates.py     validation, export and revocation
  web.py              public, dashboard, audit and admin routes
  services.py         account, challenge and verification logic
  pki.py              CA, CSR, issuance, trust checks and key vault
  crypto/primitives.py library-backed cryptographic operations
  demonstrations.py   isolated negative cryptography experiments
  cli.py              safe management commands
  templates/          complete Jinja interface
  static/             local Bootstrap, CSS and minimal JavaScript
migrations/           versioned database schema
tests/                real crypto and HTTP security tests
scripts/              configuration and offline challenge signer
examples/             fictional demonstration documents
docs/                 architecture, threat model, guides and viva
```

An online educational root CA issues leaves directly. Blueprints call shared services; private files are referenced by unpredictable generated names; SQLAlchemy stores identities and evidence. See [architecture diagrams](docs/architecture.md).

## Security considerations and limitations

This is an educational prototype, **not production PKI**. It uses an online root, server-side signing/decryption, encrypted keys unlocked in process memory, in-process rate limiting and SQLite. A compromised application can capture submitted key passphrases. Administrators with OS/database access can bypass application policy. Audit logs are not append-only or tamper-evident. No OCSP/CRL publication, trusted timestamps, malware scanner, email verification, password reset, key recovery, automatic renewal or institutional identity proofing is provided.

RSA-wrapped stored files have **no forward secrecy**. Modern ephemeral TLS can provide transport forward secrecy, which is a separate property. Downloading a key/package makes cryptography usable outside the app: revocation blocks this application's operations but cannot erase a previously exported key or plaintext. Use HTTPS/TLS 1.3 for deployed traffic, a real WSGI server, offline-root/intermediate PKI, HSM custody, distributed throttling, external audit storage, malware scanning and independent security review before considering production use.

## Documentation

- [Architecture and eleven workflow diagrams](docs/architecture.md)
- [Cryptographic decisions and authoritative references](docs/cryptography.md)
- [Threat model](docs/threat-model.md)
- [Use cases](docs/use-cases.md)
- [Beginner student guide](docs/student-guide.md)
- [Viva questions and model answers](docs/viva-questions.md)
- [Video demonstration plan](docs/video-demo.md)
- [Contribution guidance](CONTRIBUTING.md) and [security policy](SECURITY.md)

## License

MIT. Bootstrap is distributed under its own MIT license; see `app/static/css/BOOTSTRAP-LICENSE.txt`.
