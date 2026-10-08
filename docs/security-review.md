# Implementation security review

Review date: 2026-10-08. This is a source and automated-test review, not an independent penetration test or certification.

| Area | Implemented protection | Evidence / remaining limitation |
| --- | --- | --- |
| Secrets | Required independent random environment secrets; encrypted CA and user PKCS#8; runtime paths ignored | Configuration checker and encrypted-key tests; host/process compromise remains in scope as trusted infrastructure |
| Passwords | Argon2id, minimum length, repetition check, generic login errors, throttles | Registration and login tests; no MFA or reset |
| Sessions | HttpOnly, SameSite=Lax, 30-minute lifetime, clear session on login/logout, strong Flask-Login protection | HTTP workflow tests; Secure required for production |
| Debug and HTTPS | Production rejects insecure cookies and debugger environment | Production configuration tests; reverse proxy must actually supply TLS |
| CSRF / XSS | Global Flask-WTF, POST mutations, Jinja autoescape, self-only CSP | Missing-token rejection and real-token successful login; no browser visual audit performed |
| Uploads | Global request ceiling, safe display names, unpredictable stored paths, private directory | Traversal filename and oversized request tests; no malware scanner or content quotas |
| Object authorization | Owner required for every original/signature workspace; recipient required for decryption | End-to-end IDOR and admin isolation tests |
| CA trust | Pinned CA signature, dates, subject/account binding, usage/extensions and revocation | Issuer spoofing, rogue CA, expiry and revoked certificate tests |
| Challenge replay | Random domain-separated challenges, browser binding, expiry, atomic consume-on-attempt | Service tests, actual HTTP proof and concurrent submission test |
| Signature integrity | RSA-PSS with fixed SHA-256 digest-length salt; exact-byte verification | Modified file, wrong key, signer mismatch and current-status tests |
| Encryption | Fresh AES-256 key/nonce, GCM full tag, OAEP-SHA256 wrapping, authenticated expected metadata | Round trip, wrong recipient/key, nonce/ciphertext/wrapped-key corruption tests |
| Plaintext handling | Decrypted data returned directly from memory as attachment | No temporary plaintext file creation; original uploads are unencrypted private files |
| Audit | Safe event names/outcomes/identifiers; no secrets or document content | Secret-content assertions; logs are not immutable |
| Database | Foreign keys enabled for SQLite, unique certificate and account associations, versioned migration | Fresh upgrade and schema-drift check |
| Source hygiene | Explicit source-only staging and secret/file scan | No runtime database, real certificates, key files, `.env` or personal records included |

## Verification limits

The Flask application and real HTTP handlers are exercised through Flask's test client. Bootstrap is vendored locally and responsive rules are present. A supported browser preview was unavailable for this Python repository in the managed environment, so visual rendering and real-browser accessibility have not been verified. No publicly hosted service is claimed. Use README local startup instructions to inspect the interface.

Revocation cannot revoke possession of an already exported key. The application checks current status, but offline key users are outside its enforcement boundary. File encryption has no forward secrecy. Do not portray the demo as end-to-end encryption, institutional identity proofing or production PKI.
