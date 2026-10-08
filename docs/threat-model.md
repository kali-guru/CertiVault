# Threat model

## Scope and trust assumptions

Assets: passwords and hashes, user and CA keys, public certificates, original documents, encrypted packages, database associations, sessions and audit events. Actors: unauthenticated visitor, registered sender/recipient/verifier, application admin, malicious account, and trusted host operator. Browser ↔ Flask, Flask ↔ private filesystem, and Flask ↔ SQLite are trust boundaries. The OS, deployed source and trust-anchor file must be trusted. This is a local academic prototype, not a hardened multi-tenant service.

| Threat / asset | Attack scenario | Likelihood / impact | Mitigation | Residual risk |
| --- | --- | --- | --- | --- |
| Credential guessing / accounts | Repeated password attempts | Medium / high | Argon2id, long passwords, generic login error, route throttles | No MFA, distributed throttling or breach-password lookup |
| Database theft / password hashes | Offline guessing | Medium / high | Salted memory-hard hashes, private directory | Weak passwords remain guessable |
| Key theft / private keys | Copy key-vault files | Medium / critical | Encrypted PKCS#8, mode-0600 files, ignored runtime directory | Password guessing and runtime capture |
| CA compromise / trust root | Steal CA key and environment | Low–medium / critical | Separate random passphrase, private files, no export route | Online CA; host compromise breaks trust |
| Certificate spoofing / identity | Replace user's cert with attacker cert | Medium / high | Exact fingerprint, subject ID/SAN/account checks, issuer signature | Self-declared identity is not institutional proofing |
| Untrusted CA / authenticity | Upload syntactically valid rogue cert | Medium / high | Pinned root signature verification | Trust-anchor file replacement defeats policy |
| Replay / session | Resubmit signed challenge | Medium / high | Expiry, session binding, atomic consume-on-attempt | Stolen session remains dangerous |
| MITM / credentials and plaintext | Intercept HTTP | High if remote HTTP / critical | HTTPS deployment, secure cookies, HSTS in production | Development localhost HTTP is not deployment security |
| Document modification / integrity | Change one byte after signing | Medium / high | RSA-PSS over exact bytes | Key holder can sign a new document |
| Ciphertext modification / secrecy | Change ciphertext, tag, wrapped key or header | Medium / high | GCM tag, OAEP decoding, expected AAD metadata | Denial of service remains possible |
| IDOR / originals | Change document ID | Medium / high | Owner checks on view/download/sign/encrypt/evidence | OS or database operator can read originals |
| Unauthorized decrypt / recipient package | Sender or third user requests plaintext | Medium / high | Recipient check before key access; current certificate validation | Exported keys allow offline operations |
| Malicious upload / host and browser | Script or executable file | Medium / high | Never execute or inline-render; private random filenames; attachment/octet-stream downloads; nosniff | No antivirus; downloaded files may be dangerous when opened |
| Resource exhaustion / availability | Large uploads or repeated RSA generation | Medium / medium–high | Request size ceiling, throttling | Single-process memory limiter; no quotas or job queue |
| CSRF / account actions | Foreign page submits operation | Medium / high | Flask-WTF tokens, SameSite cookies, POST-only mutations | XSS or stolen sessions can bypass browser defenses |
| XSS / sessions | HTML in names or filenames | Medium / high | Jinja autoescape, normalized filenames, restrictive CSP | Future unsafe template filters could reintroduce risk |
| Audit deletion / evidence | Database editor changes events | Low–medium / high | No UI edit/delete route, role-limited inspection | Logs are not cryptographically chained or externalized |
| Historical validity / signatures | Backdate metadata | Medium / high | Clearly label claimed time; validate current status | No trusted timestamp or historical revocation model |
| Key loss / availability | Forget password or delete key | Medium / high | Explicit export/backup instructions | No recovery or rewrapping workflow |
| Long-term key compromise / archives | Later theft decrypts captured packages | Medium / high | Protect and limit key exposure | RSA file wrapping lacks forward secrecy |

## Operational recommendations

Use fictional records locally. For deployment, use TLS, a supported WSGI server, strict filesystem ownership, encrypted backups, distributed rate limits, separate CA operations, vetted identity enrollment and external audit storage. Do not expose the Flask debugger. App-admin status does not grant host-admin privileges; the latter is outside the application authorization model.
