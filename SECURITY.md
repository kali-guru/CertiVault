# Security policy

CertiVault is an educational prototype and has not undergone an independent security audit. Do not store real student records or sensitive personal documents in a public deployment.

Report vulnerabilities privately through GitHub private vulnerability reporting if enabled for this repository. If unavailable, ask the maintainer for a private channel without posting exploit details, credentials or personal data in a public issue. Do not test against systems you do not own or have permission to assess.

Include the affected commit, minimal fictional reproduction, expected/actual results and impact. Never attach `.env`, instance databases, user keys or CA keys. Supported development is the current main branch; there is no promised response SLA.

Core boundaries: only owners access originals, only recipients request decryption, admins manage certificates but cannot browse user private content through the UI. The server and OS operator remain trusted. See `docs/threat-model.md` for residual risks. Key export is encrypted but does not prevent offline guessing; choose a long unique passphrase. Revocation does not erase exported keys or copies of plaintext.
