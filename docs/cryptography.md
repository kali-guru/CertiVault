# Cryptographic design

## Password authentication and custody

Argon2id is a memory-hard password hash, not encryption. CertiVault uses argon2-cffi with a fresh library-generated salt, 64 MiB memory, three iterations and four lanes. Password verification uses the library, including a dummy hash for unknown users. Scrypt is an alternative; ordinary SHA-256 is inappropriate for passwords because it is fast. Rate limiting supplements hashing but the in-memory limiter is only suitable for a single-process local demonstration.

User RSA keys are serialized as encrypted PKCS#8 with `BestAvailableEncryption`, using the registration password. This serialization is separate from the Argon2id login hash: its password derivation is selected by the cryptography/OpenSSL implementation, not Argon2. The CA key uses a separate random environment passphrase. Keys are never written unencrypted, but are present in process memory during operations. Python does not guarantee secure zeroization. Offline theft still enables passphrase guessing; passphrase quality matters. Export remains encrypted and requires password confirmation.

## RSA-3072 and RSA-PSS

RSA keypairs use exponent 65537 and 3072-bit moduli. A signed CSR demonstrates local key possession before issuance. Document signatures call the RSA-PSS API over exact bytes, with SHA-256, MGF1-SHA-256 and a 32-byte (digest-length) salt. This is a library-recommended PSS salt choice and is fixed in the detached format. PSS is randomized; signatures are not obtained by manually “encrypting the hash.” Verification requires both a valid signature and a trusted, currently valid, non-revoked, identity-matched certificate.

Ed25519 is a simpler compact alternative for signatures but does not support RSA key wrapping; RSA was selected for the required educational design. Digital signatures do not hide document contents. Signature evidence metadata includes a claimed time, but no trusted timestamp; it cannot prove historical validity or legal non-repudiation. Identity proofing is self-registration only.

## AES-256-GCM and RSA-OAEP

For each package, `AESGCM.generate_key(bit_length=256)` creates a new random key and `os.urandom(12)` creates a 96-bit nonce. GCM encrypts the file and authenticates both the ciphertext and canonical JSON header. The returned ciphertext contains the complete 16-byte tag. Key/nonce reuse must never be introduced. No plaintext AES key is stored.

RSA-OAEP uses SHA-256, MGF1-SHA-256 and the default empty label to wrap only the 32-byte AES key for the recipient. It does not encrypt the whole file and never uses PKCS#1 v1.5 encryption. AES-GCM is efficient for file data; RSA solves recipient key delivery. ChaCha20-Poly1305 and modern HPKE designs are alternatives, with different protocol and interoperability choices.

The version-1 JSON envelope has exactly `header`, `wrapped_key`, `nonce` and `ciphertext`. Binary fields use strict base64. Header fields are `version`, `content_algorithm`, `wrap_algorithm`, `sender`, `recipient`, `fingerprint`, `created`, `name`, `package_id`. Sorted compact JSON is authenticated as AAD. Decryption compares the complete header to server-side expected metadata before unwrapping. This prevents recipient/algorithm substitutions. GCM authentication does not independently prove the sender's real identity; the sender label relies on authenticated application creation. Sign documents separately for signer evidence.

## SHA-256

SHA-256 maps bytes to a fixed-size fingerprint, used for documents and DER certificate fingerprints. It is not encryption and has no secret inverse key. Comparing hashes alone does not prove authorship: a malicious sender could replace both data and an unprotected digest. RSA-PSS verification is authoritative. A mismatch with detached evidence's claimed digest is useful diagnostic information, not a replacement for signature verification.

## X.509 and trust

An encrypted online root key signs a self-signed educational CA with Basic Constraints CA=true, path length zero, certificate-signing/CRL-signing key usage and subject key identifier. Leaves include random serials, a username common name, immutable local user ID, email SAN, critical CA=false Basic Constraints, critical digital-signature/key-encipherment usages, client-auth EKU, SKI and AKI. RSA-PSS signs both CSR and certificates.

The root certificate stored in the private instance is the local trust anchor, not the uploaded issuer name. Validation checks the actual issuer signature, leaf and CA dates, exact registered fingerprint, account association, subject ID/common name/email, revocation, supported critical extensions, expected usages and RSA-3072. A parseable PEM is not sufficient. The validator implements this deliberately restricted single-root policy, not a general-purpose Internet chain builder. No AIA fetching, OCSP or CRL distribution is implemented; revocation is authoritative only within this database.

## Challenge protocol

A fresh 192-bit challenge ID and 256-bit nonce are bound to the browser session, account and exact certificate, with a three-minute expiry. Signed bytes are UTF-8 `CertiVault certificate authentication v1\n<ID>\n<nonce>`, preventing confusion with ordinary document signing. The offline client reads the encrypted key and prompts for its passphrase. The server atomically updates unused/unexpired state to consumed before checking the proof. Only one racing request can claim the challenge. Invalid attempts consume it too. A browser-bound challenge cannot be used in another browser session.

## Transport versus stored-file security

Use HTTPS with TLS 1.3 and ephemeral key exchange to protect network traffic and obtain transport forward secrecy. Long-term RSA-OAEP file wrapping has no forward secrecy: stealing the recipient private key can expose previously recorded packages. Revocation cannot undo that compromise. Offline root/intermediate CA separation, HSM custody, key rotation and client-side key operations are production improvements, not features claimed here.

## Authoritative references

- [cryptography RSA API: PSS, OAEP and key serialization](https://cryptography.io/en/stable/hazmat/primitives/asymmetric/rsa/)
- [cryptography authenticated encryption API](https://cryptography.io/en/stable/hazmat/primitives/aead/)
- [cryptography X.509 API](https://cryptography.io/en/stable/x509/reference/)
- [RFC 8017: RSA cryptography specifications](https://www.rfc-editor.org/rfc/rfc8017)
- [RFC 5280: X.509 certificate and CRL profile](https://www.rfc-editor.org/rfc/rfc5280)
- [RFC 9106: Argon2](https://www.rfc-editor.org/rfc/rfc9106)
- [RFC 8446: TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446)
- [NIST SP 800-38D: GCM](https://csrc.nist.gov/pubs/sp/800/38/d/final)
- [OWASP password storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [OWASP file upload](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)
- [Flask security considerations](https://flask.palletsprojects.com/en/stable/web-security/)

These explain design choices; they do not certify this implementation or imply compliance with a formal standard.
