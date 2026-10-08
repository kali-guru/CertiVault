# Architecture and workflows

The application factory configures extensions, private storage and Blueprints. Models remain in one compact domain module; cryptographic primitives, PKI and application services are separate from request handlers. The server is trusted for ordinary signing/decryption; the certificate-login client signs locally.

## System architecture

```mermaid
flowchart TD
  Browser["Browser / Jinja forms"] --> Flask["Flask Blueprints"]
  Flask --> Services["Authorization and security services"]
  Services --> Crypto["cryptography library"]
  Services --> Database["SQLite: identities and evidence"]
  Services --> Vault["Private files and encrypted keys"]
```

## PKI architecture

```mermaid
flowchart TD
  Root["Encrypted online educational root"] --> CA["Pinned self-signed CA certificate"]
  Root --> Issue["Sign validated CSRs"]
  Issue --> Leaf["RSA-3072 account certificates"]
  Leaf --> Validate["Issuer, dates, identity and usages"]
  Revocation["Local revocation database"] --> Validate
  CA --> Validate
```

## Registration

```mermaid
flowchart TD
  Form["Validated registration"] --> Unique{"Unique account?"}
  Unique -->|No| Reject["Safe error"]
  Unique -->|Yes| Hash["Argon2id password hash"]
  Hash --> Identity["Generate key and issue certificate"]
  Identity --> Store["Encrypted PKCS#8 and account commit"]
  Store --> Audit["Registration and issuance events"]
```

## Certificate issuance

```mermaid
flowchart TD
  RSA["Generate RSA-3072 key"] --> CSR["Sign CSR with leaf key"]
  CSR --> Check{"CSR signature valid?"}
  Check -->|No| Reject["Reject request"]
  Check -->|Yes| Extensions["Bind account and usage extensions"]
  Extensions --> Sign["CA signs X.509 certificate"]
  Sign --> Persist["Persist public certificate and fingerprint"]
```

## Certificate authentication

```mermaid
flowchart TD
  Request["Request challenge in browser session"] --> Challenge["Random ID and nonce; three-minute expiry"]
  Challenge --> Local["Offline client signs domain-separated bytes"]
  Local --> Claim{"Atomic unused and unexpired claim?"}
  Claim -->|No| Reject["Reject expired or replayed proof"]
  Claim -->|Yes| Validate{"Certificate and signature valid?"}
  Validate -->|No| Failed["Reject; challenge stays consumed"]
  Validate -->|Yes| Session["Establish authenticated session"]
```

## Document signing

```mermaid
flowchart TD
  Select["Select owned document"] --> Auth{"Owner and certificate valid?"}
  Auth -->|No| Reject["Deny signing"]
  Auth -->|Yes| Unlock["Unlock encrypted key in memory"]
  Unlock --> PSS["RSA-PSS over exact file bytes"]
  PSS --> History["Signature record and audit event"]
  History --> Evidence["Download detached evidence"]
```

## Signature verification

```mermaid
flowchart TD
  Upload["Document, evidence and expected signer"] --> Cert{"Trusted current certificate?"}
  Cert -->|No| Reject["Certificate failure"]
  Cert -->|Yes| Identity{"Expected account matches?"}
  Identity -->|No| Mismatch["Signer mismatch"]
  Identity -->|Yes| Verify{"RSA-PSS verifies exact bytes?"}
  Verify -->|No| Invalid["Invalid signature or modified content"]
  Verify -->|Yes| Valid["Valid signature"]
```

## Hybrid encryption

```mermaid
flowchart TD
  Source["Owner selects document and recipient"] --> Cert{"Recipient certificate valid?"}
  Cert -->|No| Reject["Reject encryption"]
  Cert -->|Yes| Random["Fresh AES-256 key and 96-bit nonce"]
  Random --> AES["AES-GCM: bytes and authenticated metadata"]
  Random --> RSA["RSA-OAEP wraps AES key"]
  AES --> Package["Versioned JSON package"]
  RSA --> Package
```

## Decryption

```mermaid
flowchart TD
  Request["Authenticated package request"] --> Recipient{"Intended recipient?"}
  Recipient -->|No| Deny["403 and audit event"]
  Recipient -->|Yes| Cert["Validate current recipient certificate"]
  Cert --> Unlock["Unlock PKCS#8 key and unwrap AES key"]
  Unlock --> GCM{"Header matches and GCM authenticates?"}
  GCM -->|No| Fail["Safe decryption failure"]
  GCM -->|Yes| Download["Attachment response; no temporary plaintext"]
```

## Revocation

```mermaid
flowchart TD
  Request["Owner or admin requests revocation"] --> Auth{"Role, password and CSRF valid?"}
  Auth -->|No| Reject["Deny mutation"]
  Auth -->|Yes| Record["Unique revocation: reason, actor, time"]
  Record --> Commit["Commit and audit"]
  Commit --> Block["All certificate-sensitive operations reject"]
```

## Attack testing

```mermaid
flowchart TD
  Fixtures["Temporary test instance and fictional users"] --> Positive["Establish successful baseline"]
  Positive --> Modify["Change bytes, identity, state or request"]
  Modify --> Real["Execute real service or HTTP route"]
  Real --> Assert{"Expected failure observed?"}
  Assert -->|Yes| Pass["Recorded test pass"]
  Assert -->|No| Fail["Fail suite and investigate"]
```

## Domain schema

User owns certificates and documents. CertificateRevocation uniquely references a certificate and records the actor. DocumentSignature links document, signer and exact certificate. EncryptedPackage records sender, recipient and recipient certificate. AuthenticationChallenge binds account, certificate, browser token, expiry and consumed flag. AuditEvent records safe event metadata only. Foreign keys and uniqueness constraints protect database associations; route checks implement per-user authorization.

Files use generated random names under the private instance, never paths supplied by a browser. The browser receives only controlled attachments. Migrations are versioned; `db.create_all` is used only for temporary test fixtures.
