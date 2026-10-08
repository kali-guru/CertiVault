# Viva questions and model answers

1. **What problem does CertiVault solve?** It demonstrates verifiable document integrity, account-key authentication and recipient confidentiality for university document exchange.
2. **What is PKI?** The keys, certificates, issuers, validation policies and lifecycle processes used to associate identities with public keys.
3. **What does a CA do?** It signs certificates binding an identity and public key under an issuer policy.
4. **Is this CA publicly trusted?** No. Only this application's pinned educational root is trusted.
5. **What is X.509?** A standard certificate structure containing identity, public key, validity, issuer, serial, extensions and a signature.
6. **Why is a public certificate not a password?** Anyone may possess it; only a valid private-key proof establishes possession of the corresponding secret.
7. **What is the public/private key distinction?** Public keys are shared for verification or wrapping; private keys sign or unwrap and must stay protected.
8. **Why RSA-3072?** It meets the project's chosen security margin and supports both PSS signatures and OAEP wrapping through mature libraries.
9. **Why exponent 65537?** It is a widely supported secure standard RSA public exponent.
10. **What is RSA-PSS?** A randomized signature encoding scheme used with RSA, a hash and mask-generation function.
11. **Which PSS salt is used?** A 32-byte SHA-256 digest-length salt, explicitly agreed by signer and verifier.
12. **Is signing just encrypting a hash?** No. This implementation uses the RSA-PSS signature API and its defined encoding and verification rules.
13. **What is RSA-OAEP?** A randomized RSA encryption encoding used here to wrap the small AES key with SHA-256 and MGF1.
14. **Why not PKCS#1 v1.5 encryption?** OAEP is the preferred design for new RSA encryption and avoids using the older v1.5 encryption scheme.
15. **Why not encrypt the whole file with RSA?** RSA has strict message-size limits and poor bulk-data efficiency; AES handles file contents.
16. **What is AES?** A symmetric block cipher; both parties need the same secret key.
17. **What does GCM add?** Authenticated encryption: ciphertext and additional metadata are checked with an authentication tag.
18. **What is the nonce?** A public per-encryption input, 96 bits here, that must not repeat under the same key.
19. **What happens on nonce reuse?** Reusing a key/nonce pair can catastrophically undermine confidentiality and authentication.
20. **Where is the tag stored?** The AESGCM API appends the full 16-byte tag to ciphertext.
21. **What is AAD?** Additional authenticated data: metadata protected against modification but not encrypted.
22. **What is SHA-256 used for?** Document and certificate fingerprints, and as the hash used by PSS and OAEP.
23. **Can SHA-256 be decrypted?** No. Hashing is not encryption and has no decryption key.
24. **Does a hash prove authorship?** No. Anyone can compute a new hash; a verified signature supplies key-possession evidence.
25. **What is hybrid encryption?** Symmetric file encryption combined with asymmetric delivery of the symmetric key.
26. **Does encryption prove the sender?** Not independently. The application associates a sender with creation; use a digital signature for signer evidence.
27. **Does signing hide the document?** No. Signatures provide integrity and evidence of private-key possession, not secrecy.
28. **Why Argon2id?** Its salted memory-hard work makes offline password guessing more expensive than fast general hashes.
29. **Does the stored password hash unlock PKCS#8?** No. The passphrase is needed; PKCS#8 encryption uses a separate library-selected password derivation.
30. **Where are private keys stored?** In mode-0600 encrypted PKCS#8 files under the private instance directory, excluded from Git.
31. **Is key custody end-to-end?** No. Ordinary signing and decryption unlock keys on the server; a compromised server can capture passphrases.
32. **How is the CA key protected?** Encrypted at rest with an independent random environment passphrase and never exposed by an export route.
33. **How do you validate issuer trust?** Verify the actual certificate signature against the pinned root, then check dates, identity, usages and revocation.
34. **Why check identity after the signature?** A valid certificate for another account must not authenticate the target account or expected signer.
35. **How is expiry handled?** Current UTC time must be inside leaf and CA validity intervals; expired leaves are rejected.
36. **What is revocation?** Permanent early invalidation recorded with certificate, actor, time and reason.
37. **Does revocation erase keys or plaintext?** No. It blocks application operations but cannot revoke mathematical possession or previously exported copies.
38. **Does an old signature stay valid after revocation here?** Current-status verification rejects it; historical validation needs additional trusted evidence not implemented here.
39. **What is certificate spoofing?** Substituting a certificate to claim another identity; fingerprint and subject/account checks prevent this locally.
40. **What is a replay attack?** Reusing a captured valid response to authenticate again without making a fresh proof.
41. **How is replay prevented?** Random expiring browser-bound challenges are atomically consumed once, including invalid verification attempts.
42. **Why atomic consumption?** Two concurrent requests must not both observe and accept the same unused challenge.
43. **What signs the login challenge?** The offline Python helper using the user's exported encrypted private key and locally entered passphrase.
44. **What does TLS protect?** Network traffic between client and deployment endpoint; it is separate from stored-file encryption.
45. **Does RSA wrapping provide forward secrecy?** No. Later recipient private-key compromise may decrypt previously recorded packages.
46. **How can TLS provide forward secrecy?** Ephemeral key exchange prevents later compromise of a long-term authentication key from revealing prior session keys.
47. **What is IDOR?** Accessing another user's object by manipulating its identifier; every protected document route checks the owner.
48. **Can an admin decrypt every package?** No through the application. Decryption requires recipient authorization and the recipient key passphrase.
49. **What protects against CSRF?** Flask-WTF tokens on state-changing forms, POST-only mutations and SameSite session cookies.
50. **How are uploads contained?** Size limits, sanitized display names, random server names, private storage and attachment-only downloads; files are never executed.
51. **Why avoid logging keys and passwords?** Logs often have broader access and longer retention, turning diagnostics into a secret-exposure channel.
52. **Are audit logs tamper-proof?** No. They are ordinary SQLite records; external append-only storage is future work.
53. **What is the value of negative tests?** They prove rejection for tampering, revocation, replay and unauthorized access instead of testing only successful examples.
54. **Does the claimed signing time establish historical evidence?** No. It is unsigned metadata, not a trusted timestamp or timestamp authority token.
55. **What are the main production gaps?** Online root custody, self-declared enrollment, no HSM, no distributed limiter, no recovery/renewal, no malware scanner and no independent audit.
56. **What would you improve first?** Define production threat and enrollment policy, isolate CA/key operations, deploy HTTPS with a real WSGI server and add independent review and operational controls.
