# Video demonstration plan

Use only the fictional sample files and accounts. Choose your own seed password off camera. Hide terminal prompts and never display `.env`, key contents or private filesystem secrets.

1. **0:00–0:45 — Purpose.** Show the home page and explain confidentiality, integrity and authentication as different properties. State educational trust limitations.
2. **0:45–1:30 — Identity.** Register a fictional account or log in as Carol. Show certificate issuer, serial, RSA size, dates and SHA-256 fingerprint. Download only the public certificate on screen.
3. **1:30–3:00 — Transcript signing.** Upload `official_transcript.txt`, sign with Carol and download original/evidence. Sign out; sign in as Employer. Verify with expected signer `carol` and explain the cryptographic result.
4. **3:00–3:45 — Tamper and signer tests.** Modify a copy with a text editor. Verify again and show failure. Try a different expected signer and show mismatch. The original is preserved.
5. **3:45–5:15 — Confidential exchange.** Alice uploads coursework and encrypts for Bob. Show Alice is denied the decrypt URL. Bob logs in, decrypts and downloads the correct file. Explain fresh AES key, nonce, GCM tag and OAEP wrap.
6. **5:15–6:00 — Recommendation.** Bob signs the recommendation; Employer verifies as `bob`. Explain self-declared account identity versus institutional proof.
7. **6:00–7:30 — Certificate proof.** Prepare encrypted key export privately. Request a challenge, run `sign_challenge.py`, show only the public signature response, and submit proof. Explain expiry, browser binding and atomic consumption. Demonstrate replay rejection using the automated challenge test for a clear deterministic result.
8. **7:30–8:30 — Revocation.** Use a disposable completed-demo identity. Revoke as owner/admin with a reason. Repeat verification to show rejection. Explain that decryption is also blocked by current certificate policy and exported keys cannot be erased remotely.
9. **8:30–9:15 — Laboratory and audit.** Run live isolated cryptographic experiments. Show audit outcomes without secrets. Mention application tests for untrusted CA, expiry and object authorization.
10. **9:15–10:00 — Evidence and limitations.** Run `pytest -v`, show actual results, then the threat model and architecture. Explain no RSA file forward secrecy, no HSM, online root, no trusted timestamps and no independent production audit.

For a shorter recording, cover transcript tampering, Alice-to-Bob encryption, challenge replay test and revocation; link the longer written walkthrough for the remaining cases.
