# Testing and reproducible evidence

Run from the repository root in its activated virtual environment:

```bash
pytest -v
pytest --cov=app --cov-report=term-missing
```

Tests execute the actual application factory, services, SQLite database, HTTP routes and cryptography library. Each fixture receives a temporary database, CA and key vault. Test passphrases and accounts are fictional. Tests never use the configured local development instance. A fixed test-only passphrase is deliberately visible in test source and is not a deployment credential.

## Recorded result

On 2026-10-08, Python 3.12.14: **57 tests passed in 59.37 seconds**, with **93% statement coverage** (862 statements, 61 missed), no warnings. See `test-results.txt` for the per-module table.

## Attack-to-test mapping

| Scenario | Test / actual expected result |
| --- | --- |
| Document tampering | `test_signatures`, `test_end_to_end_documents`: modified content fails RSA-PSS |
| Fake signer | `test_signatures`: expected identity mismatch and wrong-key rejection |
| Revoked certificate | `test_revoked_certificate_and_signature`, challenge cases: reject |
| Expired certificate | `test_certificate_dates`, `test_expired_signature`, challenge case: reject |
| Untrusted CA | `test_untrusted_and_spoofed_certificates`: untrusted issuer |
| Certificate spoofing | Same issuer-name rogue signature and wrong-account certificate both fail |
| Replay attack | `test_challenge_security`, `test_unknown_challenge_and_failed_attempt_consumption`: replay rejected |
| Concurrent replay | `test_concurrent_challenge_claim`: exactly one of two parallel claims succeeds |
| Unauthorized decryption | End-to-end test: sender gets 403; correct recipient gets exact bytes |
| Ciphertext and wrapped-key corruption | `test_encryption_and_corruption`: authentication/unwrap fails |
| Broken object authorization | Other user and admin cannot download another owner's original |
| CSRF | Missing token rejected; genuine token permits valid login |
| Upload traversal and size | Names normalized; large request gets 413 |
| Secret handling | Encrypted PEM and audit assertions |
| Production configuration | Insecure cookies and debugger rejected |
| CLI | Configuration check, migration command, development seed and admin creation |

## Live laboratory

The authenticated Security laboratory performs six real ephemeral-key experiments: tampered document, wrong signer, wrong private key, changed ciphertext, recipient metadata mismatch and successful round trip. These results are computed, not hard-coded badges. Certificate-state and route-authorization demonstrations run in pytest to avoid damaging live user identities.

## Installation verification

`flask --app run db upgrade` applied the initial migration. `flask --app run init-ca` created encrypted CA material. `flask --app run verify-security-config` checked configured secrets and PEM permissions. `flask --app run db check` checks schema drift. Test-client HTTP flows exercise startup, templates and operations. No real-browser visual verification or public hosting is claimed.

Final executed test output is recorded in `docs/test-results.txt`. Coverage is a measurement of executed statements, not proof of cryptographic security. Open-source dependencies, OS security, TLS deployment and broader operational controls require separate review.
