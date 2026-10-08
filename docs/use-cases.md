# University use cases

## Signed transcript

Carol, a fictional administrator, uploads `examples/official_transcript.txt`, signs with her password-unlocked key, and exports detached evidence. Employer receives the original and evidence through a separate channel, logs in, and verifies with expected signer `carol`. Success requires current certificate trust and exact byte integrity. Editing a copy fails; using expected signer `bob` fails. The application does not prove Carol's actual employment or the truth of grades.

## Confidential coursework

Alice uploads `examples/coursework.txt`, chooses Bob and encrypts. The recipient certificate is validated before its key is used. A fresh AES key encrypts the file; Bob's RSA key receives the wrapped AES key. Bob logs in and decrypts using his key passphrase. Alice cannot use the decrypt endpoint; a third user cannot download the package. Header or ciphertext corruption is rejected. The sender's unencrypted original remains privately stored; encryption does not delete it.

## Recommendation letter

Bob uploads `examples/recommendation.txt`, signs it and shares original plus evidence with Employer. Employer checks expected signer `bob`. A copied signature fails on a changed letter. Revoking Bob's certificate makes subsequent current-status verification fail, even for signatures created earlier. The displayed date is not an independent trusted timestamp.

All sample records are visibly fictional. Do not upload real personal or academic records for assessment demonstrations.
