# Contributing

Use Python 3.12+ and a virtual environment. Follow README setup. Make a focused branch and explain the behavior change and its security impact. Run `pytest -v` before proposing changes. Tests must use temporary isolated state and real library algorithms, never production secrets.

Keep cryptographic code inside `app/crypto` or `app/pki.py`; preserve domain separation and certificate checks. Do not weaken negative tests to make code pass. Schema changes require a reviewed Flask-Migrate revision: `flask --app run db migrate -m "Describe schema change"`, then test upgrade on an isolated database. Do not delete old revisions.

Suggested meaningful commits: `feat: add certificate renewal with retained key history`, `security: bind challenge proof to session and certificate`, `test: reject modified package metadata`, `docs: explain historical verification limits`. Do not commit runtime `instance/`, `.env`, private keys, real documents or assignment PDFs. Use fictional `example.test` identities.
