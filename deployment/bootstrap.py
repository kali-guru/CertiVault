"""Migrate a private volume without silently replacing an existing trust root."""
import fcntl
import os
from pathlib import Path
from flask_migrate import upgrade
from app import create_app, pki
from app.extensions import db
from app.models import Certificate
from app.crypto.primitives import unlock


def initialize(app=None):
    os.umask(0o077)
    app = app or create_app()
    instance = Path(app.instance_path)
    # Separate startup processes sharing this volume cannot race CA generation.
    with (instance / '.bootstrap.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        with app.app_context():
            upgrade(directory=str(Path(__file__).resolve().parents[1] / 'migrations'))
            key_path = pki.vault('ca', 'private.pem')
            cert_path = pki.vault('ca', 'certificate.pem')
            if key_path.exists() != cert_path.exists():
                raise RuntimeError('Incomplete CA volume. Restore matching CA files; refusing replacement.')
            if not key_path.exists():
                if db.session.scalar(db.select(Certificate.id).limit(1)) is not None:
                    raise RuntimeError('Existing identities have no CA. Restore the original CA backup.')
                pki.init_ca()
            key = unlock(key_path.read_bytes(), app.config['CA_PASSPHRASE'])
            ca = pki.ca_certificate()
            ca.verify_directly_issued_by(ca)
            if key.public_key().public_numbers() != ca.public_key().public_numbers():
                raise RuntimeError('CA key and certificate do not match')
            print('Database ready; encrypted CA verified.', flush=True)


if __name__ == '__main__':
    initialize()
