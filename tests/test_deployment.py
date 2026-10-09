"""Exercise the actual container bootstrap against fresh temporary volumes."""
import secrets
import pytest
pytest.importorskip('fcntl', reason='Container bootstrap uses Linux/POSIX file locks; Windows runs the Linux image via Docker Desktop.')
from sqlalchemy import text
from app import create_app, pki
from app.extensions import db
from app.services import register
from deployment.bootstrap import initialize


def fresh_app(tmp_path):
    return create_app(dict(TESTING=True, SECRET_KEY=secrets.token_urlsafe(48),
        CA_PASSPHRASE=secrets.token_urlsafe(48), INSTANCE_PATH=str(tmp_path),
        SQLALCHEMY_DATABASE_URI='sqlite:///'+str(tmp_path/'certivault.db'),
        RATELIMIT_ENABLED=False))


def test_first_start_and_restart_preserve_identity(tmp_path):
    app = fresh_app(tmp_path)
    initialize(app)
    with app.app_context():
        root = pki.vault('ca','certificate.pem').read_bytes()
        user = register('Container Test','container','container@example.test','Container test passphrase 923!')
        certificate = pki.latest(user.id).pem
        assert db.session.execute(text('SELECT version_num FROM alembic_version')).scalar()
    initialize(app)
    with app.app_context():
        assert pki.vault('ca','certificate.pem').read_bytes() == root
        assert pki.latest(user.id).pem == certificate
        assert pki.validate(certificate,user.id) == 'VALID'


def test_incomplete_ca_refused(tmp_path):
    app = fresh_app(tmp_path)
    initialize(app)
    with app.app_context():
        pki.vault('ca','certificate.pem').unlink()
        original_key = pki.vault('ca','private.pem').read_bytes()
    with pytest.raises(RuntimeError,match='Incomplete CA'):
        initialize(app)
    with app.app_context():
        assert pki.vault('ca','private.pem').read_bytes() == original_key


def test_wrong_ca_passphrase_refused(tmp_path):
    app = fresh_app(tmp_path)
    initialize(app)
    app.config['CA_PASSPHRASE'] = secrets.token_urlsafe(48)
    with pytest.raises(ValueError):
        initialize(app)


def test_missing_root_with_existing_accounts_refused(tmp_path):
    app = fresh_app(tmp_path)
    initialize(app)
    with app.app_context():
        register('Existing User','existing','existing@example.test','Existing test passphrase 923!')
        pki.vault('ca','private.pem').unlink()
        pki.vault('ca','certificate.pem').unlink()
    with pytest.raises(RuntimeError,match='Existing identities have no CA'):
        initialize(app)
