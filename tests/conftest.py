import secrets
import pytest
from app import create_app, pki
from app.extensions import db
from app.services import register

PASSWORD = 'Test-only passphrase 294!'

@pytest.fixture
def app(tmp_path):
    app = create_app(dict(TESTING=True, SECRET_KEY=secrets.token_urlsafe(48), CA_PASSPHRASE=secrets.token_urlsafe(48),
        INSTANCE_PATH=str(tmp_path), SQLALCHEMY_DATABASE_URI='sqlite:///'+str(tmp_path/'test.db'),
        WTF_CSRF_ENABLED=False, RATELIMIT_ENABLED=False))
    with app.app_context():
        db.create_all()
        pki.init_ca()
        yield app
        db.session.remove()
        db.drop_all()

@pytest.fixture
def client(app):
    return app.test_client()

@pytest.fixture
def users(app):
    return [register(name, name.lower(), name.lower()+'@example.test', PASSWORD, 'ADMIN' if name == 'Carol' else 'USER')
            for name in ('Alice','Bob','Carol')]

@pytest.fixture
def alice(client, users):
    assert client.post('/login', data={'identity':'alice','password':PASSWORD}).status_code == 302
    return client
