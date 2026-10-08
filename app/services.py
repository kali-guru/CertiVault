"""Authorization-aware application operations shared by routes and tests."""
import secrets
from datetime import timedelta
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, InvalidHashError
from sqlalchemy import update
from .extensions import db
from .models import User, AuditEvent, AuthenticationChallenge, now
from . import pki
from .crypto.primitives import verify, digest

passwords = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)
DUMMY_HASH = passwords.hash(secrets.token_urlsafe(32))

def audit(event, user_id=None, outcome='SUCCESS', detail=''):
    db.session.add(AuditEvent(user_id=user_id, event=event, outcome=outcome, detail=detail[:250]))

def register(name, username, email, password, role='USER'):
    user = User(name=name, username=username.lower(), email=email.lower(), password_hash=passwords.hash(password), role=role)
    db.session.add(user)
    db.session.flush()
    pki.issue(user, password)
    audit('USER_REGISTERED', user.id)
    audit('CERTIFICATE_ISSUED', user.id)
    db.session.commit()
    return user

def check_password(user, password):
    try:
        result = passwords.verify(user.password_hash if user else DUMMY_HASH, password)
        return bool(user and result)
    except (VerificationError, InvalidHashError):
        return False

def challenge_message(challenge):
    return ('CertiVault certificate authentication v1\n' + challenge.id + '\n' + challenge.nonce).encode()

def new_challenge(user, binding):
    cert = pki.latest(user.id) if user else None
    challenge = AuthenticationChallenge(id=secrets.token_hex(24), user_id=user.id if user else None,
        certificate_id=cert.id if cert else None, nonce=secrets.token_hex(32), binding=binding,
        expires=now()+timedelta(minutes=3))
    db.session.add(challenge)
    audit('AUTH_CHALLENGE_CREATED', user.id if user else None)
    db.session.commit()
    return challenge

def consume_challenge(identifier, signature, pem, binding):
    ch = db.session.get(AuthenticationChallenge, identifier)
    if not ch or ch.binding != binding:
        raise ValueError('Challenge rejected')
    # Atomic conditional UPDATE prevents two concurrent requests accepting one nonce.
    changed = db.session.execute(update(AuthenticationChallenge).where(
        AuthenticationChallenge.id == identifier, AuthenticationChallenge.used.is_(False),
        AuthenticationChallenge.expires > now()).values(used=True)).rowcount
    db.session.commit()
    if changed != 1:
        audit('REPLAY_ATTEMPT_DETECTED', ch.user_id, 'FAILURE')
        db.session.commit()
        raise ValueError('Challenge expired or already consumed')
    try:
        if ch.user_id is None:
            raise ValueError('Unknown identity')
        cert = db.session.get(pki.Certificate, ch.certificate_id)
        supplied = pki.x509.load_pem_x509_certificate(pem)
        if supplied.fingerprint(pki.hashes.SHA256()).hex() != cert.fingerprint:
            raise ValueError('Certificate mismatch')
        pki.require_valid(cert, ch.user_id)
        verify(supplied.public_key(), signature, challenge_message(ch))
    except Exception as exc:
        audit('AUTH_CHALLENGE_FAILURE', ch.user_id, 'FAILURE')
        db.session.commit()
        raise ValueError('Certificate proof rejected') from exc
    audit('AUTH_CHALLENGE_SUCCESS', ch.user_id)
    db.session.commit()
    return db.session.get(User, ch.user_id)

def verify_signature(record, data, expected_signer=None):
    if expected_signer is not None and record.signer_id != expected_signer:
        return 'SIGNER MISMATCH'
    status = pki.validate(record.certificate.pem, record.signer_id)
    if status != 'VALID':
        return 'CERTIFICATE ' + status
    try:
        cert = pki.x509.load_pem_x509_certificate(record.certificate.pem.encode())
        verify(cert.public_key(), record.signature, data)
    except Exception:
        return 'DOCUMENT MODIFIED' if digest(data) != record.digest else 'INVALID SIGNATURE'
    return 'VALID SIGNATURE'
