"""Persistent identities, immutable certificate history and security evidence."""
from datetime import datetime, timezone
from flask_login import UserMixin
from .extensions import db

def now():
    return datetime.now(timezone.utc).replace(tzinfo=None)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(254), unique=True, nullable=False)
    name = db.Column(db.String(120), nullable=False)
    password_hash = db.Column(db.Text, nullable=False)
    role = db.Column(db.String(16), nullable=False, default='USER')
    created = db.Column(db.DateTime, default=now, nullable=False)
    certificates = db.relationship('Certificate', backref='user', lazy=True)

class Certificate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    pem = db.Column(db.Text, nullable=False)
    serial = db.Column(db.String(64), unique=True, nullable=False)
    fingerprint = db.Column(db.String(64), unique=True, nullable=False)
    key_file = db.Column(db.String(64), nullable=False)
    created = db.Column(db.DateTime, default=now, nullable=False)
    revocation = db.relationship('CertificateRevocation', backref='certificate', uselist=False)

class CertificateRevocation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    certificate_id = db.Column(db.Integer, db.ForeignKey('certificate.id'), unique=True, nullable=False)
    actor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    reason = db.Column(db.String(32), nullable=False)
    created = db.Column(db.DateTime, default=now, nullable=False)

class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    name = db.Column(db.String(255), nullable=False)
    storage = db.Column(db.String(64), unique=True, nullable=False)
    digest = db.Column(db.String(64), nullable=False)
    size = db.Column(db.Integer, nullable=False)
    created = db.Column(db.DateTime, default=now, nullable=False)
    signatures = db.relationship('DocumentSignature', backref='document')

class DocumentSignature(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    document_id = db.Column(db.Integer, db.ForeignKey('document.id'), nullable=False)
    signer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    certificate_id = db.Column(db.Integer, db.ForeignKey('certificate.id'), nullable=False)
    signature = db.Column(db.LargeBinary, nullable=False)
    digest = db.Column(db.String(64), nullable=False)
    created = db.Column(db.DateTime, default=now, nullable=False)
    certificate = db.relationship('Certificate')

class EncryptedPackage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    certificate_id = db.Column(db.Integer, db.ForeignKey('certificate.id'), nullable=False)
    name = db.Column(db.String(255), nullable=False)
    storage = db.Column(db.String(64), unique=True, nullable=False)
    created = db.Column(db.DateTime, default=now, nullable=False)
    certificate = db.relationship('Certificate')

class AuthenticationChallenge(db.Model):
    id = db.Column(db.String(64), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    certificate_id = db.Column(db.Integer, db.ForeignKey('certificate.id'), nullable=True)
    nonce = db.Column(db.String(64), nullable=False)
    binding = db.Column(db.String(64), nullable=False)
    created = db.Column(db.DateTime, default=now, nullable=False)
    expires = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, nullable=False, default=False)

class AuditEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), index=True)
    event = db.Column(db.String(64), nullable=False)
    outcome = db.Column(db.String(16), nullable=False)
    detail = db.Column(db.String(250), nullable=False, default='')
    created = db.Column(db.DateTime, default=now, nullable=False)
