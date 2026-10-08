"""Single-root educational PKI with strict local identity and status checks."""
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from flask import current_app
from .extensions import db
from .models import Certificate
from .crypto.primitives import keypair, protect, unlock, PSS

def vault(folder, name):
    return Path(current_app.instance_path) / folder / name

def private_write(path, data):
    import os
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)

def ca_certificate():
    return x509.load_pem_x509_certificate(vault('ca', 'certificate.pem').read_bytes())

def init_ca():
    path = vault('ca', 'private.pem')
    if path.exists() or vault('ca', 'certificate.pem').exists():
        raise ValueError('CA already exists; refusing replacement')
    key = keypair()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'CertiVault Educational Root CA')])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=1))
            .not_valid_after(now+timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
            .sign(key, hashes.SHA256(), rsa_padding=PSS))
    private_write(path, protect(key, current_app.config['CA_PASSPHRASE']))
    private_write(vault('ca', 'certificate.pem'), cert.public_bytes(serialization.Encoding.PEM))

def issue(user, password):
    ca = ca_certificate()
    key = keypair()
    ca_key = unlock(vault('ca', 'private.pem').read_bytes(), current_app.config['CA_PASSPHRASE'])
    now = datetime.now(timezone.utc)
    if not ca.not_valid_before_utc <= now < ca.not_valid_after_utc:
        raise ValueError('CA validity ended')
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, user.username),
                         x509.NameAttribute(NameOID.USER_ID, str(user.id))])
    csr = (x509.CertificateSigningRequestBuilder().subject_name(subject)
           .add_extension(x509.SubjectAlternativeName([x509.RFC822Name(user.email)]), False)
           .sign(key, hashes.SHA256(), rsa_padding=PSS))
    if not csr.is_signature_valid:
        raise ValueError('Invalid CSR')
    cert = (x509.CertificateBuilder().subject_name(csr.subject).issuer_name(ca.subject)
            .public_key(csr.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now-timedelta(minutes=1)).not_valid_after(min(now+timedelta(days=365), ca.not_valid_after_utc))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
            .add_extension(x509.KeyUsage(True, False, True, False, False, False, False, False, False), True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), False)
            .add_extension(x509.SubjectAlternativeName([x509.RFC822Name(user.email)]), False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca.public_key()), False)
            .sign(ca_key, hashes.SHA256(), rsa_padding=PSS))
    name = secrets.token_hex(24) + '.pem'
    private_write(vault('key_vault', name), protect(key, password))
    record = Certificate(user_id=user.id, pem=cert.public_bytes(serialization.Encoding.PEM).decode(),
                         serial=str(cert.serial_number), fingerprint=cert.fingerprint(hashes.SHA256()).hex(), key_file=name)
    db.session.add(record)
    db.session.flush()
    return record

def latest(user_id):
    return db.session.scalar(db.select(Certificate).where(Certificate.user_id == user_id).order_by(Certificate.id.desc()))

def validate(pem, expected_user=None):
    try:
        cert = x509.load_pem_x509_certificate(pem.encode() if isinstance(pem, str) else pem)
        ca = ca_certificate()
        if cert.issuer != ca.subject:
            return 'UNTRUSTED ISSUER'
        try:
            cert.verify_directly_issued_by(ca)
        except (InvalidSignature, ValueError, TypeError):
            return 'INVALID SIGNATURE'
        now = datetime.now(timezone.utc)
        if not ca.not_valid_before_utc <= now < ca.not_valid_after_utc:
            return 'UNTRUSTED ISSUER'
        if now >= cert.not_valid_after_utc:
            return 'EXPIRED'
        if now < cert.not_valid_before_utc:
            return 'INVALID CERTIFICATE'
        record = db.session.scalar(db.select(Certificate).where(Certificate.fingerprint == cert.fingerprint(hashes.SHA256()).hex()))
        if record is None:
            return 'IDENTITY MISMATCH'
        if expected_user is not None and record.user_id != expected_user:
            return 'IDENTITY MISMATCH'
        if cert.subject.get_attributes_for_oid(NameOID.USER_ID)[0].value != str(record.user_id):
            return 'IDENTITY MISMATCH'
        if cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value != record.user.username:
            return 'IDENTITY MISMATCH'
        if cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.RFC822Name) != [record.user.email]:
            return 'IDENTITY MISMATCH'
        if record.revocation:
            return 'REVOKED'
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage)
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        if bc.value.ca or not bc.critical or not ku.critical or not ku.value.digital_signature or not ku.value.key_encipherment or ku.value.key_cert_sign:
            return 'INVALID CERTIFICATE'
        if ExtendedKeyUsageOID.CLIENT_AUTH not in eku:
            return 'INVALID CERTIFICATE'
        supported = {x509.ExtensionOID.BASIC_CONSTRAINTS, x509.ExtensionOID.KEY_USAGE}
        if any(ext.critical and ext.oid not in supported for ext in cert.extensions):
            return 'INVALID CERTIFICATE'
        public = cert.public_key()
        if not isinstance(public, rsa.RSAPublicKey) or public.key_size != 3072:
            return 'INVALID CERTIFICATE'
        return 'VALID'
    except (ValueError, TypeError, IndexError, x509.ExtensionNotFound):
        return 'INVALID CERTIFICATE'

def require_valid(record, user_id):
    result = validate(record.pem, user_id)
    if result != 'VALID':
        raise ValueError('Certificate rejected: ' + result)
    return x509.load_pem_x509_certificate(record.pem.encode())

def user_key(record, password):
    key = unlock(vault('key_vault', record.key_file).read_bytes(), password)
    cert = x509.load_pem_x509_certificate(record.pem.encode())
    if key.public_key().public_numbers() != cert.public_key().public_numbers():
        raise ValueError('Key does not match certificate')
    return key
