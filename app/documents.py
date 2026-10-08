import io
import json
import secrets
from flask import Blueprint, render_template, redirect, url_for, flash, send_file, abort, request
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
from .extensions import db, limiter
from .models import Document, DocumentSignature, EncryptedPackage, User
from .forms import UploadForm, PasswordForm, EncryptForm, VerifyForm
from .services import audit, verify_signature
from .crypto.primitives import digest, sign, encrypt, decrypt, canonical, b64, unb64
from . import pki

documents = Blueprint('documents', __name__)

def owned(identifier):
    doc = db.get_or_404(Document, identifier)
    if doc.owner_id != current_user.id:
        audit('UNAUTHORIZED_ACCESS_ATTEMPT', current_user.id, 'FAILURE', 'Document access denied')
        db.session.commit()
        abort(403)
    return doc

def download(data, name, mime='application/octet-stream'):
    return send_file(io.BytesIO(data), as_attachment=True, download_name=name, mimetype=mime)

@documents.get('/documents')
@login_required
def index():
    docs = db.session.scalars(db.select(Document).where(Document.owner_id == current_user.id).order_by(Document.id.desc())).all()
    return render_template('documents.html', title='My documents', docs=docs)

@documents.route('/documents/upload', methods=['GET','POST'])
@login_required
def upload():
    form = UploadForm()
    if form.validate_on_submit():
        data = form.file.data.read()
        name = secure_filename(form.file.data.filename)[:255] or 'document.bin'
        storage = secrets.token_hex(24)
        pki.private_write(pki.vault('uploads', storage), data)
        doc = Document(owner_id=current_user.id, name=name, storage=storage, digest=digest(data), size=len(data))
        db.session.add(doc)
        audit('DOCUMENT_UPLOADED', current_user.id)
        db.session.commit()
        return redirect(url_for('documents.detail', identifier=doc.id))
    return render_template('form.html', title='Upload a document', form=form, intro='Files stay in private storage. Originals are not encrypted at rest; use hybrid encryption to create a protected recipient package.')

@documents.get('/documents/<int:identifier>')
@login_required
def detail(identifier):
    return render_template('document.html', title='Document workspace', doc=owned(identifier))

@documents.get('/documents/<int:identifier>/download')
@login_required
def original(identifier):
    doc = owned(identifier)
    return download(pki.vault('uploads', doc.storage).read_bytes(), doc.name)

@documents.route('/documents/<int:identifier>/sign', methods=['GET','POST'])
@login_required
@limiter.limit('10 per minute')
def signing(identifier):
    doc = owned(identifier)
    form = PasswordForm()
    if form.validate_on_submit():
        try:
            cert = pki.latest(current_user.id)
            pki.require_valid(cert, current_user.id)
            data = pki.vault('uploads', doc.storage).read_bytes()
            signature = sign(pki.user_key(cert, form.password.data), data)
            db.session.add(DocumentSignature(document_id=doc.id, signer_id=current_user.id, certificate_id=cert.id, signature=signature, digest=digest(data)))
            audit('DOCUMENT_SIGNED', current_user.id)
            db.session.commit()
            flash('Document signed using RSA-PSS / SHA-256.', 'success')
            return redirect(url_for('documents.detail', identifier=doc.id))
        except ValueError:
            flash('Signing failed. Check your key passphrase and certificate status.', 'danger')
    return render_template('form.html', title='Sign '+doc.name, form=form, intro='Signing proves integrity and private-key possession. It does not encrypt the document.')

@documents.get('/signatures/<int:identifier>/evidence')
@login_required
def evidence(identifier):
    record = db.get_or_404(DocumentSignature, identifier)
    owned(record.document_id)
    data = dict(version=1, signature=b64(record.signature), certificate=record.certificate.pem,
                digest=record.digest, signer=record.certificate.user.username, signed_at=record.created.isoformat(),
                algorithm='RSA-PSS-SHA256-salt32')
    return download(canonical(data), 'signature-evidence.json', 'application/json')

@documents.post('/signatures/<int:identifier>/verify')
@login_required
def verify_stored(identifier):
    record = db.get_or_404(DocumentSignature, identifier)
    doc = owned(record.document_id)
    result = verify_signature(record, pki.vault('uploads', doc.storage).read_bytes(), current_user.id)
    audit('SIGNATURE_VERIFIED' if result == 'VALID SIGNATURE' else 'SIGNATURE_INVALID', current_user.id, 'SUCCESS' if result == 'VALID SIGNATURE' else 'FAILURE', result)
    db.session.commit()
    flash(result, 'success' if result == 'VALID SIGNATURE' else 'danger')
    return redirect(url_for('documents.detail', identifier=doc.id))

@documents.route('/verify', methods=['GET','POST'])
@login_required
def verify_external():
    from types import SimpleNamespace
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from .models import Certificate
    form = VerifyForm()
    result = None
    info = None
    if form.validate_on_submit():
        try:
            payload = json.loads(form.evidence.data.read(65536))
            if payload['version'] != 1 or payload['algorithm'] != 'RSA-PSS-SHA256-salt32':
                raise ValueError('Unsupported format')
            status = pki.validate(payload['certificate'])
            if status != 'VALID':
                result = 'CERTIFICATE ' + status
            else:
                parsed = x509.load_pem_x509_certificate(payload['certificate'].encode())
                cert = db.session.scalar(db.select(Certificate).where(Certificate.fingerprint == parsed.fingerprint(hashes.SHA256()).hex()))
                expected = db.session.scalar(db.select(User).where(User.username == form.signer.data.strip().lower()))
                record = SimpleNamespace(certificate=cert, signer_id=cert.user_id, signature=unb64(payload['signature']), digest=payload['digest'])
                result = verify_signature(record, form.file.data.read(), expected.id if expected else -1)
                info = {'Signer':cert.user.username, 'Certificate serial':cert.serial,'Fingerprint':cert.fingerprint,
                        'Algorithm':'RSA-PSS / SHA-256', 'Claimed signing time (not trusted timestamp)':payload.get('signed_at','Unknown')}
        except (ValueError, KeyError, TypeError):
            result = 'INVALID SIGNATURE EVIDENCE'
        audit('SIGNATURE_VERIFIED' if result == 'VALID SIGNATURE' else 'SIGNATURE_INVALID', current_user.id, 'SUCCESS' if result == 'VALID SIGNATURE' else 'FAILURE', result)
        db.session.commit()
    return render_template('form.html', title='Verify a signed document', form=form, result=result, info=info, intro='Upload the exact document and detached evidence shared by its signer. Verification uses current certificate validity and revocation status.')

@documents.route('/documents/<int:identifier>/encrypt', methods=['GET','POST'])
@login_required
def encryption(identifier):
    doc = owned(identifier)
    form = EncryptForm()
    users = db.session.scalars(db.select(User).order_by(User.username)).all()
    form.recipient.choices = [(u.id, u.username+' · '+u.name) for u in users]
    if form.validate_on_submit():
        cert = pki.latest(form.recipient.data)
        try:
            public = pki.require_valid(cert, form.recipient.data).public_key()
            record = EncryptedPackage(sender_id=current_user.id, recipient_id=form.recipient.data, certificate_id=cert.id, name=doc.name, storage=secrets.token_hex(24))
            db.session.add(record)
            db.session.flush()
            package = encrypt(public, pki.vault('uploads', doc.storage).read_bytes(), package_metadata(record))
            pki.private_write(pki.vault('encrypted', record.storage), canonical(package))
            audit('DOCUMENT_ENCRYPTED', current_user.id)
            db.session.commit()
            flash('Encrypted package delivered to recipient.', 'success')
            return redirect(url_for('documents.packages'))
        except ValueError:
            db.session.rollback()
            flash('Recipient certificate is not valid.', 'danger')
    return render_template('form.html', title='Encrypt '+doc.name, form=form, intro='A fresh AES-256 key encrypts this document. RSA-OAEP wraps that key for your chosen recipient.')

def package_metadata(record):
    return dict(sender=record.sender_id, recipient=record.recipient_id, fingerprint=record.certificate.fingerprint,
                created=record.created.isoformat(), name=record.name, package_id=record.id)

@documents.get('/packages')
@login_required
def packages():
    rows = db.session.scalars(db.select(EncryptedPackage).where((EncryptedPackage.sender_id == current_user.id)|(EncryptedPackage.recipient_id == current_user.id)).order_by(EncryptedPackage.id.desc())).all()
    return render_template('packages.html', title='Encrypted exchange', packages=rows)

@documents.get('/packages/<int:identifier>/download')
@login_required
def package_download(identifier):
    row = db.get_or_404(EncryptedPackage, identifier)
    if current_user.id not in (row.sender_id, row.recipient_id):
        abort(403)
    return download(pki.vault('encrypted', row.storage).read_bytes(), 'encrypted-package.json','application/json')

@documents.route('/packages/<int:identifier>/decrypt', methods=['GET','POST'])
@login_required
@limiter.limit('10 per minute')
def decryption(identifier):
    row = db.get_or_404(EncryptedPackage, identifier)
    if row.recipient_id != current_user.id:
        audit('UNAUTHORIZED_ACCESS_ATTEMPT', current_user.id, 'FAILURE','Recipient mismatch')
        db.session.commit()
        abort(403)
    form = PasswordForm()
    if form.validate_on_submit():
        try:
            pki.require_valid(row.certificate, current_user.id)
            package = json.loads(pki.vault('encrypted', row.storage).read_bytes())
            data = decrypt(pki.user_key(row.certificate, form.password.data), package, package_metadata(row))
            audit('DOCUMENT_DECRYPTED', current_user.id)
            db.session.commit()
            return download(data, row.name)
        except Exception:
            db.session.rollback()
            audit('DECRYPTION_FAILED', current_user.id, 'FAILURE')
            db.session.commit()
            flash('Decryption failed. Check passphrase, certificate status and package integrity.', 'danger')
    return render_template('form.html', title='Decrypt '+row.name, form=form, intro='Only the intended recipient may decrypt. Plaintext is returned as a download and is never written to a temporary file.')
