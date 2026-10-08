from flask import Blueprint, render_template, redirect, url_for, flash, abort
from flask_login import login_required, current_user
from cryptography import x509
from .extensions import db
from .models import Certificate, CertificateRevocation
from .forms import ValidateForm, RevokeForm
from .services import audit, check_password
from .documents import download
from . import pki

certificates = Blueprint('certificates', __name__)

@certificates.get('/certificates')
@login_required
def index():
    rows = db.session.scalars(db.select(Certificate).where(Certificate.user_id == current_user.id).order_by(Certificate.id.desc())).all()
    return render_template('certificates.html', title='My cryptographic identity', certificates=rows, validate=pki.validate, parse=lambda c:x509.load_pem_x509_certificate(c.pem.encode()))

@certificates.get('/certificates/<int:identifier>/download')
@login_required
def public_download(identifier):
    cert = db.get_or_404(Certificate, identifier)
    if cert.user_id != current_user.id and current_user.role != 'ADMIN':
        abort(403)
    return download(cert.pem.encode(), 'certivault-certificate.pem','application/x-pem-file')

@certificates.get('/ca.pem')
def root_download():
    from cryptography.hazmat.primitives.serialization import Encoding
    return download(pki.ca_certificate().public_bytes(Encoding.PEM), 'certivault-root-ca.pem','application/x-pem-file')

@certificates.route('/certificates/validate', methods=['GET','POST'])
@login_required
def validation():
    form = ValidateForm()
    result = None
    if form.validate_on_submit():
        result = pki.validate(form.certificate.data.read(32768))
        audit('CERTIFICATE_VALIDATED' if result == 'VALID' else 'CERTIFICATE_VALIDATION_FAILED', current_user.id, 'SUCCESS' if result == 'VALID' else 'FAILURE', result)
        db.session.commit()
    return render_template('form.html', title='Certificate validation', form=form, result=result, intro='Checks CA signature, validity dates, registered identity, extensions and revocation. This CA is trusted only inside this educational application.')

@certificates.route('/certificates/<int:identifier>/revoke', methods=['GET','POST'])
@login_required
def revoke(identifier):
    cert = db.get_or_404(Certificate, identifier)
    if cert.user_id != current_user.id and current_user.role != 'ADMIN':
        abort(403)
    form = RevokeForm()
    if form.validate_on_submit():
        if not check_password(current_user, form.password.data):
            flash('Password rejected.', 'danger')
        elif cert.revocation:
            flash('Certificate already revoked.', 'warning')
        else:
            db.session.add(CertificateRevocation(certificate_id=cert.id, actor_id=current_user.id, reason=form.reason.data))
            audit('CERTIFICATE_REVOKED', current_user.id, detail='Serial '+cert.serial)
            db.session.commit()
            flash('Certificate permanently revoked. Existing encrypted packages using this certificate can no longer be decrypted through this application.', 'warning')
            return redirect(url_for('certificates.index'))
    return render_template('form.html', title='Revoke certificate', form=form, intro='This is irreversible. It blocks certificate authentication, signing, verification and decryption for this certificate. Password login remains available.')
