from flask import Blueprint, render_template, abort
from flask_login import current_user, login_required
from .extensions import db, limiter
from .models import Document, DocumentSignature, EncryptedPackage, AuditEvent, User, Certificate
from . import pki

main = Blueprint('main', __name__)

@main.get('/')
def home():
    return render_template('home.html', title='Secure. Sign. Verify. Protect.')

@main.get('/about')
@main.get('/security')
@main.get('/how-it-works')
def information():
    from flask import request
    return render_template('information.html', title={'/about':'Trust built on evidence','/security':'Security, explained','/how-it-works':'From identity to verified document'}[request.path])

@main.get('/dashboard')
@login_required
def dashboard():
    docs = db.session.scalars(db.select(Document).where(Document.owner_id == current_user.id)).all()
    packages = db.session.scalars(db.select(EncryptedPackage).where(EncryptedPackage.sender_id == current_user.id)).all()
    received = db.session.scalars(db.select(EncryptedPackage).where(EncryptedPackage.recipient_id == current_user.id)).all()
    cert = pki.latest(current_user.id)
    events = db.session.scalars(db.select(AuditEvent).where(AuditEvent.user_id == current_user.id).order_by(AuditEvent.id.desc()).limit(6)).all()
    return render_template('dashboard.html', title='Your security workspace', docs=docs, packages=packages,
                           received=received, signed=sum(bool(d.signatures) for d in docs), cert=cert,
                           status=pki.validate(cert.pem,current_user.id), events=events,
                           parsed=pki.x509.load_pem_x509_certificate(cert.pem.encode()))

@main.get('/audit')
@login_required
def audit_log():
    rows = db.session.scalars(db.select(AuditEvent).where(AuditEvent.user_id == current_user.id).order_by(AuditEvent.id.desc()).limit(500)).all()
    return render_template('audit.html', title='Security activity', events=rows)

@main.get('/admin')
@login_required
def admin():
    if current_user.role != 'ADMIN':
        abort(403)
    return render_template('admin.html', title='Administration', users=db.session.scalars(db.select(User)).all(),
        certificates=db.session.scalars(db.select(Certificate)).all(), validate=pki.validate,
        events=db.session.scalars(db.select(AuditEvent).order_by(AuditEvent.id.desc()).limit(500)).all())

@main.route('/demonstrations', methods=['GET','POST'])
@login_required
@limiter.limit('5 per minute')
def demonstrations():
    from flask import request
    from .demonstrations import run_demonstrations
    results = run_demonstrations() if request.method == 'POST' else None
    return render_template('demonstrations.html', title='Security laboratory', results=results)
