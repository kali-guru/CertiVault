import secrets
from flask import Blueprint, render_template, redirect, url_for, flash, session, request, send_file
from flask_login import login_user, logout_user, login_required, current_user
from sqlalchemy.exc import IntegrityError
from .extensions import db, limiter
from .models import User
from .forms import RegisterForm, LoginForm, ChallengeForm, ProofForm
from .services import register, check_password, audit, new_challenge, challenge_message, consume_challenge
from .crypto.primitives import unb64
from . import pki

auth = Blueprint('auth', __name__)

def find_user(identity):
    value = identity.strip().lower()
    return db.session.scalar(db.select(User).where((User.username == value) | (User.email == value)))

@auth.route('/register', methods=['GET','POST'])
@limiter.limit('5 per minute')
def register_view():
    form = RegisterForm()
    if form.validate_on_submit():
        if len(set(form.password.data)) < 6:
            form.password.errors.append('Choose a less repetitive passphrase.')
        else:
            try:
                register(form.name.data, form.username.data, form.email.data, form.password.data)
                flash('Account and cryptographic identity created. Sign in to continue.', 'success')
                return redirect(url_for('auth.login_view'))
            except IntegrityError:
                db.session.rollback()
                flash('Registration could not be completed with these details.', 'warning')
    return render_template('form.html', title='Create your secure identity', form=form, intro='Your password protects your account and encrypts your private key. Keep it safe: no password recovery is available in this prototype.')

@auth.route('/login', methods=['GET','POST'])
@limiter.limit('10 per minute')
def login_view():
    form = LoginForm()
    if form.validate_on_submit():
        user = find_user(form.identity.data)
        if check_password(user, form.password.data):
            session.clear()
            login_user(user)
            session.permanent = True
            audit('LOGIN_SUCCESS', user.id)
            db.session.commit()
            return redirect(url_for('main.dashboard'))
        audit('LOGIN_FAILURE', outcome='FAILURE')
        db.session.commit()
        flash('Invalid username/email or password.', 'danger')
    return render_template('form.html', title='Welcome back', form=form, intro='Access your documents and cryptographic identity.')

@auth.post('/logout')
@login_required
def logout():
    audit('LOGOUT', current_user.id)
    db.session.commit()
    logout_user()
    session.clear()
    return redirect(url_for('main.home'))

@auth.route('/certificate-auth', methods=['GET','POST'])
@limiter.limit('10 per minute')
def certificate_auth():
    form = ChallengeForm()
    challenge = None
    if form.validate_on_submit():
        binding = session.setdefault('challenge_binding', secrets.token_hex(32))
        challenge = new_challenge(find_user(form.identity.data), binding)
    return render_template('challenge.html', title='Prove your private-key possession', form=form,
                           challenge=challenge, message=challenge_message(challenge).decode() if challenge else None, proof=ProofForm())

@auth.post('/certificate-auth/verify')
@limiter.limit('10 per minute')
def proof():
    form = ProofForm()
    if form.validate_on_submit():
        try:
            user = consume_challenge(form.challenge_id.data, unb64(form.signature.data.strip()),
                form.certificate.data.read(32768), session.get('challenge_binding',''))
            session.clear()
            login_user(user)
            session.permanent = True
            return redirect(url_for('main.dashboard'))
        except (ValueError, TypeError):
            flash('Proof rejected. Request a fresh challenge and check the certificate and signature.', 'danger')
    else:
        flash('Complete all proof fields.', 'warning')
    return redirect(url_for('auth.certificate_auth'))

@auth.route('/key-export', methods=['GET','POST'])
@login_required
@limiter.limit('5 per minute')
def key_export():
    from .forms import PasswordForm
    form = PasswordForm()
    if form.validate_on_submit():
        if check_password(current_user, form.password.data):
            cert = pki.latest(current_user.id)
            if pki.validate(cert.pem, current_user.id) != 'VALID':
                flash('Export blocked: your certificate is no longer valid.', 'danger')
                return redirect(url_for('certificates.index'))
            audit('ENCRYPTED_KEY_EXPORTED', current_user.id)
            db.session.commit()
            return send_file(pki.vault('key_vault', cert.key_file), as_attachment=True, download_name='certivault-encrypted-key.pem', mimetype='application/octet-stream')
        flash('Password rejected.', 'danger')
    return render_template('form.html', title='Export encrypted identity key', form=form, intro='For local challenge signing. The downloaded PKCS#8 key remains encrypted with your registration password. Never share it.')
