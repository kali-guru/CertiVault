import copy
import io
import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
import pytest
from cryptography import x509
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID
from app import pki
from app.extensions import db
from app.models import Certificate, CertificateRevocation, Document, DocumentSignature, EncryptedPackage, AuthenticationChallenge, AuditEvent, User, now
from app.services import register, check_password, new_challenge, consume_challenge, challenge_message, verify_signature
from app.crypto.primitives import keypair, protect, unlock, sign, verify, encrypt, decrypt, unb64, b64, digest
from conftest import PASSWORD

def revoke(cert, actor):
    db.session.add(CertificateRevocation(certificate_id=cert.id, actor_id=actor.id, reason='KEY_COMPROMISE'))
    db.session.commit()

def make_signature(user):
    cert=pki.latest(user.id)
    return SimpleNamespace(certificate=cert, signer_id=user.id, signature=sign(pki.user_key(cert,PASSWORD),b'original'), digest=digest(b'original'))

def replace_cert_dates(cert, expired=True):
    original=x509.load_pem_x509_certificate(cert.pem.encode())
    ca=pki.ca_certificate()
    clock=datetime.now(timezone.utc)
    builder=(x509.CertificateBuilder().subject_name(original.subject).issuer_name(ca.subject)
        .public_key(original.public_key()).serial_number(original.serial_number)
        .not_valid_before(clock-timedelta(days=5) if expired else clock+timedelta(days=1))
        .not_valid_after(clock-timedelta(days=1) if expired else clock+timedelta(days=5)))
    for extension in original.extensions:
        builder=builder.add_extension(extension.value,extension.critical)
    key=unlock(pki.vault('ca','private.pem').read_bytes(),pki.current_app.config['CA_PASSPHRASE'])
    changed=builder.sign(key,hashes.SHA256(),rsa_padding=pki.PSS)
    cert.pem=changed.public_bytes(serialization.Encoding.PEM).decode()
    cert.fingerprint=changed.fingerprint(hashes.SHA256()).hex()
    db.session.commit()

@pytest.mark.parametrize('path',['/','/about','/security','/how-it-works','/login','/register','/certificate-auth'])
def test_public_pages(client,path):
    response=client.get(path)
    assert response.status_code == 200
    assert b'CertiVault' in response.data

@pytest.mark.parametrize('path',['/dashboard','/documents','/packages','/certificates','/audit','/admin','/verify'])
def test_auth_required(client,path):
    assert client.get(path).status_code == 302

@pytest.mark.parametrize('path',['/dashboard','/documents','/packages','/certificates','/audit','/verify','/demonstrations','/certificates/validate','/key-export'])
def test_authenticated_pages(alice,path):
    assert alice.get(path).status_code == 200

def test_registration_and_password_storage(client):
    fields=dict(name='Test Student',username='student',email='student@example.com',password=PASSWORD,confirm=PASSWORD)
    assert client.post('/register',data=fields).status_code == 302
    user=db.session.scalar(db.select(User))
    assert user.password_hash.startswith('$argon2id$')
    assert PASSWORD not in user.password_hash
    assert check_password(user,PASSWORD)
    assert not check_password(user,'wrong')
    assert pki.validate(pki.latest(user.id).pem,user.id) == 'VALID'
    assert client.post('/register',data=fields).status_code == 200
    fields['username']='another'
    assert client.post('/register',data=fields).status_code == 200
    assert len(db.session.scalars(db.select(User)).all()) == 1

def test_login_logout_and_redirect(client,users):
    assert client.post('/login',data={'identity':'alice','password':'incorrect'}).status_code == 200
    response=client.post('/login?next=https://evil.example',data={'identity':'alice','password':PASSWORD})
    assert response.location == '/dashboard'
    assert client.post('/logout').status_code == 302
    assert client.get('/dashboard').status_code == 302

def test_csrf_headers_and_errors(app,client):
    app.config['WTF_CSRF_ENABLED']=True
    assert client.post('/login',data={}).status_code == 400
    response=client.get('/')
    assert "frame-ancestors 'none'" in response.headers['Content-Security-Policy']
    assert response.headers['X-Content-Type-Options'] == 'nosniff'
    assert client.get('/does-not-exist').status_code == 404

def test_ca_and_encrypted_keys(app,users):
    ca=pki.ca_certificate()
    ca.verify_directly_issued_by(ca)
    assert ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    assert ca.public_key().key_size == 3072
    with pytest.raises(ValueError): pki.init_ca()
    for user in users:
        cert=pki.latest(user.id)
        raw=pki.vault('key_vault',cert.key_file).read_bytes()
        assert b'BEGIN ENCRYPTED PRIVATE KEY' in raw
        with pytest.raises(ValueError): unlock(raw,'wrong')
        assert pki.validate(cert.pem,user.id) == 'VALID'
        assert pki.validate(cert.pem,-1) == 'IDENTITY MISMATCH'
    assert b'ENCRYPTED PRIVATE KEY' in pki.vault('ca','private.pem').read_bytes()

@pytest.mark.parametrize('expired,expected',[(True,'EXPIRED'),(False,'INVALID CERTIFICATE')])
def test_certificate_dates(app,users,expired,expected):
    cert=pki.latest(users[0].id)
    replace_cert_dates(cert,expired)
    assert pki.validate(cert.pem,users[0].id) == expected

def test_revoked_certificate_and_signature(app,users):
    record=make_signature(users[0])
    revoke(record.certificate,users[0])
    assert pki.validate(record.certificate.pem,users[0].id) == 'REVOKED'
    assert verify_signature(record,b'original') == 'CERTIFICATE REVOKED'

def test_expired_signature(app,users):
    record=make_signature(users[0])
    replace_cert_dates(record.certificate)
    assert verify_signature(record,b'original') == 'CERTIFICATE EXPIRED'

def test_untrusted_and_spoofed_certificates(app,users):
    cert=pki.latest(users[0].id)
    assert pki.validate('not a certificate') == 'INVALID CERTIFICATE'
    assert pki.validate(cert.pem,users[1].id) == 'IDENTITY MISMATCH'
    key=keypair()
    clock=datetime.now(timezone.utc)
    name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'Other Test CA')])
    other=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(clock-timedelta(days=1))
        .not_valid_after(clock+timedelta(days=1)).sign(key,hashes.SHA256()))
    assert pki.validate(other.public_bytes(serialization.Encoding.PEM)) == 'UNTRUSTED ISSUER'
    # Same issuer name is insufficient: signature must chain to the pinned root.
    spoof=(x509.CertificateBuilder().subject_name(name).issuer_name(pki.ca_certificate().subject).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(clock-timedelta(days=1))
        .not_valid_after(clock+timedelta(days=1)).sign(key,hashes.SHA256()))
    assert pki.validate(spoof.public_bytes(serialization.Encoding.PEM)) == 'INVALID SIGNATURE'

def test_signatures(app,users):
    record=make_signature(users[0])
    assert verify_signature(record,b'original',users[0].id) == 'VALID SIGNATURE'
    assert verify_signature(record,b'modified') == 'DOCUMENT MODIFIED'
    assert verify_signature(record,b'original',users[1].id) == 'SIGNER MISMATCH'
    record.signature=sign(pki.user_key(pki.latest(users[1].id),PASSWORD),b'original')
    assert verify_signature(record,b'original') == 'INVALID SIGNATURE'

def test_encryption_and_corruption(app,users):
    alice=pki.user_key(pki.latest(users[0].id),PASSWORD)
    bob=pki.user_key(pki.latest(users[1].id),PASSWORD)
    meta={'recipient':users[0].id,'sender':users[1].id}
    package=encrypt(alice.public_key(),b'secret',meta)
    assert decrypt(alice,package,meta) == b'secret'
    assert package['nonce'] != encrypt(alice.public_key(),b'secret',meta)['nonce']
    with pytest.raises(ValueError): decrypt(bob,package,meta)
    with pytest.raises(ValueError): decrypt(alice,package,dict(meta,recipient=-1))
    for field in ('ciphertext','wrapped_key','nonce'):
        changed=copy.deepcopy(package)
        raw=bytearray(unb64(changed[field])); raw[0]^=1; changed[field]=b64(bytes(raw))
        with pytest.raises((ValueError,InvalidTag)): decrypt(alice,changed,meta)
    with pytest.raises(ValueError): decrypt(alice,{},meta)

@pytest.mark.parametrize('case',['valid','invalid','expired','replay','revoked','spoofed','binding','certificate_expired'])
def test_challenge_security(app,users,case):
    user=users[0]; cert=pki.latest(user.id)
    challenge=new_challenge(user,'browser-session')
    signature=sign(pki.user_key(cert,PASSWORD),challenge_message(challenge))
    pem=cert.pem.encode(); binding='browser-session'
    if case=='invalid': signature=b'not a signature'
    if case=='expired': challenge.expires=now()-timedelta(seconds=1); db.session.commit()
    if case=='revoked': revoke(cert,user)
    if case=='certificate_expired':
        replace_cert_dates(cert)
        pem=cert.pem.encode()
    if case=='spoofed': pem=pki.latest(users[1].id).pem.encode()
    if case=='binding': binding='different-session'
    if case in ('valid','replay'):
        assert consume_challenge(challenge.id,signature,pem,binding).id == user.id
        with pytest.raises(ValueError): consume_challenge(challenge.id,signature,pem,binding)
        assert db.session.scalar(db.select(AuditEvent).where(AuditEvent.event=='REPLAY_ATTEMPT_DETECTED'))
    else:
        with pytest.raises(ValueError): consume_challenge(challenge.id,signature,pem,binding)

def upload(alice,filename='transcript.txt',data=b'Original transcript'):
    response=alice.post('/documents/upload',data={'file':(io.BytesIO(data),filename)},content_type='multipart/form-data')
    assert response.status_code == 302
    return db.session.scalar(db.select(Document).order_by(Document.id.desc()))

def test_end_to_end_documents(alice,users):
    doc=upload(alice,'../../transcript.txt')
    assert doc.name == 'transcript.txt' and '/' not in doc.storage
    assert alice.get('/documents/'+str(doc.id)).status_code == 200
    assert alice.post(f'/documents/{doc.id}/sign',data={'password':PASSWORD}).status_code == 302
    sig=db.session.scalar(db.select(DocumentSignature))
    assert verify_signature(sig,b'Original transcript') == 'VALID SIGNATURE'
    evidence=alice.get(f'/signatures/{sig.id}/evidence').data
    for data,expected in [(b'Original transcript',b'VALID SIGNATURE'),(b'changed',b'DOCUMENT MODIFIED')]:
        response=alice.post('/verify',data={'file':(io.BytesIO(data),'transcript.txt'),'evidence':(io.BytesIO(evidence),'evidence.json'),'signer':'alice'})
        assert expected in response.data
    assert alice.post(f'/documents/{doc.id}/encrypt',data={'recipient':users[1].id}).status_code == 302
    package=db.session.scalar(db.select(EncryptedPackage))
    assert alice.get(f'/packages/{package.id}/decrypt').status_code == 403
    alice.post('/logout')
    alice.post('/login',data={'identity':'bob','password':PASSWORD})
    assert alice.get(f'/documents/{doc.id}').status_code == 403
    assert alice.get(f'/documents/{doc.id}/download').status_code == 403
    assert alice.get(f'/signatures/{sig.id}/evidence').status_code == 403
    response=alice.post(f'/packages/{package.id}/decrypt',data={'password':PASSWORD})
    assert response.data == b'Original transcript'
    assert 'attachment' in response.headers['Content-Disposition']
    raw=json.loads(pki.vault('encrypted',package.storage).read_bytes())
    raw['ciphertext']=b64(b'broken')
    pki.vault('encrypted',package.storage).write_text(json.dumps(raw))
    assert b'Decryption failed' in alice.post(f'/packages/{package.id}/decrypt',data={'password':PASSWORD}).data

def test_roles_and_revocation(alice,users):
    cert=pki.latest(users[1].id)
    assert alice.get('/admin').status_code == 403
    assert alice.post(f'/certificates/{cert.id}/revoke',data={'reason':'KEY_COMPROMISE','password':PASSWORD}).status_code == 403
    alice.post('/logout'); alice.post('/login',data={'identity':'carol','password':PASSWORD})
    assert alice.get('/admin').status_code == 200
    assert alice.post(f'/certificates/{cert.id}/revoke',data={'reason':'KEY_COMPROMISE','password':PASSWORD}).status_code == 302
    assert pki.validate(cert.pem) == 'REVOKED'

def test_upload_limits(app,alice):
    app.config['MAX_CONTENT_LENGTH']=1024
    assert alice.post('/documents/upload',data={'file':(io.BytesIO(b'x'*2048),'large.bin')}).status_code == 413

def test_no_secrets_in_audit(alice,users):
    upload(alice)
    events=db.session.scalars(db.select(AuditEvent)).all()
    assert events
    for event in events:
        assert PASSWORD not in event.detail
        assert 'PRIVATE KEY' not in event.detail

def test_live_demonstrations(alice):
    response=alice.post('/demonstrations')
    assert response.status_code == 200
    assert response.data.count(b'PASSED') == 6
    assert b'FAILED' not in response.data

def test_certificate_login_http(client,users):
    cert=pki.latest(users[0].id)
    response=client.post('/certificate-auth',data={'identity':'alice'})
    assert response.status_code == 200
    challenge=db.session.scalar(db.select(AuthenticationChallenge))
    signature=b64(sign(pki.user_key(cert,PASSWORD),challenge_message(challenge)))
    data={'challenge_id':challenge.id,'signature':signature,'certificate':(io.BytesIO(cert.pem.encode()),'cert.pem')}
    assert client.post('/certificate-auth/verify',data=data).location == '/dashboard'
    assert client.get('/dashboard').status_code == 200

def test_csrf_valid_login(app,client,users):
    import re
    app.config['WTF_CSRF_ENABLED']=True
    response=client.get('/login')
    token=re.search(rb'name="csrf_token" type="hidden" value="([^"]+)"',response.data).group(1).decode()
    response=client.post('/login',data={'identity':'alice','password':PASSWORD,'csrf_token':token})
    assert response.location == '/dashboard'

def test_cli_and_migration(app,tmp_path):
    runner=app.test_cli_runner()
    assert runner.invoke(args=['verify-security-config']).exit_code == 0
    assert runner.invoke(args=['db','current']).exit_code == 0
    app.config['APP_ENV']='production'
    result=runner.invoke(args=['seed-demo','--password',PASSWORD])
    assert result.exit_code != 0
    assert 'restricted to development' in result.output

def test_revoked_export_safe(alice,users):
    revoke(pki.latest(users[0].id),users[0])
    response=alice.post('/key-export',data={'password':PASSWORD},follow_redirects=True)
    assert response.status_code == 200
    assert b'Export blocked' in response.data

def test_admin_cannot_read_others_original(alice,users):
    doc=upload(alice)
    alice.post('/logout'); alice.post('/login',data={'identity':'carol','password':PASSWORD})
    assert alice.get(f'/documents/{doc.id}/download').status_code == 403

def test_concurrent_challenge_claim(app,users):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier
    cert=pki.latest(users[0].id)
    challenge=new_challenge(users[0],'shared-browser')
    identifier=challenge.id
    signature=sign(pki.user_key(cert,PASSWORD),challenge_message(challenge))
    pem=cert.pem.encode()
    barrier=Barrier(2)
    def attempt():
        with app.app_context():
            barrier.wait(timeout=10)
            try:
                consume_challenge(identifier,signature,pem,'shared-browser')
                return True
            except ValueError:
                return False
    with ThreadPoolExecutor(max_workers=2) as executor:
        results=list(executor.map(lambda _:attempt(),range(2)))
    assert sorted(results) == [False,True]

def test_production_guards(tmp_path,monkeypatch):
    import secrets
    from app import create_app
    cfg=dict(SECRET_KEY=secrets.token_urlsafe(48),CA_PASSPHRASE=secrets.token_urlsafe(48),
             APP_ENV='production',INSTANCE_PATH=str(tmp_path))
    with pytest.raises(RuntimeError,match='secure cookies'): create_app(dict(cfg,SESSION_COOKIE_SECURE=False))
    monkeypatch.setenv('FLASK_DEBUG','1')
    with pytest.raises(RuntimeError,match='debugger'): create_app(dict(cfg,SESSION_COOKIE_SECURE=True))

def test_seed_and_admin_commands(app):
    runner=app.test_cli_runner()
    result=runner.invoke(args=['seed-demo'],input=PASSWORD+'\n'+PASSWORD+'\n')
    assert result.exit_code == 0, result.output
    assert len(db.session.scalars(db.select(User)).all()) == 4
    result=runner.invoke(args=['create-admin','--username','newadmin','--email','admin@example.com','--name','New Admin'],input=PASSWORD+'\n'+PASSWORD+'\n')
    assert result.exit_code == 0, result.output
    assert db.session.scalar(db.select(User).where(User.username=='newadmin')).role == 'ADMIN'

def test_encrypted_export_and_public_validation(alice,users):
    cert=pki.latest(users[0].id)
    response=alice.post('/key-export',data={'password':PASSWORD})
    assert response.status_code == 200
    assert b'BEGIN ENCRYPTED PRIVATE KEY' in response.data
    assert unlock(response.data,PASSWORD).public_key().key_size == 3072
    assert alice.get(f'/certificates/{cert.id}/download').data == cert.pem.encode()
    assert b'BEGIN CERTIFICATE' in alice.get('/ca.pem').data
    response=alice.post('/certificates/validate',data={'certificate':(io.BytesIO(cert.pem.encode()),'cert.pem')})
    assert b'>VALID<' in response.data

def test_unknown_challenge_and_failed_attempt_consumption(app,users):
    with pytest.raises(ValueError): consume_challenge('missing',b'x',b'x','session')
    cert=pki.latest(users[0].id)
    challenge=new_challenge(users[0],'session')
    with pytest.raises(ValueError): consume_challenge(challenge.id,b'bad',cert.pem.encode(),'session')
    good=sign(pki.user_key(cert,PASSWORD),challenge_message(challenge))
    with pytest.raises(ValueError): consume_challenge(challenge.id,good,cert.pem.encode(),'session')
