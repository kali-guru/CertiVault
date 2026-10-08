import os
from pathlib import Path
from datetime import timedelta
from dotenv import load_dotenv
from flask import Flask, render_template
from .extensions import db, migrate, login, csrf, limiter

def create_app(test_config=None):
    load_dotenv()
    app = Flask(__name__, instance_relative_config=True, instance_path=os.environ.get('CERTIVAULT_INSTANCE', str(Path(__file__).resolve().parent.parent / 'instance')))
    app.config.from_mapping(SECRET_KEY=os.getenv('SECRET_KEY'), CA_PASSPHRASE=os.getenv('CA_PASSPHRASE'),
        APP_ENV=os.getenv('APP_ENV','development'), SQLALCHEMY_DATABASE_URI='sqlite:///certivault.db',
        MAX_CONTENT_LENGTH=int(os.getenv('MAX_CONTENT_LENGTH','16777216')),
        SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax',
        SESSION_COOKIE_SECURE=os.getenv('SESSION_COOKIE_SECURE','false').lower() == 'true',
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=30), WTF_CSRF_TIME_LIMIT=3600,
        RATELIMIT_STORAGE_URI='memory://')
    if test_config:
        app.config.update(test_config)
        if test_config.get('INSTANCE_PATH'):
            app.instance_path = test_config['INSTANCE_PATH']
    for secret in ['SECRET_KEY','CA_PASSPHRASE']:
        if not app.config.get(secret) or len(app.config[secret]) < 32:
            raise RuntimeError(secret + ' must contain at least 32 characters; run scripts/configure.py')
    if app.config['APP_ENV'] == 'production' and not app.config['SESSION_COOKIE_SECURE']:
        raise RuntimeError('Production requires secure cookies and HTTPS')
    if app.config['APP_ENV'] == 'production' and (app.config.get('DEBUG') or os.getenv('FLASK_DEBUG', '').lower() in ('1', 'true', 'yes')):
        raise RuntimeError('Production forbids the Flask debugger')
    for folder in ['', 'uploads','encrypted','key_vault','ca']:
        path = Path(app.instance_path) / folder
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
    for extension in (db, login, csrf, limiter):
        extension.init_app(app)
    migrate.init_app(app, db)
    login.login_view = 'auth.login_view'
    login.session_protection = 'strong'
    from .models import User
    @login.user_loader
    def load_user(identifier):
        return db.session.get(User, int(identifier)) if identifier.isdigit() else None
    from .web import main
    from .auth import auth
    from .documents import documents
    from .certificates import certificates
    for bp in [main, auth, documents, certificates]:
        app.register_blueprint(bp)
    from .cli import register_commands
    register_commands(app)
    @app.after_request
    def secure_headers(response):
        response.headers.update({'Content-Security-Policy': "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'",
            'X-Content-Type-Options':'nosniff','Referrer-Policy':'same-origin','X-Frame-Options':'DENY',
            'Permissions-Policy':'camera=(), microphone=(), geolocation=()', 'Cache-Control':'no-store'})
        if app.config['APP_ENV'] == 'production':
            response.headers['Strict-Transport-Security'] = 'max-age=31536000'
        return response
    def error_page(error):
        db.session.rollback()
        return render_template('error.html', title=str(error.code), error=error), error.code
    for code in (400,403,404,413,429,500):
        app.register_error_handler(code, error_page)
    return app
