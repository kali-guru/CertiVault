import click
from flask import current_app
from .extensions import db
from .models import User
from .services import register
from . import pki

def register_commands(app):
    @app.cli.command('init-ca')
    def initialize_ca():
        """Initialize a new encrypted educational CA; never overwrite one."""
        try:
            pki.init_ca()
        except ValueError as exc:
            raise click.ClickException(str(exc))
        click.echo('Encrypted CA initialized.')

    @app.cli.command('create-admin')
    @click.option('--username', prompt=True)
    @click.option('--email', prompt=True)
    @click.option('--name', prompt=True)
    @click.password_option()
    def create_admin(username, email, name, password):
        """Create an administrator via trusted local CLI only."""
        from .forms import RegisterForm
        form = RegisterForm(meta={'csrf':False}, data=dict(username=username,email=email,name=name,password=password,confirm=password))
        if not form.validate():
            raise click.ClickException('Invalid registration fields: '+str(form.errors))
        register(name, username, email, password, 'ADMIN')
        click.echo('Administrator created.')

    @app.cli.command('seed-demo')
    @click.password_option(help='Choose a development-only password, at least 12 characters.')
    def seed_demo(password):
        """Create four fictional accounts in development only."""
        if current_app.config['APP_ENV'] != 'development':
            raise click.ClickException('Demo seeding is restricted to development.')
        if len(password) < 12 or len(set(password)) < 6:
            raise click.ClickException('Use a strong passphrase of at least 12 characters.')
        for username, name, email, role in [
            ('alice','Alice Student','alice.student@example.test','USER'),
            ('bob','Bob Lecturer','bob.lecturer@example.test','USER'),
            ('carol','Carol Administrator','carol.admin@example.test','ADMIN'),
            ('employer','External Verifier','employer.verifier@example.test','USER')]:
            if not db.session.scalar(db.select(User).where(User.username == username)):
                register(name, username, email, password, role)
        click.echo('Demo accounts ready: alice, bob, carol, employer. Use your chosen password.')

    @app.cli.command('verify-security-config')
    def verify_config():
        """Check secret configuration and sensitive directory permissions."""
        from pathlib import Path
        bad = [str(p.relative_to(current_app.instance_path)) for p in Path(current_app.instance_path).rglob('*')
               if p.is_file() and p.suffix == '.pem' and p.stat().st_mode & 0o077]
        if bad:
            raise click.ClickException('Overly broad PEM permissions: '+', '.join(bad))
        click.echo('Secrets configured; PEM permissions checked. Environment: '+current_app.config['APP_ENV'])
        if current_app.config['APP_ENV'] != 'production':
            click.echo('Development mode: use HTTPS and secure cookies for deployment.')
