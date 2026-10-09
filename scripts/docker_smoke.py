"""CI-only HTTP and restart check. Creates a fictional account in disposable Docker data."""
import hashlib
import http.cookiejar
import re
import secrets
import subprocess
from urllib.parse import urlencode
from urllib.request import HTTPCookieProcessor, build_opener

BASE = 'http://127.0.0.1:8000'


def browser():
    return build_opener(HTTPCookieProcessor(http.cookiejar.CookieJar()))


def submit(client, path, fields):
    with client.open(BASE + path, timeout=15) as response:
        page = response.read().decode()
    token = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', page)
    if not token:
        raise RuntimeError('CSRF token missing')
    payload = urlencode(dict(fields, csrf_token=token.group(1))).encode()
    with client.open(BASE + path, data=payload, timeout=60) as response:
        return response.geturl(), response.read().decode()


def certificate_hash(client):
    with client.open(BASE + '/certificates', timeout=15) as response:
        page = response.read().decode()
    link = re.search(r'href="(/certificates/\d+/download)"', page)
    if not link:
        raise RuntimeError('Certificate download missing')
    with client.open(BASE + link.group(1), timeout=15) as response:
        return hashlib.sha256(response.read()).hexdigest()


def main():
    client = browser()
    username = 'ci_' + secrets.token_hex(8)
    password = secrets.token_urlsafe(32)
    location, _ = submit(client, '/register', dict(name='CI Fictional User', username=username,
        email=username+'@example.com', password=password, confirm=password))
    if not location.endswith('/login'):
        raise RuntimeError('Container registration failed')
    location, _ = submit(client, '/login', dict(identity=username,password=password))
    if not location.endswith('/dashboard'):
        raise RuntimeError('Container login failed')
    fingerprint = certificate_hash(client)
    subprocess.run(['docker','compose','restart','web'],check=True)
    subprocess.run(['docker','compose','up','-d','--wait','--wait-timeout','180'],check=True)
    client = browser()
    location, _ = submit(client, '/login', dict(identity=username,password=password))
    if not location.endswith('/dashboard') or certificate_hash(client) != fingerprint:
        raise RuntimeError('Account or certificate changed after restart')
    print('PASS: HTTP registration, CSRF login and certificate persistence across restart.')


if __name__ == '__main__':
    main()
