"""Generate local configuration without printing secrets or overwriting .env."""
import os
import secrets
from pathlib import Path
path = Path(__file__).resolve().parents[1] / '.env'
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd,'w') as file:
    file.write('SECRET_KEY='+secrets.token_urlsafe(48)+'\nCA_PASSPHRASE='+secrets.token_urlsafe(48)+'\nAPP_ENV=development\nSESSION_COOKIE_SECURE=false\n')
print('Created local .env with fresh secrets. Keep a secure backup; never commit it.')
