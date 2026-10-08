"""Check HTTP readiness and the persisted schema without exposing secret values."""
import os
import sqlite3
from pathlib import Path
from urllib.request import urlopen


def main():
    instance = Path(os.environ.get('CERTIVAULT_INSTANCE', '/data'))
    with urlopen('http://127.0.0.1:8000/', timeout=3) as response:
        if response.status != 200:
            raise SystemExit(1)
    with sqlite3.connect((instance / 'certivault.db').as_uri() + '?mode=ro', uri=True) as db:
        if not db.execute('SELECT version_num FROM alembic_version').fetchone():
            raise SystemExit(1)
        db.execute('SELECT id FROM user LIMIT 1').fetchall()
    if not all((instance / 'ca' / name).is_file() for name in ('private.pem', 'certificate.pem')):
        raise SystemExit(1)


if __name__ == '__main__':
    main()
