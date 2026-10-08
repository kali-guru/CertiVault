"""Initialize persisted state once, then replace this process with Gunicorn."""
import os
import sys
from .bootstrap import initialize


def main():
    os.umask(0o077)
    args = sys.argv[1:]
    if not args:
        raise SystemExit('A server command is required')
    if args[0] == 'gunicorn':
        initialize()
    os.execvp(args[0], args)


if __name__ == '__main__':
    main()
