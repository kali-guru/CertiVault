"""One process keeps SQLite and the process-local rate limiter predictable."""
bind = '0.0.0.0:8000'
workers = 1
worker_class = 'gthread'
threads = 4
timeout = 120
graceful_timeout = 30
worker_tmp_dir = '/tmp'
accesslog = None  # Avoid recording sensitive URL/query data; app audits actions.
errorlog = '-'
loglevel = 'info'
umask = 0o077
