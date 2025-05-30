bind = "unix:/tmp/gunicorn.sock"
workers = 3
worker_class = "gevent"
timeout = 120
graceful_timeout = 120
keepalive = 5
preload_app = True
max_requests = 1000
max_requests_jitter = 50
accesslog = "-"
errorlog = "-"
loglevel = "info"
