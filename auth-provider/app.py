from Himalia.app import create_app, init_db
import os
from gevent.pywsgi import WSGIServer

app = create_app({
    'SECRET_KEY': 'secret',
    'OAUTH2_REFRESH_TOKEN_GENERATOR': True,
    'SQLALCHEMY_TRACK_MODIFICATIONS': False,
    'SQLALCHEMY_DATABASE_URI': 'sqlite:///db.sqlite',
})

if os.environ.get('INIT_DB') == "true":
    init_db()
