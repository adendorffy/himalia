from Himalia.app import create_app, init_db
import os

app = create_app({
    'SECRET_KEY': 'secret',
    'OAUTH2_REFRESH_TOKEN_GENERATOR': True,
    'SQLALCHEMY_TRACK_MODIFICATIONS': False,
    'SQLALCHEMY_DATABASE_URI': 'sqlite:///db.sqlite',
})

if os.environ.get('INIT_DB') == "true":
    init_db()

if __name__ == "__main__":
    from waitress import serve
    serve(app, host="0.0.0.0", port=8080)