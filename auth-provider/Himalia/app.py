import os
from flask import Flask
from .models import db
from .routes import bp


def create_app(config=None):
    app = Flask(__name__)

    # load default configuration
    app.config.from_object('Himalia.settings')

    # load environment configuration
    if 'WEBSITE_CONF' in os.environ:
        app.config.from_envvar('WEBSITE_CONF')

    # load app specified configuration
    if config is not None:
        if isinstance(config, dict):
            app.config.update(config)
        elif config.endswith('.py'):
            app.config.from_pyfile(config)

    setup_app(app)
    return app


def setup_app(app):

    db.init_app(app)
    # Create tables if they do not exist already
    with app.app_context():
        db.create_all()
    app.register_blueprint(bp, url_prefix='')


def init_db(app):
    with app.app_context():
        db.drop_all()
        db.create_all()
    print("Database initialized.")
