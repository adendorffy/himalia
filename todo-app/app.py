from todoing.app import create_app
from todoing.db import init_db

app = create_app()
with app.app_context():
    init_db()