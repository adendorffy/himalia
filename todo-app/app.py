from todoing.app import create_app
from todoing.db import init_db
init_db()
app = create_app()
app.app_context()