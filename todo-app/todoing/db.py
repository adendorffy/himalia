import sqlite3
import click
from flask import current_app, g

# Function to get a database connection
def get_db():
    """
    Get a database connection.
    
    If a connection doesn't exist in the current application context (g), create one.
    
    Returns:
        sqlite3.Connection: The database connection.
    """
    if 'db' not in g:
        g.db = sqlite3.connect(
            current_app.config['DATABASE'],
            detect_types=sqlite3.PARSE_DECLTYPES
        )
        g.db.row_factory = sqlite3.Row

    return g.db

# Function to close the database connection
def close_db(e=None):
    """
    Close the database connection.

    Parameters:
        e: An exception if one occurred during the request.

    Closes the database connection stored in the current application context (g).
    """
    db = g.pop('db', None)

    if db is not None:
        db.close()

# Function to initialize the database
def init_db():
    """
    Initialize the database with schema.

    Reads the 'schema.sql' file and executes the SQL script to create tables.
    """
    db = get_db()

    with current_app.open_resource('schema.sql') as f:
        db.executescript(f.read().decode('utf8'))

# Click command to initialize the database
@click.command('init-db')
def init_db_command():
    """
    Click command to initialize the database.

    Clears the existing data and creates new tables. Used via the command line.
    """
    init_db()
    click.echo('Initialized the database.')

# Function to initialize the app with database-related functions
def init_app(app):
    """
    Initialize the app with database functions.

    Attaches teardown function to close the database connection and adds a CLI command for database initialization.

    Parameters:
        app: The Flask application instance.
    """
    app.teardown_appcontext(close_db)
    app.cli.add_command(init_db_command)
