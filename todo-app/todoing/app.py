import os

from flask import Flask

def create_app(test_config=None):
    """
    Create and configure the Flask application.
    
    This function initializes and configures a Flask web application instance.
    
    Parameters:
        test_config (dict, optional): A dictionary containing configuration options for testing.
        
    Returns:
        Flask: The configured Flask application instance.
    """
    # Create and configure the Flask app
    app = Flask(__name__, instance_relative_config=True)
    
    # Configure app settings
    app.config.from_mapping(
        SECRET_KEY='dev',  # Secret key for session management
        DATABASE=os.path.join(app.instance_path, 'flaskr.sqlite'),  # Database file path
    )

    if test_config is None:
        # Load the instance config if it exists, when not testing
        app.config.from_pyfile('config.py', silent=True)
    else:
        # Load the test config if passed in
        app.config.from_mapping(test_config)

    # Ensure the instance folder exists
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass
    
    # Initialize the database
    from . import db
    db.init_app(app)

    # Register the 'auth' blueprint for authentication routes
    from . import auth
    app.register_blueprint(auth.bp)

    # Register the 'main' blueprint for main application routes
    from . import main
    app.register_blueprint(main.bp)
    app.add_url_rule('/', endpoint='index')  # Set the endpoint for the index route
    

    return app
