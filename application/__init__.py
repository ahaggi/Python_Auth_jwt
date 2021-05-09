from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow


# Globally accessible db and ma
# Note the presence of (db and ma) and its location: this our database object being set as a global variable outside of create_app(). Inside of create_app(), on the other hand, contains the line db.init_app(app). Even though we've set our db object globally, this means nothing until we initialize it after creating our application. We accomplish this by calling init_app() within create_app(), 
sqlalc = SQLAlchemy()
ma = Marshmallow()


def create_app():
    """Initialize the core application."""
    app = Flask(__name__, instance_relative_config=False)
    app.config.from_object('config.Config')


    # Initialize Plugins,, Bind db to Flask  instead of "db = SQLAlchemy(app)"
    # After the app object is created, we then "initialize" those plugins we mentioned earlier. Initializing a plugin registers a plugin with our Flask app.
    # Setting db as global variables outside of init_app() makes it globally accessible to other parts of our application
    sqlalc.init_app(app)
    ma.init_app(app)

    with app.app_context():
        # Include our Routes
        from . import routes

        # Register Blueprints
        # app.register_blueprint(auth.auth_bp)
        # app.register_blueprint(admin.admin_bp)

        return app