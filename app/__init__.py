from flask import Flask
import logging

def create_app():
    app = Flask(__name__)
    app.secret_key = 'your_very_secret_key'  # Keep this secure in production

    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )
    app.logger.info("Email Filter API started")

    from .routes import main
    app.register_blueprint(main)
    return app
