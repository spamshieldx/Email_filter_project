import os
from flask import Flask, jsonify
import logging
from flask_caching import Cache
from werkzeug.exceptions import HTTPException
from flasgger import Swagger
from flask_cors import CORS
from .config import DevConfig

def create_app():
    app = Flask(__name__)
    CORS(app, supports_credentials=True, origins=["http://localhost:5173"])
    app.secret_key = 'your_very_secret_key'  # ⚠️ Use env variable in production
    app.config.from_object(DevConfig)
    app.config['CLIENT_SECRETS_FILE'] = os.environ.get("CLIENT_SECRETS_FILE", "credentials.json")

    # Basic config
    app.config.setdefault('CACHE_TYPE', 'SimpleCache')
    app.config.setdefault('CACHE_DEFAULT_TIMEOUT', 60 * 60)
    app.config.setdefault('MAX_FETCH_MESSAGES', 50)
    app.config['SWAGGER'] = {
        'title': 'Email Spam Filter API',
        'uiversion': 3
    }

    # Cache setup
    cache = Cache(app)
    app.cache = cache

    # Swagger UI
    Swagger(app)

    # Logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )
    app.logger.info("Email Filter API started with Swagger documentation")

    # Register routes
    from .routes import main
    app.register_blueprint(main, url_prefix="/api")

    # Global error handlers
    @app.errorhandler(404)
    def not_found(e):
        return jsonify({"error": "not_found", "message": "The requested endpoint was not found"}), 404

    @app.errorhandler(400)
    def bad_request(e):
        message = getattr(e, 'description', 'bad request')
        return jsonify({"error": "bad_request", "message": message}), 400

    @app.errorhandler(Exception)
    def internal_error(e):
        if isinstance(e, HTTPException):
            return jsonify({"error": e.name.lower(), "message": e.description}), e.code
        app.logger.exception("Unhandled exception")
        return jsonify({"error": "internal_server_error", "message": "An internal error occurred"}), 500

    return app
