from flask import Flask, jsonify
import logging
from flask_caching import Cache
from werkzeug.exceptions import HTTPException, BadRequest

def create_app():
    app = Flask(__name__)
    app.secret_key = 'your_very_secret_key'  # ⚠️ Replace with env var in production

    # Basic config (override with env vars if needed)
    app.config.setdefault('CACHE_TYPE', 'SimpleCache')
    app.config.setdefault('CACHE_DEFAULT_TIMEOUT', 60 * 60)  # 1 hour for ip geolocation cache
    app.config.setdefault('MAX_FETCH_MESSAGES', 50)

    cache = Cache(app)
    app.cache = cache  # make it available globally (used in ip_locator.py)

    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )
    app.logger.info("Email Filter API started")

    # Register routes
    from .routes import main
    app.register_blueprint(main, url_prefix="/api")

    # Error handlers: return JSON consistently
    @app.errorhandler(404)
    def not_found(e):
        return jsonify({"error": "not_found", "message": "The requested endpoint was not found"}), 404

    @app.errorhandler(400)
    def bad_request(e):
        # If it's a werkzeug HTTPException it might have description
        message = getattr(e, 'description', 'bad request')
        return jsonify({"error": "bad_request", "message": message}), 400

    @app.errorhandler(422)
    def unprocessable(e):
        return jsonify({"error": "unprocessable_entity", "message": "Cannot process input"}), 422

    @app.errorhandler(Exception)
    def internal_error(e):
        # If HTTPException, return its code and description
        if isinstance(e, HTTPException):
            return jsonify({"error": e.name.lower().replace(" ", "_"), "message": e.description}), e.code or 500
        # otherwise generic 500
        app.logger.exception("Unhandled exception")
        return jsonify({"error": "internal_server_error", "message": "An internal error occurred"}), 500

    return app
