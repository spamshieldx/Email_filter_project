from flask import Flask
from app.routes import main as main_bp
import os
from app import create_app

# Create app via factory
app = create_app()

# Ensure templates folder is loaded correctly
app = Flask(__name__, template_folder=os.path.join(os.path.dirname(__file__), 'app', 'templates'))
app.secret_key = 'your-secret-key'
app.register_blueprint(main_bp)

if __name__ == '__main__':
    app.run(debug=True)
