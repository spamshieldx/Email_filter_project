from flask import Flask
from app.routes import main as main_bp

app = Flask(__name__)
app.secret_key = 'your-secret-key'
app.register_blueprint(main_bp)

if __name__ == '__main__':
    app.run(debug=True)
