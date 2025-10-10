import os

class BaseConfig:
    SECRET_KEY = os.environ.get("FLASK_SECRET", "your_very_secret_key")
    CACHE_TYPE = os.environ.get("CACHE_TYPE", "SimpleCache")
    CACHE_DEFAULT_TIMEOUT = int(os.environ.get("CACHE_DEFAULT_TIMEOUT", 3600))
    MAX_FETCH_MESSAGES = int(os.environ.get("MAX_FETCH_MESSAGES", 50))
    # ip-api throttling: keep some default timeout for requests
    IP_API_TIMEOUT = float(os.environ.get("IP_API_TIMEOUT", 5.0))
    # Allow overriding Gmail client secrets file location
    CLIENT_SECRETS_FILE = os.environ.get("CLIENT_SECRETS_FILE", "credentials.json")

class DevConfig(BaseConfig):
    DEBUG = True

class ProdConfig(BaseConfig):
    DEBUG = False
