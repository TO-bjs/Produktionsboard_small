import os

from flask import Flask
from flask_wtf.csrf import CSRFProtect

from app.config import CONFIG_MAP
from app.db import init_db
from app.routes.admin import admin_bp
from app.routes.auth import auth_bp
from app.routes.public import public_bp
from app.services.storage import ensure_storage_dirs

csrf = CSRFProtect()


def create_app(config_name=None):
    app = Flask(__name__, instance_relative_config=False)
    cfg = config_name or os.environ.get('FLASK_ENV', 'development')
    app.config.from_object(CONFIG_MAP.get(cfg, CONFIG_MAP['development']))

    csrf.init_app(app)

    with app.app_context():
        ensure_storage_dirs()
        init_db()

    app.register_blueprint(public_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp)

    return app
