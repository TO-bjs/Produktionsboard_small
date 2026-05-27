import os

from flask import Flask
from flask_wtf.csrf import CSRFProtect

from app.config import CONFIG_MAP
from app.db import init_db
from app.logging_config import configure_logging
from app.routes.admin import admin_bp
from app.routes.auth import auth_bp
from app.routes.public import public_bp
from app.services.storage import ensure_storage_dirs

csrf = CSRFProtect()


def create_app(config_name=None):
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # ...\produktionsboard
    app = Flask(
        __name__,
        template_folder=os.path.join(base_dir, "templates"),
        static_folder=os.path.join(base_dir, "static"),
    )
    cfg = config_name or os.environ.get('FLASK_ENV', 'development')
    app.config.from_object(CONFIG_MAP.get(cfg, CONFIG_MAP['development']))
    configure_logging(app.config.get('LOG_LEVEL', 'INFO'))

    csrf.init_app(app)

    with app.app_context():
        ensure_storage_dirs()
        init_db()

    app.register_blueprint(public_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp)

    return app
