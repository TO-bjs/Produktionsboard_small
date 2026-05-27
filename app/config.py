import os


class BaseConfig:
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO').upper()
    SECRET_KEY = os.environ.get('SECRET_KEY', 'your_secret_key')
    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', 'uploads')
    WTF_CSRF_TIME_LIMIT = 3600
    MAX_CONTENT_LENGTH = 64 * 1024 * 1024
    DATABASE = os.environ.get('DATABASE', 'users.db')


class DevelopmentConfig(BaseConfig):
    DEBUG = True


class ProductionConfig(BaseConfig):
    DEBUG = False


class TestingConfig(BaseConfig):
    TESTING = True
    WTF_CSRF_ENABLED = False
    DATABASE = os.environ.get('TEST_DATABASE', 'test_users.db')


CONFIG_MAP = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
}
