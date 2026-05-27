import os


class BaseConfig:
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO').upper()
    SECRET_KEY = os.environ.get('SECRET_KEY', 'your_secret_key')
    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', 'uploads')
    WTF_CSRF_TIME_LIMIT = 3600
    MAX_CONTENT_LENGTH = 64 * 1024 * 1024
    MAX_UPLOAD_SIZE_SCREENSHOT = int(os.environ.get('MAX_UPLOAD_SIZE_SCREENSHOT', 10 * 1024 * 1024))
    MAX_UPLOAD_SIZE_ANNOUNCEMENT = int(os.environ.get('MAX_UPLOAD_SIZE_ANNOUNCEMENT', 15 * 1024 * 1024))
    MAX_UPLOAD_SIZE_QUALIMATRIX = int(os.environ.get('MAX_UPLOAD_SIZE_QUALIMATRIX', 20 * 1024 * 1024))
    UPLOAD_RETENTION_DAYS_SCREENSHOTS = int(os.environ.get('UPLOAD_RETENTION_DAYS_SCREENSHOTS', 14))
    UPLOAD_RETENTION_DAYS_ANNOUNCEMENTS = int(os.environ.get('UPLOAD_RETENTION_DAYS_ANNOUNCEMENTS', 90))
    UPLOAD_RETENTION_DAYS_QUALIMATRIX = int(os.environ.get('UPLOAD_RETENTION_DAYS_QUALIMATRIX', 180))
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
