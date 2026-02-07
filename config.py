"""СКРИПТ: Настройки"""

# -- импорт модулей
from dotenv import load_dotenv
import os
from pathlib import Path

load_dotenv()


# -- базовая конфигурация
class Config:
    # настройки flask
    SECRET_KEY = os.environ.get('SECRET_KEY', 'unsecure-secret-key')
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///database.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Настройка сессий
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SECURE = True if os.environ.get('FLASK_ENV') == 'production' else False
    SESSION_COOKIE_SAMESITE = 'Lax'

    # настройки путей
    STATIC_PATH = Path('static')
    TEMPLATE_PATH = Path('templates')

    # хранение сессий на сервере
    SESSION_TYPE = 'filesystem'
    SESSION_PERMANENT = False
    SESSION_USE_SIGNER = True
    SESSION_KEY_PREFIX = 'auth:'

    # настройки пользователей
    DEFAULT_ADMIN_USERNAME = os.environ.get('DEFAULT_ADMIN_USERNAME', 'admin')
    DEFAULT_ADMIN_PASSWORD = os.environ.get('DEFAULT_ADMIN_PASSWORD', 'password')


# -- конфигурация для разработки
class DevelopmentConfig(Config):
    DEBUG = True


# -- конфигурация для продакшена
class ProductionConfig(Config):
    DEBUG = False


CONFIGS = {
    'default': Config(),
    'development': DevelopmentConfig(),
    'production': ProductionConfig()
}

CURRENT_CONFIG_NAME = os.environ.get('FLASK_ENV', 'development')