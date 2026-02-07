"""СКРИПТ: Файл запуска"""

# - импортирование модулей
from flask import Flask
from config import *
from models import db, User
import models
from blueprints.registration.validation import hash_password
from flask_socketio import SocketIO


# - инициализация приложения
def create_app(config_name='default') -> Flask:
    app = Flask(__name__)

    config_class = CONFIGS.get(config_name)
    app.config.from_object(config_class)

    db.init_app(app)
    socketio = SocketIO(app)
    models.socketio = socketio

    with app.app_context():
        from blueprints.main.routes import bp as main_bp
        from blueprints.registration.routes import bp as registration_bp
        from blueprints.registration.routes import inject_user, load_user

        app.context_processor(inject_user)
        app.before_request(load_user)

        app.register_blueprint(main_bp)
        app.register_blueprint(registration_bp, url_prefix='/registration')

        db.create_all()

        if not User.query.filter_by(username=app.config['DEFAULT_ADMIN_USERNAME']).first():
            admin_user = User(
                username=app.config['DEFAULT_ADMIN_USERNAME'],
                password_sha256=hash_password(app.config['DEFAULT_ADMIN_PASSWORD']),
                privileges=1
            )

            db.session.add(admin_user)
            db.session.commit()

    return app


app = create_app(config_name=CURRENT_CONFIG_NAME)


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)
