import PyQt6.QtWebEngineWidgets
from PyQt6.QtWidgets import QApplication, QMainWindow, QMessageBox
from PyQt6.QtCore import QSettings, QEvent, Qt
from network import make_server_request_async, messenger_api
from styles import style_input_dialog
import sys
import traceback
import shutil
from pathlib import Path


def catch_all_exceptions():
    def excepthook(exc_type, exc_value, exc_traceback):
        print(f"Поймана ошибка:\n{''.join(traceback.format_exception(exc_type, exc_value, exc_traceback))}")

    sys.excepthook = excepthook


catch_all_exceptions()


class MainWindow(QMainWindow):
    # -- главное окно программы
    def __init__(self):
        super().__init__()
        self.cur_widget = None
        self.settings = QSettings("Phantom", "Messenger")

        self.current_user = None
        self.user_token = None
        self.user_id = None
        self.username = None
        self.session_token = None
        self.navigation_lock = False

        self.show_login_window()

    def save_window_state(self):
        self.settings.setValue("window_size", self.size())
        self.settings.setValue("window_pos", self.pos())

    def restore_window_state(self, default_size):
        last_size = self.settings.value("window_size")
        last_pos = self.settings.value("window_pos")

        if last_size and last_pos:
            self.resize(last_size)
            self.move(last_pos)
        else:
            self.resize(default_size[0], default_size[1])

    def is_default_login_size(self):
        cur_size = self.size()
        return cur_size.width() == 570 and cur_size.height() == 700

    def show_login_window(self):
        from authorization.login_window import LoginWindow
        self.save_window_state()
        self._clear_cur_widget()
        self.login_window = LoginWindow(self)
        self.setCentralWidget(self.login_window)
        self.cur_widget = self.login_window
        self.restore_window_state((570, 700))

    def show_register_window(self):
        from authorization.register_window import RegisterWindow
        self.save_window_state()
        self._clear_cur_widget()
        self.register_window = RegisterWindow(self)
        self.setCentralWidget(self.register_window)
        self.cur_widget = self.register_window
        self.restore_window_state((500, 600))

    def show_chat_window(self):
        from chats.chat_window import ChatWindow
        if self.navigation_lock:
            return
        self.navigation_lock = True

        self.save_window_state()
        self._clear_cur_widget()

        def handle_auth_response(response):
            if response and response.get('success'):
                self.chat_window = ChatWindow(self)
                self.setCentralWidget(self.chat_window)
                self.cur_widget = self.chat_window

                if self.is_default_login_size():
                    self.resize(800, 600)
                else:
                    cur_size = self.size()
                    self.resize(cur_size)

                last_pos = self.settings.value("window_pos")
                if last_pos:
                    self.move(last_pos)
            else:
                QMessageBox.warning(self, "Ошибка", "Не удалось установить соединение с сервером")
                self.show_login_window()
            self.navigation_lock = False

        make_server_request_async('auth', {
            'user_token': self.user_token,
            'user_id': self.user_id,
            'session_token': self.session_token
        }, handle_auth_response)

    def show_settings_window(self):
        from chats.settings_window import SettingsWindow
        if self.navigation_lock:
            return
        self.navigation_lock = True

        self.save_window_state()
        self._clear_cur_widget()
        self.settings_window = SettingsWindow(self)
        self.setCentralWidget(self.settings_window)
        self.cur_widget = self.settings_window

        if self.is_default_login_size():
            self.resize(850, 700)
        else:
            cur_size = self.size()
            self.resize(cur_size)

        last_pos = self.settings.value("window_pos")
        if last_pos:
            self.move(last_pos)

        self.navigation_lock = False

    def logout(self):
        if self.user_token and self.user_id:
            make_server_request_async('logout_current', {
                'user_token': self.user_token,
                'user_id': self.user_id,
                'session_token': self.session_token
            }, lambda x: None)

        if hasattr(self, 'chat_window') and self.chat_window:
            from utils import DATA_PATH
            shutil.rmtree(DATA_PATH / 'chats_save' / str(self.user_id), ignore_errors=True)
            shutil.rmtree(DATA_PATH / 'files_cache' / str(self.user_id), ignore_errors=True)

        self.current_user = None
        self.user_token = None
        self.user_id = None
        self.username = None
        self.session_token = None
        self.show_login_window()

    def closeEvent(self, event):
        self.save_window_state()
        if self.user_token and self.user_id:
            from network.transport import SyncHTTPRequest
            try:
                SyncHTTPRequest.post('set_offline', {
                    'session_token': self.session_token,
                    'user_id': self.user_id,
                    'user_token': self.user_token
                })
            except Exception:
                pass
            SyncHTTPRequest.post('logout_current', {
                'session_token': self.session_token,
                'user_id': self.user_id,
                'user_token': self.user_token
            })
        event.accept()

    def changeEvent(self, event):
        if event.type() == QEvent.Type.WindowStateChange:
            if self.user_token and self.user_id:
                if self.windowState() & Qt.WindowState.WindowMinimized:
                    messenger_api.set_offline_async()
                else:
                    messenger_api.send_heartbeat()
        super().changeEvent(event)

    def _clear_cur_widget(self):
        if self.cur_widget:
            self.cur_widget.deleteLater()
            self.cur_widget = None


if __name__ == '__main__':
    app = QApplication(sys.argv)
    app.setStyleSheet(style_input_dialog)
    from PyQt6.QtGui import QIcon
    from utils import find_file
    icon_path = find_file('images/icon_on_exe.ico')
    if icon_path:
        app.setWindowIcon(QIcon(icon_path))
    messenger_api.init_device_id()
    window = MainWindow()
    window.setWindowIcon(app.windowIcon())
    window.show()
    sys.exit(app.exec())