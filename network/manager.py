from pathlib import Path
from PyQt6.QtCore import QObject, pyqtSignal
from network.transport import SSEListener, SyncHTTPRequest


class NetworkManager(QObject):
    # -- менеджер сети
    message_received = pyqtSignal(dict)
    connection_status_changed = pyqtSignal(bool)
    avatar_updated = pyqtSignal(dict)
    contact_status_changed = pyqtSignal(dict)

    def __init__(self, host='155.212.132.185', port=6666):
        super().__init__()
        self.host = host
        self.port = port
        self.base_url = f"https://{host}:{port}"
        self.session_token = None
        self.user_token = None
        self.user_id = None
        self.user_login = None
        self.sse_listener = None
        from utils import DATA_PATH
        self.avatars_dir = DATA_PATH / 'avatars'
        self.avatars_dir.mkdir(exist_ok=True)

    def set_credentials(self, session_token=None, user_token=None, user_id=None, user_login=None):
        if session_token is not None:
            self.session_token = session_token
        if user_token is not None:
            self.user_token = user_token
        if user_id is not None:
            self.user_id = user_id
        if user_login is not None:
            self.user_login = user_login

    def start_event_listener(self):
        self.stop_event_listener()
        self.sse_listener = SSEListener(self.session_token, self.user_id, self.user_login)
        self.sse_listener.message_received.connect(self.message_received)
        self.sse_listener.avatar_updated.connect(self.avatar_updated)
        self.sse_listener.status_update.connect(self.contact_status_changed)
        self.sse_listener.connection_status.connect(self.connection_status_changed)
        self.sse_listener.start()

    def stop_event_listener(self):
        if self.sse_listener:
            self.sse_listener.stop()
            self.sse_listener.deleteLater()
            self.sse_listener = None

    def send_sync_request(self, endpoint, data):
        if self.session_token and 'session_token' not in data:
            data['session_token'] = self.session_token
        if self.user_token and 'user_token' not in data:
            data['user_token'] = self.user_token
        if self.user_id and 'user_id' not in data:
            data['user_id'] = self.user_id
        return SyncHTTPRequest.post(endpoint, data)

    def get_avatar_path(self, user_id, avatar_version):
        return self.avatars_dir / f"{user_id}_{avatar_version}.jpg"

    def has_avatar_cached(self, user_id, avatar_version):
        return self.get_avatar_path(user_id, avatar_version).exists()

    def save_avatar_to_cache(self, user_id, avatar_version, avatar_data):
        with open(self.get_avatar_path(user_id, avatar_version), 'wb') as f:
            f.write(avatar_data)

    def get_avatar_from_cache(self, user_id, avatar_version):
        p = self.get_avatar_path(user_id, avatar_version)
        if p.exists():
            with open(p, 'rb') as f:
                return f.read()
        return None

    def remove_old_avatar(self, user_id, old_version):
        p = self.get_avatar_path(user_id, old_version)
        if p.exists():
            p.unlink()