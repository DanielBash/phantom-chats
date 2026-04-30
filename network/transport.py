import json
from PyQt6.QtCore import QObject, pyqtSignal, QUrl, QTimer, QByteArray, QEventLoop
from PyQt6.QtNetwork import QNetworkAccessManager, QNetworkRequest, QNetworkReply
from network.config import SERVER_URL


class SSEListener(QObject):
    # -- слушатель событий от сервера
    message_received = pyqtSignal(dict)
    avatar_updated = pyqtSignal(dict)
    status_update = pyqtSignal(dict)
    connection_status = pyqtSignal(bool)

    def __init__(self, session_token, user_id, user_login):
        super().__init__()
        self.session_token = session_token
        self.user_id = user_id
        self.user_login = user_login
        self.nam = QNetworkAccessManager()
        self.reply = None
        self.buffer = b""
        self.active = False

    def start(self):
        self.active = True
        url = QUrl(f"{SERVER_URL}/api/events")
        request = QNetworkRequest(url)
        request.setHeader(QNetworkRequest.KnownHeaders.ContentTypeHeader, "text/event-stream")
        request.setRawHeader(b"X-User-Id", str(self.user_id).encode())
        request.setRawHeader(b"X-Session-Token", self.session_token.encode())
        from network.api import messenger_api
        if messenger_api and messenger_api.device_id:
            request.setRawHeader(b"X-Device-ID", messenger_api.device_id.encode())
        request.setAttribute(QNetworkRequest.Attribute.CacheLoadControlAttribute,
                             QNetworkRequest.CacheLoadControl.AlwaysNetwork)
        self.reply = self.nam.get(request)
        self.reply.readyRead.connect(self._on_ready_read)
        self.reply.finished.connect(self._on_finished)
        self.connection_status.emit(True)

    def stop(self):
        self.active = False
        if self.reply:
            self.reply.abort()
            self.reply.deleteLater()
            self.reply = None

    def _on_ready_read(self):
        if not self.reply:
            return
        data = self.reply.readAll().data()
        self.buffer += data
        while b"\n\n" in self.buffer:
            part, self.buffer = self.buffer.split(b"\n\n", 1)
            self._parse_sse_event(part)

    def _parse_sse_event(self, chunk):
        lines = chunk.decode('utf-8', errors='ignore').split('\n')
        event_type = None
        data = None
        for line in lines:
            if line.startswith("event:"):
                event_type = line[6:].strip()
            elif line.startswith("data:"):
                data = line[5:].strip()
        if data and event_type:
            json_data = json.loads(data)
            if event_type == 'new_message':
                self.message_received.emit(json_data)
            elif event_type == 'avatar_updated':
                self.avatar_updated.emit(json_data)
            elif event_type == 'status_update':
                self.status_update.emit(json_data)

    def _on_finished(self):
        if self.active:
            self.connection_status.emit(False)
            QTimer.singleShot(1000, self.start)


class AsyncHTTPRequest(QObject):
    _active_requests = []
    def __init__(self, endpoint, data, callback):
        super().__init__()
        self._callback = callback
        AsyncHTTPRequest._active_requests.append(self)

        url = QUrl(f"{SERVER_URL}/api/{endpoint}")
        request = QNetworkRequest(url)
        request.setHeader(QNetworkRequest.KnownHeaders.ContentTypeHeader, "application/json")
        request.setAttribute(
            QNetworkRequest.Attribute.CacheLoadControlAttribute,
            QNetworkRequest.CacheLoadControl.AlwaysNetwork
        )
        from network.api import messenger_api
        if messenger_api and messenger_api.device_id:
            request.setRawHeader(b"X-Device-ID", messenger_api.device_id.encode())
        if 'session_token' in data:
            request.setRawHeader(b"X-Session-Token", str(data.pop('session_token')).encode())
        if 'user_id' in data:
            request.setRawHeader(b"X-User-Id", str(data.pop('user_id')).encode())
        if 'user_token' in data:
            request.setRawHeader(b"X-User-Token", str(data.pop('user_token')).encode())

        body = QByteArray(json.dumps(data, ensure_ascii=False).encode('utf-8'))

        self._nam = QNetworkAccessManager()
        self._reply = self._nam.post(request, body)
        self._reply.finished.connect(self._on_finished)

    def _on_finished(self):
        result = None
        try:
            if self._reply.error() != QNetworkReply.NetworkError.NoError:
                result = {'success': False, 'error': self._reply.errorString()}
            else:
                status = self._reply.attribute(QNetworkRequest.Attribute.HttpStatusCodeAttribute)
                raw = bytes(self._reply.readAll().data())
                if not raw:
                    result = {'success': False,
                              'error': f'empty response (HTTP {status})'}
                else:
                    try:
                        result = json.loads(raw)
                    except (ValueError, json.JSONDecodeError):
                        snippet = raw[:120].decode('utf-8', errors='replace')
                        result = {'success': False,
                                  'error': f'non-JSON response (HTTP {status}): {snippet}'}
                if status and status != 200 and isinstance(result, dict):
                    result = {'success': False,
                              'error': result.get('error', f'HTTP {status}')}
        except Exception as e:
            result = {'success': False, 'error': str(e)}
        finally:
            self._reply.deleteLater()
            if self in AsyncHTTPRequest._active_requests:
                AsyncHTTPRequest._active_requests.remove(self)

        # Last-resort wrap so a buggy callback never freezes the UI in a
        # half-finished state — the user has at least *something* in hand.
        try:
            self._callback(result)
        except Exception as cb_exc:
            try:
                self._callback({'success': False,
                                'error': f'callback failed: {cb_exc}'})
            except Exception:
                pass


class SyncHTTPRequest:
    # -- синхронный https запрос для е2ее
    @staticmethod
    def post(endpoint, data=None):
        try:
            url = QUrl(f"{SERVER_URL}/api/{endpoint}")
            request = QNetworkRequest(url)
            request.setHeader(QNetworkRequest.KnownHeaders.ContentTypeHeader, "application/json")
            from network.api import messenger_api
            if messenger_api and messenger_api.device_id:
                request.setRawHeader(b"X-Device-ID", messenger_api.device_id.encode())
            if data:
                if 'session_token' in data:
                    request.setRawHeader(b"X-Session-Token", str(data['session_token']).encode())
                    del data['session_token']
                if 'user_id' in data:
                    request.setRawHeader(b"X-User-Id", str(data['user_id']).encode())
                    del data['user_id']
                if 'user_token' in data:
                    request.setRawHeader(b"X-User-Token", str(data['user_token']).encode())
                    del data['user_token']
            json_data = (QByteArray(json.dumps(data, ensure_ascii=False).encode('utf-8'))
                         if data else QByteArray())
            nam = QNetworkAccessManager()
            reply = nam.post(request, json_data)
            loop = QEventLoop()
            reply.finished.connect(loop.quit)
            loop.exec()

            status_code = reply.attribute(QNetworkRequest.Attribute.HttpStatusCodeAttribute)
            response_data = bytes(reply.readAll().data())
            net_err = reply.error()

            if net_err != QNetworkReply.NetworkError.NoError:
                return {'success': False,
                        'error': reply.errorString() or 'network error',
                        'status': status_code}

            # Empty body — common when an endpoint hasn't been deployed yet
            # or returns 204. Don't try to json.loads "" — it raises and
            # would deadlock callers waiting on a callback.
            if not response_data:
                return {'success': False,
                        'error': f'empty response (HTTP {status_code})',
                        'status': status_code}

            try:
                parsed = json.loads(response_data)
            except (ValueError, json.JSONDecodeError):
                snippet = response_data[:120].decode('utf-8', errors='replace')
                return {'success': False,
                        'error': f'non-JSON response (HTTP {status_code}): {snippet}',
                        'status': status_code}

            if status_code and status_code != 200:
                if isinstance(parsed, dict) and 'error' in parsed:
                    return {'success': False, 'error': parsed['error'],
                            'status': status_code}
                return {'success': False,
                        'error': f'HTTPS ошибка {status_code}',
                        'status': status_code}

            return parsed
        except Exception as exc:  # last-resort: never propagate
            return {'success': False, 'error': f'sync request failed: {exc}'}