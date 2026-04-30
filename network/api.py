import hashlib
import json
import os
import base64
import traceback
from datetime import datetime, timezone
from PyQt6.QtCore import QSettings
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import opaque_ke_py
from network.manager import NetworkManager
from network.cache import FileCache
from network.crypto import (
    gen_msg_master_key, encrypt_master_key, decrypt_master_key,
)
from network.cryptolib import (
    IdentityKeys, PreKeyStore, SessionManager,
    UnknownInitialMessage, SessionError,
)
from network.cryptolib.prekeys import OPK_REFILL_THRESHOLD, DEFAULT_OPK_BATCH
from network.transport import AsyncHTTPRequest


class MessengerAPI:
    # -- главный api для работы с сервером
    def __init__(self, host='155.212.132.185', port=6666):
        self.network_manager = NetworkManager(host, port)
        self.file_cache = None
        self.login_in_progress = False
        self.device_id = None
        self.user_login = None
        self.master_key_bytes = None
        self.identity = None
        self.prekey_store = None
        self.session_manager = None
        self.encrypted_master_key = None

    def init_device_id(self):
        settings = QSettings("Phantom", "Messenger")
        device_id = settings.value("device_id", "")
        if not device_id:
            import uuid
            device_id = str(uuid.uuid4())
            settings.setValue("device_id", device_id)
        self.device_id = device_id

    def get_user_info(self, token, user_id, target_login):
        data = {'user_token': token, 'user_id': user_id, 'target_login': target_login}
        if self.network_manager.session_token:
            data['session_token'] = self.network_manager.session_token
        return self.network_manager.send_sync_request('get_user_info', data)

    def set_user_credentials(self, session_token, user_id, user_login=None):
        if user_login is not None:
            self.user_login = user_login
        self.network_manager.set_credentials(session_token=session_token, user_id=user_id, user_login=self.user_login)
        if user_id:
            self.file_cache = FileCache(user_id)

    def set_session_token(self, session_token):
        self.network_manager.session_token = session_token

    def auth(self, token, user_id):
        data = {'user_token': token, 'user_id': user_id}
        if self.network_manager.session_token:
            data['session_token'] = self.network_manager.session_token
        response = self.network_manager.send_sync_request('auth', data)
        if response and response.get('success'):
            self.network_manager.set_credentials(session_token=self.network_manager.session_token, user_token=token,
                                                 user_id=user_id)
            self.network_manager.start_event_listener()
        return response

    def init_e2ee(self, master_key):
        self.master_key_bytes = bytes(master_key)
        self.identity = IdentityKeys.from_master_key(self.master_key_bytes)

        stored = SessionManager.load_prekey_store_dict(
            self.user_login or 'unknown', self.master_key_bytes,
        )
        if stored is not None:
            self.prekey_store = PreKeyStore.from_dict(stored)
        else:
            self.prekey_store = PreKeyStore()

        self.session_manager = SessionManager(
            own_login=self.user_login or 'unknown',
            identity_keys=self.identity,
            prekey_store=self.prekey_store,
            master_key=self.master_key_bytes,
            bundle_fetcher=self._fetch_prekey_bundle,
        )

        self._publish_identity_bundle()
        self._ensure_signed_prekey_published()
        self._maybe_refill_one_time_prekeys()

        self.session_manager.save_prekey_store()

    def _publish_identity_bundle(self):
        bundle = json.dumps({
            'x25519': base64.b64encode(self.identity.ik_pub_bytes).decode(),
            'ed25519': base64.b64encode(self.identity.sik_pub_bytes).decode(),
        }, separators=(',', ':'))
        signature = base64.b64encode(self.identity.sign_identity_binding()).decode()
        self.network_manager.send_sync_request('publish_public_key', {
            'public_key': bundle,
            'signature': signature,
        })

    def _ensure_signed_prekey_published(self):
        spk = self.prekey_store.ensure_signed_prekey(self.identity)
        self.network_manager.send_sync_request('upload_signed_prekey', {
            'spk_id': spk.key_id,
            'public_key': base64.b64encode(spk.pub_bytes).decode(),
            'signature': base64.b64encode(spk.signature).decode(),
        })

    def _maybe_refill_one_time_prekeys(self):
        resp = self.network_manager.send_sync_request('get_one_time_prekey_count', {})
        remote = (resp or {}).get('count', 0) if isinstance(resp, dict) else 0
        if remote >= OPK_REFILL_THRESHOLD:
            return
        new_keys = self.prekey_store.generate_one_time_prekeys(DEFAULT_OPK_BATCH)
        payload = [
            {'opk_id': k.key_id,
             'public_key': base64.b64encode(k.pub_bytes).decode()}
            for k in new_keys
        ]
        self.network_manager.send_sync_request('upload_one_time_prekeys', {
            'prekeys': payload,
        })

    def _fetch_prekey_bundle(self, contact_login):
        resp = self.network_manager.send_sync_request('get_prekey_bundle', {
            'contact_login': contact_login,
        })
        if not resp:
            return None
        if not resp.get('success'):
            err = resp.get('error', 'unknown')
            return None
        bundle = resp.get('bundle')
        return bundle

    def send_message(self, token, user_id, receiver_login, text='', file_id=None):
        if text:
            if not self.session_manager:
                raise SessionError(
                    'E2EE не инициализирован - сообщение не отправлено. '
                    'Перелогиньтесь, чтобы восстановить шифрование.'
                )
            wire = self.session_manager.encrypt_for(receiver_login, text)
            text = json.dumps(wire, separators=(',', ':'))
        client_timestamp = datetime.now(timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')
        nonce = os.urandom(8).hex()
        data = {
            'user_token': token,
            'user_id': user_id,
            'receiver_login': receiver_login,
            'text': text,
            'file_id': file_id,
            'client_timestamp': client_timestamp,
            'nonce': nonce
        }
        if self.network_manager.session_token:
            data['session_token'] = self.network_manager.session_token
        return self.network_manager.send_sync_request('send_message', data)

    def get_messages(self, token, user_id, other_user_login):
        data = {'user_token': token, 'user_id': user_id, 'other_user_login': other_user_login}
        if self.network_manager.session_token:
            data['session_token'] = self.network_manager.session_token
        return self.network_manager.send_sync_request('get_messages', data)

    def get_messages_since(self, token, user_id, contact_login, since_id):
        data = {'user_token': token, 'user_id': user_id, 'contact_login': contact_login, 'since_id': since_id}
        if self.network_manager.session_token:
            data['session_token'] = self.network_manager.session_token
        return self.network_manager.send_sync_request('get_messages_since', data)

    def logout_current(self, token, user_id):
        data = {'user_token': token, 'user_id': user_id}
        if self.network_manager.session_token:
            data['session_token'] = self.network_manager.session_token
        resp = self.network_manager.send_sync_request('logout_current', data)
        self.network_manager.stop_event_listener()
        self.file_cache = None
        return resp

    def info(self, token, user_id):
        data = {'user_token': token, 'user_id': user_id}
        if self.network_manager.session_token:
            data['session_token'] = self.network_manager.session_token
        return self.network_manager.send_sync_request('info', data)

    def get_sessions(self, token, user_id):
        data = {'user_token': token, 'user_id': user_id}
        if self.network_manager.session_token:
            data['session_token'] = self.network_manager.session_token
        return self.network_manager.send_sync_request('get_sessions', data)

    def logout_session(self, token, user_id, target_session_id):
        data = {'user_token': token, 'user_id': user_id, 'target_session_id': target_session_id}
        if self.network_manager.session_token:
            data['session_token'] = self.network_manager.session_token
        return self.network_manager.send_sync_request('logout_session', data)

    def logout_all_sessions(self, token, user_id):
        data = {'user_token': token, 'user_id': user_id}
        if self.network_manager.session_token:
            data['session_token'] = self.network_manager.session_token
        return self.network_manager.send_sync_request('logout_all_sessions', data)

    def get_cleanup_interval(self, token, user_id):
        data = {'user_token': token, 'user_id': user_id}
        if self.network_manager.session_token:
            data['session_token'] = self.network_manager.session_token
        return self.network_manager.send_sync_request('get_cleanup_interval', data)

    def set_cleanup_interval(self, token, user_id, interval):
        data = {'user_token': token, 'user_id': user_id, 'interval': interval}
        if self.network_manager.session_token:
            data['session_token'] = self.network_manager.session_token
        return self.network_manager.send_sync_request('set_cleanup_interval', data)

    def encrypt_file_data(self, file_data, thumbnail_data, receiver_login=None, video_meta=None):
        if not self.session_manager:
            raise SessionError('Session manager not initialised')
        if not receiver_login:
            raise SessionError('receiver_login required for file encryption')

        file_key = os.urandom(32)
        nonce_file = os.urandom(12)
        aesgcm = AESGCM(file_key)
        ciphertext = aesgcm.encrypt(nonce_file, file_data, None)

        wrapper_fields = {
            'k': base64.b64encode(file_key).decode(),
            'n': base64.b64encode(nonce_file).decode(),
            'h': hashlib.sha256(file_data).hexdigest(),
        }
        if video_meta:
            wrapper_fields['vid'] = True
            duration_ms = int(video_meta.get('duration_ms') or 0)
            if duration_ms > 0:
                wrapper_fields['dur'] = duration_ms
        wrapper = json.dumps(wrapper_fields, separators=(',', ':')).encode('utf-8')

        wire = self.session_manager.encrypt_for(receiver_login, wrapper)

        result = {
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
            'nonce_file': base64.b64encode(nonce_file).decode('utf-8'),
            'encrypted_key': json.dumps(wire, separators=(',', ':')),
        }

        if thumbnail_data:
            nonce_thumb = os.urandom(12)
            thumb_cipher = aesgcm.encrypt(nonce_thumb, thumbnail_data, None)
            result['thumbnail'] = base64.b64encode(thumb_cipher).decode('utf-8')
            result['nonce_thumbnail'] = base64.b64encode(nonce_thumb).decode('utf-8')

        return result

    def decrypt_file_data(self, ciphertext, nonce, encrypted_key, sender_login=None, return_meta=False):
        if not self.session_manager:
            raise SessionError('Session manager not initialised')
        if not sender_login:
            raise SessionError('sender_login required for file decryption')

        wire = json.loads(encrypted_key)
        wrapper_bytes = self.session_manager.decrypt_from(sender_login, wire)
        wrapper = json.loads(wrapper_bytes.decode('utf-8'))
        file_key = base64.b64decode(wrapper['k'])
        plaintext = AESGCM(file_key).decrypt(nonce, ciphertext, None)
        if hashlib.sha256(plaintext).hexdigest() != wrapper.get('h'):
            raise SessionError('file integrity check failed')
        if return_meta:
            meta = {}
            if wrapper.get('vid'):
                meta['is_video'] = True
                if 'dur' in wrapper:
                    meta['duration_ms'] = int(wrapper['dur'])
            return plaintext, meta
        return plaintext

    def decrypt_file_thumbnail(self, encrypted_thumb, nonce_thumb, encrypted_key, sender_login):
        if not self.session_manager:
            raise SessionError('Session manager not initialised')
        wire = json.loads(encrypted_key)
        wrapper_bytes = self.session_manager.decrypt_from(sender_login, wire)
        wrapper = json.loads(wrapper_bytes.decode('utf-8'))
        file_key = base64.b64decode(wrapper['k'])
        return AESGCM(file_key).decrypt(nonce_thumb, encrypted_thumb, None)

    def peek_file_meta(self, encrypted_key, sender_login):
        if not self.session_manager:
            raise SessionError('Session manager not initialised')
        wire = json.loads(encrypted_key)
        wrapper_bytes = self.session_manager.decrypt_from(sender_login, wire)
        wrapper = json.loads(wrapper_bytes.decode('utf-8'))
        meta = {}
        if wrapper.get('vid'):
            meta['is_video'] = True
            if 'dur' in wrapper:
                meta['duration_ms'] = int(wrapper['dur'])
        return meta

    def send_heartbeat(self, callback=None):
        if callback is None:
            callback = lambda x: None
        make_server_request_async('heartbeat', {}, callback)

    def set_offline_async(self, callback=None):
        if callback is None:
            callback = lambda x: None
        make_server_request_async('set_offline', {}, callback)

    def set_offline_sync(self):
        data = {}
        if self.network_manager.session_token:
            data['session_token'] = self.network_manager.session_token
        if self.network_manager.user_token:
            data['user_token'] = self.network_manager.user_token
        if self.network_manager.user_id:
            data['user_id'] = self.network_manager.user_id
        from network.transport import SyncHTTPRequest
        return SyncHTTPRequest.post('set_offline', data)

    def get_contacts_status(self, callback=None):
        if callback is None:
            callback = lambda x: None
        make_server_request_async('get_contacts_status', {}, callback)

    def save_privacy_preferences(self, hide_online_status, callback=None):
        if callback is None:
            callback = lambda x: None
        make_server_request_async('save_privacy_preferences',
                                  {'hide_online_status': bool(hide_online_status)},
                                  callback)

    def get_privacy_preferences(self, callback=None):
        if callback is None:
            callback = lambda x: None
        make_server_request_async('get_privacy_preferences', {}, callback)

    def upload_file(self, token, user_id, file_data, file_name, file_type,
                    is_image_only=False, encrypted_key=None, nonce_file=None,
                    thumbnail=None, nonce_thumbnail=None):
        data = {
            'user_token': token,
            'user_id': user_id,
            'file_data': file_data,
            'file_name': file_name,
            'file_type': file_type,
            'is_image_only': is_image_only
        }
        if encrypted_key:
            data['encrypted_key'] = encrypted_key
            data['nonce_file'] = nonce_file
            data['is_encrypted'] = 1
        if thumbnail:
            data['thumbnail'] = thumbnail
        if nonce_thumbnail:
            data['nonce_thumbnail'] = nonce_thumbnail

        if self.network_manager.session_token:
            data['session_token'] = self.network_manager.session_token
        return self.network_manager.send_sync_request('upload_file', data)

    def get_file(self, token, user_id, file_id, include_data=True, include_thumbnail=False):
        data = {
            'user_token': token,
            'user_id': user_id,
            'file_id': file_id,
            'include_data': include_data,
            'include_thumbnail': include_thumbnail
        }
        if self.network_manager.session_token:
            data['session_token'] = self.network_manager.session_token
        return self.network_manager.send_sync_request('get_file', data)

    def update_profile(self, token, user_id, username=None, avatar=None):
        data = {'user_token': token, 'user_id': user_id}
        if username:
            data['username'] = username
        if avatar:
            data['avatar'] = avatar
        if self.network_manager.session_token:
            data['session_token'] = self.network_manager.session_token
        return self.network_manager.send_sync_request('update_profile', data)

    def add_contact(self, token, user_id, contact_login):
        data = {'user_token': token, 'user_id': user_id, 'contact_login': contact_login}
        if self.network_manager.session_token:
            data['session_token'] = self.network_manager.session_token
        return self.network_manager.send_sync_request('add_contact', data)

    def get_contacts(self, token, user_id):
        data = {'user_token': token, 'user_id': user_id}
        if self.network_manager.session_token:
            data['session_token'] = self.network_manager.session_token
        return self.network_manager.send_sync_request('get_contacts', data)

    def get_avatar_versions(self, token, user_id, user_ids):
        data = {'user_token': token, 'user_id': user_id, 'user_ids': user_ids}
        if self.network_manager.session_token:
            data['session_token'] = self.network_manager.session_token
        return self.network_manager.send_sync_request('get_avatar_versions', data)

    def get_avatar(self, token, user_id, target_user_id):
        data = {'user_token': token, 'user_id': user_id, 'target_user_id': target_user_id}
        if self.network_manager.session_token:
            data['session_token'] = self.network_manager.session_token
        return self.network_manager.send_sync_request('get_avatar', data)

    def save_contact_settings(self, token, user_id, contact_login, display_name):
        data = {'user_token': token, 'user_id': user_id, 'contact_login': contact_login, 'display_name': display_name}
        if self.network_manager.session_token:
            data['session_token'] = self.network_manager.session_token
        return self.network_manager.send_sync_request('save_contact_settings', data)

    def get_contact_settings(self, token, user_id):
        data = {'user_token': token, 'user_id': user_id}
        if self.network_manager.session_token:
            data['session_token'] = self.network_manager.session_token
        return self.network_manager.send_sync_request('get_contact_settings', data)

    def remove_contact(self, token, user_id, contact_login):
        data = {'user_token': token, 'user_id': user_id, 'contact_login': contact_login}
        if self.network_manager.session_token:
            data['session_token'] = self.network_manager.session_token
        return self.network_manager.send_sync_request('remove_contact', data)

    def search_users(self, token, user_id, search_query):
        data = {'user_token': token, 'user_id': user_id, 'search_query': search_query}
        if self.network_manager.session_token:
            data['session_token'] = self.network_manager.session_token
        return self.network_manager.send_sync_request('search_users', data)

    def disconnect(self):
        self.network_manager.stop_event_listener()
        self.file_cache = None

    def _handle_register_start(self, login, username, password, callback, response):
        if not response or not response.get('success'):
            callback(response)
            return

        client_reg_start = opaque_ke_py.client_registration_start(password.encode('utf-8'))
        registration_request = client_reg_start.get_message()
        client_reg_state = client_reg_start.get_state()

        make_server_request_async('opaque/register/finish', {
            'login': login,
            'username': username,
            'registration_request': base64.b64encode(registration_request).decode('utf-8')
        }, lambda resp: self._handle_register_finish(login, username, password, client_reg_state, callback, resp))

    def _handle_register_finish(self, login, username, password, client_reg_state, callback, response):
        if not response or not response.get('success'):
            callback(response)
            return

        server_response = base64.b64decode(response['server_response'])
        client_reg_finish = opaque_ke_py.client_registration_finish(password.encode('utf-8'), client_reg_state,
                                                                    server_response)
        registration_upload = client_reg_finish.get_message()

        master_key = gen_msg_master_key()
        encrypted = encrypt_master_key(master_key, password)
        encrypted_master_key = json.dumps(encrypted)

        make_server_request_async('opaque/register/upload', {
            'login': login,
            'username': username,
            'registration_upload': base64.b64encode(registration_upload).decode('utf-8'),
            'encrypted_master_key': encrypted_master_key
        }, lambda resp: self._handle_register_upload(login, username, password, master_key, callback, resp))

    def _handle_register_upload(self, login, username, password, master_key, callback, response):
        if response and response.get('success'):
            user_id = response['user_id']
            self.user_login = login
            try:
                self.init_e2ee(master_key)
            except Exception as exc:
                print(f'init_e2ee failed register: {type(exc).__name__}: {exc}')
                traceback.print_exc()
            callback(response)
        else:
            callback(response)

    def opaque_register_async(self, login, username, password, callback):
        make_server_request_async('opaque/register/start', {
            'login': login,
            'username': username
        }, lambda resp: self._handle_register_start(login, username, password, callback, resp))

    def _handle_login_start(self, login, password, client_login_state, callback, response):
        if not response or not response.get('success'):
            self.login_in_progress = False
            self.network_manager.stop_event_listener()
            callback(response)
            return

        state_id = response['state_id']
        credential_response = base64.b64decode(response['credential_response'])

        try:
            client_login_finish = opaque_ke_py.client_login_finish(password.encode('utf-8'), client_login_state,
                                                                   credential_response)
            credential_finalization = client_login_finish.get_message()
        except Exception as e:
            def handle_failed_response(failed_response):
                self.login_in_progress = False
                self.network_manager.stop_event_listener()
                if failed_response and failed_response.get('blocked'):
                    callback({'success': False, 'error': failed_response.get('error')})
                else:
                    callback({'success': False, 'error': 'Неверный логин или пароль'})
            make_server_request_async('opaque/login/failed', {
                'login': login
            }, handle_failed_response)
            return

        make_server_request_async('opaque/login/finish', {
            'state_id': state_id,
            'credential_finalization': base64.b64encode(credential_finalization).decode('utf-8')
        }, lambda resp: self._handle_login_finish(login, password, callback, resp))

    def _handle_login_finish(self, login, password, callback, response):
        if response and response.get('success'):
            user_id = response['user_id']
            self.set_user_credentials(response['session_token'], user_id, login)
            encrypted_master_key_str = response.get('encrypted_master_key')
            if encrypted_master_key_str:
                try:
                    encrypted = json.loads(encrypted_master_key_str)
                    master_key = decrypt_master_key(encrypted, password)
                    self.init_e2ee(master_key)
                except Exception as exc:
                    print(f'init_e2ee failed login: {type(exc).__name__}: {exc}')
                    traceback.print_exc()
            self.network_manager.start_event_listener()
            self.login_in_progress = False
            callback(response)
        else:
            self.login_in_progress = False
            callback(response)

    def opaque_login_async(self, login, password, callback):
        if self.login_in_progress:
            callback({'success': False, 'error': 'Логин уже выполняется'})
            return
        self.login_in_progress = True

        client_login_start = opaque_ke_py.client_login_start(password.encode('utf-8'))
        credential_request = client_login_start.get_message()
        client_login_state = client_login_start.get_state()

        make_server_request_async('opaque/login/start', {
            'login': login,
            'credential_request': base64.b64encode(credential_request).decode('utf-8')
        }, lambda resp: self._handle_login_start(login, password, client_login_state, callback, resp))

    def _handle_change_password_server_response(self, new_password, client_reg_state, callback, response):
        if not response or not response.get('success'):
            callback(response)
            return

        server_response = base64.b64decode(response['server_response'])
        client_reg_finish = opaque_ke_py.client_registration_finish(new_password.encode('utf-8'), client_reg_state,
                                                                    server_response)
        registration_upload = client_reg_finish.get_message()

        master_key = self.master_key_bytes
        encrypted_new = encrypt_master_key(master_key, new_password)
        encrypted_master_key_new = json.dumps(encrypted_new)

        make_server_request_async('opaque/change_password/upload', {
            'registration_upload': base64.b64encode(registration_upload).decode('utf-8'),
            'encrypted_master_key': encrypted_master_key_new
        }, lambda resp: self._handle_change_password_upload(callback, resp))

    def _handle_change_password_upload(self, callback, response):
        if response and response.get('success'):
            callback({'success': True})
        else:
            callback(response)

    def opaque_change_password_async(self, new_password, callback):
        if not self.master_key_bytes:
            callback({'success': False, 'error': 'E2EE не инициализирован'})
            return

        client_reg_start = opaque_ke_py.client_registration_start(new_password.encode('utf-8'))
        client_reg_state = client_reg_start.get_state()
        registration_request = client_reg_start.get_message()

        make_server_request_async('opaque/change_password/get_server_response', {
            'registration_request': base64.b64encode(registration_request).decode('utf-8')
        }, lambda resp: self._handle_change_password_server_response(new_password, client_reg_state, callback, resp))


messenger_api = MessengerAPI()


def make_server_request_async(endpoint, data=None, callback=None):
    # -- асинхронный запрос
    if data is None:
        data = {}
    if callback is None:
        callback = lambda x: None

    payload = dict(data)
    nm = messenger_api.network_manager
    if nm.session_token and 'session_token' not in payload:
        payload['session_token'] = nm.session_token
    if nm.user_token and 'user_token' not in payload:
        payload['user_token'] = nm.user_token
    if nm.user_id and 'user_id' not in payload:
        payload['user_id'] = nm.user_id

    AsyncHTTPRequest(endpoint, payload, callback)