import json
import time

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QLabel, QPushButton, QHBoxLayout, QPlainTextEdit,
    QMessageBox,
)

from network.cryptolib.safety_numbers import (
    compute_safety_number, format_safety_number,
)
from network.cryptolib.storage import trust_path


def _read_trust(own_login):
    p = trust_path(own_login)
    if not p.exists():
        return {}
    try:
        with open(p, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}


def _write_trust(own_login, data):
    p = trust_path(own_login)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def mark_verified(own_login, peer_login, peer_ik_b64):
    data = _read_trust(own_login)
    data[peer_login] = {
        'ik': peer_ik_b64,
        'verified_at': time.time(),
    }
    _write_trust(own_login, data)


def is_verified(own_login, peer_login, peer_ik_b64):
    data = _read_trust(own_login)
    entry = data.get(peer_login)
    return bool(entry and entry.get('ik') == peer_ik_b64)


class SafetyNumberDialog(QDialog):
    def __init__(self, own_login, peer_login, own_ik_bytes, peer_ik_bytes,
                 parent=None):
        super().__init__(parent)
        import base64
        self.own_login = own_login
        self.peer_login = peer_login
        self.peer_ik_b64 = base64.b64encode(peer_ik_bytes).decode()

        chunks = compute_safety_number(own_ik_bytes, peer_ik_bytes)
        formatted = format_safety_number(chunks)

        self.setWindowTitle(f'Verify — {peer_login}')
        self.setModal(True)
        self.resize(460, 320)

        layout = QVBoxLayout(self)
        layout.addWidget(QLabel(
            f'Safety number for chat with <b>{peer_login}</b>.<br>'
            'Compare these 60 digits with your contact (over a different<br>'
            'channel: in person, voice call, etc.). If they match, no one is<br>'
            'intercepting your conversation.'
        ))

        text = QPlainTextEdit(formatted, self)
        text.setReadOnly(True)
        text.setStyleSheet('font-family: monospace; font-size: 14pt;')
        text.setFixedHeight(80)
        layout.addWidget(text)

        self.status_label = QLabel(self._status_text(), self)
        layout.addWidget(self.status_label)

        buttons = QHBoxLayout()
        verify_btn = QPushButton('Mark as verified', self)
        verify_btn.clicked.connect(self._on_verify)
        close_btn = QPushButton('Close', self)
        close_btn.clicked.connect(self.accept)
        buttons.addStretch(1)
        buttons.addWidget(verify_btn)
        buttons.addWidget(close_btn)
        layout.addLayout(buttons)

    def _status_text(self):
        if is_verified(self.own_login, self.peer_login, self.peer_ik_b64):
            return '<span style="color: #2a9d2a;">✓ This contact is marked as verified.</span>'
        return '<span style="color: #c08a00;">Not yet verified.</span>'

    def _on_verify(self):
        mark_verified(self.own_login, self.peer_login, self.peer_ik_b64)
        self.status_label.setText(self._status_text())
        QMessageBox.information(self, 'Verified', f'{self.peer_login} marked as verified.')
