import io
import struct

from PIL import Image, ImageDraw

GENERIC_THUMB_SIZE = (480, 270)


def make_placeholder_thumbnail():
    img = Image.new('RGB', GENERIC_THUMB_SIZE, color=(36, 38, 48))
    draw = ImageDraw.Draw(img)
    cx, cy = GENERIC_THUMB_SIZE[0] // 2, GENERIC_THUMB_SIZE[1] // 2
    r = 56
    draw.ellipse((cx - r, cy - r, cx + r, cy + r), fill=(255, 255, 255, 230))
    triangle = [
        (cx - r // 3, cy - r // 2),
        (cx - r // 3, cy + r // 2),
        (cx + r // 2, cy),
    ]
    draw.polygon(triangle, fill=(36, 38, 48))
    out = io.BytesIO()
    img.save(out, format='JPEG', quality=70, optimize=True)
    return out.getvalue()


def _parse_mp4_duration_ms(file_path):
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
    except OSError:
        return 0

    def walk(buf, end):
        i = 0
        while i + 8 <= end:
            size = struct.unpack('>I', buf[i:i + 4])[0]
            atype = buf[i + 4:i + 8]
            header = 8
            if size == 1:
                if i + 16 > end:
                    return None
                size = struct.unpack('>Q', buf[i + 8:i + 16])[0]
                header = 16
            if size < header:
                return None
            yield atype, i + header, i + size
            i += size

    try:
        for atype, start, stop in walk(data, len(data)):
            if atype == b'moov':
                for sub_type, s, e in walk(data, stop):
                    if s < start or e > stop:
                        continue
                    if sub_type == b'mvhd':
                        if e - s < 24:
                            return 0
                        version = data[s]
                        if version == 1:
                            if e - s < 36:
                                return 0
                            timescale = struct.unpack('>I', data[s + 20:s + 24])[0]
                            duration = struct.unpack('>Q', data[s + 24:s + 32])[0]
                        else:
                            timescale = struct.unpack('>I', data[s + 12:s + 16])[0]
                            duration = struct.unpack('>I', data[s + 16:s + 20])[0]
                        if timescale == 0:
                            return 0
                        return int((duration * 1000) // timescale)
    except Exception:
        return 0
    return 0


def _try_qt_extract(file_path, timeout_ms=3000):
    try:
        from PyQt6.QtCore import QUrl, QEventLoop, QTimer
        from PyQt6.QtMultimedia import QMediaPlayer, QVideoSink
    except Exception:
        return 0, None

    duration_ms = [0]
    thumb_bytes = [None]
    captured = [False]
    loop = QEventLoop()

    try:
        player = QMediaPlayer()
        sink = QVideoSink()
        player.setVideoSink(sink)
    except Exception:
        return 0, None

    def maybe_quit():
        if captured[0] and duration_ms[0]:
            loop.quit()

    def on_frame_changed(frame):
        if captured[0]:
            return
        try:
            if not frame or not frame.isValid():
                return
            img = frame.toImage()
            if img.isNull():
                return
            from PyQt6.QtCore import QBuffer, QByteArray
            ba = QByteArray()
            buf = QBuffer(ba)
            buf.open(QBuffer.OpenModeFlag.WriteOnly)
            scaled = img.scaledToWidth(GENERIC_THUMB_SIZE[0])
            ok = scaled.save(buf, 'JPEG', 75)
            buf.close()
            if ok:
                thumb_bytes[0] = bytes(ba)
                captured[0] = True
                maybe_quit()
        except Exception:
            pass

    def on_duration(d):
        duration_ms[0] = int(d) if d else 0
        maybe_quit()

    def on_status(status):
        try:
            from PyQt6.QtMultimedia import QMediaPlayer as _MP
            if status == _MP.MediaStatus.InvalidMedia:
                loop.quit()
        except Exception:
            pass
    sink.videoFrameChanged.connect(on_frame_changed)
    player.durationChanged.connect(on_duration)
    player.mediaStatusChanged.connect(on_status)
    timer = QTimer()
    timer.setSingleShot(True)
    timer.timeout.connect(loop.quit)
    try:
        player.setSource(QUrl.fromLocalFile(str(file_path)))
        player.setPosition(50)
        player.play()
        timer.start(timeout_ms)
        loop.exec()
    finally:
        try:
            player.stop()
        except Exception:
            pass

    return duration_ms[0], thumb_bytes[0]


def probe_video(file_path):
    duration_ms, thumb_bytes = _try_qt_extract(file_path)
    if duration_ms <= 0:
        duration_ms = _parse_mp4_duration_ms(file_path)
    if not thumb_bytes:
        thumb_bytes = make_placeholder_thumbnail()
    return max(0, int(duration_ms)), thumb_bytes
