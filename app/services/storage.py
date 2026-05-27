import os
import time
import uuid
from typing import Optional

from flask import current_app
from PIL import Image, UnidentifiedImageError
from werkzeug.utils import secure_filename

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'webp', 'gif', 'svg'}
EXTENSION_TO_MIME = {
    'png': 'image/png',
    'jpg': 'image/jpeg',
    'jpeg': 'image/jpeg',
    'webp': 'image/webp',
    'gif': 'image/gif',
    'svg': 'image/svg+xml',
}
UPLOAD_TYPE_MAP = {
    'screenshots': 'SCREENSHOT',
    'announcements': 'ANNOUNCEMENT',
    'qualimatrix': 'QUALIMATRIX',
}
DIAGRAM_BASE = os.path.join('static', 'diagramme', 'ausschussquote')
DIAGRAM_TYPES = {
    'produktivitaet': 'Produktivität',
    'stueckzahlen': 'Stückzahlen [GE]',
    'lieferzeit': 'Lieferzeit',
    'termintreue': 'Termintreue',
    'fertigungsqualitaet': 'Fertigungsqualität',
    'prozesstoerung': 'Prozesstörung',
}


def ensure_storage_dirs():
    os.makedirs(current_app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static', exist_ok=True)
    os.makedirs(DIAGRAM_BASE, exist_ok=True)
    for key in DIAGRAM_TYPES:
        os.makedirs(os.path.join(DIAGRAM_BASE, key), exist_ok=True)
    cleanup_upload_directories()


def allowed_file(filename: str) -> bool:
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def _expected_mime_for_extension(filename: str) -> Optional[str]:
    if '.' not in filename:
        return None
    ext = filename.rsplit('.', 1)[1].lower()
    return EXTENSION_TO_MIME.get(ext)


def _validate_file_signature(file_storage, expected_mime: str):
    if expected_mime == 'image/svg+xml':
        header = file_storage.stream.read(512).decode('utf-8', errors='ignore').lower()
        file_storage.stream.seek(0)
        if '<svg' not in header:
            raise ValueError('Dateiinhalt passt nicht zum Dateityp (SVG erwartet).')
        return

    try:
        image = Image.open(file_storage.stream)
        image.verify()
    except (UnidentifiedImageError, OSError) as exc:
        raise ValueError('Dateisignatur ungültig oder Datei ist beschädigt.') from exc
    finally:
        file_storage.stream.seek(0)

    if file_storage.mimetype and file_storage.mimetype != expected_mime:
        raise ValueError(f'Ungültiger MIME-Type: {file_storage.mimetype} (erwartet: {expected_mime}).')


def _validate_upload_size(file_storage, upload_type: str):
    limit_key = f'MAX_UPLOAD_SIZE_{upload_type}'
    max_bytes = current_app.config.get(limit_key)
    if not max_bytes:
        return

    position = file_storage.stream.tell()
    file_storage.stream.seek(0, os.SEEK_END)
    size = file_storage.stream.tell()
    file_storage.stream.seek(position)

    if size > max_bytes:
        raise ValueError(
            f'Datei zu groß ({size} Bytes). Erlaubt für {upload_type.lower()}: maximal {max_bytes} Bytes.'
        )


def validate_uploaded_file(file_storage, upload_type: str):
    original_name = secure_filename(file_storage.filename or '')
    if not original_name or not allowed_file(original_name):
        raise ValueError('Ungültiger Dateityp.')
    expected_mime = _expected_mime_for_extension(original_name)
    _validate_upload_size(file_storage, upload_type.upper())
    if expected_mime:
        _validate_file_signature(file_storage, expected_mime)


def save_uploaded_file(file_storage, target_folder: str, upload_type: Optional[str] = None) -> str:
    original_name = secure_filename(file_storage.filename or '')
    if not original_name or not allowed_file(original_name):
        raise ValueError('Ungültiger Dateityp.')

    expected_mime = _expected_mime_for_extension(original_name)
    upload_type = (upload_type or UPLOAD_TYPE_MAP.get(target_folder, 'SCREENSHOT')).upper()

    try:
        _validate_upload_size(file_storage, upload_type)
        if expected_mime:
            _validate_file_signature(file_storage, expected_mime)
    except ValueError as exc:
        current_app.logger.warning(
            'Upload validation failed: filename=%s target=%s upload_type=%s mimetype=%s reason=%s',
            original_name,
            target_folder,
            upload_type,
            file_storage.mimetype,
            str(exc),
        )
        raise

    ext = original_name.rsplit('.', 1)[1].lower()
    unique_filename = f"{uuid.uuid4().hex}.{ext}"
    full_dir = os.path.join(current_app.config['UPLOAD_FOLDER'], target_folder)
    os.makedirs(full_dir, exist_ok=True)
    file_storage.save(os.path.join(full_dir, unique_filename))
    return os.path.join(target_folder, unique_filename).replace('\\', '/')


def cleanup_upload_directories():
    now = time.time()
    upload_root = current_app.config['UPLOAD_FOLDER']
    retention_days = {
        'screenshots': current_app.config.get('UPLOAD_RETENTION_DAYS_SCREENSHOTS', 14),
        'announcements': current_app.config.get('UPLOAD_RETENTION_DAYS_ANNOUNCEMENTS', 90),
        'qualimatrix': current_app.config.get('UPLOAD_RETENTION_DAYS_QUALIMATRIX', 180),
    }

    for folder, days in retention_days.items():
        full_dir = os.path.join(upload_root, folder)
        if not os.path.isdir(full_dir) or days is None:
            continue
        cutoff = now - (days * 86400)
        removed = 0
        for name in os.listdir(full_dir):
            path = os.path.join(full_dir, name)
            if not os.path.isfile(path):
                continue
            try:
                if os.path.getmtime(path) < cutoff:
                    os.remove(path)
                    removed += 1
            except OSError as exc:
                current_app.logger.warning('Cleanup failed for %s: %s', path, exc)
        if removed:
            current_app.logger.info('Removed %s old files from %s (retention=%s days).', removed, folder, days)
