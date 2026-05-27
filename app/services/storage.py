import os
import uuid
from flask import current_app
from werkzeug.utils import secure_filename

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'webp', 'gif', 'svg'}
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


def allowed_file(filename: str) -> bool:
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def save_uploaded_file(file_storage, target_folder: str) -> str:
    original_name = secure_filename(file_storage.filename or '')
    if not original_name or not allowed_file(original_name):
        raise ValueError('Ungültiger Dateityp.')

    ext = original_name.rsplit('.', 1)[1].lower()
    unique_filename = f"{uuid.uuid4().hex}.{ext}"
    full_dir = os.path.join(current_app.config['UPLOAD_FOLDER'], target_folder)
    os.makedirs(full_dir, exist_ok=True)
    file_storage.save(os.path.join(full_dir, unique_filename))
    return os.path.join(target_folder, unique_filename).replace('\\', '/')
