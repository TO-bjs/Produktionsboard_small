# Produktionsboard_small

Abgespecktes Produktionsboard auf Basis von Flask.

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
# optional für Tests
pip install -e .[dev]
```

## ENV-Variablen

- `FLASK_ENV`: `development`, `production` oder `testing`
- `SECRET_KEY`: Flask Secret
- `DATABASE`: SQLite-Datei für die App (Default: `users.db`)
- `TEST_DATABASE`: DB-Pfad im Testmodus (Default: `test_users.db`)
- `UPLOAD_FOLDER`: Upload-Verzeichnis (Default: `uploads`)
- `LOG_LEVEL`: Logging-Level wie `DEBUG`, `INFO`, `WARNING`, `ERROR`
- `DATABASE_URL`: optional für Alembic (z. B. `sqlite:///users.db`)

## Start (Dev)

```bash
export FLASK_ENV=development
python app.py
```

## Start (Prod)

```bash
export FLASK_ENV=production
python start_server.py
```

## Logging

Die Anwendung nutzt eine zentrale Logging-Konfiguration (`app/logging_config.py`) mit konsistentem Format:

```text
%(asctime)s | %(levelname)s | %(name)s | %(message)s
```

Betriebsfehler werden via Logger erfasst (kein `print` für Fehlerpfade).

## Tests

```bash
pytest
```

Aktuelles Grundgerüst:
- Login-Flow
- Passwort-Reset-Request
- Admin-CRUD (User anlegen/löschen)

## Migrationen (Alembic)

Initiale Migration liegt unter `migrations/versions/0001_initial_schema.py`.

```bash
# aktives DB-Ziel setzen (optional)
export DATABASE_URL=sqlite:///users.db

# auf aktuellen Stand migrieren
alembic upgrade head

# neue Migration erzeugen
alembic revision -m "beschreibung"
```
