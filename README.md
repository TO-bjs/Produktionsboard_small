# Produktionsboard_small

Abgespecktes Produktionsboard.

## Verbindlicher App-Aufbau

- **Produktiv gilt ausschließlich** die Flask-App-Fabrik `create_app()` in `app/__init__.py`.
- Alle produktiven Routen werden ausschließlich über Blueprints in `app/routes/` registriert.
- `app.py` ist nur ein minimaler Bootstrap für lokale Starts und darf **keine eigene Business-Logik oder Route-Definitionen** enthalten.

## Startpfad

### Produktion

```bash
python start_server.py
```

`start_server.py` verwendet ausschließlich `create_app()` und startet die App via Waitress.

### Lokal (Entwicklung)

```bash
python app.py
```

Auch dieser Pfad nutzt intern `create_app()`; die zentrale Laufzeit-Implementierung bleibt damit an genau einer Stelle.
