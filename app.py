"""Legacy bootstrap for local starts.

Produktive App-Logik lebt ausschließlich in ``app/__init__.py`` und den Blueprints
unter ``app/routes``.
"""

from app import create_app

app = create_app()


if __name__ == "__main__":
    # Nur lokaler Dev-Start; produktiv wird z. B. start_server.py / WSGI verwendet.
    app.run(host="0.0.0.0", port=5000)
