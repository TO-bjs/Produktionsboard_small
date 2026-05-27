from waitress import serve
from app import create_app

app = create_app()
serve(app, host='0.0.0.0', port=5000)
