"""Runnable entrypoint: ``sanic download_demo.server:app --port 8000``."""

from .app import create_app

app = create_app()
