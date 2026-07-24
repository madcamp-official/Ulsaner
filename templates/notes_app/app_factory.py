from fastapi import FastAPI
from routes import notes


def create_app() -> FastAPI:
    app = FastAPI()
    app.include_router(notes.router)
    return app
