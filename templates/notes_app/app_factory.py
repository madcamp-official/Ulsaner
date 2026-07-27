from fastapi import FastAPI
from routes import notes, search


def create_app() -> FastAPI:
    app = FastAPI()
    app.include_router(search.router)
    app.include_router(notes.router)
    return app
