from fastapi import FastAPI
from routes import tickets, search


def create_app() -> FastAPI:
    app = FastAPI()
    app.include_router(search.router)
    app.include_router(tickets.router)
    return app
