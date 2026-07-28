from fastapi import FastAPI
from routes import notes, search, ui


def create_app() -> FastAPI:
    app = FastAPI()
    app.include_router(search.router)
    app.include_router(notes.router)
    app.include_router(ui.router)  # 학생용 프론트엔드(취약 표면을 브라우징으로 노출). 슬롯 무관.
    return app
