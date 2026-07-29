from fastapi import FastAPI
from routes import portal, ui


def create_app() -> FastAPI:
    # 훈련용: 자동 API 문서(/docs·/redoc·/openapi.json)를 끈다.
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.include_router(portal.router)
    app.include_router(ui.router)  # 학생용 프론트엔드. 슬롯 무관.
    return app
