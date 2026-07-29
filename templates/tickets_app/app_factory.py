from fastapi import FastAPI
from routes import tickets, search, ui


def create_app() -> FastAPI:
    # 훈련용: 자동 API 문서(/docs·/redoc·/openapi.json)를 끈다 — 스키마를 통째로
    # 넘겨주면 '엔드포인트·파라미터를 직접 찾아내는' 정찰 난이도가 사라진다.
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.include_router(search.router)
    app.include_router(tickets.router)
    app.include_router(ui.router)  # 학생용 프론트엔드(취약 표면을 브라우징으로 노출). 슬롯 무관.
    return app
