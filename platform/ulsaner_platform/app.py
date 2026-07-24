"""Ulsaner 플랫폼 FastAPI 앱 (Part B).

Day 1: 스캐폴드 + 헬스체크. 챌린지 요청/배포/flag 제출은 Day 2~3 에서 붙인다.
"""

from fastapi import FastAPI

app = FastAPI(
    title="Ulsaner Platform",
    description="매번 새로 생성되는 웹 취약점 훈련 엔진 — 플랫폼(검증 서비스 · 웹 UI)",
    version="0.1.0",
)


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}
