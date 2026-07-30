# easy/idor fixture 번들 이미지.
# 설계 §11: non-root 로 실행. 자원 상한·네트워크 격리는 오케스트레이터가 런타임 플래그로 건다.
FROM python:3.12-slim

WORKDIR /app

# 의존성 먼저 설치해 레이어 캐시 활용
COPY app/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/

# non-root 사용자
RUN useradd --create-home --uid 10001 appuser
USER appuser

EXPOSE 8000

# manifest.entry.port 와 일치해야 한다 (8000)
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
