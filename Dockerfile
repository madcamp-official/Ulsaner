# 플랫폼 앱(platform/ulsaner_platform) 배포용 이미지.
# 오케스트레이터(orchestrator/runner.py)가 챌린지 컨테이너를 띄우기 위해
# docker CLI로 호스트 도커 소켓에 접근해야 한다(DooD) — 이 이미지엔 도커
# "데몬"은 없고 CLI만 설치하며, 실제 소켓은 실행 시 -v로 마운트해서 쓴다.
FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl gnupg \
    && install -m 0755 -d /etc/apt/keyrings \
    && curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc \
    && chmod a+r /etc/apt/keyrings/docker.asc \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian $(. /etc/os-release && echo $VERSION_CODENAME) stable" > /etc/apt/sources.list.d/docker.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends docker-ce-cli \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 의존성만 먼저 복사해 pip install 레이어를 캐싱한다(코드만 바뀌면 재설치 안 함).
COPY engine/requirements-dev.txt engine/requirements-dev.txt
RUN pip install --no-cache-dir -r engine/requirements-dev.txt

# 로컬 실행(docs/running-the-platform.md)과 동일한 레이아웃을 그대로 유지:
# 저장소 루트가 WORKDIR이고, PYTHONPATH가 platform과 루트 둘 다를 가리켜야
# `ulsaner_platform`(platform/ 아래)과 `engine`/`orchestrator`(루트 아래)가
# 둘 다 정상적으로 import된다.
COPY engine/ engine/
COPY orchestrator/ orchestrator/
COPY templates/ templates/
COPY contract/ contract/
COPY platform/ platform/

ENV PYTHONPATH=/app/platform:/app

EXPOSE 8000
CMD ["uvicorn", "ulsaner_platform.app:app", "--host", "0.0.0.0", "--port", "8000"]
