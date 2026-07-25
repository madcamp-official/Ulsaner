"""엔진이 생성한 번들을 플랫폼(오케스트레이터)이 기대하는 레이아웃에 맞춘다.

플랫폼의 orchestrator.runner.build_image()는 `bundle_dir/Dockerfile`을 찾는다.
엔진은 자체 자가검증(engine.verifier)을 위해 `bundle_dir/app/Dockerfile`을 쓰는
관례를 이미 갖고 있으므로(테스트로 검증된 기존 동작, 바꾸지 않는다), 여기서는
`app/`를 빌드 컨텍스트로 삼는 위임 Dockerfile을 번들 루트에 추가로 만들어
두 관례를 동시에 만족시킨다.
"""

from __future__ import annotations

import pathlib

_ROOT_DOCKERFILE = """FROM python:3.11-slim
WORKDIR /app
COPY app/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY app/ .
RUN useradd -m appuser
USER appuser
EXPOSE 8000
CMD ["python", "main.py"]
"""


def add_platform_dockerfile(bundle_dir: pathlib.Path) -> None:
    (bundle_dir / "Dockerfile").write_text(_ROOT_DOCKERFILE)
