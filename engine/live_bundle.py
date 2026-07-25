"""플랫폼이 스핀업 요청마다 새 인스턴스를 만들 때 쓰는 진입점.

설계의 핵심 약속("인스턴스마다 유니크한 앱")을 실제로 지키려면, 플랫폼이
고정 fixture가 아니라 매 요청마다 엔진으로 방금 생성한 번들을 배포해야 한다.
"""

from __future__ import annotations

import pathlib
import random
import uuid
from typing import Callable

from engine.bundle import generate_bundle
from engine.platform_adapter import add_platform_dockerfile
from engine.slots.base import Slot

TASK_PROMPT = "다른 사용자의 비공개 노트를 읽어 flag를 찾아라"

SOLUTION_SUMMARIES = {
    "easy": "get_note의 소유권 체크 누락을 이용해 다른 유저의 노트를 조회",
    "hard": "workspace_id 스코프 체크가 owner_id를 대신하는 결함을 이용",
}


def generate_live_bundle(slot_builder: Callable[[], Slot], workdir: pathlib.Path) -> pathlib.Path:
    """slot_builder로 새 인스턴스를 생성하고, 플랫폼이 바로 배포 가능한 형태로 반환한다."""
    seed = random.SystemRandom().getrandbits(32)
    output_dir = workdir / f"live-{uuid.uuid4().hex[:12]}"
    tier = slot_builder().tier
    result = generate_bundle(
        seed=seed,
        output_dir=output_dir,
        slot_builder=slot_builder,
        task_prompt=TASK_PROMPT,
        solution_summary=SOLUTION_SUMMARIES[tier],
    )
    add_platform_dockerfile(result)
    return result
