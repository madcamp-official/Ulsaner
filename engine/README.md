# engine/

**소유: A(엔진) — `feature-sy` 브랜치**

슬롯 라이브러리, 주입 엔진(AST), 레퍼런스 익스플로잇, 자가검증, VibeCutter 벤치마크 하네스.

구현 계획: [`docs/superpowers/plans/2026-07-24-ulsaner-engine-implementation-plan.md`](../docs/superpowers/plans/2026-07-24-ulsaner-engine-implementation-plan.md) — Task 1, 4~15.

## VibeCutter 벤치마크

`vibecutter_bench.py`는 "자동도구(VibeCutter) vs 사람" 비교에서 자동도구 쪽 성공률 숫자를
만드는 2단계 배치 하네스다(gen=Ulsaner venv에서 seed별 취약앱 생성, audit=VibeCutter
자체 venv에서 탐지·검증 + 레퍼런스 익스플로잇으로 독립 ground truth 확인). 결과 JSON을
`platform/data/vibecutter_result.json`에 쓰면 대시보드가 자동으로 채운다.

```bash
# Phase 1 (Ulsaner venv, 저장소 루트에서)
ULSANER_ROOT="$(pwd)" .venv/bin/python -m engine.vibecutter_bench gen <workdir>

# Phase 2 (VibeCutter venv, 절대경로 스크립트로)
VC_ROOT=/path/to/VibeCutter VCVENV_PY=/path/to/target/.vcvenv/bin/python \
    "$VC_ROOT/.venv/bin/python" "$ULSANER_ROOT/engine/vibecutter_bench.py" audit \
    <workdir> <out.json>
```

자세한 사전준비·옵션·출력 스키마는 [`docs/running-vibecutter-benchmark.md`](../docs/running-vibecutter-benchmark.md) 참고.
