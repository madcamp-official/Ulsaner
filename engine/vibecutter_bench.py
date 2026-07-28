"""Ulsaner ↔ VibeCutter 벤치마크 하네스 (단일 진입점).

`docs/vibecutter-patches/benchmark/{gen_apps,audit_apps}.py` 임시 스크립트를 엔진
자산으로 승격한 것. seed별 취약앱 생성 → VibeCutter 감사 → 결과 JSON 저장을 하나의
모듈/두 서브커맨드(gen, audit)로 묶는다.

두 단계는 서로 다른 파이썬 인터프리터에서 돌아야 한다(의존성이 상호 배타적):
  * gen   : Ulsaner의 .venv (libcst + engine 패키지 필요)
  * audit : VibeCutter 자체 venv (contracts/runtime/verifiers/surface + httpx 필요)
그래서 이 파일은 "단일 파일/단일 진입점"이되, VibeCutter 관련 import는 cmd_audit
내부에, engine 관련 import는 generate_apps/cmd_gen 내부에 지연(lazy) 배치한다.
모듈 최상단은 표준 라이브러리만 import 한다.

실행법:
  # Phase 1 — Ulsaner venv, 저장소 루트에서 실행:
  ULSANER_ROOT="$(pwd)" .venv/bin/python -m engine.vibecutter_bench gen <workdir> \
      [--classes idor-easy,idor-hard,sqli-easy,sqli-hard] [--seeds-per-class N]

  # Phase 2 — VibeCutter venv, 아무 cwd에서 절대 경로 스크립트로 실행:
  VC_ROOT=/path/to/VibeCutter VCVENV_PY=/path/to/target/.vcvenv/bin/python \
      "$VC_ROOT/.venv/bin/python" "$ULSANER_ROOT/engine/vibecutter_bench.py" audit \
      <workdir> <out.json>

engine/benchmark.py(제네릭 exit-code 하네스)·engine/vibecutter_config.py 와의 관계:
  benchmark.py 의 run_external_auditor/run_benchmark 는 "타깃 디렉토리에 대해 한 번
  실행하고 종료코드를 읽는" 배치 CLI 감사도구를 가정한다. 실제 VibeCutter 는 대화형
  MCP stdio 서버라 그 인터페이스와 근본적으로 맞지 않는다(engine/vibecutter_config.py
  참고). 그래서 실제로 도는 VibeCutter 하네스는 run_benchmark 를 재사용하지 않고 이
  모듈이 별도로 존재한다. benchmark.py 는 미래의 가상 배치-CLI 감사도구를 위해 남겨둔다.
"""
import argparse
import json
import os
import sys
from pathlib import Path

# 새 위치(engine/vibecutter_bench.py) 기준: parents[0]=engine/, parents[1]=저장소 루트.
ULSANER_ROOT = Path(os.environ.get("ULSANER_ROOT", Path(__file__).resolve().parents[1]))
# gen 을 -m 이 아닌 절대 경로 스크립트로 돌려도 `from engine ...` 이 되도록 보강.
if str(ULSANER_ROOT) not in sys.path:
    sys.path.insert(0, str(ULSANER_ROOT))

TEMPLATE = ULSANER_ROOT / "templates" / "notes_app"

# VibeCutter 클론 경로(별도 체크아웃). 아래 기본값은 팀원 기준의 머신 특정값이므로
# 정상 사용은 env(VC_ROOT / VCVENV_PY)로 덮어쓰는 것이다.
_DEFAULT_VC_ROOT = str(Path.home() / "Documents/몰입캠프/VibeCutter")
_DEFAULT_VCVENV_PY = str(Path.home() / "vibecutter-targets/easy-idor-seed9896/.vcvenv/bin/python")


def _class_registry() -> dict:
    """벤치마크 클래스 레지스트리. slot 빌더가 파이썬 콜러블이라 JSON이 아닌 파이썬
    레벨 레지스트리이지만, seed 블록과 클래스 선택은 CLI로 노출된다(아래 cmd_gen).

    나중에 xss / tickets_app 을 추가하려면: 아래에 한 줄(빌더 + 겹치지 않는 새 base_seed
    블록)만 더한다. 기존 idor/sqli 감사 코드경로를 그대로 재사용하는 클래스(예: sqli-hard)는
    이 한 줄이 유일한 변경점이다. (xss 는 VibeCutter verify_xss 가 서버측 스텁이라 감사
    신호를 못 내고, tickets_app 은 gen 템플릿 일반화가 더 필요해 이번 기본 플랜에서 제외.)

    kind 는 인덱스 엔트리 형태 + 감사 디스패치를 결정한다("idor" | "sqli").
    """
    from engine.slots.easy_idor import build_easy_idor_slot
    from engine.slots.hard_idor import build_hard_idor_slot
    from engine.slots.easy_sqli import build_easy_sqli_slot
    from engine.slots.hard_sqli import build_hard_sqli_slot
    from engine.exploit_gen import build_sqli_exploit, build_hard_sqli_exploit

    return {
        "idor-easy": {"builder": build_easy_idor_slot, "base_seed": 1101, "kind": "idor"},
        "idor-hard": {"builder": build_hard_idor_slot, "base_seed": 2201, "kind": "idor"},
        "sqli-easy": {"builder": build_easy_sqli_slot, "base_seed": 3301, "kind": "sqli",
                      "exploit": build_sqli_exploit},
        "sqli-hard": {"builder": build_hard_sqli_slot, "base_seed": 4401, "kind": "sqli",
                      "exploit": build_hard_sqli_exploit},
    }


DEFAULT_CLASSES = ["idor-easy", "idor-hard", "sqli-easy", "sqli-hard"]


def generate_apps(workdir, classes: list[str], seeds_per_class: int = 5) -> list[dict]:
    """Phase 1 코어: 선택된 클래스마다 seeds_per_class 개의 취약앱을 생성하고
    <workdir>/index.json 을 쓴 뒤 인덱스(list[dict])를 돌려준다.

    sqli 엔트리의 exploit_path 는 engine.exploit_gen 의 레퍼런스 익스플로잇을 그대로
    호출해 얻는다(UNION 페이로드를 여기서 다시 만들지 않는다 — 엔진 자가검증과 동일한
    익스플로잇을 벤치마크가 쓰도록 보장).
    """
    import random
    import shutil
    from engine import injector, params

    workdir = Path(workdir).resolve()
    registry = _class_registry()
    unknown = [c for c in classes if c not in registry]
    if unknown:
        raise ValueError(f"unknown class(es): {unknown}; known: {sorted(registry)}")

    index: list[dict] = []
    for key in classes:
        spec = registry[key]
        vuln_class, tier = key.split("-", 1)
        seeds = [spec["base_seed"] + i for i in range(seeds_per_class)]
        for seed in seeds:
            app_dir = workdir / f"{vuln_class}-{tier}-{seed}" / "app"
            if app_dir.parent.exists():
                shutil.rmtree(app_dir.parent)
            injector.inject(TEMPLATE, app_dir, spec["builder"]())
            seed_data, flag = params.build_seed_data(random.Random(seed))
            params.write_seed_data(app_dir, seed_data)

            entry = {"vuln_class": vuln_class, "tier": tier, "seed": seed,
                     "app_dir": str(app_dir), "flag": flag}
            if spec["kind"] == "idor":
                bob = seed_data["users"][1]  # 공격자
                entry.update({
                    "attacker_token": bob["token"],
                    "baseline_path": "/notes/2",   # bob 자기 노트("hello")
                    "attack_path": "/notes/1",     # alice 비공개 노트(flag)
                    "victim_marker": flag,
                    "owner_marker": "hello",
                })
            else:  # sqli — 레퍼런스 익스플로잇의 전체 path 를 그대로 저장
                exploit = spec["exploit"](seed_data, flag)
                entry.update({
                    "exploit_path": exploit.path,               # 독립 ground-truth 용
                    "inject_path": exploit.path.split("?", 1)[0],  # VC 폴백 후보 구성용
                    "inject_param": "q",                         # easy/hard 공통 1차 쿼리 파라미터
                })
            index.append(entry)

    workdir.mkdir(parents=True, exist_ok=True)
    (workdir / "index.json").write_text(json.dumps(index, ensure_ascii=False, indent=2))
    return index


def cmd_gen(args) -> None:
    classes = [c.strip() for c in args.classes.split(",") if c.strip()]
    index = generate_apps(args.workdir, classes, args.seeds_per_class)
    workdir = Path(args.workdir).resolve()
    print(f"생성 완료: {len(index)}개 → {workdir / 'index.json'}")
    for e in index:
        print(f"  {e['vuln_class']}-{e['tier']}-{e['seed']}: flag={e['flag']}")


def cmd_audit(args) -> None:  # 실제 구현은 Task 3 에서 채운다.
    raise NotImplementedError("cmd_audit is implemented in Task 3")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="engine.vibecutter_bench",
        description="Ulsaner ↔ VibeCutter 벤치마크 하네스 (gen / audit).",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("gen", help="Phase 1: seed별 취약앱 생성 + index.json (Ulsaner venv)")
    g.add_argument("workdir", help="생성물이 놓일 작업 디렉토리")
    g.add_argument("--classes", default=",".join(DEFAULT_CLASSES),
                   help=f"쉼표구분 클래스 목록 (기본: {','.join(DEFAULT_CLASSES)})")
    g.add_argument("--seeds-per-class", type=int, default=5,
                   help="클래스당 seed 개수 (기본: 5)")
    g.set_defaults(func=cmd_gen)

    a = sub.add_parser("audit", help="Phase 2: VibeCutter 감사 + 결과 JSON (VibeCutter venv)")
    a.add_argument("workdir", help="Phase 1 이 만든 index.json 이 있는 작업 디렉토리")
    a.add_argument("out", help="결과 JSON 출력 경로 (예: platform/data/vibecutter_result.json)")
    a.set_defaults(func=cmd_audit)
    return parser


def main(argv=None) -> None:
    args = build_parser().parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
