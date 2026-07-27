"""Phase 1: easy/hard IDOR 취약 앱을 seed별로 생성하고 index.json을 쓴다.

Ulsaner 엔진 환경(libcst 필요, `.venv/bin/python`)에서 실행한다. Docker 자가검증
(`engine.bundle.generate_bundle`)은 건너뛰고 `injector.inject`로 취약 인스턴스만 만든다.

seed_data 규약(engine/params.py): user1=alice(id1, note1=flag/private),
user2=bob(id2, note2="hello"/public). 공격자=bob, 피해자=alice. bob 토큰으로
alice의 /notes/1을 읽으면 flag 유출 = IDOR.

  ULSANER_ROOT=/path/to/Ulsaner  $ULSANER_ROOT/.venv/bin/python gen_apps.py <workdir>
"""
import json
import os
import random
import shutil
import sys
from pathlib import Path

ULSANER = Path(os.environ.get("ULSANER_ROOT", Path(__file__).resolve().parents[3]))
sys.path.insert(0, str(ULSANER))

from engine import injector, params
from engine.slots.easy_idor import build_easy_idor_slot
from engine.slots.hard_idor import build_hard_idor_slot

TEMPLATE = ULSANER / "templates" / "notes_app"
WORK = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("/tmp/bench_work")
WORK.mkdir(parents=True, exist_ok=True)

PLAN = [("easy", s) for s in (1101, 1102, 1103, 1104)] + \
       [("hard", s) for s in (2201, 2202, 2203, 2204)]
SLOTS = {"easy": build_easy_idor_slot, "hard": build_hard_idor_slot}

index = []
for tier, seed in PLAN:
    app_dir = WORK / f"{tier}-{seed}" / "app"
    if app_dir.parent.exists():
        shutil.rmtree(app_dir.parent)
    injector.inject(TEMPLATE, app_dir, SLOTS[tier]())
    seed_data, flag = params.build_seed_data(random.Random(seed))
    params.write_seed_data(app_dir, seed_data)
    bob = seed_data["users"][1]  # 공격자
    index.append({
        "tier": tier, "seed": seed, "app_dir": str(app_dir), "flag": flag,
        "attacker_token": bob["token"],
        "baseline_path": "/notes/2",   # bob 자기 노트("hello")
        "attack_path": "/notes/1",     # alice 비공개 노트(flag)
        "victim_marker": flag, "owner_marker": "hello",
    })

(WORK / "index.json").write_text(json.dumps(index, ensure_ascii=False, indent=2))
print(f"생성 완료: {len(index)}개 → {WORK / 'index.json'}")
for e in index:
    print(f"  {e['tier']}-{e['seed']}: flag={e['flag']}")
