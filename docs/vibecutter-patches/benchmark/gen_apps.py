"""Phase 1: IDOR/SQLi 취약 앱을 seed별로 생성하고 index.json을 쓴다.

Ulsaner 엔진 환경(libcst 필요, `.venv/bin/python`)에서 실행한다. Docker 자가검증
(`engine.bundle.generate_bundle`)은 건너뛰고 `injector.inject`로 취약 인스턴스만 만든다.

seed_data 규약(engine/params.py): user1=alice(id1, note1=flag/private),
user2=bob(id2, note2="hello"/public), 둘 다 같은 workspace.

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
from engine.slots.easy_sqli import build_easy_sqli_slot

TEMPLATE = ULSANER / "templates" / "notes_app"
WORK = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("/tmp/bench_work")
WORK.mkdir(parents=True, exist_ok=True)

# (vuln_class, tier, slot_builder, [seeds])
PLAN = [
    ("idor", "easy", build_easy_idor_slot, [1101, 1102, 1103, 1104, 1105]),
    ("idor", "hard", build_hard_idor_slot, [2201, 2202, 2203, 2204, 2205]),
    ("sqli", "easy", build_easy_sqli_slot, [3301, 3302, 3303, 3304, 3305]),
]

index = []
for vuln_class, tier, builder, seeds in PLAN:
    for seed in seeds:
        app_dir = WORK / f"{vuln_class}-{tier}-{seed}" / "app"
        if app_dir.parent.exists():
            shutil.rmtree(app_dir.parent)
        injector.inject(TEMPLATE, app_dir, builder())
        seed_data, flag = params.build_seed_data(random.Random(seed))
        params.write_seed_data(app_dir, seed_data)

        entry = {"vuln_class": vuln_class, "tier": tier, "seed": seed,
                 "app_dir": str(app_dir), "flag": flag}
        if vuln_class == "idor":
            bob = seed_data["users"][1]  # 공격자
            entry.update({
                "attacker_token": bob["token"],
                "baseline_path": "/notes/2",   # bob 자기 노트("hello")
                "attack_path": "/notes/1",     # alice 비공개 노트(flag)
                "victim_marker": flag, "owner_marker": "hello",
            })
        else:  # sqli — 인증 없는 /notes/search?q=, UNION으로 비공개 note body 유출
            owner_id = seed_data["notes"][0]["owner_id"]
            entry.update({
                "inject_path": "/notes/search", "inject_param": "q",
                "exploit_payload": f"' UNION SELECT id, body FROM notes WHERE owner_id={owner_id} -- ",
            })
        index.append(entry)

(WORK / "index.json").write_text(json.dumps(index, ensure_ascii=False, indent=2))
print(f"생성 완료: {len(index)}개 → {WORK / 'index.json'}")
for e in index:
    print(f"  {e['vuln_class']}-{e['tier']}-{e['seed']}: flag={e['flag']}")
