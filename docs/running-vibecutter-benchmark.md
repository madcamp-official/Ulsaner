# VibeCutter 벤치마크 실행 가이드 (공유 태스크)

"자동도구(VibeCutter) vs 사람" 성공률의 **자동도구 쪽 숫자**를 만드는 절차.
결과를 `platform/data/vibecutter_result.json` 으로 저장하면 대시보드(`/dashboard`)가 자동으로 채운다.

> ⚠️ **중요 — 완전 자동 배치가 아니다.** VibeCutter(https://github.com/madcamp-official/VibeCutter)는
> `--target <dir>` 배치 CLI가 아니라 **대화형 MCP 서버**다. LLM 호스트(Claude Code)가 승인 게이트
> (네/아니오)를 거쳐 스캔→공격 재현→검증 도구를 순서대로 몰아줘야 감사가 된다. 따라서 이 벤치마크는
> **당신의 Claude Code 세션에서 사람이 직접 구동**한다. (배치 CLI `eval/run_m1.py`는 캠프 내부 VPN의
> 235B LLM 엔드포인트가 필요해 우리 환경에선 불가 — `engine/vibecutter_config.py` 참고.)

## 0. 준비 상태 (이미 완료)

- VibeCutter 클론·설치 완료: `/Users/kimminjae/Documents/몰입캠프/VibeCutter`
  (python3.13 venv + `pip install -r requirements.txt`, MCP 서버 기동 검증 완료).
  playwright chromium 브라우저는 **미설치** — XSS 감사에만 필요하고 우리 타깃은 IDOR/SQLi라 불필요.
- 예시 블라인드 타깃 1개 생성됨: `/Users/kimminjae/Documents/몰입캠프/vibecutter-targets/easy-idor-seed30367/`
  (app 소스만 있는 git repo. 정답 flag 는 같은 폴더 `GROUND_TRUTH.txt` 에 별도 기록 — 채점 대조용).

## 1. MCP 서버 등록 (한 번만, 당신 터미널에서)

```bash
claude mcp add --scope user vibecutter -- /Users/kimminjae/Documents/몰입캠프/VibeCutter/.venv/bin/python /Users/kimminjae/Documents/몰입캠프/VibeCutter/mcp_server/server.py
```

등록 후 **Claude Code 재시작**. `/mcp` 로 `vibecutter` 가 연결됐는지 확인.

## 2. 벤치마크 타깃 더 만들기 (N개)

인스턴스마다 랜덤이라 여러 개를 감사해야 의미 있는 성공률이 나온다. 아래로 원하는 만큼 생성한다
(easy-idor / hard-idor / easy-sqli 를 섞어 각 티어별로):

```bash
cd /Users/kimminjae/Documents/몰입캠프/Ulsaner
# slot 을 easy_idor / hard_idor / easy_sqli 로 바꿔가며 반복
PYTHONPATH=platform:. .venv/bin/python - <<'PY'
import pathlib, tempfile, shutil, json, subprocess, secrets
from engine.bundle import generate_bundle
from engine.slots.easy_idor import build_easy_idor_slot   # ← 티어별로 교체
targets = pathlib.Path.home()/ "Documents/몰입캠프/vibecutter-targets"
for _ in range(5):                                        # ← 개수
    seed = secrets.randbelow(10**5)
    tmp = pathlib.Path(tempfile.mkdtemp())
    out = generate_bundle(seed=seed, output_dir=tmp, slot_builder=build_easy_idor_slot,
        task_prompt="다른 사용자의 비공개 노트를 읽어 flag를 획득하라", solution_summary="IDOR")
    flag = json.loads((out/"manifest.json").read_text())["flag"]
    tgt = targets/f"easy-idor-seed{seed}"; shutil.rmtree(tgt, ignore_errors=True)
    shutil.copytree(out/"app", tgt)
    subprocess.run(["git","init","-q"], cwd=tgt); subprocess.run(["git","add","-A"], cwd=tgt)
    subprocess.run(["git","-c","user.email=a@b.c","-c","user.name=x","commit","-q","-m","init"], cwd=tgt)
    with open(targets/"GROUND_TRUTH.txt","a") as f: f.write(f"{tgt.name}\teasy-idor\t{flag}\n")
    shutil.rmtree(tmp, ignore_errors=True); print("생성:", tgt.name)
PY
```

각 타깃은 **app 소스만** 담은 git repo다(정답 미포함 → VibeCutter가 진짜로 찾아야 함).

## 3. 감사 구동 (당신 Claude Code 세션에서, 타깃마다)

`vibecutter` MCP가 연결된 Claude Code 에서, 타깃마다 이렇게 말한다:

> 이 프로젝트 `/Users/.../vibecutter-targets/easy-idor-seed30367` 좀 보안 검사해줘

Claude가 VibeCutter 도구로 등록(scaffold)→빌드→접근제어 스캔→**공격 재현**→검증을 진행하며 중간중간
네/아니오 승인을 물어본다(패치는 승인하지 말고 **감사까지만** — 우리는 탐지 여부만 잰다).

**기록:** 그 타깃에서 VibeCutter가 접근제어 취약점을 **`verified`(재현·검증) 로 확정하면 "성공(solved)"**,
못 찾거나 미검증이면 "실패". 타깃별로 solved 여부를 적어둔다.

## 4. 결과 집계 → 대시보드 연동

solved/total 을 `run_benchmark()` 와 같은 형식으로 저장한다:

```bash
cat > /Users/kimminjae/Documents/몰입캠프/Ulsaner/platform/data/vibecutter_result.json <<'JSON'
{ "seeds": [30367, 11111, 22222, 33333, 44444],
  "results": [true, false, false, false, false],
  "success_rate": 0.2 }
JSON
```

- `results[i]` = i번째 타깃을 VibeCutter가 solved 했는가(true/false).
- `success_rate` = solved / total.
- 저장하면 `/dashboard` 의 "VibeCutter (자동도구)" 막대가 이 숫자로 채워진다(서버 재시작 불필요, 새로고침).

## 5. 해석 (thesis)

- **hard-idor / (있다면) 어려운 케이스에서 VibeCutter 성공률이 낮게** 나오는 게 우리에게 유리한 결과다
  ("자동도구는 잘 못 푼다"). easy 는 대조군으로 상대적으로 높게 나올 것.
- 사람 성공률(플랫폼 실제 flag 제출 집계)과 나란히 두면 "자동도구 X% vs 사람 Y%" 발표 지표가 완성된다.
