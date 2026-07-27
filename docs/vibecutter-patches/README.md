# VibeCutter 패치 — IDOR 프리필터 인가 맹점 수정

VibeCutter([`madcamp-official/VibeCutter`](https://github.com/madcamp-official/VibeCutter))로
Ulsaner가 주입한 IDOR 타깃 `easy-idor-seed9896`을 감사하다 발견한 **자동 프리필터의 오탐(미탐)**과
그 로컬 수정 기록이다. VibeCutter는 이 레포에 vendoring되지 않은 별도 클론이므로, 수정은 여기
**패치 파일**로만 보관한다 — VibeCutter 원격에는 올리지 않는다.

- 패치 베이스 커밋(VibeCutter): `95577bf` (origin/main, 2026-07-27 기준)

## 발견한 버그

취약 핸들러(주입된 타깃):

```python
@router.get("/notes/{note_id}")
def get_note(note_id: int, user=Depends(get_current_user)):
    note = get_note_by_id(note_id)          # note_id로만 조회, 소유권 검사 없음
    return {"id": note.id, "title": note.title, "body": note.body}
```

`user`를 **인증용으로 주입만 하고** 소유권(인가) 검사에는 전혀 쓰지 않는 전형적 IDOR(CWE-639).
그런데 VibeCutter의 정적 프리필터 `surface/graph.py`(`_analyze`)는
`references_current_user(signature + body)` — 즉 **핸들러 어딘가에 `get_current_user`·`user`가
보이기만 하면 "소유권 스코프됨 → 의심 아님"으로 조기 제외**했다. 결과:

- `find_idor_suspects` → suspect **0개**
- `vc_scan_access_control` → 후보 0개, `blocked: "path-id suspect가 없어..."`
- verifier가 공격을 **시도조차 못 함** → 미탐

즉 프리필터가 **"인증됨(authenticated)"을 "인가됨(authorized)"으로 착각**한다. 자물쇠가
*걸려만* 있고 *잠기진* 않은 문을 "안전"으로 넘기는 셈.

## 수정 (`idor-prefilter-authz-blindspot.patch`)

`surface/roles.py`에 `current_user_scopes_ownership(signature, body)`를 추가하고
`surface/graph.py:_analyze`가 이를 쓰게 바꿨다. 판정 규칙:

1. 본문이 현재사용자 관용구를 직접 쓰면 → 소유권 스코프로 봄(종전과 동일, 제외).
2. 시그니처가 `Depends(get_current_user)`로 **주입만** 하면 → 그 주입 변수가 **본문에서
   참조될 때만** 스코프로 인정. 받기만 하고 안 쓰면 인증일 뿐 인가가 아니므로 **의심 유지**.
3. `Depends`가 아닌 시그니처 참조(예: Java `@AuthenticationPrincipal`)는 종전대로 방어로 둠.

보수적 변경 — 정당하게 소유권 검사하는 핸들러(본문에서 user 사용)는 계속 제외되고, "주입만 하고
안 쓰는" 좁은 케이스만 새로 잡는다. 검증한 케이스: 취약 `get_note`=의심O / 방어 `get_profile`(본문서
user 사용)=제외 / 본문 `current_user()` 사용=제외 / Java `@AuthenticationPrincipal`=제외(종전 유지).

## 전제 패치 (`seed9896-provisioning.patch`)

이 타깃을 verifier가 재현하려면 self_signup provisioning 계약이 필요하다(버그와 별개, 벤치마크
셋업). `surface/candidates.py`의 `_SELF_SIGNUP_HINTS`에 seed9896 힌트(signup `/signup`,
owner-setup `POST /notes`, `path_template /notes/{id}`, `token_key accessToken`)와
`targets/verifier_provisioning.yaml` 항목을 추가한다.

## 적용 & 재현

```bash
# 1) VibeCutter 클론에 로컬 적용 (원격에 push 금지)
cd /path/to/VibeCutter
git apply /path/to/Ulsaner/docs/vibecutter-patches/seed9896-provisioning.patch
git apply /path/to/Ulsaner/docs/vibecutter-patches/idor-prefilter-authz-blindspot.patch

# 2) 타깃 앱 기동 (http://127.0.0.1:8000)
~/vibecutter-targets/.run/seed9896-start.sh

# 3) scan→verify 재현
VC_ROOT=/path/to/VibeCutter TARGET_SRC=~/vibecutter-targets/easy-idor-seed9896 \
  /path/to/VibeCutter/.venv/bin/python \
  /path/to/Ulsaner/docs/vibecutter-patches/reproduce_seed9896.py
```

## 결과 (2026-07-27)

| 상태 | prefilter suspects | scan 후보 | verify |
|---|---|---|---|
| stock VibeCutter | 0 | 0 (blocked) | 시도 못 함 (미탐) |
| 프리필터 패치 후 | 1 (`get_note`) | 1 (CWE-639) | **verified=True** — 공격 응답에만 피해자 마커 노출 |

**thesis 함의:** stock 자동 파이프라인은 이 IDOR 클래스를 놓친다(인증≠인가 혼동). 이는 "자동도구가
사람이 잡는 취약점을 놓친다"의 실증 사례이자, 동시에 프리필터의 개선 지점이다.

## 멀티-seed 벤치마크 (`benchmark/`)

seed9896 한 건이 아니라 엔진으로 생성한 여러 인스턴스에 같은 실험을 돌려 성공률을 낸다.
`platform/data/vibecutter_result.json`(대시보드 `/stats`가 읽는 형식 `{seeds,results,success_rate}`)에
저장되며, 커밋된 스냅샷은 `benchmark/benchmark-result.json`이다.

- `benchmark/gen_apps.py` (Phase 1, Ulsaner env): `easy_idor`/`hard_idor` 슬롯으로 seed별 취약 앱 생성.
- `benchmark/audit_apps.py` (Phase 2, VibeCutter env): 각 앱을 띄워 prefilter 탐지(stock/fixed) +
  verifier 재현을 기록. **회원가입 스캐폴딩 없이** seed 유저 토큰으로 `bearer_fixture` 재현.

```bash
ULSANER_ROOT=/path/to/Ulsaner \
  $ULSANER_ROOT/.venv/bin/python docs/vibecutter-patches/benchmark/gen_apps.py /tmp/bench_work
VC_ROOT=/path/to/VibeCutter VCVENV_PY=/path/to/target/.vcvenv/bin/python \
  $VC_ROOT/.venv/bin/python docs/vibecutter-patches/benchmark/audit_apps.py \
    /tmp/bench_work platform/data/vibecutter_result.json
```

### 결과 (8 인스턴스: easy×4, hard×4 — 2026-07-27)

| tier | 정적 탐지 (stock) | 정적 탐지 (fixed) | 실제 취약(verifier) | VibeCutter solved (fixed) |
|---|---|---|---|---|
| easy-idor ×4 | ✗ | ✓ | ✓ | ✓ (4/4) |
| hard-idor ×4 | ✗ | ✗ | ✓ | ✗ (0/4) |

- **stock VibeCutter: 0/8 (0%)** — prefilter 맹점으로 easy조차 미탐.
- **fixed VibeCutter: 4/8 (50%)** — easy는 다 잡지만 hard는 전부 놓침.

`hard_idor` 슬롯은 소유권 검사를 **제거**하는 게 아니라 `note.owner_id != user.id`를
`note.workspace_id != user.workspace_id`로 **바꾼다**. 두 유저가 같은 workspace라 교차 조회가
통과되는 실제 IDOR(verifier가 8건 전부 재현=`exploitable:true`)인데, 코드가 겉보기엔 `user`로
스코프된 듯 보여 정적 prefilter가 놓친다. 즉 **hard 미탐은 취약점이 없어서가 아니라 자동 도구가
위장을 못 알아봐서** — 사람은 잡고 자동도구는 놓치는 지점의 실증이다.
