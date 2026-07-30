"""task_prompt 의 {attacker_token} placeholder 치환 단위 테스트 (Docker 불필요).

인증형(idor) 챌린지가 인스턴스별 랜덤 토큰을 학생에게 알려주는 통로. 공개하는 것은 반드시
**공격자**(flag 항목 소유자가 아닌 사용자) 토큰이어야 한다 — 피해자 토큰을 주면 학생이
'자기 노트'를 읽는 꼴이라 IDOR 가 성립하지 않는다.
"""

from engine.bundle import _resolve_task_prompt


def _seed(alice_token="token-aaaa", bob_token="token-bbbb"):
    # 엔진 seed 구조: alice(id 1)가 flag 노트 소유(피해자), bob(id 2)이 공격자.
    return {
        "users": [
            {"id": 1, "token": alice_token, "name": "alice", "workspace_id": 7},
            {"id": 2, "token": bob_token, "name": "bob", "workspace_id": 7},
        ],
        "notes": [
            {"id": 1, "owner_id": 1, "title": "private", "body": "FLAG{x}", "is_private": True},
            {"id": 2, "owner_id": 2, "title": "public", "body": "hi", "is_private": False},
        ],
    }


def test_substitutes_attacker_not_victim():
    # 공격자(bob) 토큰이 들어가야 한다. 피해자(alice, flag 소유자) 토큰이면 IDOR 아님.
    out = _resolve_task_prompt(
        "당신은 bob 계정입니다 (Authorization: Bearer {attacker_token}). alice 노트를 읽으세요.",
        _seed(alice_token="token-VICTIM", bob_token="token-ATTACKER"),
    )
    assert "Bearer token-ATTACKER" in out
    assert "token-VICTIM" not in out  # 피해자(flag 소유자) 토큰은 절대 안 들어간다
    assert "{attacker_token}" not in out


def test_works_for_tickets_seed():
    seed = {
        "users": [{"id": 1, "token": "t-alice"}, {"id": 2, "token": "t-bob"}],
        "tickets": [{"id": 1, "owner_id": 1}, {"id": 2, "owner_id": 2}],
    }
    assert _resolve_task_prompt("h {attacker_token}", seed) == "h t-bob"


def test_noop_without_placeholder():
    # 인증 불필요한 sqli 프롬프트 등은 원문 그대로(치환 없음).
    prompt = "노트 검색(GET /notes/search?q=)에 SQL 인젝션이 있습니다."
    assert _resolve_task_prompt(prompt, _seed()) == prompt


def test_attacker_is_non_owner_regardless_of_user_order():
    seed = {
        "users": [{"id": 2, "token": "t-bob"}, {"id": 1, "token": "t-alice"}],
        "notes": [{"id": 1, "owner_id": 1}],  # 피해자 = id 1
    }
    assert _resolve_task_prompt("h {attacker_token}", seed) == "h t-bob"


def test_tolerates_missing_structure():
    # seed 구조가 예상과 달라도 예외 없이 빈 토큰으로 치환(방어적).
    assert _resolve_task_prompt("x {attacker_token}", {}) == "x "
