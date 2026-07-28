"""task_prompt 의 {alice_token} placeholder 치환 단위 테스트 (Docker 불필요).

인증형(idor) 챌린지가 인스턴스별 랜덤 토큰을 학생에게 알려주는 통로. 토큰은 alice 자신의
자격증명이라 공개돼도 flag 는 안 샌다(치환 대상은 alice=id 1 토큰뿐).
"""

from engine.bundle import _resolve_task_prompt


def _seed(alice_token="token-aaaa", bob_token="token-bbbb"):
    return {
        "users": [
            {"id": 1, "token": alice_token, "name": "alice", "workspace_id": 7},
            {"id": 2, "token": bob_token, "name": "bob", "workspace_id": 7},
        ]
    }


def test_substitutes_alice_token():
    out = _resolve_task_prompt(
        "당신은 alice 계정입니다 (Authorization: Bearer {alice_token}). 노트를 읽으세요.",
        _seed(alice_token="token-1234"),
    )
    assert "Bearer token-1234" in out
    assert "{alice_token}" not in out


def test_never_leaks_bob_token():
    out = _resolve_task_prompt(
        "Bearer {alice_token}", _seed(alice_token="token-aaaa", bob_token="token-SECRET")
    )
    assert "token-SECRET" not in out  # bob(공격 대상) 토큰은 절대 프롬프트에 안 들어간다
    assert out == "Bearer token-aaaa"


def test_noop_without_placeholder():
    # 인증 불필요한 sqli 프롬프트 등은 원문 그대로(치환 없음).
    prompt = "노트 검색(GET /notes/search?q=)에 SQL 인젝션이 있습니다."
    assert _resolve_task_prompt(prompt, _seed()) == prompt


def test_picks_user_id_1_regardless_of_order():
    seed = {"users": [{"id": 2, "token": "t-bob"}, {"id": 1, "token": "t-alice"}]}
    assert _resolve_task_prompt("h {alice_token}", seed) == "h t-alice"


def test_tolerates_missing_users():
    # seed 구조가 예상과 달라도 예외 없이 빈 토큰으로 치환(방어적).
    assert _resolve_task_prompt("x {alice_token}", {}) == "x "
