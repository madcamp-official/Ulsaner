"""카탈로그 배선(sources._SLOTS + engine_source) 유닛 테스트 — Docker 불필요.

엔진 슬롯(hard_sqli·xss·tickets_app)이 플랫폼 카탈로그에 제대로 연결됐는지,
그리고 각 조합이 generate_bundle 에 올바른 오버라이드(template_dir·exploit_builders·
seed_data_builder·health_check_path·reorder_var_name)를 넘기는지 확인한다. 실제 번들
생성(Docker 빌드·자가검증)은 하지 않고 generate_bundle 을 스텁으로 가로채 인자만 본다.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from ulsaner_platform.sources import _SLOTS, engine_source

# --- 레지스트리 커버리지: 6개 취약 클래스 × 2개 템플릿이 전부 등록됐나 --------
EXPECTED_KEYS = {
    ("idor", "easy", "notes"),
    ("idor", "hard", "notes"),
    ("sqli", "easy", "notes"),
    ("hard_sqli", "hard", "notes"),
    ("xss", "easy", "notes"),
    ("idor", "easy", "tickets"),
    ("idor", "hard", "tickets"),
    ("sqli", "easy", "tickets"),
}


def test_registry_covers_all_expected_challenge_combos():
    assert EXPECTED_KEYS <= set(_SLOTS)


def test_tickets_specs_carry_tickets_overrides():
    for key in [
        ("idor", "easy", "tickets"),
        ("idor", "hard", "tickets"),
        ("sqli", "easy", "tickets"),
    ]:
        spec = _SLOTS[key]
        assert spec.template == "tickets"
        assert spec.health_check_path == "/tickets/2"
        assert spec.reorder_var_name == "ticket"
        assert spec.module_path == "engine.slots.tickets"


def test_notes_specs_keep_notes_defaults():
    for key in [
        ("idor", "easy", "notes"),
        ("hard_sqli", "hard", "notes"),
        ("xss", "easy", "notes"),
    ]:
        spec = _SLOTS[key]
        assert spec.template == "notes"
        assert spec.health_check_path == "/notes/2"
        assert spec.reorder_var_name == "note"


# --- engine_source 디스패치 ---------------------------------------------------
def test_engine_source_backward_compatible_two_positional_args():
    # 기존 호출부(app.py·platform 테스트)는 template 없이 2-인자로 부른다.
    assert callable(engine_source("idor", "easy"))
    assert callable(engine_source("sqli", "easy"))


def test_engine_source_accepts_new_notes_combos():
    assert callable(engine_source("hard_sqli", "hard"))
    assert callable(engine_source("xss", "easy"))


def test_engine_source_accepts_tickets_template():
    assert callable(engine_source("idor", "easy", template="tickets"))
    assert callable(engine_source("sqli", "easy", template="tickets"))


def test_engine_source_rejects_unknown_combo():
    with pytest.raises(KeyError):
        engine_source("xss", "hard")  # 없는 조합
    with pytest.raises(KeyError):
        engine_source("idor", "easy", template="nope")


# --- provision() 이 generate_bundle 에 넘기는 인자 검증(스텁으로 가로채기) -----
def _install_stub(monkeypatch):
    """engine.bundle.generate_bundle 을 스텁으로 바꿔 호출 인자를 기록한다.

    provision() 은 `from engine.bundle import generate_bundle` 를 호출 시점에 하므로,
    모듈 속성을 갈아끼우면 스텁이 잡힌다. 실제 Docker 빌드/자가검증은 일어나지 않는다.
    """
    import engine.bundle as eb

    captured: dict = {}

    def stub(**kwargs):
        captured.update(kwargs)
        return kwargs["output_dir"]

    monkeypatch.setattr(eb, "generate_bundle", stub)
    return captured, eb


def test_notes_provision_passes_notes_defaults(monkeypatch):
    captured, _ = _install_stub(monkeypatch)
    _bundle_dir, cleanup = engine_source("xss", "easy")()
    try:
        # notes 계열은 template_dir/exploit_builders/seed_data_builder 를 넘기지 않는다
        # (엔진 기본값 사용). health/reorder 만 명시.
        assert "template_dir" not in captured
        assert "exploit_builders" not in captured
        assert "seed_data_builder" not in captured
        assert captured["health_check_path"] == "/notes/2"
        assert captured["reorder_var_name"] == "note"
        assert callable(captured["slot_builder"])
    finally:
        cleanup()


def test_tickets_provision_passes_tickets_overrides(monkeypatch):
    captured, eb = _install_stub(monkeypatch)
    from engine import tickets_params

    _bundle_dir, cleanup = engine_source("idor", "easy", template="tickets")()
    try:
        assert captured["template_dir"] == eb.TICKETS_TEMPLATE_DIR
        assert captured["exploit_builders"] is eb.TICKETS_EXPLOIT_BUILDERS
        assert captured["seed_data_builder"] is tickets_params.build_seed_data
        assert captured["health_check_path"] == "/tickets/2"
        assert captured["reorder_var_name"] == "ticket"
    finally:
        cleanup()


def test_provision_cleans_up_tempdir_on_generate_failure(monkeypatch):
    import engine.bundle as eb

    holder: dict = {}

    def boom(**kwargs):
        holder["tmp"] = kwargs["output_dir"]
        raise RuntimeError("generate 실패 시뮬레이션")

    monkeypatch.setattr(eb, "generate_bundle", boom)
    with pytest.raises(RuntimeError):
        engine_source("xss", "easy")()
    # 생성 실패 시 임시 디렉토리는 즉시 정리돼야 한다.
    assert not Path(holder["tmp"]).exists()


# --- 카탈로그(app.py)가 실제로 새 카드를 노출하나 -----------------------------
def test_default_challenges_expose_new_classes():
    from ulsaner_platform.app import DEFAULT_CHALLENGES

    names = {c.name for c in DEFAULT_CHALLENGES}
    assert {"hard-sqli-live", "jwt-forge-live"} <= names


def test_tickets_idor_sqli_wired_but_not_carded():
    # tickets 의 idor/sqli 는 엔진 슬롯·배선은 유지하되(범용성 증명·벤치마크용) 플레이어
    # 카드로는 내보내지 않는다 — notes 와 메커니즘이 같아 중복이라. xss 와 동일한 패턴.
    from ulsaner_platform.app import DEFAULT_CHALLENGES

    assert ("idor", "easy", "tickets") in _SLOTS  # 엔진/벤치마크 배선 유지
    assert ("sqli", "easy", "tickets") in _SLOTS
    names = {c.name for c in DEFAULT_CHALLENGES}
    assert "tickets-idor-live" not in names
    assert "tickets-sqli-live" not in names
    # tickets 는 이제 어떤 카드도 노출하지 않는다(범용성/벤치마크 배선만 유지)
    assert not any(c.name.startswith("tickets-") for c in DEFAULT_CHALLENGES)


def test_xss_wired_but_not_exposed_as_interactive_card():
    # XSS 는 벤치마크용으로 배선만 남기고 인터랙티브 카드로는 내보내지 않는다
    # (반사형이라 flag 제출 모델과 안 맞음 — app.py 주석 참고). 배선은 살아 있어야 한다.
    from ulsaner_platform.app import DEFAULT_CHALLENGES

    assert ("xss", "easy", "notes") in _SLOTS  # 엔진/벤치마크 경로용 배선 유지
    names = {c.name for c in DEFAULT_CHALLENGES}
    assert "easy-xss-live" not in names  # 인터랙티브 카드로는 미노출
    assert not any(c.vuln_type == "xss" for c in DEFAULT_CHALLENGES)
