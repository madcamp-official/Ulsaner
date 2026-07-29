"""SSRF 2-hop 피벗 — 슬롯·다단계 익스플로잇 단위 테스트 (Docker 불필요).

fetch 의 내부 URL 차단이 빠지면(SSRF) 서버를 통해 내부로 피벗. 1차: /internal/services 에서
vault_token 추출 → 2차: /internal/vault 로 flag. 다단계 엔진의 값 추출·치환을 쓰는 체인.
"""

import libcst as cst

from engine.bundle import GATEWAY_EXPLOIT_BUILDERS
from engine.exploit_gen import build_ssrf_pivot_exploit
from engine.slots.ssrf import build_ssrf_slot

_CLEAN_FETCH = '''\
from fastapi import HTTPException


def _is_internal(url):
    return "localhost" in url


def fetch(req):
    if _is_internal(req.url):
        raise HTTPException(400, "internal URLs are not allowed")
    return _do_fetch(req.url)
'''


def test_slot_removes_internal_guard():
    out = build_ssrf_slot().transform(cst.parse_module(_CLEAN_FETCH)).code
    assert "_is_internal(req.url)" not in out.split("def fetch")[1]  # 차단 제거됨
    assert "_do_fetch" in out                                        # 본문(요청)은 유지
    assert "def _is_internal" in out                                 # 헬퍼 정의 자체는 남음


def test_slot_metadata():
    slot = build_ssrf_slot()
    assert slot.vuln_type == "ssrf"
    assert slot.tier == "hard"
    assert slot.target_file == "routes/gateway.py"
    assert slot.target_function == "fetch"


def test_exploit_is_2hop_chain_with_token_extraction():
    exploit = build_ssrf_pivot_exploit({}, "FLAG{x}")
    assert exploit.steps is not None and len(exploit.steps) == 2
    # 1차: 내부 서비스 디렉터리 fetch → vault_token 추출
    hop1 = exploit.steps[0]
    assert hop1.path == "/fetch"
    assert "internal/services" in hop1.body["url"]
    assert hop1.extract and "vtok" in hop1.extract
    # 2차: 추출한 토큰으로 vault fetch
    hop2 = exploit.steps[1]
    assert "internal/vault" in hop2.body["url"]
    assert "{vtok}" in hop2.body["url"]
    assert exploit.expected_flag == "FLAG{x}"


def test_ssrf_registered_in_gateway_exploit_builders():
    assert GATEWAY_EXPLOIT_BUILDERS["ssrf"] is build_ssrf_pivot_exploit
