import json
import pathlib

_SEED_PATH = pathlib.Path(__file__).parent / "seed_data.json"


def _load_seed() -> dict:
    with open(_SEED_PATH) as f:
        return json.load(f)


_SEED = _load_seed()
INTERNAL_TOKEN = _SEED["internal_token"]  # /fetch 가 내부 요청에 붙이는 신뢰 헤더값(서버 전용)
VAULT_TOKEN = _SEED["vault_token"]        # vault 접근에 추가로 필요한 토큰(/internal/services 가 흘림)
FLAG = _SEED["flag"]
