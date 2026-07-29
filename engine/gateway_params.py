import random


def build_seed_data(rng: random.Random) -> tuple[dict, str]:
    """gateway SSRF 체인 seed.

    - internal_token: /fetch 가 내부 요청에 붙이는 신뢰 헤더(서버 전용, 외부 미노출).
    - vault_token: vault 접근에 필요한 토큰 — /internal/services 가 흘리므로 1차 피벗으로 얻는다.
    - flag: /internal/vault 가 반환(internal_token + vault_token 둘 다 필요).
    둘 다 인스턴스마다 랜덤이라 미리 알 수 없고, SSRF 로 서버를 통해 단계적으로 얻어야 한다.
    """
    flag = f"FLAG{{{rng.getrandbits(64):016x}}}"
    internal_token = f"int-{rng.getrandbits(64):016x}"
    vault_token = f"vtok-{rng.getrandbits(64):016x}"
    seed_data = {
        "internal_token": internal_token,
        "vault_token": vault_token,
        "flag": flag,
    }
    return seed_data, flag
