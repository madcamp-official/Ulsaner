import random


def build_seed_data(rng: random.Random) -> tuple[dict, str]:
    """accounts 계정탈취 체인 seed.

    - reset_salt: 재설정 토큰 생성에 쓰이는 랜덤 salt(취약 버전에서 md5(username+salt)). 인스턴스
      마다 랜덤이라 미리 계산 불가 — 학생은 자기 계정 재설정 메일에서 salt 를 관찰해 알아낸다.
    - guest: 학생 계정(비밀번호 공개). admin: 비밀번호 랜덤(모름) → 재설정으로 탈취해야 함.
    - flag 는 관리자 전용 /admin/flag 가 반환.
    """
    flag = f"FLAG{{{rng.getrandbits(64):016x}}}"
    salt = f"{rng.getrandbits(64):016x}"
    admin_pw = f"pw-{rng.getrandbits(48):012x}"
    seed_data = {
        "reset_salt": salt,
        "flag": flag,
        "users": [
            {"username": "guest", "password": "guest", "role": "user"},
            {"username": "admin", "password": admin_pw, "role": "admin"},
        ],
    }
    return seed_data, flag
