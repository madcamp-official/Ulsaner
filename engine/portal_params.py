import random


def build_seed_data(rng: random.Random) -> tuple[dict, str]:
    """portal 챌린지 seed — JWT 서명키(secret)·flag·일반 사용자(guest, role user).

    secret 은 추측 불가한 강한 랜덤값이라 정상적으론 유효한 admin 토큰을 만들 수 없다. 하지만
    서버가 서명을 검증하지 않으면(슬롯) 서명값과 무관하게 payload(role:"admin")를 위조해 통과
    시킬 수 있다. flag 는 관리자 전용 엔드포인트(/admin/flag)가 반환한다.
    """
    flag = f"FLAG{{{rng.getrandbits(64):016x}}}"
    secret = f"{rng.getrandbits(128):032x}"
    seed_data = {
        "secret": secret,
        "flag": flag,
        "users": [
            {"username": "guest", "role": "user"},
        ],
    }
    return seed_data, flag
