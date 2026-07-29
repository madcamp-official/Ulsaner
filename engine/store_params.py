import random


def build_seed_data(rng: random.Random) -> tuple[dict, str]:
    """store 챌린지 seed — 잔액 100 의 사용자 + 프리미엄 상품(리워드=flag).

    프리미엄 상품(items[1])은 9999P 라 잔액 100 으로는 정상 구매 불가. 수량 양수 검증이
    빠지면(로직 결함) 음수 수량으로 총액을 음수로 만들어 잔액 검사를 우회 → 리워드(flag) 획득.
    build_store_logic_exploit 은 secret 이 있는 상품(=프리미엄)을 표적으로 삼는다.
    """
    flag = f"FLAG{{{rng.getrandbits(64):016x}}}"
    token = f"token-{rng.getrandbits(32):08x}"
    seed_data = {
        "users": [
            {"id": 1, "token": token, "name": "shopper", "balance": 100},
        ],
        "items": [
            {"id": 1, "name": "스티커 팩", "price": 10, "secret": ""},
            {"id": 2, "name": "한정판 골드 배지", "price": 9999, "secret": flag},
        ],
    }
    return seed_data, flag
