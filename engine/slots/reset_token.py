import libcst as cst

from .base import Slot


class _PredictableResetToken(cst.CSTTransformer):
    """_make_reset_token 의 본문을 '예측 가능한' 토큰 생성으로 바꾼다.

    clean: secrets.token_hex(16) (강한 랜덤). vuln: md5(username + _SALT) — 사용자명과 (메일로
    새어나온) salt 만 알면 누구의 재설정 토큰이든 계산할 수 있다 → 관리자 계정 탈취. hashlib·
    _SALT 는 db.py 에 이미 존재하므로 참조만 하면 된다."""

    def __init__(self, function_name: str):
        self.function_name = function_name

    def leave_FunctionDef(self, original_node, updated_node):
        if original_node.name.value != self.function_name:
            return updated_node
        new_return = cst.parse_statement(
            "return hashlib.md5((username + _SALT).encode()).hexdigest()"
        )
        return updated_node.with_changes(body=cst.IndentedBlock(body=[new_return]))


def build_reset_token_slot() -> Slot:
    return Slot(
        vuln_type="takeover",
        tier="hard",
        target_file="db.py",
        target_function="_make_reset_token",
        transform=lambda module: module.visit(_PredictableResetToken("_make_reset_token")),
    )
