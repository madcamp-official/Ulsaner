import libcst as cst

from .base import Slot


class _RemoveSignatureCheck(cst.CSTTransformer):
    """verify_token 안에서 `if not hmac.compare_digest(...): raise ...` 서명 검증을 제거한다.

    서명 검증이 사라지면 서버는 어떤 서명값이든 받아들인다 → payload 를 원하는 대로 위조한
    토큰(role:"admin")이 통과 → 관리자 전용 리소스 접근(JWT 위조 · 서명 미검증)."""

    def __init__(self, function_name: str):
        self.function_name = function_name
        self._inside_target = False

    def visit_FunctionDef(self, node: cst.FunctionDef) -> bool:
        if node.name.value == self.function_name:
            self._inside_target = True
        return True

    def leave_FunctionDef(self, original_node, updated_node):
        if original_node.name.value == self.function_name:
            self._inside_target = False
        return updated_node

    def leave_If(self, original_node, updated_node):
        if not self._inside_target:
            return updated_node
        test = original_node.test
        # `not hmac.compare_digest(...)` 형태의 서명 검증을 잡는다.
        is_sig_check = (
            isinstance(test, cst.UnaryOperation)
            and isinstance(test.operator, cst.Not)
            and isinstance(test.expression, cst.Call)
            and isinstance(test.expression.func, cst.Attribute)
            and test.expression.func.attr.value == "compare_digest"
        )
        if is_sig_check:
            return cst.RemovalSentinel.REMOVE
        return updated_node


def build_jwt_forge_slot() -> Slot:
    return Slot(
        vuln_type="jwt",
        tier="easy",
        target_file="db.py",
        target_function="verify_token",
        transform=lambda module: module.visit(_RemoveSignatureCheck("verify_token")),
    )
