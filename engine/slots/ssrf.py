import libcst as cst

from .base import Slot


class _RemoveInternalGuard(cst.CSTTransformer):
    """fetch 안에서 `if _is_internal(...): raise ...` 내부 URL 차단을 제거한다.

    차단이 사라지면 서버가 임의 URL(내부/loopback 포함)을 대신 요청한다(SSRF) → 외부에서
    못 가는 내부 서비스에 서버를 통해 피벗할 수 있다."""

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
        is_internal_guard = (
            isinstance(test, cst.Call)
            and isinstance(test.func, cst.Name)
            and test.func.value == "_is_internal"
        )
        if is_internal_guard:
            return cst.RemovalSentinel.REMOVE
        return updated_node


def build_ssrf_slot() -> Slot:
    return Slot(
        vuln_type="ssrf",
        tier="hard",
        target_file="routes/gateway.py",
        target_function="fetch",
        transform=lambda module: module.visit(_RemoveInternalGuard("fetch")),
    )
