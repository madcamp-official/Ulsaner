import libcst as cst

from .base import Slot


class _RemoveQuantityGuard(cst.CSTTransformer):
    """대상 함수 안에서 `if <x>.quantity < 1: raise ...` 수량 검증을 제거한다.

    수량 양수 검증이 사라지면, 음수 수량으로 총액(가격×수량)을 음수로 만들어 잔액 검사를
    통과할 수 있다 → 잔액으로는 못 사는 프리미엄 상품을 '구매' → 리워드(flag) 획득.
    비즈니스 로직 결함(BOLA/인젝션 아님 — 앱 규칙 자체의 허점)."""

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
        is_quantity_guard = (
            isinstance(test, cst.Comparison)
            and isinstance(test.left, cst.Attribute)
            and test.left.attr.value == "quantity"
        )
        if is_quantity_guard:
            return cst.RemovalSentinel.REMOVE
        return updated_node


def build_store_logic_slot() -> Slot:
    return Slot(
        vuln_type="logic",
        tier="easy",
        target_file="routes/store.py",
        target_function="purchase",
        transform=lambda module: module.visit(_RemoveQuantityGuard("purchase")),
    )
