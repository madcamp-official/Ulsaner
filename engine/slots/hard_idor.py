import libcst as cst
from .base import Slot, is_ownership_check


class _SwapToWorkspaceScopeCheck(cst.CSTTransformer):
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
        if not self._inside_target or not is_ownership_check(original_node):
            return updated_node
        new_test = _rebuild_as_workspace_check(original_node.test)
        return updated_node.with_changes(test=new_test)


def _rebuild_as_workspace_check(test: cst.Comparison) -> cst.Comparison:
    new_left = test.left.with_changes(attr=cst.Name("workspace_id"))
    new_comparisons = [
        target.with_changes(comparator=target.comparator.with_changes(attr=cst.Name("workspace_id")))
        for target in test.comparisons
    ]
    return test.with_changes(left=new_left, comparisons=new_comparisons)


def build_hard_idor_slot() -> Slot:
    def transform(module: cst.Module) -> cst.Module:
        return module.visit(_SwapToWorkspaceScopeCheck("get_note"))

    return Slot(
        vuln_type="idor",
        tier="hard",
        target_file="routes/notes.py",
        target_function="get_note",
        transform=transform,
    )
