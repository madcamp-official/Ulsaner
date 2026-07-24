import libcst as cst
from .base import Slot, is_ownership_check


class _RemoveOwnershipCheck(cst.CSTTransformer):
    def __init__(self, function_name: str):
        self.function_name = function_name

    def leave_FunctionDef(self, original_node, updated_node):
        if original_node.name.value != self.function_name:
            return updated_node
        new_body = [stmt for stmt in updated_node.body.body if not is_ownership_check(stmt)]
        return updated_node.with_changes(body=updated_node.body.with_changes(body=new_body))


def build_easy_idor_slot() -> Slot:
    def transform(module: cst.Module) -> cst.Module:
        return module.visit(_RemoveOwnershipCheck("get_note"))

    return Slot(
        vuln_type="idor",
        tier="easy",
        target_file="routes/notes.py",
        target_function="get_note",
        transform=transform,
    )
