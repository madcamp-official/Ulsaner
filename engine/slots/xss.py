import libcst as cst
from .base import Slot


class _RemoveSearchTermEscape(cst.CSTTransformer):
    """Inside the target function, rewrite `safe_q = html_lib.escape(q)` to the
    bare `safe_q = q`, making the reflected search term an unescaped sink. The
    results-list escaping (html_lib.escape(row[1])) is deliberately left intact
    so exactly one minimal reflected sink is introduced."""

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

    def leave_Assign(self, original_node, updated_node):
        if not self._inside_target:
            return updated_node
        targets = updated_node.targets
        if (
            len(targets) == 1
            and isinstance(targets[0].target, cst.Name)
            and targets[0].target.value == "safe_q"
        ):
            return updated_node.with_changes(value=cst.Name("q"))
        return updated_node


def build_xss_slot() -> Slot:
    def transform(module: cst.Module) -> cst.Module:
        return module.visit(_RemoveSearchTermEscape("search_notes_view"))

    return Slot(
        vuln_type="xss",
        tier="easy",
        target_file="routes/search.py",
        target_function="search_notes_view",
        transform=transform,
    )
