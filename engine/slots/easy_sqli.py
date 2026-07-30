import libcst as cst
from .base import Slot


def _is_notes_db_execute(node: cst.Call) -> bool:
    func = node.func
    return (
        isinstance(func, cst.Attribute)
        and func.attr.value == "execute"
        and isinstance(func.value, cst.Name)
        and func.value.value == "_NOTES_DB"
    )


class _ConcatenateSearchQuery(cst.CSTTransformer):
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

    def leave_Call(self, original_node, updated_node):
        if not self._inside_target or not _is_notes_db_execute(original_node):
            return updated_node
        vulnerable_query = cst.FormattedString(
            parts=[
                cst.FormattedStringText(
                    value="SELECT id, title FROM notes WHERE is_private = 0 AND title LIKE '%"
                ),
                cst.FormattedStringExpression(expression=cst.Name("q")),
                cst.FormattedStringText(value="%'"),
            ],
            start='f"',
            end='"',
        )
        return updated_node.with_changes(args=[cst.Arg(value=vulnerable_query)])


def build_easy_sqli_slot() -> Slot:
    def transform(module: cst.Module) -> cst.Module:
        return module.visit(_ConcatenateSearchQuery("search_notes_by_title"))

    return Slot(
        vuln_type="sqli",
        tier="easy",
        target_file="db.py",
        target_function="search_notes_by_title",
        transform=transform,
    )
