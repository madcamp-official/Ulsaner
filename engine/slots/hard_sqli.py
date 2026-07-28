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


class _InjectExcludeInterpolation(cst.CSTTransformer):
    """Inside the target function, turn a genuinely-safe 2-parameter query into a
    prepared-statement disguise: the `query` string literal is rewritten into an
    f-string that raw-interpolates `exclude` (dropping its ? placeholder) while
    keeping the ? placeholder for `q`, and the `.execute(query, (..., exclude))`
    call's params tuple is rewritten to drop `exclude`. Net effect: a 2-arg
    `.execute` call with a params tuple (looks parameterized) whose `exclude`
    value is actually string-interpolated (injectable)."""

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
        if not (
            len(targets) == 1
            and isinstance(targets[0].target, cst.Name)
            and targets[0].target.value == "query"
        ):
            return updated_node
        vulnerable_query = cst.FormattedString(
            parts=[
                cst.FormattedStringText(
                    value="SELECT id, title FROM notes WHERE is_private = 0 "
                    "AND title LIKE ? AND title != '"
                ),
                cst.FormattedStringExpression(expression=cst.Name("exclude")),
                cst.FormattedStringText(value="'"),
            ],
            start='f"',
            end='"',
        )
        return updated_node.with_changes(value=vulnerable_query)

    def leave_Call(self, original_node, updated_node):
        if not self._inside_target or not _is_notes_db_execute(original_node):
            return updated_node
        new_params = cst.Tuple(
            elements=[
                cst.Element(
                    value=cst.FormattedString(
                        parts=[
                            cst.FormattedStringText(value="%"),
                            cst.FormattedStringExpression(expression=cst.Name("q")),
                            cst.FormattedStringText(value="%"),
                        ],
                        start='f"',
                        end='"',
                    ),
                    comma=cst.Comma(),
                )
            ],
        )
        new_args = [
            updated_node.args[0],
            updated_node.args[1].with_changes(value=new_params),
        ]
        return updated_node.with_changes(args=new_args)


def build_hard_sqli_slot() -> Slot:
    def transform(module: cst.Module) -> cst.Module:
        return module.visit(_InjectExcludeInterpolation("search_notes_advanced"))

    return Slot(
        vuln_type="hard_sqli",
        tier="hard",
        target_file="db.py",
        target_function="search_notes_advanced",
        transform=transform,
    )
