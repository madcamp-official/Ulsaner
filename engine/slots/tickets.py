import libcst as cst
from .base import Slot
from .easy_idor import _RemoveOwnershipCheck
from .hard_idor import _SwapToWorkspaceScopeCheck


def _is_tickets_db_execute(node: cst.Call) -> bool:
    func = node.func
    return (
        isinstance(func, cst.Attribute)
        and func.attr.value == "execute"
        and isinstance(func.value, cst.Name)
        and func.value.value == "_TICKETS_DB"
    )


class _ConcatenateTicketsSearchQuery(cst.CSTTransformer):
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
        if not self._inside_target or not _is_tickets_db_execute(original_node):
            return updated_node
        vulnerable_query = cst.FormattedString(
            parts=[
                cst.FormattedStringText(
                    value="SELECT id, subject FROM tickets WHERE is_confidential = 0 AND subject LIKE '%"
                ),
                cst.FormattedStringExpression(expression=cst.Name("q")),
                cst.FormattedStringText(value="%'"),
            ],
            start='f"',
            end='"',
        )
        return updated_node.with_changes(args=[cst.Arg(value=vulnerable_query)])


def build_tickets_easy_idor_slot() -> Slot:
    return Slot(
        vuln_type="idor",
        tier="easy",
        target_file="routes/tickets.py",
        target_function="get_ticket",
        transform=lambda module: module.visit(_RemoveOwnershipCheck("get_ticket")),
    )


def build_tickets_hard_idor_slot() -> Slot:
    return Slot(
        vuln_type="idor",
        tier="hard",
        target_file="routes/tickets.py",
        target_function="get_ticket",
        transform=lambda module: module.visit(_SwapToWorkspaceScopeCheck("get_ticket")),
    )


def build_tickets_easy_sqli_slot() -> Slot:
    return Slot(
        vuln_type="sqli",
        tier="easy",
        target_file="db.py",
        target_function="search_tickets_by_subject",
        transform=lambda module: module.visit(_ConcatenateTicketsSearchQuery("search_tickets_by_subject")),
    )
