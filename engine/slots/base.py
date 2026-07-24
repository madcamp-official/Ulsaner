from dataclasses import dataclass
from typing import Callable
import libcst as cst


@dataclass(frozen=True)
class Slot:
    vuln_type: str
    tier: str
    target_file: str
    target_function: str
    transform: Callable[[cst.Module], cst.Module]


def is_ownership_check(stmt: cst.BaseStatement) -> bool:
    if not isinstance(stmt, cst.If):
        return False
    test = stmt.test
    return (
        isinstance(test, cst.Comparison)
        and isinstance(test.left, cst.Attribute)
        and test.left.attr.value == "owner_id"
    )
