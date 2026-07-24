import libcst as cst


class _RenameLocalVariable(cst.CSTTransformer):
    def __init__(self, function_name: str, old_name: str, new_name: str):
        self.function_name = function_name
        self.old_name = old_name
        self.new_name = new_name
        self._inside_target = False

    def visit_FunctionDef(self, node: cst.FunctionDef) -> bool:
        if node.name.value == self.function_name:
            self._inside_target = True
        return True

    def leave_FunctionDef(self, original_node, updated_node):
        if original_node.name.value == self.function_name:
            self._inside_target = False
        return updated_node

    def leave_Name(self, original_node, updated_node):
        if self._inside_target and original_node.value == self.old_name:
            return updated_node.with_changes(value=self.new_name)
        return updated_node


def rename_local_variable(module: cst.Module, function_name: str, old_name: str, new_name: str) -> cst.Module:
    return module.visit(_RenameLocalVariable(function_name, old_name, new_name))
