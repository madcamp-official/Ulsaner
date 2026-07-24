import shutil
import pathlib
from typing import Callable
import libcst as cst
from .slots.base import Slot


def apply_extra_transform(app_dir: pathlib.Path, target_file: str, transform: Callable[[cst.Module], cst.Module]) -> None:
    target_path = app_dir / target_file
    module = cst.parse_module(target_path.read_text())
    transformed = transform(module)
    target_path.write_text(transformed.code)


def inject(template_dir: pathlib.Path, output_dir: pathlib.Path, slot: Slot) -> None:
    shutil.copytree(template_dir, output_dir, dirs_exist_ok=True)
    apply_extra_transform(output_dir, slot.target_file, slot.transform)
