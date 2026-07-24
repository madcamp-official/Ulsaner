import subprocess
import pathlib
from dataclasses import dataclass
from typing import Callable
from .bundle import generate_bundle
from .slots.base import Slot


@dataclass(frozen=True)
class AuditResult:
    solved: bool
    raw_output: str


def run_external_auditor(bundle_app_dir: pathlib.Path, command: list[str]) -> AuditResult:
    result = subprocess.run(
        command,
        cwd=str(bundle_app_dir),
        capture_output=True,
        text=True,
        timeout=600,
    )
    return AuditResult(solved=result.returncode == 0, raw_output=result.stdout + result.stderr)


def run_benchmark(
    seeds: list[int],
    slot_builder: Callable[[], Slot],
    command_template: list[str],
    workdir: pathlib.Path,
    task_prompt: str,
    solution_summary: str,
) -> dict:
    results = []
    for seed in seeds:
        bundle_dir = workdir / f"bundle-{seed}"
        generate_bundle(
            seed=seed,
            output_dir=bundle_dir,
            slot_builder=slot_builder,
            task_prompt=task_prompt,
            solution_summary=solution_summary,
        )
        audit = run_external_auditor(bundle_dir / "app", command_template)
        results.append(audit.solved)
    success_rate = sum(results) / len(results) if results else 0.0
    return {"seeds": seeds, "results": results, "success_rate": success_rate}
