import random
import pathlib
import shutil
from typing import Callable
from . import params, injector, exploit_gen, verifier
from . import manifest as manifest_mod
from .slots.base import Slot

TEMPLATE_DIR = pathlib.Path(__file__).parent.parent / "templates" / "notes_app"
SCHEMA_PATH = pathlib.Path(__file__).parent.parent / "contract" / "manifest_schema.json"


class BundleGenerationError(Exception):
    pass


def generate_bundle(
    seed: int,
    output_dir: pathlib.Path,
    slot_builder: Callable[[], Slot],
    task_prompt: str,
    solution_summary: str,
    max_attempts: int = 3,
) -> pathlib.Path:
    for attempt in range(max_attempts):
        rng = random.Random(seed + attempt)
        seed_data, flag = params.build_seed_data(rng)
        slot = slot_builder()

        app_dir = output_dir / "app"
        if app_dir.exists():
            shutil.rmtree(app_dir)
        injector.inject(TEMPLATE_DIR, app_dir, slot)
        params.write_seed_data(app_dir, seed_data)

        exploit = exploit_gen.build_idor_exploit(seed_data, flag)
        tag = f"ulsaner-bundle-{seed}-{attempt}"

        if verifier.verify_bundle(app_dir, exploit, tag):
            m = manifest_mod.build_manifest(
                vuln_type=slot.vuln_type,
                tier=slot.tier,
                flag=flag,
                task_prompt=task_prompt,
                reference_exploit_path="exploits/reference.json",
                solution_summary=solution_summary,
            )
            manifest_mod.write_manifest(output_dir, m, SCHEMA_PATH)
            return output_dir

    raise BundleGenerationError(f"failed to generate a verifiable bundle after {max_attempts} attempts (seed={seed})")
