import json
import random
import pathlib
import shutil
import dataclasses
from typing import Callable
from . import params, injector, exploit_gen, verifier, reorder
from . import manifest as manifest_mod
from .slots.base import Slot

TEMPLATE_DIR = pathlib.Path(__file__).parent.parent / "templates" / "notes_app"
TICKETS_TEMPLATE_DIR = pathlib.Path(__file__).parent.parent / "templates" / "tickets_app"
SCHEMA_PATH = pathlib.Path(__file__).parent.parent / "contract" / "manifest_schema.json"

_EXPLOIT_BUILDERS: dict[str, Callable[[dict, str], exploit_gen.ReferenceExploit]] = {
    "idor": exploit_gen.build_idor_exploit,
    "sqli": exploit_gen.build_sqli_exploit,
    "hard_sqli": exploit_gen.build_hard_sqli_exploit,
    "xss": exploit_gen.build_xss_exploit,
}

TICKETS_EXPLOIT_BUILDERS: dict[str, Callable[[dict, str], exploit_gen.ReferenceExploit]] = {
    "idor": exploit_gen.build_tickets_idor_exploit,
    "sqli": exploit_gen.build_tickets_sqli_exploit,
}


class BundleGenerationError(Exception):
    pass


def _resolve_task_prompt(task_prompt: str, seed_data: dict) -> str:
    """task_prompt 의 ``{alice_token}`` placeholder 를 seed 의 alice(=id 1) 토큰으로 치환한다.

    인증형(idor) 챌린지는 인스턴스마다 토큰이 랜덤이라, 학생이 자기 자격증명을 얻을 통로가
    필요하다. fixture 가 프롬프트로 'alice-token' 을 알려주는 것과 동일하게, 여기서 랜덤 토큰을
    프롬프트에 채워 넣는다. 토큰은 alice 자신의 자격증명이므로 공개해도 flag(=bob 의 비공개
    본문)는 새지 않는다. placeholder 가 없으면(인증 불필요한 sqli 등) 원문 그대로 반환한다.
    """
    if "{alice_token}" not in task_prompt:
        return task_prompt
    users = seed_data.get("users") or []
    alice = next((u for u in users if u.get("id") == 1), users[0] if users else {})
    return task_prompt.replace("{alice_token}", alice.get("token", ""))


def generate_bundle(
    seed: int,
    output_dir: pathlib.Path,
    slot_builder: Callable[[], Slot],
    task_prompt: str,
    solution_summary: str,
    max_attempts: int = 3,
    template_dir: pathlib.Path = TEMPLATE_DIR,
    seed_data_builder: Callable[[random.Random], tuple[dict, str]] = params.build_seed_data,
    exploit_builders: dict[str, Callable[[dict, str], exploit_gen.ReferenceExploit]] | None = None,
    reorder_var_name: str = "note",
    health_check_path: str = "/notes/2",
) -> pathlib.Path:
    if exploit_builders is None:
        exploit_builders = _EXPLOIT_BUILDERS
    for attempt in range(max_attempts):
        rng = random.Random(seed + attempt)
        seed_data, flag = seed_data_builder(rng)
        slot = slot_builder()

        app_dir = output_dir / "app"
        if app_dir.exists():
            shutil.rmtree(app_dir)
        injector.inject(template_dir, app_dir, slot)
        if slot.tier == "hard":
            new_var_name = f"n{rng.getrandbits(16):04x}"
            # Note: hard_sqli's reorder is a no-op—search_notes_advanced has no local var "note".
            # hard_sqli difficulty comes from prepared-statement-disguise, not rename obfuscation.
            injector.apply_extra_transform(
                app_dir,
                slot.target_file,
                lambda module: reorder.rename_local_variable(
                    module, slot.target_function, reorder_var_name, new_var_name
                ),
            )
        params.write_seed_data(app_dir, seed_data)

        build_exploit = exploit_builders[slot.vuln_type]
        exploit = build_exploit(seed_data, flag)
        tag = f"ulsaner-bundle-{seed}-{attempt}"

        if verifier.verify_bundle(app_dir, exploit, tag, health_check_path):
            exploits_dir = output_dir / "exploits"
            exploits_dir.mkdir(parents=True, exist_ok=True)
            exploit_json_path = exploits_dir / "reference.json"
            exploit_dict = dataclasses.asdict(exploit)
            with open(exploit_json_path, "w") as f:
                json.dump(exploit_dict, f, indent=2)

            m = manifest_mod.build_manifest(
                vuln_type=slot.vuln_type,
                tier=slot.tier,
                flag=flag,
                task_prompt=_resolve_task_prompt(task_prompt, seed_data),
                reference_exploit_path="exploits/reference.json",
                solution_summary=solution_summary,
            )
            manifest_mod.write_manifest(output_dir, m, SCHEMA_PATH)
            return output_dir

    raise BundleGenerationError(f"failed to generate a verifiable bundle after {max_attempts} attempts (seed={seed})")
