import pytest
from engine.bundle import generate_bundle, BundleGenerationError
from engine.slots.easy_idor import build_easy_idor_slot


@pytest.mark.integration
def test_generate_easy_idor_bundle_e2e(tmp_path):
    output_dir = tmp_path / "bundle-1"
    result = generate_bundle(
        seed=1,
        output_dir=output_dir,
        slot_builder=build_easy_idor_slot,
        task_prompt="다른 사용자의 비공개 노트를 읽어 flag를 찾아라",
        solution_summary="get_note의 소유권 체크 누락을 이용해 다른 유저의 노트를 조회",
    )
    assert (result / "manifest.json").exists()
    assert (result / "app" / "seed_data.json").exists()
    assert (result / "app" / "Dockerfile").exists()


@pytest.mark.integration
def test_generate_bundle_raises_after_max_attempts_when_verification_always_fails(tmp_path):
    from engine.slots.base import Slot

    def broken_slot_builder():
        return Slot(
            vuln_type="idor",
            tier="easy",
            target_file="routes/notes.py",
            target_function="get_note",
            transform=lambda module: module,  # no-op: check stays in place, exploit will fail
        )

    with pytest.raises(BundleGenerationError):
        generate_bundle(
            seed=2,
            output_dir=tmp_path / "bundle-2",
            slot_builder=broken_slot_builder,
            task_prompt="prompt",
            solution_summary="summary",
            max_attempts=2,
        )
