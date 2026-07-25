import pathlib
import pytest
from engine.platform_adapter import add_platform_dockerfile


def test_add_platform_dockerfile_writes_root_dockerfile_copying_from_app(tmp_path):
    add_platform_dockerfile(tmp_path)
    code = (tmp_path / "Dockerfile").read_text()
    assert "COPY app/requirements.txt" in code
    assert "COPY app/ ." in code
    assert 'CMD ["python", "main.py"]' in code


@pytest.mark.integration
def test_live_bundle_is_deployable_by_orchestrator_runner(tmp_path):
    from engine.live_bundle import generate_live_bundle
    from engine.slots.easy_idor import build_easy_idor_slot
    from orchestrator.runner import deploy_bundle, stop_container

    bundle_dir = generate_live_bundle(build_easy_idor_slot, tmp_path)
    assert (bundle_dir / "Dockerfile").exists()
    assert (bundle_dir / "manifest.json").exists()

    instance = deploy_bundle(bundle_dir, tag="ulsaner-live-test", container_port=8000)
    try:
        import time
        import requests

        deadline = time.time() + 10
        last_error = None
        resp = None
        while time.time() < deadline:
            try:
                resp = requests.get(f"{instance.url}/notes/2", timeout=1)
                break
            except requests.RequestException as e:
                last_error = e
                time.sleep(0.5)
        assert resp is not None, f"container never became healthy: {last_error}"
        assert resp.status_code in (200, 401, 422)
    finally:
        stop_container(instance.container_id)
