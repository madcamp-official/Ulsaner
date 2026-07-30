import socket
import subprocess
import time
import contextlib
import pathlib
import pytest
import requests

APP_DIR = pathlib.Path(__file__).parent.parent.parent / "templates" / "notes_app"


def _free_port() -> int:
    with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(("", 0))
        return s.getsockname()[1]


@pytest.mark.integration
def test_template_app_serves_notes_when_owner_requests():
    tag = "ulsaner-notes-app-smoke"
    port = _free_port()
    subprocess.run(["docker", "build", "-t", tag, str(APP_DIR)], check=True, capture_output=True, text=True)
    run = subprocess.run(["docker", "run", "-d", "-p", f"{port}:8000", tag], check=True, capture_output=True, text=True)
    container_id = run.stdout.strip()
    try:
        deadline = time.time() + 10
        last_error = None
        while time.time() < deadline:
            try:
                resp = requests.get(f"http://localhost:{port}/notes/1", headers={"Authorization": "Bearer token-alice"}, timeout=1)
                assert resp.status_code == 200
                assert "FLAG" in resp.text
                return
            except (requests.RequestException, AssertionError) as e:
                last_error = e
                time.sleep(0.5)
        raise AssertionError(f"container never became healthy: {last_error}")
    finally:
        subprocess.run(["docker", "rm", "-f", container_id], capture_output=True)
