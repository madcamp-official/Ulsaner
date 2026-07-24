import subprocess
import socket
import time
import contextlib
import pathlib
import requests
from .exploit_gen import ReferenceExploit


class VerificationError(Exception):
    pass


def _free_port() -> int:
    with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(("", 0))
        return s.getsockname()[1]


def _build_image(bundle_dir: pathlib.Path, tag: str) -> None:
    subprocess.run(["docker", "build", "-t", tag, str(bundle_dir)], check=True, capture_output=True, text=True)


def _run_container(tag: str, port: int) -> str:
    result = subprocess.run(["docker", "run", "-d", "-p", f"{port}:8000", tag], check=True, capture_output=True, text=True)
    return result.stdout.strip()


def _stop_container(container_id: str) -> None:
    subprocess.run(["docker", "rm", "-f", container_id], check=True, capture_output=True)


def _wait_for_health(port: int, timeout: float = 10.0) -> None:
    deadline = time.time() + timeout
    last_error = None
    while time.time() < deadline:
        try:
            requests.get(f"http://localhost:{port}/notes/2", timeout=1)
            return
        except requests.RequestException as e:
            last_error = e
            time.sleep(0.5)
    raise VerificationError(f"container never became healthy: {last_error}")


def _run_exploit(port: int, exploit: ReferenceExploit) -> bool:
    response = requests.request(
        exploit.method,
        f"http://localhost:{port}{exploit.path}",
        headers=exploit.headers,
        timeout=5,
    )
    return exploit.expected_flag in response.text


def verify_bundle(app_dir: pathlib.Path, exploit: ReferenceExploit, tag: str) -> bool:
    port = _free_port()
    _build_image(app_dir, tag)
    container_id = _run_container(tag, port)
    try:
        _wait_for_health(port)
        return _run_exploit(port, exploit)
    finally:
        _stop_container(container_id)
