import subprocess
import socket
import time
import contextlib
import json
import pathlib
import re
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


def _wait_for_health(port: int, path: str = "/notes/2", timeout: float = 10.0) -> None:
    deadline = time.time() + timeout
    last_error = None
    while time.time() < deadline:
        try:
            requests.get(f"http://localhost:{port}{path}", timeout=1)
            return
        except requests.RequestException as e:
            last_error = e
            time.sleep(0.5)
    raise VerificationError(f"container never became healthy: {last_error}")


def _subst(text: str, ctx: dict) -> str:
    for name, value in ctx.items():
        text = text.replace("{" + name + "}", value)
    return text


def _run_chain(port: int, exploit: ReferenceExploit) -> bool:
    """다단계 체인: 각 스텝을 순차 실행하며 응답에서 값을 추출(extract)해 다음 스텝의
    path/headers/body 의 {var} 에 대입한다. 마지막 응답에 flag 가 있으면 성공."""
    ctx: dict[str, str] = {}
    last_text = ""
    for step in exploit.steps:
        path = _subst(step.path, ctx)
        headers = {k: _subst(v, ctx) for k, v in step.headers.items()}
        body = step.body
        if body is not None:
            body = json.loads(_subst(json.dumps(body), ctx))
        resp = requests.request(
            step.method, f"http://localhost:{port}{path}", headers=headers, json=body, timeout=5
        )
        last_text = resp.text
        for var, pattern in (step.extract or {}).items():
            m = re.search(pattern, resp.text)
            if m:
                ctx[var] = m.group(1)
    return exploit.expected_flag in last_text


def _run_exploit(port: int, exploit: ReferenceExploit) -> bool:
    if exploit.steps:
        return _run_chain(port, exploit)
    response = requests.request(
        exploit.method,
        f"http://localhost:{port}{exploit.path}",
        headers=exploit.headers,
        json=exploit.body,  # None 이면 바디 없음(기존 GET 동작 그대로)
        timeout=5,
    )
    return exploit.expected_flag in response.text


def verify_bundle(
    app_dir: pathlib.Path,
    exploit: ReferenceExploit,
    tag: str,
    health_check_path: str = "/notes/2",
) -> bool:
    port = _free_port()
    _build_image(app_dir, tag)
    container_id = _run_container(tag, port)
    try:
        _wait_for_health(port, health_check_path)
        return _run_exploit(port, exploit)
    finally:
        _stop_container(container_id)
