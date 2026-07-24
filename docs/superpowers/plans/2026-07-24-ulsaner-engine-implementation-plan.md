# Ulsaner Engine (Part A) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the engine that generates a unique, self-verified, exploitable vulnerable app instance (easy/idor and hard/idor) from a seed, and a benchmark harness to measure VibeCutter's success rate against it.

**Architecture:** A clean multi-user FastAPI "notes" template app is copied per-instance and mutated via `libcst` AST transforms ("slots"). Each slot either removes an authorization check entirely (`easy/idor`) or swaps it to compare the wrong scope field (`hard/idor`). A parameterization step randomizes user tokens, IDs, and the flag. A self-verification step builds the mutated app into a Docker image, runs it, and replays a reference exploit to confirm the flag is reachable — only verified bundles are written to disk with a `manifest.json`. A benchmark harness runs an external auditor command (VibeCutter) against generated bundles and tallies success rate.

**Tech Stack:** Python 3.11, FastAPI + uvicorn (template app), libcst (AST transforms), jsonschema (contract validation), requests (exploit replay), pytest, Docker CLI (via subprocess), semgrep CLI (sanity tests).

## Global Constraints

- Python 3.11 for both the template app and the engine.
- No real auth/signup — per-instance header token (`X-User-Token`) mapped to seeded users (design spec section 3, YAGNI).
- Containers run as non-root (design spec section 11) — every generated Docker image must `USER appuser`.
- `manifest.json` must validate against `contract/manifest_schema.json` — this file is the shared contract with Part B (platform). Any change to it requires notifying the platform owner first (see `CLAUDE.md`).
- No persistence, no leaderboard code, no auth system — these are explicit non-goals (design spec section 3). Do not build them even as stubs.
- Tests that require Docker, semgrep, or an external auditor binary on `PATH` must be marked `@pytest.mark.integration` so fast unit tests can run without them.

---

## File Structure

```
contract/
  manifest_schema.json          # shared contract — JSON Schema for manifest.json

templates/notes_app/            # clean template app (Task 2)
  requirements.txt
  Dockerfile
  main.py
  app_factory.py
  db.py
  seed_data.json                # default/example seed, overwritten per-instance by the engine
  routes/
    __init__.py
    notes.py                    # get_note handler — the AST transform target

engine/
  requirements-dev.txt
  __init__.py
  slots/
    __init__.py
    base.py                     # Slot dataclass + shared is_ownership_check() helper
    easy_idor.py                # removes the ownership check entirely
    hard_idor.py                # swaps owner_id check to workspace_id (wrong scope)
  injector.py                   # copies template + applies a slot's/extra AST transform
  params.py                     # seed -> randomized users/notes/flag
  exploit_gen.py                # seed_data + flag -> ReferenceExploit
  verifier.py                   # docker build/run + replay exploit + teardown
  reorder.py                    # AST rename pass (hard tier structural noise)
  manifest.py                   # manifest.json builder + schema validation
  bundle.py                     # orchestrates the full generate -> verify -> ship pipeline
  benchmark.py                  # runs an external auditor command against N generated seeds
  semgrep_rules/
    missing_ownership_check.yml # existence-only rule used by the sanity test (Task 13)

tests/
  engine/
    test_easy_idor_slot.py
    test_hard_idor_slot.py
    test_injector.py
    test_params.py
    test_exploit_gen.py
    test_verifier_integration.py     # @pytest.mark.integration (needs Docker)
    test_manifest.py
    test_reorder.py
    test_bundle_e2e.py               # @pytest.mark.integration (needs Docker)
    test_semgrep_sanity.py           # @pytest.mark.integration (needs semgrep)
    test_benchmark.py
  templates/
    test_notes_app_smoke.py          # @pytest.mark.integration (needs Docker)

pytest.ini
```

## Platform (Part B) scope — interface only, not detailed here

Part B owns `platform/` and `orchestrator/` and is planned separately by its owner. The only things Part B needs from this plan:
- **Bundle shape it will deploy**: a directory containing `app/` (with `Dockerfile`, runnable on port 8000) and `manifest.json` at the bundle root, matching `contract/manifest_schema.json`.
- **What it must NOT read**: the `_internal` block of `manifest.json` (flag, reference exploit path, solution summary) is for the engine's own self-verification and the benchmark harness — the platform must strip or ignore it before anything reaches a student-facing surface.
- **Verification protocol**: student submits a string; platform compares it to `manifest.json`'s top-level `flag` field (design spec section 10).

---

## Task 1: Repo scaffolding + shared contract schema

**Files:**
- Create: `contract/manifest_schema.json`
- Create: `pytest.ini`
- Create: `engine/requirements-dev.txt`
- Create: `engine/__init__.py`, `engine/slots/__init__.py`
- Test: `tests/engine/test_manifest.py` (schema-loading part only, expanded further in Task 9)

**Interfaces:**
- Produces: `contract/manifest_schema.json` — the schema every later manifest-writing task validates against.

- [ ] **Step 1: Write the contract schema**

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "Ulsaner Challenge Manifest",
  "type": "object",
  "required": ["id", "vuln_type", "tier", "entry", "flag", "verify"],
  "properties": {
    "id": { "type": "string" },
    "vuln_type": { "type": "string", "enum": ["idor", "sqli"] },
    "tier": { "type": "string", "enum": ["easy", "hard"] },
    "entry": {
      "type": "object",
      "required": ["port", "task_prompt"],
      "properties": {
        "port": { "type": "integer" },
        "task_prompt": { "type": "string" }
      }
    },
    "flag": { "type": "string" },
    "verify": {
      "type": "object",
      "required": ["method"],
      "properties": {
        "method": { "type": "string", "enum": ["flag_submit"] }
      }
    },
    "_internal": {
      "type": "object",
      "properties": {
        "flag_planted_in": { "type": "string" },
        "reference_exploit": { "type": "string" },
        "solution_summary": { "type": "string" }
      }
    }
  }
}
```

- [ ] **Step 2: Write test config**

`pytest.ini`:
```ini
[pytest]
testpaths = tests
markers =
    integration: requires Docker/semgrep/an external auditor binary on PATH
```

- [ ] **Step 3: Write engine dev dependencies**

`engine/requirements-dev.txt`:
```
libcst==1.4.0
jsonschema==4.23.0
requests==2.32.3
pytest==8.3.3
```

- [ ] **Step 4: Create package scaffolding**

```bash
mkdir -p engine/slots engine/semgrep_rules tests/engine tests/templates
touch engine/__init__.py engine/slots/__init__.py
```

- [ ] **Step 5: Write the failing test**

```python
# tests/engine/test_manifest.py
import json
import pathlib

SCHEMA_PATH = pathlib.Path(__file__).parent.parent.parent / "contract" / "manifest_schema.json"

def test_schema_file_is_valid_json():
    schema = json.loads(SCHEMA_PATH.read_text())
    assert schema["title"] == "Ulsaner Challenge Manifest"
```

- [ ] **Step 6: Run test to verify it passes**

Run: `pip install -r engine/requirements-dev.txt && pytest tests/engine/test_manifest.py -v`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add contract/manifest_schema.json pytest.ini engine/requirements-dev.txt engine/__init__.py engine/slots/__init__.py tests/engine/test_manifest.py
git commit -m "feat: add manifest contract schema and engine scaffolding"
```

---

## Task 2: Clean template app (models, auth, routes)

**Files:**
- Create: `templates/notes_app/requirements.txt`
- Create: `templates/notes_app/db.py`
- Create: `templates/notes_app/routes/__init__.py`
- Create: `templates/notes_app/routes/notes.py`
- Create: `templates/notes_app/app_factory.py`
- Create: `templates/notes_app/main.py`
- Create: `templates/notes_app/seed_data.json`
- Test: `tests/templates/test_notes_app_unit.py`

**Interfaces:**
- Produces: `db.get_current_user(x_user_token: str) -> User`, `db.get_note_by_id(note_id: int) -> Note | None`, `User(id, token, name, workspace_id)`, `Note(id, owner_id, workspace_id, title, body, is_private)`. Task 4 (easy_idor slot) and Task 11 (hard_idor slot) transform the `get_note` function this task defines.

- [ ] **Step 1: Write requirements**

`templates/notes_app/requirements.txt`:
```
fastapi==0.115.0
uvicorn==0.30.6
```

- [ ] **Step 2: Write the default seed data**

`templates/notes_app/seed_data.json`:
```json
{
  "users": [
    {"id": 1, "token": "token-alice", "name": "alice", "workspace_id": 100},
    {"id": 2, "token": "token-bob", "name": "bob", "workspace_id": 100}
  ],
  "notes": [
    {"id": 1, "owner_id": 1, "workspace_id": 100, "title": "private", "body": "FLAG{example}", "is_private": true},
    {"id": 2, "owner_id": 2, "workspace_id": 100, "title": "public", "body": "hello", "is_private": false}
  ]
}
```

- [ ] **Step 3: Write the failing test for `db.py`**

```python
# tests/templates/test_notes_app_unit.py
import sys
import pathlib
import pytest
from fastapi import HTTPException

APP_DIR = pathlib.Path(__file__).parent.parent.parent / "templates" / "notes_app"
sys.path.insert(0, str(APP_DIR))

import db  # noqa: E402

def test_get_current_user_returns_user_for_valid_token():
    user = db.get_current_user("token-alice")
    assert user.id == 1
    assert user.workspace_id == 100

def test_get_current_user_rejects_unknown_token():
    with pytest.raises(HTTPException) as exc_info:
        db.get_current_user("not-a-real-token")
    assert exc_info.value.status_code == 401

def test_get_note_by_id_returns_none_for_missing_note():
    assert db.get_note_by_id(999) is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/templates/test_notes_app_unit.py -v`
Expected: FAIL with "No module named 'db'"

- [ ] **Step 3: Write `db.py`**

```python
# templates/notes_app/db.py
import json
import pathlib
from fastapi import Header, HTTPException

_SEED_PATH = pathlib.Path(__file__).parent / "seed_data.json"


def _load_seed() -> dict:
    with open(_SEED_PATH) as f:
        return json.load(f)


_SEED = _load_seed()
_USERS_BY_TOKEN = {u["token"]: u for u in _SEED["users"]}
_NOTES_BY_ID = {n["id"]: n for n in _SEED["notes"]}


class User:
    def __init__(self, id: int, token: str, name: str, workspace_id: int):
        self.id = id
        self.token = token
        self.name = name
        self.workspace_id = workspace_id


class Note:
    def __init__(self, id: int, owner_id: int, workspace_id: int, title: str, body: str, is_private: bool):
        self.id = id
        self.owner_id = owner_id
        self.workspace_id = workspace_id
        self.title = title
        self.body = body
        self.is_private = is_private


def get_current_user(x_user_token: str = Header(...)) -> User:
    raw = _USERS_BY_TOKEN.get(x_user_token)
    if raw is None:
        raise HTTPException(401, "invalid token")
    return User(**raw)


def get_note_by_id(note_id: int) -> Note | None:
    raw = _NOTES_BY_ID.get(note_id)
    if raw is None:
        return None
    return Note(**raw)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/templates/test_notes_app_unit.py -v`
Expected: PASS (all 3 tests)

- [ ] **Step 5: Write the route handler (the AST transform target)**

`templates/notes_app/routes/__init__.py`: (empty file)

`templates/notes_app/routes/notes.py`:
```python
from fastapi import APIRouter, HTTPException, Depends
from db import get_current_user, get_note_by_id

router = APIRouter()


@router.get("/notes/{note_id}")
def get_note(note_id: int, user=Depends(get_current_user)):
    note = get_note_by_id(note_id)
    if note is None:
        raise HTTPException(404)
    if note.owner_id != user.id:
        raise HTTPException(403)
    return {"id": note.id, "title": note.title, "body": note.body}
```

- [ ] **Step 6: Write app factory and entrypoint**

`templates/notes_app/app_factory.py`:
```python
from fastapi import FastAPI
from routes import notes


def create_app() -> FastAPI:
    app = FastAPI()
    app.include_router(notes.router)
    return app
```

`templates/notes_app/main.py`:
```python
import uvicorn
from app_factory import create_app

app = create_app()

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
```

- [ ] **Step 7: Commit**

```bash
git add templates/notes_app tests/templates/test_notes_app_unit.py
git commit -m "feat: add clean notes_app template (models, auth, get_note route)"
```

---

## Task 3: Dockerize the template app + container smoke test

**Files:**
- Create: `templates/notes_app/Dockerfile`
- Test: `tests/templates/test_notes_app_smoke.py`

**Interfaces:**
- Consumes: `templates/notes_app/` (Task 2), must contain a runnable `main.py` on port 8000.
- Produces: a buildable, non-root Docker image — Task 8 (verifier) builds/runs images with this same shape for generated bundles.

- [ ] **Step 1: Write the Dockerfile**

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN useradd -m appuser
USER appuser
EXPOSE 8000
CMD ["python", "main.py"]
```

- [ ] **Step 2: Write the failing smoke test**

```python
# tests/templates/test_notes_app_smoke.py
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
                resp = requests.get(f"http://localhost:{port}/notes/1", headers={"X-User-Token": "token-alice"}, timeout=1)
                assert resp.status_code == 200
                assert "FLAG" in resp.text
                return
            except (requests.RequestException, AssertionError) as e:
                last_error = e
                time.sleep(0.5)
        raise AssertionError(f"container never became healthy: {last_error}")
    finally:
        subprocess.run(["docker", "rm", "-f", container_id], capture_output=True)
```

- [ ] **Step 3: Run test to verify it fails**

Run: `pytest tests/templates/test_notes_app_smoke.py -v -m integration`
Expected: FAIL — `docker build` fails, no Dockerfile found

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/templates/test_notes_app_smoke.py -v -m integration`
Expected: PASS (requires Docker running locally)

- [ ] **Step 5: Commit**

```bash
git add templates/notes_app/Dockerfile tests/templates/test_notes_app_smoke.py
git commit -m "feat: dockerize notes_app template, non-root, smoke tested"
```

---

## Task 4: `easy/idor` slot — remove the ownership check

**Files:**
- Create: `engine/slots/base.py`
- Create: `engine/slots/easy_idor.py`
- Test: `tests/engine/test_easy_idor_slot.py`

**Interfaces:**
- Produces: `Slot(vuln_type, tier, target_file, target_function, transform)` dataclass, `is_ownership_check(stmt: cst.BaseStatement) -> bool`, `easy_idor.build_easy_idor_slot() -> Slot`. Task 5 (injector) consumes `Slot.transform`. Task 11 (hard_idor) consumes `is_ownership_check`.

- [ ] **Step 1: Write the failing test**

```python
# tests/engine/test_easy_idor_slot.py
import libcst as cst
from engine.slots.easy_idor import build_easy_idor_slot

CLEAN_SOURCE = '''
from fastapi import APIRouter, HTTPException, Depends
from db import get_current_user, get_note_by_id

router = APIRouter()

@router.get("/notes/{note_id}")
def get_note(note_id: int, user=Depends(get_current_user)):
    note = get_note_by_id(note_id)
    if note is None:
        raise HTTPException(404)
    if note.owner_id != user.id:
        raise HTTPException(403)
    return {"id": note.id, "title": note.title, "body": note.body}
'''


def test_easy_idor_slot_removes_ownership_check():
    slot = build_easy_idor_slot()
    module = cst.parse_module(CLEAN_SOURCE)
    transformed = slot.transform(module)
    code = transformed.code
    assert "owner_id" not in code
    assert "note is None" in code


def test_easy_idor_transformed_code_is_valid_python():
    slot = build_easy_idor_slot()
    module = cst.parse_module(CLEAN_SOURCE)
    transformed = slot.transform(module)
    compile(transformed.code, "<generated>", "exec")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/engine/test_easy_idor_slot.py -v`
Expected: FAIL with "No module named 'engine.slots.easy_idor'"

- [ ] **Step 3: Write `engine/slots/base.py`**

```python
from dataclasses import dataclass
from typing import Callable
import libcst as cst


@dataclass(frozen=True)
class Slot:
    vuln_type: str
    tier: str
    target_file: str
    target_function: str
    transform: Callable[[cst.Module], cst.Module]


def is_ownership_check(stmt: cst.BaseStatement) -> bool:
    if not isinstance(stmt, cst.If):
        return False
    test = stmt.test
    return (
        isinstance(test, cst.Comparison)
        and isinstance(test.left, cst.Attribute)
        and test.left.attr.value == "owner_id"
    )
```

- [ ] **Step 4: Write `engine/slots/easy_idor.py`**

```python
import libcst as cst
from .base import Slot, is_ownership_check


class _RemoveOwnershipCheck(cst.CSTTransformer):
    def __init__(self, function_name: str):
        self.function_name = function_name

    def leave_FunctionDef(self, original_node, updated_node):
        if original_node.name.value != self.function_name:
            return updated_node
        new_body = [stmt for stmt in updated_node.body.body if not is_ownership_check(stmt)]
        return updated_node.with_changes(body=updated_node.body.with_changes(body=new_body))


def build_easy_idor_slot() -> Slot:
    def transform(module: cst.Module) -> cst.Module:
        return module.visit(_RemoveOwnershipCheck("get_note"))

    return Slot(
        vuln_type="idor",
        tier="easy",
        target_file="routes/notes.py",
        target_function="get_note",
        transform=transform,
    )
```

- [ ] **Step 5: Run test to verify it passes**

Run: `pytest tests/engine/test_easy_idor_slot.py -v`
Expected: PASS (both tests)

- [ ] **Step 6: Commit**

```bash
git add engine/slots/base.py engine/slots/easy_idor.py tests/engine/test_easy_idor_slot.py
git commit -m "feat: add easy/idor slot (removes ownership check via AST)"
```

---

## Task 5: Injection engine

**Files:**
- Create: `engine/injector.py`
- Test: `tests/engine/test_injector.py`

**Interfaces:**
- Consumes: `Slot` (Task 4), `templates/notes_app/` (Task 2).
- Produces: `injector.inject(template_dir: Path, output_dir: Path, slot: Slot) -> None`, `injector.apply_extra_transform(app_dir: Path, target_file: str, transform: Callable[[cst.Module], cst.Module]) -> None`. Task 12 (reorder) consumes `apply_extra_transform`.

- [ ] **Step 1: Write the failing test**

```python
# tests/engine/test_injector.py
import pathlib
from engine.injector import inject
from engine.slots.easy_idor import build_easy_idor_slot

TEMPLATE_DIR = pathlib.Path(__file__).parent.parent.parent / "templates" / "notes_app"


def test_inject_writes_vulnerable_code(tmp_path):
    output_dir = tmp_path / "bundle_app"
    slot = build_easy_idor_slot()
    inject(TEMPLATE_DIR, output_dir, slot)
    result = (output_dir / "routes" / "notes.py").read_text()
    assert "owner_id" not in result


def test_inject_preserves_untouched_files(tmp_path):
    output_dir = tmp_path / "bundle_app"
    slot = build_easy_idor_slot()
    inject(TEMPLATE_DIR, output_dir, slot)
    assert (output_dir / "Dockerfile").exists()
    assert (output_dir / "db.py").read_text() == (TEMPLATE_DIR / "db.py").read_text()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/engine/test_injector.py -v`
Expected: FAIL with "No module named 'engine.injector'"

- [ ] **Step 3: Write `engine/injector.py`**

```python
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/engine/test_injector.py -v`
Expected: PASS (both tests)

- [ ] **Step 5: Commit**

```bash
git add engine/injector.py tests/engine/test_injector.py
git commit -m "feat: add injection engine (copy template + apply AST transform)"
```

---

## Task 6: Parameterization (randomized seed data + flag)

**Files:**
- Create: `engine/params.py`
- Test: `tests/engine/test_params.py`

**Interfaces:**
- Produces: `params.build_seed_data(rng: random.Random) -> tuple[dict, str]` (returns seed_data dict matching `seed_data.json` shape from Task 2, and the flag string), `params.write_seed_data(app_dir: Path, seed_data: dict) -> None`. Task 7 (exploit_gen) and Task 10 (bundle) consume `build_seed_data`'s return shape.

- [ ] **Step 1: Write the failing test**

```python
# tests/engine/test_params.py
import random
import json
from engine.params import build_seed_data, write_seed_data


def test_build_seed_data_is_deterministic_for_same_rng_seed():
    data_a, flag_a = build_seed_data(random.Random(42))
    data_b, flag_b = build_seed_data(random.Random(42))
    assert data_a == data_b
    assert flag_a == flag_b


def test_build_seed_data_differs_across_seeds():
    _, flag_a = build_seed_data(random.Random(1))
    _, flag_b = build_seed_data(random.Random(2))
    assert flag_a != flag_b


def test_build_seed_data_shape_matches_notes_app_contract():
    data, flag = build_seed_data(random.Random(1))
    assert len(data["users"]) == 2
    assert len(data["notes"]) == 2
    assert data["notes"][0]["body"] == flag
    assert data["notes"][0]["is_private"] is True
    assert data["users"][0]["workspace_id"] == data["users"][1]["workspace_id"]


def test_write_seed_data_writes_valid_json(tmp_path):
    data, _ = build_seed_data(random.Random(1))
    write_seed_data(tmp_path, data)
    written = json.loads((tmp_path / "seed_data.json").read_text())
    assert written == data
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/engine/test_params.py -v`
Expected: FAIL with "No module named 'engine.params'"

- [ ] **Step 3: Write `engine/params.py`**

```python
import json
import pathlib
import random


def build_seed_data(rng: random.Random) -> tuple[dict, str]:
    flag = f"FLAG{{{rng.getrandbits(64):016x}}}"
    token_alice = f"token-{rng.getrandbits(32):08x}"
    token_bob = f"token-{rng.getrandbits(32):08x}"
    shared_workspace = rng.getrandbits(16)
    seed_data = {
        "users": [
            {"id": 1, "token": token_alice, "name": "alice", "workspace_id": shared_workspace},
            {"id": 2, "token": token_bob, "name": "bob", "workspace_id": shared_workspace},
        ],
        "notes": [
            {"id": 1, "owner_id": 1, "workspace_id": shared_workspace, "title": "private", "body": flag, "is_private": True},
            {"id": 2, "owner_id": 2, "workspace_id": shared_workspace, "title": "public", "body": "hello", "is_private": False},
        ],
    }
    return seed_data, flag


def write_seed_data(app_dir: pathlib.Path, seed_data: dict) -> None:
    (app_dir / "seed_data.json").write_text(json.dumps(seed_data, indent=2))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/engine/test_params.py -v`
Expected: PASS (all 4 tests)

- [ ] **Step 5: Commit**

```bash
git add engine/params.py tests/engine/test_params.py
git commit -m "feat: add seed parameterization (randomized users/notes/flag)"
```

---

## Task 7: Reference exploit generator

**Files:**
- Create: `engine/exploit_gen.py`
- Test: `tests/engine/test_exploit_gen.py`

**Interfaces:**
- Consumes: `seed_data` shape and `flag` from Task 6's `build_seed_data`.
- Produces: `ReferenceExploit(method, path, headers, expected_flag)` dataclass, `exploit_gen.build_idor_exploit(seed_data: dict, flag: str) -> ReferenceExploit`. Task 8 (verifier) and Task 10 (bundle) consume this.

- [ ] **Step 1: Write the failing test**

```python
# tests/engine/test_exploit_gen.py
import random
from engine.params import build_seed_data
from engine.exploit_gen import build_idor_exploit


def test_build_idor_exploit_targets_bob_reading_alices_note():
    seed_data, flag = build_seed_data(random.Random(1))
    exploit = build_idor_exploit(seed_data, flag)
    assert exploit.method == "GET"
    assert exploit.path == "/notes/1"
    assert exploit.headers["X-User-Token"] == seed_data["users"][1]["token"]
    assert exploit.expected_flag == flag
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/engine/test_exploit_gen.py -v`
Expected: FAIL with "No module named 'engine.exploit_gen'"

- [ ] **Step 3: Write `engine/exploit_gen.py`**

```python
from dataclasses import dataclass


@dataclass(frozen=True)
class ReferenceExploit:
    method: str
    path: str
    headers: dict[str, str]
    expected_flag: str


def build_idor_exploit(seed_data: dict, flag: str) -> ReferenceExploit:
    attacker_token = seed_data["users"][1]["token"]
    target_note_id = seed_data["notes"][0]["id"]
    return ReferenceExploit(
        method="GET",
        path=f"/notes/{target_note_id}",
        headers={"X-User-Token": attacker_token},
        expected_flag=flag,
    )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/engine/test_exploit_gen.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add engine/exploit_gen.py tests/engine/test_exploit_gen.py
git commit -m "feat: add reference exploit generator for idor slots"
```

---

## Task 8: Self-verification (Docker build/run + exploit replay)

**Files:**
- Create: `engine/verifier.py`
- Test: `tests/engine/test_verifier_integration.py`

**Interfaces:**
- Consumes: a bundle `app/` directory (Task 5's output) with a `Dockerfile`, `ReferenceExploit` (Task 7).
- Produces: `verifier.verify_bundle(app_dir: Path, exploit: ReferenceExploit, tag: str) -> bool`. Task 10 (bundle) consumes this directly.

- [ ] **Step 1: Write the failing integration test**

```python
# tests/engine/test_verifier_integration.py
import pathlib
import random
import pytest
from engine.injector import inject
from engine.params import build_seed_data, write_seed_data
from engine.exploit_gen import build_idor_exploit
from engine.slots.easy_idor import build_easy_idor_slot
from engine.verifier import verify_bundle

TEMPLATE_DIR = pathlib.Path(__file__).parent.parent.parent / "templates" / "notes_app"


@pytest.mark.integration
def test_verify_bundle_passes_for_easy_idor(tmp_path):
    app_dir = tmp_path / "app"
    inject(TEMPLATE_DIR, app_dir, build_easy_idor_slot())
    seed_data, flag = build_seed_data(random.Random(7))
    write_seed_data(app_dir, seed_data)
    exploit = build_idor_exploit(seed_data, flag)
    assert verify_bundle(app_dir, exploit, tag="ulsaner-verifier-test") is True
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/engine/test_verifier_integration.py -v -m integration`
Expected: FAIL with "No module named 'engine.verifier'"

- [ ] **Step 3: Write `engine/verifier.py`**

```python
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/engine/test_verifier_integration.py -v -m integration`
Expected: PASS (requires Docker running locally)

- [ ] **Step 5: Commit**

```bash
git add engine/verifier.py tests/engine/test_verifier_integration.py
git commit -m "feat: add self-verification (docker build/run + exploit replay)"
```

---

## Task 9: Manifest builder

**Files:**
- Create: `engine/manifest.py`
- Test: `tests/engine/test_manifest.py` (extend from Task 1)

**Interfaces:**
- Consumes: `contract/manifest_schema.json` (Task 1).
- Produces: `manifest.build_manifest(vuln_type, tier, flag, task_prompt, reference_exploit_path, solution_summary) -> dict`, `manifest.write_manifest(output_dir: Path, manifest: dict, schema_path: Path) -> None`. Task 10 (bundle) consumes both.

- [ ] **Step 1: Write the failing test (append to existing file)**

```python
# tests/engine/test_manifest.py (add below the existing test)
import pytest
import jsonschema
from engine.manifest import build_manifest, write_manifest


def test_build_manifest_has_required_fields():
    m = build_manifest(
        vuln_type="idor",
        tier="easy",
        flag="FLAG{abc}",
        task_prompt="다른 사용자의 비공개 노트를 읽어 flag를 찾아라",
        reference_exploit_path="exploits/reference.json",
        solution_summary="get_note의 소유권 체크 누락",
    )
    assert m["vuln_type"] == "idor"
    assert m["tier"] == "easy"
    assert m["flag"] == "FLAG{abc}"
    assert m["_internal"]["solution_summary"] == "get_note의 소유권 체크 누락"


def test_write_manifest_validates_against_schema(tmp_path):
    m = build_manifest(
        vuln_type="idor", tier="easy", flag="FLAG{abc}",
        task_prompt="prompt", reference_exploit_path="exploits/reference.json",
        solution_summary="summary",
    )
    write_manifest(tmp_path, m, SCHEMA_PATH)
    assert (tmp_path / "manifest.json").exists()


def test_write_manifest_rejects_invalid_manifest(tmp_path):
    with pytest.raises(jsonschema.ValidationError):
        write_manifest(tmp_path, {"id": "only-id"}, SCHEMA_PATH)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/engine/test_manifest.py -v`
Expected: FAIL with "No module named 'engine.manifest'"

- [ ] **Step 3: Write `engine/manifest.py`**

```python
import json
import uuid
import pathlib
import jsonschema


def build_manifest(
    vuln_type: str,
    tier: str,
    flag: str,
    task_prompt: str,
    reference_exploit_path: str,
    solution_summary: str,
) -> dict:
    return {
        "id": str(uuid.uuid4()),
        "vuln_type": vuln_type,
        "tier": tier,
        "entry": {"port": 8000, "task_prompt": task_prompt},
        "flag": flag,
        "verify": {"method": "flag_submit"},
        "_internal": {
            "flag_planted_in": "target user's private note",
            "reference_exploit": reference_exploit_path,
            "solution_summary": solution_summary,
        },
    }


def write_manifest(output_dir: pathlib.Path, manifest: dict, schema_path: pathlib.Path) -> None:
    schema = json.loads(schema_path.read_text())
    jsonschema.validate(manifest, schema)
    (output_dir / "manifest.json").write_text(json.dumps(manifest, indent=2))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/engine/test_manifest.py -v`
Expected: PASS (4 tests total)

- [ ] **Step 5: Commit**

```bash
git add engine/manifest.py tests/engine/test_manifest.py
git commit -m "feat: add manifest builder with schema validation"
```

---

## Task 10: Bundle orchestrator + Day-3-gate E2E test (`easy/idor`)

**Files:**
- Create: `engine/bundle.py`
- Test: `tests/engine/test_bundle_e2e.py`

**Interfaces:**
- Consumes: `injector.inject`/`apply_extra_transform` (Task 5), `params.build_seed_data`/`write_seed_data` (Task 6), `exploit_gen.build_idor_exploit` (Task 7), `verifier.verify_bundle` (Task 8), `manifest.build_manifest`/`write_manifest` (Task 9), `Slot` (Task 4).
- Produces: `bundle.generate_bundle(seed, output_dir, slot_builder, task_prompt, solution_summary, max_attempts=3) -> Path`, `bundle.BundleGenerationError`. Task 11 (hard_idor bundle), Task 12 (reorder wiring), Task 14 (benchmark) all consume `generate_bundle`.

**This task completes the design spec's Day-3 gate: `easy/idor` generate → verify → manifest, end to end.**

- [ ] **Step 1: Write the failing E2E test**

```python
# tests/engine/test_bundle_e2e.py
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/engine/test_bundle_e2e.py -v -m integration`
Expected: FAIL with "No module named 'engine.bundle'"

- [ ] **Step 3: Write `engine/bundle.py`**

```python
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/engine/test_bundle_e2e.py -v -m integration`
Expected: PASS (requires Docker running locally). **This is the bottom-line demo: run it live as proof the E2E gate works.**

- [ ] **Step 5: Commit**

```bash
git add engine/bundle.py tests/engine/test_bundle_e2e.py
git commit -m "feat: add bundle orchestrator — closes easy/idor E2E gate"
```

---

## Task 11: `hard/idor` slot — existence vs correctness

**Files:**
- Create: `engine/slots/hard_idor.py`
- Test: `tests/engine/test_hard_idor_slot.py`
- Test (extend): `tests/engine/test_bundle_e2e.py`

**Interfaces:**
- Consumes: `Slot`, `is_ownership_check` (Task 4).
- Produces: `hard_idor.build_hard_idor_slot() -> Slot`. Task 13 (semgrep sanity) and Task 14 (benchmark) target this slot specifically.

This slot does not remove the check — it swaps the compared field from `owner_id` (true ownership) to `workspace_id` (shared by multiple users), so the check still looks legitimate but authorizes the wrong scope. This is the concrete implementation of the design spec's "existence vs correctness" distinction (section 8).

- [ ] **Step 1: Write the failing test**

```python
# tests/engine/test_hard_idor_slot.py
import libcst as cst
from engine.slots.hard_idor import build_hard_idor_slot

CLEAN_SOURCE = '''
from fastapi import APIRouter, HTTPException, Depends
from db import get_current_user, get_note_by_id

router = APIRouter()

@router.get("/notes/{note_id}")
def get_note(note_id: int, user=Depends(get_current_user)):
    note = get_note_by_id(note_id)
    if note is None:
        raise HTTPException(404)
    if note.owner_id != user.id:
        raise HTTPException(403)
    return {"id": note.id, "title": note.title, "body": note.body}
'''


def test_hard_idor_slot_swaps_to_workspace_scope_check():
    slot = build_hard_idor_slot()
    module = cst.parse_module(CLEAN_SOURCE)
    transformed = slot.transform(module)
    code = transformed.code
    assert "note.workspace_id != user.workspace_id" in code
    assert "note.owner_id" not in code
    assert "note is None" in code  # unrelated check preserved


def test_hard_idor_transformed_code_is_valid_python():
    slot = build_hard_idor_slot()
    module = cst.parse_module(CLEAN_SOURCE)
    transformed = slot.transform(module)
    compile(transformed.code, "<generated>", "exec")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/engine/test_hard_idor_slot.py -v`
Expected: FAIL with "No module named 'engine.slots.hard_idor'"

- [ ] **Step 3: Write `engine/slots/hard_idor.py`**

```python
import libcst as cst
from .base import Slot, is_ownership_check


class _SwapToWorkspaceScopeCheck(cst.CSTTransformer):
    def __init__(self, function_name: str):
        self.function_name = function_name
        self._inside_target = False

    def visit_FunctionDef(self, node: cst.FunctionDef) -> bool:
        if node.name.value == self.function_name:
            self._inside_target = True
        return True

    def leave_FunctionDef(self, original_node, updated_node):
        if original_node.name.value == self.function_name:
            self._inside_target = False
        return updated_node

    def leave_If(self, original_node, updated_node):
        if not self._inside_target or not is_ownership_check(original_node):
            return updated_node
        new_test = _rebuild_as_workspace_check(original_node.test)
        return updated_node.with_changes(test=new_test)


def _rebuild_as_workspace_check(test: cst.Comparison) -> cst.Comparison:
    new_left = test.left.with_changes(attr=cst.Name("workspace_id"))
    new_comparisons = [
        target.with_changes(comparator=target.comparator.with_changes(attr=cst.Name("workspace_id")))
        for target in test.comparisons
    ]
    return test.with_changes(left=new_left, comparisons=new_comparisons)


def build_hard_idor_slot() -> Slot:
    def transform(module: cst.Module) -> cst.Module:
        return module.visit(_SwapToWorkspaceScopeCheck("get_note"))

    return Slot(
        vuln_type="idor",
        tier="hard",
        target_file="routes/notes.py",
        target_function="get_note",
        transform=transform,
    )
```

**Known limitation** (not a bug to fix now, just be aware): `_inside_target` tracking assumes `get_note` has no nested function definitions reusing the same variable names. Fine for this template; would need proper scope stacking if the template grows nested functions.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/engine/test_hard_idor_slot.py -v`
Expected: PASS (both tests)

- [ ] **Step 5: Write the failing hard-tier E2E test (append to test_bundle_e2e.py)**

```python
# tests/engine/test_bundle_e2e.py (add below existing tests)
from engine.slots.hard_idor import build_hard_idor_slot


@pytest.mark.integration
def test_generate_hard_idor_bundle_e2e(tmp_path):
    output_dir = tmp_path / "bundle-3"
    result = generate_bundle(
        seed=3,
        output_dir=output_dir,
        slot_builder=build_hard_idor_slot,
        task_prompt="다른 사용자의 비공개 노트를 읽어 flag를 찾아라",
        solution_summary="workspace_id 스코프 체크가 owner_id를 대신하는 결함을 이용 (같은 workspace의 다른 유저 노트 열람 가능)",
    )
    assert (result / "manifest.json").exists()
```

- [ ] **Step 6: Run test to verify it passes**

Run: `pytest tests/engine/test_bundle_e2e.py -v -m integration`
Expected: PASS — bob (same workspace as alice, different owner) successfully reads alice's flag note despite the "authorization check" being present.

- [ ] **Step 7: Commit**

```bash
git add engine/slots/hard_idor.py tests/engine/test_hard_idor_slot.py tests/engine/test_bundle_e2e.py
git commit -m "feat: add hard/idor slot (broken scope check, not missing check)"
```

---

## Task 12: AST reordering (structural noise on top of hard tier)

**Files:**
- Create: `engine/reorder.py`
- Modify: `engine/bundle.py:1-45` (wire in the reorder pass for `hard` tier bundles)
- Test: `tests/engine/test_reorder.py`

**Interfaces:**
- Consumes: `injector.apply_extra_transform` (Task 5).
- Produces: `reorder.rename_local_variable(module: cst.Module, function_name: str, old_name: str, new_name: str) -> cst.Module`.

- [ ] **Step 1: Write the failing test**

```python
# tests/engine/test_reorder.py
import libcst as cst
from engine.reorder import rename_local_variable

CLEAN_SOURCE = '''
from fastapi import APIRouter, HTTPException, Depends
from db import get_current_user, get_note_by_id

router = APIRouter()

@router.get("/notes/{note_id}")
def get_note(note_id: int, user=Depends(get_current_user)):
    note = get_note_by_id(note_id)
    if note is None:
        raise HTTPException(404)
    if note.owner_id != user.id:
        raise HTTPException(403)
    return {"id": note.id, "title": note.title, "body": note.body}
'''


def test_rename_local_variable_renames_all_occurrences_in_function():
    module = cst.parse_module(CLEAN_SOURCE)
    renamed = rename_local_variable(module, "get_note", "note", "n7x2")
    code = renamed.code
    assert "n7x2 = get_note_by_id(note_id)" in code
    assert "if n7x2 is None" in code
    assert "n7x2.owner_id != user.id" in code
    assert "note = get_note_by_id(note_id)" not in code


def test_rename_local_variable_produces_valid_python():
    module = cst.parse_module(CLEAN_SOURCE)
    renamed = rename_local_variable(module, "get_note", "note", "n7x2")
    compile(renamed.code, "<generated>", "exec")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/engine/test_reorder.py -v`
Expected: FAIL with "No module named 'engine.reorder'"

- [ ] **Step 3: Write `engine/reorder.py`**

```python
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/engine/test_reorder.py -v`
Expected: PASS (both tests)

- [ ] **Step 5: Wire the reorder pass into hard-tier bundle generation**

Modify `engine/bundle.py` — add the import and the conditional call right after `injector.inject(...)`:

```python
# add to imports at top of engine/bundle.py
from . import reorder

# inside generate_bundle, immediately after injector.inject(TEMPLATE_DIR, app_dir, slot):
        if slot.tier == "hard":
            new_var_name = f"n{rng.getrandbits(16):04x}"
            injector.apply_extra_transform(
                app_dir,
                slot.target_file,
                lambda module: reorder.rename_local_variable(module, slot.target_function, "note", new_var_name),
            )
```

- [ ] **Step 6: Run the hard-tier E2E test again to confirm it still passes with reordering applied**

Run: `pytest tests/engine/test_bundle_e2e.py::test_generate_hard_idor_bundle_e2e -v -m integration`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add engine/reorder.py engine/bundle.py tests/engine/test_reorder.py
git commit -m "feat: add AST reordering pass, wired into hard-tier bundle generation"
```

---

## Task 13: Semgrep sanity test — prove existence-vs-correctness empirically

**Files:**
- Create: `engine/semgrep_rules/missing_ownership_check.yml`
- Test: `tests/engine/test_semgrep_sanity.py`

**Interfaces:**
- Consumes: `injector.inject` (Task 5), `easy_idor.build_easy_idor_slot` (Task 4), `hard_idor.build_hard_idor_slot` (Task 11). Requires `semgrep` CLI on `PATH`.

This is the task that turns the design spec's central claim into a runnable, falsifiable check: a generic (field-name-agnostic) "is there any per-object check" rule must flag `easy/idor` and must NOT flag `hard/idor`.

- [ ] **Step 1: Write the semgrep rule**

```yaml
# engine/semgrep_rules/missing_ownership_check.yml
rules:
  - id: missing-ownership-check
    languages: [python]
    severity: WARNING
    message: >
      Route handler fetches a resource by ID and returns it without any
      per-object authorization check (IDOR risk).
    patterns:
      - pattern: |
          def $FUNC(...):
              ...
              $OBJ = $GET_FN(...)
              ...
              return ...
      - pattern-not: |
          def $FUNC(...):
              ...
              $OBJ = $GET_FN(...)
              ...
              if $OBJ.$FIELD != $USER.$FIELD2:
                  ...
              ...
              return ...
```

- [ ] **Step 2: Write the failing test**

```python
# tests/engine/test_semgrep_sanity.py
import json
import pathlib
import subprocess
import pytest
from engine.injector import inject
from engine.slots.easy_idor import build_easy_idor_slot
from engine.slots.hard_idor import build_hard_idor_slot

TEMPLATE_DIR = pathlib.Path(__file__).parent.parent.parent / "templates" / "notes_app"
RULE_PATH = pathlib.Path(__file__).parent.parent.parent / "engine" / "semgrep_rules" / "missing_ownership_check.yml"


def _run_semgrep(target_file: pathlib.Path) -> list:
    result = subprocess.run(
        ["semgrep", "--config", str(RULE_PATH), "--json", str(target_file)],
        capture_output=True, text=True, check=True,
    )
    return json.loads(result.stdout)["results"]


@pytest.mark.integration
def test_semgrep_flags_easy_idor(tmp_path):
    app_dir = tmp_path / "easy_app"
    inject(TEMPLATE_DIR, app_dir, build_easy_idor_slot())
    findings = _run_semgrep(app_dir / "routes" / "notes.py")
    assert len(findings) > 0


@pytest.mark.integration
def test_semgrep_does_not_flag_hard_idor(tmp_path):
    app_dir = tmp_path / "hard_app"
    inject(TEMPLATE_DIR, app_dir, build_hard_idor_slot())
    findings = _run_semgrep(app_dir / "routes" / "notes.py")
    assert len(findings) == 0
```

- [ ] **Step 3: Run test to verify it fails**

Run: `pytest tests/engine/test_semgrep_sanity.py -v -m integration`
Expected: FAIL — rule file doesn't exist yet or semgrep not installed (install with `pip install semgrep` if missing)

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/engine/test_semgrep_sanity.py -v -m integration`
Expected: PASS (both tests) — this is the empirical proof for design spec section 8's core claim.

- [ ] **Step 5: Commit**

```bash
git add engine/semgrep_rules/missing_ownership_check.yml tests/engine/test_semgrep_sanity.py
git commit -m "test: add semgrep sanity check proving existence-vs-correctness gap"
```

---

## Task 14: Benchmark harness core

**Files:**
- Create: `engine/benchmark.py`
- Test: `tests/engine/test_benchmark.py`

**Interfaces:**
- Consumes: `bundle.generate_bundle` (Task 10).
- Produces: `AuditResult(solved: bool, raw_output: str)`, `benchmark.run_external_auditor(bundle_app_dir: Path, command: list[str]) -> AuditResult`, `benchmark.run_benchmark(seeds: list[int], slot_builder, command_template: list[str], workdir: Path, task_prompt: str, solution_summary: str) -> dict`. Task 15 (VibeCutter wiring) consumes `run_benchmark`.

- [ ] **Step 1: Write the failing test**

```python
# tests/engine/test_benchmark.py
import pathlib
from engine.benchmark import run_external_auditor


def test_run_external_auditor_reports_success_on_exit_code_zero(tmp_path):
    stub = tmp_path / "fake_auditor.sh"
    stub.write_text("#!/bin/sh\necho solved\nexit 0\n")
    stub.chmod(0o755)
    result = run_external_auditor(tmp_path, [str(stub)])
    assert result.solved is True
    assert "solved" in result.raw_output


def test_run_external_auditor_reports_failure_on_nonzero_exit(tmp_path):
    stub = tmp_path / "fake_auditor.sh"
    stub.write_text("#!/bin/sh\necho no bugs found\nexit 1\n")
    stub.chmod(0o755)
    result = run_external_auditor(tmp_path, [str(stub)])
    assert result.solved is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/engine/test_benchmark.py -v`
Expected: FAIL with "No module named 'engine.benchmark'"

- [ ] **Step 3: Write `engine/benchmark.py`**

```python
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/engine/test_benchmark.py -v`
Expected: PASS (both tests)

- [ ] **Step 5: Commit**

```bash
git add engine/benchmark.py tests/engine/test_benchmark.py
git commit -m "feat: add benchmark harness core (external auditor adapter)"
```

---

## Task 15: VibeCutter integration spike + wiring

**Files:**
- Create: `engine/vibecutter_config.py`
- Modify: none (this task is discovery + configuration, not new abstractions)

**Interfaces:**
- Consumes: `benchmark.run_benchmark` (Task 14).
- Produces: `vibecutter_config.COMMAND_TEMPLATE: list[str]` — the actual invocation, discovered in Step 1.

This task cannot be fully written in advance because VibeCutter's real CLI is defined in an external repo this plan hasn't inspected. Step 1 is a real, concrete action (not a placeholder) — everything after it is just filling in a config value with what Step 1 discovers.

- [ ] **Step 1: Clone and inspect VibeCutter's actual interface**

```bash
git clone https://github.com/madcamp-official/VibeCutter /tmp/vibecutter-inspect
cat /tmp/vibecutter-inspect/README.md
# find and run its CLI help, e.g.:
cd /tmp/vibecutter-inspect && python -m vibecutter --help  # or whatever its actual entrypoint turns out to be
```

Record: the exact command, what exit code it uses for "vulnerability found" vs "not found" (or what stdout marker to look for instead — if it doesn't use exit codes cleanly, `run_external_auditor` in Task 14 will need a follow-up change to parse stdout instead of relying on `returncode`).

- [ ] **Step 2: Write the config**

```python
# engine/vibecutter_config.py
# Filled in after Task 15 Step 1's spike. Replace with the real command found there.
COMMAND_TEMPLATE = ["python", "-m", "vibecutter", "audit", "--target", "."]
```

- [ ] **Step 3: Run one real benchmark pass against a hard/idor bundle**

```python
from pathlib import Path
from engine.benchmark import run_benchmark
from engine.slots.hard_idor import build_hard_idor_slot
from engine.vibecutter_config import COMMAND_TEMPLATE

result = run_benchmark(
    seeds=[1, 2, 3, 4, 5],
    slot_builder=build_hard_idor_slot,
    command_template=COMMAND_TEMPLATE,
    workdir=Path("/tmp/ulsaner-benchmark-run"),
    task_prompt="다른 사용자의 비공개 노트를 읽어 flag를 찾아라",
    solution_summary="workspace_id 스코프 체크가 owner_id를 대신하는 결함을 이용",
)
print(result)
```

Run this manually (not a pytest step — it's a real interaction with an external tool whose behavior we're actively measuring) and record `result["success_rate"]`. Repeat with `build_easy_idor_slot` for the missing-check-vs-broken-check contrast the design spec calls for.

- [ ] **Step 4: Commit**

```bash
git add engine/vibecutter_config.py
git commit -m "feat: wire up VibeCutter benchmark command after CLI spike"
```

---

## Self-Review Notes

- **Spec coverage:** Task 1 (contract) → design spec section 5. Task 2/3 (template) → section 6-1. Task 4/11 (slots) → section 6-2, 8. Task 5 (injector) → section 9. Task 6 (params) → section 9's parameterization. Task 7 (exploit) → section 6-4. Task 8 (verifier) → section 6-5. Task 9 (manifest) → section 5. Task 10 (bundle E2E) → the Day-3 gate. Task 12 (reorder) → section 9's AST 재배열. Task 13 (semgrep) → section 13's sanity test requirement. Task 14/15 (benchmark) → section 6-7, 14.
- **Type consistency checked:** `Slot`, `ReferenceExploit`, seed_data shape (`{"users": [...], "notes": [...]}`), and `generate_bundle`'s signature are used identically across Tasks 4–15.
- **No placeholders** except Task 15 Step 1, which is intentionally a discovery spike against a real external repo this plan cannot see in advance — everything downstream of it is a fully working adapter, not a stub.

---

**Plan complete and saved to `docs/superpowers/plans/2026-07-24-ulsaner-engine-implementation-plan.md`. Two execution options:**

**1. Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration.

**2. Inline Execution** — Execute tasks in this session using executing-plans, batch execution with checkpoints.

**Which approach?**
