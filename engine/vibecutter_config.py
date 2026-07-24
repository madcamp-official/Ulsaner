"""VibeCutter integration config (Task 15 spike).

Discovery summary (see .superpowers/sdd/task-15-report.md for the full write-up):

VibeCutter (https://github.com/madcamp-official/VibeCutter, inspected at commit
checked out into /tmp/vibecutter-inspect on 2026-07-24) is **not** a batch CLI you
invoke against a target directory and read an exit code from. It is an MCP
(Model Context Protocol) stdio server (`mcp_server/server.py`) exposing ~28
fine-grained tools (`vc_register_local_target`, `vc_build_target`,
`vc_scan_access_control`, `vc_verify_access_control`, `vc_generate_patch`,
`vc_apply_patch`, `vc_resume_audit`, ...) that an LLM host (Claude Code / Claude
Desktop) is expected to call one at a time, in a specific order, with
human-in-the-loop yes/no approval gates between steps (see VibeCutter's
SKILL.md "표준 절차" and README.md section 4). There is no `--target <dir>`
flag anywhere in the repo, and no single command performs "scan this directory
and tell me pass/fail".

The literal, real command used to *launch* VibeCutter (from README.md section
4, the Claude Code MCP registration instructions) is:

    <vibecutter-checkout>/.venv/bin/python <vibecutter-checkout>/mcp_server/server.py

This is the actual discovered invocation, not a guess. But running it does
NOT perform an audit: it starts a long-lived stdio MCP server that blocks
waiting for MCP protocol messages on stdin. Nothing about it exits 0/1 based
on whether a vulnerability was found -- it just sits there until someone
(an MCP client) drives it through the ~7-step tool sequence, or until it is
killed. VibeCutter also has two batch/eval-style CLIs (`scanners/batch_scan.py`,
`eval/run_m1.py`), but both require the target to already be registered in
VibeCutter's own `datasets/inventory*.yaml` (with a `repo_url`, cloned by
VibeCutter itself) rather than accepting an arbitrary local directory, and
`eval/run_m1.py` additionally requires a remote "235B" LLM endpoint reachable
only over the camp's internal VPN (see `.env.example`) that we do not have
credentials/network access for.

CONSEQUENCE FOR engine.benchmark.run_external_auditor (Task 14): that function
runs `subprocess.run(command, cwd=bundle_app_dir, timeout=600)` and treats
`returncode == 0` as "solved". Pointed at VibeCutter's real launch command,
this would not measure anything -- the process would just idle until the
600s timeout, get killed by subprocess.run's timeout enforcement, and record
every single seed as "not solved" regardless of whether the injected IDOR is
actually exploitable. This is a fundamental interface mismatch (stateful,
multi-turn, human-approved tool protocol vs. one-shot exit-code subprocess),
not a stdout-parsing detail Task 14 could patch its way around -- flagging
for the controller rather than silently working around it, per the task
brief's instructions.

COMMAND_TEMPLATE below is left set to VibeCutter's real, documented launch
command for accuracy/transparency (this is what "running VibeCutter" actually
means), but it should be treated as NOT USABLE with
`engine.benchmark.run_external_auditor` as currently written. Do not swap in
a hand-rolled wrapper script here and call it "VibeCutter's command" -- that
would misrepresent what was actually discovered. The path placeholders below
must be replaced with an absolute path to a real VibeCutter checkout + its
own (separate, non-project) virtualenv; there is no repo-relative path since
VibeCutter is not vendored into this project.
"""

# Discovered from VibeCutter's README.md section 4 (Claude Code MCP registration
# command). This starts VibeCutter's MCP stdio server -- it is the real launch
# command, but it is a long-running server, not a one-shot auditor, so it is
# NOT compatible with run_external_auditor's returncode==0 success check (see
# module docstring above and task-15-report.md for the full explanation).
COMMAND_TEMPLATE: list[str] = [
    "/absolute/path/to/VibeCutter/.venv/bin/python",
    "/absolute/path/to/VibeCutter/mcp_server/server.py",
]
