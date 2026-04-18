import argparse
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

from llm_interact import LLM_INTERACT

RESULT_MARKER = "GSS_AGENTIC_RESULT_JSON="
DEFAULT_MODEL = "openai/gpt-4o-mini"
SKIP_DIRS = {
    ".git",
    "__pycache__",
    ".idea",
    ".vscode",
    "node_modules",
    "target",
    "dist",
    "build",
    ".venv",
    "venv",
}
BLOCKED_SUBSTRINGS = [
    "rm -rf /",
    "mkfs",
    "shutdown",
    "reboot",
    "poweroff",
    "docker ",
    "podman",
    "mount ",
    " umount",
    " dd ",
    "chown ",
    "chmod 777 /",
    "curl ",
    "wget ",
    "ssh ",
    "scp ",
    "nc ",
    "ncat ",
    ":(){:|:&};:",
]
SOURCE_EXTENSIONS = {
    ".c",
    ".cc",
    ".cpp",
    ".h",
    ".hpp",
    ".hh",
    ".txt",
    ".md",
    ".json",
    ".toml",
    ".yaml",
    ".yml",
    ".ini",
    ".cfg",
    ".log",
    ".py",
    ".java",
    ".go",
    ".rs",
    ".js",
    ".ts",
    ".sh",
    ".bat",
    ".ps1",
    ".cmake",
    ".mk",
    ".o",
    ".obj",
    ".a",
    ".lib",
    ".d",
}


def setup_logging(out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    log_path = out_dir / "agentic_compile.log"
    handlers = [
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(log_path, encoding="utf-8"),
    ]
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=handlers,
        force=True,
    )


def collect_repo_files(repo_dir: Path, max_files: int = 400) -> list[str]:
    files: list[str] = []
    for root, dirs, names in os.walk(repo_dir):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in names:
            p = Path(root) / name
            try:
                rel = p.relative_to(repo_dir)
            except ValueError:
                continue
            files.append(str(rel).replace("\\", "/"))
            if len(files) >= max_files:
                return files
    return files


def read_context_files(repo_dir: Path, max_chars: int = 12000) -> dict[str, str]:
    candidates = [
        "README.md",
        "README",
        "Makefile",
        "makefile",
        "CMakeLists.txt",
        "configure",
        "meson.build",
        "Cargo.toml",
        "go.mod",
        "package.json",
        "pyproject.toml",
        "setup.py",
    ]
    out: dict[str, str] = {}
    remaining = max_chars
    for rel in candidates:
        path = repo_dir / rel
        if not path.exists() or not path.is_file():
            continue
        if remaining <= 0:
            break
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        text = text[: min(len(text), remaining, 2500)]
        out[rel] = text
        remaining -= len(text)
    return out


def tail_text(value: str, max_chars: int = 2000) -> str:
    if value is None:
        return ""
    if len(value) <= max_chars:
        return value
    return value[-max_chars:]


def extract_json_object(raw: str) -> dict[str, Any]:
    try:
        obj = json.loads(raw)
        if isinstance(obj, dict):
            return obj
    except Exception:
        pass

    start = raw.find("{")
    end = raw.rfind("}")
    if start != -1 and end != -1 and end > start:
        candidate = raw[start : end + 1]
        try:
            obj = json.loads(candidate)
            if isinstance(obj, dict):
                return obj
        except Exception:
            pass
    raise ValueError("No JSON object found in LLM response")


def coerce_action(obj: dict[str, Any]) -> dict[str, Any]:
    done = bool(obj.get("done", False))
    next_command = str(obj.get("next_command", "")).strip()
    reason = str(obj.get("reason", "")).strip()
    expected_outputs_raw = obj.get("expected_outputs", [])
    expected_outputs: list[str] = []
    if isinstance(expected_outputs_raw, list):
        for item in expected_outputs_raw:
            if item is None:
                continue
            s = str(item).strip()
            if s:
                expected_outputs.append(s)
    return {
        "done": done,
        "next_command": next_command,
        "reason": reason,
        "expected_outputs": expected_outputs,
    }


def validate_command(command: str) -> tuple[bool, str]:
    if not command:
        return False, "Command is empty."
    if len(command) > 300:
        return False, "Command length exceeded 300 chars."
    if "\n" in command or "\r" in command:
        return False, "Multi-line commands are not allowed."

    lowered = f" {command.lower()} "
    for blocked in BLOCKED_SUBSTRINGS:
        if blocked in lowered:
            return False, f"Command blocked by policy pattern: {blocked}"

    if not re.fullmatch(r"[A-Za-z0-9_\-./:=+,'\"|&;()<>\[\]{}*?!@%$\\ ]+", command):
        return False, "Command contains unsupported characters."
    return True, ""


def build_agent_messages(
    file_list: list[str],
    context_files: dict[str, str],
    history: list[dict[str, Any]],
    last_error: str,
    expected_outputs: list[str],
    step: int,
    max_steps: int,
) -> list[dict[str, str]]:
    history_tail = history[-4:]
    history_lines: list[str] = []
    for h in history_tail:
        history_lines.append(
            f"- step={h.get('step')} exit={h.get('exit_code')} cmd={h.get('command')}\n"
            f"  stdout_tail={tail_text(h.get('stdout_tail', ''), 500)}\n"
            f"  stderr_tail={tail_text(h.get('stderr_tail', ''), 500)}"
        )
    history_text = "\n".join(history_lines) if history_lines else "(none)"

    context_blocks = []
    for rel, text in context_files.items():
        context_blocks.append(f"### {rel}\n{text}")
    context_text = "\n\n".join(context_blocks) if context_blocks else "(none)"

    files_text = "\n".join(file_list[:300])
    expected_text = ", ".join(expected_outputs) if expected_outputs else "(none)"
    error_text = tail_text(last_error, 1200) if last_error else "(none)"

    system_prompt = (
        "You are an autonomous build engineer. "
        "Your only task is to produce ONE next shell command to compile/build the current repository in Linux. "
        "You must be concise and deterministic. "
        "Output must be strict JSON with keys: "
        "`done` (boolean), `next_command` (string), `reason` (short string), `expected_outputs` (array of filenames). "
        "If build appears complete, set done=true and next_command=\"\"."
    )

    user_prompt = (
        f"Step {step}/{max_steps}\n"
        "Repository files (partial):\n"
        f"{files_text}\n\n"
        "Context files:\n"
        f"{context_text}\n\n"
        "Previous command results:\n"
        f"{history_text}\n\n"
        "Last error:\n"
        f"{error_text}\n\n"
        "Currently expected outputs:\n"
        f"{expected_text}\n\n"
        "Return only JSON."
    )

    return [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]


def query_next_action(
    llm: LLM_INTERACT,
    model: str,
    file_list: list[str],
    context_files: dict[str, str],
    history: list[dict[str, Any]],
    last_error: str,
    expected_outputs: list[str],
    step: int,
    max_steps: int,
) -> dict[str, Any]:
    messages = build_agent_messages(
        file_list=file_list,
        context_files=context_files,
        history=history,
        last_error=last_error,
        expected_outputs=expected_outputs,
        step=step,
        max_steps=max_steps,
    )
    response = llm.query_LLM(model, messages, [], {"type": "json_object"})
    if "choices" not in response:
        raise RuntimeError(f"LLM response missing choices: {response}")
    content = response["choices"][0]["message"]["content"]
    return coerce_action(extract_json_object(content))


def copy_repo_to_workspace(repo_dir: Path, workspace_dir: Path) -> None:
    if workspace_dir.exists():
        shutil.rmtree(workspace_dir, ignore_errors=True)
    ignore = shutil.ignore_patterns(*SKIP_DIRS)
    shutil.copytree(repo_dir, workspace_dir, ignore=ignore)


def run_command_in_docker(workspace_dir: Path, command: str, timeout_sec: int) -> dict[str, Any]:
    docker_cmd = [
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        "256",
        "--memory",
        "1g",
        "--cpus",
        "1.0",
        "--read-only",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,noexec,size=256m",
        "--tmpfs",
        "/run:rw,nosuid,nodev,noexec,size=16m",
        "-v",
        f"{workspace_dir}:/work:rw",
        "--workdir",
        "/work",
        "gcc:13",
        "bash",
        "-lc",
        command,
    ]
    start = time.time()
    try:
        proc = subprocess.run(
            docker_cmd,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            check=False,
            encoding="utf-8",
            errors="replace",
        )
        return {
            "exit_code": int(proc.returncode),
            "stdout": proc.stdout or "",
            "stderr": proc.stderr or "",
            "duration_sec": round(time.time() - start, 3),
            "timed_out": False,
        }
    except subprocess.TimeoutExpired as e:
        return {
            "exit_code": 124,
            "stdout": (e.stdout or "") if isinstance(e.stdout, str) else "",
            "stderr": (e.stderr or "") if isinstance(e.stderr, str) else "",
            "duration_sec": round(time.time() - start, 3),
            "timed_out": True,
        }
    except FileNotFoundError:
        return {
            "exit_code": 127,
            "stdout": "",
            "stderr": "docker command not found.",
            "duration_sec": round(time.time() - start, 3),
            "timed_out": False,
        }
    except Exception as e:
        return {
            "exit_code": 125,
            "stdout": "",
            "stderr": str(e),
            "duration_sec": round(time.time() - start, 3),
            "timed_out": False,
        }


def collect_binary_candidates(workspace_dir: Path, expected_outputs: set[str]) -> list[Path]:
    candidates: list[Path] = []
    seen: set[str] = set()

    def add_candidate(path: Path) -> None:
        if not path.exists() or not path.is_file():
            return
        key = str(path.resolve())
        if key in seen:
            return
        seen.add(key)
        candidates.append(path)

    for name in sorted(expected_outputs):
        expected_path = workspace_dir / name
        if expected_path.is_file():
            add_candidate(expected_path)
            continue
        base = Path(name).name
        for p in workspace_dir.rglob(base):
            if p.is_file():
                add_candidate(p)

    if candidates:
        return candidates

    for default_name in ("server", "a.out", "main"):
        p = workspace_dir / default_name
        if p.is_file():
            add_candidate(p)
    if candidates:
        return candidates

    for p in workspace_dir.rglob("*"):
        if not p.is_file():
            continue
        if p.suffix.lower() in SOURCE_EXTENSIONS:
            continue
        try:
            size = p.stat().st_size
        except Exception:
            continue
        if size < 1024:
            continue
        add_candidate(p)
        if len(candidates) >= 8:
            break
    return candidates


def copy_binaries(candidates: list[Path], out_dir: Path) -> list[str]:
    out_dir.mkdir(parents=True, exist_ok=True)
    copied: list[str] = []
    used_names: set[str] = set()
    for src in candidates:
        name = src.name
        if not name:
            continue
        safe_name = re.sub(r"[\\/:*?\"<>|]", "_", name)
        candidate_name = safe_name
        idx = 1
        while candidate_name in used_names:
            candidate_name = f"{safe_name}_{idx}"
            idx += 1
        used_names.add(candidate_name)
        dst = out_dir / candidate_name
        try:
            shutil.copy2(src, dst)
            copied.append(str(dst))
        except Exception:
            continue
    return copied


def write_json(path: Path, obj: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2)


def build_failure_result(
    message: str,
    out_dir: Path,
    steps: list[dict[str, Any]],
    expected_outputs: set[str],
    transcript_path: Path,
) -> dict[str, Any]:
    return {
        "success": False,
        "message": message,
        "output_dir": str(out_dir),
        "binaries": [],
        "steps": steps,
        "expected_outputs": sorted(expected_outputs),
        "transcript_path": str(transcript_path),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--token", required=False)
    parser.add_argument("--model", required=False, default=DEFAULT_MODEL)
    parser.add_argument("--max-steps", type=int, required=False, default=10)
    parser.add_argument("--command-timeout", type=int, required=False, default=180)
    args = parser.parse_args()

    repo_dir = Path(args.repo).expanduser().resolve()
    out_dir = Path(args.out).expanduser().resolve()
    transcript_path = out_dir / "agentic_compile_transcript.json"
    result_path = out_dir / "agentic_compile_result.json"
    setup_logging(out_dir)

    if args.token:
        os.environ["GSS_TOKEN"] = args.token

    steps: list[dict[str, Any]] = []
    expected_outputs: set[str] = set()
    if not repo_dir.exists() or not repo_dir.is_dir():
        result = build_failure_result(
            f"Repository path not found: {repo_dir}",
            out_dir,
            steps,
            expected_outputs,
            transcript_path,
        )
        write_json(result_path, result)
        write_json(transcript_path, {"steps": steps, "error": result["message"]})
        print(RESULT_MARKER + json.dumps(result, ensure_ascii=False))
        return 1

    workspace_dir = out_dir / "_workspace"
    logging.info("Preparing workspace from %s", repo_dir)
    try:
        copy_repo_to_workspace(repo_dir, workspace_dir)
    except Exception as e:
        result = build_failure_result(
            f"Failed to prepare workspace: {e}",
            out_dir,
            steps,
            expected_outputs,
            transcript_path,
        )
        write_json(result_path, result)
        write_json(transcript_path, {"steps": steps, "error": result["message"]})
        print(RESULT_MARKER + json.dumps(result, ensure_ascii=False))
        return 1

    file_list = collect_repo_files(workspace_dir)
    context_files = read_context_files(workspace_dir)
    logging.info("Collected %d files for planning context", len(file_list))

    try:
        llm = LLM_INTERACT()
    except Exception as e:
        result = build_failure_result(
            f"Failed to initialize LLM client: {e}",
            out_dir,
            steps,
            expected_outputs,
            transcript_path,
        )
        write_json(result_path, result)
        write_json(transcript_path, {"steps": steps, "error": result["message"]})
        print(RESULT_MARKER + json.dumps(result, ensure_ascii=False))
        return 1

    last_error = ""
    done = False
    for step in range(1, max(args.max_steps, 1) + 1):
        logging.info("Agent step %d/%d", step, args.max_steps)
        try:
            action = query_next_action(
                llm=llm,
                model=args.model,
                file_list=file_list,
                context_files=context_files,
                history=steps,
                last_error=last_error,
                expected_outputs=sorted(expected_outputs),
                step=step,
                max_steps=args.max_steps,
            )
        except Exception as e:
            last_error = f"LLM planning failed: {e}"
            steps.append(
                {
                    "step": step,
                    "command": "",
                    "exit_code": -1,
                    "stdout_tail": "",
                    "stderr_tail": tail_text(last_error),
                    "duration_sec": 0,
                    "status": "planner_error",
                }
            )
            break

        expected_outputs.update(action.get("expected_outputs", []))
        if action.get("done") and not action.get("next_command"):
            done = True
            steps.append(
                {
                    "step": step,
                    "command": "",
                    "exit_code": 0,
                    "stdout_tail": "",
                    "stderr_tail": "",
                    "duration_sec": 0,
                    "status": "done",
                    "reason": action.get("reason", ""),
                }
            )
            break

        command = action.get("next_command", "")
        valid, reason = validate_command(command)
        if not valid:
            last_error = f"Blocked command: {reason}"
            steps.append(
                {
                    "step": step,
                    "command": command,
                    "exit_code": -2,
                    "stdout_tail": "",
                    "stderr_tail": tail_text(last_error),
                    "duration_sec": 0,
                    "status": "blocked",
                    "reason": action.get("reason", ""),
                }
            )
            continue

        exec_result = run_command_in_docker(workspace_dir, command, max(args.command_timeout, 30))
        status = "ok" if exec_result["exit_code"] == 0 else "failed"
        if exec_result["timed_out"]:
            status = "timeout"
        steps.append(
            {
                "step": step,
                "command": command,
                "exit_code": exec_result["exit_code"],
                "stdout_tail": tail_text(exec_result["stdout"]),
                "stderr_tail": tail_text(exec_result["stderr"]),
                "duration_sec": exec_result["duration_sec"],
                "status": status,
                "reason": action.get("reason", ""),
            }
        )

        if exec_result["exit_code"] != 0:
            last_error = tail_text(exec_result["stderr"] or exec_result["stdout"])
        else:
            last_error = ""
            if action.get("done", False):
                done = True
                break

    candidates = collect_binary_candidates(workspace_dir, expected_outputs)
    copied = copy_binaries(candidates, out_dir)

    if copied:
        message = f"Compiled {len(copied)} binary file(s)."
        success = True
    elif done:
        message = "Agent reported done but no binaries were detected."
        success = False
    else:
        message = "Compilation did not produce any detectable binaries."
        success = False

    transcript = {
        "repo": str(repo_dir),
        "workspace": str(workspace_dir),
        "model": args.model,
        "max_steps": args.max_steps,
        "command_timeout_sec": args.command_timeout,
        "expected_outputs": sorted(expected_outputs),
        "steps": steps,
    }
    write_json(transcript_path, transcript)

    result = {
        "success": success,
        "message": message,
        "output_dir": str(out_dir),
        "binaries": copied,
        "steps": steps,
        "expected_outputs": sorted(expected_outputs),
        "transcript_path": str(transcript_path),
    }
    write_json(result_path, result)

    print(RESULT_MARKER + json.dumps(result, ensure_ascii=False))
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
