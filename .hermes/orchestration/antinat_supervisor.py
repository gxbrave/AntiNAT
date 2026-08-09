#!/usr/bin/env python3
"""Persistent, low-duty-cycle AntiNAT Kanban supervisor.

The daemon itself is deterministic. It invokes a short-lived Hermes supervisor
turn only when the board is idle or diagnostics require attention. Kanban
Workers remain owned by the default gateway dispatcher.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import threading
import time
from typing import Any

REPO = Path("/root/AntiNAT")
PROMPT_PATH = REPO / ".hermes/orchestration/supervisor-prompt.md"
LOG_DIR = Path("/root/.hermes/logs")
LOG_PATH = LOG_DIR / "antinat-supervisor.log"
STATE_PATH = LOG_DIR / "antinat-supervisor-state.json"
LOCK_PATH = Path("/run/lock/antinat-supervisor.lock")
BOARD_DB = Path("/root/.hermes/kanban/boards/antinat/kanban.db")
BOARD = "antinat"
PROFILE = "sub-agent-sol-supervisor"
HERMES = "/usr/local/bin/hermes"
POLL_SECONDS = 45
UNCHANGED_RECHECK_SECONDS = 600
ACTIVE_HEARTBEAT_SECONDS = 600
ALL_DONE_RECHECK_SECONDS = 3600
AGENT_TIMEOUT_SECONDS = 1800

stop_event = threading.Event()
current_proc: subprocess.Popen[str] | None = None


def redact(text: str) -> str:
    """Defense-in-depth redaction before persistent logging."""
    text = re.sub(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+", "Bearer [REDACTED]", text)
    text = re.sub(
        r"(?i)((?:api[_-]?key|access[_-]?token|auth(?:orization)?|client[_-]?secret|password)\s*[:=]\s*)\S+",
        r"\1[REDACTED]",
        text,
    )
    return text


def configure_logging() -> logging.Logger:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("antinat-supervisor")
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter("%(asctime)sZ %(levelname)s %(message)s", "%Y-%m-%dT%H:%M:%S")
    formatter.converter = time.gmtime

    file_handler = RotatingFileHandler(LOG_PATH, maxBytes=10 * 1024 * 1024, backupCount=5)
    file_handler.setFormatter(formatter)
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)
    return logger


logger = configure_logging()


def signal_handler(signum: int, _frame: Any) -> None:
    global current_proc
    logger.info("stop requested signal=%s", signum)
    stop_event.set()
    proc = current_proc
    if proc is not None and proc.poll() is None:
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass


def command_env() -> dict[str, str]:
    env = os.environ.copy()
    env.update(
        {
            "HOME": "/root",
            "HERMES_KANBAN_BOARD": BOARD,
            "HERMES_KANBAN_DB": str(BOARD_DB),
            "HERMES_SUPERVISOR": "1",
            "PYTHONUNBUFFERED": "1",
        }
    )
    return env


def run_json(args: list[str], timeout: int = 120) -> Any:
    result = subprocess.run(
        args,
        cwd=REPO,
        env=command_env(),
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"command failed rc={result.returncode}: {' '.join(args)}; "
            f"stderr={redact(result.stderr.strip())[:1000]}"
        )
    return json.loads(result.stdout)


def board_state() -> dict[str, Any]:
    stats = run_json([HERMES, "kanban", "--board", BOARD, "stats", "--json"])
    diagnostics = run_json([HERMES, "kanban", "--board", BOARD, "diagnostics", "--json"])
    tasks = run_json([HERMES, "kanban", "--board", BOARD, "list", "--json"])
    compact = [
        {
            "id": task.get("id"),
            "title": task.get("title"),
            "status": task.get("status"),
            "assignee": task.get("assignee"),
            "started_at": task.get("started_at"),
            "completed_at": task.get("completed_at"),
            "result": task.get("result"),
        }
        for task in tasks
    ]
    digest = hashlib.sha256(
        json.dumps(compact, sort_keys=True, ensure_ascii=False).encode("utf-8")
    ).hexdigest()
    active = [task for task in compact if task["status"] in {"todo", "ready", "running"}]
    running = [task for task in compact if task["status"] == "running"]
    return {
        "stats": stats,
        "diagnostics": diagnostics,
        "tasks": compact,
        "digest": digest,
        "active": active,
        "running": running,
    }


def state_summary(state: dict[str, Any]) -> str:
    by_status = state.get("stats", {}).get("by_status", {})
    active = [f"{t['id']}:{t['status']}:{t.get('assignee') or '-'}" for t in state["active"]]
    return f"status={by_status} active={active or ['none']} diagnostics={len(state['diagnostics'])}"


def read_persistent_state() -> dict[str, Any]:
    try:
        data = json.loads(STATE_PATH.read_text())
        return data if isinstance(data, dict) else {}
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}


def write_persistent_state(data: dict[str, Any]) -> None:
    temp = STATE_PATH.with_suffix(".tmp")
    temp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    os.chmod(temp, 0o600)
    os.replace(temp, STATE_PATH)


def invoke_supervisor(state: dict[str, Any]) -> tuple[int, str]:
    global current_proc
    static_prompt = PROMPT_PATH.read_text()
    runtime = {
        "utc_epoch": int(time.time()),
        "board_digest": state["digest"],
        "stats": state["stats"],
        "diagnostics_count": len(state["diagnostics"]),
        "active": state["active"],
    }
    prompt = (
        static_prompt
        + "\n\n## Runtime snapshot supplied by the daemon\n\n"
        + "```json\n"
        + json.dumps(runtime, indent=2, ensure_ascii=False)
        + "\n```\n\nRe-read the live board before acting; this snapshot can become stale."
    )
    args = [
        HERMES,
        "-p",
        PROFILE,
        "chat",
        "-Q",
        "--max-turns",
        "60",
        "--source",
        "antinat-supervisor",
        "-q",
        prompt,
    ]
    logger.info("agent tick start profile=%s reasoning=medium board_digest=%s", PROFILE, state["digest"][:12])
    current_proc = subprocess.Popen(
        args,
        cwd=REPO,
        env=command_env(),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    try:
        output, _ = current_proc.communicate(timeout=AGENT_TIMEOUT_SECONDS)
        rc = current_proc.returncode or 0
    except subprocess.TimeoutExpired:
        logger.error("agent tick timeout after %ss; terminating process group", AGENT_TIMEOUT_SECONDS)
        try:
            os.killpg(current_proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            output, _ = current_proc.communicate(timeout=20)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(current_proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            output, _ = current_proc.communicate()
        rc = 124
    finally:
        current_proc = None
    output = redact((output or "").strip())
    logger.info("agent tick end rc=%s\n%s", rc, output[-12000:] or "[no output]")
    return rc, output


def sleep_interruptible(seconds: int) -> None:
    stop_event.wait(seconds)


def main() -> int:
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, signal_handler)

    LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    lock_file = LOCK_PATH.open("w")
    try:
        fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        logger.error("another supervisor instance holds %s", LOCK_PATH)
        return 2
    lock_file.write(str(os.getpid()))
    lock_file.flush()

    if not PROMPT_PATH.is_file():
        logger.error("missing supervisor prompt: %s", PROMPT_PATH)
        return 2
    if not BOARD_DB.is_file():
        logger.error("missing shared board DB: %s", BOARD_DB)
        return 2

    persisted = read_persistent_state()
    last_invoked_digest = persisted.get("last_invoked_digest")
    last_invoked_at = float(persisted.get("last_invoked_at") or 0)
    last_active_log = 0.0
    logger.info(
        "service start pid=%s repo=%s board=%s profile=%s reasoning=medium",
        os.getpid(), REPO, BOARD, PROFILE,
    )

    while not stop_event.is_set():
        try:
            before = board_state()
            now = time.time()
            by_status = before["stats"].get("by_status", {})
            blocked_count = int(by_status.get("blocked", 0) or 0)
            todo_count = int(by_status.get("todo", 0) or 0)
            ready_count = int(by_status.get("ready", 0) or 0)
            running_count = int(by_status.get("running", 0) or 0)

            if blocked_count == 0 and todo_count == 0 and ready_count == 0 and running_count == 0:
                logger.info("board has no remaining blocked/ready/running tasks: %s", state_summary(before))
                sleep_interruptible(ALL_DONE_RECHECK_SECONDS)
                continue

            must_invoke = bool(before["diagnostics"])
            if running_count > 0 and not must_invoke:
                if now - last_active_log >= ACTIVE_HEARTBEAT_SECONDS:
                    logger.info("workers active; supervision deferred: %s", state_summary(before))
                    last_active_log = now
                sleep_interruptible(POLL_SECONDS)
                continue

            unchanged_recently = (
                before["digest"] == last_invoked_digest
                and now - last_invoked_at < UNCHANGED_RECHECK_SECONDS
            )
            if unchanged_recently and not must_invoke:
                sleep_interruptible(POLL_SECONDS)
                continue

            logger.info("board before tick: %s", state_summary(before))
            rc, _ = invoke_supervisor(before)
            after = board_state()
            logger.info("board after tick: %s", state_summary(after))
            last_invoked_digest = before["digest"]
            last_invoked_at = now
            write_persistent_state(
                {
                    "last_invoked_at": last_invoked_at,
                    "last_invoked_digest": last_invoked_digest,
                    "last_return_code": rc,
                    "last_after_digest": after["digest"],
                    "updated_at": int(time.time()),
                }
            )
        except Exception as exc:
            logger.exception("supervisor loop error: %s", redact(str(exc)))

        sleep_interruptible(POLL_SECONDS)

    logger.info("service stopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
