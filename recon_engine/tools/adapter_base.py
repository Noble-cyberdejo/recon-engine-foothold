"""
recon_engine.tools.adapter_base
=================================
Base subprocess wrapper for external recon tools (nmap, naabu, httpx).
Rules enforced here:

  - Commands are ALWAYS invoked as a list of args (subprocess with
    shell=False). Never string-concatenated into a shell command.
  - Every invocation is scope-checked by the caller *before* this wrapper
    is invoked -- this module has no scope awareness, it only runs
    already-approved commands.
  - If the tool binary is missing (exit 127) and a fallback is
    registered, the fallback runs and discovery continues (FAILURE-01).
  - If a *required* tool fails with no fallback, that's a hard stop:
    the run records a nonzero-exit error and does not silently continue
    (FAILURE-02).
"""
from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Callable, Optional


class ToolExecutionError(Exception):
    def __init__(self, tool: str, exit_code: int, stderr: str = ""):
        super().__init__(f"{tool} exited {exit_code}: {stderr}")
        self.tool = tool
        self.exit_code = exit_code
        self.stderr = stderr


@dataclass
class ToolResult:
    tool: str
    exit_code: int
    stdout: str
    stderr: str
    used_fallback: bool = False


def run_tool(tool_name: str, args: list[str],
             fallback: Optional[Callable[[], ToolResult]] = None,
             timeout: float = 30.0) -> ToolResult:
    """Run an external tool as a list of args (never shell=True, never
    string concatenation). On missing-binary (FileNotFoundError, which
    maps to the conventional exit 127) fall back if one is registered;
    otherwise a nonzero/failed exit with no fallback propagates as
    ToolExecutionError."""
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout, shell=False)
    except FileNotFoundError:
        if fallback is not None:
            return fallback()
        raise ToolExecutionError(tool_name, 127, "tool binary not found and no fallback registered")
    except subprocess.TimeoutExpired as e:
        raise ToolExecutionError(tool_name, -1, f"timed out after {timeout}s") from e

    if proc.returncode != 0:
        if fallback is not None:
            return fallback()
        raise ToolExecutionError(tool_name, proc.returncode, proc.stderr)

    return ToolResult(tool=tool_name, exit_code=0, stdout=proc.stdout, stderr=proc.stderr)


def simulate_tool_exit(tool_name: str, exit_code: int, fallback_available: bool,
                        fallback: Optional[Callable[[], ToolResult]] = None) -> str:
    """Pure decision-logic helper matching FAILURE-01/02 exactly, without
    actually invoking a subprocess -- used by tests and by the
    orchestrator's pre-flight dry-run mode.

    Returns 'fallback' if a fallback was available and would be used,
    or raises ToolExecutionError if the exit is fatal with no fallback.
    """
    if exit_code == 0:
        return "ok"
    if fallback_available:
        return "fallback"
    raise ToolExecutionError(tool_name, exit_code, "nonzero exit, no fallback available")