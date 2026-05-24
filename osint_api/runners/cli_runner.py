"""
Secure CLI runner: executes whitelisted binaries with whitelisted arguments only.
Never uses shell=True. Never passes raw user input directly to subprocess.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass

from osint_api.security.allowlist import get_tool_config, is_tool_allowed, validate_args

logger = logging.getLogger(__name__)


class ToolNotAllowedError(Exception):
    pass


class ToolArgError(Exception):
    pass


class ToolTimeoutError(Exception):
    pass


@dataclass
class RunResult:
    tool: str
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False


async def run_cli_tool(
    tool_name: str,
    args: list[str],
    timeout: float | None = None,
    env: dict[str, str] | None = None,
) -> RunResult:
    """
    Execute a whitelisted CLI tool safely.

    Args:
        tool_name: Key in TOOL_ALLOWLIST (e.g. "whois", "sherlock")
        args: List of arguments; each flag is checked against the allowlist
        timeout: Seconds before forceful kill; defaults to tool's configured timeout
        env: Optional extra environment variables (merged with current env)
    """
    if not is_tool_allowed(tool_name):
        raise ToolNotAllowedError(f"Tool '{tool_name}' is not in the allowlist")

    ok, err = validate_args(tool_name, args)
    if not ok:
        raise ToolArgError(err)

    config = get_tool_config(tool_name)
    binary = config["binary"]  # type: ignore[index]
    effective_timeout = timeout or config.get("timeout", 60)  # type: ignore[index]

    cmd = [binary, *args]
    logger.info("Running: %s (timeout=%ss)", " ".join(cmd), effective_timeout)

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
        try:
            stdout_b, stderr_b = await asyncio.wait_for(
                proc.communicate(), timeout=effective_timeout
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            logger.warning("Tool '%s' timed out after %ss", tool_name, effective_timeout)
            return RunResult(
                tool=tool_name, returncode=-1, stdout="", stderr="", timed_out=True
            )

        result = RunResult(
            tool=tool_name,
            returncode=proc.returncode or 0,
            stdout=stdout_b.decode("utf-8", errors="replace"),
            stderr=stderr_b.decode("utf-8", errors="replace"),
        )
        if result.returncode not in (0, -1):
            logger.warning(
                "Tool '%s' exited rc=%d | stderr: %s",
                tool_name, result.returncode,
                result.stderr[:500] if result.stderr else "(empty)",
            )
        else:
            logger.debug("Tool '%s' finished rc=%d", tool_name, result.returncode)
        return result

    except FileNotFoundError:
        logger.error("Binary '%s' not found", binary)
        return RunResult(tool=tool_name, returncode=-2, stdout="", stderr=f"Binary '{binary}' not found")
