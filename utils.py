import ipaddress
import json
import logging
import os
import subprocess
from datetime import datetime, timezone


class _JsonFormatter(logging.Formatter):
    def format(self, record):
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "step": record.getMessage(),
        }
        if hasattr(record, "data"):
            entry["data"] = record.data
        return json.dumps(entry)


def _setup_logger():
    os.makedirs("logs", exist_ok=True)
    logger = logging.getLogger("pipeline")
    logger.setLevel(logging.DEBUG)
    if not logger.handlers:
        handler = logging.FileHandler("logs/agent_execution.log")
        handler.setFormatter(_JsonFormatter())
        logger.addHandler(handler)
    return logger


logger = _setup_logger()


def _run_tool(cmd, timeout=30):
    """Run a forensic CLI tool, return (stdout, stderr, returncode)."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout, r.stderr, r.returncode
    except FileNotFoundError:
        return "", f"tool not found: {cmd[0]}", 127
    except subprocess.TimeoutExpired:
        return "", "timeout", 1


def _run_tool_binary(cmd, timeout=30):
    """Like _run_tool but returns stdout as raw bytes (required for icat)."""
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout)
        return r.stdout, r.stderr.decode(errors="ignore"), r.returncode
    except FileNotFoundError:
        return b"", f"tool not found: {cmd[0]}", 127
    except subprocess.TimeoutExpired:
        return b"", "timeout", 1


import re

_IP_RE = re.compile(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b')


def _is_rfc1918(ip_str):
    try:
        return ipaddress.ip_address(ip_str).is_private
    except ValueError:
        return False
