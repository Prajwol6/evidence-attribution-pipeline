import re
import time
from datetime import datetime, timezone

from utils import logger

_B64_RE = re.compile(r'(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')

# Matches ISO-like timestamps (group 1) or syslog-style (group 2)
_TS_RE = re.compile(
    r'(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)'
    r'|([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})'
)


def _parse_ts(line):
    """Return a UTC-aware datetime from a log line, or None if no timestamp found."""
    m = _TS_RE.search(line)
    if not m:
        return None
    if m.group(1):
        ts = m.group(1).rstrip("Z")
        try:
            dt = datetime.fromisoformat(ts)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    if m.group(2):
        try:
            dt = datetime.strptime(f"{datetime.now().year} {m.group(2)}", "%Y %b %d %H:%M:%S")
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    return None


def extract_log_artifacts(item):
    artifacts = []
    data = item["data"].decode(errors="ignore")

    for lineno, line in enumerate(data.splitlines(), start=1):
        source = f"{item['path']}:{lineno}"
        low = line.lower()

        if "password" in low:
            artifacts.append(("credential_hint", source, line))

        if "cmd.exe" in low or "powershell" in low:
            artifacts.append(("suspicious_execution", source, line))

        if "http://" in low or "https://" in low:
            artifacts.append(("network_indicator", source, line))

        if "net user" in low:
            artifacts.append(("account_creation", source, line))

        if _B64_RE.search(line):
            artifacts.append(("base64_payload", source, line))

    return artifacts
