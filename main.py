import ipaddress
import os
import hashlib
import json
import logging
import re
import subprocess
import time
from datetime import datetime, timezone

import anthropic


# ----------------------------
# STRUCTURED LOGGER SETUP
# ----------------------------
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

# ----------------------------
# 1. INGESTION
# ----------------------------
def ingest_evidence(path):
    logger.info("ingest_start", extra={"data": {"path": path}})
    t0 = time.monotonic()
    evidence_files = []
    for root, _, files in os.walk(path):
        for f in files:
            full_path = os.path.join(root, f)
            with open(full_path, "rb") as file:
                data = file.read()
                evidence_files.append({
                    "path": full_path,
                    "data": data,
                    "hash": hashlib.sha256(data).hexdigest(),
                    "size": len(data)
                })
    logger.info("ingest_complete", extra={"data": {
        "file_count": len(evidence_files),
        "total_bytes": sum(e["size"] for e in evidence_files),
        "duration_s": round(time.monotonic() - t0, 3),
    }})
    return evidence_files


# ----------------------------
# 2. ARTIFACT EXTRACTION
# ----------------------------
_B64_RE = re.compile(r'(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')

# Matches ISO-like timestamps (group 1) or syslog-style (group 2)
_TS_RE = re.compile(
    r'(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)'
    r'|([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})'
)
_IP_RE = re.compile(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b')


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


def _is_rfc1918(ip_str):
    try:
        return ipaddress.ip_address(ip_str).is_private
    except ValueError:
        return False


def extract_artifacts(evidence):
    logger.info("extract_start", extra={"data": {"file_count": len(evidence)}})
    t0 = time.monotonic()
    artifacts = []

    for item in evidence:
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

    by_type = {}
    for atype, _, __ in artifacts:
        by_type[atype] = by_type.get(atype, 0) + 1
    logger.info("extract_complete", extra={"data": {
        "artifact_count": len(artifacts),
        "by_type": by_type,
        "duration_s": round(time.monotonic() - t0, 3),
    }})
    return artifacts


# ----------------------------
# 3. TIMELINE NORMALIZATION
# ----------------------------
def normalize_timeline(artifacts):
    logger.info("normalize_start", extra={"data": {"artifact_count": len(artifacts)}})
    t0 = time.monotonic()
    timeline = []

    for atype, source, line in artifacts:
        ts = _parse_ts(line)
        if ts is None:
            # Fall back to the source file's mtime so events from the same file
            # at least sort consistently relative to one another.
            file_path = source.rsplit(":", 1)[0]
            try:
                ts = datetime.fromtimestamp(os.path.getmtime(file_path), tz=timezone.utc)
            except OSError:
                ts = datetime.fromtimestamp(0, tz=timezone.utc)
        timeline.append({
            "time": ts.isoformat(),
            "event_type": atype,
            "source": source
        })

    timeline = sorted(timeline, key=lambda x: x["time"])
    logger.info("normalize_complete", extra={"data": {
        "event_count": len(timeline),
        "duration_s": round(time.monotonic() - t0, 3),
    }})
    return timeline


# ----------------------------
# 4. LLM REASONING
# ----------------------------
_REASON_SYSTEM = (
    "You are a forensic analyst examining security event timelines. "
    "Analyze the events and generate hypotheses about potential security incidents. "
    "The 'support' field in each hypothesis must be the exact source file path "
    "from the corresponding timeline event — do not summarize or paraphrase it."
)

_REASON_SCHEMA = {
    "format": {
        "type": "json_schema",
        "schema": {
            "type": "object",
            "properties": {
                "hypotheses": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "claim": {"type": "string"},
                            "support": {"type": "string"},
                        },
                        "required": ["claim", "support"],
                        "additionalProperties": False,
                    },
                }
            },
            "required": ["hypotheses"],
            "additionalProperties": False,
        },
    }
}

_MAX_RETRIES = 3


def llm_reason(timeline):
    logger.info("llm_reason_start", extra={"data": {"event_count": len(timeline)}})
    t0 = time.monotonic()
    client = anthropic.Anthropic()

    messages = [{
        "role": "user",
        "content": (
            "Analyze this forensic timeline and generate hypotheses:\n\n"
            + json.dumps(timeline, indent=2)
        ),
    }]

    last_exc = None

    for attempt in range(1, _MAX_RETRIES + 1):
        response = client.messages.create(
            model="claude-opus-4-7",
            max_tokens=4096,
            thinking={"type": "adaptive"},
            system=_REASON_SYSTEM,
            messages=messages,
            output_config=_REASON_SCHEMA,
        )

        text_block = next((b for b in response.content if b.type == "text"), None)

        try:
            if text_block is None:
                raise ValueError("response contained no text block")

            hypotheses = json.loads(text_block.text).get("hypotheses")

            if not hypotheses:
                raise ValueError("hypotheses list is empty")

            usage = response.usage
            logger.info("llm_reason_complete", extra={"data": {
                "attempt": attempt,
                "hypothesis_count": len(hypotheses),
                "input_tokens": usage.input_tokens,
                "output_tokens": usage.output_tokens,
                "total_tokens": usage.input_tokens + usage.output_tokens,
                "duration_s": round(time.monotonic() - t0, 3),
            }})
            return hypotheses

        except (json.JSONDecodeError, ValueError) as exc:
            last_exc = exc
            raw_output = text_block.text[:300] if text_block else "(none)"
            logger.warning("llm_reason_retry", extra={"data": {
                "attempt": attempt,
                "max_retries": _MAX_RETRIES,
                "error": str(exc),
                "raw_output": raw_output,
            }})

            if attempt < _MAX_RETRIES:
                # Self-correction: feed the bad response back and tell the model
                # exactly what was wrong so it can fix its own output.
                messages.append({"role": "assistant", "content": response.content})
                messages.append({
                    "role": "user",
                    "content": (
                        f"Your previous response was invalid: {exc}. "
                        "Return a valid JSON object with a non-empty 'hypotheses' array. "
                        "Each item must have 'claim' (string describing the finding) and "
                        "'support' (exact source file path from the timeline). "
                        "Do not return an empty hypotheses list."
                    ),
                })

    raise RuntimeError(
        f"llm_reason failed after {_MAX_RETRIES} attempts. Last error: {last_exc}"
    )


# ----------------------------
# 5. VERIFICATION LAYER — SIFT forensic tool suite
# ----------------------------
def _run_tool(cmd, timeout=30):
    """Run a forensic CLI tool, return (stdout, stderr, returncode)."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout, r.stderr, r.returncode
    except FileNotFoundError:
        return "", f"tool not found: {cmd[0]}", 127
    except subprocess.TimeoutExpired:
        return "", "timeout", 1


def verify_hypothesis(hypothesis):
    claim = hypothesis["claim"].lower()
    source = hypothesis["support"]
    # source may be "path:lineno" — strip the line number to get the actual file path
    parts = source.rsplit(":", 1)
    file_path = parts[0] if len(parts) == 2 and parts[1].isdigit() else source
    tool_outputs = {}
    evidence_found = []

    # 1. file — identify the file type before deeper analysis
    stdout, _, _ = _run_tool(["file", file_path])
    tool_outputs["file"] = stdout.strip()

    # 2. strings — pull printable sequences; catches IOCs in binaries too
    stdout, _, _ = _run_tool(["strings", file_path])
    tool_outputs["strings"] = stdout
    strings_lower = stdout.lower()

    ioc_keywords = [
        "powershell", "cmd.exe", "cmd /", "/bin/sh", "/bin/bash",
        "http://", "https://", "wget", "curl",
        "password", "passwd", "credential", "secret",
    ]
    for kw in ioc_keywords:
        if kw in strings_lower:
            evidence_found.append(f"strings: found '{kw}'")

    # 3. grep — targeted regex patterns keyed to the hypothesis claim
    grep_patterns = []
    if any(k in claim for k in ("execution", "powershell", "cmd", "process", "command", "script")):
        grep_patterns += [r"powershell", r"cmd\.exe", r"cmd /[a-z]", r"/bin/(sh|bash)", r"\bexec\b"]
    if any(k in claim for k in ("network", "c2", "exfiltration", "http", "communication", "beacon")):
        grep_patterns += [r"https?://[^\s]+", r"\b\d{1,3}(\.\d{1,3}){3}\b(:\d+)?"]
    if any(k in claim for k in ("credential", "password", "auth", "login")):
        grep_patterns += [r"password\s*[:=]", r"passwd", r"secret\s*[:=]"]
    if not grep_patterns:
        grep_patterns = [r"powershell", r"cmd\.exe", r"https?://", r"password"]

    grep_hits = []
    for pattern in grep_patterns:
        stdout, _, rc = _run_tool(["grep", "-iEo", pattern, file_path])
        if rc == 0 and stdout.strip():
            matches = list(dict.fromkeys(stdout.strip().splitlines()))  # dedupe
            grep_hits.append({"pattern": pattern, "matches": matches})
            evidence_found.append(f"grep '{pattern}': {matches}")
    tool_outputs["grep"] = grep_hits

    # 3b. Classify any IP addresses found in grep matches
    all_ips = [ip for hit in grep_hits for m in hit["matches"] for ip in _IP_RE.findall(m)]
    if all_ips:
        internal = [ip for ip in all_ips if _is_rfc1918(ip)]
        external = [ip for ip in all_ips if not _is_rfc1918(ip)]
        if external:
            evidence_found.append(f"ip_classification: external IPs {external} — potential C2/exfiltration target")
        if internal:
            note = "RFC 1918 — lateral movement / internal staging"
            if any(k in claim for k in ("c2", "exfiltration", "outbound", "beacon")):
                note += " (claim characterises as external C2, but address is internal)"
            evidence_found.append(f"ip_classification: internal IPs {internal} — {note}")

    # 4. xxd — hex dump; useful for obfuscated or binary artifacts
    stdout, _, _ = _run_tool(["xxd", file_path])
    tool_outputs["xxd_head"] = stdout[:1024]

    verified = len(evidence_found) > 0

    logger.info("verify_hypothesis", extra={"data": {
        "claim": hypothesis["claim"],
        "support": source,
        "file_type": tool_outputs["file"],
        "grep_hits": len(grep_hits),
        "evidence_found": evidence_found,
        "verified": verified,
    }})

    if not verified:
        logger.warning("verify_hypothesis_failed", extra={"data": {
            "claim": hypothesis["claim"],
            "support": source,
            "file_type": tool_outputs["file"],
        }})

    return verified


# ----------------------------
# 6. REPORT GENERATION
# ----------------------------
def generate_report(verified):
    logger.info("report_start", extra={"data": {"verified_count": len(verified)}})
    report = []
    report.append("=== FORENSIC REPORT ===\n")

    for item in verified:
        report.append(f"- FINDING: {item['claim']}")
        report.append(f"  SOURCE: {item['support']}\n")

    output = "\n".join(report)

    with open("report.txt", "w") as f:
        f.write(output)

    logger.info("report_complete", extra={"data": {"output_path": "report.txt"}})
    print(output)


# ----------------------------
# MAIN PIPELINE
# ----------------------------
def main():
    t0 = time.monotonic()
    logger.info("pipeline_start")
    evidence = ingest_evidence("evidence/")
    artifacts = extract_artifacts(evidence)
    timeline = normalize_timeline(artifacts)
    hypotheses = llm_reason(timeline)
    verified = [h for h in hypotheses if verify_hypothesis(h)]
    generate_report(verified)
    logger.info("pipeline_complete", extra={"data": {
        "verified_findings": len(verified),
        "total_duration_s": round(time.monotonic() - t0, 3),
    }})


if __name__ == "__main__":
    main()
