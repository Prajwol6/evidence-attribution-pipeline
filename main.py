import os
import hashlib
import json
import logging
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
def extract_artifacts(evidence):
    logger.info("extract_start", extra={"data": {"file_count": len(evidence)}})
    t0 = time.monotonic()
    artifacts = []

    for item in evidence:
        data = item["data"].decode(errors="ignore")

        # simple heuristic extraction
        if "password" in data.lower():
            artifacts.append(("credential_hint", item["path"]))

        if "cmd.exe" in data.lower() or "powershell" in data.lower():
            artifacts.append(("suspicious_execution", item["path"]))

        if "http://" in data.lower() or "https://" in data.lower():
            artifacts.append(("network_indicator", item["path"]))

    by_type = {}
    for atype, _ in artifacts:
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

    for i, (atype, source) in enumerate(artifacts):
        timeline.append({
            "time": datetime.now(timezone.utc).isoformat(),
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
def llm_reason(timeline):
    logger.info("llm_reason_start", extra={"data": {"event_count": len(timeline)}})
    t0 = time.monotonic()
    client = anthropic.Anthropic()

    response = client.messages.create(
        model="claude-opus-4-7",
        max_tokens=4096,
        thinking={"type": "adaptive"},
        system=(
            "You are a forensic analyst examining security event timelines. "
            "Analyze the events and generate hypotheses about potential security incidents. "
            "The 'support' field in each hypothesis must be the exact source file path "
            "from the corresponding timeline event — do not summarize or paraphrase it."
        ),
        messages=[{
            "role": "user",
            "content": (
                "Analyze this forensic timeline and generate hypotheses:\n\n"
                + json.dumps(timeline, indent=2)
            )
        }],
        output_config={
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
                                    "support": {"type": "string"}
                                },
                                "required": ["claim", "support"],
                                "additionalProperties": False
                            }
                        }
                    },
                    "required": ["hypotheses"],
                    "additionalProperties": False
                }
            }
        }
    )

    usage = response.usage
    text = next(b.text for b in response.content if b.type == "text")
    hypotheses = json.loads(text)["hypotheses"]
    logger.info("llm_reason_complete", extra={"data": {
        "hypothesis_count": len(hypotheses),
        "input_tokens": usage.input_tokens,
        "output_tokens": usage.output_tokens,
        "total_tokens": usage.input_tokens + usage.output_tokens,
        "duration_s": round(time.monotonic() - t0, 3),
    }})
    return hypotheses


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
    tool_outputs = {}
    evidence_found = []

    # 1. file — identify the file type before deeper analysis
    stdout, _, _ = _run_tool(["file", source])
    tool_outputs["file"] = stdout.strip()

    # 2. strings — pull printable sequences; catches IOCs in binaries too
    stdout, _, _ = _run_tool(["strings", source])
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
        stdout, _, rc = _run_tool(["grep", "-iEo", pattern, source])
        if rc == 0 and stdout.strip():
            matches = list(dict.fromkeys(stdout.strip().splitlines()))  # dedupe
            grep_hits.append({"pattern": pattern, "matches": matches})
            evidence_found.append(f"grep '{pattern}': {matches}")
    tool_outputs["grep"] = grep_hits

    # 4. xxd — hex dump; useful for obfuscated or binary artifacts
    stdout, _, _ = _run_tool(["xxd", source])
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
