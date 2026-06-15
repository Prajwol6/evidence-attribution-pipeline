from utils import logger, _run_tool, _is_rfc1918, _IP_RE


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
        return None

    return {
        "evidence_found": evidence_found,
        "grep_hits": grep_hits,
        "file_type": tool_outputs["file"],
    }
