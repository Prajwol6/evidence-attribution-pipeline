import os
import textwrap
from collections import defaultdict

from utils import logger

_MATCH_LABEL = {
    "hash":      "HASH MATCH",
    "filename":  "FILENAME MATCH",
    "technique": "TECHNIQUE MATCH",
}

# ATT&CK base technique ID → kill chain phase
_TECHNIQUE_PHASE = {
    "T1566": "Initial Access",     "T1190": "Initial Access",
    "T1133": "Initial Access",     "T1189": "Initial Access",
    "T1091": "Initial Access",     "T1195": "Initial Access",
    "T1199": "Initial Access",     "T1078": "Initial Access",
    "T1059": "Execution",          "T1204": "Execution",
    "T1072": "Execution",          "T1047": "Execution",
    "T1053": "Execution",
    "T1547": "Persistence",        "T1543": "Persistence",
    "T1546": "Persistence",        "T1197": "Persistence",
    "T1176": "Persistence",        "T1556": "Persistence",
    "T1055": "Privilege Escalation", "T1068": "Privilege Escalation",
    "T1134": "Privilege Escalation", "T1484": "Privilege Escalation",
    "T1070": "Defense Evasion",    "T1036": "Defense Evasion",
    "T1027": "Defense Evasion",    "T1218": "Defense Evasion",
    "T1562": "Defense Evasion",
    "T1003": "Credential Access",  "T1110": "Credential Access",
    "T1555": "Credential Access",  "T1558": "Credential Access",
    "T1057": "Discovery",          "T1083": "Discovery",
    "T1049": "Discovery",          "T1087": "Discovery",
    "T1021": "Lateral Movement",   "T1080": "Lateral Movement",
    "T1534": "Lateral Movement",
    "T1005": "Collection",         "T1056": "Collection",
    "T1074": "Collection",
    "T1071": "Command and Control", "T1090": "Command and Control",
    "T1095": "Command and Control", "T1102": "Command and Control",
    "T1105": "Command and Control",
    "T1041": "Exfiltration",       "T1048": "Exfiltration",
    "T1567": "Exfiltration",
    "T1486": "Impact",             "T1490": "Impact",
    "T1565": "Impact",
}

_PHASE_ORDER = [
    "Initial Access", "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery",
    "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact",
]

_TECHNIQUE_ACTIONS = {
    "T1003": "Reset all potentially exposed credentials and enable Credential Guard on Windows endpoints.",
    "T1027": "Scan for encoded/obfuscated payloads across email, web, and endpoint telemetry.",
    "T1036": "Verify binary signatures and compare running processes against known-good baselines.",
    "T1041": "Monitor and restrict large outbound data transfers; deploy data loss prevention controls.",
    "T1047": "Restrict WMI access; monitor for unusual WMI activity in endpoint telemetry.",
    "T1053": "Audit all scheduled tasks and cron jobs for unauthorized or modified entries.",
    "T1055": "Audit for memory injection; deploy endpoint detection with memory-scanning capabilities.",
    "T1059": "Restrict PowerShell and scripting engine execution policies; enable Script Block Logging.",
    "T1070": "Preserve and archive all relevant logs immediately to prevent further tampering.",
    "T1071": "Block or alert on outbound connections to non-standard ports; inspect TLS SNI for anomalies.",
    "T1078": "Rotate all potentially compromised credentials; audit recent account creation and privilege grants.",
    "T1105": "Block known C2 infrastructure at the perimeter; inspect all files dropped from remote sources.",
    "T1110": "Enforce MFA on all accounts; implement account lockout policies and monitor for brute-force patterns.",
    "T1190": "Patch internet-facing services promptly; review WAF and IDS alert backlogs for prior exploitation.",
    "T1486": "Isolate affected systems immediately and initiate backup recovery procedures.",
    "T1547": "Audit startup locations, registry run keys, and scheduled tasks for unauthorized persistence.",
    "T1566": "Retrain users on phishing identification and tighten email gateway filtering rules.",
}


def _extract_host(source: str) -> str:
    path = source.rsplit(":", 1)[0]
    parts = path.replace("\\", "/").split("/")
    if len(parts) >= 2 and parts[0] == "extracted":
        return parts[1]
    if len(parts) >= 2 and parts[0] == "evidence":
        return os.path.splitext(parts[1])[0]
    return os.path.splitext(os.path.basename(path))[0]


def _get_phase(attck_id: str) -> str:
    if not attck_id:
        return "Unknown"
    return _TECHNIQUE_PHASE.get(attck_id.split(".")[0], "Unknown")


def _wrap(text, width=74, indent=""):
    return textwrap.fill(
        text, width=width,
        initial_indent=indent, subsequent_indent=indent,
    )


def generate_report(verified, correlations, scan_stats=None):
    logger.info("report_start", extra={"data": {
        "verified_count":    len(verified),
        "correlation_count": len(correlations),
    }})

    lines = []

    # ── Derived metadata ──────────────────────────────────────────────────────
    all_hosts: set[str] = set()
    for c in correlations:
        all_hosts.update(c["hosts"])
    for item in verified:
        all_hosts.add(_extract_host(item["support"]))

    confirmed = [v for v in verified if v.get("confidence") == "CONFIRMED"]
    probable  = [v for v in verified if v.get("confidence") == "PROBABLE"]
    techniques = {v["attck_id"] for v in verified if v.get("attck_id")}
    phases_seen = {_get_phase(t) for t in techniques} - {"Unknown"}
    phase_str = ", ".join(p for p in _PHASE_ORDER if p in phases_seen)

    # ── Header ────────────────────────────────────────────────────────────────
    lines += [
        "=" * 72,
        "INCIDENT REPORT — FORENSIC ANALYSIS",
        "=" * 72,
        "",
    ]

    _sec = 1  # rolling section counter

    # ── 1. Executive Summary ──────────────────────────────────────────────────
    lines += [f"{_sec}. EXECUTIVE SUMMARY", "-" * 40, ""]
    _sec += 1

    host_list = ", ".join(sorted(all_hosts)) if all_hosts else "an unidentified system"
    sentence1 = (
        f"Forensic analysis of evidence collected from {len(all_hosts)} host(s) "
        f"({host_list}) identified {len(verified)} finding(s) covering "
        f"{len(techniques)} MITRE ATT&CK technique(s)."
    )

    if confirmed and probable:
        sentence2 = (
            f"{len(confirmed)} finding(s) are CONFIRMED with direct forensic evidence "
            f"and {len(probable)} are rated PROBABLE; the remainder require further investigation."
        )
    elif confirmed:
        sentence2 = (
            f"{len(confirmed)} of {len(verified)} finding(s) are CONFIRMED with direct "
            f"forensic evidence; remaining findings are unverified."
        )
    elif probable:
        sentence2 = (
            f"No findings were fully confirmed; {len(probable)} are rated PROBABLE "
            f"based on corroborating evidence."
        )
    else:
        sentence2 = "No findings have been confirmed or rated probable at this time."

    sentence3 = (
        f"Observed activity spans the following attack phases: {phase_str}."
        if phase_str else
        "The attack phases could not be determined from available evidence."
    )

    lines.append(_wrap(f"{sentence1} {sentence2} {sentence3}"))

    if correlations:
        lines.append("")
        lines.append(_wrap(
            f"Cross-host correlation identified {len(correlations)} shared indicator(s) "
            f"across {len(all_hosts)} host(s), indicating coordinated or propagating activity."
        ))

    lines.append("")

    # ── 2. YARA Scan Statistics (conditional) ─────────────────────────────────
    if scan_stats and scan_stats.get("files_scanned", 0) > 0:
        lines += [f"{_sec}. YARA SCAN STATISTICS", "-" * 40, ""]
        _sec += 1
        w = 22  # label column width
        lines += [
            f"  {'Artifacts scanned':<{w}}: {scan_stats['files_scanned']}",
            f"  {'YARA matches':<{w}}: {scan_stats['yara_matches']}",
            f"  {'Confirmed malicious':<{w}}: {scan_stats['confirmed_malicious']}"
            f"  (≥ 2 rules matched)",
            f"  {'Suspicious only':<{w}}: {scan_stats['suspicious_only']}"
            f"  (1 rule matched)",
            f"  {'Scan errors':<{w}}: {scan_stats['errors']}",
            f"  {'Skipped — too large':<{w}}: {scan_stats['skipped_large']}",
            f"  {'Corrupted files':<{w}}: {scan_stats['corrupted']}",
            f"  {'Scan timeouts':<{w}}: {scan_stats['timeouts']}",
            "",
        ]

    # ── Attack Timeline ───────────────────────────────────────────────────────
    lines += [f"{_sec}. ATTACK TIMELINE", "-" * 40, ""]
    _sec += 1
    lines.append(_wrap(
        "The following narrative reconstructs the attack progression from collected "
        "forensic evidence. Events are organized by kill chain phase and listed in "
        "discovery order within each phase. Where source timestamps were unavailable, "
        "ordering reflects evidence sequence rather than wall-clock time."
    ))
    lines.append("")

    phase_findings: dict[str, list] = defaultdict(list)
    for item in verified:
        phase_findings[_get_phase(item.get("attck_id", ""))].append(item)

    ordered_phases = [p for p in _PHASE_ORDER if p in phase_findings]
    if "Unknown" in phase_findings:
        ordered_phases.append("Unknown")

    step = 1
    for phase in ordered_phases:
        lines.append(f"  [{phase.upper()}]")
        for item in phase_findings[phase]:
            host = _extract_host(item["support"])
            conf = item.get("confidence", "")
            conf_tag = f" — {conf}" if conf else ""
            tech_tag = (
                f" [{item['attck_id']}: {item['attck_name']}]"
                if item.get("attck_id") else ""
            )
            lines.append(f"  {step:>2}. [{host}] {item['claim']}{conf_tag}{tech_tag}")
            step += 1
        lines.append("")

    # ── Technical Findings ────────────────────────────────────────────────────
    lines += [f"{_sec}. TECHNICAL FINDINGS", "-" * 40, ""]
    _sec += 1
    lines.append(_wrap(
        "Findings are grouped first by host and then by attack phase. Each entry "
        "includes the associated MITRE ATT&CK technique, confidence rating, and "
        "the forensic evidence source."
    ))
    lines.append("")

    by_host: dict[str, list] = defaultdict(list)
    for item in verified:
        by_host[_extract_host(item["support"])].append(item)

    for host in sorted(by_host):
        lines += [f"  Host: {host}", f"  {'─' * 44}"]

        host_phase: dict[str, list] = defaultdict(list)
        for item in by_host[host]:
            host_phase[_get_phase(item.get("attck_id", ""))].append(item)

        host_phases = [p for p in _PHASE_ORDER if p in host_phase]
        if "Unknown" in host_phase:
            host_phases.append("Unknown")

        for phase in host_phases:
            lines.append(f"  [{phase}]")
            for item in host_phase[phase]:
                tech = (
                    f"[{item['attck_id']}] {item['attck_name']}"
                    if item.get("attck_id") else "Technique unknown"
                )
                conf = item.get("confidence", "N/A")
                lines += [
                    f"    Finding    : {item['claim']}",
                    f"    ATT&CK     : {tech}",
                    f"    Confidence : {conf}",
                    f"    Source     : {item['support']}",
                    "",
                ]

    if correlations:
        lines += ["  Cross-Host Correlations", f"  {'─' * 44}", ""]
        for c in correlations:
            label = _MATCH_LABEL.get(c["match_type"], c["match_type"].upper())
            if c["match_type"] == "hash":
                header = f"  [{label}] SHA256: {c['value']}"
            elif c["match_type"] == "filename":
                header = f"  [{label}] {c['value']}"
            else:
                header = f"  [{label}] [{c['value']}] {c['attck_name']}"
            lines.append(header)
            lines.append(f"  Hosts involved : {', '.join(c['hosts'])}")
            for entry in c["findings"]:
                lines.append(f"    - [{entry['host']}] {entry['claim']}")
            lines.append("")

    # ── Recommended Actions ───────────────────────────────────────────────────
    lines += [f"{_sec}. RECOMMENDED ACTIONS", "-" * 40, ""]
    lines.append(_wrap(
        "The following actions are prioritized based on the techniques identified "
        "in this investigation. Address CONFIRMED findings first, then PROBABLE. "
        "All recommendations should be reviewed with the relevant system owners "
        "before implementation."
    ))
    lines.append("")

    seen_actions: set[str] = set()
    action_num = 1
    for t in sorted(techniques):
        action = _TECHNIQUE_ACTIONS.get(t.split(".")[0])
        if not action or action in seen_actions:
            continue
        seen_actions.add(action)
        tech_name = next(
            (v["attck_name"] for v in verified if v.get("attck_id", "").split(".")[0] == t.split(".")[0]),
            "",
        )
        label = f"{t} — {tech_name}" if tech_name else t
        lines.append(f"  {action_num}. [{label}]")
        lines.append(_wrap(action, indent="     "))
        lines.append("")
        action_num += 1

    if action_num == 1:
        lines.append(
            "  No specific remediation rules matched the detected techniques. "
            "Consult the MITRE ATT&CK framework for guidance."
        )
        lines.append("")

    lines.append(f"  {action_num}. [Evidence Preservation]")
    lines.append(_wrap(
        "Preserve all forensic images, logs, memory dumps, and artifacts in a "
        "secure, write-protected location. Maintain chain-of-custody documentation "
        "for any evidence that may be used in legal or disciplinary proceedings.",
        indent="     ",
    ))
    lines.append("")

    lines += ["=" * 72, "END OF REPORT", "=" * 72]

    output = "\n".join(lines)

    with open("report.txt", "w") as f:
        f.write(output)

    logger.info("report_complete", extra={"data": {"output_path": "report.txt"}})
    print(output)
