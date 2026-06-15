import csv
import io
import os

from utils import logger, _run_tool

_EXTRACTED_DIR = "extracted"
_VOL3_CMD = "vol3"  # set to "vol" or "python3 /opt/volatility3/vol.py" if needed

# Process names that are unambiguously malicious when seen in a process list
_KNOWN_BAD_PROCS = frozenset({
    "mimikatz.exe", "meterpreter", "cobaltstrike", "ncat.exe",   "nc.exe",
    "netcat.exe",   "psexec.exe",  "wce.exe",      "pwdump.exe", "gsecdump.exe",
    "fgdump.exe",   "lsadump",     "procdump.exe", "wmiexec.py", "empire",
})

# Windows processes with well-known, fixed parent relationships.
# A mismatch is a strong lateral-movement or process-hollowing indicator.
_EXPECTED_PARENTS = {
    "svchost.exe":  {"services.exe", "wininit.exe"},
    "lsass.exe":    {"wininit.exe"},
    "smss.exe":     {"system"},
    "csrss.exe":    {"smss.exe"},
    "wininit.exe":  {"smss.exe"},
    "userinit.exe": {"winlogon.exe"},
}


def _parse_vol_csv(output):
    """
    Parse Volatility3 --renderer csv output into a list of row dicts.

    Volatility3 writes the framework banner and progress to stderr; stdout
    should be clean CSV. Restricting to lines that start with '"' makes the
    parser tolerant of any stray informational lines that reach stdout across
    different Volatility3 versions.
    """
    csv_lines = [l for l in output.splitlines() if l.lstrip().startswith('"')]
    if not csv_lines:
        return []
    try:
        return list(csv.DictReader(io.StringIO("\n".join(csv_lines))))
    except csv.Error:
        return []


def _vol(image_path, plugin, timeout=120):
    """
    Run a single Volatility3 plugin with CSV output.
    Returns (rows, raw_stdout, stderr, returncode).
    """
    stdout, stderr, rc = _run_tool(
        [_VOL3_CMD, "-f", image_path, "--renderer", "csv", plugin],
        timeout=timeout,
    )
    return _parse_vol_csv(stdout), stdout, stderr, rc


def _flag_suspicious(rows, pid_field, ppid_field, name_field):
    """
    Apply lightweight heuristic rules to a list of Volatility3 process rows.

    Rules:
      1. Name matches a known malicious tool (_KNOWN_BAD_PROCS).
      2. Windows process has an unexpected parent (_EXPECTED_PARENTS).
         A mismatch indicates process spoofing or lateral movement.
      3. More than one lsass.exe instance — classic process-hollowing sign.

    Returns a list of (row, reasons) tuples for every flagged process.
    """
    pid_to_name: dict[int, str] = {}
    for row in rows:
        try:
            pid  = int(row.get(pid_field) or -1)
            name = (row.get(name_field) or "").strip().lower()
            pid_to_name[pid] = name
        except (ValueError, TypeError):
            pass

    lsass_count = sum(
        1 for r in rows
        if (r.get(name_field) or "").strip().lower() == "lsass.exe"
    )

    flagged = []
    for row in rows:
        name       = (row.get(name_field) or "").strip()
        name_lower = name.lower()
        reasons: list[str] = []

        if name_lower in _KNOWN_BAD_PROCS:
            reasons.append(f"known malicious process name: {name}")

        if name_lower in _EXPECTED_PARENTS:
            try:
                ppid     = int(row.get(ppid_field) or -1)
                expected = _EXPECTED_PARENTS[name_lower]
                if ppid > 4:
                    parent_name = pid_to_name.get(ppid)   # None if absent
                    if parent_name is None:
                        # Parent PID not in process list — hidden or terminated
                        # parent is a stronger indicator than a wrong-name parent.
                        reasons.append(
                            f"PPID anomaly: {name} PPID {ppid} absent from "
                            f"process list (expected parent in {sorted(expected)})"
                        )
                    elif parent_name not in expected:
                        reasons.append(
                            f"PPID anomaly: {name} parented by '{parent_name}' "
                            f"(expected {sorted(expected)})"
                        )
            except (ValueError, TypeError):
                pass

        if name_lower == "lsass.exe" and lsass_count > 1:
            reasons.append(
                f"multiple lsass.exe instances ({lsass_count})"
                " — possible process hollowing"
            )

        if reasons:
            flagged.append((row, reasons))

    return flagged


def extract_memory_artifacts(item):
    """
    Analyse a memory dump with Volatility3 and return forensic artifacts.

    Steps:
      1. Auto-detect OS by trying Windows then Linux pslist plugins.
      2. Write the full pslist CSV to extracted/<stem>/pslist.txt; emit one
         memory_process_list artifact so the LLM sees it in the timeline.
      3. Apply _flag_suspicious() heuristics; write hits to
         extracted/<stem>/suspicious_procs.txt and emit one
         memory_suspicious_process artifact per flagged process.
      4. Run the matching OS netstat plugin; write to netstat.txt and emit
         one memory_network_connection artifact per connection row.

    Source paths in all returned artifacts point to real files under
    extracted/ so verify_hypothesis() can run file/strings/grep/xxd on them
    without modification.
    """
    image_path  = item["path"]
    image_stem  = os.path.splitext(os.path.basename(image_path))[0]
    extract_dir = os.path.join(_EXTRACTED_DIR, image_stem)
    os.makedirs(extract_dir, exist_ok=True)
    artifacts: list[tuple] = []

    logger.info("memory_dump_start", extra={"data": {
        "image": image_path,
        "size":  item["size"],
        "hash":  item["hash"],
    }})

    # ── Step 1: detect OS via pslist ──────────────────────────────────────
    os_candidates = [
        ("windows", "windows.pslist.PsList", "PID", "PPID", "ImageFileName"),
        ("linux",   "linux.pslist.PsList",   "PID", "PPID", "COMM"),
    ]
    detected_os                    = None
    proc_rows: list[dict]          = []
    pslist_raw                     = ""
    pid_f = ppid_f = name_f        = ""

    for os_name, plugin, pf, ppf, nf in os_candidates:
        rows, raw, stderr, rc = _vol(image_path, plugin)
        if rc == 127:
            # vol3 binary not found — abort rather than trying every plugin
            logger.warning("memory_dump_vol3_not_found", extra={"data": {
                "image":   image_path,
                "command": _VOL3_CMD,
                "hint":    "install Volatility3 or set _VOL3_CMD in extract_memory.py",
            }})
            return artifacts
        if rc == 0 and rows:
            detected_os              = os_name
            proc_rows, pslist_raw    = rows, raw
            pid_f, ppid_f, name_f   = pf, ppf, nf
            break

    if not detected_os:
        logger.warning("memory_dump_os_undetected", extra={"data": {
            "image": image_path,
            "hint":  "neither windows.pslist nor linux.pslist returned data; "
                     "verify the dump is a supported format and Volatility3 "
                     "symbols are available",
        }})
        return artifacts

    logger.info("memory_dump_os_detected", extra={"data": {
        "image":      image_path,
        "os":         detected_os,
        "proc_count": len(proc_rows),
    }})

    # ── Step 2: process list ──────────────────────────────────────────────
    pslist_path = os.path.join(extract_dir, "pslist.txt")
    with open(pslist_path, "w") as fh:
        fh.write(pslist_raw)

    artifacts.append((
        "memory_process_list",
        f"{pslist_path}:1",
        f"process list from {image_path} ({len(proc_rows)} processes, OS: {detected_os})",
    ))

    # ── Step 3: suspicious process heuristics ─────────────────────────────
    flagged = _flag_suspicious(proc_rows, pid_f, ppid_f, name_f)

    if flagged:
        susp_path = os.path.join(extract_dir, "suspicious_procs.txt")
        with open(susp_path, "w") as fh:
            for row, reasons in flagged:
                fh.write(
                    f"{row.get(name_f, '')} "
                    f"PID:{row.get(pid_f, '')} "
                    f"PPID:{row.get(ppid_f, '')} "
                    f"— {'; '.join(reasons)}\n"
                )

        for lineno, (row, reasons) in enumerate(flagged, start=1):
            name = (row.get(name_f)  or "").strip()
            pid  = (row.get(pid_f)   or "").strip()
            ppid = (row.get(ppid_f)  or "").strip()
            line = f"{name} PID:{pid} PPID:{ppid} — {'; '.join(reasons)}"
            artifacts.append((
                "memory_suspicious_process",
                f"{susp_path}:{lineno}",
                line,
            ))
            logger.info("memory_suspicious_process_flagged", extra={"data": {
                "image":   image_path,
                "process": name,
                "pid":     pid,
                "reasons": reasons,
            }})

    logger.info("memory_pslist_complete", extra={"data": {
        "image":             image_path,
        "os":                detected_os,
        "total_processes":   len(proc_rows),
        "flagged_processes": len(flagged),
    }})

    # ── Step 4: network connections ───────────────────────────────────────
    net_plugin = (
        "windows.netstat.NetStat" if detected_os == "windows"
        else "linux.netstat.Netstat"
    )
    net_rows, netstat_raw, netstat_stderr, net_rc = _vol(image_path, net_plugin)

    if net_rc != 0:
        logger.warning("memory_dump_netstat_failed", extra={"data": {
            "image":  image_path,
            "plugin": net_plugin,
            "stderr": netstat_stderr.strip(),
        }})
    else:
        netstat_path = os.path.join(extract_dir, "netstat.txt")
        with open(netstat_path, "w") as fh:
            fh.write(netstat_raw)

        for lineno, row in enumerate(net_rows, start=1):
            proto        = (row.get("Proto")       or row.get("Type",  "")).strip()
            local_addr   = (row.get("LocalAddr")   or "").strip()
            local_port   = (row.get("LocalPort")   or "").strip()
            foreign_addr = (row.get("ForeignAddr") or "").strip()
            foreign_port = (row.get("ForeignPort") or "").strip()
            state        = (row.get("State")       or "").strip()
            owner        = (row.get("Owner")       or row.get("Comm", "")).strip()
            pid          = (row.get("PID")         or "").strip()
            created      = (row.get("Created")     or "").strip()

            # Include Created timestamp so _parse_ts() can sort this event
            # on the forensic timeline relative to process creation times.
            line = (
                f"{created} {proto} "
                f"{local_addr}:{local_port} -> {foreign_addr}:{foreign_port} "
                f"[{state}] {owner} PID:{pid}"
            ).strip()
            artifacts.append((
                "memory_network_connection",
                f"{netstat_path}:{lineno}",
                line,
            ))

        logger.info("memory_netstat_complete", extra={"data": {
            "image":       image_path,
            "connections": len(net_rows),
        }})

    logger.info("memory_dump_complete", extra={"data": {
        "image":          image_path,
        "artifact_count": len(artifacts),
    }})
    return artifacts
