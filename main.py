import csv
import io
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


# .raw is intentionally absent — it is reserved for memory dumps below.
# Raw disk images should use the .dd extension instead.
DISK_IMAGE_EXTS = frozenset({
    ".dd", ".img", ".e01", ".vmdk", ".vhd", ".vhdx", ".iso",
})

# File types worth pulling out of a disk image for analysis
SUSPICIOUS_EXTS = frozenset({
    ".ps1", ".bat", ".cmd", ".vbs", ".js", ".sh", ".py", ".rb", ".pl",  # scripts
    ".exe", ".dll", ".sys", ".scr", ".com",                              # executables
    ".zip", ".rar", ".7z", ".tar", ".gz", ".cab",                       # archives
    ".log", ".evtx",                                                     # logs
    ".docm", ".xlsm", ".pptm",                                          # macro-enabled Office
    ".pcap", ".pcapng",                                                  # network captures
})

_EXTRACTED_DIR = "extracted"
_MAX_FILES_PER_PARTITION = 100  # guard against images with thousands of matching files

# Memory dump support — Volatility3
MEMORY_DUMP_EXTS = frozenset({".vmem", ".mem", ".raw"})
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
            ext = os.path.splitext(f)[1].lower()
            if ext in MEMORY_DUMP_EXTS:
                # Volatility3 reads the dump directly by path; never load it
                # into RAM. Stream solely to compute the integrity hash.
                sha = hashlib.sha256()
                with open(full_path, "rb") as fh:
                    for chunk in iter(lambda: fh.read(65536), b""):
                        sha.update(chunk)
                evidence_files.append({
                    "path":          full_path,
                    "data":          b"",
                    "hash":          sha.hexdigest(),
                    "size":          os.path.getsize(full_path),
                    "is_disk_image": False,
                    "is_memory_dump": True,
                })
            elif ext in DISK_IMAGE_EXTS:
                # Stream the hash in chunks — disk images can be many gigabytes.
                # Store only the first 512 bytes so magic-byte checks remain possible
                # without loading the entire image into RAM.
                sha = hashlib.sha256()
                header = b""
                with open(full_path, "rb") as fh:
                    for chunk in iter(lambda: fh.read(65536), b""):
                        sha.update(chunk)
                        if not header:
                            header = chunk[:512]
                evidence_files.append({
                    "path":           full_path,
                    "data":           header,
                    "hash":           sha.hexdigest(),
                    "size":           os.path.getsize(full_path),
                    "is_disk_image":  True,
                    "is_memory_dump": False,
                })
            else:
                with open(full_path, "rb") as file:
                    data = file.read()
                evidence_files.append({
                    "path":           full_path,
                    "data":           data,
                    "hash":           hashlib.sha256(data).hexdigest(),
                    "size":           len(data),
                    "is_disk_image":  False,
                    "is_memory_dump": False,
                })
    disk_image_count  = sum(1 for e in evidence_files if e["is_disk_image"])
    memory_dump_count = sum(1 for e in evidence_files if e["is_memory_dump"])
    logger.info("ingest_complete", extra={"data": {
        "file_count":   len(evidence_files),
        "disk_images":  disk_image_count,
        "memory_dumps": memory_dump_count,
        "total_bytes":  sum(e["size"] for e in evidence_files),
        "duration_s":   round(time.monotonic() - t0, 3),
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
        if item.get("is_memory_dump"):
            artifacts.extend(extract_memory_artifacts(item))
            continue

        if item.get("is_disk_image"):
            artifacts.extend(extract_disk_image_artifacts(item))
            continue

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
# 2b. DISK IMAGE ARTIFACT EXTRACTION
# ----------------------------
def _parse_mmls(output):
    """
    Parse mmls partition-table output into a list of partition dicts.

    Skips Meta and unallocated (---) rows; keeps only rows whose slot field
    starts with a digit (e.g. "000", "000:000" for MBR, "002" for GPT).
    """
    partitions = []
    for line in output.splitlines():
        m = re.match(r"^\d+:\s+(\S+)\s+(\d+)\s+\d+\s+\d+\s+(.+)$", line.strip())
        if not m:
            continue
        slot = m.group(1)
        if not re.match(r"\d", slot):   # skip Meta, -------
            continue
        partitions.append({
            "slot":        slot,
            "start":       int(m.group(2)),
            "description": m.group(3).strip(),
        })
    return partitions


def _parse_fls(output):
    """
    Parse fls -r output into a list of file-entry dicts.

    Handles both deleted-file notations used by different TSK versions:
      r/r * 7:   path   (asterisk before inode)
      r/r 7*:    path   (asterisk after inode)

    Returns entries with keys: ftype, inode, path, deleted.
    """
    entries = []
    for line in output.splitlines():
        m = re.match(
            r"^([drclsb\-])/[drclsb\-]\s+(\*\s+)?(\d+)(\*)?\s*:\s+(.+)$",
            line.strip(),
        )
        if not m:
            continue
        entries.append({
            "ftype":   m.group(1),
            "inode":   int(m.group(3)),
            "path":    m.group(5).strip(),
            "deleted": (m.group(2) is not None) or (m.group(4) is not None),
        })
    return entries


def extract_disk_image_artifacts(item):
    """
    Extract forensic artifacts from a disk image using mmls, fls, and icat.

    Pipeline:
      1. mmls  — list partitions and their byte offsets
      2. fls -r — recursively enumerate files in each partition's filesystem
      3. icat  — extract individual files by inode number

    Suspicious files (matched by SUSPICIOUS_EXTS) are written to
    extracted/<image_stem>/partition_<slot>/ so that the existing
    verify_hypothesis() tools (file, strings, grep, xxd) work on them
    without any changes. The source field in returned artifacts points to
    those extracted paths, preserving the path:lineno convention used
    throughout the rest of the pipeline.

    Falls back to offset 0 if mmls cannot find a partition table (e.g. a
    bare filesystem image with no partition wrapper).
    """
    image_path = item["path"]
    image_stem = os.path.splitext(os.path.basename(image_path))[0]
    artifacts = []

    logger.info("disk_image_start", extra={"data": {
        "image": image_path,
        "size":  item["size"],
        "hash":  item["hash"],
    }})

    # ── Step 1: partition table ────────────────────────────────────────────
    stdout, stderr, rc = _run_tool(["mmls", image_path])
    if rc != 0:
        logger.warning("disk_image_mmls_failed", extra={"data": {
            "image":      image_path,
            "returncode": rc,
            "stderr":     stderr.strip(),
        }})
        # Bare filesystem image — try the whole image as a single filesystem
        partitions = [{"slot": "bare", "start": 0, "description": "no partition table"}]
    else:
        partitions = _parse_mmls(stdout)

    if not partitions:
        logger.warning("disk_image_no_partitions", extra={"data": {"image": image_path}})
        return artifacts

    logger.info("disk_image_partitions", extra={"data": {
        "image":      image_path,
        "count":      len(partitions),
        "partitions": partitions,
    }})

    # ── Step 2: enumerate files in each partition ──────────────────────────
    for partition in partitions:
        offset      = partition["start"]
        slot_label  = partition["slot"].replace(":", "_")
        extract_dir = os.path.join(_EXTRACTED_DIR, image_stem, f"partition_{slot_label}")
        os.makedirs(extract_dir, exist_ok=True)

        stdout, stderr, rc = _run_tool(["fls", "-r", "-o", str(offset), image_path])
        if rc != 0:
            logger.warning("disk_image_fls_failed", extra={"data": {
                "image":  image_path,
                "slot":   partition["slot"],
                "offset": offset,
                "stderr": stderr.strip(),
            }})
            continue

        all_entries = _parse_fls(stdout)
        suspicious = [
            e for e in all_entries
            if e["ftype"] == "r"
            and os.path.splitext(e["path"])[1].lower() in SUSPICIOUS_EXTS
        ]

        if len(suspicious) > _MAX_FILES_PER_PARTITION:
            logger.warning("disk_image_file_limit_hit", extra={"data": {
                "image":            image_path,
                "slot":             partition["slot"],
                "suspicious_found": len(suspicious),
                "limit":            _MAX_FILES_PER_PARTITION,
            }})
            suspicious = suspicious[:_MAX_FILES_PER_PARTITION]

        logger.info("disk_image_fls_complete", extra={"data": {
            "image":           image_path,
            "slot":            partition["slot"],
            "offset":          offset,
            "description":     partition["description"],
            "total_entries":   len(all_entries),
            "suspicious_count": len(suspicious),
        }})

        # ── Step 3: extract each suspicious file with icat ─────────────────
        for entry in suspicious:
            inode    = entry["inode"]
            filename = os.path.basename(entry["path"].rstrip("/\\")) or f"inode_{inode}"
            del_tag  = ".deleted" if entry["deleted"] else ""
            extract_path = os.path.join(
                extract_dir, f"inode_{inode}_{filename}{del_tag}"
            )

            file_bytes, stderr, rc = _run_tool_binary(
                ["icat", "-o", str(offset), image_path, str(inode)]
            )
            if rc != 0 or not file_bytes:
                logger.warning("disk_image_icat_failed", extra={"data": {
                    "image":  image_path,
                    "slot":   partition["slot"],
                    "inode":  inode,
                    "path":   entry["path"],
                    "stderr": stderr.strip(),
                }})
                continue

            with open(extract_path, "wb") as fh:
                fh.write(file_bytes)

            logger.info("disk_image_file_extracted", extra={"data": {
                "image":        image_path,
                "slot":         partition["slot"],
                "inode":        inode,
                "image_path":   entry["path"],
                "extracted_to": extract_path,
                "size":         len(file_bytes),
                "sha256":       hashlib.sha256(file_bytes).hexdigest(),
                "deleted":      entry["deleted"],
            }})

            # Run the same keyword rules as extract_artifacts() on the
            # extracted file's text content. Source uses the extracted path
            # so verify_hypothesis() receives a real filesystem path.
            text = file_bytes.decode(errors="ignore")
            for lineno, line in enumerate(text.splitlines(), start=1):
                source = f"{extract_path}:{lineno}"
                low    = line.lower()
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

    logger.info("disk_image_complete", extra={"data": {
        "image":          image_path,
        "artifact_count": len(artifacts),
    }})
    return artifacts


# ----------------------------
# 2c. MEMORY DUMP ARTIFACT EXTRACTION  (Volatility3)
# ----------------------------
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
                "hint":    f"install Volatility3 or set _VOL3_CMD in main.py",
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

    # One artifact gives the LLM a process-list event in the timeline.
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


def _run_tool_binary(cmd, timeout=30):
    """Like _run_tool but returns stdout as raw bytes (required for icat)."""
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout)
        return r.stdout, r.stderr.decode(errors="ignore"), r.returncode
    except FileNotFoundError:
        return b"", f"tool not found: {cmd[0]}", 127
    except subprocess.TimeoutExpired:
        return b"", "timeout", 1


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
