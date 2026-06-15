import math
import os
import subprocess
import tempfile
from collections import Counter
from dataclasses import dataclass

try:
    import yara as _yara
    _YARA_AVAILABLE = True
except ImportError:
    _YARA_AVAILABLE = False

from utils import logger, _IP_RE, _is_rfc1918

# ── Rule discovery ─────────────────────────────────────────────────────────────

_RULE_SEARCH_PATHS = [
    "/usr/share/yara",
    "/usr/local/share/yara",
    "/etc/yara",
    "/usr/share/windows-resources/mimikatz",
    "/opt/yara-rules",
]

# ── Thresholds and limits ──────────────────────────────────────────────────────

_MAX_FILE_SIZE          = 50 * 1024 * 1024  # 50 MB — skip larger files
_SCAN_TIMEOUT_S         = 30               # per-file YARA timeout (seconds)
_HIGH_ENTROPY_THRESHOLD = 7.0              # whole-file Shannon entropy (max 8.0)
_HIGH_ENTROPY_BLOCK     = 7.5              # per-4 KB block threshold
_BLOCK_SIZE             = 4096
_MAX_RECURSE_DEPTH      = 2                # max archive-in-archive depth
_MAX_ARCHIVE_FILES      = 20              # max files extracted per archive

# ── Suspicious Windows API imports ────────────────────────────────────────────

_SUSPICIOUS_IMPORTS = frozenset({
    # Process / memory injection
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect",
    "WriteProcessMemory", "ReadProcessMemory",
    "CreateRemoteThread", "RtlCreateUserThread", "NtCreateThreadEx",
    "OpenProcess", "NtOpenProcess",
    "NtUnmapViewOfSection", "ZwUnmapViewOfSection",
    # Keylogging / input capture
    "SetWindowsHookEx", "GetAsyncKeyState",
    # Crypto (ransomware / exfil)
    "CryptEncrypt", "CryptDecrypt",
    # Network download
    "URLDownloadToFile", "InternetOpenUrl", "HttpOpenRequest",
    # Persistence via registry
    "RegSetValueEx", "RegCreateKeyEx",
    # Anti-analysis
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
    # Launchers
    "ShellExecuteA", "ShellExecuteW", "ShellExecuteExW",
})

_COMPILED_RULES = None  # lazy-loaded list of (path, yara.Rules) pairs


# ── Scan-run statistics ────────────────────────────────────────────────────────

@dataclass
class _ScanStats:
    files_scanned:      int = 0
    yara_matches:       int = 0   # files with ≥ 1 rule match
    confirmed_malicious: int = 0  # files with ≥ 2 distinct rules matched
    suspicious_only:    int = 0   # files with exactly 1 rule matched
    errors:             int = 0
    skipped_large:      int = 0
    corrupted:          int = 0
    timeouts:           int = 0


_stats = _ScanStats()


def get_scan_stats() -> dict:
    """Return a snapshot of scanning statistics for the current run."""
    return {
        "files_scanned":       _stats.files_scanned,
        "yara_matches":        _stats.yara_matches,
        "confirmed_malicious": _stats.confirmed_malicious,
        "suspicious_only":     _stats.suspicious_only,
        "errors":              _stats.errors,
        "skipped_large":       _stats.skipped_large,
        "corrupted":           _stats.corrupted,
        "timeouts":            _stats.timeouts,
    }


# ── Rule loading ───────────────────────────────────────────────────────────────

def _discover_rule_files() -> list[str]:
    paths = list(_RULE_SEARCH_PATHS)
    env_extra = os.environ.get("YARA_RULES_DIR")
    if env_extra:
        paths.insert(0, env_extra)
    found = []
    for root in paths:
        if not os.path.isdir(root):
            continue
        for dirpath, _, filenames in os.walk(root):
            for fname in sorted(filenames):
                if fname.lower().endswith((".yar", ".yara")):
                    found.append(os.path.join(dirpath, fname))
    return found


def _load_rules() -> list[tuple]:
    if not _YARA_AVAILABLE:
        logger.warning("yara_unavailable", extra={"data": {"reason": "yara-python not installed"}})
        return []
    rule_files = _discover_rule_files()
    if not rule_files:
        logger.warning("yara_no_rules_found", extra={"data": {"searched": _RULE_SEARCH_PATHS}})
        return []
    compiled = []
    for path in rule_files:
        try:
            compiled.append((path, _yara.compile(filepath=path)))
            logger.info("yara_rules_loaded", extra={"data": {"file": path}})
        except _yara.SyntaxError as exc:
            logger.warning("yara_compile_error", extra={"data": {"file": path, "error": str(exc)}})
    logger.info("yara_rules_ready", extra={"data": {
        "loaded": len(compiled),
        "failed": len(rule_files) - len(compiled),
    }})
    return compiled


def _get_rules() -> list[tuple]:
    global _COMPILED_RULES
    if _COMPILED_RULES is None:
        _COMPILED_RULES = _load_rules()
    return _COMPILED_RULES


# ── Analysis helpers ───────────────────────────────────────────────────────────

def _compute_entropy(data: bytes) -> float:
    """Shannon entropy in bits-per-byte (0.0 – 8.0)."""
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _check_entropy(data: bytes) -> tuple[bool, float]:
    """
    Return (is_high, max_entropy_seen).
    Checks whole-file entropy and scans 4 KB blocks for localised anomalies.
    """
    whole = _compute_entropy(data)
    if whole >= _HIGH_ENTROPY_THRESHOLD:
        return True, whole
    max_block = whole
    for i in range(0, len(data), _BLOCK_SIZE):
        block_e = _compute_entropy(data[i : i + _BLOCK_SIZE])
        if block_e > max_block:
            max_block = block_e
        if block_e >= _HIGH_ENTROPY_BLOCK:
            return True, block_e
    return False, max_block


def _analyze_strings(file_path: str) -> tuple[list[str], list[str]]:
    """
    Single strings(1) pass over the file.
    Returns (suspicious_imports, external_ips), both deduplicated.
    """
    try:
        result = subprocess.run(
            ["strings", "-a", file_path],
            capture_output=True, text=True, timeout=30,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return [], []

    imports: list[str] = []
    ext_ips: list[str] = []
    for line in result.stdout.splitlines():
        token = line.strip()
        if token in _SUSPICIOUS_IMPORTS:
            imports.append(token)
        for ip in _IP_RE.findall(token):
            if not _is_rfc1918(ip):
                ext_ips.append(ip)

    return list(dict.fromkeys(imports)), list(dict.fromkeys(ext_ips))


# ── Match formatting ───────────────────────────────────────────────────────────

def _decode_match_data(raw: bytes) -> str:
    """Produce a readable string from raw YARA matched bytes."""
    # Try UTF-8 (plain ASCII / text strings)
    try:
        text = raw.decode("utf-8", errors="strict")
        if sum(1 for c in text if c.isprintable()) >= len(text) * 0.7:
            return text
    except UnicodeDecodeError:
        pass
    # Try UTF-16-LE (YARA 'wide' strings)
    try:
        text = raw.decode("utf-16-le", errors="strict").replace("\x00", "")
        if text and sum(1 for c in text if c.isprintable()) >= len(text) * 0.7:
            return text
    except (UnicodeDecodeError, ValueError):
        pass
    # Binary patterns — show hex
    return raw.hex()


def _format_match_strings(match) -> list[str]:
    parts = []
    for sm in match.strings:
        for inst in sm.instances:
            value = _decode_match_data(inst.matched_data)
            if len(value) > 60:
                value = value[:60] + "…"
            parts.append(f"{sm.identifier} = {value!r}")
    return parts


# ── Core scan ──────────────────────────────────────────────────────────────────

def _run_all_rules(file_path: str) -> tuple[list, str | None]:
    """
    Run every loaded rule file against file_path with a per-file timeout.
    Returns (flat_match_list, error_reason_or_None).
    Aggregates matches across all rule files so the caller sees one list.
    """
    rules = _get_rules()
    if not rules:
        return [], None

    all_matches: list = []
    for rule_file, compiled in rules:
        try:
            all_matches.extend(compiled.match(file_path, timeout=_SCAN_TIMEOUT_S))
        except _yara.TimeoutError:
            logger.warning("yara_timeout", extra={"data": {
                "file": file_path, "rule_file": rule_file,
            }})
            _stats.timeouts += 1
            return [], "timeout"
        except _yara.Error as exc:
            err = str(exc)
            low = err.lower()
            if any(kw in low for kw in ("could not open", "corrupt", "invalid", "truncated")):
                _stats.corrupted += 1
                return [], f"corrupted: {err}"
            logger.warning("yara_scan_error", extra={"data": {
                "file": file_path, "rule_file": rule_file, "error": err,
            }})
            _stats.errors += 1

    return all_matches, None


def _scan_single(file_path: str) -> list[tuple]:
    """
    Full verification pipeline for a single file.

    Verdict rules
    ─────────────
    yara_confirmed  ≥ 2 distinct YARA rules matched
    yara_suspicious   exactly 1 YARA rule matched
    (no artifact)   0 YARA rules matched

    Additional signals (entropy, suspicious imports, external IPs) are
    recorded in the description but do not change the verdict threshold.
    """
    # ── size / existence guard ─────────────────────────────────────────────
    try:
        size = os.path.getsize(file_path)
    except OSError as exc:
        logger.warning("yara_stat_error", extra={"data": {"file": file_path, "error": str(exc)}})
        _stats.errors += 1
        return []

    if size == 0:
        return []

    if size > _MAX_FILE_SIZE:
        logger.info("yara_skip_large", extra={"data": {"file": file_path, "size": size}})
        _stats.skipped_large += 1
        return []

    _stats.files_scanned += 1

    # ── YARA scan ──────────────────────────────────────────────────────────
    all_matches, err_reason = _run_all_rules(file_path)
    if err_reason:
        logger.warning("yara_scan_skipped", extra={"data": {
            "file": file_path, "reason": err_reason,
        }})
        return []

    if not all_matches:
        return []

    _stats.yara_matches += 1

    # ── Additional verification signals ────────────────────────────────────
    try:
        with open(file_path, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        logger.warning("yara_read_error", extra={"data": {"file": file_path, "error": str(exc)}})
        _stats.errors += 1
        return []

    high_entropy, entropy_val   = _check_entropy(data)
    suspicious_imports, ext_ips = _analyze_strings(file_path)

    # ── Verdict ────────────────────────────────────────────────────────────
    rule_names = list(dict.fromkeys(m.rule for m in all_matches))
    rule_count = len(rule_names)

    if rule_count >= 2:
        verdict = "yara_confirmed"
        _stats.confirmed_malicious += 1
    else:
        verdict = "yara_suspicious"
        _stats.suspicious_only += 1

    # ── Description ────────────────────────────────────────────────────────
    parts = [f"{rule_count} YARA rule(s) matched: {', '.join(rule_names)}"]

    string_details: list[str] = []
    for match in all_matches:
        for s in _format_match_strings(match):
            string_details.append(f"[{match.rule}] {s}")
    if string_details:
        parts.append("strings: " + "; ".join(string_details[:8]))

    if high_entropy:
        parts.append(f"high entropy ({entropy_val:.2f}/8.00) — likely packed or encrypted")
    if suspicious_imports:
        parts.append(f"suspicious imports: {', '.join(suspicious_imports[:6])}")
    if ext_ips:
        parts.append(f"external IPs: {', '.join(ext_ips[:4])}")

    description = " | ".join(parts)

    logger.info("yara_verdict", extra={"data": {
        "file":               file_path,
        "verdict":            verdict,
        "rules_matched":      rule_names,
        "rule_count":         rule_count,
        "entropy":            round(entropy_val, 3),
        "high_entropy":       high_entropy,
        "suspicious_imports": suspicious_imports[:6],
        "external_ips":       ext_ips[:4],
    }})

    return [(verdict, file_path, description)]


# ── Archive extraction ─────────────────────────────────────────────────────────

def _extract_archive(src: str, dest_dir: str) -> bool:
    """Attempt to extract an archive into dest_dir. Returns True on success."""
    ext = os.path.splitext(src)[1].lower()
    if ext in (".zip", ".jar"):
        cmd = ["unzip", "-o", "-q", src, "-d", dest_dir]
    elif ext in (".7z", ".rar", ".cab"):
        cmd = ["7z", "x", src, f"-o{dest_dir}", "-y", "-bd"]
    elif ext == ".tar":
        cmd = ["tar", "-xf", src, "-C", dest_dir]
    elif ext in (".gz", ".tgz"):
        cmd = ["tar", "-xzf", src, "-C", dest_dir]
    elif ext in (".bz2", ".tbz2"):
        cmd = ["tar", "-xjf", src, "-C", dest_dir]
    else:
        return False

    try:
        result = subprocess.run(cmd, capture_output=True, timeout=60)
        if result.returncode != 0:
            logger.info("yara_archive_extract_failed", extra={"data": {
                "archive": src,
                "stderr": result.stderr.decode(errors="ignore")[:200],
            }})
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        logger.info("yara_archive_tool_error", extra={"data": {
            "archive": src, "error": str(exc),
        }})
        return False


# ── Public entry point ─────────────────────────────────────────────────────────

def scan_file_recursive(file_path: str, _depth: int = 0) -> list[tuple]:
    """
    Scan file_path and, if it is a supported archive type, recursively scan
    its extracted contents up to _MAX_RECURSE_DEPTH levels deep.

    Returns a list of ("yara_confirmed"|"yara_suspicious", path, description)
    artifact tuples.
    """
    artifacts = _scan_single(file_path)

    if _depth >= _MAX_RECURSE_DEPTH:
        return artifacts

    # Only recurse into archives
    ext = os.path.splitext(file_path)[1].lower()
    if ext not in (".zip", ".jar", ".7z", ".rar", ".cab", ".tar", ".gz", ".tgz", ".bz2", ".tbz2"):
        return artifacts

    try:
        tmpdir_ctx = tempfile.TemporaryDirectory(prefix="yara_arc_")
        tmpdir = tmpdir_ctx.__enter__()
    except OSError as exc:
        logger.warning("yara_tmpdir_error", extra={"data": {"error": str(exc)}})
        return artifacts

    try:
        if not _extract_archive(file_path, tmpdir):
            return artifacts

        count = 0
        for dirpath, _, filenames in os.walk(tmpdir):
            for fname in sorted(filenames):
                if count >= _MAX_ARCHIVE_FILES:
                    logger.info("yara_archive_limit", extra={"data": {
                        "archive": file_path,
                        "limit":   _MAX_ARCHIVE_FILES,
                    }})
                    return artifacts
                nested = os.path.join(dirpath, fname)
                artifacts.extend(scan_file_recursive(nested, _depth + 1))
                count += 1
    finally:
        tmpdir_ctx.__exit__(None, None, None)

    return artifacts
