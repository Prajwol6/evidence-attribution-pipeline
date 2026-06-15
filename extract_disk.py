import contextlib
import hashlib
import os
import re
import tempfile

from utils import logger, _run_tool, _run_tool_binary
from extract_logs import _B64_RE
from scan_yara import scan_file_recursive as _yara_scan

# File types worth pulling out of a disk image for analysis
SUSPICIOUS_EXTS = frozenset({
    ".ps1", ".bat", ".cmd", ".vbs", ".js", ".sh", ".py", ".rb", ".pl",  # scripts
    ".exe", ".dll", ".sys", ".scr", ".com",                              # executables
    ".zip", ".rar", ".7z", ".tar", ".gz", ".cab",                       # archives
    ".log", ".evtx",                                                     # logs
    ".docm", ".xlsm", ".pptm",                                          # macro-enabled Office
    ".pcap", ".pcapng",                                                  # network captures
    ".lnk", ".reg",                                                      # shortcuts and registry exports
})

_EXTRACTED_DIR = "extracted"
_MAX_FILES_PER_PARTITION = 20   # guard against images with thousands of matching files

# Lower number = extracted first when the per-partition cap is hit.
# .dll/.sys are deprioritised — they're plentiful but rarely the smoking gun.
_EXT_PRIORITY = {
    ".ps1": 0, ".bat": 0, ".cmd": 0, ".exe": 0,
    ".vbs": 1, ".js": 1, ".sh": 1, ".py": 1, ".rb": 1, ".pl": 1,
    ".lnk": 1, ".reg": 1,
    ".evtx": 1, ".log": 1,
    ".pcap": 1, ".pcapng": 1,
    ".zip": 1, ".rar": 1, ".7z": 1, ".tar": 1, ".gz": 1, ".cab": 1,
    ".docm": 1, ".xlsm": 1, ".pptm": 1,
    ".scr": 2, ".com": 2, ".dll": 2, ".sys": 2,
}


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

    Handles:
      - Tree-indent prefixes ("+", "++", "+++ ") added by TSK on NTFS volumes
      - NTFS inode format  N-type-id  (e.g. 88509-128-1) as well as plain N
      - Deleted-file notations: asterisk before or after the inode number

    Returns entries with keys: ftype, inode, path, deleted.
    """
    entries = []
    for line in output.splitlines():
        # Strip tree-indent characters used by fls -r on NTFS volumes
        clean = line.lstrip("+ ")
        m = re.match(
            r"^([drclsb\-])/[drclsb\-]\s+(\*\s+)?(\d+)(?:-\d+-\d+)?(\*)?\s*:\s+(.+)$",
            clean,
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


@contextlib.contextmanager
def _ewfmount(image_path):
    """
    Mount an EWF (.E01) image with ewfmount and yield the raw-device path.

    ewfmount exposes the image as <mount_dir>/ewf1 — a seekable, readable
    block device that mmls / fls / icat treat identically to a raw .dd image.
    Unmounts via fusermount -u on exit regardless of success or failure.
    Multi-segment images (E01, E02 …) are handled automatically by ewfmount
    when all segments share the same directory.
    """
    mount_dir = tempfile.mkdtemp(prefix="ewf_")
    try:
        _, stderr, rc = _run_tool(["ewfmount", image_path, mount_dir], timeout=30)
        if rc != 0:
            logger.warning("ewfmount_failed", extra={"data": {
                "image":  image_path,
                "mount":  mount_dir,
                "stderr": stderr.strip(),
            }})
            yield None
        else:
            raw_path = os.path.join(mount_dir, "ewf1")
            logger.info("ewfmount_ok", extra={"data": {
                "image": image_path,
                "raw":   raw_path,
            }})
            yield raw_path
    finally:
        _run_tool(["fusermount", "-u", mount_dir], timeout=10)
        try:
            os.rmdir(mount_dir)
        except OSError:
            pass


def extract_disk_image_artifacts(item):
    """
    Extract forensic artifacts from a disk image using mmls, fls, and icat.

    EWF (.E01) images are mounted via ewfmount before analysis. The ewf1
    device path is passed directly to fls/icat — TSK auto-detects the
    partition layout, so no sector offset is needed. The mount is torn down
    automatically after extraction completes.

    For all other formats the image path is passed directly to the tools.
    Falls back to offset 0 if mmls cannot find a partition table (e.g. a
    bare filesystem image with no partition wrapper).
    """
    image_path = item["path"]
    image_stem = os.path.splitext(os.path.basename(image_path))[0]
    ext = os.path.splitext(image_path)[1].lower()
    if ext == ".e01":
        with _ewfmount(image_path) as tool_path:
            if tool_path is None:
                return []
            return _extract_disk_image_raw(image_path, image_stem, tool_path, item, direct=True)
    return _extract_disk_image_raw(image_path, image_stem, image_path, item)


def _extract_disk_image_raw(image_path, image_stem, tool_path, item, direct=False):
    """Run mmls / fls / icat on tool_path and return forensic artifacts."""
    artifacts = []

    logger.info("disk_image_start", extra={"data": {
        "image": image_path,
        "size":  item["size"],
        "hash":  item["hash"],
    }})

    # ── Step 1: partition table ────────────────────────────────────────────
    if direct:
        # ewfmount exposes the whole disk as ewf1.  fls reads it without a
        # sector offset — TSK auto-detects the partition layout from the device.
        partitions = [{
            "slot":        "ewf1",
            "start":       None,
            "description": "EWF raw device (direct, no sector offset)",
        }]
        logger.info("disk_image_ewf_direct", extra={"data": {
            "image":  image_path,
            "device": tool_path,
        }})
    else:
        stdout, stderr, rc = _run_tool(["mmls", tool_path])
        if rc != 0:
            logger.warning("disk_image_mmls_failed", extra={"data": {
                "image":      image_path,
                "returncode": rc,
                "stderr":     stderr.strip(),
            }})
            partitions = []
        else:
            partitions = _parse_mmls(stdout)

        if not partitions:
            # mmls found no usable partition entries (or failed entirely).
            # Probe the two most common NTFS sector offsets; keep the first
            # one fls -r can actually read with content.
            for probe_offset in (2048, 63):
                probe_out, _, probe_rc = _run_tool(
                    ["fls", "-r", "-o", str(probe_offset), tool_path], timeout=120
                )
                if probe_rc == 0 and probe_out.strip():
                    partitions = [{
                        "slot":        f"ntfs_{probe_offset}",
                        "start":       probe_offset,
                        "description": f"NTFS filesystem probed at sector {probe_offset}",
                    }]
                    logger.info("disk_image_ntfs_probe_ok", extra={"data": {
                        "image":  image_path,
                        "offset": probe_offset,
                    }})
                    break

            if not partitions:
                # Sector-offset probes failed — try fls -r directly on the
                # device path with no offset (bare filesystem images).
                probe_out, _, probe_rc = _run_tool(["fls", "-r", tool_path], timeout=120)
                if probe_rc == 0 and probe_out.strip():
                    partitions = [{
                        "slot":        "bare_fs",
                        "start":       None,
                        "description": "filesystem without partition table (no offset)",
                    }]
                    logger.info("disk_image_bare_fs_probe_ok", extra={"data": {
                        "image": image_path,
                    }})

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

        fls_cmd = (
            ["fls", "-r", tool_path] if offset is None
            else ["fls", "-r", "-o", str(offset), tool_path]
        )
        stdout, stderr, rc = _run_tool(fls_cmd, timeout=120)
        if rc != 0:
            logger.warning("disk_image_fls_failed", extra={"data": {
                "image":  image_path,
                "slot":   partition["slot"],
                "offset": offset,
                "stderr": stderr.strip(),
            }})
            continue

        all_entries = _parse_fls(stdout)

        print(f"\n[fls] {len(all_entries)} entries in {image_path} partition {partition['slot']}:")
        for e in all_entries:
            ext = os.path.splitext(e["path"])[1].lower()
            tag = "[SUSPICIOUS]" if (e["ftype"] == "r" and ext in SUSPICIOUS_EXTS) else f"[skipped – ftype={e['ftype']}, ext={ext!r}]"
            deleted = " (deleted)" if e["deleted"] else ""
            print(f"  inode={e['inode']:>8}  {tag}  {e['path']}{deleted}")

        suspicious = [
            e for e in all_entries
            if e["ftype"] == "r"
            and os.path.splitext(e["path"])[1].lower() in SUSPICIOUS_EXTS
        ]
        suspicious.sort(key=lambda e: _EXT_PRIORITY.get(os.path.splitext(e["path"])[1].lower(), 1))

        if len(suspicious) > _MAX_FILES_PER_PARTITION:
            logger.warning("disk_image_file_limit_hit", extra={"data": {
                "image":            image_path,
                "slot":             partition["slot"],
                "suspicious_found": len(suspicious),
                "limit":            _MAX_FILES_PER_PARTITION,
            }})
            suspicious = suspicious[:_MAX_FILES_PER_PARTITION]

        logger.info("disk_image_fls_complete", extra={"data": {
            "image":            image_path,
            "slot":             partition["slot"],
            "offset":           offset,
            "description":      partition["description"],
            "total_entries":    len(all_entries),
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

            icat_cmd = (
                ["icat", tool_path, str(inode)] if offset is None
                else ["icat", "-o", str(offset), tool_path, str(inode)]
            )
            file_bytes, stderr, rc = _run_tool_binary(icat_cmd)
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

            artifacts.extend(_yara_scan(extract_path))

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

            # Use strings(1) rather than decoding the raw bytes.
            # Binary files like hiberfil.sys / pagefile.sys are mostly
            # non-printable; decoding them yields no signal. strings
            # extracts only printable sequences (default ≥4 chars), giving
            # the same IOC patterns with far less noise.
            strings_out, _, _ = _run_tool(["strings", extract_path], timeout=60)
            for lineno, line in enumerate(strings_out.splitlines(), start=1):
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
