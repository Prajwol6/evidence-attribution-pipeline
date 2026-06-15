import hashlib
import os
import re
from collections import defaultdict

from utils import logger

# extract_disk.py names extracted files "inode_<N>_<original_name>[.deleted]"
_INODE_PREFIX_RE = re.compile(r"^inode_\d+_")


def _extract_host(source: str) -> str:
    """
    Derive a host label from a finding's support path.

    extracted/<host>/partition_.../...  ->  host directory name
    evidence/<file>                     ->  filename stem
    """
    path = source.rsplit(":", 1)[0]
    parts = path.replace("\\", "/").split("/")
    if len(parts) >= 2 and parts[0] == "extracted":
        return parts[1]
    if len(parts) >= 2 and parts[0] == "evidence":
        return os.path.splitext(parts[1])[0]
    return os.path.splitext(os.path.basename(path))[0]


def _normalize_filename(source: str) -> str:
    """
    Return the original artifact name, lower-cased, with the inode prefix
    and .deleted suffix removed so the same file on two hosts compares equal.
    """
    path = source.rsplit(":", 1)[0]
    name = os.path.basename(path)
    name = _INODE_PREFIX_RE.sub("", name)
    if name.endswith(".deleted"):
        name = name[: -len(".deleted")]
    return name.lower()


def _file_hash(source: str) -> str | None:
    """SHA256 of the artifact file (line-number suffix stripped)."""
    path = source.rsplit(":", 1)[0]
    try:
        with open(path, "rb") as fh:
            return hashlib.sha256(fh.read()).hexdigest()
    except OSError:
        return None


def correlate_findings(findings: list) -> list:
    """
    Compare findings across hosts.  Returns a list of correlation groups, each:
      {
        "match_type": "hash" | "filename" | "technique",
        "value":      str,        # shared value (hash prefix, filename, technique ID)
        "attck_name": str,        # technique name, for technique matches
        "hosts":      [str],      # distinct hosts involved
        "findings":   [           # one entry per involved finding
          {"idx": int, "host": str, "claim": str}
        ],
      }
    Hash matches are computed first; filename groups that are fully covered by
    a hash match are skipped to avoid duplicate output.
    """
    # ── per-finding metadata ───────────────────────────────────────────────
    enriched = []
    for i, f in enumerate(findings):
        source = f.get("support", "")
        host   = _extract_host(source)
        fname  = _normalize_filename(source)
        fhash  = _file_hash(source)
        enriched.append({
            "idx":      i,
            "host":     host,
            "filename": fname,
            "hash":     fhash,
            "attck_id": f.get("attck_id", ""),
        })

    correlations  = []
    hash_covered  = set()   # finding-index sets already explained by a hash match

    def _group_entry(e):
        return {"idx": e["idx"], "host": e["host"], "claim": findings[e["idx"]]["claim"]}

    # ── 1. Hash match (strongest: identical bytes on different hosts) ───────
    by_hash = defaultdict(list)
    for e in enriched:
        if e["hash"]:
            by_hash[e["hash"]].append(e)

    for h, group in by_hash.items():
        hosts = list(dict.fromkeys(e["host"] for e in group))
        if len(hosts) < 2:
            continue
        idxs = frozenset(e["idx"] for e in group)
        hash_covered.add(idxs)
        correlations.append({
            "match_type": "hash",
            "value":      h[:16] + "...",
            "attck_name": "",
            "hosts":      hosts,
            "findings":   [_group_entry(e) for e in group],
        })

    # ── 2. Filename match (same artifact name, different hosts) ────────────
    by_filename = defaultdict(list)
    for e in enriched:
        if e["filename"] and e["filename"] not in ("", "."):
            by_filename[e["filename"]].append(e)

    for fname, group in by_filename.items():
        hosts = list(dict.fromkeys(e["host"] for e in group))
        if len(hosts) < 2:
            continue
        idxs = frozenset(e["idx"] for e in group)
        if idxs in hash_covered:
            continue   # already reported as a stronger hash match
        correlations.append({
            "match_type": "filename",
            "value":      fname,
            "attck_name": "",
            "hosts":      hosts,
            "findings":   [_group_entry(e) for e in group],
        })

    # ── 3. Technique match (same ATT&CK technique ID, different hosts) ─────
    by_technique = defaultdict(list)
    for e in enriched:
        if e["attck_id"]:
            by_technique[e["attck_id"]].append(e)

    for tech_id, group in by_technique.items():
        hosts = list(dict.fromkeys(e["host"] for e in group))
        if len(hosts) < 2:
            continue
        tech_name = findings[group[0]["idx"]].get("attck_name", "")
        correlations.append({
            "match_type": "technique",
            "value":      tech_id,
            "attck_name": tech_name,
            "hosts":      hosts,
            "findings":   [_group_entry(e) for e in group],
        })

    logger.info("correlation_complete", extra={"data": {
        "finding_count":     len(findings),
        "correlation_count": len(correlations),
        "by_type": {
            "hash":      sum(1 for c in correlations if c["match_type"] == "hash"),
            "filename":  sum(1 for c in correlations if c["match_type"] == "filename"),
            "technique": sum(1 for c in correlations if c["match_type"] == "technique"),
        },
    }})

    return correlations
