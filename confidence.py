_SUSPICIOUS_TYPES = frozenset([
    "elf", "pe32", "executable", "script",
    "python", "perl", "bash", "mach-o", "shellcode",
])


def compute_confidence(evidence_found, grep_hits, file_type):
    """
    Rate a verified finding:
      CONFIRMED — multiple grep patterns hit, OR one grep hit with a suspicious
                  binary/script file type, OR four-or-more evidence items.
      PROBABLE  — at least one grep hit, OR two-or-more evidence items.
      POSSIBLE  — one evidence item only (strings-keyword match, no grep hits).
    """
    n_evidence = len(evidence_found)
    n_grep = len(grep_hits)
    is_suspicious_type = any(t in file_type.lower() for t in _SUSPICIOUS_TYPES)

    if n_grep >= 2 or (n_grep >= 1 and is_suspicious_type) or n_evidence >= 4:
        return "CONFIRMED"
    if n_grep >= 1 or n_evidence >= 2:
        return "PROBABLE"
    return "POSSIBLE"
