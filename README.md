# Evidence Attribution Pipeline

A modular digital forensics pipeline that ingests multi-source evidence, extracts
security artifacts, maps them to MITRE ATT&CK, and produces a professional incident
report — with every claim grounded in and linked back to raw evidence.

## What it does

Given a directory of evidence files the pipeline:

1. **Ingests** all files, classifies them by type, and streams SHA-256 hashes for
   chain-of-custody integrity — disk images and memory dumps are never loaded into
   RAM.
2. **Extracts** artifacts using a dedicated extractor for each evidence class: keyword
   heuristics for log files, ewfmount + The Sleuth Kit for disk images, Volatility3
   for memory dumps, tshark for network captures.
3. **Normalises** artifacts into a single chronological timeline, parsing embedded
   timestamps (ISO-8601 and syslog) and falling back to file mtime.
4. **Reasons** about the timeline with Claude (`claude-opus-4-7`, adaptive extended
   thinking) and returns structured, source-attributed hypotheses.
5. **Scans** extracted files with YARA rules, checking Shannon entropy, suspicious
   Windows API imports, and embedded external IPs.
6. **Verifies** each hypothesis with `file`, `strings`, `grep`, and `xxd`; hypotheses
   with no supporting evidence are dropped.
7. **Maps** verified findings to MITRE ATT&CK techniques (30+ keyword rules,
   sub-technique aware).
8. **Scores** each finding `CONFIRMED`, `PROBABLE`, or `POSSIBLE` based on grep-hit
   count, evidence items, and file type.
9. **Correlates** findings across hosts by SHA-256 hash, artifact filename, and ATT&CK
   technique ID.
10. **Reports** a professional incident report to `report.txt` and stdout, including an
    executive summary, YARA statistics, a kill-chain attack timeline, per-host
    technical findings with sources, and prioritised remediation actions.

Every step appends structured JSON to `logs/agent_execution.log`.

---

## Modules

| Module | Role |
|--------|------|
| `main.py` | Pipeline orchestrator — wires all stages together |
| `ingest.py` | Walk `evidence/`, classify files, stream SHA-256 hashes |
| `extract.py` | Dispatch each evidence file to the correct extractor |
| `extract_logs.py` | Keyword + regex heuristics for plain-text log files |
| `extract_disk.py` | ewfmount + mmls / fls / icat for disk images (E01 / raw) |
| `extract_memory.py` | Volatility3 pslist / netstat for memory dumps |
| `extract_network.py` | tshark (4 passes) for PCAP / PCAPNG captures |
| `normalize.py` | Build a sorted UTC event timeline from all artifacts |
| `reason.py` | Claude API call with adaptive thinking + JSON schema |
| `verify.py` | Cross-check hypotheses against raw evidence files |
| `scan_yara.py` | YARA scanning with entropy, imports, archive recursion |
| `attck.py` | Map claim text to MITRE ATT&CK technique IDs |
| `confidence.py` | Score findings CONFIRMED / PROBABLE / POSSIBLE |
| `correlate.py` | Cross-host correlation by hash, filename, and technique |
| `report.py` | Render the final incident report |
| `utils.py` | Shared logger, subprocess wrapper, IP utilities |

---

## Architecture

```
evidence/
├── *.log / *.txt       → extract_logs.py  (keyword heuristics, per-line)
├── *.E01 / *.dd / …   → extract_disk.py  (ewfmount + mmls/fls/icat)
├── *.vmem / *.raw / …  → extract_memory.py (Volatility3)
└── *.pcap / *.pcapng   → extract_network.py (tshark, 4 passes)
         │
         ▼
 ingest.py          SHA-256 hash (streamed); classify by extension
         │
         ▼
 extract.py         Route each file to the right extractor
         │ artifacts[]
         ▼
 normalize.py       Parse timestamps; sort by UTC; build timeline[]
         │ timeline[]
         ▼
 reason.py          claude-opus-4-7, adaptive thinking, JSON schema output
         │ hypotheses[]
         ├──────────────────────────────────────┐
         ▼                                      ▼
 scan_yara.py                           verify.py
 YARA rules + entropy                   file / strings / grep / xxd
 suspicious imports                     RFC 1918 IP classification
         │                                      │
         └──────────────────┬───────────────────┘
                            ▼
                    attck.py      map_to_attck()
                    confidence.py compute_confidence()
                    correlate.py  hash / filename / technique groups
                            │
                            ▼
                    report.py     report.txt + stdout

logs/agent_execution.log  ← structured JSON log for every step
extracted/                ← files pulled out of disk images
```

---

## Evidence types and artifacts produced

### Text / log files (`extract_logs.py`)

| Artifact type | Trigger |
|---------------|---------|
| `credential_hint` | line contains `password` |
| `suspicious_execution` | line contains `cmd.exe` or `powershell` |
| `network_indicator` | line contains `http://` or `https://` |
| `account_creation` | line contains `net user` |
| `base64_payload` | Base64 sequence ≥ 32 characters |

Artifacts record `path:lineno` as the source so every finding links to an exact line.

### Disk images — E01 / EWF and raw (`extract_disk.py`)

Supports `.E01`, `.dd`, `.img`, `.vmdk`, `.vhd`, `.vhdx`, `.iso`.

E01 images are mounted read-only via `ewfmount` (libewf) into a temporary directory;
the raw block device is then passed to The Sleuth Kit. Multi-segment E01 files
(`image(1).E01`, `image(2).E01`, …) are automatically detected — only the base
segment is processed, continuation segments are skipped.

Partition detection order:
1. `mmls` — reads MBR / GPT partition tables.
2. NTFS sector-offset probe at offsets 2048 and 63 — fallback when `mmls` finds no
   table (common with EWF images).
3. Direct `fls` call with no offset — fallback for bare filesystem images.

Files with suspicious extensions (scripts, executables, logs, archives, Office
macros, LNK, REG, PCAP) are extracted with `icat` into `extracted/<image>/`, then
scanned with `strings`. The same keyword rules as log files are applied to the
printable output. Extraction is capped at 100 files per partition.

Extracted files are also passed to `scan_yara.scan_file_recursive()`.

### Memory dumps (`extract_memory.py`)

Supports `.vmem`, `.mem`, `.raw`.

Volatility3 is invoked for `windows.pslist` / `linux.pslist` and
`windows.netstat` / `linux.netstat`. OS detection is automatic — Windows plugins
are tried first; if they return no results the Linux equivalents are run.

| Artifact type | Source |
|---------------|--------|
| `memory_process_list` | pslist output |
| `memory_suspicious_process` | Known-bad names, unexpected parent–child, duplicate `lsass.exe` |
| `memory_network_connection` | netstat output |

Suspicious process heuristics: built-in list of known malicious tool names
(mimikatz, meterpreter, psexec, procdump, …); Windows system processes (svchost,
lsass, csrss, …) with unexpected parents; more than one `lsass.exe` instance.

### Network captures (`extract_network.py`)

Supports `.pcap`, `.pcapng`. tshark is run in four passes:

| Pass | Artifact type | Content |
|------|---------------|---------|
| 1 | `pcap_connection_summary` | Total IP packets, unique dst:port pairs |
| 2 | `pcap_dns_query` | Every DNS query name |
| 3 | `pcap_http_request` | Method, host, URI, User-Agent |
| 4 | `pcap_tls_session` | SNI hostname, destination, port |

C2 detection signals produce `pcap_c2_candidate` artifacts:
- **Beaconing**: ≥ 10 packets to the same external dst:port.
- **DGA / DNS tunnelling**: query length > 50, > 5 DNS labels, or Shannon entropy
  of the leftmost label > 3.5 bits/symbol.
- **Suspicious HTTP**: plain HTTP to an external IP on a non-standard port.
- **Suspicious TLS**: missing SNI, or high-entropy SNI to an external IP on a
  non-standard port.

### YARA scanning (`scan_yara.py`)

Rules are loaded from `/usr/share/yara`, `/usr/local/share/yara`, `/etc/yara`,
`/opt/yara-rules`, and `$YARA_RULES_DIR`. All `.yar` / `.yara` files are compiled
at first use and cached.

Per-file pipeline:
- Files > 50 MB are skipped.
- YARA rules are run with a 30-second per-file timeout.
- Shannon entropy is checked whole-file (threshold 7.0/8.0) and per 4 KB block
  (threshold 7.5/8.0).
- A single `strings -a` pass identifies suspicious Windows API imports
  (VirtualAllocEx, CreateRemoteThread, WriteProcessMemory, etc.) and embedded
  external IP addresses.
- Archives (`.zip`, `.jar`, `.7z`, `.rar`, `.tar`, `.gz`, `.bz2`) are extracted
  to a temp directory and recursed up to 2 levels deep (max 20 files per archive).

Verdict thresholds:
- `yara_confirmed` — ≥ 2 distinct rule names matched.
- `yara_suspicious` — exactly 1 rule name matched.

Scan statistics (files scanned, matches, confirmed malicious, suspicious, errors,
skipped-large, corrupted, timeouts) are surfaced in the report.

---

## Confidence scoring (`confidence.py`)

| Rating | Criteria |
|--------|----------|
| `CONFIRMED` | ≥ 2 grep patterns matched, OR 1 grep hit on a binary/script file, OR ≥ 4 evidence items |
| `PROBABLE` | ≥ 1 grep pattern matched, OR ≥ 2 evidence items |
| `POSSIBLE` | 1 evidence item (strings keyword match, no grep hits) |

---

## MITRE ATT&CK mapping (`attck.py`)

Claim text is matched against 30+ keyword rules (most-specific first) to return
the most relevant technique ID and name. Examples:

| Keywords matched | Technique |
|-----------------|-----------|
| mimikatz, lsass, hashdump | T1003 — OS Credential Dumping |
| powershell | T1059.001 — PowerShell |
| base64, obfuscat, encod | T1027 — Obfuscated Files or Information |
| beacon, c2, callback | T1071 — Application Layer Protocol |
| persistence, registry run, scheduled task | T1547 — Boot or Logon Autostart Execution |

---

## Cross-host correlation (`correlate.py`)

After all findings are verified and scored, `correlate_findings()` groups them
across hosts using three match strategies (strongest first):

1. **Hash match** — identical SHA-256 of the artifact file on ≥ 2 hosts.
2. **Filename match** — same artifact name (inode prefix and `.deleted` suffix
   stripped, lowercased) on ≥ 2 hosts. Groups already covered by a hash match
   are suppressed.
3. **Technique match** — same ATT&CK technique ID detected on ≥ 2 hosts.

Correlation groups appear in the Technical Findings section and drive the
executive summary sentence about coordinated activity.

---

## Report structure (`report.py`)

```
========================================================================
INCIDENT REPORT — FORENSIC ANALYSIS
========================================================================

1. EXECUTIVE SUMMARY
2. YARA SCAN STATISTICS        (only when files were scanned)
3. ATTACK TIMELINE             (findings by kill chain phase)
4. TECHNICAL FINDINGS          (per-host, per-phase, with ATT&CK / confidence / source)
   Cross-Host Correlations
5. RECOMMENDED ACTIONS         (per-technique, prioritised by confidence)
```

Kill chain phases follow MITRE ATT&CK order: Initial Access → Execution →
Persistence → Privilege Escalation → Defense Evasion → Credential Access →
Discovery → Lateral Movement → Collection → Command and Control → Exfiltration →
Impact.

---

## Requirements

### Python

Python 3.9+ and the Anthropic SDK:

```bash
pip install anthropic
export ANTHROPIC_API_KEY="sk-ant-..."
```

`yara-python` is optional; YARA scanning is silently skipped if it is not
installed:

```bash
pip install yara-python
```

### System tools

| Evidence type | Tools required |
|---------------|----------------|
| Text logs | *(none — built-in)* |
| Disk images (`.dd`, `.img`, …) | `mmls`, `fls`, `icat` (The Sleuth Kit), `strings` |
| Disk images (`.E01` / EWF) | all of the above **+** `ewfmount` (libewf), `fusermount` |
| Memory dumps (`.vmem`, `.mem`, `.raw`) | `vol3` (Volatility3) with OS symbol tables |
| Network captures (`.pcap`, `.pcapng`) | `tshark` (Wireshark CLI) |
| Verification layer | `file`, `strings`, `grep`, `xxd` |

On Debian / Ubuntu / Kali:

```bash
# The Sleuth Kit + ewfmount
sudo apt install sleuthkit libewf-dev ewf-tools

# tshark
sudo apt install tshark

# Volatility3
pip install volatility3
# or: git clone https://github.com/volatilityfoundation/volatility3
```

---

## Installation

```bash
git clone <repo-url>
cd evidence-attribution-pipeline
pip install anthropic
export ANTHROPIC_API_KEY="sk-ant-..."
```

Install optional dependencies as needed (see table above).

---

## Usage

1. Place evidence files in the `evidence/` directory.
2. Run:

```bash
python main.py
```

Output:
- Report printed to stdout and written to `report.txt`.
- Extracted files written under `extracted/`.
- Structured JSON log appended to `logs/agent_execution.log`.

### Evidence directory layout

```
evidence/
├── auth.log                   ← plain-text log
├── windows_event.log          ← plain-text log
├── rocba-cdrive.E01           ← EWF disk image (ewfmount)
├── memdump.vmem               ← memory dump (Volatility3)
└── capture.pcap               ← network capture (tshark)
```

Any combination is accepted. Unrecognised extensions are read as text
(`errors="ignore"`). Split multi-segment E01 images are handled automatically —
only the base `.E01` is processed; continuation segments are skipped.

### Environment variables

| Variable | Effect |
|----------|--------|
| `ANTHROPIC_API_KEY` | Required — Anthropic API key |
| `YARA_RULES_DIR` | Optional — additional directory searched for `.yar` / `.yara` files |

---

## Example output — SANS SRL-2018 dataset

The `evidence/` directory ships with `rocba-cdrive.e01` (a Windows C: drive image
from the SANS 2018 Forensics challenge) and two log files.

Running `python main.py` against this dataset produces:

```
========================================================================
INCIDENT REPORT — FORENSIC ANALYSIS
========================================================================

1. EXECUTIVE SUMMARY
----------------------------------------

Forensic analysis of evidence collected from 3 host(s) (rocba-cdrive,
test, windows_event) identified 14 finding(s) covering 7 MITRE ATT&CK
technique(s). 13 finding(s) are CONFIRMED with direct forensic evidence
and 1 are rated PROBABLE; the remainder require further investigation.
Observed activity spans the following attack phases: Initial Access,
Execution, Persistence, Privilege Escalation, Defense Evasion, Command and
Control.

2. YARA SCAN STATISTICS
----------------------------------------

  Artifacts scanned     : 20
  YARA matches          : 0
  Confirmed malicious   : 0  (≥ 2 rules matched)
  Suspicious only       : 0  (1 rule matched)
  Scan errors           : 0
  Skipped — too large   : 0
  Corrupted files       : 0
  Scan timeouts         : 0

3. ATTACK TIMELINE
----------------------------------------

  [INITIAL ACCESS]
   1. [rocba-cdrive] Credential hint embedded in integrator.exe suggests
      credential theft or hardcoded authentication material — CONFIRMED
      [T1078: Valid Accounts]
   2. [rocba-cdrive] VC_redist.x64.exe contains credential hints and
      base64 payloads, suggesting masquerading malware impersonating the
      Microsoft Visual C++ redistributable — CONFIRMED [T1078: Valid Accounts]
   3. [rocba-cdrive] vcredist_x64.exe and vcredist_x86.exe show identical
      credential_hint offsets indicating cloned trojanized binaries for
      both architectures — CONFIRMED [T1078: Valid Accounts]

  [EXECUTION]
   6. [rocba-cdrive] Coordinated timestamp across four distinct executables
      indicates a single staged malware drop — CONFIRMED [T1204: User Execution]

  [PERSISTENCE]
   8. [windows_event] Account creation within 10 seconds of suspicious
      execution indicates persistence via rogue user account — CONFIRMED
      [T1547: Boot or Logon Autostart Execution]

  [PRIVILEGE ESCALATION]
   9. [rocba-cdrive] Suspicious execution patterns in software_reporter_tool.exe
      suggest process injection capability — CONFIRMED [T1055: Process Injection]

  [DEFENSE EVASION]
  11. [rocba-cdrive] integrator.exe contains >200 base64-encoded payloads
      alongside network indicators — consistent with a packed dropper —
      CONFIRMED [T1027: Obfuscated Files or Information]

  [COMMAND AND CONTROL]
  14. [test] Secondary suspicious execution with network indicator suggests
      follow-on C2 beaconing — CONFIRMED [T1071: Application Layer Protocol]

4. TECHNICAL FINDINGS
----------------------------------------

  Host: rocba-cdrive
  ────────────────────────────────────────────
  [Defense Evasion]
    Finding    : integrator.exe contains massive volumes (>200) of base64-encoded
                 payloads alongside network indicators, consistent with a
                 packed/obfuscated malware dropper or stager
    ATT&CK     : [T1027] Obfuscated Files or Information
    Confidence : CONFIRMED
    Source     : extracted/rocba-cdrive/partition_ewf1/inode_107711_integrator.exe:75407

5. RECOMMENDED ACTIONS
----------------------------------------

  1. [T1027 — Obfuscated Files or Information]
     Scan for encoded/obfuscated payloads across email, web, and endpoint
     telemetry.

  2. [T1055 — Process Injection]
     Audit for memory injection; deploy endpoint detection with memory-
     scanning capabilities.

  3. [T1078 — Valid Accounts]
     Rotate all potentially compromised credentials; audit recent account
     creation and privilege grants.

  ...

========================================================================
END OF REPORT
========================================================================
```

### Structured JSON log (excerpt)

```json
{"timestamp": "2026-06-15T06:18:55Z", "level": "INFO", "step": "pipeline_start"}
{"timestamp": "2026-06-15T06:18:55Z", "level": "INFO", "step": "ingest_complete",
 "data": {"file_count": 3, "disk_images": 1, "memory_dumps": 0, "pcaps": 0,
          "total_bytes": 2147483648}}
{"timestamp": "2026-06-15T06:19:01Z", "level": "INFO", "step": "ewfmount_ok",
 "data": {"image": "evidence/rocba-cdrive.E01", "raw": "/tmp/ewf_a1b2c3/ewf1"}}
{"timestamp": "2026-06-15T06:19:02Z", "level": "INFO", "step": "disk_image_ntfs_probe_ok",
 "data": {"image": "evidence/rocba-cdrive.E01", "offset": 2048}}
{"timestamp": "2026-06-15T06:19:30Z", "level": "INFO", "step": "disk_image_file_extracted",
 "data": {"inode": 107711, "image_path": "integrator.exe",
          "extracted_to": "extracted/rocba-cdrive/partition_ewf1/inode_107711_integrator.exe"}}
{"timestamp": "2026-06-15T06:20:10Z", "level": "INFO", "step": "llm_reason_complete",
 "data": {"hypothesis_count": 16, "input_tokens": 4096, "output_tokens": 820,
          "total_tokens": 4916, "duration_s": 8.4}}
{"timestamp": "2026-06-15T06:20:18Z", "level": "INFO", "step": "finding_scored",
 "data": {"claim": "integrator.exe contains >200 base64-encoded payloads ...",
          "confidence": "CONFIRMED", "attck_id": "T1027",
          "attck_name": "Obfuscated Files or Information",
          "evidence_count": 5, "grep_hit_count": 3}}
{"timestamp": "2026-06-15T06:20:20Z", "level": "INFO", "step": "pipeline_complete",
 "data": {"verified_findings": 14, "total_duration_s": 85.3}}
```

---

## Project structure

```
evidence-attribution-pipeline/
├── main.py                 # Pipeline orchestrator
├── ingest.py               # File ingestion and classification
├── extract.py              # Extractor dispatcher
├── extract_logs.py         # Log file heuristics
├── extract_disk.py         # Disk image extraction (ewfmount + TSK)
├── extract_memory.py       # Memory dump analysis (Volatility3)
├── extract_network.py      # PCAP analysis (tshark)
├── normalize.py            # Timeline construction
├── reason.py               # Claude LLM reasoning
├── verify.py               # Evidence-backed verification
├── scan_yara.py            # YARA scanning with entropy and imports
├── attck.py                # MITRE ATT&CK technique mapping
├── confidence.py           # CONFIRMED / PROBABLE / POSSIBLE scoring
├── correlate.py            # Cross-host correlation
├── report.py               # Incident report rendering
├── utils.py                # Logger, subprocess helper, IP utilities
├── evidence/               # Input evidence directory
│   ├── rocba-cdrive.E01    # SANS SRL-2018 disk image
│   ├── test.log
│   └── windows_event.log
├── extracted/              # Files pulled from disk images
│   └── rocba-cdrive/
│       └── partition_ewf1/
│           └── inode_107711_integrator.exe
├── logs/
│   └── agent_execution.log # Structured JSON execution log
└── report.txt              # Generated incident report
```

---

## Limitations

**Heuristic extractor** — text extraction uses substring and regex matching.
Obfuscated payloads (XOR, custom encoding, heavily fragmented strings) require
custom rules.

**Timestamp fallback** — lines with no recognisable timestamp fall back to the
source file's mtime, not the actual event time. Events sharing the same fallback
mtime sort consistently relative to each other but may not reflect actual incident
ordering.

**Disk extraction cap** — only files matching `SUSPICIOUS_EXTS` are extracted and
`strings`-scanned; extraction is capped at 100 files per partition. IOCs in
non-printable byte ranges are missed by the strings pass.

**Volatility3 symbols** — memory dump analysis fails silently if OS-specific symbol
tables are not installed. Heuristics cover known-bad process names, parent–child
anomalies, and duplicate lsass; they do not cover SSDT hooks, driver analysis, or
code injection detection.

**Verification depth** — verification confirms that the cited source file contains
IOC keywords relevant to the claim type. It cannot detect interpretation-level
errors: a hypothesis that correctly cites a file but overstates what that file
proves will still pass.

**YARA rules not bundled** — no YARA rule files are included in this repository.
YARA scanning is a no-op until rules are installed in one of the search paths or
`$YARA_RULES_DIR` is set.
