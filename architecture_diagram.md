# Architecture Diagram — Evidence Attribution Pipeline

---

## Full Pipeline with Logging Sidebar

```
  ┌─────────────────────────────────────────────────────────────────┐
  │                  EVIDENCE ATTRIBUTION PIPELINE                  │
  │                           main.py                               │
  └─────────────────────────────────────────────────────────────────┘

  ╔══════════════════════════════╗
  ║       evidence/  (input)     ║  any file type accepted
  ║  ├─ *.log  *.evtx            ║
  ║  ├─ *.dd  *.img  *.E01       ║
  ║  ├─ *.vmem  *.mem  *.raw     ║
  ║  └─ *.pcap  *.pcapng         ║
  ╚══════════════╤═══════════════╝
                 │ os.walk()
                 ▼
  ┌──────────────────────────────────────────────┐  ┌─────────────────────────────────┐
  │  STEP 1 · INGESTION                          │  │  STRUCTURED LOGGING             │
  │  ingest.py                                   │  │  _JsonFormatter → FileHandler   │
  │                                              │  │  logs/agent_execution.log       │
  │  • type detection per file extension:        │  │                                 │
  │    .dd / .img / .E01   → is_disk_image       │  │  ← pipeline_start               │
  │    .vmem / .mem / .raw → is_memory_dump      │──▶  ← ingest_start                │
  │    .pcap / .pcapng     → is_pcap             │  │  ← ingest_complete              │
  │    else                → log / text          │  │    {file_count, disk_images,    │
  │  • sha256 (streaming, 64 KB chunks)          │  │     memory_dumps, pcaps,        │
  │  • record: path · data · hash · size · flags │  │     total_bytes, duration_s}    │
  └──────────────────────┬───────────────────────┘  │                                 │
                         │                          │                                 │
   evidence_files[]      │                          │                                 │
   [{path, data, hash,   │                          │                                 │
     size, is_disk_image,│                          │                                 │
     is_memory_dump,     │                          │                                 │
     is_pcap}]           │                          │                                 │
                         ▼                          │                                 │
  ┌──────────────────────────────────────────────┐  │                                 │
  │  STEP 2 · ARTIFACT EXTRACTION                │  │                                 │
  │  extract.py  (router)  +  4 sub-modules      │  │                                 │
  │                                              │  │  ← extract_start               │
  │    is_memory_dump ──▶ extract_memory.py      │──▶  ← extract_complete            │
  │    is_disk_image  ──▶ extract_disk.py        │  │    {artifact_count,             │
  │    is_pcap        ──▶ extract_network.py     │  │     by_type{}, duration_s}      │
  │    else           ──▶ extract_logs.py        │  │                                 │
  │                                              │  │  ← disk_image_file_extracted    │
  │  all sub-modules emit tuples:                │  │    {image, inode, sha256,       │
  │  (event_type, source_path, raw_line)         │  │     extracted_to, size}         │
  └──────────────────────┬───────────────────────┘  │                                 │
                         │                          │                                 │
   artifacts[]           │                          │                                 │
   (type, source, line)  │                          │                                 │
                         ▼                          │                                 │
  ┌──────────────────────────────────────────────┐  │                                 │
  │  STEP 3 · TIMELINE NORMALIZATION             │  │                                 │
  │  normalize.py                                │  │                                 │
  │                                              │  │  ← normalize_start              │
  │  • _parse_ts(): ISO-8601 + syslog timestamps │──▶  ← normalize_complete          │
  │  • file mtime fallback for unparsed lines    │  │    {event_count, duration_s}    │
  │  • sorted(timeline, key=x["time"])           │  │                                 │
  └──────────────────────┬───────────────────────┘  │                                 │
                         │                          │                                 │
   timeline[]            │                          │                                 │
   [{time, event_type,   │                          │                                 │
     source}]            │                          │                                 │
                         ▼                          │                                 │
  ┌──────────────────────────────────────────────┐  │                                 │
  │  STEP 4 · LLM REASONING                      │  │                                 │
  │  reason.py                                   │  │                                 │
  │                                              │  │  ← llm_reason_start             │
  │  model:       claude-opus-4-7                │──▶    {event_count}                │
  │  thinking:    adaptive                       │  │                                 │
  │  output:      JSON schema enforced           │  │  ← llm_reason_retry  (WARNING)  │
  │  max_tokens:  4096                           │  │    {attempt, error,             │
  │  max_retries: 3  (self-correction loop)      │  │     raw_output}                 │
  └──────────────────────┬───────────────────────┘  │                                 │
                         │                          │  ← llm_reason_complete          │
   hypotheses[]          │                          │    {hypothesis_count,           │
   [{claim, support}]    │  for each hypothesis:    │     input_tokens, duration_s}   │
                         ▼                          │                                 │
  ┌──────────────────────────────────────────────┐  │                                 │
  │  STEP 5 · HYPOTHESIS VERIFICATION            │  │                                 │
  │  verify.py                                   │  │                                 │
  │                                              │  │  ← verify_hypothesis            │
  │  subprocess tools (30 s timeout each):       │──▶    {claim, file_type,           │
  │    file · strings · grep -iEo · xxd          │  │     grep_hits,                  │
  │    + RFC-1918 IP classification              │  │     evidence_found[],           │
  │                                              │  │     verified: true|false}       │
  │  returns None  if unverified, else:          │  │                                 │
  │    {evidence_found[], grep_hits[],           │  │  ← verify_hypothesis_failed     │
  │     file_type}                               │  │    (WARNING if not verified)    │
  └──────────────────────┬───────────────────────┘  │    {claim, support, file_type}  │
                         │ if verify_result:         │                                 │
                         ▼                          │                                 │
  ┌──────────────────────────────────────────────┐  │                                 │
  │  STEP 6 · FINDING ENRICHMENT                 │  │                                 │
  │  attck.py  +  confidence.py  (per finding)   │  │                                 │
  │                                              │  │  ← finding_scored               │
  │  attck.py:  29 keyword rules, first match:   │──▶    {claim, confidence,          │
  │    "powershell"  → T1059.001                 │  │     attck_id, attck_name,       │
  │    "ftp"         → T1048.003                 │  │     evidence_count,             │
  │    "lsass"       → T1003                     │  │     grep_hit_count,             │
  │    fallback      → T1204                     │  │     file_type}                  │
  │                                              │  │                                 │
  │  confidence.py:  evidence weighting:         │  │                                 │
  │    CONFIRMED   n_grep≥2  or                  │  │                                 │
  │                n_grep≥1 + suspicious type    │  │                                 │
  │    PROBABLE    n_grep≥1  or  n_evidence≥2    │  │                                 │
  │    POSSIBLE    n_evidence≥1 (strings-only)   │  │                                 │
  └──────────────────────┬───────────────────────┘  │                                 │
                         │                          │                                 │
   verified[]            │                          │                                 │
   [{claim, support,     │                          │                                 │
     attck_id, attck_name│                          │                                 │
     confidence}]        │                          │                                 │
                         ▼                          │                                 │
  ┌──────────────────────────────────────────────┐  │                                 │
  │  STEP 7 · CROSS-HOST CORRELATION             │  │                                 │
  │  correlate.py                                │  │                                 │
  │                                              │  │  ← correlation_complete         │
  │  host label ← support path stem:            │──▶    {finding_count,              │
  │    extracted/<host>/… → directory stem       │  │     correlation_count,          │
  │    evidence/<file>    → filename stem        │  │     by_type{hash,               │
  │                                              │  │       filename, technique}}     │
  │  match passes in priority order:             │  │                                 │
  │    1. hash      SHA256 of artifact file      │  │                                 │
  │    2. filename  basename, inode prefix off   │  │                                 │
  │    3. technique same ATT&CK ID, diff. host   │  │                                 │
  │  hash match suppresses filename duplicate    │  │                                 │
  └──────────────────────┬───────────────────────┘  │                                 │
                         │                          │                                 │
   correlations[]        │                          │                                 │
   [{match_type, value,  │                          │                                 │
     hosts[], findings[]}│                          │                                 │
                         ▼                          │                                 │
  ┌──────────────────────────────────────────────┐  │                                 │
  │  STEP 8 · REPORT GENERATION                  │  │                                 │
  │  report.py                                   │  │                                 │
  │                                              │  │  ← report_start                 │
  │  section 1 — FORENSIC REPORT                 │──▶  ← report_complete              │
  │    FINDING / CONFIDENCE / ATT&CK / SOURCE    │  │    {output_path}                │
  │                                              │  │                                 │
  │  section 2 — CROSS-HOST CORRELATION          │  │  ← pipeline_complete            │
  │    [HASH MATCH] / [FILENAME MATCH]           │  │    {verified_findings,          │
  │    [TECHNIQUE MATCH]  per group:             │  │     total_duration_s}           │
  │      Hosts: host1, host2, …                 │  └─────────────────────────────────┘
  │      - [host] claim text                     │
  │  • write → report.txt  • print → stdout      │
  └──────────────────────┬───────────────────────┘
                         │
                         ▼
  ╔══════════════════════════════════════╗
  ║  OUTPUTS                            ║
  ║  ├─ report.txt                      ║  findings + correlation groups
  ║  └─ stdout                          ║  terminal output
  ╚═════════════════════════════════════╝
```

---

## Extraction Fan-Out (Step 2 Detail)

```
                 evidence_files[]
                       │
                       ▼
             ┌─────────────────┐
             │   extract.py    │
             │    (router)     │
             └────────┬────────┘
                      │
        ┌─────────────┼─────────────┬──────────────────┐
        ▼             ▼             ▼                   ▼
  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────────────────┐
  │ extract  │  │ extract  │  │ extract  │  │ extract        │
  │ _memory  │  │ _disk    │  │ _network │  │ _logs          │
  │ .py      │  │ .py      │  │ .py      │  │ .py            │
  │          │  │          │  │          │  │                │
  │Volatility│  │ mmls     │  │ tshark   │  │ line-by-line   │
  │ process  │  │ fls      │  │ flow +   │  │ keyword scan:  │
  │ cmdline  │  │ icat     │  │ IOC grep │  │  password      │
  │ modules  │  │          │  │          │  │  cmd.exe       │
  │ handles  │  │ extracts │  │ emits    │  │  powershell    │
  │          │  │ suspic.  │  │ network  │  │  http://       │
  │ .vmem    │  │ files to │  │ indics.  │  │  net user      │
  │ .mem     │  │ extracted│  │          │  │  base64        │
  │ .raw     │  │ /<host>/ │  │ .pcap    │  │                │
  │          │  │          │  │ .pcapng  │  │ .log  .evtx    │
  └────┬─────┘  └────┬─────┘  └────┬─────┘  └───────┬────────┘
       │              │              │                │
       └──────────────┴──────────────┴────────────────┘
                                │
                                ▼
                          artifacts[]
                     (event_type, source, raw_line)
```

---

## LLM Self-Correction Loop (Step 4 Detail)

```
  messages = [ {role: "user", content: timeline JSON} ]
       │
       ▼
  ┌────────────────────────────────────────────────────────┐
  │  attempt 1                                             │
  │  client.messages.create(model, thinking, schema, ...)  │
  │             │                                          │
  │     ┌───────┴────────┐                                 │
  │  pass                fail (JSONDecodeError | ValueError)│
  │     │                │                                  │
  │     │       log WARNING: llm_reason_retry               │
  │     │       {attempt:1, error, raw_output[:300]}        │
  │     │                │                                  │
  │     │       messages.append({role:"assistant",          │
  │     │                        content: response.content})│
  │     │       messages.append({role:"user",               │
  │     │                        content: correction text}) │
  │     │                │                                  │
  │     │                ▼                                  │
  │     │          attempt 2  (model sees its own mistake)  │
  │     │             │                                     │
  │     │     ┌───────┴────────┐                            │
  │     │  pass                fail                         │
  │     │     │                │                            │
  │     │     │       messages.append(×2) again             │
  │     │     │                │                            │
  │     │     │                ▼                            │
  │     │     │          attempt 3                          │
  │     │     │             │                               │
  │     │     │     ┌───────┴───────┐                       │
  │     │     │  pass               fail                    │
  │     │     │     │               │                       │
  │     │     │     │        raise RuntimeError             │
  │     │     │     │        "failed after 3 attempts"      │
  └─────┼─────┼─────┘                                       │
        │     │                                             │
        ▼     ▼
   return hypotheses[]
```

---

## SIFT Verification Fan-Out (Step 5 Detail)

```
                   hypothesis
                   {claim, support}
                        │
                        ▼
              ┌─────────────────┐
              │  _run_tool()    │  subprocess.run(cmd,
              │  wrapper        │  capture_output=True,
              │  timeout=30s    │  text=True, timeout=30)
              └────────┬────────┘
                       │
          ┌────────────┼─────────────┬────────────────┐
          ▼            ▼             ▼                 ▼
    ┌──────────┐ ┌──────────┐ ┌───────────┐  ┌──────────────┐
    │  file    │ │ strings  │ │   grep    │  │     xxd      │
    │ <source> │ │ <source> │ │  -iEo     │  │  <source>    │
    └────┬─────┘ └────┬─────┘ │ <pattern> │  └──────┬───────┘
         │            │       │ <source>  │         │
         ▼            ▼       └─────┬─────┘         ▼
    file type   printable      claim-keyed       hex dump
    ID string   sequences      regex hits        (1024 B
                + IOC scan     + IP RFC-1918      logged)
                     │         classification
                     │              │
                     └──────┬───────┘
                            ▼
                     evidence_found[]
                     list of match strings
                            │
                    ┌───────┴────────┐
              non-empty              empty
                    │                │
                    ▼                ▼
          return dict:          return None
          {evidence_found,      log WARNING:
           grep_hits,           verify_hypothesis
           file_type}           _failed
```

---

## Log Entry Schema

Every pipeline event writes one JSON line to `logs/agent_execution.log`:

```
{
  "timestamp": "2026-04-23T04:23:27.190511+00:00",  ← UTC ISO-8601
  "level":     "INFO" | "WARNING",                   ← log level
  "step":      "<function_event_name>",               ← stage identifier
  "data":      { ... }                                ← step-specific payload
}
```

| step | level | key data fields |
|------|-------|-----------------|
| `pipeline_start` | INFO | — |
| `ingest_start` | INFO | `path` |
| `ingest_complete` | INFO | `file_count`, `disk_images`, `memory_dumps`, `pcaps`, `total_bytes`, `duration_s` |
| `extract_start` | INFO | `file_count` |
| `disk_image_file_extracted` | INFO | `image`, `inode`, `sha256`, `extracted_to`, `size` |
| `extract_complete` | INFO | `artifact_count`, `by_type`, `duration_s` |
| `normalize_start` | INFO | `artifact_count` |
| `normalize_complete` | INFO | `event_count`, `duration_s` |
| `llm_reason_start` | INFO | `event_count` |
| `llm_reason_retry` | WARNING | `attempt`, `max_retries`, `error`, `raw_output` |
| `llm_reason_complete` | INFO | `attempt`, `hypothesis_count`, `input_tokens`, `output_tokens`, `total_tokens`, `duration_s` |
| `verify_hypothesis` | INFO | `claim`, `support`, `file_type`, `grep_hits`, `evidence_found`, `verified` |
| `verify_hypothesis_failed` | WARNING | `claim`, `support`, `file_type` |
| `finding_scored` | INFO | `claim`, `confidence`, `attck_id`, `attck_name`, `evidence_count`, `grep_hit_count`, `file_type` |
| `correlation_complete` | INFO | `finding_count`, `correlation_count`, `by_type` |
| `report_start` | INFO | `verified_count`, `correlation_count` |
| `report_complete` | INFO | `output_path` |
| `pipeline_complete` | INFO | `verified_findings`, `total_duration_s` |

---

## Data Structures at Each Stage Boundary

```
  evidence_files[]           artifacts[]            timeline[]
  ──────────────────         ─────────────          ──────────────────────
  [                          [                      [
    {                          (                      {
      path:           str,       "suspicious_           time:       str,
      data:           bytes,      execution",           event_type: str,
      hash:           str,        "extracted/           source:     str
      size:           int,         host1/…:5"         }
      is_disk_image:  bool,    ),                    ]
      is_memory_dump: bool,    ...
      is_pcap:        bool     ]
    },
    ...
  ]


  hypotheses[]               verified[]
  ─────────────              ──────────────────────────────
  [                          [
    {                          {
      claim:   str,              claim:      str,
      support: str               support:    str,
    },                           attck_id:   str,
    ...                          attck_name: str,
  ]                              confidence: str
                               },
                               ...
                             ]


  correlations[]             report.txt
  ──────────────             ───────────────────────────────────────
  [                          === FORENSIC REPORT ===
    {
      match_type: str,       - FINDING: <claim>
      value:      str,         CONFIDENCE: CONFIRMED|PROBABLE|POSSIBLE
      attck_name: str,         ATT&CK:     [Txxxx.xxx] <technique name>
      hosts:      [str],       SOURCE:     <path>
      findings: [
        {                    === CROSS-HOST CORRELATION ===
          idx:   int,
          host:  str,        [HASH MATCH] SHA256: <16-char prefix>...
          claim: str           Hosts: host1, host2
        }                      - [host1] <claim>
      ]                        - [host2] <claim>
    },
    ...                      [TECHNIQUE MATCH] [T1059.001] PowerShell
  ]                            Hosts: host1, host3
                               - [host1] <claim>
                               - [host3] <claim>
```
