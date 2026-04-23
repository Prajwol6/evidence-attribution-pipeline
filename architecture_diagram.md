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
  ║  ├─ test.log          51 B   ║
  ║  ├─ windows_event.log 205 B  ║
  ║  ├─ evidence.zip        0 B  ║
  ║  └─ ex2.pcap            0 B  ║
  ╚══════════════╤═══════════════╝
                 │ os.walk()
                 ▼
  ┌──────────────────────────────────────────────┐  ┌─────────────────────────────────┐
  │  STEP 1 · INGESTION                          │  │  STRUCTURED LOGGING             │
  │  ingest_evidence(path)                       │  │  _JsonFormatter → FileHandler   │
  │                                              │  │  logs/agent_execution.log       │
  │  • os.walk()  recursive directory scan       │  │                                 │
  │  • open(file, "rb")  binary-safe read        │  │  ← pipeline_start               │
  │  • hashlib.sha256(data).hexdigest()          │──▶  ← ingest_start                │
  │  • record: path · data · hash · size         │  │  ← ingest_complete              │
  └──────────────────────┬───────────────────────┘  │    {file_count, total_bytes,    │
                         │                          │     duration_s}                 │
   evidence_files[]      │                          │                                 │
   list of dicts:        │                          │                                 │
   {path, data,          │                          │                                 │
    hash, size}          │                          │                                 │
                         ▼                          │                                 │
  ┌──────────────────────────────────────────────┐  │                                 │
  │  STEP 2 · ARTIFACT EXTRACTION                │  │                                 │
  │  extract_artifacts(evidence)                 │  │                                 │
  │                                              │  │                                 │
  │  heuristic keyword matching — per file:      │──▶  ← extract_start               │
  │                                              │  │  ← extract_complete             │
  │  "password"              → credential_hint   │  │    {artifact_count,             │
  │  "powershell" | "cmd.exe"→ suspicious_exec   │  │     by_type{},                 │
  │  "http://"   | "https://"→ network_indicator │  │     duration_s}                 │
  └──────────────────────┬───────────────────────┘  │                                 │
                         │                          │                                 │
   artifacts[]           │                          │                                 │
   list of tuples:       │                          │                                 │
   (type, source_path)   │                          │                                 │
                         ▼                          │                                 │
  ┌──────────────────────────────────────────────┐  │                                 │
  │  STEP 3 · TIMELINE NORMALIZATION             │  │                                 │
  │  normalize_timeline(artifacts)               │  │                                 │
  │                                              │  │                                 │
  │  • datetime.now(UTC) per event               │──▶  ← normalize_start             │
  │  • build {time, event_type, source}          │  │  ← normalize_complete           │
  │  • sorted(timeline, key=x["time"])           │  │    {event_count, duration_s}    │
  └──────────────────────┬───────────────────────┘  │                                 │
                         │                          │                                 │
   timeline[]            │                          │                                 │
   list of dicts:        │                          │                                 │
   {time, event_type,    │                          │                                 │
    source}              │                          │                                 │
                         ▼                          │                                 │
  ┌──────────────────────────────────────────────┐  │                                 │
  │  STEP 4 · LLM REASONING                      │  │                                 │
  │  llm_reason(timeline)                        │  │                                 │
  │                                              │  │                                 │
  │  model:      claude-opus-4-7                 │──▶  ← llm_reason_start             │
  │  thinking:   adaptive                        │  │    {event_count}                │
  │  output:     JSON schema enforced            │  │                                 │
  │  max_tokens: 4096                            │  │  ← llm_reason_retry  (WARNING)  │
  │  max_retries: 3                              │  │    {attempt, max_retries,       │
  │                                              │  │     error, raw_output}          │
  │  ┌── self-correction retry loop ───────────┐ │  │                                 │
  │  │                                         │ │  │  ← llm_reason_complete          │
  │  │  messages = [{role:user, content:...}]  │ │  │    {attempt, hypothesis_count,  │
  │  │                  │                      │ │  │     input_tokens,               │
  │  │                  ▼                      │ │  │     output_tokens,              │
  │  │         API call (attempt N)            │ │  │     total_tokens,               │
  │  │                  │                      │ │  │     duration_s}                 │
  │  │       ┌──────────┴──────────┐           │ │  │                                 │
  │  │  pass │                     │ fail       │ │  │                                 │
  │  │       ▼                     ▼           │ │  │                                 │
  │  │  return hypotheses   check: N < 3?      │ │  │                                 │
  │  │                            │            │ │  │                                 │
  │  │                       yes  │  no        │ │  │                                 │
  │  │                            ▼    ▼       │ │  │                                 │
  │  │               append bad response  raise│ │  │                                 │
  │  │               + correction msg  RuntimeError│ │                               │
  │  │               to messages[]            │ │  │                                 │
  │  │                       │                │ │  │                                 │
  │  │                       └──▶ attempt N+1 │ │  │                                 │
  │  └─────────────────────────────────────────┘ │  │                                 │
  └──────────────────────┬───────────────────────┘  │                                 │
                         │                          │                                 │
   hypotheses[]          │                          │                                 │
   list of dicts:        │                          │                                 │
   {claim, support}      │  for each hypothesis:    │                                 │
                         ▼                          │                                 │
  ┌──────────────────────────────────────────────┐  │                                 │
  │  STEP 5 · HYPOTHESIS VERIFICATION            │  │                                 │
  │  verify_hypothesis(hypothesis)               │  │                                 │
  │                                              │  │  ← verify_hypothesis            │
  │  subprocess calls (30 s timeout each):       │──▶    {claim, support,             │
  │                                              │  │     file_type, grep_hits,       │
  │  ┌──────────────────────────────────────┐    │  │     evidence_found[],           │
  │  │ file   <source>                      │    │  │     verified: true|false}       │
  │  │  → identify file type                │    │  │                                 │
  │  │                                      │    │  │  ← verify_hypothesis_failed     │
  │  │ strings <source>                     │    │  │    (WARNING, if not verified)   │
  │  │  → extract printable sequences       │    │  │    {claim, support, file_type}  │
  │  │  → scan for IOC keywords:            │    │  │                                 │
  │  │    powershell · cmd.exe · http://    │    │  │                                 │
  │  │    https:// · wget · curl · passwd   │    │  │                                 │
  │  │    /bin/sh · /bin/bash · credential  │    │  │                                 │
  │  │                                      │    │  │                                 │
  │  │ grep -iEo <pattern> <source>         │    │  │                                 │
  │  │  → claim-keyed regex patterns:       │    │  │                                 │
  │  │    execution → powershell            │    │  │                                 │
  │  │               cmd\.exe              │    │  │                                 │
  │  │               cmd /[a-z]            │    │  │                                 │
  │  │               /bin/(sh|bash)        │    │  │                                 │
  │  │    network   → https?://[^\s]+      │    │  │                                 │
  │  │               \b\d{1,3}(\.\d{1,3}) │    │  │                                 │
  │  │    credential→ password\s*[:=]      │    │  │                                 │
  │  │               passwd                │    │  │                                 │
  │  │                                      │    │  │                                 │
  │  │ xxd <source>                         │    │  │                                 │
  │  │  → hex dump, first 1024 B logged     │    │  │                                 │
  │  └──────────────────────────────────────┘    │  │                                 │
  │                                              │  │                                 │
  │  verified = len(evidence_found) > 0          │  │                                 │
  └──────────────────────┬───────────────────────┘  │                                 │
                         │                          │                                 │
   verified[]            │  only hypotheses         │                                 │
   [{claim, support}]    │  that passed SIFT checks │                                 │
                         ▼                          │                                 │
  ┌──────────────────────────────────────────────┐  │                                 │
  │  STEP 6 · REPORT GENERATION                  │  │                                 │
  │  generate_report(verified)                   │  │                                 │
  │                                              │  │  ← report_start                 │
  │  • format: "FINDING / SOURCE" blocks         │──▶  ← report_complete              │
  │  • write → report.txt                        │  │    {output_path}                │
  │  • print → stdout                            │  │                                 │
  └──────────────────────┬───────────────────────┘  │  ← pipeline_complete           │
                         │                          │    {verified_findings,          │
                         ▼                          │     total_duration_s}           │
  ╔══════════════════════════════╗                  └─────────────────────────────────┘
  ║       OUTPUTS               ║
  ║  ├─ report.txt              ║  persisted finding list
  ║  └─ stdout                  ║  terminal output
  ╚═════════════════════════════╝
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
                + IOC scan     deduped list       logged)
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
               verified=True   verified=False
                                    │
                               log WARNING:
                               verify_hypothesis_failed
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
| `ingest_complete` | INFO | `file_count`, `total_bytes`, `duration_s` |
| `extract_start` | INFO | `file_count` |
| `extract_complete` | INFO | `artifact_count`, `by_type`, `duration_s` |
| `normalize_start` | INFO | `artifact_count` |
| `normalize_complete` | INFO | `event_count`, `duration_s` |
| `llm_reason_start` | INFO | `event_count` |
| `llm_reason_retry` | WARNING | `attempt`, `max_retries`, `error`, `raw_output` |
| `llm_reason_complete` | INFO | `attempt`, `hypothesis_count`, `input_tokens`, `output_tokens`, `total_tokens`, `duration_s` |
| `verify_hypothesis` | INFO | `claim`, `support`, `file_type`, `grep_hits`, `evidence_found`, `verified` |
| `verify_hypothesis_failed` | WARNING | `claim`, `support`, `file_type` |
| `report_start` | INFO | `verified_count` |
| `report_complete` | INFO | `output_path` |
| `pipeline_complete` | INFO | `verified_findings`, `total_duration_s` |

---

## Data Structures at Each Stage Boundary

```
  evidence_files[]          artifacts[]           timeline[]
  ─────────────────         ────────────          ──────────────────────
  [                         [                     [
    {                         (                     {
      path: str,                "suspicious_          time:       str,
      data: bytes,               execution",          event_type: str,
      hash: str,                 "evidence/           source:     str
      size: int                  test.log"          }
    },                        ),                   ]
    ...                       ...
  ]                         ]


  hypotheses[]              verified[]            report.txt
  ─────────────             ──────────            ──────────
  [                         [                     === FORENSIC REPORT ===
    {                         {
      claim:   str,             claim:   str,     - FINDING: <claim>
      support: str              support: str        SOURCE:  <support>
    },                        },
    ...                       ...               (written + printed)
  ]                         ]
```
