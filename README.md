# Evidence Attribution Pipeline

A forensic analysis pipeline that ingests raw evidence files, extracts security artifacts, and uses Claude's extended thinking to generate and verify hypotheses about potential security incidents — producing a grounded, source-attributed report.

## Overview

This tool automates the core steps of a digital forensics investigation:

1. **Ingest** — Walk a directory of evidence files, read them, and compute SHA-256 hashes for integrity verification.
2. **Extract** — Apply heuristic pattern matching to detect artifacts: credential hints, suspicious process executions, and network indicators.
3. **Normalize** — Build a chronologically sorted event timeline from the extracted artifacts.
4. **LLM Reasoning** — Send the timeline to Claude (claude-opus-4-7 with adaptive extended thinking) and receive structured, source-attributed hypotheses about the incident.
5. **Verify** — Cross-check each hypothesis against its cited source file; only hypotheses that can be confirmed against the raw evidence are promoted.
6. **Report** — Write verified findings to `report.txt`, with each claim linked back to its source file.

Every step is recorded as structured JSON to `logs/agent_execution.log`, including token usage and duration metrics.

## Architecture

```
evidence/               ← Input directory of raw evidence files
│
└── (logs, binaries, text files...)
        │
        ▼
┌─────────────────┐
│  1. Ingestion   │  os.walk + sha256 hash
└────────┬────────┘
         │ evidence_files[]
         ▼
┌─────────────────────┐
│  2. Artifact        │  keyword heuristics:
│     Extraction      │  credential_hint | suspicious_execution | network_indicator
└────────┬────────────┘
         │ artifacts[]
         ▼
┌─────────────────────┐
│  3. Timeline        │  sort by UTC timestamp
│     Normalization   │
└────────┬────────────┘
         │ timeline[]
         ▼
┌─────────────────────────┐
│  4. LLM Reasoning       │  Claude claude-opus-4-7
│     (claude-opus-4-7)   │  adaptive thinking + JSON schema output
└────────┬────────────────┘
         │ hypotheses[]
         ▼
┌─────────────────────┐
│  5. Verification    │  re-read source file, keyword check
└────────┬────────────┘
         │ verified[]
         ▼
┌─────────────────────┐
│  6. Report          │  report.txt + stdout
└─────────────────────┘

logs/agent_execution.log  ← structured JSON log for every step
```

### Key design decisions

- **Grounded attribution**: The LLM is instructed to use exact source file paths from the timeline. The verification layer then opens those files and confirms the claim is supported — hallucinated paths fail verification and are dropped.
- **Structured output**: The Claude API call uses `output_config` with a JSON schema, so hypotheses always arrive in a predictable `{claim, support}` shape.
- **Adaptive thinking**: `thinking: {type: "adaptive"}` lets the model use extended reasoning only when the timeline complexity warrants it, keeping latency and token cost proportional to difficulty.
- **Integrity hashing**: Every ingested file is SHA-256 hashed at read time so provenance can be audited later.

## Requirements

- Python 3.9+
- An Anthropic API key with access to `claude-opus-4-7`

### Python dependencies

```
anthropic
```

Install with:

```bash
pip install anthropic
```

## Installation

```bash
git clone <repo-url>
cd evidence-attribution-pipeline
pip install anthropic
export ANTHROPIC_API_KEY="sk-ant-..."
```

## Usage

1. Place evidence files (logs, text files, binaries) inside the `evidence/` directory.
2. Run the pipeline:

```bash
python main.py
```

The pipeline will:
- Print the forensic report to stdout when complete.
- Write the same report to `report.txt`.
- Append structured JSON logs to `logs/agent_execution.log`.

### Evidence directory

```
evidence/
├── auth.log
├── syslog
├── network_capture.txt
└── ...
```

Any file format is accepted. The extractor reads files as text (with `errors="ignore"` for binary files) and scans for the following patterns:

| Artifact type           | Trigger keyword(s)              |
|-------------------------|---------------------------------|
| `credential_hint`       | `password`                      |
| `suspicious_execution`  | `cmd.exe`, `powershell`         |
| `network_indicator`     | `http://`, `https://`           |

## Example output

### report.txt / stdout

```
=== FORENSIC REPORT ===

- FINDING: A suspicious process execution occurred which may indicate malware or unauthorized activity on the host.
  SOURCE: evidence/test.log

- FINDING: A network indicator was observed contemporaneously with the suspicious execution, suggesting possible C2 communication or data exfiltration initiated by the executed process.
  SOURCE: evidence/test.log
```

### logs/agent_execution.log (structured JSON)

```json
{"timestamp": "2026-04-23T04:23:23.321928+00:00", "level": "INFO", "step": "pipeline_start"}
{"timestamp": "2026-04-23T04:23:23.322039+00:00", "level": "INFO", "step": "ingest_complete", "data": {"file_count": 1, "total_bytes": 51, "duration_s": 0.0}}
{"timestamp": "2026-04-23T04:23:23.322088+00:00", "level": "INFO", "step": "extract_complete", "data": {"artifact_count": 2, "by_type": {"suspicious_execution": 1, "network_indicator": 1}, "duration_s": 0.0}}
{"timestamp": "2026-04-23T04:23:27.190511+00:00", "level": "INFO", "step": "llm_reason_complete", "data": {"hypothesis_count": 2, "input_tokens": 528, "output_tokens": 133, "total_tokens": 661, "duration_s": 3.868}}
{"timestamp": "2026-04-23T04:23:27.190643+00:00", "level": "INFO", "step": "verify_hypothesis", "data": {"claim": "A suspicious process execution...", "support": "evidence/test.log", "verified": true}}
{"timestamp": "2026-04-23T04:23:27.192959+00:00", "level": "INFO", "step": "pipeline_complete", "data": {"verified_findings": 2, "total_duration_s": 3.871}}
```

## Project structure

```
evidence-attribution-pipeline/
├── main.py                    # Full pipeline (single file)
├── evidence/                  # Input evidence directory
│   └── test.log               # Sample evidence file
├── logs/
│   └── agent_execution.log    # Structured JSON execution log
├── report.txt                 # Generated forensic report
└── README.md
```

## Limitations

- The heuristic extractor uses simple substring matching. Complex obfuscated artifacts (base64-encoded commands, encrypted traffic) will not be detected without extending the extraction rules.
- Timeline timestamps are assigned at runtime rather than parsed from the evidence files themselves, so event ordering reflects processing order, not actual incident timing.
- Verification only checks for the presence of a short keyword list (`powershell`, `cmd`, `http`); a hypothesis citing a file that contains these keywords but for unrelated reasons will still pass.
