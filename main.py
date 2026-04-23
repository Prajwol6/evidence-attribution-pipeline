import os
import hashlib
import json
from datetime import datetime

import anthropic

# ----------------------------
# 1. INGESTION
# ----------------------------
def ingest_evidence(path):
    evidence_files = []
    for root, _, files in os.walk(path):
        for f in files:
            full_path = os.path.join(root, f)
            with open(full_path, "rb") as file:
                data = file.read()
                evidence_files.append({
                    "path": full_path,
                    "data": data,
                    "hash": hashlib.sha256(data).hexdigest(),
                    "size": len(data)
                })
    return evidence_files


# ----------------------------
# 2. ARTIFACT EXTRACTION
# ----------------------------
def extract_artifacts(evidence):
    artifacts = []

    for item in evidence:
        data = item["data"].decode(errors="ignore")

        # simple heuristic extraction
        if "password" in data.lower():
            artifacts.append(("credential_hint", item["path"]))

        if "cmd.exe" in data.lower() or "powershell" in data.lower():
            artifacts.append(("suspicious_execution", item["path"]))

        if "http://" in data.lower() or "https://" in data.lower():
            artifacts.append(("network_indicator", item["path"]))

    return artifacts


# ----------------------------
# 3. TIMELINE NORMALIZATION
# ----------------------------
def normalize_timeline(artifacts):
    timeline = []

    for i, (atype, source) in enumerate(artifacts):
        timeline.append({
            "time": datetime.utcnow().isoformat(),
            "event_type": atype,
            "source": source
        })

    return sorted(timeline, key=lambda x: x["time"])


# ----------------------------
# 4. LLM REASONING
# ----------------------------
def llm_reason(timeline):
    client = anthropic.Anthropic()

    response = client.messages.create(
        model="claude-opus-4-7",
        max_tokens=4096,
        thinking={"type": "adaptive"},
        system=(
            "You are a forensic analyst examining security event timelines. "
            "Analyze the events and generate hypotheses about potential security incidents. "
            "The 'support' field in each hypothesis must be the exact source file path "
            "from the corresponding timeline event — do not summarize or paraphrase it."
        ),
        messages=[{
            "role": "user",
            "content": (
                "Analyze this forensic timeline and generate hypotheses:\n\n"
                + json.dumps(timeline, indent=2)
            )
        }],
        output_config={
            "format": {
                "type": "json_schema",
                "schema": {
                    "type": "object",
                    "properties": {
                        "hypotheses": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "claim": {"type": "string"},
                                    "support": {"type": "string"}
                                },
                                "required": ["claim", "support"],
                                "additionalProperties": False
                            }
                        }
                    },
                    "required": ["hypotheses"],
                    "additionalProperties": False
                }
            }
        }
    )

    text = next(b.text for b in response.content if b.type == "text")
    return json.loads(text)["hypotheses"]


# ----------------------------
# 5. VERIFICATION LAYER (CRITICAL PART)
# ----------------------------
def verify_hypothesis(hypothesis):
    # fake verification logic (replace with real checks later)
    required_keywords = ["powershell", "cmd", "http"]

    try:
        with open(hypothesis["support"], "r", errors="ignore") as f:
            content = f.read().lower()

        return any(k in content for k in required_keywords)

    except:
        return False


# ----------------------------
# 6. REPORT GENERATION
# ----------------------------
def generate_report(verified):
    report = []
    report.append("=== FORENSIC REPORT ===\n")

    for item in verified:
        report.append(f"- FINDING: {item['claim']}")
        report.append(f"  SOURCE: {item['support']}\n")

    output = "\n".join(report)

    with open("report.txt", "w") as f:
        f.write(output)

    print(output)


# ----------------------------
# MAIN PIPELINE
# ----------------------------
def main():
    evidence = ingest_evidence("evidence/")
    artifacts = extract_artifacts(evidence)
    timeline = normalize_timeline(artifacts)
    hypotheses = llm_reason(timeline)
    verified = [h for h in hypotheses if verify_hypothesis(h)]
    generate_report(verified)


if __name__ == "__main__":
    main()
