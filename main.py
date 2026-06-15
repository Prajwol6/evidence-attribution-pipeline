import time

from utils import logger
from ingest import ingest_evidence
from extract import extract_artifacts
from normalize import normalize_timeline
from reason import llm_reason
from verify import verify_hypothesis
from attck import map_to_attck
from confidence import compute_confidence
from correlate import correlate_findings
from report import generate_report
from scan_yara import get_scan_stats


def main():
    t0 = time.monotonic()
    logger.info("pipeline_start")
    evidence = ingest_evidence("evidence/")
    artifacts = extract_artifacts(evidence)
    timeline = normalize_timeline(artifacts)
    hypotheses = llm_reason(timeline)

    verified = []
    for h in hypotheses:
        verify_result = verify_hypothesis(h)
        if verify_result:
            technique = map_to_attck(h["claim"])
            confidence = compute_confidence(
                verify_result["evidence_found"],
                verify_result["grep_hits"],
                verify_result["file_type"],
            )
            h["attck_id"] = technique["id"]
            h["attck_name"] = technique["name"]
            h["confidence"] = confidence
            logger.info("finding_scored", extra={"data": {
                "claim": h["claim"],
                "confidence": confidence,
                "attck_id": technique["id"],
                "attck_name": technique["name"],
                "evidence_count": len(verify_result["evidence_found"]),
                "grep_hit_count": len(verify_result["grep_hits"]),
                "file_type": verify_result["file_type"],
            }})
            verified.append(h)

    correlations = correlate_findings(verified)
    generate_report(verified, correlations, scan_stats=get_scan_stats())
    logger.info("pipeline_complete", extra={"data": {
        "verified_findings": len(verified),
        "total_duration_s": round(time.monotonic() - t0, 3),
    }})


if __name__ == "__main__":
    main()
