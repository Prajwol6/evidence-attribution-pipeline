import time

from utils import logger
from extract_logs import extract_log_artifacts
from extract_disk import extract_disk_image_artifacts
from extract_memory import extract_memory_artifacts
from extract_network import extract_pcap_artifacts


def extract_artifacts(evidence):
    logger.info("extract_start", extra={"data": {"file_count": len(evidence)}})
    t0 = time.monotonic()
    artifacts = []

    for item in evidence:
        if item.get("is_memory_dump"):
            artifacts.extend(extract_memory_artifacts(item))
        elif item.get("is_disk_image"):
            artifacts.extend(extract_disk_image_artifacts(item))
        elif item.get("is_pcap"):
            artifacts.extend(extract_pcap_artifacts(item))
        else:
            artifacts.extend(extract_log_artifacts(item))

    by_type = {}
    for atype, _, __ in artifacts:
        by_type[atype] = by_type.get(atype, 0) + 1
    logger.info("extract_complete", extra={"data": {
        "artifact_count": len(artifacts),
        "by_type": by_type,
        "duration_s": round(time.monotonic() - t0, 3),
    }})
    return artifacts
