import os
import time
from datetime import datetime, timezone

from utils import logger
from extract_logs import _parse_ts


def normalize_timeline(artifacts):
    logger.info("normalize_start", extra={"data": {"artifact_count": len(artifacts)}})
    t0 = time.monotonic()
    timeline = []

    for atype, source, line in artifacts:
        ts = _parse_ts(line)
        if ts is None:
            # Fall back to the source file's mtime so events from the same file
            # at least sort consistently relative to one another.
            file_path = source.rsplit(":", 1)[0]
            try:
                ts = datetime.fromtimestamp(os.path.getmtime(file_path), tz=timezone.utc)
            except OSError:
                ts = datetime.fromtimestamp(0, tz=timezone.utc)
        event = {
            "time": ts.isoformat(),
            "event_type": atype,
            "source": source,
        }
        if atype in ("yara_confirmed", "yara_suspicious") and line:
            event["detail"] = line
        timeline.append(event)

    timeline = sorted(timeline, key=lambda x: x["time"])
    logger.info("normalize_complete", extra={"data": {
        "event_count": len(timeline),
        "duration_s": round(time.monotonic() - t0, 3),
    }})
    return timeline
