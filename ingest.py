import hashlib
import os
import re
import time

from utils import logger

# .raw is intentionally absent — it is reserved for memory dumps below.
# Raw disk images should use the .dd extension instead.
DISK_IMAGE_EXTS = frozenset({
    ".dd", ".img", ".e01", ".vmdk", ".vhd", ".vhdx", ".iso",
})
MEMORY_DUMP_EXTS = frozenset({".vmem", ".mem", ".raw"})
PCAP_EXTS = frozenset({".pcap", ".pcapng"})


def ingest_evidence(path):
    logger.info("ingest_start", extra={"data": {"path": path}})
    t0 = time.monotonic()
    evidence_files = []
    for root, _, files in os.walk(path):
        for f in files:
            full_path = os.path.join(root, f)
            ext = os.path.splitext(f)[1].lower()
            if ext in MEMORY_DUMP_EXTS:
                # Volatility3 reads the dump directly by path; never load it
                # into RAM. Stream solely to compute the integrity hash.
                sha = hashlib.sha256()
                with open(full_path, "rb") as fh:
                    for chunk in iter(lambda: fh.read(65536), b""):
                        sha.update(chunk)
                evidence_files.append({
                    "path":           full_path,
                    "data":           b"",
                    "hash":           sha.hexdigest(),
                    "size":           os.path.getsize(full_path),
                    "is_disk_image":  False,
                    "is_memory_dump": True,
                    "is_pcap":        False,
                })
            elif ext in DISK_IMAGE_EXTS:
                # For split E01 images, skip every segment file that carries a
                # parenthesised number in its stem (e.g. image(1).E01,
                # image(2).E01 …). ewfmount locates all segments automatically
                # when given the base file (image.E01). Processing the segments
                # individually would try to mount incomplete images and produce
                # duplicate or partial results.
                if ext == ".e01" and re.search(r"\(\d+\)", os.path.splitext(f)[0]):
                    logger.info("disk_image_segment_skipped", extra={"data": {
                        "path":   full_path,
                        "reason": "non-base E01 segment — ewfmount reads it from the base file",
                    }})
                    continue

                # Stream the hash in chunks — disk images can be many gigabytes.
                # Store only the first 512 bytes so magic-byte checks remain possible
                # without loading the entire image into RAM.
                sha = hashlib.sha256()
                header = b""
                with open(full_path, "rb") as fh:
                    for chunk in iter(lambda: fh.read(65536), b""):
                        sha.update(chunk)
                        if not header:
                            header = chunk[:512]
                evidence_files.append({
                    "path":           full_path,
                    "data":           header,
                    "hash":           sha.hexdigest(),
                    "size":           os.path.getsize(full_path),
                    "is_disk_image":  True,
                    "is_memory_dump": False,
                    "is_pcap":        False,
                })
            elif ext in PCAP_EXTS:
                # tshark reads the capture directly by path; stream hash only.
                sha = hashlib.sha256()
                with open(full_path, "rb") as fh:
                    for chunk in iter(lambda: fh.read(65536), b""):
                        sha.update(chunk)
                evidence_files.append({
                    "path":           full_path,
                    "data":           b"",
                    "hash":           sha.hexdigest(),
                    "size":           os.path.getsize(full_path),
                    "is_disk_image":  False,
                    "is_memory_dump": False,
                    "is_pcap":        True,
                })
            else:
                with open(full_path, "rb") as file:
                    data = file.read()
                evidence_files.append({
                    "path":           full_path,
                    "data":           data,
                    "hash":           hashlib.sha256(data).hexdigest(),
                    "size":           len(data),
                    "is_disk_image":  False,
                    "is_memory_dump": False,
                    "is_pcap":        False,
                })
    disk_image_count  = sum(1 for e in evidence_files if e["is_disk_image"])
    memory_dump_count = sum(1 for e in evidence_files if e["is_memory_dump"])
    pcap_count        = sum(1 for e in evidence_files if e["is_pcap"])
    logger.info("ingest_complete", extra={"data": {
        "file_count":   len(evidence_files),
        "disk_images":  disk_image_count,
        "memory_dumps": memory_dump_count,
        "pcaps":        pcap_count,
        "total_bytes":  sum(e["size"] for e in evidence_files),
        "duration_s":   round(time.monotonic() - t0, 3),
    }})
    return evidence_files
