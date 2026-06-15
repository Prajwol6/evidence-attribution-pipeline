import csv
import io
import math
import os
from datetime import datetime, timezone

from utils import logger, _run_tool, _is_rfc1918

_EXTRACTED_DIR = "extracted"
_BEACON_THRESHOLD    = 10     # packets to same external dst:port → beaconing candidate
_HIGH_ENTROPY_THRESHOLD = 3.5 # Shannon entropy threshold for DGA/tunnelling detection
_DNS_TUNNEL_LEN      = 50     # DNS query names longer than this are suspicious
_COMMON_PORTS        = frozenset({
    21, 22, 23, 25, 53, 80, 110, 143, 443,
    465, 587, 993, 995, 1433, 3306, 3389, 5900, 8080, 8443,
})


def _parse_tshark_csv(output):
    """
    Parse tshark -T fields output (with -E header=y -E quote=d) into a list
    of row dicts.  The first non-blank line is taken as the header.
    """
    lines = [l for l in output.splitlines() if l.strip()]
    if not lines:
        return []
    try:
        return list(csv.DictReader(io.StringIO("\n".join(lines))))
    except csv.Error:
        return []


def _tshark(pcap_path, display_filter=None, fields=None, timeout=60):
    """
    Run tshark on a pcap file and return (rows, stderr, returncode).

    -E quote=d    double-quotes all values so csv.DictReader handles commas
                  inside User-Agent strings or URIs without misaligning columns.
    -E occurrence=f  keeps only the first occurrence of each field per packet,
                  preventing duplicated values on multi-value frames (e.g. a
                  DNS response with several A records).
    """
    cmd = [
        "tshark", "-r", pcap_path,
        "-T", "fields",
        "-E", "header=y",
        "-E", "separator=,",
        "-E", "quote=d",
        "-E", "occurrence=f",
    ]
    if display_filter:
        cmd += ["-Y", display_filter]
    for f in fields or []:
        cmd += ["-e", f]
    stdout, stderr, rc = _run_tool(cmd, timeout=timeout)
    return _parse_tshark_csv(stdout), stderr, rc


def _epoch_to_iso(epoch_str):
    """
    Convert a tshark frame.time_epoch float string ('1673776800.123456') to a
    space-separated ISO-8601 UTC string ('2023-01-15 09:00:00') that _parse_ts()
    can match with its existing regex.  Returns '' on any conversion error.
    """
    try:
        ts = datetime.fromtimestamp(float(epoch_str), tz=timezone.utc)
        return ts.strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError, OSError):
        return ""


def _shannon_entropy(s):
    """Shannon entropy (bits per symbol) of string s."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((cnt / n) * math.log2(cnt / n) for cnt in freq.values())


def extract_pcap_artifacts(item):
    """
    Analyse a network capture with tshark and return forensic artifacts.

    Four targeted passes over the capture file:

      1. IP connections  — all src→dst:port pairs; flag beaconing when the
         same external dst:port is seen ≥ _BEACON_THRESHOLD times.
      2. DNS queries     — extract queried names; flag long names, many labels,
         or high Shannon-entropy leftmost labels as DGA / DNS-tunnelling.
      3. HTTP requests   — extract method, host, URI, User-Agent; flag plain
         HTTP on non-standard ports to external IPs.
      4. TLS Client Hellos — extract SNI; flag missing SNI or high-entropy SNI
         hostnames on non-standard ports to external IPs.

    All C2 candidates from every pass are accumulated and written to a single
    c2_candidates.txt file at the end of the function.

    Source paths in all returned artifacts point to real files under
    extracted/ so verify_hypothesis() can run file/strings/grep/xxd on them
    without any modification.
    """
    pcap_path   = item["path"]
    pcap_stem   = os.path.splitext(os.path.basename(pcap_path))[0]
    extract_dir = os.path.join(_EXTRACTED_DIR, pcap_stem)
    os.makedirs(extract_dir, exist_ok=True)
    artifacts: list[tuple] = []

    logger.info("pcap_start", extra={"data": {
        "pcap": pcap_path,
        "size": item["size"],
        "hash": item["hash"],
    }})

    # C2 candidates accumulate across all four passes; written once at the end.
    c2_path  = os.path.join(extract_dir, "c2_candidates.txt")
    c2_lines: list[str] = []

    def _add_c2(line):
        c2_lines.append(line)
        artifacts.append(("pcap_c2_candidate", f"{c2_path}:{len(c2_lines)}", line))

    # ── Step 1: IP connections ─────────────────────────────────────────────
    conn_rows, _, conn_rc = _tshark(
        pcap_path,
        display_filter="ip",
        fields=["frame.time_epoch", "ip.src", "ip.dst",
                "tcp.dstport", "udp.dstport"],
    )
    if conn_rc == 127:
        logger.warning("pcap_tshark_not_found", extra={"data": {
            "pcap": pcap_path,
            "hint": "install tshark (e.g. apt install tshark) and re-run",
        }})
        return artifacts

    conn_rows = conn_rows or []
    conn_path = os.path.join(extract_dir, "connections.txt")
    with open(conn_path, "w") as fh:
        for row in conn_rows:
            src  = (row.get("ip.src")       or "").strip()
            dst  = (row.get("ip.dst")       or "").strip()
            tcp  = (row.get("tcp.dstport")  or "").strip()
            udp  = (row.get("udp.dstport")  or "").strip()
            port = tcp or udp
            proto = "TCP" if tcp else ("UDP" if udp else "IP")
            fh.write(f"{src} -> {dst}:{port} {proto}\n")

    # Count packets per (dst_ip, dst_port); track first timestamp and source IP.
    pair_count:    dict[tuple[str, str], int] = {}
    pair_first_ts: dict[tuple[str, str], str] = {}
    pair_src:      dict[tuple[str, str], str] = {}
    for row in conn_rows:
        dst  = (row.get("ip.dst")           or "").strip()
        tcp  = (row.get("tcp.dstport")      or "").strip()
        udp  = (row.get("udp.dstport")      or "").strip()
        port = tcp or udp
        src  = (row.get("ip.src")           or "").strip()
        ep   = (row.get("frame.time_epoch") or "").strip()
        if dst and port:
            key = (dst, port)
            pair_count[key] = pair_count.get(key, 0) + 1
            if key not in pair_first_ts:
                pair_first_ts[key] = ep
                pair_src[key]      = src

    artifacts.append((
        "pcap_connection_summary",
        f"{conn_path}:1",
        f"network capture {pcap_path}: {len(conn_rows)} IP packets, "
        f"{len(pair_count)} unique dst:port pairs",
    ))

    for (dst, port), count in sorted(pair_count.items(), key=lambda x: -x[1]):
        if count < _BEACON_THRESHOLD:
            continue
        try:
            if _is_rfc1918(dst):
                continue
        except Exception:
            continue
        ts  = _epoch_to_iso(pair_first_ts.get((dst, port), ""))
        src = pair_src.get((dst, port), "unknown")
        _add_c2(f"{ts} beaconing {src} -> {dst}:{port} ({count} packets)")
        logger.info("pcap_beaconing_detected", extra={"data": {
            "pcap": pcap_path, "dst": dst, "port": port, "count": count,
        }})

    logger.info("pcap_connections_complete", extra={"data": {
        "pcap":             pcap_path,
        "packets":          len(conn_rows),
        "unique_dst_pairs": len(pair_count),
        "beaconing_hits":   sum(1 for v in pair_count.values() if v >= _BEACON_THRESHOLD),
    }})

    # ── Step 2: DNS queries ────────────────────────────────────────────────
    dns_rows, _, _ = _tshark(
        pcap_path,
        display_filter="dns.flags.response eq 0",
        fields=["frame.time_epoch", "ip.src", "dns.qry.name"],
    )
    dns_rows = dns_rows or []
    dns_path = os.path.join(extract_dir, "dns_queries.txt")
    with open(dns_path, "w") as fh:
        for row in dns_rows:
            ts    = _epoch_to_iso((row.get("frame.time_epoch") or "").strip())
            src   = (row.get("ip.src")       or "").strip()
            qname = (row.get("dns.qry.name") or "").strip().rstrip(".")
            fh.write(f"{ts} {src} -> {qname}\n")

    for lineno, row in enumerate(dns_rows, start=1):
        ts    = _epoch_to_iso((row.get("frame.time_epoch") or "").strip())
        src   = (row.get("ip.src")       or "").strip()
        qname = (row.get("dns.qry.name") or "").strip().rstrip(".")
        if not qname:
            continue

        artifacts.append((
            "pcap_dns_query",
            f"{dns_path}:{lineno}",
            f"{ts} DNS query {src} -> {qname}",
        ))

        labels  = qname.split(".")
        reasons = []
        if len(qname) > _DNS_TUNNEL_LEN:
            reasons.append(f"name length {len(qname)} > {_DNS_TUNNEL_LEN}")
        if len(labels) > 5:
            reasons.append(f"{len(labels)} labels")
        if labels:
            ent = _shannon_entropy(labels[0])
            if ent > _HIGH_ENTROPY_THRESHOLD:
                reasons.append(f"label entropy {ent:.2f} (DGA/tunnelling indicator)")
        if reasons:
            _add_c2(f"{ts} DNS anomaly {src} -> {qname} — {', '.join(reasons)}")
            logger.info("pcap_dns_anomaly", extra={"data": {
                "pcap": pcap_path, "qname": qname, "reasons": reasons,
            }})

    logger.info("pcap_dns_complete", extra={"data": {
        "pcap": pcap_path, "dns_queries": len(dns_rows),
    }})

    # ── Step 3: HTTP requests ──────────────────────────────────────────────
    http_rows, _, _ = _tshark(
        pcap_path,
        display_filter="http.request",
        fields=["frame.time_epoch", "ip.src", "ip.dst", "tcp.dstport",
                "http.request.method", "http.host",
                "http.request.uri",    "http.user_agent"],
    )
    http_rows = http_rows or []
    http_path = os.path.join(extract_dir, "http_requests.txt")
    with open(http_path, "w") as fh:
        for row in http_rows:
            ts     = _epoch_to_iso((row.get("frame.time_epoch")    or "").strip())
            src    = (row.get("ip.src")                             or "").strip()
            dst    = (row.get("ip.dst")                             or "").strip()
            port   = (row.get("tcp.dstport")                        or "80").strip()
            method = (row.get("http.request.method")                or "").strip()
            host   = (row.get("http.host")                          or dst).strip()
            uri    = (row.get("http.request.uri")                   or "/").strip()
            ua     = (row.get("http.user_agent")                    or "").strip()
            fh.write(
                f"{ts} {src} -> {dst}:{port} "
                f"{method} http://{host}{uri} UA:{ua}\n"
            )

    for lineno, row in enumerate(http_rows, start=1):
        ts     = _epoch_to_iso((row.get("frame.time_epoch")   or "").strip())
        src    = (row.get("ip.src")                            or "").strip()
        dst    = (row.get("ip.dst")                            or "").strip()
        port   = (row.get("tcp.dstport")                       or "80").strip()
        method = (row.get("http.request.method")               or "").strip()
        host   = (row.get("http.host")                         or dst).strip()
        uri    = (row.get("http.request.uri")                  or "/").strip()
        ua     = (row.get("http.user_agent")                   or "").strip()

        artifacts.append((
            "pcap_http_request",
            f"{http_path}:{lineno}",
            f"{ts} HTTP {method} http://{host}{uri} {src}->{dst}:{port} UA:{ua}",
        ))

        try:
            if int(port) not in _COMMON_PORTS and not _is_rfc1918(dst):
                _add_c2(
                    f"{ts} HTTP on non-standard port {port}: "
                    f"{src} -> {dst}:{port} {method} http://{host}{uri}"
                )
        except (ValueError, TypeError):
            pass

    logger.info("pcap_http_complete", extra={"data": {
        "pcap": pcap_path, "http_requests": len(http_rows),
    }})

    # ── Step 4: TLS Client Hellos ──────────────────────────────────────────
    tls_rows, _, _ = _tshark(
        pcap_path,
        display_filter="tls.handshake.type == 1",
        fields=["frame.time_epoch", "ip.src", "ip.dst", "tcp.dstport",
                "tls.handshake.extensions_server_name"],
    )
    tls_rows = tls_rows or []
    tls_path = os.path.join(extract_dir, "tls_hellos.txt")
    with open(tls_path, "w") as fh:
        for row in tls_rows:
            ts   = _epoch_to_iso((row.get("frame.time_epoch")                  or "").strip())
            src  = (row.get("ip.src")                                           or "").strip()
            dst  = (row.get("ip.dst")                                           or "").strip()
            port = (row.get("tcp.dstport")                                      or "").strip()
            sni  = (row.get("tls.handshake.extensions_server_name")            or "").strip().rstrip(".")
            fh.write(f"{ts} {src} -> {dst}:{port} SNI:{sni or '(none)'}\n")

    for lineno, row in enumerate(tls_rows, start=1):
        ts   = _epoch_to_iso((row.get("frame.time_epoch")                 or "").strip())
        src  = (row.get("ip.src")                                          or "").strip()
        dst  = (row.get("ip.dst")                                          or "").strip()
        port = (row.get("tcp.dstport")                                     or "443").strip()
        sni  = (row.get("tls.handshake.extensions_server_name")           or "").strip().rstrip(".")

        artifacts.append((
            "pcap_tls_session",
            f"{tls_path}:{lineno}",
            f"{ts} TLS {src} -> {dst}:{port} SNI:{sni or '(none)'}",
        ))

        try:
            if not _is_rfc1918(dst):
                reasons = []
                if int(port) not in _COMMON_PORTS:
                    reasons.append(f"non-standard port {port}")
                if not sni:
                    reasons.append("no SNI (C2 tools commonly omit it)")
                elif _shannon_entropy(sni.split(".")[0]) > _HIGH_ENTROPY_THRESHOLD:
                    ent = _shannon_entropy(sni.split(".")[0])
                    reasons.append(f"high-entropy SNI label (entropy {ent:.2f})")
                if reasons:
                    _add_c2(
                        f"{ts} TLS C2 candidate {src} -> {dst}:{port} "
                        f"SNI:{sni or '(none)'} — {', '.join(reasons)}"
                    )
        except (ValueError, TypeError):
            pass

    logger.info("pcap_tls_complete", extra={"data": {
        "pcap": pcap_path, "tls_hellos": len(tls_rows),
    }})

    # Write the accumulated C2 candidates file
    with open(c2_path, "w") as fh:
        for line in c2_lines:
            fh.write(line + "\n")

    logger.info("pcap_complete", extra={"data": {
        "pcap":           pcap_path,
        "artifact_count": len(artifacts),
        "c2_candidates":  len(c2_lines),
    }})
    return artifacts
