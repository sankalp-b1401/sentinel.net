# detector/metrics.py
"""
Pure feature/metric helpers for network flow records.

You pass raw values from your flow JSON (protocol, IPs, ports, counts, times).
No I/O. No record parsing. Just math.

All functions are side-effect free and safe against zeros (use epsilons).
"""

from __future__ import annotations
import math
import ipaddress

# ----------- constants -----------

EPS = 1e-9  # to avoid division by zero in logs
# Small floor for duration-based rates to avoid astronomical pps/bps when duration ~ 0
MIN_DURATION = 0.01  # seconds (10 ms) — used only for rate calcs
# Caps to protect from numeric explosion (tweak as needed)
MAX_PPS = 1e6         # packets per second
MAX_BPS = 1e9         # bytes per second
MAX_BYTES_PER_PKT = 1e7

# ----------- safe math helpers -----------

def log1p_safe(x: float) -> float:
    """Return log(1+x) with x clipped at -1+EPS to avoid domain errors."""
    return math.log1p(max(x, -1 + EPS))


# ----------- basic time/size metrics -----------

def duration_sec(start_time: float, end_time: float) -> float:
    """
    Flow duration in seconds (non-negative).
    NOTE: we return the true duration (possibly very small) — callers that compute
    rates should use rate_duration() to apply the MIN_DURATION floor.
    """
    return max(0.0, end_time - start_time)


def rate_duration(start_time: float, end_time: float) -> float:
    """Duration used for rate calculations — apply MIN_DURATION floor."""
    d = duration_sec(start_time, end_time)
    return max(MIN_DURATION, d)


def log_duration(start_time: float, end_time: float) -> float:
    """Safe log of duration seconds (uses true duration)."""
    return log1p_safe(duration_sec(start_time, end_time))


def log_bytes(byte_count: int) -> float:
    """Safe log of total bytes in flow."""
    return log1p_safe(float(byte_count))


def log_pkts(packet_count: int) -> float:
    """Safe log of total packets in flow."""
    return log1p_safe(float(packet_count))


def bytes_per_pkt(byte_count: int, packet_count: int) -> float:
    """Average bytes per packet, capped to avoid extreme values."""
    pcount = max(1.0, float(packet_count))
    val = float(byte_count) / pcount
    return min(val, MAX_BYTES_PER_PKT)


def pps(packet_count: int, start_time: float, end_time: float) -> float:
    """Packets per second with duration floor and cap."""
    d = rate_duration(start_time, end_time)
    val = float(packet_count) / d
    return min(val, MAX_PPS)


def bps(byte_count: int, start_time: float, end_time: float) -> float:
    """Bytes per second with duration floor and cap."""
    d = rate_duration(start_time, end_time)
    val = float(byte_count) / d
    return min(val, MAX_BPS)


# ----------- directionality (A->B vs B->A) -----------

def out_in_ratio(bytes_a_to_b: int, bytes_b_to_a: int) -> float:
    """Directional byte ratio; >1 means A->B dominates."""
    return (float(bytes_a_to_b) + 1.0) / (float(bytes_b_to_a) + 1.0)


def dir_pkt_ratio(pkts_a_to_b: int, pkts_b_to_a: int) -> float:
    """Directional packet ratio; >1 means A->B dominates."""
    return (float(pkts_a_to_b) + 1.0) / (float(pkts_b_to_a) + 1.0)


# ----------- TCP flag metrics (pass zeros for UDP) -----------

def syn_only(syn_count: int, ack_count: int) -> int:
    """1 if SYN seen and no ACKs (scan-ish); else 0."""
    return 1 if (syn_count > 0 and ack_count == 0) else 0


def rst_ratio(rst_count: int, packet_count: int) -> float:
    """RSTs / packets (bounded)."""
    return float(rst_count) / max(1.0, float(packet_count))


def fin_present(fin_count: int) -> int:
    """1 if any FIN observed; else 0."""
    return 1 if fin_count > 0 else 0


def ack_present(ack_count: int) -> int:
    """1 if any ACK observed; else 0."""
    return 1 if ack_count > 0 else 0


# ----------- protocol/port features -----------

def proto_is_tcp(protocol: str) -> int:
    """1 if protocol is 'TCP' (case-insensitive); else 0."""
    return 1 if (protocol.upper() == "TCP") else 0


def dst_port_bin(endpointB_port: int) -> int:
    """
    Coarse bucket of destination port:
      0 = well-known (0–1023)
      1 = registered (1024–49151)
      2 = dynamic/private (49152–65535)
    """
    if endpointB_port <= 1023:
        return 0
    if endpointB_port <= 49151:
        return 1
    return 2


def flow_size_class(byte_count: int) -> int:
    """
    Ordinal bucket of flow total size:
      0: <= 1KB
      1: <= 10KB
      2: <= 100KB
      3: <= 1MB
      4:  > 1MB
    """
    b = int(byte_count)
    if b <= 1_024:
        return 0
    if b <= 10_240:
        return 1
    if b <= 102_400:
        return 2
    if b <= 1_048_576:
        return 3
    return 4


# ----------- IPv4 context features -----------

def is_private_ipv4(ip: str) -> bool:
    """True if RFC1918 private IPv4 address."""
    try:
        addr = ipaddress.IPv4Address(ip)
    except Exception:
        return False
    return addr.is_private  # matches RFC1918 ranges


def same_subnet_v4(ip1: str, ip2: str, prefix: int = 24) -> int:
    """1 if ip1 and ip2 share the same IPv4 subnet (/prefix), else 0."""
    try:
        net1 = ipaddress.ip_network(f"{ip1}/{prefix}", strict=False)
        net2 = ipaddress.ip_network(f"{ip2}/{prefix}", strict=False)
        return 1 if net1.network_address == net2.network_address else 0
    except Exception:
        return 0


def is_priv_to_public(src_ip: str, dst_ip: str) -> int:
    """1 if src is private and dst is public; else 0."""
    try:
        src_priv = is_private_ipv4(src_ip)
        dst_priv = is_private_ipv4(dst_ip)
        return 1 if (src_priv and not dst_priv) else 0
    except Exception:
        return 0


# ----------- composite helper -----------

def compute_core_features(
    *,
    protocol: str,
    endpointA_ip: str,
    endpointA_port: int,
    endpointB_ip: str,
    endpointB_port: int,
    start_time: float,
    end_time: float,
    packet_count: int,
    byte_count: int,
    pkts_a_to_b: int,
    pkts_b_to_a: int,
    bytes_a_to_b: int,
    bytes_b_to_a: int,
    syn_count: int = 0,
    ack_count: int = 0,
    fin_count: int = 0,
    rst_count: int = 0,
) -> dict[str, float]:
    d: dict[str, float] = {
        # time/size
        "log_duration":  log_duration(start_time, end_time),
        "log_bytes":     log_bytes(byte_count),
        "log_pkts":      log_pkts(packet_count),
        "bytes_per_pkt": bytes_per_pkt(byte_count, packet_count),
        "pps":           pps(packet_count, start_time, end_time),
        "bps":           bps(byte_count, start_time, end_time),

        # directionality
        "out_in_ratio":  out_in_ratio(bytes_a_to_b, bytes_b_to_a),
        "dir_pkt_ratio": dir_pkt_ratio(pkts_a_to_b, pkts_b_to_a),

        # tcp flags
        "syn_only":      float(syn_only(syn_count, ack_count)),
        "rst_ratio":     rst_ratio(rst_count, packet_count),
        "fin_present":   float(fin_present(fin_count)),
        "ack_present":   float(ack_present(ack_count)),

        # protocol/port & context
        "proto_is_tcp":      float(proto_is_tcp(protocol)),
        "dst_port_bin":      float(dst_port_bin(endpointB_port)),
        "flow_size_class":   float(flow_size_class(byte_count)),
        "same_subnet_v4":    float(same_subnet_v4(endpointA_ip, endpointB_ip, 24)),
        "is_priv_to_public": float(is_priv_to_public(endpointA_ip, endpointB_ip)),
    }

    return d


FEATURE_ORDER = [
    "log_duration", "log_bytes", "log_pkts",
    "bytes_per_pkt", "pps", "bps",
    "out_in_ratio", "dir_pkt_ratio",
    "syn_only", "rst_ratio", "fin_present", "ack_present",
    "proto_is_tcp", "dst_port_bin", "flow_size_class",
    "same_subnet_v4", "is_priv_to_public",
]


def features_from_record(flow: dict) -> dict[str, float]:
    """Accept one flow-record dict (from your parser) and return feature dict (no rarity)."""
    return compute_core_features(
        protocol       = flow["protocol"],
        endpointA_ip   = flow["endpointA_ip"],
        endpointA_port = flow["endpointA_port"],
        endpointB_ip   = flow["endpointB_ip"],
        endpointB_port = flow["endpointB_port"],
        start_time     = flow["start_time"],
        end_time       = flow["end_time"],
        packet_count   = flow["packet_count"],
        byte_count     = flow["byte_count"],
        pkts_a_to_b    = flow["pkts_a_to_b"],
        pkts_b_to_a    = flow["pkts_b_to_a"],
        bytes_a_to_b   = flow["bytes_a_to_b"],
        bytes_b_to_a   = flow["bytes_b_to_a"],
        syn_count      = flow.get("syn_count", 0),
        ack_count      = flow.get("ack_count", 0),
        fin_count      = flow.get("fin_count", 0),
        rst_count      = flow.get("rst_count", 0),
    )


__all__ = [
    # math
    "log1p_safe",
    # time/size
    "duration_sec", "rate_duration", "log_duration", "log_bytes", "log_pkts",
    "bytes_per_pkt", "pps", "bps",
    # directionality
    "out_in_ratio", "dir_pkt_ratio",
    # tcp flags
    "syn_only", "rst_ratio", "fin_present", "ack_present",
    # proto/port & context
    "proto_is_tcp", "dst_port_bin", "flow_size_class",
    "is_private_ipv4", "same_subnet_v4", "is_priv_to_public",
    # composite & wrappers
    "compute_core_features", "features_from_record", "FEATURE_ORDER",
]
