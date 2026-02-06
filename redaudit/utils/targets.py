from __future__ import annotations

import ipaddress
from typing import List, Tuple


def parse_target_tokens(tokens: List[str], max_len: int) -> Tuple[List[str], List[str]]:
    """Parse targets into CIDR strings. Supports CIDR, IP, and ranges."""
    valid: List[str] = []
    invalid: List[str] = []

    for token in tokens:
        raw = token.strip()
        if not raw:
            continue
        if len(raw) > max_len:
            invalid.append(raw)
            continue
        if "-" in raw:
            start_str, end_str = (part.strip() for part in raw.split("-", 1))
            if not start_str or not end_str:
                invalid.append(raw)
                continue
            try:
                start_ip = ipaddress.ip_address(start_str)
                end_ip = ipaddress.ip_address(end_str)
            except ValueError:
                invalid.append(raw)
                continue
            if start_ip.version != end_ip.version or int(start_ip) > int(end_ip):
                invalid.append(raw)
                continue
            for net in ipaddress.summarize_address_range(start_ip, end_ip):
                valid.append(str(net))
            continue
        try:
            net = ipaddress.ip_network(raw, strict=False)
            valid.append(str(net))
        except ValueError:
            invalid.append(raw)

    seen = set()
    deduped: List[str] = []
    for entry in valid:
        if entry in seen:
            continue
        seen.add(entry)
        deduped.append(entry)

    return deduped, invalid
