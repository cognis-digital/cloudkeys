"""cloudkeys.feeds — cloud IP-range attribution backed by REAL public feeds.

This wires the bundled, edge/air-gap-deployable :mod:`cloudkeys.datafeeds`
ingestion layer into cloudkeys and restricts the catalog to the two feeds this
tool actually consumes:

  * ``aws-ip-ranges``  — https://ip-ranges.amazonaws.com/ip-ranges.json
  * ``gcp-ip-ranges``  — https://www.gstatic.com/ipranges/cloud.json

Both are authoritative, keyless HTTPS JSON published by the cloud providers.
``datafeeds`` fetches them once, caches them to disk
(``COGNIS_FEEDS_CACHE``), and re-serves them **offline** so attribution keeps
working on a disconnected / air-gapped enclave.

Why this matters for a secret scanner: a leaked AWS/GCP credential is far more
actionable when you can also say *which cloud the endpoints/IPs in the same
file belong to* — e.g. "this AKIA key sits next to 3.4.x.x, AWS EC2 eu-west-1".
That turns a raw match into an attributable blast-radius hint.

Defensive / authorized-use only. No credential is ever used.
"""
from __future__ import annotations

import ipaddress
from functools import lru_cache
from typing import Optional

from . import datafeeds

# This repo's domain feeds only. We never widen beyond these ids.
FEED_IDS = ("aws-ip-ranges", "gcp-ip-ranges")


def relevant_catalog() -> dict:
    """Return the bundled catalog filtered to just this tool's feed ids."""
    cat = datafeeds.load_catalog()
    feeds = [f for f in cat.get("feeds", []) if f["id"] in FEED_IDS]
    return {"_meta": cat.get("_meta", {}), "feeds": feeds}


def list_feeds() -> list[dict]:
    """List only the feeds cloudkeys consumes, with cache freshness."""
    out = []
    for f in relevant_catalog()["feeds"]:
        age = datafeeds.cached_age_hours(f["id"])
        out.append({
            "id": f["id"],
            "name": f["name"],
            "url": f["url"],
            "domain": f.get("domain", ""),
            "cached_age_hours": None if age is None else round(age, 2),
        })
    return out


def update(offline: bool = False) -> dict:
    """Refresh both feeds into the disk cache. Returns id -> bytes/-error."""
    if offline:
        raise ValueError("update fetches from the network; drop --offline")
    cat = relevant_catalog()
    res = {}
    for fid in FEED_IDS:
        path = datafeeds.update(fid, catalog=cat)
        res[fid] = path.stat().st_size
    return res


# --------------------------------------------------------------------------- #
# Prefix index (built once from cached feed data)
# --------------------------------------------------------------------------- #
def _load_feed(fid: str, offline: bool) -> dict:
    return datafeeds.get(fid, offline=offline, catalog=relevant_catalog())


@lru_cache(maxsize=8)
def _build_index(offline: bool) -> tuple:
    """Return a tuple of (network, attrs) entries, longest-prefix friendly.

    attrs = {"cloud","service","region","cidr"}.  Cached per offline flag.
    """
    entries: list = []

    aws = _load_feed("aws-ip-ranges", offline)
    for p in aws.get("prefixes", []):
        _add(entries, p.get("ip_prefix"), "aws", p.get("service"), p.get("region"))
    for p in aws.get("ipv6_prefixes", []):
        _add(entries, p.get("ipv6_prefix"), "aws", p.get("service"), p.get("region"))

    gcp = _load_feed("gcp-ip-ranges", offline)
    for p in gcp.get("prefixes", []):
        cidr = p.get("ipv4Prefix") or p.get("ipv6Prefix")
        _add(entries, cidr, "gcp", p.get("service"), p.get("scope"))

    # Longest prefix first so the most specific match wins.
    entries.sort(key=lambda e: e[0].prefixlen, reverse=True)
    return tuple(entries)


def _add(entries: list, cidr: Optional[str], cloud: str,
         service: Optional[str], region: Optional[str]) -> None:
    if not cidr:
        return
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return
    entries.append((net, {
        "cloud": cloud,
        "service": service or "",
        "region": region or "",
        "cidr": cidr,
    }))


def attribute_ip(ip: str, *, offline: bool = False) -> Optional[dict]:
    """Attribute a single IP to AWS/GCP using the cached IP-range feeds.

    Returns the most-specific match {cloud,service,region,cidr} or ``None``.
    Set ``offline=True`` to serve from cache only (air-gap).
    """
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return None
    for net, attrs in _build_index(offline):
        if addr.version == net.version and addr in net:
            return dict(attrs)
    return None


def attribute_ips(ips, *, offline: bool = False) -> dict:
    """Attribute many IPs; returns {ip: attribution-or-None}."""
    return {ip: attribute_ip(ip, offline=offline) for ip in ips}
