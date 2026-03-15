import os
import re
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor

import math
from datetime import datetime, timezone

import requests
import redis

# -----------------------------
# Config
# -----------------------------
REDIS_HOST = os.environ.get("REDIS_HOST", "localhost")
REDIS_PORT = int(os.environ.get("REDIS_PORT", "6379"))
FEEDS_CONFIG_KEY = "config:feeds"
COLLECT_LAST_KEY = "config:collect_last"
TTL_SECONDS = 604800  # 7 days
PIPELINE_BATCH = 2000
IP_REGEX = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")

DEFAULT_FEEDS = {
    "Blocklist.de":     "https://lists.blocklist.de/lists/all.txt",
    "CINSscore":        "https://cinsscore.com/list/ci-badguys.txt",
    "FireHOL":          "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
    "EmergingThreats":  "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
    "Feodo":            "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
    "Greensnow":        "https://blocklist.greensnow.co/greensnow.txt",
    "MalSilo":          "https://malsilo.gitlab.io/feeds/dumps/ip_list.txt",
    "ThreatView":       "https://threatview.io/Downloads/IP-High-Confidence-Feed.txt",
}


def get_redis() -> redis.Redis:
    return redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)


def get_feeds(r: redis.Redis) -> dict[str, str]:
    """Return feed name -> url from Redis, or default feeds. Seeds Redis if empty."""
    raw = r.hgetall(FEEDS_CONFIG_KEY)
    if raw:
        return dict(raw)
    if DEFAULT_FEEDS:
        r.hset(FEEDS_CONFIG_KEY, mapping=DEFAULT_FEEDS)
    return dict(DEFAULT_FEEDS)


def set_feeds(r: redis.Redis, feeds: dict[str, str]) -> None:
    r.delete(FEEDS_CONFIG_KEY)
    if feeds:
        r.hset(FEEDS_CONFIG_KEY, mapping=feeds)


def add_or_update_feed(r: redis.Redis, name: str, url: str) -> None:
    r.hset(FEEDS_CONFIG_KEY, name, url)


def remove_feed(r: redis.Redis, name: str) -> None:
    r.hdel(FEEDS_CONFIG_KEY, name)


def _now_ts() -> int:
    return int(time.time())


def _fetch_feed(name: str, url: str) -> tuple[str, set[str], str | None]:
    """Fetch a single feed. Returns (name, set of IPs, error_message or None)."""
    try:
        response = requests.get(url, timeout=20)
        response.raise_for_status()
        ips = set(IP_REGEX.findall(response.text))
        return name, ips, None
    except Exception as e:
        return name, set(), str(e)


def _calculate_score(
    source_count: int,
    total_feeds: int,
    peak_count: int | None = None,
    last_seen_timestamp: float | None = None,
) -> int:

    if source_count <= 0 and (peak_count is None or peak_count <= 0):
        return 0
    if total_feeds <= 0:
        return 0

    if peak_count is None or peak_count < source_count:
        peak_count = source_count

    # ── Step 1: Evidence score ─────────────────────────────────────
    coverage      = source_count / total_feeds
    corroboration = math.log(source_count + 1) / math.log(total_feeds + 1)
    peak_memory   = min(1.0, peak_count / total_feeds)

    evidence = (0.50 * coverage) + (0.30 * corroboration) + (0.20 * peak_memory)
    evidence = min(1.0, evidence)

    # ── Step 2: Power-curve base score ────────────────────────────
    base_score = round(math.pow(evidence, 0.55) * 100)

    # ── Step 3: Temporal decay ────────────────────────────────────
    if last_seen_timestamp is None:
        decay_mult = 1.0
    else:
        now = datetime.now(timezone.utc).timestamp()
        days_since = (now - last_seen_timestamp) / 86400
        HALF_LIFE = 21.0
        FLOOR     = 0.12
        decay_mult = max(FLOOR, math.exp(-math.log(2) / HALF_LIFE * days_since))

    return min(100, max(0, round(base_score * decay_mult)))


def get_score_label(score: int) -> str:
    """Return the Microsoft Defender TI category for a score."""
    if score >= 75:
        return "malicious"
    if score >= 50:
        return "suspicious"
    if score >= 25:
        return "neutral"
    return "unknown"


def _store_ips(r: redis.Redis, ip_sources: dict[str, set[str]], total_feeds: int) -> None:
    current_time = _now_ts()
    ip_list = list(ip_sources.keys())

    # Pre-fetch all existing data in one round-trip
    fetch_pipe = r.pipeline()
    for ip in ip_list:
        fetch_pipe.hgetall(f"ip:{ip}")
    existing_data = fetch_pipe.execute()

    existing_map: dict[str, dict] = {
        ip: (existing_data[i] or {})
        for i, ip in enumerate(ip_list)
    }

    pipe = r.pipeline()
    counter = 0

    for ip, sources in ip_sources.items():
        key        = f"ip:{ip}"
        count      = len(sources)
        source_list = ",".join(sorted(sources))

        existing   = existing_map.get(ip, {})
        old_peak   = int(existing.get("peak_count", 0))
        new_peak   = max(old_peak, count)

        # Use previous last_seen for decay — NOT current_time
        prev_last_seen = existing.get("last_seen")
        last_seen_ts   = float(prev_last_seen) if prev_last_seen else None

        score = _calculate_score(
            source_count=count,
            total_feeds=total_feeds,
            peak_count=new_peak,
            last_seen_timestamp=last_seen_ts,
        )

        pipe.hset(key, mapping={
            "score":      str(score),
            "label":      get_score_label(score),
            "count":      str(count),
            "peak_count": str(new_peak),
            "sources":    source_list,
            "last_seen":  str(current_time),
        })
        pipe.hsetnx(key, "first_seen", str(current_time))
        pipe.expire(key, TTL_SECONDS)
        pipe.zadd("ip_scores", {ip: score})

        counter += 1
        if counter % PIPELINE_BATCH == 0:
            pipe.execute()
            pipe = r.pipeline()

    pipe.execute()


def _apply_decay_to_missing(
    r: redis.Redis,
    live_ips: set[str],
    total_feeds: int,
) -> None:
 
    current_time = _now_ts()
    pipe = r.pipeline()
    counter = 0
    cursor = 0

    while True:
        cursor, keys = r.scan(cursor, match="ip:*", count=2000)
        for key in keys:
            ip_addr = key[3:]
            if ip_addr in live_ips:
                continue

            existing = r.hgetall(key)
            if not existing:
                continue
            if existing.get("status") == "clean":
                continue

            old_peak       = int(existing.get("peak_count", 0))
            prev_last_seen = existing.get("last_seen")
            last_seen_ts   = float(prev_last_seen) if prev_last_seen else None

            # source_count=0: IP is missing this run, only peak memory + decay
            new_score = _calculate_score(
                source_count=0,
                total_feeds=total_feeds,
                peak_count=old_peak,
                last_seen_timestamp=last_seen_ts,
            )

            if new_score < 5:
                # Fully decayed — remove
                pipe.delete(key)
                pipe.zrem("ip_scores", ip_addr)
            else:
                pipe.hset(key, mapping={
                    "score": str(new_score),
                    "label": get_score_label(new_score),
                })
                pipe.zadd("ip_scores", {ip_addr: new_score})

            counter += 1
            if counter % PIPELINE_BATCH == 0:
                pipe.execute()
                pipe = r.pipeline()

        if cursor == 0:
            break

    pipe.execute()


def run_collector(r: redis.Redis | None = None) -> dict:
    """
    Load feeds from Redis (or defaults), fetch all, store IPs in Redis.

    Returns dict: ips_count, duration_seconds, feed_results, error.
    """
    if r is None:
        r = get_redis()

    feeds = get_feeds(r)
    start = time.time()
    ip_sources: dict[str, set[str]] = defaultdict(set)
    feed_results = []

    # 1. Fetch all URL-based feeds concurrently
    if feeds:
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [
                executor.submit(_fetch_feed, name, url)
                for name, url in feeds.items()
            ]
            for fut in futures:
                name, ips, err = fut.result()
                feed_results.append(
                    {"name": name, "ips_count": len(ips), "error": err}
                )
                for ip in ips:
                    ip_sources[ip].add(name)

    # 2. Include manual feeds already bulk-imported into Redis
    manual_feeds_raw  = r.hgetall("config:manual_feeds")
    manual_feed_names = set(manual_feeds_raw.keys()) if manual_feeds_raw else set()

    if manual_feed_names:
        manual_ip_counts: dict[str, int] = defaultdict(int)
        cursor = 0
        while True:
            cursor, keys = r.scan(cursor, match="ip:*", count=2000)
            for key in keys:
                sources_str = r.hget(key, "sources")
                if not sources_str:
                    continue
                ip_addr = key[3:]
                for src in set(sources_str.split(",")) & manual_feed_names:
                    ip_sources[ip_addr].add(src)
                    manual_ip_counts[src] += 1
            if cursor == 0:
                break

        for mf_name in manual_feed_names:
            feed_results.append({
                "name":      f"{mf_name} (manual)",
                "ips_count": manual_ip_counts.get(mf_name, 0),
                "error":     None,
            })

    # 3. Guard
    total_feeds = len(feeds) + len(manual_feed_names)
    if total_feeds == 0:
        return {
            "ips_count": 0,
            "duration_seconds": 0,
            "feed_results": [],
            "error": "No feeds configured",
        }

    # 4. Store seen IPs
    try:
        _store_ips(r, ip_sources, total_feeds)
    except Exception as e:
        return {
            "ips_count": len(ip_sources),
            "duration_seconds": round(time.time() - start, 2),
            "feed_results": feed_results,
            "error": str(e),
        }

    # 5. Decay missing IPs (slight drop on 1 missed day, remove if near-zero)
    try:
        _apply_decay_to_missing(r, set(ip_sources.keys()), total_feeds)
    except Exception:
        pass  # Non-fatal

    # 6. Persist run metadata
    duration = round(time.time() - start, 2)
    r.hset(COLLECT_LAST_KEY, mapping={
        "last_run":         str(_now_ts()),
        "ips_count":        str(len(ip_sources)),
        "duration_seconds": str(duration),
        "feed_count":       str(total_feeds),
    })

    return {
        "ips_count":        len(ip_sources),
        "duration_seconds": duration,
        "feed_results":     feed_results,
        "error":            None,
    }


def get_last_collect(r: redis.Redis) -> dict | None:
    """Return last collect run metadata from Redis, or None if never run."""
    raw = r.hgetall(COLLECT_LAST_KEY)
    if not raw:
        return None
    return {
        "last_run":         int(raw.get("last_run", 0)),
        "ips_count":        int(raw.get("ips_count", 0)),
        "duration_seconds": float(raw.get("duration_seconds", 0)),
        "feed_count":       int(raw.get("feed_count", 0)),
    }