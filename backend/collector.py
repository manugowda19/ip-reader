import os
import re
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor

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
    "Blocklist.de": "https://lists.blocklist.de/lists/all.txt",
    "CINSscore": "https://cinsscore.com/list/ci-badguys.txt",
    "FireHOL": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
    "EmergingThreats": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
    "Feodo": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
    "Greensnow": "https://blocklist.greensnow.co/greensnow.txt",
    "MalSilo": "https://malsilo.gitlab.io/feeds/dumps/ip_list.txt",
    "ThreatView": "https://threatview.io/Downloads/IP-High-Confidence-Feed.txt",
}


def get_redis():
    return redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)


def get_feeds(r: redis.Redis) -> dict[str, str]:
    """Return feed name -> url from Redis, or default feeds. Seeds Redis if empty."""
    raw = r.hgetall(FEEDS_CONFIG_KEY)
    if raw:
        return dict(raw)
    # Seed with defaults
    if DEFAULT_FEEDS:
        for name, url in DEFAULT_FEEDS.items():
            r.hset(FEEDS_CONFIG_KEY, name, url)
    return dict(DEFAULT_FEEDS)


def set_feeds(r: redis.Redis, feeds: dict[str, str]) -> None:
    """Replace stored feeds with the given dict."""
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
    """Fetch a single feed. Returns (name, set of ips, error_message or None)."""
    try:
        response = requests.get(url, timeout=20)
        response.raise_for_status()
        ips = set(IP_REGEX.findall(response.text))
        return name, ips, None
    except Exception as e:
        return name, set(), str(e)


def _calculate_score(source_count: int, total_feeds: int) -> int:
    if total_feeds <= 0:
        return 0
    return min(100, int((source_count / total_feeds) * 100))


def _store_ips(r: redis.Redis, ip_sources: dict[str, set[str]], total_feeds: int) -> None:
    pipe = r.pipeline()
    current_time = _now_ts()
    counter = 0
    for ip, sources in ip_sources.items():
        key = f"ip:{ip}"
        source_list = ",".join(sorted(sources))
        count = len(sources)
        score = _calculate_score(count, total_feeds)
        pipe.hsetnx(key, "first_seen", current_time)
        pipe.hset(key, "score", str(score))
        pipe.hset(key, "count", str(count))
        pipe.hset(key, "sources", source_list)
        pipe.hset(key, "last_seen", str(current_time))
        pipe.expire(key, TTL_SECONDS)
        pipe.zadd("ip_scores", {ip: score})
        counter += 1
        if counter % PIPELINE_BATCH == 0:
            pipe.execute()
            pipe = r.pipeline()
    pipe.execute()


def run_collector(r: redis.Redis | None = None) -> dict:
    """
    Load feeds from Redis (or default), fetch all, store IPs in same Redis.
    Returns dict: ips_count, duration_seconds, feed_results [{ name, ips_count, error? }], error?
    """
    if r is None:
        r = get_redis()
    feeds = get_feeds(r)
    start = time.time()
    ip_sources = defaultdict(set)
    feed_results = []

    # 1. Fetch all URL-based link feeds
    if feeds:
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(_fetch_feed, name, url) for name, url in feeds.items()]
            for fut in futures:
                name, ips, err = fut.result()
                feed_results.append({
                    "name": name,
                    "ips_count": len(ips),
                    "error": err,
                })
                for ip in ips:
                    ip_sources[ip].add(name)

    # 2. Include manual feeds (bulk-imported IPs already in Redis)
    import json as _json
    manual_feeds_raw = r.hgetall("config:manual_feeds")
    manual_feed_names = set(manual_feeds_raw.keys()) if manual_feeds_raw else set()

    if manual_feed_names:
        # Scan all ip:* keys and collect IPs that belong to manual sources
        manual_ip_counts = defaultdict(int)
        cursor = 0
        while True:
            cursor, keys = r.scan(cursor, match="ip:*", count=2000)
            for key in keys:
                sources_str = r.hget(key, "sources")
                if not sources_str:
                    continue
                ip_addr = key.replace("ip:", "", 1)
                existing_sources = set(sources_str.split(","))
                for src in existing_sources:
                    if src in manual_feed_names:
                        ip_sources[ip_addr].add(src)
                        manual_ip_counts[src] += 1
            if cursor == 0:
                break

        for mf_name in manual_feed_names:
            feed_results.append({
                "name": f"{mf_name} (manual)",
                "ips_count": manual_ip_counts.get(mf_name, 0),
                "error": None,
            })

    # Total feeds = link feeds + manual feeds (for score calculation)
    total_feeds = len(feeds) + len(manual_feed_names)
    if total_feeds == 0:
        return {
            "ips_count": 0,
            "duration_seconds": 0,
            "feed_results": [],
            "error": "No feeds configured",
        }

    # Flush stale IPs that are no longer in any feed
    try:
        cursor = 0
        pipe = r.pipeline()
        batch = 0
        while True:
            cursor, keys = r.scan(cursor, match="ip:*", count=2000)
            for key in keys:
                ip_addr = key.replace("ip:", "", 1)
                if ip_addr not in ip_sources:
                    # Check if it's a clean IP (keep those)
                    status = r.hget(key, "status")
                    if status == "clean":
                        continue
                    pipe.delete(key)
                    pipe.zrem("ip_scores", ip_addr)
                    batch += 1
                    if batch % PIPELINE_BATCH == 0:
                        pipe.execute()
                        pipe = r.pipeline()
            if cursor == 0:
                break
        pipe.execute()
    except Exception:
        pass  # Non-fatal — stale cleanup is best-effort

    try:
        _store_ips(r, ip_sources, total_feeds)
    except Exception as e:
        return {
            "ips_count": len(ip_sources),
            "duration_seconds": round(time.time() - start, 2),
            "feed_results": feed_results,
            "error": str(e),
        }

    duration = round(time.time() - start, 2)
    result = {
        "ips_count": len(ip_sources),
        "duration_seconds": duration,
        "feed_results": feed_results,
        "error": None,
    }
    # Persist last run for admin UI
    r.hset(COLLECT_LAST_KEY, "last_run", str(_now_ts()))
    r.hset(COLLECT_LAST_KEY, "ips_count", str(len(ip_sources)))
    r.hset(COLLECT_LAST_KEY, "duration_seconds", str(duration))
    r.hset(COLLECT_LAST_KEY, "feed_count", str(total_feeds))
    return result


def get_last_collect(r: redis.Redis) -> dict | None:
    """Return last collect run info from Redis, or None."""
    raw = r.hgetall(COLLECT_LAST_KEY)
    if not raw:
        return None
    return {
        "last_run": int(raw.get("last_run", 0)),
        "ips_count": int(raw.get("ips_count", 0)),
        "duration_seconds": float(raw.get("duration_seconds", 0)),
        "feed_count": int(raw.get("feed_count", 0)),
    }
