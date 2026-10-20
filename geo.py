"""
GeoIP lookup for LogLens.

Finds the country and map position of attacking IP addresses using the
free ip-api.com batch service (no API key needed, non-commercial use).

- Private / reserved / test IP addresses are skipped (they have no location).
- Results are cached in memory so the same IP is not looked up twice.
- If the lookup service is unreachable, the dashboard still works. The map
  simply shows that locations are unavailable.
"""

import ipaddress
import json
from collections import Counter
from urllib import request as urlrequest

GEO_URL = (
    "http://ip-api.com/batch"
    "?fields=status,country,countryCode,city,lat,lon,query"
)

MAX_IPS = 50          # most IPs looked up per report (one batch request)
TIMEOUT_SECONDS = 4   # never keep the user waiting for long

_cache = {}           # ip -> location dict, or None if it has no location


def _is_public(ip):
    """True only for real public internet addresses."""
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def _lookup_batch(ips):
    """Ask ip-api.com about up to 100 IPs in one request."""
    body = json.dumps(ips).encode("utf-8")
    req = urlrequest.Request(
        GEO_URL,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    with urlrequest.urlopen(req, timeout=TIMEOUT_SECONDS) as response:
        return json.loads(response.read().decode("utf-8"))


def build_geo(ip_counts):
    """
    Turn a Counter of {ip: number_of_findings} into map data.

    Returns a dictionary with:
      points         - list of located IPs (for the map)
      country_counts - list of (country, findings) sorted high to low
      unlocated      - how many IPs could not be located
    """

    ips = [ip for ip, _ in ip_counts.most_common(MAX_IPS)]

    # Only look up public IPs that are not already cached.
    to_lookup = [ip for ip in ips if ip not in _cache and _is_public(ip)]

    if to_lookup:
        try:
            for item in _lookup_batch(to_lookup):
                if item.get("status") == "success":
                    _cache[item["query"]] = {
                        "country": item.get("country", "Unknown"),
                        "city": item.get("city", ""),
                        "lat": item.get("lat"),
                        "lon": item.get("lon"),
                    }
                else:
                    _cache[item.get("query")] = None
        except Exception:
            # Service down, blocked or too slow: carry on without a map.
            pass

    points = []
    country_counter = Counter()
    unlocated = 0

    for ip in ips:
        info = _cache.get(ip)

        if not info or info["lat"] is None or info["lon"] is None:
            unlocated += 1
            continue

        count = ip_counts[ip]
        country_counter[info["country"]] += count

        points.append({
            "ip": ip,
            "count": count,
            "country": info["country"],
            "city": info["city"],
            "lat": info["lat"],
            "lon": info["lon"],
        })

    return {
        "points": points,
        "country_counts": country_counter.most_common(),
        "unlocated": unlocated,
    }
