#!/usr/bin/env python3
"""
EPG (XMLTV) generator for OnTVTonight.com local TV listings.

Fetches the channel list for a given provider/region and the per-channel
listings for N days, then writes a standard XMLTV `guide.xml`.

Designed to run in GitHub Actions on a schedule, but works anywhere.

Usage:
    python epg.py --provider X341764498 --region 901 --days 3 \
        --output guide.xml --channels-output channels.xml

All options can also be set via environment variables (see argparse defaults).
"""

import argparse
import json
import os
import re
import sys
import time
import xml.sax.saxutils as sax
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

import requests

# vendored AWS WAF challenge solver (xKiian/awswaf, python port)
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "vendor"))

BASE_URL = os.getenv("ONTV_BASE_URL", "https://www.ontvtonight.com")
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36"
)

# Matches OnTVTonight's channel listing URLs:
#   /guide/listings/channel/<number>/<slug>.html
CHANNEL_LINK_RE = re.compile(
    r'href="(?P<url>' + re.escape(BASE_URL) +
    r'/guide/listings/channel/(?P<number>\d+)/(?P<slug>[^"]+)\.html)"[^>]*title="(?P<name>[^"]*)"'
)
LOGO_RE = re.compile(r'<img[^>]+class="[^"]*channel-logo[^"]*"[^>]+src="([^"]+)"', re.I)


def make_session():
    s = requests.Session()
    s.headers.update({
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9,es;q=0.8",
    })
    return s


_waf_token = None  # cached aws-waf-token for this run


def detect_egress_timezone():
    """OnTVTonight renders schedule times in the requester's local timezone,
    so detect ours via the egress IP. Falls back to America/New_York."""
    try:
        r = requests.get("https://ipinfo.io/json", timeout=10)
        tz = r.json().get("timezone")
        if tz:
            ZoneInfo(tz)  # validate
            return tz
    except Exception as e:
        print(f"  could not detect egress timezone ({e}); defaulting to America/New_York")
    return "America/New_York"


def solve_waf_challenge(url, body):
    """Compute an aws-waf-token from an AWS WAF challenge page (best effort)."""
    global _waf_token
    if _waf_token:
        return _waf_token
    try:
        from awswaf.aws import AwsWaf  # lazy: needs curl_cffi/cryptography/pyscrypt
        goku = json.loads(body.split("window.gokuProps = ")[1].split(";")[0])
        host = body.split('src="https://')[1].split("/challenge.js")[0]
        domain = "www.ontvtonight.com"
        _waf_token = AwsWaf(goku, host, domain, USER_AGENT)()
        print("  solved AWS WAF challenge, got aws-waf-token")
        return _waf_token
    except Exception as e:
        raise RuntimeError(f"could not solve AWS WAF challenge for {url}: {e}")


def fetch(session, url, accept_json=False, retries=5):
    """GET a URL with retries/backoff and AWS WAF handling. Raises on failure."""
    headers = {}
    if accept_json:
        headers["Accept"] = "application/json, text/plain, */*"
    last_err = None
    for attempt in range(1, retries + 1):
        try:
            r = session.get(url, headers=headers, timeout=30)
            if r.status_code == 200:
                return r
            # AWS WAF challenge: 405 (or 202) with a challenge page
            if r.status_code in (202, 405) or "challenge.js" in r.text[:5000]:
                try:
                    token = solve_waf_challenge(url, r.text)
                    session.cookies.set("aws-waf-token", token, domain=".ontvtonight.com")
                    continue  # retry immediately with the fresh token
                except RuntimeError as e:
                    last_err = e  # challenge is intermittent: fall through and retry anyway
                    if attempt < retries:
                        time.sleep(2 * attempt)
                    continue
            last_err = RuntimeError(f"HTTP {r.status_code} for {url}")
        except requests.RequestException as e:
            last_err = e
        if attempt < retries:
            time.sleep(2 * attempt)
    raise last_err or RuntimeError(f"failed to fetch {url}")


def unwrap_html(resp):
    """The schedule endpoint returns a JSON string wrapping HTML; unwrap if so."""
    text = resp.text
    try:
        data = json.loads(text)
        if isinstance(data, str):
            return data
    except (json.JSONDecodeError, ValueError):
        pass
    return text


def get_channels(session, provider, region, date_str):
    """Fetch the schedule grid and extract the channel list."""
    url = (
        f"{BASE_URL}/guide/schedule?provider={provider}&region={region}"
        f"&TVperiod=Night&date={date_str}&st=0&u_time=0000&is_mobile=1"
    )
    html = unwrap_html(fetch(session, url, accept_json=True))
    channels = {}
    for m in CHANNEL_LINK_RE.finditer(html):
        number, slug = m.group("number"), m.group("slug")
        name = m.group("name") or slug
        cid = f"ontvtonight-{number}-{slug}"
        channels[cid] = {
            "id": cid,
            "number": number,
            "slug": slug,
            "name": name,
            "url": m.group("url"),
        }
    # logos (best effort, matched in document order to channel links)
    logos = LOGO_RE.findall(html)
    links = list(CHANNEL_LINK_RE.finditer(html))
    for m, logo in zip(links, logos):
        channels[f"ontvtonight-{m.group('number')}-{m.group('slug')}"]["logo"] = logo
    return list(channels.values())


ROW_RE = re.compile(r"<tr[^>]*>(.*?)</tr>", re.S)
TIME_RE = re.compile(r'<td[^>]*class="[^"]*ott-channel-time-cell[^"]*"[^>]*>\s*<h5[^>]*>(.*?)</h5>', re.S)
TITLE_RE = re.compile(r'<h5[^>]*class="[^"]*ott-channel-show__title[^"]*"[^>]*>(.*?)</h5>', re.S)
META_RE = re.compile(r'<h6[^>]*class="[^"]*ott-channel-show__meta[^"]*"[^>]*>(.*?)</h6>', re.S)
TAG_RE = re.compile(r"<[^>]+>")
WS_RE = re.compile(r"\s+")


def clean(html_fragment):
    if not html_fragment:
        return ""
    text = TAG_RE.sub(" ", html_fragment)
    return WS_RE.sub(" ", text).strip()


def get_programs(session, channel, date_str, site_tz, out_tz):
    """Fetch one channel's listings page for one date and return programs.

    The site renders times in the SITE timezone (US Eastern for the .com site,
    even for Puerto Rico); they are converted to the viewer's timezone (out_tz)
    so the EPG shows true local time.
    """
    url = f"{channel['url']}?dt={date_str}"
    html = fetch(session, url).text
    programs = []
    day_offset = 0
    prev_start = None
    base_date = datetime.strptime(date_str, "%Y-%m-%d")
    for row in ROW_RE.findall(html):
        tm = TIME_RE.search(row)
        tt = TITLE_RE.search(row)
        if not tm or not tt:
            continue
        time_str = clean(tm.group(1))          # e.g. "01:00 am"
        title = clean(tt.group(1))
        desc = clean(META_RE.search(row).group(1)) if META_RE.search(row) else ""
        try:
            t = datetime.strptime(time_str, "%I:%M %p")
        except ValueError:
            continue
        start = base_date + timedelta(days=day_offset, hours=t.hour, minutes=t.minute)
        start = start.replace(tzinfo=site_tz)
        if prev_start and start < prev_start:   # schedule wrapped past midnight
            day_offset += 1
            start = base_date + timedelta(days=day_offset, hours=t.hour, minutes=t.minute)
            start = start.replace(tzinfo=site_tz)
        prev_start = start
        programs.append({"title": title, "desc": desc, "start": start, "stop": None})
    # stop = next program's start; last one defaults to +1h
    for i, p in enumerate(programs):
        p["stop"] = programs[i + 1]["start"] if i + 1 < len(programs) else p["start"] + timedelta(hours=1)
    # drop zero/negative-length entries (duplicate time rows on the site)
    programs = [p for p in programs if p["stop"] > p["start"]]
    # convert from site tz to the viewer's local tz
    for p in programs:
        p["start"] = p["start"].astimezone(out_tz)
        p["stop"] = p["stop"].astimezone(out_tz)
    return programs


WITH_OFFSET = True  # strict XMLTV form "... -0400" by default; --no-offset to drop it


def xmltv_time(dt):
    # Strict XMLTV includes the UTC offset; players that ignore the offset
    # treat the stamp as UTC and show times 4h early, so we emit "-0400".
    if WITH_OFFSET:
        return dt.strftime("%Y%m%d%H%M%S %z")
    return dt.strftime("%Y%m%d%H%M%S")


def esc(text):
    return sax.escape(text or "")


def write_guide(path, channels, all_programs):
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<tv generator-info-name="epg-ontvtonight" generator-info-url="https://www.ontvtonight.com/guide/">',
    ]
    for ch in channels:
        lines.append(f'  <channel id="{esc(ch["id"])}">')
        lines.append(f'    <display-name>{esc(ch["name"])}</display-name>')
        if ch.get("logo"):
            lines.append(f'    <icon src="{esc(ch["logo"])}"/>')
        lines.append("  </channel>")
    for ch in channels:
        for p in all_programs.get(ch["id"], []):
            lines.append(
                f'  <programme start="{xmltv_time(p["start"])}" stop="{xmltv_time(p["stop"])}" channel="{esc(ch["id"])}">'
            )
            lines.append(f'    <title lang="es">{esc(p["title"])}</title>')
            if p["desc"]:
                lines.append(f'    <desc lang="es">{esc(p["desc"])}</desc>')
            lines.append("  </programme>")
    lines.append("</tv>")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def write_channels_xml(path, channels):
    lines = ['<?xml version="1.0" encoding="UTF-8"?>', "<channels>"]
    for ch in channels:
        lines.append(
            f'  <channel id="{esc(ch["id"])}" site="ontvtonight.com" '
            f'xmltv_id="{esc(ch["id"])}" site_id="us#{ch["number"]}/{ch["slug"]}" lang="es">{esc(ch["name"])}</channel>'
        )
    lines.append("</channels>")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def main():
    ap = argparse.ArgumentParser(description="Generate XMLTV EPG from OnTVTonight.com")
    ap.add_argument("--provider", default=os.getenv("PROVIDER", "X341764498"))
    ap.add_argument("--region", default=os.getenv("REGION", "901"))
    ap.add_argument("--days", type=int, default=int(os.getenv("DAYS", "3")))
    ap.add_argument("--tz", default=os.getenv("TZ_NAME", "America/Puerto_Rico"),
                    help="IANA timezone of the EPG output (viewer's local time)")
    ap.add_argument("--site-tz", default=os.getenv("SITE_TZ", "America/New_York"),
                    help="IANA timezone in which the site renders its times "
                         "(US site = America/New_York). 'auto' = detect egress IP tz.")
    ap.add_argument("--output", default=os.getenv("OUT_GUIDE", "guide.xml"))
    ap.add_argument("--channels-output", default=os.getenv("OUT_CHANNELS", "channels.xml"))
    ap.add_argument("--workers", type=int, default=int(os.getenv("WORKERS", "6")))
    ap.add_argument("--delay", type=float, default=float(os.getenv("DELAY", "0.25")),
                    help="seconds to wait between requests")
    ap.add_argument("--no-offset", action="store_true",
                    default=os.getenv("NO_OFFSET", "") == "1",
                    help="emit times WITHOUT the UTC offset (some players need this). "
                         "Default: strict XMLTV with offset, e.g. ... -0400")
    args = ap.parse_args()

    global WITH_OFFSET
    WITH_OFFSET = not args.no_offset

    out_tz = ZoneInfo(args.tz)
    site_tz_name = args.site_tz
    if site_tz_name == "auto":
        site_tz_name = detect_egress_timezone()
        print(f"Detected egress timezone (site renders times in it): {site_tz_name}")
    site_tz = ZoneInfo(site_tz_name)
    today = datetime.now(out_tz).date()
    dates = [(today + timedelta(days=i)).strftime("%Y-%m-%d") for i in range(args.days)]

    session = make_session()
    print(f"Fetching channel list: provider={args.provider} region={args.region} ...")
    channels = get_channels(session, args.provider, args.region, dates[0])
    print(f"Found {len(channels)} channels.")

    all_programs = {ch["id"]: [] for ch in channels}
    tasks = [(ch, d) for ch in channels for d in dates]
    done = 0
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(get_programs, make_session(), ch, d, site_tz, out_tz): (ch, d) for ch, d in tasks}
        for fut in as_completed(futures):
            ch, d = futures[fut]
            try:
                progs = fut.result()
                all_programs[ch["id"]].extend(progs)
                done += 1
                if done % 20 == 0 or done == len(tasks):
                    print(f"  {done}/{len(tasks)} channel-days fetched")
            except Exception as e:
                print(f"  WARN: {ch['slug']} {d}: {e}", file=sys.stderr)
            time.sleep(args.delay)

    # sort programs by start time per channel
    for progs in all_programs.values():
        progs.sort(key=lambda p: p["start"])

    write_guide(args.output, channels, all_programs)
    write_channels_xml(args.channels_output, channels)
    n_prog = sum(len(v) for v in all_programs.values())
    print(f"Wrote {args.output} ({n_prog} programmes) and {args.channels_output} ({len(channels)} channels).")


if __name__ == "__main__":
    main()
