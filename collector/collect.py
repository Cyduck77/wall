#!/usr/bin/env python3
"""WALL collector: fetch sources -> merge 7-day state -> cluster stories -> write feed.json.

Usage: python collector/collect.py --out site [--prev-url URL] [--offline-state FILE]
"""
import argparse
import concurrent.futures as cf
import datetime as dt
import hashlib
import html
import json
import os
import re
import sys
import time
import urllib.parse

import feedparser
import numpy as np
import requests

sys.path.insert(0, os.path.dirname(__file__))
from sources import RSS, CISA_KEV, RANSOMWARE_LIVE  # noqa: E402
from cluster import build_stories  # noqa: E402

WINDOW_H = 168            # keep 7 days
UA = "WallNewsBot/1.0 (+https://cyduck77.github.io/wall)"
TIMEOUT = 20
NOW = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)


def iso(t):
    return t.astimezone(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_iso(s):
    return dt.datetime.fromisoformat(s.replace("Z", "+00:00"))


def clean_title(t):
    t = html.unescape(re.sub(r"<[^>]+>", "", t or ""))
    return re.sub(r"\s+", " ", t).strip()


TRACKING = re.compile(r"^(utm_|fbclid|gclid|mc_|ref$|source$)")


def norm_url(u):
    try:
        p = urllib.parse.urlsplit(u.strip())
        q = [(k, v) for k, v in urllib.parse.parse_qsl(p.query) if not TRACKING.match(k)]
        path = p.path.rstrip("/") or "/"
        return urllib.parse.urlunsplit((p.scheme.lower(), p.netloc.lower().removeprefix("www."), path,
                                        urllib.parse.urlencode(q), ""))
    except Exception:
        return u


def item_id(url, title):
    return hashlib.sha1((norm_url(url) or title).encode()).hexdigest()[:16]


def get(url):
    r = requests.get(url, headers={"User-Agent": UA, "Accept": "*/*"}, timeout=TIMEOUT)
    r.raise_for_status()
    return r


# ---------------------------------------------------------------- fetchers
def fetch_rss(name, url, kind):
    feed = feedparser.parse(get(url).content)
    out = []
    for e in feed.entries[:60]:
        title = clean_title(e.get("title"))
        link = e.get("link") or ""
        if len(title) < 15 or not link.startswith("http"):
            continue
        if kind == "social":
            if title.endswith("?"):          # community questions are noise
                continue
            m = re.search(r'href="(https?://(?!www\.reddit\.com)[^"]+)"[^>]*>\[link\]',
                          (e.get("content") or [{}])[0].get("value", "") if e.get("content") else "")
            ext = html.unescape(m.group(1)) if m else None
        else:
            ext = None
        tp = e.get("published_parsed") or e.get("updated_parsed")
        pub = dt.datetime.fromtimestamp(time.mktime(tp), dt.timezone.utc) if tp else NOW
        pub = min(pub, NOW)
        out.append({
            "id": item_id(link, title), "title": title, "url": link, "source": name,
            "kind": kind, "published": iso(pub), "ext": ext,
        })
    return out


def fetch_kev():
    data = get(CISA_KEV).json()
    out = []
    for v in data.get("vulnerabilities", []):
        try:
            pub = dt.datetime.strptime(v["dateAdded"], "%Y-%m-%d").replace(tzinfo=dt.timezone.utc, hour=17)
        except Exception:
            continue
        if NOW - pub > dt.timedelta(hours=WINDOW_H):
            continue
        cve = v.get("cveID", "")
        name = v.get("vulnerabilityName") or f'{v.get("vendorProject","")} {v.get("product","")}'
        title = f"CISA KEV: {cve} — {name} exploited in the wild"
        url = f"https://nvd.nist.gov/vuln/detail/{cve}"
        out.append({"id": item_id(url, title), "title": title, "url": url, "source": "CISA KEV",
                    "kind": "advisory", "published": iso(min(pub, NOW))})
    return out


def fetch_ransomware_live():
    data = get(RANSOMWARE_LIVE).json()
    if isinstance(data, dict):
        data = data.get("victims") or data.get("data") or []
    out = []
    for v in data[:200]:
        victim = clean_title(v.get("victim") or v.get("post_title") or "")
        group = (v.get("group") or v.get("group_name") or "unknown").strip()
        when = v.get("discovered") or v.get("published") or v.get("attackdate")
        if not victim or not when:
            continue
        try:
            pub = dt.datetime.fromisoformat(str(when).replace("Z", "+00:00").replace(" ", "T"))
            if pub.tzinfo is None:
                pub = pub.replace(tzinfo=dt.timezone.utc)
        except Exception:
            continue
        if NOW - pub > dt.timedelta(hours=WINDOW_H):
            continue
        country = (v.get("country") or "").strip()
        title = f"{group.title()} ransomware claims {victim}" + (f" ({country})" if country else "")
        url = v.get("url") or v.get("permalink") or \
            f"https://www.ransomware.live/group/{urllib.parse.quote(group.lower())}"
        out.append({"id": item_id(f"rl:{group}:{victim}", title), "title": title, "url": url,
                    "source": "ransomware.live", "kind": "leak", "victim": victim,
                    "published": iso(min(pub, NOW))})
    return out


def collect():
    jobs = {f"rss:{n}": (fetch_rss, (n, u, k)) for n, u, k in RSS}
    jobs["CISA KEV"] = (fetch_kev, ())
    jobs["ransomware.live"] = (fetch_ransomware_live, ())
    items, ok, failed = [], [], []
    with cf.ThreadPoolExecutor(max_workers=12) as ex:
        futs = {ex.submit(fn, *args): key for key, (fn, args) in jobs.items()}
        for f in cf.as_completed(futs):
            key = futs[f].removeprefix("rss:")
            try:
                got = f.result()
                items += got
                ok.append(key)
                print(f"  ok   {key:24s} {len(got):4d}")
            except Exception as e:
                failed.append(key)
                print(f"  FAIL {key:24s} {type(e).__name__}: {str(e)[:90]}")
    return items, sorted(ok), sorted(failed)


def load_prev(prev_url, offline):
    try:
        if offline:
            return json.load(open(offline)).get("items", [])
        r = requests.get(prev_url, params={"t": int(time.time())}, headers={"User-Agent": UA}, timeout=TIMEOUT)
        if r.status_code == 200:
            return r.json().get("items", [])
        print(f"  no previous state ({r.status_code})")
    except Exception as e:
        print(f"  no previous state ({e})")
    return []


def merge(prev, new):
    """Union by id; keep earliest published; drop items outside the window."""
    cutoff = NOW - dt.timedelta(hours=WINDOW_H)
    by_id, seen_titles = {}, set()
    for it in prev + new:
        try:
            if parse_iso(it["published"]) < cutoff:
                continue
        except Exception:
            continue
        key = (it["source"], it["title"].lower())
        if it["id"] in by_id:
            old = by_id[it["id"]]
            if it["published"] < old["published"]:
                old["published"] = it["published"]
            continue
        if key in seen_titles:
            continue
        seen_titles.add(key)
        by_id[it["id"]] = dict(it)
    return list(by_id.values())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="site")
    ap.add_argument("--prev-url", default=os.environ.get("PREV_STATE_URL",
                                                          "https://cyduck77.github.io/wall/state.json"))
    ap.add_argument("--offline-state", help="use a local state.json instead of fetching (testing)")
    ap.add_argument("--no-fetch", action="store_true", help="only re-cluster the previous state (testing)")
    a = ap.parse_args()

    t0 = time.time()
    print("fetching sources…")
    new, ok, failed = ([], [], []) if a.no_fetch else collect()
    prev = load_prev(a.prev_url, a.offline_state)
    items = merge(prev, new)
    print(f"items: new={len(new)} prev={len(prev)} window={len(items)}")
    if not items:
        sys.exit("no items at all — refusing to publish an empty wall")

    stories = build_stories(items)
    print(f"stories: {len(stories)}  (multi-source: {sum(len(s['sources']) > 1 for s in stories)})")

    os.makedirs(a.out, exist_ok=True)
    feed = {
        "generated_at": iso(NOW), "window_hours": WINDOW_H,
        "sources": {"ok": len(ok), "failed": failed},
        "stories": stories,
    }
    with open(os.path.join(a.out, "feed.json"), "w") as f:
        json.dump(feed, f, ensure_ascii=False, separators=(",", ":"))
    with open(os.path.join(a.out, "state.json"), "w") as f:
        json.dump({"generated_at": iso(NOW), "items": items}, f, ensure_ascii=False, separators=(",", ":"))
    print(f"done in {time.time() - t0:.1f}s")


if __name__ == "__main__":
    main()
