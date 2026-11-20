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
import unicodedata
import urllib.parse

import feedparser
import numpy as np
import requests

sys.path.insert(0, os.path.dirname(__file__))
from sources import RSS, HIBP_BREACHES, CISA_KEV, RANSOMWARE_LIVE, BLUESKY, MASTODON, TELEGRAM, STRICT, SKIP_TITLE  # noqa: E402
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
        if "news.google.com" in url:
            title = re.sub(r"\s+-\s+[^-]+$", "", title)
        if re.search(SKIP_TITLE, title, re.I):
            continue
        if name in STRICT and not SEC_RX.search(title):
            continue                      # general tech / lifestyle / sponsored
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


# ---------------------------------------------------------------- social
SEC_RX = re.compile(r"\b(breach\w*|ransom\w*|cve-\d|exploit\w*|vulnerab\w*|zero-?days?|0-?days?|hack(ed|ers?|ing)?|"
                    r"leak(ed|s)?|malware|phish\w*|backdoor\w*|botnets?|apt\d+|patch(ed|es)?|attack(s|ed|ers?)?|"
                    r"\w*stealer|compromis\w*|threat actors?|ddos|extort\w*|spyware|rootkit|trojan\w*|wiper|"
                    r"cisa|incident|victims?|data theft|credentials?|steal\w*|scam\w*|fraud\w*|privacy|spy\w*|surveil\w*|"
                    r"passwords?|security|cyber\w*|deepfakes?|darknet|dark web|encrypt\w*|takedown|arrest\w*)\b", re.I)
MOCK_RX = re.compile(r"([a-z][A-Z]){3}")      # mOcKiNg case memes
ALERT_HDR = re.compile(r"^\W*(new )?(cyber|threat intelligence|ransomware|data breach|data leak|hacktivist|security)?"
                       r"\s*(alert|breaking|update)s?\W*$", re.I)
URL_RX = re.compile(r"https?://\S+|\b[\w.-]+\.(com|net|org|io|co|gov)/\S*")


def social_title(text):
    t = unicodedata.normalize("NFKC", text or "")
    t = URL_RX.sub("", t)
    lines = [l.strip(" -•|") for l in t.splitlines()]
    lines = [l for l in lines if len(re.sub(r"[^\w]", "", l)) >= 3]
    body = [l for l in lines if not ALERT_HDR.match(l)]
    if body:
        lines = body
    title = ""
    for l in lines:                       # build up to ~160 chars from the first lines
        title = (title + " — " + l) if title else l
        if len(title) >= 60:
            break
    title = re.sub(r"\s+", " ", title).strip()
    return title[:157] + "…" if len(title) > 160 else title


def social_item(platform, name, text, url, when, ext=None):
    title = social_title(text)
    if len(title) < 25 or not SEC_RX.search(title) or MOCK_RX.search(text or ""):
        return None                       # chit-chat / memes
    pub = min(when, NOW)
    return {"id": item_id(url, title), "title": title, "url": url,
            "source": f"{platform} · {name}", "kind": "social", "platform": platform.lower(),
            "published": iso(pub), "ext": ext}


def fetch_bluesky(name, handle):
    r = get("https://public.api.bsky.app/xrpc/app.bsky.feed.getAuthorFeed?"
            + urllib.parse.urlencode({"actor": handle, "limit": 40, "filter": "posts_no_replies"})).json()
    out = []
    for f in r.get("feed", []):
        if f.get("reason"):               # skip reposts
            continue
        p = f["post"]
        rec = p.get("record", {})
        ext = (p.get("embed") or {}).get("external", {}).get("uri")
        rkey = p["uri"].rsplit("/", 1)[-1]
        it = social_item("Bluesky", name, rec.get("text", ""),
                         f"https://bsky.app/profile/{handle}/post/{rkey}",
                         dt.datetime.fromisoformat(rec.get("createdAt", iso(NOW)).replace("Z", "+00:00")), ext)
        if it:
            out.append(it)
    return out


def fetch_mastodon(name, instance, acct):
    a = get(f"https://{instance}/api/v1/accounts/lookup?acct={acct}").json()
    sts = get(f"https://{instance}/api/v1/accounts/{a['id']}/statuses?exclude_replies=true&exclude_reblogs=true&limit=40").json()
    out = []
    for st in sts:
        txt = re.sub(r"<br\s*/?>|</p>", "\n", st.get("content", ""))
        txt = html.unescape(re.sub(r"<[^>]+>", "", txt))
        ext = (st.get("card") or {}).get("url")
        it = social_item("Mastodon", name, txt, st.get("url"),
                         dt.datetime.fromisoformat(st["created_at"].replace("Z", "+00:00")), ext)
        if it:
            out.append(it)
    return out


def fetch_telegram(name, channel):
    from bs4 import BeautifulSoup
    soup = BeautifulSoup(get(f"https://t.me/s/{channel}").text, "html.parser")
    out = []
    for m in soup.select(".tgme_widget_message_wrap"):
        body = m.select_one(".tgme_widget_message_text")
        link = m.select_one("a.tgme_widget_message_date")
        tm = m.select_one("time[datetime]")
        if not (body and link and tm):
            continue
        ext = None
        for a in body.select("a[href^=http]"):
            if "t.me/" not in a["href"]:
                ext = a["href"]
                break
        it = social_item("Telegram", name, body.get_text("\n"), link["href"],
                         dt.datetime.fromisoformat(tm["datetime"]), ext)
        if it:
            out.append(it)
    return out


def fetch_hibp():
    """Breaches newly loaded into Have I Been Pwned (by the date HIBP added them)."""
    out = []
    for b in get(HIBP_BREACHES).json():
        try:
            added = dt.datetime.fromisoformat(b["AddedDate"].replace("Z", "+00:00"))
        except Exception:
            continue
        if NOW - added > dt.timedelta(hours=WINDOW_H) or b.get("IsSpamList") or b.get("IsFabricated"):
            continue
        classes = ", ".join(c.lower() for c in (b.get("DataClasses") or [])[:4])
        flag = "" if b.get("IsVerified", True) else " (unverified)"
        title = f"{b['Title']}{flag}: {b.get('PwnCount', 0):,} accounts added to Have I Been Pwned" + \
                (f" — {classes}" if classes else "")
        url = f"https://haveibeenpwned.com/Breach/{b['Name']}"
        out.append({"id": item_id(url, title), "title": title, "url": url, "source": "Have I Been Pwned",
                    "kind": "hibp", "published": iso(min(added, NOW)),
                    "breach_date": b.get("BreachDate"), "domain": b.get("Domain") or ""})
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
    jobs.update({f"Bluesky · {n}": (fetch_bluesky, (n, h)) for n, h in BLUESKY})
    jobs.update({f"Mastodon · {n}": (fetch_mastodon, (n, i, a)) for n, i, a in MASTODON})
    jobs.update({f"Telegram · {n}": (fetch_telegram, (n, c)) for n, c in TELEGRAM})
    jobs["CISA KEV"] = (fetch_kev, ())
    jobs["Have I Been Pwned"] = (fetch_hibp, ())
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
    # re-apply today's filters to stored items, so rule changes clean up the history too
    blocked = {"Sophos News", "SC Media", "GBHackers"}
    prev = [p for p in prev if p["source"] not in blocked
            and not re.search(SKIP_TITLE, p["title"], re.I)
            and (p["source"] not in STRICT or SEC_RX.search(p["title"]))
            and (p["kind"] != "social" or (SEC_RX.search(p["title"]) and not MOCK_RX.search(p["title"])))]
    items = merge(prev, new)
    print(f"items: new={len(new)} prev={len(prev)} window={len(items)}")
    if not items:
        sys.exit("no items at all — refusing to publish an empty wall")

    stories = build_stories(items)
    from collections import Counter
    print(f"stories: {len(stories)}  (multi-source: {sum(len(s['sources']) > 1 and not s.get('bundle') for s in stories)})")
    print("  tags:", dict(Counter(s["tag"] for s in stories)))
    if True:  # log a sample of untagged stories to tune the tag rules
        for s_ in [s for s in stories if s["tag"] == "general"][:80]:
            print("  GEN |", s_["sources"][0]["name"], "|", s_["title"][:110])
    print("  claim bundles:", {s["id"]: len(s["sources"]) for s in stories if s.get("bundle")})

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
