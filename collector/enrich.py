"""CVE context for vulnerability stories — all free, no API keys.

  severity  CVSS base score + product   CVE Program records (github.com/CVEProject/cvelistV5)
  EPSS      exploitation probability    FIRST (api.first.org)
  KEV       exploited in the wild       CISA KEV catalog (full list)
  PoC       public exploit code         github.com/nomi-sec/PoC-in-GitHub

Results are cached in state.json ("cve_cache") so each CVE is looked up once;
records still missing a score or PoC are retried every 12h, EPSS is refreshed daily.
"""
import concurrent.futures as cf
import datetime as dt
import re

import requests

UA = "WallNewsBot/1.0 (+https://cyduck77.github.io/wall)"
CVE_RE = re.compile(r"\bCVE-(\d{4})-(\d{4,7})\b", re.I)
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
RECORD_URL = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{y}/{bucket}xxx/CVE-{y}-{n}.json"
POC_URL = "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/{y}/CVE-{y}-{n}.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
MAX_LOOKUPS = 150            # per run, keeps the build fast; the rest are picked up next run
RETRY_H = 12
EPSS_H = 20


def find_cves(text):
    """Normalized CVE ids in text, in order of appearance, unique."""
    out = []
    for y, n in CVE_RE.findall(text or ""):
        c = f"CVE-{y}-{n}"
        if c not in out:
            out.append(c)
    return out


def _get(url, **kw):
    return requests.get(url, headers={"User-Agent": UA}, timeout=20, **kw)


def _parse_iso(s):
    try:
        return dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        return None


def _iso(t):
    return t.replace(microsecond=0).isoformat().replace("+00:00", "Z")


# ---------------------------------------------------------------- lookups
def kev_set():
    try:
        return {v["cveID"].upper() for v in _get(KEV_URL).json().get("vulnerabilities", [])}
    except Exception as e:
        print(f"  enrich: KEV list unavailable ({type(e).__name__})")
        return None


def _best_cvss(metrics):
    for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"):
        for m in metrics or []:
            c = m.get(key)
            if c and c.get("baseScore") is not None:
                return float(c["baseScore"]), (c.get("baseSeverity") or "").upper(), key.replace("cvssV", "").replace("_", ".")
    return None


def fetch_record(cve):
    y, n = cve.split("-")[1:]
    r = _get(RECORD_URL.format(y=y, bucket=int(n) // 1000, n=n))
    if r.status_code == 404:
        return {"published": False}
    r.raise_for_status()
    rec = r.json()
    cont = rec.get("containers", {})
    cna = cont.get("cna", {})
    out = {"published": rec.get("cveMetadata", {}).get("state") == "PUBLISHED"}
    best = _best_cvss(cna.get("metrics"))
    if not best:
        for adp in cont.get("adp", []) or []:          # CISA "vulnrichment" often adds a score
            best = _best_cvss(adp.get("metrics"))
            if best:
                break
    if best:
        out["cvss"], out["sev"], out["cvss_v"] = best
    aff = (cna.get("affected") or [{}])[0]
    vendor, product = aff.get("vendor") or "", aff.get("product") or ""
    if vendor.lower() in ("n/a", "unknown"):
        vendor = ""
    if product.lower() in ("n/a", "unknown"):
        product = ""
    if vendor or product:
        first = vendor.split()[0].lower() if vendor else ""
        out["product"] = product if (first and first in product.lower()) or not vendor else f"{vendor} {product}".strip()
    desc = next((d.get("value") for d in cna.get("descriptions", []) if d.get("lang", "").startswith("en")), "")
    if desc:
        out["desc"] = re.sub(r"\s+", " ", desc).strip()[:240]
    return out


def fetch_poc(cve):
    y, n = cve.split("-")[1:]
    r = _get(POC_URL.format(y=y, n=n))
    if r.status_code == 404:
        return {"poc": 0}
    r.raise_for_status()
    repos = r.json() or []
    repos.sort(key=lambda x: x.get("stargazers_count", 0), reverse=True)
    return {"poc": len(repos), "poc_url": repos[0].get("html_url") if repos else None}


def fetch_epss(cves):
    out = {}
    for i in range(0, len(cves), 80):
        chunk = cves[i:i + 80]
        try:
            data = _get(EPSS_URL, params={"cve": ",".join(chunk)}).json().get("data", [])
            for d in data:
                out[d["cve"].upper()] = (round(float(d["epss"]), 4), round(float(d["percentile"]), 4))
        except Exception as e:
            print(f"  enrich: EPSS batch failed ({type(e).__name__})")
    return out


# ---------------------------------------------------------------- main entry
def enrich(stories, items, cache, now):
    """Attach `cves` (list of dicts) to stories; update and return the cache."""
    # 1. which CVEs does each story mention, and how strongly are they tied to it
    for s in stories:
        if s.get("bundle"):
            continue
        headline_ids = find_cves(s["title"])
        for src in s["sources"]:
            headline_ids += [c for c in find_cves(src.get("title", "")) if c not in headline_ids]
        mentions = {}
        for c in s.get("_member_cves", []):
            mentions[c] = mentions.get(c, 0) + 1
        ids = headline_ids + [c for c in mentions if c not in headline_ids]
        s["_cves"] = ids[:8]
        s["_headline_cves"] = set(headline_ids)
        s["_mentions"] = mentions
    wanted = {c for s in stories for c in s.get("_cves", [])}
    if not wanted:
        for s in stories:
            s.pop("_cves", None)
        return cache

    # 2. refresh what's missing or stale
    kev = kev_set()
    todo_rec, todo_poc = [], []
    for c in sorted(wanted):
        e = cache.setdefault(c, {})
        last = _parse_iso(e.get("checked", "")) if e.get("checked") else None
        stale = not last or (now - last).total_seconds() > RETRY_H * 3600
        if "published" not in e or (stale and (not e.get("published") or "cvss" not in e)):
            todo_rec.append(c)
        if "poc" not in e or (stale and not e.get("poc")):
            todo_poc.append(c)
    todo_rec, todo_poc = todo_rec[:MAX_LOOKUPS], todo_poc[:MAX_LOOKUPS]

    def job(kind, c):
        return kind, c, (fetch_record(c) if kind == "rec" else fetch_poc(c))

    ok = fail = 0
    with cf.ThreadPoolExecutor(max_workers=16) as ex:
        futs = [ex.submit(job, "rec", c) for c in todo_rec] + [ex.submit(job, "poc", c) for c in todo_poc]
        for f in cf.as_completed(futs):
            try:
                kind, c, res = f.result()
                cache[c].update(res)
                cache[c]["checked"] = _iso(now)
                ok += 1
            except Exception:
                fail += 1

    epss_todo = [c for c in wanted
                 if not cache[c].get("epss_at") or
                 (now - _parse_iso(cache[c]["epss_at"])).total_seconds() > EPSS_H * 3600]
    if epss_todo:
        for c, (score, pct) in fetch_epss(epss_todo).items():
            if c in cache:
                cache[c].update({"epss": score, "epss_pct": pct, "epss_at": _iso(now)})
    if kev is not None:
        for c in wanted:
            cache[c]["kev"] = c in kev

    print(f"  enrich: {len(wanted)} CVEs in stories, {len(todo_rec)} records + {len(todo_poc)} PoC lookups "
          f"({ok} ok, {fail} failed), {len(epss_todo)} EPSS requested")

    # 3. attach to stories: most relevant first, then most dangerous
    words = lambda t: {w for w in re.findall(r"[a-z0-9][a-z0-9\-]{2,}", (t or "").lower())
                       if w not in ("the", "and", "for", "remote", "server", "software", "networks", "security")}

    for s in stories:
        ids = s.pop("_cves", [])
        heads = s.pop("_headline_cves", set())
        mentions = s.pop("_mentions", {})
        if not ids:
            continue
        title_words = words(" ".join([s["title"]] + [x.get("title", "") for x in s["sources"]]))

        def rank(c):
            e = cache.get(c, {})
            in_head = c in heads
            prod_match = bool(words(e.get("product", "")) & title_words)
            return (in_head, prod_match, mentions.get(c, 0), e.get("kev", False), e.get("cvss", 0), e.get("epss", 0))

        ranked = sorted(ids, key=rank, reverse=True)
        top = cache.get(ranked[0], {})
        # show the CVE under the headline only when it clearly belongs to this story
        s["cve_primary"] = (ranked[0] in heads or bool(words(top.get("product", "")) & title_words)
                            or len(ids) == 1)
        s["cves"] = []
        for c in ranked:
            e = cache.get(c, {})
            d = {"id": c}
            for k in ("cvss", "sev", "epss", "epss_pct", "kev", "poc", "poc_url", "product", "desc"):
                if e.get(k) not in (None, "", 0, False):
                    d[k] = e[k]
            s["cves"].append(d)
    return cache


def prune(cache, keep):
    """Drop cache entries for CVEs no longer in the 7-day window."""
    return {c: e for c, e in cache.items() if c in keep}
