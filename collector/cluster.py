"""Group items about the same event into stories, and tag each story.

Join rules (item -> existing story active in the last 72h), first match wins:
  1. same linked URL (e.g. a Reddit post linking a news article)
  2. shared CVE id
  3. embedding cosine >= HIGH
  4. embedding cosine >= MID and at least one shared *rare* token (an entity:
     company, product, group, place...) that isn't generic security vocabulary
Ransomware leak-site posts never merge with each other (different victims look
alike), and only merge with news that mentions the victim by name.
"""
import datetime as dt
import hashlib
import os
import re
from collections import Counter

import numpy as np

HIGH, MID = 0.80, 0.58          # tuned for all-MiniLM-L6-v2
FALLBACK_HIGH, FALLBACK_MID = 0.70, 0.40
ACTIVE_H = 72
MODEL = "sentence-transformers/all-MiniLM-L6-v2"

STOP = set("""a an the and or of to in on for with by from at as is are was were be been it its this that
these those new now after over into via amid how why what who when says said say report reports update
updates warns warn more than about not but has have had will can could may might first last week today
yet out up off top all one two three via vs""".split())
GENERIC = set("""security cyber cybersecurity hackers hacker attack attacks attacker attackers threat threats
data breach breaches vulnerability vulnerabilities flaw flaws bug bugs patch patches patched exploit exploited
exploits exploitation critical malware ransomware campaign campaigns actors actor group groups users user
customers customer company companies firm network networks systems system software servers server
access information million billion thousands researchers research targets targeting targeted phishing
government agency agencies microsoft google zero-day zero day remote code execution rce cisa kev wild
claims claimed stolen leak leaked leaks exposed exposes impacts impacted affecting affected""".split())

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9\-\.]{2,}")

TAG_RULES = [
    ("ransomware", re.compile(r"ransom|extortion|leak site|lockbit|akira|qilin|blackcat|alphv|cl0p|\bclop\b|"
                              r"black ?basta|medusa|rhysida|8base|bianlian|dragonforce|safepay|play ransomware|"
                              r"inc ransom|hunters international|ransomhub|scattered spider", re.I)),
    ("breach", re.compile(r"breach|data leak|leaked|exposed|stolen|hacked|compromis|unauthori[sz]ed access|"
                          r"data theft|customer data|personal data|records|cyberattack|cyber attack|creds|credential|dump|"
                          r"cyber incident|security incident|offered|for sale|\bfullz\b|\bcvvs?\b|database|profiles", re.I)),
    ("cve", re.compile(r"\bcve-\d|vulnerab|zero-day|0-day|\bflaws?\b|exploit|\bpatch|\brce\b|"
                       r"remote code|security update|advisory|\bkev\b|bug|vuln\w*|\w+[24]shell\b|hotpatch", re.I)),
    ("policy", re.compile(r"arrest|charged|sentenc|indict|extradit|plead|convict|\bpolice|europol|interpol|"
                          r"\bfbi\b|\bdoj\b|justice department|law enforcement|takedown|dismantl|seiz|sanction|"
                          r"\bfined?\b|fines\b|penalt|regulat|lawsuit|\bsues?\b|court|legislat|\bbill\b|congress|"
                          r"parliament|senat|\bgdpr\b|\bnis2\b|\bftc\b|\bsec\b|\bico\b|policy|ban(s|ned)?\b|"
                          r"ministry|minister|government|white house|executive order|cisa (warns|urges|orders)|lawmaker|\bmps?\b|"
                          r"caucus|watchdog|nominee|nominat|cyber director|\bdems?\b|republican|democrat|accused|"
                          r"shut(s|ting)? down|crackdown|illegal|insurer|compliance", re.I)),
    ("threat", re.compile(r"malware|\bapt\d*\b|campaign|backdoor|botnet|phish|stealer|trojan|\brat\b|loader|"
                          r"spyware|threat actor|hackers?\b|espionage|wiper|rootkit|ddos|scam|fraud|infostealer|"
                          r"supply.chain|worm|c2\b|command.and.control|social engineering|attack(s|ed)?\b|"
                          r"\bactor\b|aligned|nation.state|north korea|china.nexus|deepfake|impersonat|"
                          r"infosteal\w*|dead drops?|honeypot|fake \w+ sites?|steal logins", re.I)),
]

# accounts whose posts are mostly "group X claims victim Y" alerts
CLAIM_ACCOUNTS = {"Bluesky · FalconFeeds", "Bluesky · HackManac"}
GROUP_RE = re.compile(r"^(.+?) ransomware claims ", re.I)


CORP = set("inc llc ltd gmbh corp co sa ag plc group bv srl spa limited company".split())


def victim_key(v):
    """'Acme Bank, Inc.' -> 'acme bank' (only if specific enough to match on)."""
    w = [t for t in re.findall(r"[a-z0-9&]+", v.lower()) if t not in CORP]
    k = " ".join(w)
    return k if len(k) >= 5 else ""


def tokens(text):
    return {t.strip(".-") for t in TOKEN_RE.findall(text.lower())} - STOP


def _parse(s):
    return dt.datetime.fromisoformat(s.replace("Z", "+00:00"))


def norm_link(u):
    if not u:
        return None
    u = re.sub(r"^https?://(www\.)?", "", u.lower()).split("#")[0].split("?")[0].rstrip("/")
    return u


# ------------------------------------------------------------- embeddings
def embed(texts):
    """Return (L2-normalized matrix, high, mid). Falls back to hashed bag-of-words."""
    try:
        if os.environ.get("WALL_NO_MODEL"):
            raise RuntimeError("model disabled")
        from fastembed import TextEmbedding
        m = TextEmbedding(MODEL, cache_dir=os.environ.get("FASTEMBED_CACHE_PATH"))
        v = np.array(list(m.embed(texts, batch_size=128)), dtype=np.float32)
        hi, mid = HIGH, MID
        print(f"  embeddings: {MODEL}")
    except Exception as e:
        print(f"  embeddings: FALLBACK bag-of-words ({type(e).__name__})")
        dim = 4096
        v = np.zeros((len(texts), dim), dtype=np.float32)
        for i, t in enumerate(texts):
            for tok in tokens(t) - GENERIC:
                v[i, int(hashlib.md5(tok.encode()).hexdigest(), 16) % dim] += 1
        hi, mid = FALLBACK_HIGH, FALLBACK_MID
    v /= np.linalg.norm(v, axis=1, keepdims=True) + 1e-9
    return v, hi, mid


# ------------------------------------------------------------- tagging
def tag_story(members):
    if any(m["kind"] == "leak" for m in members):
        return "ransomware"
    if all(m["kind"] == "advisory" for m in members):
        return "cve"                      # CISA ICS advisories etc.
    score = Counter()
    for m in members:
        for tag, rx in TAG_RULES:
            if rx.search(m["title"]):
                score[tag] += 1
    if not score:
        return "general"
    best = max(score.values())
    for tag, _ in TAG_RULES:              # priority order on ties
        if score[tag] == best:
            return tag
    return "general"


SOURCE_RANK = {"news": 0, "advisory": 1, "vendor": 2, "social": 3, "leak": 4}


def build_stories(items):
    items = sorted(items, key=lambda x: x["published"])
    n = len(items)
    vecs, hi, mid = embed([it["title"] for it in items])

    toks = [tokens(it["title"]) for it in items]
    df = Counter(t for ts in toks for t in ts)
    rare_cut = max(6, int(n * 0.02))
    rare = [{t for t in ts if df[t] <= rare_cut and t not in GENERIC and not t.isdigit()} for ts in toks]
    cves = [{c.upper() for c in CVE_RE.findall(it["title"])} for it in items]
    links = [{norm_link(it.get("url")), norm_link(it.get("ext"))} - {None} for it in items]

    clusters = []      # dict(members, vec_sum, rare, cves, links, last, has_leak, victim_toks)
    for i, it in enumerate(items):
        ts = _parse(it["published"])
        is_leak = it["kind"] == "leak"
        victim_toks = (tokens(it.get("victim", "")) - GENERIC - CORP) if is_leak else set()
        vname = victim_key(it.get("victim", "")) if is_leak else ""
        title_l = it["title"].lower()
        best, best_score = None, -1.0
        for c in clusters:
            if (ts - c["last"]).total_seconds() > ACTIVE_H * 3600:
                continue
            if is_leak or c["has_leak"]:
                # leak-site posts only merge with news that names the victim
                if is_leak and c["has_leak"]:
                    continue
                named = (is_leak and vname and vname in c["text"]) or \
                        (not is_leak and any(v and v in title_l for v in c["vnames"]))
                if named:
                    best, best_score = c, 2.0
                    break
                continue
            if cves[i] and c["cves"] and not (cves[i] & c["cves"]):
                continue                     # different CVEs = different stories
            if links[i] & c["links"] or cves[i] & c["cves"]:
                best, best_score = c, 2.0
                break
            cvec = c["vec_sum"] / (np.linalg.norm(c["vec_sum"]) + 1e-9)
            s = float(vecs[i] @ cvec)
            if s >= hi or (s >= mid and rare[i] & c["rare"]):
                if s > best_score:
                    best, best_score = c, s
        if best is None:
            best = {"members": [], "vec_sum": np.zeros_like(vecs[i]), "rare": set(), "cves": set(),
                    "links": set(), "all_toks": set(), "has_leak": False, "victim_toks": set(), "vnames": set(), "text": "", "last": ts}
            clusters.append(best)
        best["members"].append(it)
        best["vec_sum"] += vecs[i]
        best["rare"] |= rare[i]
        best["cves"] |= cves[i]
        best["links"] |= links[i]
        best["all_toks"] |= toks[i]
        best["text"] += " " + it["title"].lower()
        best["last"] = max(best["last"], ts)
        if is_leak:
            best["has_leak"] = True
            best["victim_toks"] |= victim_toks
            best["vnames"].add(vname)

    stories = []
    for c in clusters:
        ms = c["members"]
        # one entry per source (earliest)
        per_src, srcs = set(), []
        for m in ms:
            if m["source"] in per_src:
                continue
            per_src.add(m["source"])
            srcs.append(m)
        # headline: earliest from the most "journalistic" kind
        head = min(srcs, key=lambda m: (SOURCE_RANK.get(m["kind"], 9), m["published"]))
        stories.append({
            "id": hashlib.sha1(ms[0]["id"].encode()).hexdigest()[:12],
            "tag": tag_story(ms),
            "social_only": all(m["kind"] == "social" for m in srcs),
            "title": head["title"],
            "url": head["url"],
            "source": srcs[0]["source"],
            "first_seen": ms[0]["published"],
            "updated": ms[-1]["published"],
            "sources": [{"name": m["source"], "url": m["url"], "title": m["title"],
                         "published": m["published"], "kind": m["kind"],
                         **({"platform": m["platform"]} if m.get("platform") else {})} for m in srcs],
        })
    stories = bundle_claims(stories)
    stories.sort(key=lambda s: s["updated"], reverse=True)
    return stories


def is_claim(story):
    """Single-victim claim nobody in the news has picked up yet."""
    src = story["sources"]
    if story["tag"] != "ransomware":
        return False
    return all(x["kind"] == "leak" or x["name"] in CLAIM_ACCOUNTS for x in src)


def claim_group(story):
    for x in story["sources"]:
        m = GROUP_RE.match(x["title"]) if x["kind"] == "leak" else None
        if m:
            return m.group(1).strip()
    t = " ".join(x["title"] for x in story["sources"])
    m = TAG_RULES[0][1].search(t)
    g = m.group(0) if m else ""
    return g.title() if g and g.lower() not in ("ransom", "extortion", "leak site") else "Unattributed"


def bundle_claims(stories):
    """Collapse leak-site / claim-alert stories into one card per Athens day."""
    try:
        from zoneinfo import ZoneInfo
        tz = ZoneInfo("Europe/Athens")
    except Exception:
        tz = dt.timezone.utc
    keep, days = [], {}
    for st in stories:
        if not is_claim(st):
            keep.append(st)
            continue
        day = _parse(st["first_seen"]).astimezone(tz).date().isoformat()
        days.setdefault(day, []).append(st)
    for day, claims in days.items():
        claims.sort(key=lambda c: c["first_seen"])
        groups = Counter(claim_group(c) for c in claims)
        rows = []
        for c in claims:
            rows.append({"name": claim_group(c), "url": c["url"], "title": c["title"],
                         "published": c["first_seen"], "kind": "leak",
                         "via": sorted({x["name"] for x in c["sources"]})})
        keep.append({
            "id": "claims-" + day,
            "bundle": "claims",
            "tag": "ransomware",
            "social_only": False,
            "title": f"{len(claims)} ransomware & leak-site claims",
            "groups": [[g, n] for g, n in groups.most_common()],
            "url": rows[-1]["url"],
            "source": "ransomware.live",
            "first_seen": claims[0]["first_seen"],
            "updated": max(c["updated"] for c in claims),
            "sources": rows,
        })
    return keep
