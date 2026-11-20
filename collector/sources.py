"""Source list for the wall collector.

kind:
  news      - journalism / news sites
  vendor    - vendor & research blogs
  advisory  - government / CERT advisories
  social    - community (Reddit etc.)
A failing source is skipped for that run; it never breaks the build.
Sources in STRICT mix general tech/sponsored content: their items are kept
only when the headline itself is about security.
"""

RSS = [
    # --- news ---
    ("BleepingComputer", "https://www.bleepingcomputer.com/feed/", "news"),
    ("The Hacker News", "https://feeds.feedburner.com/TheHackersNews", "news"),
    ("The Record", "https://therecord.media/feed", "news"),
    ("SecurityWeek", "https://www.securityweek.com/feed/", "news"),
    ("Dark Reading", "https://www.darkreading.com/rss.xml", "news"),
    ("KrebsOnSecurity", "https://krebsonsecurity.com/feed/", "news"),
    ("Help Net Security", "https://www.helpnetsecurity.com/feed/", "news"),
    ("The Register", "https://www.theregister.com/security/headlines.atom", "news"),
    ("Infosecurity Magazine", "https://www.infosecurity-magazine.com/rss/news/", "news"),
    ("CyberScoop", "https://cyberscoop.com/feed/", "news"),
    ("Security Affairs", "https://securityaffairs.com/feed", "news"),
    ("DataBreaches.net", "https://databreaches.net/feed/", "news"),
    ("The Cyber Express", "https://thecyberexpress.com/feed/", "news"),
    ("Hackread", "https://hackread.com/feed/", "news"),
    ("Cybersecurity Dive", "https://www.cybersecuritydive.com/feeds/news/", "news"),
    ("Cybernews", "https://news.google.com/rss/search?q=site:cybernews.com+when:7d&hl=en-US&gl=US&ceid=US:en", "news"),
    # --- vendor / research ---
    ("Cisco Talos", "https://blog.talosintelligence.com/rss/", "vendor"),
    ("Unit 42", "https://unit42.paloaltonetworks.com/feed/", "vendor"),
    ("Microsoft Security", "https://www.microsoft.com/en-us/security/blog/feed/", "vendor"),
    ("Google Threat Intel", "https://cloud.google.com/blog/topics/threat-intelligence/rss/", "vendor"),
    ("Securelist", "https://securelist.com/feed/", "vendor"),
    ("WeLiveSecurity", "https://www.welivesecurity.com/en/rss/feed/", "vendor"),
    ("Malwarebytes Labs", "https://www.malwarebytes.com/blog/feed/index.xml", "vendor"),
    ("Schneier", "https://www.schneier.com/feed/atom/", "vendor"),
    ("SANS ISC", "https://isc.sans.edu/rssfeed_full.xml", "vendor"),
    # --- advisories ---
    ("CISA", "https://www.cisa.gov/cybersecurity-advisories/all.xml", "advisory"),
    # --- community ---
    # Reddit blocks GitHub Actions IPs (429/404) -> re-add later via a different route
]

HIBP_BREACHES = "https://haveibeenpwned.com/api/v3/breaches"   # free, no key
CISA_KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
RANSOMWARE_LIVE = "https://api.ransomware.live/v2/recentvictims"

STRICT = {"Cybernews", "The Register", "Hackread"}
SKIP_TITLE = r"^ISC Stormcast|^Sponsored|^\[sponsored\]|webinar"

# --- social (no accounts needed: public endpoints) ---
# handles verified active on 2026-11-19
BLUESKY = [
    ("Kevin Beaumont", "doublepulsar.com"),
    ("Catalin Cimpanu", "campuscodi.risky.biz"),
    ("HackManac", "hackmanac.com"),
    ("FalconFeeds", "falconfeedsio.bsky.social"),
    ("404 Media", "404media.co"),
]
MASTODON = [  # (name, instance, account)
    ("Brian Krebs", "infosec.exchange", "briankrebs"),
    ("Will Dormann", "infosec.exchange", "wdormann"),
]
TELEGRAM = [  # public web preview t.me/s/<channel>
    ("DarkfeedNews", "DarkfeedNews"),
    ("vx-underground", "vxunderground"),
]
