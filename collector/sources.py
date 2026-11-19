"""Source list for the wall collector.

kind:
  news      - journalism / news sites
  vendor    - vendor & research blogs
  advisory  - government / CERT advisories
  social    - community (Reddit etc.)
A failing source is skipped for that run; it never breaks the build.
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
    ("Cybernews", "https://cybernews.com/feed/", "news"),
    # --- vendor / research ---
    ("Cisco Talos", "https://blog.talosintelligence.com/rss/", "vendor"),
    ("Unit 42", "https://unit42.paloaltonetworks.com/feed/", "vendor"),
    ("Microsoft Security", "https://www.microsoft.com/en-us/security/blog/feed/", "vendor"),
    ("Google Threat Intel", "https://cloud.google.com/blog/topics/threat-intelligence/rss/", "vendor"),
    ("Securelist", "https://securelist.com/feed/", "vendor"),
    ("WeLiveSecurity", "https://www.welivesecurity.com/en/rss/feed/", "vendor"),
    ("Schneier", "https://www.schneier.com/feed/atom/", "vendor"),
    ("SANS ISC", "https://isc.sans.edu/rssfeed_full.xml", "vendor"),
    # --- advisories ---
    ("CISA", "https://www.cisa.gov/cybersecurity-advisories/all.xml", "advisory"),
    # --- community ---
    ("r/netsec", "https://www.reddit.com/r/netsec/.rss", "social"),
    ("r/cybersecurity", "https://www.reddit.com/r/cybersecurity/top/.rss?t=day", "social"),
]

CISA_KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
RANSOMWARE_LIVE = "https://api.ransomware.live/v2/recentvictims"
