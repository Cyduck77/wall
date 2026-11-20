# wall

Live cybersecurity news wall: **https://cyduck77.github.io/wall/**

Every 10 minutes a GitHub Action pulls ~25 security sources (news, vendor research,
CISA, Reddit, ransomware.live), groups reports of the same event into one story with
a local embedding model, tags it (breach / CVE / ransomware / general) and publishes
a static `feed.json` to GitHub Pages.

- `site/` – the PWA (single `index.html`, add it to your iPhone home screen)
- `collector/sources.py` – the source list (add a feed = add a line)
- `collector/collect.py` – fetch, merge the rolling 7-day window, write feed
- `collector/cluster.py` – story grouping + tagging rules
- `.github/workflows/pages.yml` – schedule, build, deploy, monthly keepalive

Local test: `pip install -r collector/requirements.txt && python collector/collect.py --out /tmp/out`
