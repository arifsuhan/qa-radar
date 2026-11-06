"""Edit this file to customize QA Radar. Broken feeds are skipped automatically."""

FEEDS = [
    # --- Testing & QA ---
    {"name": "Google Testing Blog", "url": "https://testing.googleblog.com/feeds/posts/default", "category": "Testing"},
    {"name": "DEV #testing", "url": "https://dev.to/feed/tag/testing", "category": "Testing"},
    {"name": "DEV #qa", "url": "https://dev.to/feed/tag/qa", "category": "Testing"},
    # --- Tool releases ---
    {"name": "Playwright", "url": "https://github.com/microsoft/playwright/releases.atom", "category": "Tools"},
    {"name": "Cypress", "url": "https://github.com/cypress-io/cypress/releases.atom", "category": "Tools"},
    {"name": "Selenium", "url": "https://github.com/SeleniumHQ/selenium/releases.atom", "category": "Tools"},
    {"name": "k6", "url": "https://github.com/grafana/k6/releases.atom", "category": "Tools"},
    # --- Security news ---
    {"name": "The Hacker News", "url": "https://feeds.feedburner.com/TheHackersNews", "category": "Security"},
    {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/", "category": "Security"},
]

# Used only if TAVILY_API_KEY is set. 3 queries x 4 runs/day ≈ 360 credits/month (free tier = 1,000).
TAVILY_QUERIES = [
    "software testing QA news",
    "test automation tool release",
    "major software bug outage",
]

NEWS_DAYS = 7      # ignore news older than this
NVD_DAYS = 7       # look back this many days for new critical CVEs (NVD max: 120)
ARCHIVE_DAYS = 30  # keep daily snapshots in docs/archive/ for this many days (0 = no archive)
MAX_KEV = 12       # actively exploited vulns to show
MAX_NVD = 12       # critical CVEs to show
MAX_GHSA = 12      # package advisories to show
TOP_NEWS = 8       # AI-picked "must read" items