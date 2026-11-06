"""QA Radar agent: collects vulnerabilities + SQA news, lets an LLM rank and summarize,
and writes docs/data.json for the website. Facts (CVE IDs, scores) always come from
the official feeds; the LLM only ranks and summarizes."""

import datetime as dt
import json
import os
import re
import sys
import time
from email.utils import parsedate_to_datetime
from pathlib import Path
from urllib.parse import urlparse

import feedparser
import requests

from config import (ARCHIVE_DAYS, FEEDS, MAX_GHSA, MAX_KEV, MAX_NVD, NEWS_DAYS, NVD_DAYS,
                    TAVILY_QUERIES, TOP_NEWS)

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "data.json"
ARCHIVE = ROOT / "docs" / "archive"
REPO_URL = f"https://github.com/{os.getenv('GITHUB_REPOSITORY', 'qa-radar')}"
UA = {"User-Agent": f"qa-radar/1.0 (+{REPO_URL})"}
NOW = dt.datetime.now(dt.timezone.utc)
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
BULLET_RE = re.compile(r"^\s*(?:[-*•]|\d+[.)])\s+")
SECTIONS = ("kev", "nvd", "ghsa", "news")


# ---------------------------------------------------------------- helpers
def get_json(url, headers=None, timeout=30, **kw):
    r = requests.get(url, headers={**UA, **(headers or {})}, timeout=timeout, **kw)
    r.raise_for_status()
    return r.json()


def clean(html):
    text = re.sub(r"<[^>]+>", " ", html or "")
    return re.sub(r"\s+", " ", text).strip()


def safe(fn, name):
    try:
        data = fn()
        print(f"[ok]   {name}: {len(data)} items")
        return data
    except Exception as e:  # one broken source must never kill the run
        print(f"[skip] {name}: {e}")
        return []


# ---------------------------------------------------------------- sources
def fetch_kev():
    data = get_json("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
    vulns = sorted(data["vulnerabilities"], key=lambda v: v["dateAdded"], reverse=True)[:MAX_KEV]
    return [{
        "id": v["cveID"],
        "title": v["vulnerabilityName"],
        "product": f'{v["vendorProject"]} {v["product"]}',
        "description": v["shortDescription"],
        "date": v["dateAdded"],
        "ransomware": v.get("knownRansomwareCampaignUse") == "Known",
        "url": f'https://nvd.nist.gov/vuln/detail/{v["cveID"]}',
    } for v in vulns]


def fetch_nvd():
    """Critical CVEs published in the last NVD_DAYS, scored with CVSS v3.x OR v4.0 (many CNAs now
    publish v4-only scores). Pages through all results; NVD returns oldest first."""
    fmt = "%Y-%m-%dT%H:%M:%S.000"
    api_key = os.getenv("NVD_API_KEY")
    headers = {"apiKey": api_key} if api_key else {}
    pause = 0.7 if api_key else 6.5  # NVD rate limit: 50 req/30s with key, 5 req/30s without
    base = {
        "pubStartDate": (NOW - dt.timedelta(days=NVD_DAYS)).strftime(fmt),
        "pubEndDate": NOW.strftime(fmt),
        "resultsPerPage": 2000,
    }
    found, first = {}, True
    for severity_param in ("cvssV3Severity", "cvssV4Severity"):
        start, total = 0, 1
        while start < total:
            if not first:
                time.sleep(pause)
            first = False
            data = get_json("https://services.nvd.nist.gov/rest/json/cves/2.0", headers=headers,
                            params={**base, severity_param: "CRITICAL", "startIndex": start}, timeout=60)
            total = data.get("totalResults", 0)
            page = data.get("vulnerabilities", [])
            start += len(page)
            for wrap in page:
                c = wrap["cve"]
                found[c["id"]] = c
            if not page:
                break

    items = []
    for c in found.values():
        desc = next((d["value"] for d in c.get("descriptions", []) if d.get("lang") == "en"), "")
        score = None
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
            if c.get("metrics", {}).get(key):
                score = c["metrics"][key][0]["cvssData"]["baseScore"]
                break
        items.append({
            "id": c["id"],
            "description": desc[:400],
            "score": score,
            "date": c.get("published", "")[:10],
            "url": f"https://nvd.nist.gov/vuln/detail/{c['id']}",
        })
    items.sort(key=lambda x: (x["score"] or 0, x["date"]), reverse=True)
    return items[:MAX_NVD]


def fetch_ghsa():
    headers = {"Accept": "application/vnd.github+json"}
    if os.getenv("GITHUB_TOKEN"):
        headers["Authorization"] = f"Bearer {os.environ['GITHUB_TOKEN']}"
    data = get_json("https://api.github.com/advisories", headers=headers,
                    params={"type": "reviewed", "severity": "critical", "per_page": MAX_GHSA})
    out = []
    for a in data:
        pkgs = sorted({
            f'{v["package"]["ecosystem"]}/{v["package"]["name"]}'
            for v in (a.get("vulnerabilities") or []) if v.get("package")
        })
        out.append({
            "id": a["ghsa_id"],
            "cve": a.get("cve_id"),
            "title": a.get("summary", ""),
            "packages": pkgs[:4],
            "date": (a.get("published_at") or "")[:10],
            "url": a["html_url"],
        })
    return out


def fetch_feeds():
    items, cutoff = [], NOW - dt.timedelta(days=NEWS_DAYS)
    for feed in FEEDS:
        try:
            resp = requests.get(feed["url"], headers=UA, timeout=20)
            resp.raise_for_status()
            count = 0
            for e in feedparser.parse(resp.content).entries[:10]:
                t = e.get("published_parsed") or e.get("updated_parsed")
                if not t:  # undated entries would always look "newest" and crowd out real news
                    continue
                when = dt.datetime(*t[:6], tzinfo=dt.timezone.utc)
                if when < cutoff:
                    continue
                items.append({
                    "title": clean(e.get("title", "")),
                    "url": e.get("link", ""),
                    "source": feed["name"],
                    "category": feed["category"],
                    "date": when.strftime("%Y-%m-%d"),
                    "snippet": clean(e.get("summary", ""))[:300],
                })
                count += 1
            print(f"[ok]   feed {feed['name']}: {count} items")
        except Exception as ex:
            print(f"[skip] feed {feed['name']}: {ex}")
    return items


def fetch_tavily():
    key = os.getenv("TAVILY_API_KEY")
    if not key:
        return []
    items = []
    for q in TAVILY_QUERIES:
        try:
            r = requests.post("https://api.tavily.com/search",
                              headers={"Authorization": f"Bearer {key}"},
                              json={"query": q, "topic": "news", "days": NEWS_DAYS, "max_results": 5},
                              timeout=30)
            r.raise_for_status()
            results = r.json().get("results", [])
        except Exception as e:  # one failed query must not drop the others
            print(f"[skip] Tavily query {q!r}: {e}")
            continue
        for res in results:
            when = parse_date(res.get("published_date"))
            if not when:  # undated results would always sort as "newest"
                continue
            items.append({
                "title": res.get("title", ""),
                "url": res.get("url", ""),
                "source": urlparse(res.get("url", "")).netloc.removeprefix("www."),
                "category": "Web",
                "date": when.strftime("%Y-%m-%d"),
                "snippet": clean(res.get("content", ""))[:300],
            })
    return items


def parse_date(value):
    """Parse ISO-8601 or RFC-2822 date strings (Tavily uses either); None if unparseable."""
    if not value:
        return None
    for parse in (lambda v: dt.datetime.fromisoformat(v.replace("Z", "+00:00")), parsedate_to_datetime):
        try:
            return parse(value)
        except (ValueError, TypeError):
            continue
    return None


# ---------------------------------------------------------------- LLM
SYSTEM = ("You are QA Radar, an assistant for software QA engineers. Be concise and factual. "
          "Never invent CVE IDs, versions, or facts that are not in the input.")


def llm(prompt):
    base = os.getenv("LLM_BASE_URL")
    if not base or not os.getenv("LLM_MODEL"):
        return None
    r = requests.post(
        base.rstrip("/") + "/chat/completions",
        headers={"Authorization": f"Bearer {os.getenv('LLM_API_KEY') or 'none'}"},
        json={"model": os.environ["LLM_MODEL"], "temperature": 0.2,
              "messages": [{"role": "system", "content": SYSTEM},
                           {"role": "user", "content": prompt}]},
        timeout=900,
    )
    r.raise_for_status()
    text = r.json()["choices"][0]["message"]["content"] or ""
    return re.sub(r"<think>.*?</think>", "", text, flags=re.S).strip()  # strip reasoning tags


def pick_top_news(news):
    cands = news[:40]
    fallback = [{**n, "why": ""} for n in cands[:TOP_NEWS]]
    if not cands:
        return []
    listing = "\n".join(f"{i}. [{n['source']}] {n['title']} — {n['snippet'][:150]}" for i, n in enumerate(cands))
    prompt = (f"Here are recent news items:\n{listing}\n\n"
              f"Pick the {TOP_NEWS} items most important for QA/test engineers "
              "(testing tools, test automation, quality failures, security issues testers should check). "
              'Reply ONLY with a JSON array like [{"i": 3, "why": "one short sentence"}].')
    try:
        text = llm(prompt)
        if not text:
            return fallback
        arr = json.loads(re.search(r"\[.*\]", text, re.S).group(0))
        top, seen = [], set()
        for obj in arr:
            i = int(obj.get("i", -1))
            if 0 <= i < len(cands) and i not in seen:
                seen.add(i)
                top.append({**cands[i], "why": str(obj.get("why", ""))[:200]})
        return top[:TOP_NEWS] or fallback
    except Exception as e:
        print(f"[warn] ranking failed, using newest items: {e}")
        return fallback


def write_brief(kev, nvd, ghsa, top):
    facts = "\n".join(
        [f"- EXPLOITED: {v['id']} {v['product']}: {v['title']}" for v in kev[:5]]
        + [f"- CRITICAL: {v['id']} (CVSS {v['score']}): {v['description'][:150]}" for v in nvd[:5]]
        + [f"- NEWS: {n['title']} ({n['source']})" for n in top[:8]]
    )
    # The guard allows exactly the CVE IDs the model was shown (incl. ones inside news titles).
    known = {c.upper() for c in CVE_RE.findall(facts)}
    prompt = (f"Facts:\n{facts}\n\nWrite a daily brief for QA engineers: exactly 5 bullet points, "
              "each starting with '- ' and an emoji, max 25 words each. Use only the facts above.")
    try:
        text = llm(prompt)
    except Exception as e:
        print(f"[warn] brief failed: {e}")
        return []
    if not text:
        return []
    bullets = []
    for line in text.splitlines():
        m = BULLET_RE.match(line)
        if not m:
            continue
        bullet = line[m.end():].replace("**", "").replace("__", "").strip()
        if not bullet:
            continue
        # QA check on our own AI: drop any bullet that mentions a CVE we never gave it
        if all(c.upper() in known for c in CVE_RE.findall(bullet)):
            bullets.append(bullet)
        else:
            print(f"[guard] dropped hallucinated bullet: {bullet}")
    return bullets[:5]


# ---------------------------------------------------------------- main
def load_previous():
    try:
        return json.loads(OUT.read_text(encoding="utf-8"))
    except Exception:
        return {}


def prune_archive():
    cutoff = (NOW - dt.timedelta(days=ARCHIVE_DAYS)).strftime("%Y-%m-%d")
    for f in ARCHIVE.glob("*.json"):
        if f.stem < cutoff:
            f.unlink()
            print(f"[prune] {f.name}")


def main():
    kev = safe(fetch_kev, "CISA KEV")
    nvd = safe(fetch_nvd, "NVD critical")
    ghsa = safe(fetch_ghsa, "GitHub advisories")
    news = fetch_feeds() + safe(fetch_tavily, "Tavily")

    seen, unique = set(), []
    for n in sorted(news, key=lambda x: x["date"], reverse=True):
        if n["url"] and n["url"] not in seen:
            seen.add(n["url"])
            unique.append(n)

    if not (kev or nvd or ghsa or unique):
        print("[abort] every source failed — keeping the previous data.json untouched")
        sys.exit(1)

    # A single source being down must not blank its section on the site: reuse the last good data.
    prev = load_previous()
    fresh = {"kev": kev, "nvd": nvd, "ghsa": ghsa, "news": unique}
    for key in SECTIONS:
        if not fresh[key] and prev.get(key):
            print(f"[keep] {key}: no fresh data, reusing {len(prev[key])} items from last run")
            fresh[key] = prev[key]
    kev, nvd, ghsa, unique = (fresh[k] for k in SECTIONS)

    top = pick_top_news(unique)
    brief = write_brief(kev, nvd, ghsa, top)

    data = {
        "generated_at": NOW.isoformat(timespec="seconds"),
        "model": os.getenv("LLM_MODEL") or "none",
        "brief": brief,
        "top_news": top,
        "kev": kev,
        "nvd": nvd,
        "ghsa": ghsa,
        "news": unique[:60],
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(data, indent=2, ensure_ascii=False)
    OUT.write_text(payload, encoding="utf-8")
    if ARCHIVE_DAYS > 0:
        ARCHIVE.mkdir(parents=True, exist_ok=True)
        (ARCHIVE / f"{NOW:%Y-%m-%d}.json").write_text(payload, encoding="utf-8")
        prune_archive()
    print(f"[done] wrote {OUT} — {len(kev)} KEV, {len(nvd)} NVD, {len(ghsa)} GHSA, {len(unique)} news")


if __name__ == "__main__":
    main()