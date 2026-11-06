# 📡 QA Radar

**A free, self-updating radar of exploited vulnerabilities, critical CVEs and software testing news — summarized by an AI agent. Zero servers. Zero cost. Fork it in 2 minutes.**

![Updates every day at 6:00 AM](https://img.shields.io/badge/updates-every%206h-brightgreen) ![Cost](https://img.shields.io/badge/cost-%240-blue) ![Servers](https://img.shields.io/badge/servers-0-orange)

👉 **Live site:** `https://<your-username>.github.io/qa-radar/`

## ✨ What you get
- 🧠 **AI Daily Brief** — 5 bullets every QA engineer should know today
- ⭐ **Must-read for QA** — AI picks the most relevant news and explains why
- 🔥 **Actively exploited vulns** from CISA KEV
- 🚨 **New critical CVEs** from NVD
- 📦 **Critical package advisories** (npm, PyPI, Maven…) from GitHub
- 📰 **Testing & tool news** — Playwright, Cypress, Selenium, k6, testing blogs

## ⚙️ How it works
```
GitHub Actions (every day 6:00 AM) → fetch feeds → LLM ranks & summarizes → data.json → GitHub Pages
```
Facts (CVE IDs, scores) come straight from official feeds. The AI only ranks and summarizes,
and a built-in guard drops any AI bullet that mentions a CVE not in the source data. 🛡️

## 🚀 Setup (2 minutes)
1. **Fork** this repo.
2. **Settings → Pages** → Source: *Deploy from a branch* → `main` / `/docs`.
3. **Settings → Secrets and variables → Actions**, then pick ONE model option below.
4. **Actions tab** → enable workflows → *QA Radar update* → **Run workflow**.

### Option A — Free LLM API (recommended, smarter)
| Type | Name | Example (Groq) |
|---|---|---|
| Variable | `LLM_BASE_URL` | `https://api.groq.com/openai/v1` |
| Variable | `LLM_MODEL` | a model from your provider's docs |
| Secret | `LLM_API_KEY` | your free API key |

Any OpenAI-compatible provider works (Groq, Gemini, OpenRouter, Mistral…).

### Option B — 100% local open-source model (no API key)
| Type | Name | Value |
|---|---|---|
| Variable | `LLM_PROVIDER` | `ollama` |
| Variable | `OLLAMA_MODEL` | `llama3.2:3b` (optional) |

Runs Ollama inside the GitHub Action. Slower, but no keys at all.

### Optional
- Secret `TAVILY_API_KEY` — adds live web search for QA news (free tier is enough)
- Secret `NVD_API_KEY` — higher NVD rate limits

No model configured? It still works — you get the raw feeds without AI summaries.

## 🎨 Customize
Edit `agent/config.py` to add RSS feeds, search queries, or change limits.

## 🤝 Contributing
Add a feed, improve a prompt, polish the UI — PRs welcome! Look for `good first issue`.

## ⚠️ Disclaimer
AI summaries can be wrong. Always verify with the linked source before acting.
Feed titles and snippets are untrusted third-party text passed to the model; everything is
HTML-escaped on the site, but a crafted headline could still skew the AI's ranking or wording.

## 📄 License
MIT