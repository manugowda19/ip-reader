# ThreatGuard — IP Reader / Threat Intelligence Platform

A threat intelligence dashboard and admin panel for checking IP reputation against multiple threat feeds. The system stores malicious IP data in Redis and exposes a **Dashboard** for lookups and an **Admin Panel** for managing feeds and syncing data.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Backend](#backend)
- [Frontend](#frontend)
- [Redis Data Format](#redis-data-format)
- [API Reference](#api-reference)
- [Project Structure](#project-structure)
- [Environment Variables](#environment-variables)
- [Troubleshooting](#troubleshooting)

---

## Overview

| Part | Purpose |
|------|--------|
| **Dashboard** (`/`) | IP reputation lookup, stats, top malicious IPs, recent activity. No changes to data. |
| **Admin Panel** (`/admin`) | Manage threat-intel feeds (add/remove), trigger sync of feeds into Redis. |

Data is stored in **Redis** in a consistent format: each IP has a hash `ip:<ip>` with `first_seen`, `last_seen`, `score`, `count`, and `sources`. The admin panel controls which feeds are used and when data is collected.

---

## Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────┐
│   Next.js app   │────▶│  Flask API      │────▶│  Redis  │
│   (port 3000)  │     │  (port 5000)    │     │  6379   │
└─────────────────┘     └────────┬────────┘     └─────────┘
        │                        │
        │  /api/* proxy to Flask  │  Admin: load feeds from Redis,
        │                        │  run collector → write ip:* hashes
        └────────────────────────┘
```

- **Frontend** (Next.js 16, App Router) serves the Dashboard and Admin UI. It calls the Flask backend via Next.js API routes (`/api/ip/*`, `/api/stats`, `/api/admin/*`, etc.) that proxy to the Flask app.
- **Backend** (Flask) talks to Redis for IP lookups, stats, activity, and admin (feeds CRUD, run collector).
- **Redis** holds IP hashes, feed config, collector status, and activity list.

---

## Prerequisites

- **Redis** — running on `localhost:6379` (or set `REDIS_HOST` / `REDIS_PORT`).
- **Python 3.10+** — for the backend.
- **Node.js 18+** — for the frontend.

---

## Quick Start

1. **Start Redis** (if not already running):
   ```bash
   redis-server
   ```

2. **Backend** (terminal 1):
   ```bash
   cd backend
   python -m venv venv
   source venv/bin/activate   # Windows: venv\Scripts\activate
   pip install -r requirements.txt
   python api.py
   ```
   API runs at **http://127.0.0.1:5000**.

3. **Frontend** (terminal 2):
   ```bash
   cd frountend
   cp .env.example .env      # optional: edit BACKEND_URL if needed
   npm install
   npm run dev
   ```
   App runs at **http://localhost:3000**.

4. **Optional — seed threat data**: Open **http://localhost:3000/admin**, add feeds if needed, then click **Run collector** to fetch feeds and write IPs to Redis. Or run the CLI collector once (see [Backend → Collector](#collector-cli)).

5. **Use the Dashboard**: Open **http://localhost:3000**, search for an IP to check reputation.

---

## Backend

- **Location:** `backend/`
- **Stack:** Flask, Redis, `requests` (for feed fetching).

### Setup

```bash
cd backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Run the API

```bash
python api.py
```

Runs at **http://0.0.0.0:5000** (debug mode).

### Environment variables (backend)

| Variable | Default | Description |
|----------|---------|-------------|
| `REDIS_HOST` | `localhost` | Redis host. |
| `REDIS_PORT` | `6379` | Redis port. |

### Collector (CLI)

You can run the same collector logic from the command line (uses the same Redis and feed config as the Admin panel):

```bash
cd backend
source venv/bin/activate
python msip_feed_collect.py
```

This loads feeds from Redis (`config:feeds`), or seeds default feeds if empty, then fetches all feed URLs, aggregates IPs, and writes them to Redis in the same format as the Admin “Run collector” action.

### Backend files (summary)

| File | Purpose |
|------|--------|
| `api.py` | Flask app: IP lookup, stats, activity, admin feeds + collect. |
| `collector.py` | Shared logic: Redis connection, feed config, fetch feeds, write `ip:*` hashes. |
| `msip_feed_collect.py` | CLI entrypoint that calls `collector.run_collector()`. |
| `requirements.txt` | Python dependencies. |

---

## Frontend

- **Location:** `frountend/`
- **Stack:** Next.js 16, React 19, Tailwind CSS v4, Radix UI.

### Setup

```bash
cd frountend
npm install
cp .env.example .env
```

Edit `.env` if the Flask API is not at `http://127.0.0.1:5000` (see [Environment Variables](#environment-variables)).

### Scripts

| Script | Command | Description |
|--------|--------|-------------|
| **dev** | `npm run dev` | Start dev server (Webpack). Use this if Turbopack has module resolution issues. |
| **dev:turbo** | `npm run dev:turbo` | Start dev server with Turbopack. |
| **build** | `npm run build` | Production build. |
| **start** | `npm run start` | Run production server. |
| **lint** | `npm run lint` | Run ESLint. |

### Routes

| Path | Description |
|------|-------------|
| `/` | **Dashboard** — IP search, stats, top malicious IPs, activity feed. |
| `/admin` | **Admin** — Manage feeds, run collector, view last run status. |

---

## Redis Data Format

### IP hashes (malicious or clean)

- **Key:** `ip:<ip>` (e.g. `ip:108.62.62.39`)
- **Type:** Hash
- **Fields:**
  - `first_seen` — Unix timestamp (or ISO string for clean IPs set by the API).
  - `last_seen` — Unix timestamp (or ISO for API-set clean).
  - `score` — 0–100 threat score (malicious IPs).
  - `count` — Number of feeds that listed the IP.
  - `sources` — Comma-separated feed names (e.g. `Blocklist.de,FireHOL`).
  - `status` — Optional; `clean` for IPs marked clean by the API.

Example:

```
127.0.0.1:6379> HGETALL ip:108.62.62.39
1) "first_seen"
2) "1773118827"
3) "score"
4) "12"
5) "count"
6) "1"
6) "sources"
7) "Blocklist.de"
8) "last_seen"
9) "1773118827"
```

### Other keys

| Key | Type | Description |
|-----|------|-------------|
| `ip_scores` | Sorted set | IP → score; used for “top” malicious IPs. |
| `clean_ips` | Set | IPs marked clean. |
| `recent_activity` | List | Recent activity events (JSON strings). |
| `config:feeds` | Hash | Feed name → URL (used by Admin and CLI collector). |
| `config:collect_last` | Hash | Last collector run: `last_run`, `ips_count`, `duration_seconds`, `feed_count`. |

---

## API Reference

### Public (Dashboard)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Service info. |
| GET | `/ip/<ip>` | IP reputation lookup. Returns `malicious`, `score`, `sources`, etc., or clean. |
| GET | `/top` | Top 10 malicious IPs by score. |
| GET | `/stats` | Counts: `malicious_ips`, `clean_ips`, `total_tracked_ips`. |
| GET | `/activity` | Recent activity (last 20). |

### Admin

| Method | Path | Description |
|--------|------|-------------|
| GET | `/admin/feeds` | List feeds `{ "feeds": { "Name": "https://..." } }`. |
| POST | `/admin/feeds` | Add/update feed. Body: `{ "name": "FeedName", "url": "https://..." }`. |
| DELETE | `/admin/feeds/<name>` | Remove a feed. |
| POST | `/admin/collect` | Run collector: fetch all feeds, write IPs to Redis. Returns `ips_count`, `duration_seconds`, `feed_results`, `error`. |
| GET | `/admin/collect/status` | Last run info: `last_run`, `ips_count`, `duration_seconds`, `feed_count`. |

The Next.js app proxies these under `/api/*` (e.g. `/api/ip/1.2.3.4`, `/api/admin/feeds`, `/api/admin/collect`).

---

## Project Structure

```
ip-reader/
├── README.md                 # This file
├── backend/
│   ├── api.py                # Flask app + routes
│   ├── collector.py          # Feed config, fetch, store to Redis
│   ├── msip_feed_collect.py  # CLI collector
│   └── requirements.txt
└── frountend/
    ├── .env.example          # BACKEND_URL
    ├── app/
    │   ├── layout.tsx
    │   ├── page.tsx           # Dashboard
    │   ├── globals.css
    │   ├── admin/
    │   │   ├── layout.tsx
    │   │   └── page.tsx       # Admin panel
    │   └── api/               # Next.js API routes (proxy to Flask)
    │       ├── ip/[ip]/route.ts
    │       ├── stats/route.ts
    │       ├── top/route.ts
    │       ├── activity/route.ts
    │       └── admin/
    │           ├── feeds/route.ts
    │           ├── feeds/[name]/route.ts
    │           └── collect/route.ts, collect/status/route.ts
    ├── components/           # Dashboard & shared UI
    ├── lib/
    │   └── backend.ts        # BACKEND_URL, backendFetch()
    ├── package.json
    └── next.config.mjs
```

---

## Environment Variables

### Backend (`backend/`)

| Variable | Default | Description |
|----------|---------|-------------|
| `REDIS_HOST` | `localhost` | Redis host. |
| `REDIS_PORT` | `6379` | Redis port. |

### Frontend (`frountend/`)

| Variable | Default | Description |
|----------|---------|-------------|
| `BACKEND_URL` | `http://127.0.0.1:5000` | Flask API base URL (used by Next.js API routes only). |

Copy `frountend/.env.example` to `frountend/.env` and adjust if your API runs elsewhere.

---

## Troubleshooting

### "Can't resolve 'tailwindcss'" (Next.js dev)

Next.js 16 uses Turbopack by default; in some setups it resolves modules from the workspace root and can’t find `tailwindcss`. Use Webpack instead:

```bash
cd frountend
npm run dev
```

The default `dev` script is already set to `next dev --webpack`. If you prefer Turbopack, use `npm run dev:turbo` and ensure you run from inside `frountend`.

### Backend connection refused

- Ensure the Flask API is running: `cd backend && python api.py`.
- Ensure `BACKEND_URL` in `frountend/.env` matches (e.g. `http://127.0.0.1:5000`).

### Redis connection refused

- Start Redis: `redis-server`.
- If Redis is on another host/port, set `REDIS_HOST` and `REDIS_PORT` (backend) before starting the API.

### No threat data on the Dashboard

- Run the collector once: open **http://localhost:3000/admin** and click **Run collector**, or run `python msip_feed_collect.py` from `backend/`.
- Feeds are stored in Redis under `config:feeds`; the first run seeds default feeds if the key is empty.

---

## License

Use and modify as needed for your environment.
