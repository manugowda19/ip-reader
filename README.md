# IP Threat Intelligence Platform

A full-stack IP threat intelligence system that collects malicious IP addresses from multiple MISP-listed threat feeds, stores them in Redis with anomaly scores, and provides a web dashboard to check IP reputation, geolocation, and WHOIS details.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [How It Works](#how-it-works)
3. [Tech Stack](#tech-stack)
4. [Prerequisites](#prerequisites)
5. [Project Structure](#project-structure)
6. [Setup & Installation](#setup--installation)
7. [Usage Guide](#usage-guide)
8. [Redis Data Structure](#redis-data-structure)
9. [API Endpoints](#api-endpoints)
10. [Scoring Algorithm](#scoring-algorithm)
11. [Threat Feed Sources](#threat-feed-sources)
12. [Troubleshooting](#troubleshooting)

---

## Architecture Overview

The system is split into two main phases:

```
Phase 1: Data Collection                    Phase 2: Web Application
┌─────────────────────┐                    ┌─────────────────────────┐
│   Threat Feeds      │                    │   React Frontend (Vite) │
│  (Blocklist.de,     │                    │  ┌───────────────────┐  │
│   CINSscore,        │   ┌─────────┐     │  │ Dashboard (/)     │  │
│   FireHOL,          │──>│  Redis   │<────│  │ - IP Search       │  │
│   EmergingThreats,  │   │  (6379)  │     │  │ - Score + Sources │  │
│   Feodo,            │   └─────────┘     │  │ - WHOIS + Geo     │  │
│   Greensnow,        │        ^           │  │ - Google Maps     │  │
│   ThreatView)       │        │           │  ├───────────────────┤  │
└─────────────────────┘        │           │  │ Admin (/admin)    │  │
                               │           │  │ - Stats Overview  │  │
┌─────────────────────┐        │           │  │ - Bulk IP Import  │  │
│   Manual Feeds      │────────┘           │  │ - Feed Management │  │
│  (Bulk IP Import    │                    │  │ - Top Malicious   │  │
│   via Admin Panel)  │                    │  │ - Activity Feed   │  │
└─────────────────────┘                    │  └───────────────────┘  │
                                           │          │              │
                                           │          v              │
                                           │  ┌───────────────────┐  │
                                           │  │ Flask Backend     │  │
                                           │  │ (Port 5000)       │  │
                                           │  └───────────────────┘  │
                                           └─────────────────────────┘
```

**Data Flow:**
1. The **Collector** fetches IP blocklists from multiple threat intelligence URLs
2. IPs are parsed, deduplicated, and stored in **Redis** with scores based on a 3-component weighted formula
3. **Manual feeds** can be added via the Admin Panel's Bulk IP Importer
4. The **Flask API** serves lookup requests from Redis
5. The **React Frontend** (via Vite dev server proxy) provides the user interface for searching IPs and managing feeds
6. For each IP lookup, **geolocation** (ip-api.com) and **WHOIS** (rdap.org) data is fetched in real-time

---

## How It Works

### Anomaly Scoring

When an IP address appears in multiple threat feeds, its anomaly score increases. The score is calculated using a **3-component weighted formula** designed to be stable, fair, and historically aware:

```
Final Score = (40% × Peak Score) + (40% × Current Score) + (20% × Time Decay)
```

#### Why 3 Components?

A threat has 3 independent dimensions of truth that no single formula can capture alone:

| Component | Weight | What It Measures | Why It's Needed |
|-----------|--------|-----------------|-----------------|
| **Peak Score** | 40% | Highest count this IP ever reached across all feeds | Ensures score never crashes just because a feed went offline or new feeds were added |
| **Current Score** | 40% | How many sources are reporting this IP right now | Captures active, ongoing threat activity |
| **Time Decay** | 20% | How recently was this IP last seen | Reduces urgency for old threats without erasing history |

#### Score Behaviour Across Scenarios

| Scenario | Old Formula | New Formula |
|----------|-------------|-------------|
| IP found in more sources | Goes UP | Goes UP |
| New feeds added, IP not in them | Score DROPS | Stays stable |
| One feed goes offline | Score DROPS | Barely moves (peak protects) |
| IP not seen for 30+ days | Stays forever | Slowly decays to near 0 |
| IP reappears after silence | Goes UP | Goes UP |

#### Risk Levels in the UI

| Score | Verdict | Colour |
|-------|---------|--------|
| 0 | Clean | Green |
| 1–39 | Low Risk | Yellow |
| 40–69 | Suspicious | Orange |
| 70–100 | Malicious | Red |

### Two Types of Feeds

1. **Link Feeds** — URL-based feeds fetched automatically by the collector (e.g., Blocklist.de, FireHOL)
2. **Manual Feeds** — IPs added manually via the Admin Panel's Bulk IP Importer, where you paste text/URLs containing IPs, name the source, and classify as malicious or clean

Both feed types are merged during sync, and scores are recalculated using the combined total.

---

## Tech Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| Database | Redis | In-memory IP storage with O(1) lookup |
| Backend API | Python + Flask | REST API for IP lookup, feed management, collector |
| Frontend | React 19 + Vite | Dashboard and Admin UI (SPA) |
| Routing | React Router DOM | Client-side page routing |
| UI Components | shadcn/ui + Tailwind CSS 4 | Component library and styling |
| Geolocation | ip-api.com (free) | IP location data (no API key needed) |
| WHOIS | rdap.org (free) | IP ownership and registry data (no API key needed) |
| Maps | Google Maps Embed | Visual IP location pinpointing |

---

## Prerequisites

Before setting up, ensure you have the following installed:

| Software | Version | Download |
|----------|---------|----------|
| **Python** | 3.11+ | https://www.python.org/downloads/ |
| **Node.js** | 18+ | https://nodejs.org/ |
| **Redis** | 5+ | See installation instructions below |
| **pip** | Latest | Comes with Python |
| **npm** | Latest | Comes with Node.js |

### Verify installations:
```bash
python --version    # Should show 3.11+
node --version      # Should show 18+
npm --version       # Should show 9+
redis-server --version  # Should show 5+
```

---

## Project Structure

```
ip-reader/
├── README.md                          # Project documentation
├── docker-compose.yml                 # Optional: Redis via Docker
├── dump.rdb                           # Redis data snapshot
├── .gitignore
│
├── backend/                           # Python Backend
│   ├── api.py                         # Flask REST API (all endpoints)
│   ├── collector.py                   # Feed fetcher + Redis storage + scoring
│   ├── requirements.txt               # Python dependencies
│   └── package-lock.json
│
└── frountend/                         # Next.js + React Frontend
    ├── index.html                     # App entry point
    ├── package.json                   # Node dependencies
    ├── package-lock.json
    ├── pnpm-lock.yaml
    ├── tsconfig.json                  # TypeScript config
    ├── vite.config.ts                 # Vite bundler config
    ├── vite-env.d.ts
    ├── postcss.config.mjs
    ├── components.json                # shadcn/ui config
    ├── .env.example                   # Environment variables template
    │
    ├── app/
    │   └── globals.css                # Global styles
    │
    ├── src/
    │   ├── main.tsx                   # React entry point
    │   ├── pages/
    │   │   ├── Dashboard.tsx          # IP search + results page
    │   │   └── Admin.tsx              # Admin panel page
    │   └── layouts/
    │       └── AdminLayout.tsx        # Admin page layout wrapper
    │
    ├── components/
    │   ├── ip-search.tsx              # IP search input component
    │   ├── ip-result-panel.tsx        # Score + sources + WHOIS + map
    │   ├── stats-panel.tsx            # Stats cards (total, malicious, clean)
    │   ├── malicious-ips-table.tsx    # Top 10 malicious IPs table
    │   ├── activity-feed.tsx          # Recent lookup activity log
    │   ├── dashboard-header.tsx       # Navigation header
    │   ├── theme-provider.tsx         # Dark/light theme provider
    │   └── ui/                        # shadcn/ui component library
    │       ├── button.tsx
    │       ├── card.tsx
    │       ├── table.tsx
    │       ├── badge.tsx
    │       ├── input.tsx
    │       ├── dialog.tsx
    │       ├── tabs.tsx
    │       └── ...and more
    │
    ├── lib/
    │   ├── backend.ts                 # Flask API proxy helper
    │   └── utils.ts                   # Shared utilities
    │
    ├── hooks/
    │   ├── use-mobile.ts              # Mobile detection hook
    │   └── use-toast.ts               # Toast notification hook
    │
    └── styles/
        └── globals.css                # Additional global styles
```

---

## Setup & Installation

### Step 1: Install Redis

**Windows (via winget):**
```bash
winget install Redis.Redis
```

**Windows (via Memurai — Redis-compatible):**
```bash
winget install Memurai.MemuraiDeveloper
```

**macOS (via Homebrew):**
```bash
brew install redis
```

**Linux (Ubuntu/Debian):**
```bash
sudo apt update
sudo apt install redis-server
```

**Docker (optional):**
```bash
docker compose up -d
```

### Step 2: Start Redis

**Windows:**
```bash
redis-server --bind 127.0.0.1 --port 6379
```

**macOS/Linux:**
```bash
redis-server
```

Keep this terminal open. Redis must be running for the application to work.

**Verify Redis is running:**
```bash
redis-cli ping
# Should return: PONG
```
```bash

Total IPs in database

DBSIZE

bash# Top 10 HIGHEST scoring IPs (most dangerous)
ZREVRANGE ip_scores 0 9 WITHSCORES

bash# Bottom 10 LOWEST scoring IPs (least dangerous)
ZRANGE ip_scores 0 9 WITHSCORES

bash# IPs with score between 70-100 (Malicious)
ZRANGEBYSCORE ip_scores 70 100 WITHSCORES

bash# IPs with score between 40-69 (Suspicious)
ZRANGEBYSCORE ip_scores 40 69 WITHSCORES

bash# IPs with score between 1-39 (Low Risk)
ZRANGEBYSCORE ip_scores 1 39 WITHSCORES

bash# Count of each category
ZCOUNT ip_scores 70 100
ZCOUNT ip_scores 40 69
ZCOUNT ip_scores 1 39

bash# Full details of a specific IP
HGETALL ip:185.220.101.5
```


### Step 3: Install Backend Dependencies

Open a **new terminal**:

```bash
cd backend
pip install -r requirements.txt
```

This installs:
- `flask` + `flask-cors` — Web framework and CORS support
- `redis` — Python Redis client
- `schedule` — Task scheduling for periodic collection
- `python-dotenv` — Environment variable management

### Step 4: Run the Collector (Initial Data Load)

This fetches IPs from all configured threat feeds and loads them into Redis:

```bash
cd backend
python -c "from collector import run_collector; result = run_collector(); print(result)"
```

Expected output:
```
{'ips_count': 51472, 'duration_seconds': 11.45, 'feed_results': [...], 'error': None}
```

This typically loads 40,000–60,000 IPs from 7-8 threat feeds. You can also run the collector from the Admin Panel UI later.

### Step 5: Start the Backend API

```bash
cd backend
python api.py
```

The API starts on `http://localhost:5000`. Keep this terminal open.

**Verify the API is running:**
```bash
curl http://localhost:5000/stats
# Should return: {"clean_ips":0,"malicious_ips":51472,"total_tracked_ips":51472}
```

### Step 6: Install Frontend Dependencies

Open a **new terminal**:

```bash
cd frontend2/frountend
npm install
```

### Step 7: Start the Frontend

```bash
cd frontend2/frountend
npm run dev
```

The frontend starts on `http://localhost:5173` (Vite default).

**Open in browser:**
- **Dashboard:** http://localhost:5173
- **Admin Panel:** http://localhost:5173/admin

The Vite dev server proxies all `/api` requests to the Flask backend on port 5000.

---

## Usage Guide

### Dashboard (IP Lookup)

**URL:** `http://localhost:5173`

1. Enter an IP address in the search bar (e.g., `94.26.106.201`)
2. Click **"Check IP"**
3. The results show:
   - **Threat Score** — 0-100 anomaly score with colour-coded risk level
   - **Verdict** — Malicious / Suspicious / Low Risk / Clean
   - **Sources** — Which threat feeds reported this IP
   - **IP Details** — Full WHOIS and geolocation data:
     - Organisation name, Network name, Handle
     - IP range (CIDR), Registration date
     - Abuse contact email and phone
     - ISP, ASN, Reverse DNS
     - City, Region, Country, Coordinates, Timezone
     - Flags: Mobile, Proxy/VPN, Hosting/Datacenter
   - **IP Location Map** — Google Maps pinpointing the IP's location

### Admin Panel

**URL:** `http://localhost:5173/admin`

The admin panel provides:

#### Stats Overview
- Total tracked IPs, Malicious count, Clean count
- Auto-refreshes every 10 seconds

#### Sync Feeds to Redis
- Click **"Run collector"** to fetch all link feeds + merge manual feeds
- Shows per-feed IP counts and any errors
- Recalculates all anomaly scores using the 3-component formula

#### Bulk IP Importer (Two-Step Process)
1. **Step 1 — Extract:** Paste any text containing IPs (URLs, logs, raw IPs) and click "Extract IPs"
   - Example input:
     ```
     https://malware-c2.example.com/callback?src=192.168.1.100
     45.33.32.156 - suspicious scan detected
     103.224.182.250
     ```
   - The system extracts all unique IPs from the text
2. **Step 2 — Label & Submit:** Enter a source name (e.g., "Phishing Campaign"), select Malicious or Clean, then submit to Redis

#### Feed Management (Two Tables)
- **Link Feeds** — URL-based feeds with clickable links. Add/remove feeds. These are fetched by the collector.
- **Manual Feeds** — Shows feeds added via Bulk IP Importer with source name, label (malicious/clean), IP count, and date added. Can be deleted (removes the source from all IPs and recalculates scores).

#### Top 10 Malicious IPs
- Table showing IPs with the highest threat scores

#### Recent Activity
- Live feed of recent IP lookups (malicious and clean)

---

## Redis Data Structure

### Why Redis Hash?

We chose Redis **Hash** as the primary data structure for storing IP threat data:

1. **O(1) lookup** — `HGETALL ip:1.2.3.4` is instant regardless of how many millions of IPs are stored
2. **Multiple fields per key** — Score, peak, sources, and timestamps all stored under one key atomically
3. **Memory efficient** — Redis optimizes small hashes with ziplist encoding
4. **Independent field access** — Can read just the score without fetching all fields
5. **Partial updates** — Can update only `last_seen` without rewriting the entire record

### Key Schema

```
Key:    ip:<ip_address>           (e.g., ip:94.26.106.201)
Type:   Hash
Fields:
  score        : int (0-100)       — Final weighted anomaly score
  count        : int               — Current number of feeds reporting this IP
  peak_count   : int               — Highest count this IP has ever reached (never decreases)
  sources      : string            — Comma-separated feed names
  first_seen   : unix timestamp    — When IP was first added to the system
  last_seen    : unix timestamp    — Last time this IP was seen in any feed
  status       : "clean"           — Only set for IPs marked clean via Admin Panel
```

### Additional Redis Structures

| Key | Type | Purpose |
|-----|------|---------|
| `ip_scores` | Sorted Set | IPs ranked by score — enables instant Top 10 queries |
| `clean_ips` | Set | IPs marked as clean via Admin Panel |
| `config:feeds` | Hash | Link feed name → URL mapping |
| `config:manual_feeds` | Hash | Manual feed name → metadata (JSON) |
| `config:collect_last` | Hash | Last collector run metadata |
| `recent_activity` | List | Last 50 activity events (JSON) |

### TTL
All IP keys have a **7-day TTL** (604,800 seconds). Combined with the time decay
component in the scoring formula, IPs that disappear from all feeds will gradually
score lower AND eventually be auto-deleted from Redis.

---

## API Endpoints

### Core Endpoints (Flask — Port 5000)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Health check |
| GET | `/ip/<ip>` | IP reputation lookup |
| GET | `/whois/<ip>` | Geolocation + WHOIS data |
| GET | `/top` | Top 10 malicious IPs |
| GET | `/stats` | Database statistics |
| GET | `/activity` | Recent activity feed |

### Admin Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/admin/feeds` | List all link feeds |
| POST | `/admin/feeds` | Add a link feed `{name, url}` |
| DELETE | `/admin/feeds/<name>` | Remove a link feed |
| POST | `/admin/collect` | Run the collector |
| GET | `/admin/collect/status` | Last collector run info |
| POST | `/admin/bulk/extract` | Extract IPs from text |
| POST | `/admin/bulk/submit` | Submit extracted IPs `{ips, source, label}` |
| GET | `/admin/manual_feeds` | List manual feeds |
| DELETE | `/admin/manual_feeds/<name>` | Remove a manual feed + its IPs |

### Example Responses

**GET /ip/185.220.101.5**
```json
{
  "ip": "185.220.101.5",
  "found": true,
  "score": 72,
  "count": 3,
  "peak_count": 3,
  "sources": ["Blocklist.de", "FireHOL", "CINSscore"],
  "verdict": "Malicious",
  "first_seen": 1709123456,
  "last_seen": 1709123456
}
```

**GET /ip/8.8.8.8**
```json
{
  "ip": "8.8.8.8",
  "found": false,
  "score": 0,
  "verdict": "Clean",
  "message": "This IP was not found in any threat feed."
}
```

---

## Scoring Algorithm

### Formula

```
Final Score = (0.40 × Peak Score) + (0.40 × Current Score) + (0.20 × Decay Score)
```

### Component Breakdown

**Peak Score (40%)**
```python
peak_score = min(100, round(20 * math.log2(peak_count + 1)))
```
Uses logarithmic scale so each additional source has diminishing impact.
Based on `peak_count` which never decreases — protects against feed instability.

**Current Score (40%)**
```python
absolute = min(100, round(20 * math.log2(source_count + 1)))
relative = min(100, round((source_count / total_feeds) * 100))
current_score = round((0.5 * absolute) + (0.5 * relative))
```
Combines absolute count (log scale) with relative spread (ratio) equally.

**Time Decay (20%)**
```python
days_since = (now - last_seen_timestamp) / 86400
decay_score = max(0, round(100 * (1 - (days_since / 30))))
```
Linearly decays from 100 to 0 over 30 days of silence.

### Score Reference Table

| Peak | Current | Days Ago | Score | Verdict |
|------|---------|----------|-------|---------|
| 1 | 1 | 0 | ~36 | Low Risk |
| 2 | 2 | 0 | ~50 | Suspicious |
| 3 | 3 | 0 | ~57 | Suspicious |
| 5 | 5 | 0 | ~70 | Malicious |
| 8 | 8 | 0 | ~82 | Malicious |
| 8 | 8 | 15 | ~72 | Malicious |
| 8 | 0 | 30 | ~32 | Low Risk |

---

## Threat Feed Sources

Default link feeds configured:

| Feed | URL | Description |
|------|-----|-------------|
| Blocklist.de | https://lists.blocklist.de/lists/all.txt | Servers attacking Blocklist.de honeypots |
| CINSscore | https://cinsscore.com/list/ci-badguys.txt | Collective Intelligence Network Security |
| FireHOL | https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset | FireHOL Level 1 blocklist |
| EmergingThreats | https://rules.emergingthreats.net/blockrules/compromised-ips.txt | Proofpoint Emerging Threats |
| Feodo | https://feodotracker.abuse.ch/downloads/ipblocklist.txt | Feodo Tracker (banking trojans) |
| Greensnow | https://blocklist.greensnow.co/greensnow.txt | GreenSnow blocklist |
| MalSilo | https://malsilo.gitlab.io/feeds/dumps/ip_list.txt | MalSilo IPv4 threat list |
| ThreatView | https://threatview.io/Downloads/IP-High-Confidence-Feed.txt | High confidence threat IPs |

Additional feeds can be added at any time via the Admin Panel without restarting the system.

---

## Troubleshooting

### Redis won't start on Windows
```bash
redis-server --bind 127.0.0.1 --port 6379
```

### Port 5000 already in use
```bash
# macOS/Linux
lsof -i :5000
kill -9 <pid>

# Windows
netstat -ano | findstr 5000
taskkill /F /PID <pid>
```

### `hset` mapping error (old Redis versions)
If Redis throws `wrong number of arguments for 'hset' command`, your Redis version
does not support multi-field HSET. Use individual `hset` calls per field instead.

### WHOIS data not showing on dashboard
Ensure Flask is running and test directly:
```bash
curl http://localhost:5000/whois/8.8.8.8
```

### Collector fetches 0 IPs from some feeds
Some feeds may be temporarily down or rate-limited. The collector continues with
available feeds and logs errors for failed ones. This is expected behaviour.

### Frontend can't connect to backend
Ensure Flask is running on `http://127.0.0.1:5000`. The Vite dev server proxies
all `/api` requests to Flask via the proxy config in `vite.config.ts`.

---

## Quick Start (TL;DR)

```bash
# Terminal 1: Start Redis
redis-server --bind 127.0.0.1 --port 6379

# Terminal 2: Start Backend + Run Collector
cd backend
pip install -r requirements.txt
python -c "from collector import run_collector; print(run_collector())"
python api.py

# Terminal 3: Start Frontend
cd frontend2/frountend
npm install
npm run dev

# Open browser
# Dashboard: http://localhost:5173
# Admin:     http://localhost:5173/admin
```
