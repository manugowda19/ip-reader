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
   - [Step 1: Install Redis](#step-1-install-redis)
   - [Step 2: Start Redis](#step-2-start-redis)
   - [Step 3: Install Backend Dependencies](#step-3-install-backend-dependencies)
   - [Step 4: Run the Collector (Initial Data Load)](#step-4-run-the-collector-initial-data-load)
   - [Step 5: Start the Backend API](#step-5-start-the-backend-api)
   - [Step 6: Install Frontend Dependencies](#step-6-install-frontend-dependencies)
   - [Step 7: Start the Frontend](#step-7-start-the-frontend)
7. [Usage Guide](#usage-guide)
   - [Dashboard (IP Lookup)](#dashboard-ip-lookup)
   - [Admin Panel](#admin-panel)
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
│   Threat Feeds      │                    │   Next.js Frontend      │
│  (Blocklist.de,     │                    │  ┌───────────────────┐  │
│   CINSscore,        │   ┌─────────┐     │  │ Dashboard (/)     │  │
│   FireHOL,          │──>│  Redis   │<────│  │ - IP Search       │  │
│   EmergingThreats,  │   │  (6379)  │     │  │ - Score + Sources │  │
│   Feodo,            │   └─────────┘     │  │ - WHOIS + Geo    │  │
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
2. IPs are parsed, deduplicated, and stored in **Redis** with scores based on how many sources report them
3. **Manual feeds** can be added via the Admin Panel's Bulk IP Importer
4. The **Flask API** serves lookup requests from Redis
5. The **Next.js Frontend** provides the user interface for searching IPs and managing feeds
6. For each IP lookup, **geolocation** (ip-api.com) and **WHOIS** (rdap.org) data is fetched in real-time

---

## How It Works

### Anomaly Scoring
When an IP address appears in multiple threat feeds, its anomaly score increases. The score is calculated as:

```
score = (number_of_sources / total_feeds) * 100
```

- An IP found in 1 out of 8 feeds = score 12
- An IP found in 3 out of 8 feeds = score 37
- An IP found in 5 out of 8 feeds = score 62
- Score is clamped between 0 and 100

The more sources that report an IP as malicious, the higher its threat score.

### Two Types of Feeds
1. **Link Feeds** — URL-based feeds that are fetched automatically by the collector (e.g., Blocklist.de, FireHOL)
2. **Manual Feeds** — IPs added manually via the Admin Panel's Bulk IP Importer, where you paste text/URLs containing IPs, name the source, and classify as malicious or clean

Both feed types are merged during sync, and scores are recalculated using the combined total.

---

## Tech Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| Database | Redis | In-memory IP storage with O(1) lookup |
| Backend API | Python + Flask | REST API for IP lookup, feed management, collector |
| Frontend | Next.js 16 + React 19 | Dashboard and Admin UI |
| UI Components | shadcn/ui + Tailwind CSS | Component library and styling |
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
ip/
├── README.md                          # This file
├── docker-compose.yml                 # Optional: Redis via Docker
│
├── backend/                           # Flask API + Collector
│   ├── api.py                         # Main Flask server (all API endpoints)
│   ├── collector.py                   # Feed fetcher + Redis storage logic
│   └── requirements.txt               # Python dependencies
│
├── frontend/frountend/               # Next.js Frontend
│   ├── package.json                   # Node dependencies
│   ├── app/
│   │   ├── page.tsx                   # Dashboard (IP search + results)
│   │   ├── admin/page.tsx             # Admin panel
│   │   └── api/                       # Next.js API routes (proxy to Flask)
│   │       ├── ip/[ip]/route.ts       # IP lookup proxy
│   │       ├── whois/[ip]/route.ts    # WHOIS/geo proxy
│   │       ├── stats/route.ts         # Stats proxy
│   │       ├── top/route.ts           # Top IPs proxy
│   │       ├── activity/route.ts      # Activity feed proxy
│   │       └── admin/                 # Admin API proxies
│   │           ├── feeds/route.ts     # Link feeds CRUD
│   │           ├── bulk/route.ts      # Bulk IP extract
│   │           ├── bulk/submit/route.ts  # Bulk IP submit
│   │           ├── collect/route.ts   # Run collector
│   │           └── manual_feeds/route.ts # Manual feeds list
│   ├── components/                    # React components
│   │   ├── ip-search.tsx              # IP search input
│   │   ├── ip-result-panel.tsx        # Results + WHOIS + Geo + Map
│   │   ├── stats-panel.tsx            # Stats cards
│   │   ├── malicious-ips-table.tsx    # Top 10 malicious IPs
│   │   ├── activity-feed.tsx          # Recent activity log
│   │   └── dashboard-header.tsx       # Navigation header
│   └── lib/
│      └── backend.ts                 # Helper to proxy requests to Flask
|-- 
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

### Step 3: Install Backend Dependencies

Open a **new terminal**:

```bash
cd backend
pip install -r requirements.txt
```

This installs:
- `flask` — Web framework for the API
- `redis` — Python Redis client
- `requests` — HTTP client for fetching threat feeds

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
cd frontend/frountend
npm install
```

### Step 7: Start the Frontend

```bash
cd frontend/frountend
npm run dev
```

The frontend starts on `http://localhost:3000`.

**Open in browser:**
- **Dashboard:** http://localhost:3000
- **Admin Panel:** http://localhost:3000/admin

---

## Usage Guide

### Dashboard (IP Lookup)

**URL:** `http://localhost:3000`

1. Enter an IP address in the search bar (e.g., `94.26.106.201`)
2. Click **"Check IP"**
3. The results show:
   - **Threat Score** — 0-100 anomaly score with color-coded risk level
   - **Verdict** — Malicious / Suspicious / Clean
   - **Sources** — Which threat feeds reported this IP
   - **IP Details** — Full WHOIS and geolocation data:
     - Organization name, Network name, Handle
     - IP range (CIDR), Registration date
     - Abuse contact email and phone
     - ISP, ASN, Reverse DNS
     - City, Region, Country, Coordinates, Timezone
     - Flags: Mobile, Proxy/VPN, Hosting/Datacenter
   - **IP Location Map** — Google Maps pinpointing the IP's location

### Admin Panel

**URL:** `http://localhost:3000/admin`

The admin panel provides:

#### Stats Overview
- Total tracked IPs, Malicious count, Clean count
- Auto-refreshes every 10 seconds

#### Sync Feeds to Redis
- Click **"Run collector"** to fetch all link feeds + merge manual feeds
- Shows per-feed IP counts and any errors
- Recalculates all anomaly scores

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

1. **O(1) lookup** — `HGETALL ip:1.2.3.4` is instant, which is the only access pattern the web app needs
2. **Multiple fields per key** — Score, sources, timestamps stored atomically without serialization
3. **Memory efficient** — Redis optimizes small hashes with ziplist encoding
4. **Independent field access** — Can read just the score without fetching all fields

### Key Schema

```
Key:    ip:<ip_address>         (e.g., ip:94.26.106.201)
Type:   Hash
Fields:
  score        : int (0-100)     — Anomaly score
  count        : int             — Number of feeds reporting this IP
  sources      : string          — Comma-separated feed names
  first_seen   : unix timestamp  — When IP was first added
  last_seen    : unix timestamp  — Last update time
  status       : "clean"         — Only set for clean IPs
```

### Additional Redis Structures

| Key | Type | Purpose |
|-----|------|---------|
| `ip_scores` | Sorted Set | IPs ranked by score (for top malicious IPs) |
| `clean_ips` | Set | IPs marked as clean |
| `config:feeds` | Hash | Link feed name → URL mapping |
| `config:manual_feeds` | Hash | Manual feed name → metadata (JSON) |
| `config:collect_last` | Hash | Last collector run metadata |
| `recent_activity` | List | Last 50 activity events (JSON) |

### TTL
All IP keys have a **7-day TTL** (604,800 seconds). IPs that drop off all feeds are automatically cleaned up.

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

### Example API Calls

**Look up an IP:**
```bash
curl http://localhost:5000/ip/8.8.8.8
```

**Get WHOIS + geolocation:**
```bash
curl http://localhost:5000/whois/8.8.8.8
```

**Run the collector:**
```bash
curl -X POST http://localhost:5000/admin/collect
```

---

## Scoring Algorithm

```python
score = min(100, int((source_count / total_feeds) * 100))
```

Where:
- `source_count` = number of feeds that report this IP
- `total_feeds` = total number of successfully fetched feeds (link + manual)

| Sources Found | Total Feeds | Score | Risk Level |
|---------------|-------------|-------|------------|
| 1 | 8 | 12 | Low |
| 2 | 8 | 25 | Low |
| 3 | 8 | 37 | Suspicious |
| 4 | 8 | 50 | Suspicious |
| 5 | 8 | 62 | Suspicious |
| 6 | 8 | 75 | Malicious |
| 8 | 8 | 100 | Malicious |

**Risk levels in the UI:**
- **0** — Clean (green)
- **1-39** — Suspicious (yellow/orange)
- **40-69** — Suspicious (orange)
- **70-100** — Malicious (red)

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
| ThreatView | https://threatview.io/Downloads/IP-High-Confidence-Feed.txt | High confidence threat IPs |

Additional feeds can be added via the Admin Panel.

---

## Troubleshooting

### Redis won't start on Windows
```bash
# Bind to localhost explicitly
redis-server --bind 127.0.0.1 --port 6379
```

### Port 5000 already in use
```bash
# Windows: find and kill the process
netstat -ano | findstr 5000
taskkill /F /PID <pid>

# macOS/Linux
lsof -i :5000
kill -9 <pid>
```

### Frontend `npm run dev` fails with env variable error
If you see `'NEXT_TELEMETRY_DISABLED' is not recognized`, the fix is already applied. The `package.json` scripts should not have `NEXT_TELEMETRY_DISABLED=1` prefix on Windows. They should read:
```json
"dev": "next dev --webpack"
```

### `hset` mapping error (old Redis versions)
If Redis throws `wrong number of arguments for 'hset' command`, your Redis version doesn't support `HSET key field1 val1 field2 val2`. The codebase already handles this by using individual `hset` calls per field.

### WHOIS data not showing on dashboard
Ensure the Flask backend is running and the Next.js API route at `app/api/whois/[ip]/route.ts` exists. Test directly:
```bash
curl http://localhost:5000/whois/8.8.8.8
```

### Collector fetches 0 IPs from some feeds
Some feeds may be temporarily down or rate-limited. This is normal. The collector continues with available feeds and logs errors for failed ones.

### Frontend can't connect to backend
The Next.js frontend proxies API calls to Flask via route handlers. Ensure:
1. Flask is running on `http://127.0.0.1:5000`
2. The `BACKEND_URL` environment variable is not set to a different address (default is `http://127.0.0.1:5000`)

---

## Quick Start (TL;DR)

```bash
# Terminal 1: Start Redis
redis-server --bind 127.0.0.1 --port 6379

# Terminal 2: Start Backend
cd backend
pip install -r requirements.txt
python -c "from collector import run_collector; print(run_collector())"  # Initial load
python api.py

# Terminal 3: Start Frontend
cd frontend/frountend
npm install
npm run dev

# Open browser
# Dashboard: http://localhost:3000
# Admin:     http://localhost:3000/admin
```