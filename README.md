# PhishGuard

**ML-powered phishing URL detection with real-time CTI enrichment, FastAPI backend, SOC dashboard, and Chrome extension.**

PhishGuard is a full-stack security tool built for SOC analysts. It combines a 30-feature URL classifier (XGBoost + RandomForest ensemble) with live threat intelligence enrichment from VirusTotal, URLhaus, and WHOIS to produce a weighted risk score for any URL — in under a second.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         PhishGuard                              │
│                                                                 │
│  Chrome Extension  ──►  FastAPI Backend  ──►  SQLite / PgSQL   │
│  React Dashboard   ──►  /api/scan        ──►  scan_orchestrator │
│                              │                      │           │
│                    ┌─────────┴──────┐    ┌──────────┴────────┐ │
│                    │  ML Service    │    │   CTI Service     │ │
│                    │  XGBoost + RF  │    │  VT / URLhaus /   │ │
│                    │  30 features   │    │  WHOIS adapters   │ │
│                    └────────────────┘    └───────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

**Weighted risk score:**  `score = 0.40·ML + 0.30·VT + 0.20·URLhaus + 0.10·WHOIS`

| Score | Level |
|---|---|
| < 0.30 | Safe |
| 0.30 – 0.65 | Suspicious |
| ≥ 0.65 | Malicious |

---

## Repository Layout

```
phishguard/
├── backend/            FastAPI service
│   └── app/
│       ├── main.py
│       ├── config.py
│       ├── db/         SQLAlchemy engine + ORM models
│       ├── models/     Pydantic schemas
│       ├── routers/    scan, history, export, health
│       └── services/   scan_orchestrator, ml_service, cti_service,
│                       feature_service, db_service
├── ml/
│   ├── features/       extractor.py (30 features), obfuscation.py,
│   │                   typosquatting.py
│   ├── models/         trainer.py, evaluator.py, artifacts/
│   ├── data/           raw/, processed/metrics.json
│   └── train.py        training pipeline entry point
├── cti/
│   ├── base.py         BaseCTIAdapter + CTIResponse
│   ├── virustotal.py   VirusTotal v3 adapter
│   ├── urlhaus.py      abuse.ch URLhaus adapter
│   ├── whois_lookup.py python-whois adapter
│   ├── mock_adapters.py dev/test mock layer
│   └── risk_scorer.py  weighted aggregation
├── frontend/           React 18 + Vite + Tailwind SOC dashboard
│   └── src/
│       ├── pages/      Dashboard, HistoryPage, ReportPage
│       ├── components/ ScanForm, RiskBadge, ThreatDetails,
│       │               ScanHistory, RiskDistChart, ExportButton
│       ├── hooks/      useScan, useHistory
│       └── api/        axios client
├── extension/          Chrome MV3 extension
│   └── src/
│       ├── background.ts  webNavigation listener + badge
│       ├── popup.tsx      React popup UI
│       ├── content.ts     in-page malicious banner
│       └── api.ts         fetch wrapper with 60s cache
├── tests/              pytest suite (78 tests)
├── shared/             Python constants + dataclass types
├── .env.example
├── docker-compose.yml
├── pytest.ini
└── REPORT.md
```

---

## Quick Start

### Prerequisites

| Tool | Version |
|---|---|
| Python | 3.11+ |
| Node.js | 20+ |
| libomp | (macOS — `brew install libomp`) |

---

### 1. Create virtual environment and install dependencies

```bash
cd phishguard
python3.11 -m venv .venv
.venv/bin/pip install -r backend/requirements.txt -r ml/requirements.txt
```

---

### 2. Train the ML model

```bash
.venv/bin/python3 ml/train.py
```

This generates `ml/models/artifacts/phishguard_model.joblib` and prints evaluation metrics.
To use your own labeled URL dataset, place a CSV at `ml/data/raw/labeled_urls.csv` with columns `url,label` (1 = phishing, 0 = legitimate) before training.

---

### 3. Configure environment

```bash
cp .env.example .env
```

Key settings in `.env`:

| Variable | Default | Notes |
|---|---|---|
| `DATABASE_URL` | `sqlite+aiosqlite:///./phishguard.db` | Swap to `postgresql+asyncpg://...` for production |
| `CTI_MOCK` | `true` | Set to `false` + add `VIRUSTOTAL_API_KEY` for live enrichment |
| `VIRUSTOTAL_API_KEY` | _(empty)_ | Free tier: 4 req/min |
| `ML_MODEL_PATH` | `ml/models/artifacts/phishguard_model.joblib` | Path to trained model |
| `CORS_ORIGINS` | `["http://localhost:5173","http://localhost:3000"]` | JSON array |

---

### 4. Start the backend

```bash
PYTHONPATH=$(pwd) .venv/bin/uvicorn app.main:app --app-dir backend/ --host 0.0.0.0 --port 8000
```

Interactive API docs: **http://localhost:8000/docs**

---

### 5. Start the dashboard

```bash
cd frontend
npm install
npm run dev
```

Dashboard: **http://localhost:5173**

The Vite dev server proxies `/api/*` → `http://localhost:8000` automatically.

---

### 6. Build and load the Chrome extension

```bash
cd extension
npm install
npm run build
```

1. Open Chrome → `chrome://extensions`
2. Enable **Developer mode** (top-right toggle)
3. Click **Load unpacked** → select `extension/dist/`

The extension badge updates automatically on every page navigation:

| Badge | Meaning |
|---|---|
| `...` | Scanning |
| `OK` | Safe |
| `!!` | Suspicious |
| `BAD` | Malicious |

---

### Docker (full stack)

```bash
docker-compose up --build
```

---

## API Reference

### POST `/api/scan`

```json
{
  "url": "https://paypa1-secure-login.xyz/account/verify",
  "source": "dashboard"
}
```

Response:

```json
{
  "id": "c4a8e25c-...",
  "url": "https://paypa1-secure-login.xyz/account/verify",
  "score": 0.4151,
  "level": "suspicious",
  "ml_probability": 0.9858,
  "features": { "url_length": 47, "tld_risk": 1.0, "suspicious_keywords": 3, ... },
  "cti": {
    "virustotal": { "malicious_count": 5, "total_engines": 72 },
    "urlhaus": { "query_status": "no_results" },
    "whois": { "domain_age_days": 12 }
  },
  "indicators": [
    { "type": "ml_high_confidence", "severity": "high", "description": "ML classifier: 98.6% phishing probability", "source": "ml" },
    { "type": "high_risk_tld", "severity": "medium", "description": "URL uses a high-risk top-level domain", "source": "feature" }
  ],
  "explanation": ["ML classifier: 98.6% phishing probability", "VirusTotal: 5/72 engines flagged as malicious"],
  "scanned_at": "2026-05-18T06:18:57Z",
  "source": "dashboard"
}
```

### GET `/api/history?limit=50&offset=0`

Returns a paginated list of `ScanResult` objects (most recent first).

### GET `/api/export/csv` · `/api/export/json`

Downloads all scan records as CSV or JSON. Attach to a report or pipe into a SIEM.

### GET `/api/health`

```json
{ "status": "ok", "timestamp": "2026-05-18T06:32:33Z" }
```

---

## The 30 URL Features

The feature extractor (`ml/features/extractor.py`) computes these for every URL at inference time. The same features are used during training, ensuring no feature mismatch.

| # | Feature | Description |
|---|---|---|
| 1 | `url_length` | Total character count |
| 2 | `domain_length` | Length of registered domain |
| 3 | `subdomain_count` | Number of subdomains |
| 4 | `has_ip` | True if domain is a raw IP address |
| 5 | `uses_https` | True if scheme is HTTPS |
| 6 | `dot_count` | Dots in full URL |
| 7 | `hyphen_count` | Hyphens in domain |
| 8 | `at_sign_count` | @ characters (misdirection signal) |
| 9 | `special_char_count` | Sum of @, ?, %, +, = |
| 10 | `digit_ratio` | Fraction of domain chars that are digits |
| 11 | `entropy` | Shannon entropy of full URL |
| 12 | `suspicious_keywords` | Count of phishing keywords (login, verify, secure…) |
| 13 | `is_url_shortener` | Domain is a known URL shortener |
| 14 | `tld_risk` | 1.0 if TLD in high-risk set (.xyz, .tk, .ml…) |
| 15 | `path_depth` | Number of path segments |
| 16 | `query_param_count` | Number of query parameters |
| 17 | `has_encoded_chars` | % encoding present |
| 18 | `double_slash_in_path` | // in path (redirect trick) |
| 19 | `has_port` | Non-standard port specified |
| 20 | `is_punycode` | xn-- IDN homograph |
| 21 | `tilde_in_path` | ~ in path |
| 22 | `hex_in_domain` | 0x… hex encoding in domain |
| 23 | `redirect_double_slash` | Multiple // in URL |
| 24 | `domain_digit_count` | Raw digit count in domain |
| 25 | `url_shortener_flag` | Integer version of is_url_shortener |
| 26 | `brand_count` | Known brand names in domain (paypal, apple…) |
| 27 | `num_dots_in_path` | Dots in path segment |
| 28 | `query_length` | Raw length of query string |
| 29 | `fragment_present` | # fragment present |
| 30 | `multi_subdomain` | 1 if more than 3 domain parts |

---

## ML Model

**Ensemble:** Soft-voting classifier — XGBoost (300 estimators, depth 6) + RandomForest (200 estimators, depth 10) — wrapped in a `StandardScaler` pipeline.

**Training data:** Synthetic feature vectors calibrated to real phishing/legitimate URL distributions across all 30 features. To use a real URL dataset, supply `ml/data/raw/labeled_urls.csv` (columns: `url`, `label`).

| Metric | Score |
|---|---|
| Accuracy | 99.88% |
| Precision | 99.83% |
| Recall | 99.92% |
| F1 | 99.88% |
| ROC-AUC | 1.0000 |

---

## CTI Adapters

| Adapter | Source | API key needed? |
|---|---|---|
| `VirusTotalAdapter` | VirusTotal v3 | Yes (free tier available) |
| `URLhausAdapter` | abuse.ch URLhaus | No |
| `WHOISAdapter` | python-whois | No |
| `Mock*Adapter` | Deterministic dev stubs | No |

Set `CTI_MOCK=false` in `.env` and add `VIRUSTOTAL_API_KEY` for live enrichment. The adapter selection is automatic — no code changes needed.

---

## Switching to PostgreSQL

Change one line in `.env`:

```
DATABASE_URL=postgresql+asyncpg://user:password@localhost:5432/phishguard
```

The ORM layer is fully database-agnostic (SQLAlchemy 2.x, no raw SQL). No code changes required.

---

## Running Tests

```bash
# Backend — 78 tests
.venv/bin/pytest -v

# Frontend — 19 tests
cd frontend && npm run test -- --run
```

Test coverage:

| Suite | Tests | Scope |
|---|---|---|
| `test_feature_extractor.py` | 31 | All 30 features, vector shape, edge cases |
| `test_risk_scorer.py` | 16 | Weight math, thresholds, explanation bullets |
| `test_signals.py` | 20 | Obfuscation, URL decoding, Levenshtein, typosquatting |
| `test_api.py` | 13 | All endpoints (health, scan, history, export, 422 validation) |
| `RiskBadge.test.tsx` | 10 | All 4 risk levels, score display, Tailwind classes |
| `ScanHistory.test.tsx` | 9 | Loading/empty states, rows, badges, timestamps |

---

## Development Notes

- **Feature source of truth:** `ml/features/extractor.py:FEATURE_ORDER` — never change the order without retraining the model.
- **All DB access** routes through `backend/app/services/db_service.py`. No dialect-specific SQL anywhere.
- **Retrain** the model after changing `FEATURE_ORDER`: `python3 ml/train.py`
- **Extension cache** is 60 seconds per URL to avoid hammering the API on every sub-frame navigation.
- **CTI_MOCK=true** (default) — safe to develop and test without any API keys.

---

## License

MIT
