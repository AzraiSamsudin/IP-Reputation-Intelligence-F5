# IPRep — IP Reputation Lookup

Full-stack IP lookup app combining ip-api.com geolocation with F5 IpRep threat intelligence.

## Structure

```
iprep/
├── backend/
│   ├── app.py              # FastAPI server (async)
│   ├── requirements.txt
│   └── db/
│       └── .dat     # ← place your .dat file here
└── frontend/
    ├── src/
    │   ├── App.svelte
    │   └── lib/
    │       ├── ResultTable.svelte
    │       ├── HistoryPanel.svelte
    │       └── RateMeter.svelte
    ├── index.html
    ├── vite.config.js
    └── package.json
```

## Setup

### 1. Place the F5IpRep.dat file
```
backend/db/F5IpRep.dat
```

### 2. Backend (FastAPI)
```bash
cd backend
pip install -r requirements.txt
python app.py
# Runs on http://localhost:5000
# Auto docs available at http://localhost:5000/docs
```

### 3. Frontend (Svelte)
```bash
cd frontend
npm install
npm run dev
# Runs on http://localhost:5173
```

Open http://localhost:5173 in your browser.

## API Endpoints

| Method | Path             | Description                              |
|--------|------------------|------------------------------------------|
| POST   | /api/lookup      | Single IP lookup `{"ip": "1.2.3.4"}`    |
| POST   | /api/batch       | Batch lookup `{"ips": ["1.2.3.4", ...]}` |
| GET    | /api/rate-status | Current rate limit counters              |
| GET    | /api/status      | Server + F5 DB status                    |
| GET    | /docs            | Auto-generated Swagger UI (FastAPI)      |

## Rate Limits

ip-api.com free tier:
- **Single**: 45 req/min → backend uses 40 (12% buffer)
- **Batch**: 15 req/min → backend uses 13 (12% buffer)

The backend automatically stops requests before hitting the limit and returns
a 429 with wait_seconds so the frontend can show a countdown.
