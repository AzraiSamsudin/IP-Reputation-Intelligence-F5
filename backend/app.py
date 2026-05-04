"""
FastAPI backend for IP Reputation Lookup
- Wraps ip-api.com (single + batch modes) using async httpx
- Integrates F5IpRep.dat binary reputation DB
- Tracks rate limits: ip-api free tier = 45 req/min (single), 15 req/min (batch)
"""

import asyncio
import logging
import socket
import struct
import time
from collections import deque
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv
import os

load_dotenv()

logger = logging.getLogger("iprep")

# ── Reputation DB ──────────────────────────────────────────────────────────

DAT_FILE = Path(__file__).resolve().parent / "db" / f"{os.getenv('SECRET_FILE')}.dat"
RECORD_SIZE = 7

BIT_CATEGORIES = {
    0:  "Spam Sources",
    1:  "Windows Exploits",
    2:  "Web Attacks",
    3:  "BotNets",
    4:  "Scanners",
    7:  "Phishing",
    8:  "Proxy",
    11: "Mobile Threats",
    13: "Tor Proxy",
}

_f5_data: bytes | None = None


def load_f5_db() -> bytes | None:
    global _f5_data
    if _f5_data is not None:
        return _f5_data
    if not DAT_FILE.exists():
        logger.warning(f".dat not found at {DAT_FILE}")
        return None
    _f5_data = DAT_FILE.read_bytes()
    count = len(_f5_data) // RECORD_SIZE
    logger.info(f"Loaded .dat: {len(_f5_data):,} bytes, {count:,} records")
    return _f5_data


def flags_to_categories(flags: int) -> list[str]:
    cats = [name for bit, name in BIT_CATEGORIES.items() if flags & (1 << bit)]
    unknown_bits = flags & ~sum(1 << b for b in BIT_CATEGORIES)
    if unknown_bits:
        cats.append(f"Other(0x{unknown_bits:04x})")
    return cats or ["Unknown"]


def f5_lookup(ip_str: str) -> dict:
    data = load_f5_db()
    if data is None:
        return {"available": False, "flags": None, "categories": [], "raw_flags": None}
    try:
        target = struct.unpack(">I", socket.inet_aton(ip_str))[0]
    except OSError:
        return {"available": True, "flags": None, "categories": ["Invalid IP"], "raw_flags": None}

    lo, hi = 0, len(data) // RECORD_SIZE - 1
    while lo <= hi:
        mid = (lo + hi) // 2
        pos = mid * RECORD_SIZE
        ip_val = struct.unpack("<I", data[pos:pos + 4])[0]
        if ip_val == target:
            flags = struct.unpack("<H", data[pos + 5:pos + 7])[0]
            return {
                "available": True,
                "flags": f"0x{flags:04x}",
                "raw_flags": flags,
                "categories": flags_to_categories(flags),
            }
        elif ip_val < target:
            lo = mid + 1
        else:
            hi = mid - 1

    return {"available": True, "flags": None, "categories": ["Unknown"], "raw_flags": 0}


# ── Rate Limiter ──────────────────────────────────────────────────────────────

class RateLimiter:
    def __init__(self, max_per_minute: int, name: str):
        self.max_per_minute = max_per_minute
        self.safe_limit = int(max_per_minute * 0.88)  # 12% buffer
        self.name = name
        self.timestamps: deque = deque()
        self.lock = asyncio.Lock()
        self.paused_until: float = 0

    def _purge_old(self):
        now = time.time()
        while self.timestamps and now - self.timestamps[0] > 60:
            self.timestamps.popleft()

    async def check_and_record(self) -> dict:
        async with self.lock:
            now = time.time()
            if now < self.paused_until:
                wait = self.paused_until - now
                return {"ok": False, "wait_seconds": round(wait, 1), "reason": "rate_limit_pause"}

            self._purge_old()
            remaining = self.safe_limit - len(self.timestamps)

            if remaining <= 0:
                oldest = self.timestamps[0]
                wait = 60 - (now - oldest) + 1
                self.paused_until = now + wait
                return {"ok": False, "wait_seconds": round(wait, 1), "reason": "window_full"}

            self.timestamps.append(now)
            return {
                "ok": True,
                "requests_in_window": len(self.timestamps),
                "remaining": remaining - 1,
                "limit": self.max_per_minute,
            }

    async def status(self) -> dict:
        async with self.lock:
            self._purge_old()
            now = time.time()
            paused = now < self.paused_until
            return {
                "requests_in_window": len(self.timestamps),
                "safe_limit": self.safe_limit,
                "max_limit": self.max_per_minute,
                "remaining": max(0, self.safe_limit - len(self.timestamps)),
                "paused": paused,
                "paused_until": round(self.paused_until - now, 1) if paused else 0,
            }


single_limiter = RateLimiter(45, "single")
batch_limiter  = RateLimiter(15, "batch")

# ── App & Lifespan ────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: load F5 DB and create shared async HTTP client
    logger.info(f"Looking for the .dat file at: {DAT_FILE}")
    load_f5_db()
    app.state.http = httpx.AsyncClient(timeout=10.0)
    logger.info("HTTP client ready")
    yield
    # Shutdown
    await app.state.http.aclose()
    logger.info("HTTP client closed")


app = FastAPI(title="IPRep API", version="2.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Pydantic Models ───────────────────────────────────────────────────────────

class LookupRequest(BaseModel):
    ip: Optional[str] = ""

class BatchRequest(BaseModel):
    ips: list[str]

# ── Constants ─────────────────────────────────────────────────────────────────

IPAPI_FIELDS = "status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query"

# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/api/status")
async def api_status():
    data = load_f5_db()
    return {
        "f5_db": "loaded" if data is not None else "not_found",
        "f5_records": len(data) // RECORD_SIZE if data else 0,
        "rate_limits": {
            "single": await single_limiter.status(),
            "batch":  await batch_limiter.status(),
        },
    }


@app.post("/api/lookup")
async def lookup_single(body: LookupRequest):
    rate = await single_limiter.check_and_record()
    if not rate["ok"]:
        raise HTTPException(
            status_code=429,
            detail={
                "error": "rate_limited",
                "wait_seconds": rate["wait_seconds"],
                "message": f"Rate limit reached. Please wait {rate['wait_seconds']}s.",
            },
        )

    ip = (body.ip or "").strip()
    url = f"http://ip-api.com/json/{ip}" if ip else "http://ip-api.com/json/"

    try:
        resp = await app.state.http.get(url, params={"fields": IPAPI_FIELDS})
        geo: dict = resp.json()
    except Exception as e:
        raise HTTPException(status_code=502, detail={"error": "upstream_error", "message": str(e)})

    query_ip = geo.get("query", ip)
    geo["f5rep"] = f5_lookup(query_ip)
    geo["_rate"] = await single_limiter.status()
    return geo


@app.post("/api/batch")
async def lookup_batch(body: BatchRequest):
    if len(body.ips) == 0:
        raise HTTPException(status_code=400, detail={"error": "invalid_input", "message": "Provide at least one IP."})
    if len(body.ips) > 100:
        raise HTTPException(status_code=400, detail={"error": "too_many", "message": "Max 100 IPs per batch."})

    rate = await batch_limiter.check_and_record()
    if not rate["ok"]:
        raise HTTPException(
            status_code=429,
            detail={
                "error": "rate_limited",
                "wait_seconds": rate["wait_seconds"],
                "message": f"Rate limit reached. Please wait {rate['wait_seconds']}s.",
            },
        )

    payload = [{"query": ip, "fields": IPAPI_FIELDS} for ip in body.ips]
    try:
        resp = await app.state.http.post("http://ip-api.com/batch", json=payload)
        results: list = resp.json()
    except Exception as e:
        raise HTTPException(status_code=502, detail={"error": "upstream_error", "message": str(e)})

    for item in results:
        item["f5rep"] = f5_lookup(item.get("query", ""))

    return {
        "results": results,
        "_rate": await batch_limiter.status(),
    }


@app.get("/api/rate-status")
async def rate_status():
    return {
        "single": await single_limiter.status(),
        "batch":  await batch_limiter.status(),
    }

@app.get("/api/debug")
async def debug():
    return {
        "dat_file_path": str(DAT_FILE),
        "dat_file_exists": DAT_FILE.exists(),
        "cwd": str(Path.cwd()),
        "file_location": str(Path(__file__).resolve()),
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=5000, reload=True)
