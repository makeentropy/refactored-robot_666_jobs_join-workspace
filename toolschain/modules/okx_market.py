"""
okx_market.py — OKX Public Market Data REST Client
===================================================
Uses ONLY OKX's public, unauthenticated market-data REST endpoints:
  • /api/v5/market/ticker     — 24h ticker for instId
  • /api/v5/market/tickers    — bulk 24h tickers
  • /api/v5/market/candles    — K-line / candle history
  • /api/v5/market/trades     — recent public trades
  • /api/v5/public/instruments — instrument catalog

NO private endpoints, NO account access, NO order placement.
All data is the same public ticker anyone can see on OKX's website.
Fallback offline simulator included for air-gapped / CI environments.

Reference: https://www.okx.com/docs-v5/en/#rest-api-market-data
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import random
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Union

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None


OKX_BASE = "https://www.okx.com"
PUBLIC_TIMEOUT = 10  # seconds

POPULAR_PAIRS: Dict[str, Dict[str, str]] = {
    "BTC-USDT":  {"base": "BTC",  "quote": "USDT",  "type": "SPOT"},
    "ETH-USDT":  {"base": "ETH",  "quote": "USDT",  "type": "SPOT"},
    "SOL-USDT":  {"base": "SOL",  "quote": "USDT",  "type": "SPOT"},
    "BNB-USDT":  {"base": "BNB",  "quote": "USDT",  "type": "SPOT"},
    "XRP-USDT":  {"base": "XRP",  "quote": "USDT",  "type": "SPOT"},
    "DOGE-USDT": {"base": "DOGE", "quote": "USDT",  "type": "SPOT"},
    "ADA-USDT":  {"base": "ADA",  "quote": "USDT",  "type": "SPOT"},
    "AVAX-USDT": {"base": "AVAX", "quote": "USDT",  "type": "SPOT"},
    "BTC-USDT-SWAP": {"base": "BTC", "quote": "USDT", "type": "SWAP"},
    "ETH-USDT-SWAP": {"base": "ETH", "quote": "USDT", "type": "SWAP"},
}


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------
@dataclass
class OKXTicker:
    inst_id: str
    last: float
    bid: float
    ask: float
    open24h: float
    high24h: float
    low24h: float
    vol24h: float
    volCcy24h: float
    ts: str
    chg: float = 0.0
    pct: float = 0.0

    def __post_init__(self):
        try:
            self.chg = round(self.last - self.open24h, 6)
            self.pct = round(self.chg / self.open24h * 100, 3) if self.open24h else 0.0
        except Exception:
            pass

    def as_row(self):
        sign = "+" if self.chg >= 0 else ""
        return [
            self.inst_id, f"{self.last:.6g}",
            f"{sign}{self.chg:.6g}", f"{sign}{self.pct:.2f}%",
            f"{self.high24h:.6g}", f"{self.low24h:.6g}",
            f"{self.vol24h:,.4g}", f"{self.volCcy24h:,.0f}",
        ]


@dataclass
class OKXCandle:
    ts: str  # ISO formatted
    open: float
    high: float
    low: float
    close: float
    volume: float
    volCcy: float

    def as_list(self):
        return [self.ts, self.open, self.high, self.low, self.close,
                f"{self.volume:.4g}", f"{self.volCcy:.0f}"]


# ---------------------------------------------------------------------------
# REST client
# ---------------------------------------------------------------------------
class OKXPublicClient:
    """Authenticated-by-nothing public-market reader.

    No API key required.  Rate-limited (public endpoints share ~20 req/s
    per IP by OKX policy — client silently sleeps on 429).
    """

    def __init__(self, base_url: str = OKX_BASE, timeout: int = PUBLIC_TIMEOUT):
        self.base = base_url.rstrip("/")
        self.timeout = timeout

    # -- low-level --------------------------------------------------------
    def _get(self, path: str, params: Optional[dict] = None) -> dict:
        if requests is None:
            raise RuntimeError("requests library not installed: pip install requests")
        url = f"{self.base}{path}"
        try:
            r = requests.get(url, params=params or {}, timeout=self.timeout)
            if r.status_code == 429:
                time.sleep(1.5)
                r = requests.get(url, params=params or {}, timeout=self.timeout)
            r.raise_for_status()
            return r.json()
        except Exception as e:
            return {"code": "-1", "msg": str(e), "data": []}

    # -- endpoints --------------------------------------------------------
    def ticker(self, inst_id: str) -> Optional[OKXTicker]:
        j = self._get("/api/v5/market/ticker", {"instId": inst_id})
        if j.get("code") != "0" or not j.get("data"):
            return None
        d = j["data"][0]
        return OKXTicker(
            inst_id=d["instId"],
            last=float(d["last"]),
            bid=float(d["bidPx"]),
            ask=float(d["askPx"]),
            open24h=float(d["open24h"]),
            high24h=float(d["high24h"]),
            low24h=float(d["low24h"]),
            vol24h=float(d["vol24h"]),
            volCcy24h=float(d["volCcy24h"]),
            ts=d["ts"],
        )

    def tickers(self, inst_type: str = "SPOT") -> List[OKXTicker]:
        j = self._get("/api/v5/market/tickers", {"instType": inst_type})
        out: List[OKXTicker] = []
        if j.get("code") != "0":
            return out
        for d in j.get("data", []):
            try:
                out.append(OKXTicker(
                    inst_id=d["instId"],
                    last=float(d["last"]),
                    bid=float(d["bidPx"]),
                    ask=float(d["askPx"]),
                    open24h=float(d["open24h"]),
                    high24h=float(d["high24h"]),
                    low24h=float(d["low24h"]),
                    vol24h=float(d["vol24h"]),
                    volCcy24h=float(d["volCcy24h"]),
                    ts=d["ts"],
                ))
            except Exception:
                continue
        return out

    def candles(self, inst_id: str, bar: str = "1H", limit: int = 100) -> List[OKXCandle]:
        j = self._get("/api/v5/market/candles", {
            "instId": inst_id, "bar": bar, "limit": str(limit),
        })
        out: List[OKXCandle] = []
        if j.get("code") != "0":
            return out
        for row in j.get("data", []):
            try:
                t_ms = int(row[0])
                iso = _dt.datetime.utcfromtimestamp(t_ms / 1000).isoformat(timespec="seconds") + "Z"
                out.append(OKXCandle(
                    ts=iso, open=float(row[1]), high=float(row[2]),
                    low=float(row[3]), close=float(row[4]),
                    volume=float(row[5]), volCcy=float(row[6]),
                ))
            except Exception:
                continue
        return out[::-1]  # oldest first

    def public_trades(self, inst_id: str, limit: int = 50) -> List[dict]:
        j = self._get("/api/v5/market/trades", {"instId": inst_id, "limit": str(limit)})
        if j.get("code") != "0":
            return []
        return j.get("data", [])

    def instruments(self, inst_type: str = "SPOT") -> List[dict]:
        j = self._get("/api/v5/public/instruments", {"instType": inst_type})
        if j.get("code") != "0":
            return []
        return j.get("data", [])


# ---------------------------------------------------------------------------
# Offline deterministic simulator (air-gapped / CI / testing)
# ---------------------------------------------------------------------------
class OKXSimulator:
    BASE: Dict[str, float] = {
        "BTC-USDT": 63000.0, "ETH-USDT": 3100.0, "SOL-USDT": 140.0,
        "BNB-USDT": 580.0, "XRP-USDT": 0.52, "DOGE-USDT": 0.12,
        "ADA-USDT": 0.42, "AVAX-USDT": 35.0,
    }

    @classmethod
    def _rnd(cls, inst_id: str, salt: str = "") -> random.Random:
        h = hashlib.sha256((inst_id + "|" + salt).encode()).digest()
        return random.Random(int.from_bytes(h[:8], "little"))

    @classmethod
    def ticker(cls, inst_id: str) -> OKXTicker:
        r = cls._rnd(inst_id, _dt.date.today().isoformat())
        base = cls.BASE.get(inst_id, 1.0)
        drift = r.uniform(-5.0, 5.0)
        last = round(base * (1 + drift / 100), 6)
        op = round(base * (1 + r.uniform(-1.5, 1.5) / 100), 6)
        hi = round(last * (1 + r.random() * 0.015), 6)
        lo = round(last * (1 - r.random() * 0.015), 6)
        vol = round(abs(r.gauss(1e5, 3e4)), 4)
        volc = round(vol * last, 2)
        return OKXTicker(
            inst_id=inst_id, last=last, bid=round(last * 0.9995, 6),
            ask=round(last * 1.0005, 6), open24h=op, high24h=hi,
            low24h=lo, vol24h=vol, volCcy24h=volc,
            ts=str(int(time.time() * 1000)),
        )

    @classmethod
    def candles(cls, inst_id: str, bar: str = "1H", limit: int = 100) -> List[OKXCandle]:
        r = cls._rnd(inst_id, f"kline-{bar}-{limit}")
        base = cls.BASE.get(inst_id, 1.0)
        price = base
        now = int(time.time())
        step_s = {"1m": 60, "5m": 300, "15m": 900, "1H": 3600, "4H": 14400, "1D": 86400}.get(bar, 3600)
        out: List[OKXCandle] = []
        for i in range(limit):
            t = now - (limit - i) * step_s
            iso = _dt.datetime.utcfromtimestamp(t).isoformat(timespec="seconds") + "Z"
            o = price
            chg = r.uniform(-1.2, 1.2) / 100
            c = round(o * (1 + chg), 6)
            h = round(max(o, c) * (1 + r.random() * 0.004), 6)
            l = round(min(o, c) * (1 - r.random() * 0.004), 6)
            v = round(abs(r.gauss(500, 150)), 4)
            out.append(OKXCandle(iso, o, h, l, c, v, round(v * (o + c) / 2, 2)))
            price = c
        return out


# ---------------------------------------------------------------------------
# Public façade
# ---------------------------------------------------------------------------
def get_ticker(inst_id: str, use_network: bool = True) -> dict:
    if use_network and requests is not None:
        c = OKXPublicClient()
        t = c.ticker(inst_id)
        if t is not None:
            return {"mode": "okx-live", "ticker": t.__dict__}
    return {"mode": "simulated", "ticker": OKXSimulator.ticker(inst_id).__dict__}


def get_candles(inst_id: str, bar: str = "1H", limit: int = 100, use_network: bool = True) -> dict:
    if use_network and requests is not None:
        c = OKXPublicClient()
        rows = c.candles(inst_id, bar, limit)
        if rows:
            return {"mode": "okx-live", "inst_id": inst_id, "bar": bar,
                    "count": len(rows), "rows": [r.__dict__ for r in rows]}
    rows = OKXSimulator.candles(inst_id, bar, limit)
    return {"mode": "simulated", "inst_id": inst_id, "bar": bar,
            "count": len(rows), "rows": [r.__dict__ for r in rows]}


def top_tickers(n: int = 10, use_network: bool = True) -> dict:
    keys = list(POPULAR_PAIRS.keys())[:n]
    rows = []
    for k in keys:
        d = get_ticker(k, use_network=use_network)
        rows.append(d["ticker"])
    return {"mode": d["mode"], "count": len(rows), "tickers": rows}
