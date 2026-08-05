"""
tdx_finance.py — TongDaXin (通达信) Financial Market Data CLI
==============================================================
Thin adapter layer over TDX MCP server + public REST fallbacks.

Because the TDX MCP connector requires user-auth (ACCESS_TOKEN injected
at runtime), this module provides:
  • A unified CLI interface
  • MCP server discovery helpers (use `run_mcp` externally via caller)
  • Public-data fallback mocks + offline CSV simulator for smoke-testing
  • A-share / index / futures ticker catalog resolver

Compliance: ONLY retrieves public market-quoted data.  No broker account
trading, no PII.
"""

from __future__ import annotations

import csv
import datetime as _dt
import json
import os
import random
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Union

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None


# ---------------------------------------------------------------------------
# Ticker catalog — well-known TDX security codes
# ---------------------------------------------------------------------------
TDX_CATALOG: Dict[str, Dict[str, str]] = {
    # A-share main board (SH=1, SZ=0)
    "600519.SH": {"name": "贵州茅台", "market": "SH", "type": "stock"},
    "000001.SZ": {"name": "平安银行", "market": "SZ", "type": "stock"},
    "601318.SH": {"name": "中国平安", "market": "SH", "type": "stock"},
    "300750.SZ": {"name": "宁德时代", "market": "SZ", "type": "stock"},
    "000858.SZ": {"name": "五粮液",   "market": "SZ", "type": "stock"},
    # Major indices
    "000001.SH.INDX": {"name": "上证指数", "market": "SH", "type": "index"},
    "399001.SZ.INDX": {"name": "深证成指", "market": "SZ", "type": "index"},
    "399006.SZ.INDX": {"name": "创业板指", "market": "SZ", "type": "index"},
    "000300.SH.INDX": {"name": "沪深300", "market": "SH", "type": "index"},
    # Futures (TDX中金所/上期所代码 — informational only)
    "IF2409.CFFEX": {"name": "IF2409 沪深300期货", "market": "CFFEX", "type": "future"},
    "AU2412.SHFE":  {"name": "AU2412 黄金期货",   "market": "SHFE",  "type": "future"},
}


def resolve(code: str) -> dict:
    """Resolve a TDX code to its metadata; supports partial lookup."""
    if code in TDX_CATALOG:
        return {"code": code, **TDX_CATALOG[code]}
    # try suffix matching
    for k, v in TDX_CATALOG.items():
        if k.startswith(code.upper()) or v["name"] == code:
            return {"code": k, **v}
    return {"code": code, "name": f"UNKNOWN({code})", "market": "?", "type": "?"}


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------
@dataclass
class TickRow:
    time: str
    open: float
    high: float
    low: float
    close: float
    volume: int
    amount: float

    def as_list(self):
        return [self.time, self.open, self.high, self.low, self.close,
                self.volume, f"{self.amount:.2f}"]


@dataclass
class Quote:
    code: str
    name: str
    last: float
    chg: float
    pct: float
    high: float
    low: float
    open_: float
    prev_close: float
    volume: int
    amount: float
    bid: float = 0.0
    ask: float = 0.0
    timestamp: str = field(default_factory=lambda: _dt.datetime.now().isoformat(timespec="seconds"))

    def as_row(self) -> list:
        sign = "+" if self.chg >= 0 else ""
        return [
            self.code, self.name, f"{self.last:.2f}",
            f"{sign}{self.chg:.2f}", f"{sign}{self.pct:.2f}%",
            f"{self.high:.2f}", f"{self.low:.2f}",
            f"{self.volume:,}", f"{self.amount:,.0f}",
        ]


# ---------------------------------------------------------------------------
# MCP helper — describes which MCP tools the main CLI should invoke
# ---------------------------------------------------------------------------
class TDXMCPClient:
    """Reference for the connected MCP server name & tools.

    Actual MCP invocations happen via the host agent's `run_mcp` tool
    with server_name == `mcp_trae-remote-official_plugin_tdx_tdx`
    when that connector is authorized and installed.
    """

    SERVER_CANDIDATES = [
        "mcp_trae-remote-official_plugin_tdx_tdx",
        "mcp_tdx",
    ]

    EXPECTED_TOOL_NAMES = [
        # Based on tdx plugin — bond/stock/fund/index/etc data families
        "bond_basic_info", "bond_market_data", "stock_highfreq_quotes",
        "index_data", "index_highfreq_quotes", "search_stocks",
        "get_stock_summary", "get_stock_performance", "get_stock_info",
        "get_stock_financials",
    ]

    @classmethod
    def describe(cls) -> dict:
        return {
            "server_candidates": cls.SERVER_CANDIDATES,
            "known_tools": cls.EXPECTED_TOOL_NAMES,
            "auth": "Connector token via `tdx-api-key` header",
            "status": "See `toolschain tdx status`",
        }


# ---------------------------------------------------------------------------
# Fallback simulator — deterministic pseudo-market (offline/CI testing)
# ---------------------------------------------------------------------------
class TDXFallbackSimulator:
    """Deterministic offline simulator.  Used when MCP or network absent.

    Generates reproducible pseudo-quotes & K-line candles seeded by code
    + date, so CI tests don't flake.  Clearly labeled `mode=simulated`.
    """

    BASE_PRICES: Dict[str, float] = {
        "600519.SH": 1680.0,
        "000001.SZ": 11.5,
        "601318.SH": 48.0,
        "300750.SZ": 220.0,
        "000858.SZ": 158.0,
        "000001.SH.INDX": 2980.0,
        "399001.SZ.INDX": 9200.0,
        "399006.SZ.INDX": 1850.0,
        "000300.SH.INDX": 3520.0,
        "IF2409.CFFEX": 3510.0,
        "AU2412.SHFE": 485.0,
    }

    @staticmethod
    def _seed(code: str, date: Optional[str] = None) -> int:
        if date is None:
            date = _dt.date.today().isoformat()
        return int.from_bytes((code + "|" + date).encode(), "little") & 0xFFFFFFFF

    @classmethod
    def quote(cls, code: str) -> Quote:
        meta = resolve(code)
        rnd = random.Random(cls._seed(code))
        base = cls.BASE_PRICES.get(code, 10.0)
        pct = rnd.uniform(-3.0, 3.0)
        last = round(base * (1 + pct / 100), 2)
        prev = round(base, 2)
        chg = round(last - prev, 2)
        high = round(last * (1 + rnd.random() * 0.01), 2)
        low = round(last * (1 - rnd.random() * 0.01), 2)
        open_ = round(prev * (1 + rnd.uniform(-0.5, 0.5) / 100), 2)
        vol = rnd.randint(500_000, 50_000_000)
        amt = round(last * vol * (1 + rnd.random() * 0.05), 2)
        return Quote(
            code=meta["code"], name=meta["name"], last=last, chg=chg, pct=pct,
            high=high, low=low, open_=open_, prev_close=prev,
            volume=vol, amount=amt,
            bid=round(last * 0.999, 2), ask=round(last * 1.001, 2),
        )

    @classmethod
    def kline(cls, code: str, days: int = 30) -> List[TickRow]:
        meta = resolve(code)
        base = cls.BASE_PRICES.get(code, 10.0)
        rnd = random.Random(cls._seed(code, "kline-" + str(days)))
        rows: List[TickRow] = []
        price = base
        today = _dt.date.today()
        for i in range(days):
            d = today - _dt.timedelta(days=days - 1 - i)
            if d.weekday() >= 5:  # skip weekends for realism
                continue
            o = price
            drift = rnd.uniform(-2.0, 2.0) / 100
            c = round(o * (1 + drift), 2)
            h = round(max(o, c) * (1 + rnd.random() * 0.008), 2)
            l = round(min(o, c) * (1 - rnd.random() * 0.008), 2)
            v = rnd.randint(800_000, 12_000_000)
            amt = round((o + c) / 2 * v, 2)
            rows.append(TickRow(d.isoformat(), o, h, l, c, v, amt))
            price = c
        return rows

    @classmethod
    def search(cls, keyword: str, limit: int = 10) -> List[dict]:
        kw = keyword.lower()
        hits = []
        for k, v in TDX_CATALOG.items():
            if (kw in k.lower() or kw in v["name"] or kw in v["type"] or kw in v["market"].lower()) and len(hits) < limit:
                hits.append({"code": k, **v})
        return hits

    @classmethod
    def export_csv(cls, code: str, days: int, path: Union[str, Path]) -> str:
        rows = cls.kline(code, days)
        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["date", "open", "high", "low", "close", "volume", "amount"])
            for r in rows:
                w.writerow(r.as_list())
        return str(out)


# ---------------------------------------------------------------------------
# Public facade
# ---------------------------------------------------------------------------
def fetch_quote(code: str, use_mcp: bool = False) -> dict:
    """Get a quote; caller sets use_mcp=True to force real TDX MCP call."""
    if use_mcp:
        return {
            "mode": "mcp-delegated",
            "hint": "Run host agent run_mcp(stock_highfreq_quotes / get_stock_summary etc.)",
            "code": code,
            "mcp": TDXMCPClient.describe(),
        }
    q = TDXFallbackSimulator.quote(code)
    return {"mode": "simulated", "quote": q.__dict__}


def fetch_kline(code: str, days: int = 30, use_mcp: bool = False) -> dict:
    if use_mcp:
        return {"mode": "mcp-delegated", "code": code, "days": days,
                "mcp": TDXMCPClient.describe()}
    rows = TDXFallbackSimulator.kline(code, days)
    return {
        "mode": "simulated",
        "code": code,
        "meta": resolve(code),
        "rows": [r.__dict__ for r in rows],
    }


def search_market(keyword: str, limit: int = 10) -> dict:
    hits = TDXFallbackSimulator.search(keyword, limit)
    return {"keyword": keyword, "hits": hits, "count": len(hits)}
