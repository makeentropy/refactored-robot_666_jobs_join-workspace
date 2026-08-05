"""
chain_prober.py — Public Blockchain Data Block Explorer
========================================================
Transparent, public, read-only probes of major public chains via
community open APIs:

  • BTC   — blockchair.com public REST (no key needed for low volume)
  • ETH   — etherscan.io public API (supports optional API_KEY env)
  • Generic — any EVM-compatible RPC via web3.py

This module is a "prober" in the legitimate sense:
    ✔ Fetch block header / tx count / block hash by height
    ✔ Decode basic tx fields (from, to, value, gas)
    ✔ Compute block-hash merkle-top sanity checks
    ✔ Track address balance via public RPC

It explicitly DOES NOT:
    ✗ Implement mixing, tumbling, coinjoin-style automation
    ✗ Talk to dark-market / anonymous-market sites
    ✗ Send signed transactions (read-only)
    ✗ Hold or generate raw private keys (wallet-less)
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Union

try:
    import requests
except ImportError:
    requests = None

try:
    from web3 import Web3
except ImportError:
    Web3 = None


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------
@dataclass
class BlockSummary:
    chain: str
    height: int
    hash: str
    prev_hash: str
    time: str
    tx_count: int
    size_bytes: int
    miner: Optional[str] = None
    difficulty: Optional[float] = None
    raw: Optional[dict] = None

    def as_row(self):
        return [
            self.chain, f"#{self.height:,}", self.hash[:16] + "…",
            self.prev_hash[:16] + "…", self.time,
            str(self.tx_count), f"{self.size_bytes:,} B",
        ]


@dataclass
class TxBrief:
    chain: str
    txid: str
    block: int
    from_addr: str
    to_addr: str
    value: str  # human-readable (BTC/ETH)
    fee: str
    confirmations: int

    def as_row(self):
        return [
            self.chain, self.txid[:16] + "…", f"#{self.block:,}",
            self.from_addr[:10] + "…", self.to_addr[:10] + "…",
            self.value, self.fee, str(self.confirmations),
        ]


# ---------------------------------------------------------------------------
# BTC probe (blockchair public REST, low-rate no-key tier)
# ---------------------------------------------------------------------------
class BTCProber:
    BASE = "https://api.blockchair.com/bitcoin"
    UA = "toolschain-box/1.0 (+https://github.com/toolschain-box)"

    def _get(self, path: str) -> Optional[dict]:
        if requests is None:
            return None
        try:
            r = requests.get(f"{self.BASE}{path}",
                             headers={"User-Agent": self.UA}, timeout=15)
            if r.status_code == 429:
                time.sleep(2)
                r = requests.get(f"{self.BASE}{path}",
                                 headers={"User-Agent": self.UA}, timeout=15)
            r.raise_for_status()
            return r.json()
        except Exception:
            return None

    def block(self, height: int) -> Optional[BlockSummary]:
        j = self._get(f"/dashboards/block/{height}")
        if not j or j.get("context", {}).get("code") != 200:
            return None
        d = (j.get("data") or {}).get(str(height)) or {}
        b = d.get("block") or {}
        return BlockSummary(
            chain="BTC",
            height=int(b.get("id", height)),
            hash=b.get("hash") or "",
            prev_hash=b.get("previous_block") or "",
            time=b.get("time") or "",
            tx_count=int(b.get("transaction_count", 0)),
            size_bytes=int(b.get("size", 0)),
            miner=b.get("guessed_miner"),
            difficulty=float(b.get("difficulty") or 0),
            raw=b,
        )

    def tx(self, txid: str) -> Optional[TxBrief]:
        j = self._get(f"/dashboards/transaction/{txid}")
        if not j or j.get("context", {}).get("code") != 200:
            return None
        d = (j.get("data") or {}).get(txid) or {}
        t = d.get("transaction") or {}
        val_sat = int(t.get("output_total", 0))
        fee_sat = int(t.get("fee", 0))
        return TxBrief(
            chain="BTC",
            txid=t.get("hash") or txid,
            block=int(t.get("block_id", 0)),
            from_addr="(multiple)" if int(t.get("input_count", 0)) > 1
                        else ((d.get("inputs") or [{}])[0].get("recipient") or ""),
            to_addr="(multiple)" if int(t.get("output_count", 0)) > 1
                        else ((d.get("outputs") or [{}])[0].get("recipient") or ""),
            value=f"{val_sat / 1e8:.8f} BTC",
            fee=f"{fee_sat / 1e8:.8f} BTC",
            confirmations=int(t.get("confirmations", 0)),
        )

    def address_balance(self, addr: str) -> dict:
        j = self._get(f"/dashboards/address/{addr}")
        if not j or j.get("context", {}).get("code") != 200:
            return {"error": "not-found or rate-limited", "address": addr}
        d = (j.get("data") or {}).get(addr) or {}
        a = d.get("address") or {}
        sat = int(a.get("balance", 0))
        return {
            "chain": "BTC",
            "address": addr,
            "balance_btc": sat / 1e8,
            "balance_sat": sat,
            "tx_count": int(a.get("transaction_count", 0)),
            "received_total_btc": int(a.get("received", 0)) / 1e8,
            "spent_total_btc": int(a.get("spent", 0)) / 1e8,
        }


# ---------------------------------------------------------------------------
# ETH probe (Etherscan public + optional Web3 RPC)
# ---------------------------------------------------------------------------
class ETHProber:
    ETHERSCAN = "https://api.etherscan.io/api"

    def __init__(self, api_key: Optional[str] = None, rpc: Optional[str] = None):
        self.api_key = api_key or os.environ.get("ETHERSCAN_API_KEY") or "YourApiKeyToken"
        self.rpc = rpc or os.environ.get("ETH_RPC_URL")
        self.w3 = Web3(Web3.HTTPProvider(self.rpc)) if (Web3 and self.rpc) else None

    def _get(self, params: dict) -> Optional[dict]:
        if requests is None:
            return None
        p = {"apikey": self.api_key, **params}
        try:
            r = requests.get(self.ETHERSCAN, params=p, timeout=15)
            r.raise_for_status()
            return r.json()
        except Exception:
            return None

    def block(self, height: Union[int, str]) -> Optional[BlockSummary]:
        j = self._get({"module": "block", "action": "getblockreward", "blockno": str(height)})
        block_j = None
        if j and j.get("status") == "1" and j.get("result"):
            block_j = j["result"]
        # Also try eth_blockNumber via web3 if available
        if self.w3 is not None:
            try:
                b = self.w3.eth.get_block(int(height))
                t = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(b.timestamp))
                return BlockSummary(
                    chain="ETH",
                    height=b.number,
                    hash=b.hash.hex(),
                    prev_hash=b.parentHash.hex(),
                    time=t,
                    tx_count=len(b.transactions),
                    size_bytes=getattr(b, "size", 0) or 0,
                    miner=b.miner,
                    difficulty=float(b.difficulty),
                    raw=dict(b) if block_j is None else block_j,
                )
            except Exception:
                pass
        if block_j:
            return BlockSummary(
                chain="ETH",
                height=int(block_j.get("blockNumber", height)),
                hash=block_j.get("blockHash") or "",
                prev_hash="",
                time=block_j.get("timeStamp") and
                     time.strftime("%Y-%m-%d %H:%M:%S",
                                   time.gmtime(int(block_j["timeStamp"]))) or "",
                tx_count=0,
                size_bytes=0,
                miner=block_j.get("blockMiner"),
                difficulty=None,
                raw=block_j,
            )
        return None

    def address_balance(self, addr: str) -> dict:
        if self.w3 is not None:
            try:
                bal_wei = self.w3.eth.get_balance(Web3.to_checksum_address(addr))
                return {"chain": "ETH", "address": addr,
                        "balance_eth": float(Web3.from_wei(bal_wei, "ether")),
                        "balance_wei": bal_wei,
                        "source": "rpc"}
            except Exception:
                pass
        j = self._get({"module": "account", "action": "balance", "address": addr, "tag": "latest"})
        if j and j.get("status") == "1":
            wei = int(j["result"])
            return {"chain": "ETH", "address": addr,
                    "balance_eth": wei / 1e18, "balance_wei": wei,
                    "source": "etherscan"}
        return {"error": "fetch failed", "address": addr}


# ---------------------------------------------------------------------------
# Generic block hash integrity checker (educational, verifies header links)
# ---------------------------------------------------------------------------
def block_hash_consistency(blocks: List[BlockSummary]) -> dict:
    """Given a contiguous list of BlockSummary, check prev_hash links.

    Educational demo — does NOT re-compute PoW hash (would need full
    header serialization).  Used by CLI `chain-prober audit`.
    """
    issues: List[str] = []
    for i in range(1, len(blocks)):
        a, b = blocks[i - 1], blocks[i]
        if a.height + 1 != b.height:
            issues.append(f"Non-contiguous height: #{a.height} → #{b.height}")
            continue
        if b.prev_hash and a.hash and b.prev_hash != a.hash:
            issues.append(
                f"Broken prev_hash at #{b.height}: want {a.hash[:20]}… got {b.prev_hash[:20]}…"
            )
    return {
        "count_checked": len(blocks),
        "issues": issues,
        "consistent": len(issues) == 0,
    }


# ---------------------------------------------------------------------------
# Deterministic offline simulator (air-gapped / CI)
# ---------------------------------------------------------------------------
class ChainSimulator:
    @staticmethod
    def _hash(n: int, chain: str) -> str:
        return hashlib.sha256(f"{chain}|{n}|toolschain-sim".encode()).hexdigest()

    @classmethod
    def block(cls, chain: str, height: int) -> BlockSummary:
        t = time.time() - (840_000 - height) * 600
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(t))
        return BlockSummary(
            chain=chain, height=height,
            hash=cls._hash(height, chain),
            prev_hash=cls._hash(height - 1, chain),
            time=ts,
            tx_count=((height * 7) % 2400) + 120,
            size_bytes=((height * 1733) % 1_500_000) + 200_000,
            miner=f"simMiner{(height % 17) + 1}",
            difficulty=float(height * 1e9) if chain == "BTC" else float(height * 1e6),
            raw={"simulated": True},
        )
