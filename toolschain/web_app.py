"""
web_app.py — Flask Web CLI-Site Dashboard
==========================================
Minimal browser-based front-end with:
  • Home page — module cards, compliance notice
  • /api/run  — executes a toolschain CLI command (capture stdout JSON)
  • /terminal — xterm.js style fake-terminal UI with command input
  • /api/tdx/quote, /api/okx/top, /api/chain/block  — REST JSON endpoints

⚠  This app does NOT expose shell exec of arbitrary commands.  It only
   dispatches to a hard-coded whitelist of sub-command signatures.
"""

from __future__ import annotations

import io
import json
import os
import sys
import time
import traceback
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from typing import Any, Dict

from flask import Flask, jsonify, render_template_string, request, abort

from .modules import tdx_finance as TDX
from .modules import okx_market as OKX
from .modules import chain_prober as CHAIN
from .modules import crypto_toolkit as CT
from .modules import steganography as STG


# ---------------------------------------------------------------------------
# Template: single-file SPA
# ---------------------------------------------------------------------------
INDEX_HTML = r"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>Toolschain Box · Web CLI-Site</title>
<style>
  :root{
    --bg:#0b0f17; --fg:#d8dee9; --muted:#81a1c1; --accent:#88c0d0;
    --ok:#a3be8c; --warn:#ebcb8b; --err:#bf616a; --card:#121826;
    --border:#2a3448;
  }
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--fg);
       font-family: ui-monospace,"JetBrains Mono",Consolas,Menlo,monospace;
       padding:24px;min-height:100vh}
  h1{margin:0 0 4px;font-size:22px;color:var(--accent)}
  header.sub{color:var(--muted);margin-bottom:22px;font-size:13px}
  .grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:14px;margin-bottom:24px}
  .card{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:14px;
        box-shadow:0 1px 0 #0004}
  .card h3{margin:0 0 6px;font-size:15px;color:var(--accent)}
  .card p{margin:0 0 10px;color:var(--muted);font-size:12px;line-height:1.5}
  .card .tag{display:inline-block;padding:2px 8px;border-radius:999px;font-size:11px;
             background:#1c2638;color:var(--muted);margin-right:6px;margin-bottom:6px}
  button{cursor:pointer;background:#1f2a44;border:1px solid var(--border);color:var(--fg);
         padding:8px 12px;border-radius:8px;font-family:inherit;font-size:12px}
  button:hover{background:#2a385a;border-color:var(--accent)}
  button.primary{background:#3b4b6e;border-color:var(--accent)}
  /* terminal */
  .term{background:#050810;border:1px solid var(--border);border-radius:10px;
        padding:14px;min-height:380px;max-height:60vh;overflow-y:auto;white-space:pre-wrap;
        font-size:13px;line-height:1.55;box-shadow:inset 0 0 60px #0006}
  .prompt-line{display:flex;gap:8px;align-items:center;margin-top:8px}
  .ps1{color:var(--accent);white-space:nowrap;font-weight:700}
  input.cmd{flex:1;background:transparent;border:1px solid var(--border);border-radius:6px;
            color:var(--fg);padding:8px 10px;font-family:inherit;font-size:13px;outline:none}
  input.cmd:focus{border-color:var(--accent)}
  .out-ok{color:var(--fg)}
  .out-err{color:var(--err)}
  .chip-ok{color:var(--ok)}
  .chip-warn{color:var(--warn)}
  .notice{background:#1a1320;border:1px solid #5a3e3e;color:#ebcb8b;border-radius:10px;
          padding:12px 16px;margin-bottom:20px;font-size:12.5px;line-height:1.65}
  details>summary{cursor:pointer;color:var(--muted)}
  table{border-collapse:collapse;margin-top:8px;font-size:12.5px;width:100%;overflow:auto;display:block}
  th,td{border:1px solid var(--border);padding:5px 9px;text-align:left;white-space:nowrap}
  th{background:#1a2338;color:var(--accent)}
  tr td.num,tr th.num{text-align:right}
  .pos{color:var(--ok)}.neg{color:var(--err)}
  .row{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:6px 0}
  .pill{display:inline-block;padding:2px 8px;border-radius:6px;font-size:11px}
  .pill.sim{background:#2a1d3b;color:#d6b9ff;border:1px solid #6a4e9a}
  .pill.live{background:#18342a;color:#a3e1bb;border:1px solid #4e9569}
  pre.wrap{white-space:pre-wrap;word-break:break-all}
</style>
</head>
<body>
  <h1>╔══ TOOLSCHAIN BOX · WEB CLI-SITE ══╗</h1>
  <header class="sub">Security · Finance · Data Toolkit &nbsp;|&nbsp; UTF-8 &nbsp;|&nbsp; v1.0.0
    &nbsp;|&nbsp; <span id="conn"></span></header>

  <div class="notice">
    <b>📌 合规说明 / Compliance Notice</b><br>
    · 本仪表盘仅提供 <b>公开只读</b> 的市场/链上数据查询；<br>
    · 隐写模块仅用于 <b>版权水印 / 数字资产溯源</b>；<br>
    · 不包含任何非法交易、混币、黑网接入、暗网数据抓取等功能；<br>
    · 所有加密算法均为公开标准 (NIST AES-256-GCM / OpenPGP / SHA-2 / CRC / BLAKE2b)。
  </div>

  <div class="grid" id="cards"></div>

  <details open><summary style="font-weight:700;margin-bottom:8px">▸ 终端仿真 / Terminal Emulator</summary>
  <div class="term" id="term"></div>
  <div class="prompt-line">
    <span class="ps1">toolschain@box:~$</span>
    <input class="cmd" id="cmd" placeholder="输入命令, 例如: okx top 或 tdx quote 600519.SH" autocomplete="off" />
    <button class="primary" onclick="runCmd()">▶ RUN</button>
  </div>
  <div class="row" style="margin-top:8px;font-size:12px;color:var(--muted)">
    <span>快速命令:</span>
    <button onclick="setCmd('index')">index</button>
    <button onclick="setCmd('tdx quote 600519.SH')">tdx quote</button>
    <button onclick="setCmd('tdx kline 000001.SH.INDX -d 60')">tdx kline</button>
    <button onclick="setCmd('okx top -n 8')">okx top</button>
    <button onclick="setCmd('okx candles BTC-USDT --bar 1H -n 48')">okx kline</button>
    <button onclick="setCmd('chain block 840000 --chain BTC')">chain block</button>
    <button onclick="setCmd('chain audit --start 840000 --count 8')">chain audit</button>
    <button onclick="setCmd('crypto checksum-data hello')">crypto checksum</button>
  </div>
  </details>

<script>
const CARDS = [
  {id:'crypto', name:'01 · crypto-toolkit', zh:'加密校验工具箱',
   tags:['BaseXOR','AES-256-GCM','GPG-CA','MD5/SHA','CRC','BLAKE2b'],
   desc:'标准公开加密算法 / 数据完整性校验 / 本地迷你CA。'},
  {id:'stego', name:'02 · steganography', zh:'水印隐写(合规版)',
   tags:['LSB PNG','PNG tEXt','版权指纹'],
   desc:'仅用于版权水印 / 数字资产溯源。'},
  {id:'tdx', name:'03 · tdx-finance', zh:'通达信金融数据',
   tags:['A股','指数','期货','MCP','离线模拟'],
   desc:'TDX MCP + 离线确定性模拟器, 可直接查询。'},
  {id:'okx', name:'04 · okx-market', zh:'OKX公开行情',
   tags:['Spot','Swap','K线','24h Ticker'],
   desc:'仅调用 OKX 公开只读端点, 无账号无下单。'},
  {id:'chain', name:'05 · chain-prober', zh:'公开链上探针',
   tags:['BTC','ETH','区块头','余额','一致性审计'],
   desc:'Blockchair / Etherscan / Web3 RPC 只读探针。'},
];
const cardsEl = document.getElementById('cards');
CARDS.forEach(c=>{
  const el = document.createElement('div');
  el.className='card';
  el.innerHTML = `<h3>${c.name} · ${c.zh}</h3>
    <p>${c.desc}</p>
    <div>${c.tags.map(t=>`<span class="tag">${t}</span>`).join('')}</div>`;
  cardsEl.appendChild(el);
});

const term = document.getElementById('term');
const cmd = document.getElementById('cmd');
function log(html, cls='out-ok'){
  const d = document.createElement('div');
  d.className = cls;
  d.innerHTML = html;
  term.appendChild(d);
  term.scrollTop = term.scrollHeight;
}
function setCmd(s){cmd.value=s;cmd.focus()}
function fmtRows(rows,headers){
  if(!rows||!rows.length)return '<i>(无数据)</i>';
  const head = '<tr>'+headers.map(h=>`<th>${h}</th>`).join('')+'</tr>';
  const body = rows.map(r=>'<tr>'+r.map((c,i)=>{
    const s = String(c);
    const isNum = /^[+-]?[\d,.]+[%]?$/.test(s);
    const cls = s.startsWith('+')?'pos':s.startsWith('-')?'neg':(isNum?'num':'');
    return `<td class="${cls}">${s}</td>`}).join('')+'</tr>').join('');
  return `<table>${head}${body}</table>`;
}
function render(path, data){
  if(path==='/api/health')return `<span class="chip-ok">⬢ OK</span>  ts=${data.ts}`;
  if(path==='/api/tdx/quote'){
    const q=data.quote; const hdr=['代码','名称','最新价','涨跌','涨跌幅','最高','最低','成交量','成交额'];
    const row=[[q.code,q.name,q.last,q.chg,q.pct+'%',q.high,q.low,
               Number(q.volume).toLocaleString(),Number(q.amount).toLocaleString()]];
    return `<span class="pill ${data.mode==='simulated'?'sim':'live'}">${data.mode}</span> `+fmtRows(row,hdr);
  }
  if(path==='/api/tdx/kline'){
    const rows = (data.rows||[]).slice(-12).map(r=>[r.time,r.open,r.high,r.low,r.close,
      Number(r.volume).toLocaleString(),Number(r.amount).toLocaleString()]);
    return `<span class="pill ${data.mode==='simulated'?'sim':'live'}">${data.mode}</span> `+
           `<b>${data.meta?data.meta.code:''} ${data.meta?data.meta.name:''}</b> 共 ${data.rows?data.rows.length:0} 根`+
           fmtRows(rows,['日期','开','高','低','收','量','额']);
  }
  if(path==='/api/tdx/search'){
    const rows = (data.hits||[]).map(h=>[h.code,h.name,h.market,h.type]);
    return fmtRows(rows,['代码','名称','市场','类型']);
  }
  if(path==='/api/okx/top'||path==='/api/okx/ticker'){
    const list = data.tickers?data.tickers:[data.ticker];
    const rows = list.map(t=>[t.inst_id,Number(t.last).toPrecision(6),
      Number(t.chg>=0?'+':'')+Number(t.chg).toPrecision(6),
      Number(t.chg>=0?'+':'')+Number(t.pct).toFixed(2)+'%',
      Number(t.high24h).toPrecision(6),Number(t.low24h).toPrecision(6),
      Number(t.vol24h).toLocaleString(undefined,{maximumFractionDigits:2}),
      Number(t.volCcy24h).toLocaleString()]);
    return `<span class="pill ${data.mode==='okx-live'?'live':'sim'}">${data.mode}</span>`+
           fmtRows(rows,['交易对','最新','涨跌','涨跌幅','最高','最低','量(币)','额(USDT)']);
  }
  if(path==='/api/okx/candles'){
    const rows = (data.rows||[]).slice(-12).map(r=>[r.ts,r.open,r.high,r.low,r.close,
      Number(r.volume).toLocaleString(undefined,{maximumFractionDigits:2}),
      Number(r.volCcy).toLocaleString()]);
    return `<span class="pill ${data.mode==='okx-live'?'live':'sim'}">${data.mode}</span>`+
           ` ${data.inst_id} bar=${data.bar} 共 ${data.count} 根`+
           fmtRows(rows,['时间','开','高','低','收','量','额']);
  }
  if(path==='/api/chain/block'){
    const b=data.block; if(!b)return '<i>无数据</i>';
    return `<span class="pill ${data.mode==='simulated'?'sim':'live'}">${data.mode}</span>`+
      fmtRows([[b.chain,'#'+Number(b.height).toLocaleString(),
                 b.hash.slice(0,24)+'…',b.prev_hash.slice(0,24)+'…',
                 b.time,b.tx_count,b.size_bytes.toLocaleString()+' B']],
              ['链','高度','Hash','PrevHash','时间','交易数','大小']);
  }
  if(path==='/api/chain/balance'){
    return `<pre class="wrap">${JSON.stringify(data,null,2)}</pre>`;
  }
  if(path==='/api/chain/audit'){
    const rows=(data.blocks||[]).map(b=>[b.chain,'#'+Number(b.height).toLocaleString(),
      b.hash.slice(0,16)+'…',b.prev_hash.slice(0,16)+'…',b.time,b.tx_count,
      b.size_bytes.toLocaleString()+' B']);
    const status = data.consistent
      ? '<span class="pill live">CONSISTENT ✓</span>'
      : '<span class="pill" style="background:#3a1b1b;color:#ffa6a6;border:1px solid #8a3333">BROKEN ✗</span>';
    return status + ' 检查块数: '+data.count_checked+
      (data.issues&&data.issues.length?`<pre style="color:#ebcb8b">${data.issues.join('\n')}</pre>`:'')+
      fmtRows(rows,['链','高度','Hash','PrevHash','时间','交易数','大小']);
  }
  if(path==='/api/crypto/checksum-data'){
    const r=data.report;
    return `<pre>${['MD5: '+r.md5,'SHA-1: '+r.sha1,'SHA-256: '+r.sha256,
      'SHA-512: '+r.sha512,'CRC32: '+r.crc32,'Adler-32: '+r.adler32,
      'BLAKE2b: '+r.blake2b].join('\n')}</pre>`;
  }
  if(path==='/api/crypto/xor'){
    return `<pre class="wrap">${JSON.stringify(data,null,2)}</pre>`;
  }
  if(data.error) return `<div class="out-err">错误: ${data.error}</div>`;
  return `<pre class="wrap">${JSON.stringify(data,null,2)}</pre>`;
}
async function raw_api(path, params){
  const res = await fetch(path,{method:params?'POST':'GET',
    headers:{'Content-Type':'application/json'},
    body:params?JSON.stringify(params):undefined});
  return res.json();
}
async function runCmd(){
  const s = (cmd.value||'').trim();
  if(!s) return;
  log('<span class="ps1">toolschain@box:~$</span> '+s);
  cmd.value='';
  const parts = s.split(/\s+/);
  const [c0,c1,c2] = [parts[0],parts[1],parts[2]];
  try{
    if(c0==='index'){
      log('<b>TOOLSCHAIN BOX INDEX</b><br>· crypto-toolkit (加密校验)<br>· steganography (水印)<br>· tdx-finance (通达信)<br>· okx-market (OKX)<br>· chain-prober (区块链)<br>输入任一模块命令如: <code>tdx quote 600519.SH</code>');
      return;
    }
    if(c0==='help'||c0==='?'){
      log('可用命令: <code>index, crypto checksum-data TEXT, tdx quote CODE, tdx kline CODE -d 60, tdx search KW,<br>'
         +'okx top -n 8, okx ticker BTC-USDT, okx candles BTC-USDT --bar 1H -n 48,<br>'
         +'chain block HEIGHT --chain BTC, chain balance ADDR --chain BTC, chain audit --start 840000 --count 8</code>');
      return;
    }
    if(c0==='crypto'&&c1==='checksum-data'){
      const text = parts.slice(2).join(' ');
      const d = await raw_api('/api/crypto/checksum-data',{text});
      log(render('/api/crypto/checksum-data', d)); return;
    }
    if(c0==='crypto'&&c1==='xor-enc'){
      let k=null,t=null;
      for(let i=2;i<parts.length;i++){
        if(parts[i]==='-k'||parts[i]==='--key')k=parts[++i];
        if(parts[i]==='-t'||parts[i]==='--text')t=parts.slice(i+1).join(' ');
      }
      if(!k||!t){log('用法: crypto xor-enc -k KEY -t TEXT','out-err');return;}
      const d = await raw_api('/api/crypto/xor',{mode:'enc',key:k,text:t});
      log(render('/api/crypto/xor',d)); return;
    }
    if(c0==='tdx'&&c1==='quote'){
      const d=await raw_api('/api/tdx/quote',{code:c2||'600519.SH'});
      log(render('/api/tdx/quote',d)); return;
    }
    if(c0==='tdx'&&c1==='kline'){
      let code=c2,d=30;
      for(let i=3;i<parts.length;i++){
        if(parts[i]==='-d')d=parseInt(parts[++i]||'30',10);
      }
      const r=await raw_api('/api/tdx/kline',{code:code||'000001.SH.INDX',days:d});
      log(render('/api/tdx/kline',r)); return;
    }
    if(c0==='tdx'&&c1==='search'){
      const kw = parts.slice(2).join(' ')||'茅台';
      const r = await raw_api('/api/tdx/search',{keyword:kw});
      log(render('/api/tdx/search',r)); return;
    }
    if(c0==='okx'&&c1==='top'){
      let n=8;
      for(let i=2;i<parts.length;i++)if(parts[i]==='-n')n=parseInt(parts[++i]||'8',10);
      const r = await raw_api('/api/okx/top',{n});
      log(render('/api/okx/top',r)); return;
    }
    if(c0==='okx'&&c1==='ticker'){
      const r = await raw_api('/api/okx/ticker',{pair:c2||'BTC-USDT'});
      log(render('/api/okx/ticker',r)); return;
    }
    if(c0==='okx'&&c1==='candles'){
      let pair=c2||'BTC-USDT',bar='1H',n=48;
      for(let i=3;i<parts.length;i++){
        if(parts[i]==='--bar')bar=parts[++i];
        if(parts[i]==='-n')n=parseInt(parts[++i]||'48',10);
      }
      const r = await raw_api('/api/okx/candles',{pair,bar,limit:n});
      log(render('/api/okx/candles',r)); return;
    }
    if(c0==='chain'&&c1==='block'){
      let h=840000,chain='sim';
      for(let i=2;i<parts.length;i++){
        if(parts[i]==='--chain')chain=parts[++i]||'sim';
        else h = parseInt(parts[i],10)||h;
      }
      const r = await raw_api('/api/chain/block',{height:h,chain});
      log(render('/api/chain/block',r)); return;
    }
    if(c0==='chain'&&c1==='balance'){
      let addr=c2,chain='BTC';
      for(let i=3;i<parts.length;i++)if(parts[i]==='--chain')chain=parts[++i];
      if(!addr){log('请提供地址, 例: chain balance 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa --chain BTC','out-err');return;}
      const r = await raw_api('/api/chain/balance',{address:addr,chain});
      log(render('/api/chain/balance',r)); return;
    }
    if(c0==='chain'&&c1==='audit'){
      let start=840000,count=10,chain='BTC',sim=true;
      for(let i=2;i<parts.length;i++){
        if(parts[i]==='--start')start=parseInt(parts[++i],10);
        if(parts[i]==='--count')count=parseInt(parts[++i],10);
        if(parts[i]==='--chain')chain=parts[++i];
        if(parts[i]==='--no-sim')sim=false;
      }
      const r = await raw_api('/api/chain/audit',{start,count,chain,use_sim:sim});
      log(render('/api/chain/audit',r)); return;
    }
    log('未知命令。输入 <code>help</code> 查看可用命令。', 'out-err');
  }catch(e){
    log('执行错误: '+e.message, 'out-err');
  }
}
cmd.addEventListener('keydown',e=>{if(e.key==='Enter')runCmd()});
(async()=>{
  try{
    const h = await raw_api('/api/health');
    document.getElementById('conn').innerHTML =
      `<span class="chip-ok">⬢ 后端已连接</span>  pid/timestamp=${h.ts}`;
  }catch(e){
    document.getElementById('conn').innerHTML = '<span class="chip-warn">⚠ 后端未连接</span>';
  }
  log('<span class="ps1">toolschain@box:~$</span> echo hello');
  log('Toolschain Box Web v1.0.0 ready. 输入 <code>index</code> 查看总览, <code>help</code> 查看命令。');
})();
</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Flask app factory
# ---------------------------------------------------------------------------
def create_app() -> Flask:
    app = Flask(__name__, template_folder=None)
    app.config["JSON_AS_ASCII"] = False

    # --- health --------------------------------------------------------
    @app.get("/api/health")
    def _health():
        return jsonify({"ok": True, "ts": int(time.time()),
                        "encoding": sys.stdout.encoding or "UTF-8"})

    # --- home ----------------------------------------------------------
    @app.get("/")
    def _index():
        return render_template_string(INDEX_HTML)

    # --- TDX -----------------------------------------------------------
    @app.post("/api/tdx/quote")
    def _tdx_quote():
        body = request.get_json(silent=True) or {}
        try:
            d = TDX.fetch_quote(body.get("code", "600519.SH"),
                                use_mcp=bool(body.get("use_mcp")))
            return jsonify(d)
        except Exception as e:
            return jsonify({"error": str(e), "trace": traceback.format_exc()}), 500

    @app.post("/api/tdx/kline")
    def _tdx_kline():
        body = request.get_json(silent=True) or {}
        try:
            d = TDX.fetch_kline(body.get("code", "000001.SH.INDX"),
                                days=int(body.get("days", 30)),
                                use_mcp=bool(body.get("use_mcp")))
            return jsonify(d)
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.post("/api/tdx/search")
    def _tdx_search():
        body = request.get_json(silent=True) or {}
        return jsonify(TDX.search_market(body.get("keyword", ""),
                                          int(body.get("limit", 10))))

    # --- OKX -----------------------------------------------------------
    @app.post("/api/okx/top")
    def _okx_top():
        body = request.get_json(silent=True) or {}
        return jsonify(OKX.top_tickers(int(body.get("n", 8)),
                                        use_network=bool(body.get("live", True))))

    @app.post("/api/okx/ticker")
    def _okx_ticker():
        body = request.get_json(silent=True) or {}
        return jsonify(OKX.get_ticker(body.get("pair", "BTC-USDT"),
                                       use_network=bool(body.get("live", True))))

    @app.post("/api/okx/candles")
    def _okx_candles():
        body = request.get_json(silent=True) or {}
        return jsonify(OKX.get_candles(
            body.get("pair", "BTC-USDT"),
            bar=body.get("bar", "1H"),
            limit=int(body.get("limit", 48)),
            use_network=bool(body.get("live", True)),
        ))

    # --- CHAIN ---------------------------------------------------------
    @app.post("/api/chain/block")
    def _chain_block():
        body = request.get_json(silent=True) or {}
        chain = body.get("chain") or "sim"
        height = int(body.get("height", 840000))
        blk = None
        mode = "simulated"
        try:
            if chain == "BTC":
                blk = CHAIN.BTCProber().block(height)
                if blk: mode = "live"
            elif chain == "ETH":
                blk = CHAIN.ETHProber(
                    api_key=body.get("api_key"), rpc=body.get("rpc")
                ).block(height)
                if blk: mode = "live"
        except Exception:
            blk = None
        if blk is None:
            blk = CHAIN.ChainSimulator.block(
                "BTC" if chain == "sim" else chain, height
            )
        return jsonify({"mode": mode, "block": blk.__dict__})

    @app.post("/api/chain/balance")
    def _chain_balance():
        body = request.get_json(silent=True) or {}
        chain = body.get("chain") or "BTC"
        addr = body.get("address")
        if not addr:
            return jsonify({"error": "missing address"}), 400
        try:
            if chain == "BTC":
                r = CHAIN.BTCProber().address_balance(addr)
            else:
                r = CHAIN.ETHProber(
                    api_key=body.get("api_key"), rpc=body.get("rpc")
                ).address_balance(addr)
            return jsonify(r)
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.post("/api/chain/audit")
    def _chain_audit():
        body = request.get_json(silent=True) or {}
        chain = body.get("chain") or "BTC"
        start = int(body.get("start", 840000))
        count = int(body.get("count", 10))
        use_sim = bool(body.get("use_sim", True))
        blocks = []
        for h in range(start, start + count):
            if use_sim:
                blocks.append(CHAIN.ChainSimulator.block(chain, h))
            elif chain == "BTC":
                b = CHAIN.BTCProber().block(h)
                blocks.append(b or CHAIN.ChainSimulator.block(chain, h))
            else:
                b = CHAIN.ETHProber().block(h)
                blocks.append(b or CHAIN.ChainSimulator.block(chain, h))
        result = CHAIN.block_hash_consistency(blocks)
        return jsonify({
            **result,
            "blocks": [b.__dict__ for b in blocks],
        })

    # --- CRYPTO --------------------------------------------------------
    @app.post("/api/crypto/checksum-data")
    def _crypto_checksum():
        body = request.get_json(silent=True) or {}
        text = body.get("text", "")
        rep = CT.Checksum.of_data(text)
        return jsonify({"report": rep.__dict__})

    @app.post("/api/crypto/xor")
    def _crypto_xor():
        body = request.get_json(silent=True) or {}
        try:
            bx = CT.BaseXOR(body.get("key", "toolschain"))
            mode = body.get("mode", "enc")
            text = body.get("text", "")
            if mode == "enc":
                ct_b64 = bx.encrypt_b64(text)
                return jsonify({"mode": "enc", "cipher_b64": ct_b64,
                                "len_bytes": len(bx.encrypt(text))})
            else:
                pt = bx.decrypt_b64(text)
                return jsonify({"mode": "dec", "plaintext": pt.decode("utf-8",
                                                                      errors="replace")})
        except Exception as e:
            return jsonify({"error": str(e)}), 400

    return app
