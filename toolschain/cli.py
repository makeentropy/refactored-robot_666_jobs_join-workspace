"""
cli.py — Main entry point: `toolschain` command (Click-based).

Sub-commands:
  toolschain index                 TOOLSCHAIN BOX INDEX
  toolschain crypto checksum <f>   Integrity hashes
  toolschain crypto xor ...        BaseXOR encrypt/decrypt/prober
  toolschain crypto aes ...        AES-256-GCM
  toolschain crypto gpg ...        GPG-CA keygen/sign/verify/encrypt
  toolschain stego embed ...       LSB watermark
  toolschain stego extract ...     LSB watermark extract
  toolschain stego fingerprint ... Provenance manifest
  toolschain tdx quote <code>      通达信行情 (TDX)
  toolschain tdx kline <code>      K-line
  toolschain tdx search <kw>       证券代码检索
  toolschain tdx export <code>     CSV导出
  toolschain okx ticker <pair>     OKX行情
  toolschain okx candles <pair>    OKX K线
  toolschain okx top              TOP行情列表
  toolschain chain block <h>       BTC/ETH块查询
  toolschain chain balance <addr>  地址余额
  toolschain chain audit           区块一致性审计
  toolschain serve                 启动Web CLI-Site仪表盘
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Optional

import click

from .utils import ui_renderer as UI
from .modules import crypto_toolkit as CT
from .modules import steganography as STG
from .modules import tdx_finance as TDX
from .modules import okx_market as OKX
from .modules import chain_prober as CHAIN


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _out(*args, **kwargs):
    click.echo(*args, **kwargs)


def _splash():
    _out(UI.banner())
    _out(UI.kv_pairs([
        ("Modules", "crypto · stego · tdx · okx · chain"),
        ("License", "BSD-3 合法合规版 · 仅使用公开API & 标准算法"),
        ("UTF-8",   f"终端编码: {sys.stdout.encoding or 'UTF-8'}"),
        ("Python",  f"{sys.version.split()[0]}"),
    ]))


# ---------------------------------------------------------------------------
# Root group
# ---------------------------------------------------------------------------
@click.group(context_settings={"help_option_names": ["-h", "--help"],
                               "max_content_width": 120})
@click.version_option("1.0.0", prog_name="toolschain",
                      message="%(prog)s v%(version)s  ·  Toolschain Box")
@click.option("--no-splash", is_flag=True, help="跳过启动横幅")
@click.pass_context
def cli(ctx, no_splash):
    """TOOLSCHAIN BOX — 安全 · 金融 · 数据 综合工具箱 (UTF-8 CLI)"""
    ctx.ensure_object(dict)
    ctx.obj["no_splash"] = no_splash
    if not no_splash:
        _splash()


# ---------------------------------------------------------------------------
# INDEX
# ---------------------------------------------------------------------------
@cli.command(name="index")
def cmd_index():
    """TOOLSCHAIN BOX INDEX — 模块总览与合规说明"""
    _out(UI.section("TOOLSCHAIN BOX INDEX"))
    cards = [
        ["01", "crypto-toolkit", "加密校验工具箱",
            "BaseXOR · AES-256-GCM · GPG-CA · MD5/SHA/CRC/BLAKE2b",
            "标准公开算法"],
        ["02", "steganography", "水印隐写(合规版)",
            "LSB PNG水印 · PNG tEXt元数据 · 版权指纹链",
            "仅版权/溯源用途"],
        ["03", "tdx-finance", "通达信金融数据",
            "A股/指数/期货行情 · K线 · 代码搜索 · CSV导出",
            "TDX MCP + 离线模拟"],
        ["04", "okx-market", "OKX公开行情",
            "现货/合约Ticker · K线 · 公开成交 · 产品目录",
            "仅公开只读端点"],
        ["05", "chain-prober", "公开链上探针",
            "BTC/ETH区块头 · 交易摘要 · 地址余额 · 链一致性审计",
            "只读 · 公开RPC/API"],
        ["06", "web-ui", "Web仪表盘",
            "Flask终端仿真 · 命令回显 · JSON输出",
            "toolschain serve"],
    ]
    t = UI.TableSpec(
        headers=["#", "模块名", "中文名", "包含能力", "合规/数据源"],
        rows=cards, title="MODULE CATALOG",
    )
    _out(UI.render_table(t))
    _out()
    _out(UI.chip("COMPLIANCE NOTICE", "warn"))
    _out("  · 本工具箱不包含任何非法交易、黑网接入、洗钱混币等功能。\n"
         "  · 所有链上/交易所访问均为公开、只读端点。\n"
         "  · 所有加密算法均为公开标准 (NIST/OpenPGP/ISO/IEC)。\n"
         "  · 隐写模块仅用于版权水印与数字资产溯源, 不提供隐蔽通道能力。")


# ---------------------------------------------------------------------------
# CRYPTO group
# ---------------------------------------------------------------------------
@cli.group(name="crypto")
def grp_crypto():
    """加密/校验/GPG证书 子命令"""


@grp_crypto.command("checksum")
@click.argument("path", type=click.Path(exists=True, dir_okay=False))
def crypto_checksum(path):
    """计算文件的 MD5/SHA/CRC/BLAKE2b 摘要"""
    _out(UI.section(f"CRYPTO · CHECKSUM  {path}"))
    rep = CT.Checksum.of_file(path)
    _out(rep.as_table())


@grp_crypto.command("checksum-data")
@click.argument("text")
def crypto_checksum_data(text):
    """计算字符串的多哈希摘要"""
    _out(UI.section("CRYPTO · CHECKSUM (inline data)"))
    rep = CT.Checksum.of_data(text)
    _out(rep.as_table())


@grp_crypto.command("xor-enc")
@click.option("-k", "--key", required=True, help="BaseXOR 密钥")
@click.option("-i", "--input", "infile", type=click.Path(exists=True, dir_okay=False),
              help="输入文件 (与 --text 二选一)")
@click.option("-t", "--text", help="内联明文文本")
@click.option("-o", "--output", "outfile", type=click.Path(dir_okay=False),
              help="输出二进制文件 (默认打印 Base64)")
def crypto_xor_enc(key, infile, text, outfile):
    """BaseXOR 加密 (对称自逆)"""
    bx = CT.BaseXOR(key)
    data: bytes | str
    if infile:
        data = Path(infile).read_bytes()
    elif text:
        data = text
    else:
        raise click.UsageError("请提供 --input 或 --text")
    ct = bx.encrypt(data)
    if outfile:
        Path(outfile).write_bytes(ct)
        _out(UI.chip(f"写入 {outfile} ({len(ct)} bytes)", "ok"))
    else:
        _out(UI.chip("BASE64 CIPHERTEXT", "info"))
        _out(bx.encrypt_b64(data))


@grp_crypto.command("xor-dec")
@click.option("-k", "--key", required=True)
@click.option("-i", "--input", "infile", required=True,
              type=click.Path(exists=True, dir_okay=False))
@click.option("-o", "--output", "outfile", type=click.Path(dir_okay=False),
              help="写入文件; 否则打印到终端 (UTF-8)")
def crypto_xor_dec(key, infile, outfile):
    """BaseXOR 解密"""
    bx = CT.BaseXOR(key)
    blob = Path(infile).read_bytes()
    pt = bx.decrypt(blob)
    if outfile:
        Path(outfile).write_bytes(pt)
        _out(UI.chip(f"写入 {outfile} ({len(pt)} bytes)", "ok"))
    else:
        try:
            _out(pt.decode("utf-8"))
        except UnicodeDecodeError:
            _out(UI.hexdump(pt, limit=2048))


@grp_crypto.command("xor-prober")
@click.option("-i", "--input", "infile", required=True,
              type=click.Path(exists=True, dir_okay=False))
@click.option("--hint", default="The quick brown", show_default=True,
              help="已知明文片段, 用于暴力XOR识别")
def crypto_xor_prober(infile, hint):
    """BaseXOR prober — 单字节密钥暴力搜索演示 (教育用途)"""
    data = Path(infile).read_bytes()
    result = CT.BaseXOR.prober(data, hint_text=hint)
    _out(UI.section("CRYPTO · BaseXOR PROBER 结果"))
    _out(f"  扫描密钥空间: {result['total_keys_tested']}")
    if result["matches"]:
        for m in result["matches"]:
            _out(UI.chip(f"候选 key=0x{m['key']:02x} ({m['key']})", "ok"))
            _out(UI.hexdump(m["preview"]))
    else:
        _out(UI.chip("未匹配到提示片段", "warn"))


@grp_crypto.command("aes-enc")
@click.option("-k", "--key-hex",
              help="32字节密钥 (64 hex chars); 省略则随机生成并显示")
@click.option("-t", "--text", required=True)
@click.option("-a", "--aad", default="toolschain-aes-gcm", show_default=True)
def crypto_aes_enc(key_hex, text, aad):
    """AES-256-GCM 认证加密 (输出 HEX: NONCE||TAG||CT)"""
    if key_hex:
        key = bytes.fromhex(key_hex)
    else:
        key = CT.AESGCM.new_key()
        _out(UI.kv_pairs([("随机密钥(请保存)", key.hex())]))
    blob = CT.AESGCM.encrypt(key, text, aad=aad.encode())
    _out(UI.kv_pairs([("密文(HEX)", blob.hex()),
                      ("AAD标签", aad),
                      ("长度(Bytes)", str(len(blob)))]))


@grp_crypto.command("aes-dec")
@click.option("-k", "--key-hex", required=True)
@click.option("-c", "--cipher-hex", required=True)
@click.option("-a", "--aad", default="toolschain-aes-gcm")
def crypto_aes_dec(key_hex, cipher_hex, aad):
    """AES-256-GCM 解密"""
    key = bytes.fromhex(key_hex)
    blob = bytes.fromhex(cipher_hex)
    try:
        pt = CT.AESGCM.decrypt(key, blob, aad=aad.encode())
        _out(UI.chip("AUTH OK", "ok"))
        try:
            _out(pt.decode("utf-8"))
        except UnicodeDecodeError:
            _out(UI.hexdump(pt, limit=4096))
    except Exception as e:
        _out(UI.chip(f"AUTH FAIL: {e}", "err"))


@grp_crypto.group("gpg")
def grp_gpg():
    """GPG-CA 迷你证书中心 (需系统安装 `gpg` 可执行文件)"""


@grp_gpg.command("status")
@click.option("--home", default=None, help="GPG home 目录")
def gpg_status(home):
    ca = CT.GPGCA(home)
    _out(UI.section("CRYPTO · GPG-CA STATUS"))
    rows = [
        ["GPG 二进制可用", str(ca.available)],
        ["GPG home", str(ca.home)],
    ]
    if ca.available:
        keys = ca.list_keys()
        rows.append(["已加载公钥数", str(len(keys))])
        for k in keys[:8]:
            rows.append([f"  · {k.get('keyid','')}",
                         (k.get("uids") or ["<anon>"])[0][:60]])
    _out(UI.kv_pairs(rows))


@grp_gpg.command("gen-key")
@click.option("--email", required=True)
@click.option("--name", "realname", default="Toolschain User")
@click.option("--bits", type=int, default=2048, show_default=True)
@click.option("--passphrase", default=None, help="留空=无密码(仅测试)")
@click.option("--home", default=None)
def gpg_gen(email, realname, bits, passphrase, home):
    ca = CT.GPGCA(home)
    r = ca.generate_key(email, realname, key_length=bits, passphrase=passphrase)
    _out(json.dumps(r, ensure_ascii=False, indent=2))


@grp_gpg.command("sign")
@click.option("-i", "--input", "infile", required=True,
              type=click.Path(exists=True, dir_okay=False))
@click.option("-o", "--output", "outfile", required=True)
@click.option("--home", default=None)
@click.option("--passphrase", default=None)
@click.option("--keyid", default=None)
def gpg_sign(infile, outfile, home, passphrase, keyid):
    ca = CT.GPGCA(home)
    data = Path(infile).read_bytes()
    sig = ca.sign(data, passphrase=passphrase, keyid=keyid)
    Path(outfile).write_text(sig, encoding="utf-8")
    _out(UI.chip(f"签名已写入 {outfile}", "ok"))


@grp_gpg.command("verify")
@click.option("-s", "--sig-file", required=True,
              type=click.Path(exists=True, dir_okay=False))
@click.option("-i", "--input", "infile", default=None,
              type=click.Path(exists=True, dir_okay=False),
              help="原文 (若签名为分离式); 否则留空检查内嵌签名")
@click.option("--home", default=None)
def gpg_verify(sig_file, infile, home):
    ca = CT.GPGCA(home)
    sig = Path(sig_file).read_bytes()
    data = Path(infile).read_bytes() if infile else sig
    r = ca.verify(data, signature=None if infile is None else sig.decode(errors="ignore"))
    _out(json.dumps(r, ensure_ascii=False, indent=2))


# ---------------------------------------------------------------------------
# STEGO group
# ---------------------------------------------------------------------------
@cli.group(name="stego")
def grp_stego():
    """水印/隐写 子命令 (合规版: 仅版权溯源)"""


@grp_stego.command("lsb-embed")
@click.option("-i", "--input", "infile", required=True,
              type=click.Path(exists=True, dir_okay=False))
@click.option("-o", "--output", "outfile", required=True,
              type=click.Path(dir_okay=False))
@click.option("-t", "--text", required=True, help="水印文本")
@click.option("-p", "--password", default=None,
              help="AES-GCM 加密保护密码(可选)")
def stego_lsb_embed(infile, outfile, text, password):
    """PNG图像 LSB 嵌入水印文本"""
    r = STG.LSBWatermark.embed(infile, text, outfile, password=password)
    _out(UI.section("STEGO · LSB EMBED 结果"))
    _out(json.dumps(r, ensure_ascii=False, indent=2))


@grp_stego.command("lsb-extract")
@click.option("-i", "--input", "infile", required=True,
              type=click.Path(exists=True, dir_okay=False))
@click.option("-p", "--password", default=None)
def stego_lsb_extract(infile, password):
    """PNG图像 LSB 提取水印"""
    r = STG.LSBWatermark.extract(infile, password=password)
    _out(UI.section("STEGO · LSB EXTRACT"))
    if r.get("ok"):
        _out(UI.chip("水印已提取", "ok"))
        _out(UI.kv_pairs([
            ("加密保护", "是" if r.get("password_protected") else "否"),
            ("文本长度", f"{len(r['text'])} chars"),
        ]))
        _out("─── 水印内容 ───")
        _out(r["text"])
    else:
        _out(UI.chip(r.get("error", "未知错误"), "err"))


@grp_stego.command("png-meta")
@click.option("-i", "--input", "infile", required=True,
              type=click.Path(exists=True, dir_okay=False))
@click.option("--set", "set_tags", multiple=True,
              help="KEY=VALUE 格式, 可重复多次写入tEXt标签")
@click.option("-o", "--output", "outfile", default=None,
              help="修改时需指定输出路径")
def stego_png_meta(infile, set_tags, outfile):
    """PNG 元数据 tEXt/iTXt 读写 (版权标注)"""
    _out(UI.section("STEGO · PNG META"))
    if set_tags:
        if not outfile:
            raise click.UsageError("--set 需要 --output 指定输出")
        tags = {}
        for pair in set_tags:
            if "=" in pair:
                k, v = pair.split("=", 1)
                tags[k] = v
        r = STG.PNGMetaData.write(infile, tags, outfile)
        _out(json.dumps(r, ensure_ascii=False, indent=2))
    else:
        r = STG.PNGMetaData.read(infile)
        if r:
            _out(UI.kv_pairs(list(r.items())))
        else:
            _out(UI.chip("无可读tEXt标签", "warn"))


@grp_stego.command("fingerprint")
@click.option("-i", "--input", "infile", required=True,
              type=click.Path(exists=True, dir_okay=False))
@click.option("--author", required=True)
@click.option("--copyright", "copyr", required=True,
              help="例: © 2026 ACME Corp.")
@click.option("--license", "lic", default="All Rights Reserved")
@click.option("--attach-png", "out_png", default=None,
              type=click.Path(dir_okay=False),
              help="若是PNG, 可附加为tEXt元数据输出到新文件")
def stego_fingerprint(infile, author, copyr, lic, out_png):
    """生成数字资产版权指纹 Provenance Manifest"""
    report = STG.FingerprintWatermark.create(infile, author, copyr, lic)
    _out(UI.section("STEGO · PROVENANCE FINGERPRINT"))
    _out(report.to_json())
    if out_png:
        r = STG.FingerprintWatermark.attach_to_png(infile, report, out_png)
        _out(UI.chip(f"已附加为 tEXt 标签: {out_png}", "ok"))
        _out(json.dumps(r, indent=2))


# ---------------------------------------------------------------------------
# TDX group (通达信)
# ---------------------------------------------------------------------------
@cli.group(name="tdx")
def grp_tdx():
    """通达信 (TDX) 金融行情 子命令"""


@grp_tdx.command("status")
def tdx_status():
    """TDX MCP 客户端状态"""
    _out(UI.section("TDX · MCP STATUS"))
    desc = TDX.TDXMCPClient.describe()
    rows = [
        ("候选 MCP Server", ", ".join(desc["server_candidates"])),
        ("预期可用工具数", str(len(desc["known_tools"]))),
        ("可用工具列表", "\n    ".join("• " + t for t in desc["known_tools"])),
        ("认证方式", desc["auth"]),
    ]
    _out(UI.kv_pairs(rows))
    _out()
    _out(UI.chip("离线模拟器: 可用", "sim"))
    _out("  • 使用 --live 强制通过MCP查询 (需MCP授权且token有效)")


@grp_tdx.command("quote")
@click.argument("code")
@click.option("--live/--sim", default=False, show_default=True,
              help="--live 调用真实MCP; --sim 用离线模拟器")
def tdx_quote(code, live):
    """查询单只证券/指数/期货 实时行情"""
    _out(UI.section(f"TDX · QUOTE  {code}"))
    d = TDX.fetch_quote(code, use_mcp=live)
    if d["mode"] == "simulated":
        q = d["quote"]
        t = UI.TableSpec(
            headers=["代码", "名称", "最新价", "涨跌", "涨跌幅", "最高", "最低",
                     "成交量(股)", "成交额(元)"],
            rows=[[q["code"], q["name"], q["last"], q["chg"], f"{q['pct']:.2f}%",
                   q["high"], q["low"], f"{q['volume']:,}", f"{q['amount']:,.0f}"]],
            title="通达信行情 (模拟数据)",
        )
        _out(UI.render_table(t))
    else:
        _out(json.dumps(d, ensure_ascii=False, indent=2))


@grp_tdx.command("kline")
@click.argument("code")
@click.option("-d", "--days", type=int, default=30, show_default=True)
@click.option("--live/--sim", default=False)
@click.option("-o", "--csv", "csv_out", default=None,
              type=click.Path(dir_okay=False))
def tdx_kline(code, days, live, csv_out):
    """查询日线K线 (默认近30日)"""
    _out(UI.section(f"TDX · KLINE  {code}  {days}d"))
    d = TDX.fetch_kline(code, days, use_mcp=live)
    if d["mode"] == "simulated":
        rows = d["rows"]
        spark = UI.sparkline([r["close"] for r in rows], width=40)
        _out(UI.kv_pairs([
            ("代码/名称", f"{d['meta']['code']}  {d['meta']['name']}"),
            ("样本数", str(len(rows))),
            ("收盘走势", spark),
        ]))
        t = UI.TableSpec(
            headers=["日期", "开盘", "最高", "最低", "收盘", "成交量", "成交额"],
            rows=[[r["time"], r["open"], r["high"], r["low"], r["close"],
                   f"{r['volume']:,}", f"{r['amount']:,.0f}"] for r in rows[-10:]],
            title=f"最近10根K线 (共{len(rows)}日)",
        )
        _out(UI.render_table(t))
        if csv_out:
            p = TDX.TDXFallbackSimulator.export_csv(code, days, csv_out)
            _out(UI.chip(f"CSV 已导出: {p}", "ok"))
    else:
        _out(json.dumps(d, ensure_ascii=False, indent=2))


@grp_tdx.command("search")
@click.argument("keyword")
@click.option("-n", "--limit", type=int, default=10, show_default=True)
def tdx_search(keyword, limit):
    """按代码/名称/类型搜索证券"""
    d = TDX.search_market(keyword, limit)
    _out(UI.section(f"TDX · SEARCH  {keyword} (n={d['count']})"))
    rows = [[h["code"], h["name"], h["market"], h["type"]] for h in d["hits"]]
    t = UI.TableSpec(headers=["代码", "名称", "市场", "类型"], rows=rows,
                     title="证券搜索结果")
    _out(UI.render_table(t))


@grp_tdx.command("export")
@click.argument("code")
@click.option("-d", "--days", type=int, default=60)
@click.option("-o", "--output", required=True, type=click.Path(dir_okay=False))
def tdx_export(code, days, output):
    """导出CSV K线文件"""
    p = TDX.TDXFallbackSimulator.export_csv(code, days, output)
    _out(UI.chip(f"CSV 导出成功: {p}", "ok"))


# ---------------------------------------------------------------------------
# OKX group
# ---------------------------------------------------------------------------
@cli.group(name="okx")
def grp_okx():
    """OKX 加密货币公开行情 (仅公开只读端点)"""


@grp_okx.command("ticker")
@click.argument("pair", default="BTC-USDT")
@click.option("--live/--sim", default=True, show_default=True)
def okx_ticker(pair, live):
    """查询现货/合约 24h Ticker"""
    _out(UI.section(f"OKX · TICKER  {pair}"))
    d = OKX.get_ticker(pair, use_network=live)
    t = d["ticker"]
    _out(UI.chip(f"数据源: {d['mode']}",
                 "ok" if d["mode"] == "okx-live" else "sim"))
    _out(UI.kv_pairs([
        ("最新价", f"{t['last']:.6g}"),
        ("24h 涨跌", f"{t['chg']:+.6g}   ({t['pct']:+.2f}%)"),
        ("24h 最高", f"{t['high24h']:.6g}"),
        ("24h 最低", f"{t['low24h']:.6g}"),
        ("24h 成交量(币)", f"{t['vol24h']:,.4g}"),
        ("24h 成交额(USDT)", f"{t['volCcy24h']:,.0f}"),
        ("买一/卖一", f"{t['bid']:.6g} / {t['ask']:.6g}"),
        ("更新时间", str(t["ts"])),
    ]))


@grp_okx.command("candles")
@click.argument("pair", default="BTC-USDT")
@click.option("--bar", default="1H", show_default=True,
              type=click.Choice(["1m", "5m", "15m", "1H", "4H", "1D"]))
@click.option("-n", "--limit", type=int, default=48, show_default=True)
@click.option("--live/--sim", default=True)
def okx_candles(pair, bar, limit, live):
    """OKX K线 (含sparkline)"""
    _out(UI.section(f"OKX · CANDLES  {pair}  bar={bar}  n={limit}"))
    d = OKX.get_candles(pair, bar, limit, use_network=live)
    _out(UI.chip(f"数据源: {d['mode']}",
                 "ok" if d["mode"] == "okx-live" else "sim"))
    rows = d["rows"]
    if rows:
        closes = [r["close"] for r in rows]
        _out(UI.kv_pairs([
            ("样本数", str(len(rows))),
            ("收盘价走势", UI.sparkline(closes, width=48)),
            ("区间最高", f"{max(r['high'] for r in rows):.6g}"),
            ("区间最低", f"{min(r['low'] for r in rows):.6g}"),
        ]))
        last10 = rows[-10:]
        t = UI.TableSpec(
            headers=["时间(UTC)", "开盘", "最高", "最低", "收盘", "成交量", "成交额"],
            rows=[[r["ts"], r["open"], r["high"], r["low"], r["close"],
                   f"{r['volume']:.4g}", f"{r['volCcy']:,.0f}"] for r in last10],
            title=f"最近10根K线 {bar}",
        )
        _out(UI.render_table(t))


@grp_okx.command("top")
@click.option("-n", type=int, default=8, show_default=True)
@click.option("--live/--sim", default=True)
def okx_top(n, live):
    """主流币 24h 行情列表"""
    _out(UI.section("OKX · TOP TICKERS"))
    d = OKX.top_tickers(n, use_network=live)
    _out(UI.chip(f"数据源: {d['mode']}",
                 "ok" if d["mode"] == "okx-live" else "sim"))
    t = UI.TableSpec(
        headers=["交易对", "最新价", "涨跌", "涨跌幅", "24h最高", "24h最低",
                 "24h量(币)", "24h额(USDT)"],
        rows=[
            [t_["inst_id"], f"{t_['last']:.6g}",
             f"{t_['chg']:+.6g}", f"{t_['pct']:+.2f}%",
             f"{t_['high24h']:.6g}", f"{t_['low24h']:.6g}",
             f"{t_['vol24h']:,.4g}", f"{t_['volCcy24h']:,.0f}"]
            for t_ in d["tickers"]
        ],
        title=f"OKX TOP {len(d['tickers'])}",
    )
    _out(UI.render_table(t))


# ---------------------------------------------------------------------------
# CHAIN group
# ---------------------------------------------------------------------------
@cli.group(name="chain")
def grp_chain():
    """公开区块链数据探针 (BTC / ETH 只读)"""


@grp_chain.command("block")
@click.argument("height", type=int)
@click.option("--chain",
              type=click.Choice(["BTC", "ETH", "sim"]), default="sim",
              show_default=True,
              help="sim=离线确定性模拟 (无网络可用)")
@click.option("--api-key", default=None, help="Etherscan API key (可选, 也可从环境变量 ETHERSCAN_API_KEY)")
@click.option("--rpc", default=None, help="ETH JSON-RPC (也可从 ETH_RPC_URL)")
def chain_block(height, chain, api_key, rpc):
    """查询区块头摘要"""
    _out(UI.section(f"CHAIN · BLOCK  #{height:,}  ({chain})"))
    blk = None
    if chain == "BTC":
        blk = CHAIN.BTCProber().block(height)
        if not blk:
            _out(UI.chip("Blockchair API 受限或失败, 回退模拟", "warn"))
    if chain == "ETH":
        blk = CHAIN.ETHProber(api_key=api_key, rpc=rpc).block(height)
        if not blk:
            _out(UI.chip("Etherscan/RPC 失败, 回退模拟", "warn"))
    if blk is None:
        blk = CHAIN.ChainSimulator.block(chain if chain in ("BTC", "ETH") else "BTC", height)
        _out(UI.chip("数据源: SIM", "sim"))
    t = UI.TableSpec(
        headers=["链", "高度", "Hash", "PrevHash", "时间", "交易数", "大小"],
        rows=[blk.as_row()], title=f"区块 #{blk.height:,} 摘要",
    )
    _out(UI.render_table(t))
    if blk.miner or blk.difficulty:
        _out(UI.kv_pairs([
            ("矿工/出块者", str(blk.miner)),
            ("难度", f"{blk.difficulty:,.0f}" if blk.difficulty else "N/A"),
        ]))


@grp_chain.command("balance")
@click.argument("address")
@click.option("--chain", type=click.Choice(["BTC", "ETH"]), default="BTC",
              show_default=True)
@click.option("--api-key", default=None)
@click.option("--rpc", default=None)
def chain_balance(address, chain, api_key, rpc):
    """查询公开地址余额 (公开API / 公开RPC)"""
    _out(UI.section(f"CHAIN · BALANCE  {address}  ({chain})"))
    if chain == "BTC":
        r = CHAIN.BTCProber().address_balance(address)
    else:
        r = CHAIN.ETHProber(api_key=api_key, rpc=rpc).address_balance(address)
    if "error" in r:
        _out(UI.chip(r["error"], "warn"))
    else:
        _out(UI.kv_pairs(list(r.items())))


@grp_chain.command("audit")
@click.option("--chain", type=click.Choice(["BTC", "ETH"]), default="BTC")
@click.option("--start", type=int, required=True, help="起始高度")
@click.option("--count", type=int, default=10, show_default=True)
@click.option("--use-sim/--no-sim", default=True,
              help="--use-sim 用离线模拟器 (默认快); --no-sim 访问真实链")
def chain_audit(chain, start, count, use_sim):
    """区块 prev_hash 一致性审计 (N个连续块)"""
    _out(UI.section(f"CHAIN · AUDIT  {chain}  #{start:,} → #{start+count-1:,}"))
    blocks = []
    for h in range(start, start + count):
        if use_sim:
            blocks.append(CHAIN.ChainSimulator.block(chain, h))
        elif chain == "BTC":
            b = CHAIN.BTCProber().block(h) or CHAIN.ChainSimulator.block(chain, h)
            blocks.append(b)
        else:
            b = CHAIN.ETHProber().block(h) or CHAIN.ChainSimulator.block(chain, h)
            blocks.append(b)
    result = CHAIN.block_hash_consistency(blocks)
    t = UI.TableSpec(
        headers=["链", "高度", "Hash", "PrevHash", "时间", "交易数", "大小"],
        rows=[b.as_row() for b in blocks],
        title=f"区块一致性审计样本 ({len(blocks)}块)",
    )
    _out(UI.render_table(t))
    status = UI.chip("CONSISTENT ✓", "ok") if result["consistent"] else UI.chip("BROKEN ✗", "err")
    _out(UI.kv_pairs([
        ("审计状态", status),
        ("检查块数", str(result["count_checked"])),
        ("发现问题", "\n    " + "\n    ".join(result["issues"]) if result["issues"] else "(无)"),
    ]))


# ---------------------------------------------------------------------------
# SERVE: Web CLI-Site dashboard
# ---------------------------------------------------------------------------
@cli.command("serve")
@click.option("--host", default="127.0.0.1", show_default=True)
@click.option("--port", type=int, default=7890, show_default=True)
@click.option("--debug/--no-debug", default=False)
def cmd_serve(host, port, debug):
    """启动 Web CLI-Site 仪表盘 (Flask)"""
    try:
        from .web_app import create_app  # noqa: F401
    except Exception as e:
        _out(UI.chip(f"加载 web_app 失败: {e}", "warn"))
    app_file = Path(__file__).parent / "web_app.py"
    if app_file.exists():
        import importlib.util as _u
        spec = _u.spec_from_file_location("web_app", app_file)
        mod = _u.module_from_spec(spec)
        assert spec and spec.loader
        spec.loader.exec_module(mod)
        app = mod.create_app()
    else:
        _out(UI.chip("未找到 web_app.py, 使用最小Flask stub", "warn"))
        from flask import Flask, jsonify
        app = Flask(__name__)
        @app.get("/")
        def _i():
            return ("<h1>Toolschain Box Web Stub</h1>"
                    "<p>请完整安装 web_app.py 以启用仪表盘。</p>")
        @app.get("/api/health")
        def _h():
            return jsonify({"ok": True, "ts": int(time.time())})
    _out(UI.banner("TOOLCHAIN BOX · WEB CLI-SITE",
                   f"http://{host}:{port}/  debug={debug}"))
    app.run(host=host, port=port, debug=debug)


# ---------------------------------------------------------------------------
# Entry for `python -m toolschain`
# ---------------------------------------------------------------------------
def main():
    cli(obj={})


if __name__ == "__main__":
    main()
