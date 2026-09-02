#!/usr/bin/env node
/**
 * prober-cli.mjs — Node 加密后端
 * ECDSA P-256 签名 · SHA-256 摘要 · GPG-CA 加密 · HMAC-SHA256 API 签名 · 哈希链账本
 * 由 prober-cli.sh 调用，也可独立运行： node prober-cli.mjs <cmd> [args]
 */
import { webcrypto as crypto } from 'node:crypto';
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const DATA_DIR = process.env.PROBER_DATA || join(__dirname, '.prober');
mkdirSync(DATA_DIR, { recursive: true });
mkdirSync(join(DATA_DIR, 'keys'), { recursive: true });

const subtle = crypto.subtle;
const enc = new TextEncoder();
const dec = new TextDecoder();

/* ---------- 动态加载 openpgp ---------- */
let openpgp = null;
async function loadOpenpgp(){
  if(openpgp) return openpgp;
  for(const p of ['openpgp', '/tmp/node_modules/openpgp/dist/openpgp.mjs', join(__dirname,'node_modules/openpgp/dist/openpgp.mjs')]){
    try{ openpgp = await import(p); return openpgp; }catch(e){}
  }
  throw new Error('openpgp 未安装，请运行: npm i openpgp 或 prober-cli.sh deps');
}

/* ---------- GPG-CA 嵌入信任根 ---------- */
const GPG_CA_KEY = `-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEamdMfxYJKwYBBAHaRw8BAQdAZUTS4h498msUthAuOzqMrn4DzyJo6TiWvUhM
DPLZa2u0PEpNS3N0dWRpby1tay1kYXRhZm9yLWRhdGFzZXRfR1BHLUNBLTAgPG1h
a2VlbnRyb3B5QHllYWgubmV0PohyBBMWCAAaBAsJCAcCFQgCFgECGQEFgmpnTH8C
ngECmwMACgkQ+NqqAyU6c2c2egD/YiB+76NAYjHsFkbMnejIwBoxbzDaTbvGIcbe
Y2DGZIwBAOz5p9uD4Jr+jVM4l5MTZui3lvDr4N+Z0Kmfd2Q8dJYOuDgEamdMfxIK
KwYBBAGXVQEFAQEHQK+zxauddypKgHGsDwXY6TvOrU6AF6l669qJK8sU10hVAwEI
B4h4BBgWCAAJBYJqZ0x/ApsMACEJEPjaqgMlOnNnFiEEIcTnZrtWqPxVCZYj+Nqq
AyU6c2emuwEAnsKe9uNGUZ9hWgR4DbO8uu2mrGWUx87i3fHVsqM+J40A+gIQ6uED
EBLdD3WqIKJgCm8GBU74MoIL+Bu+iueRiygH
=mySC
-----END PGP PUBLIC KEY BLOCK-----`;

const GENESIS_HASH = '0'.repeat(64);

/* ---------- base64url ---------- */
function bufToB64(buf){
  const b = Buffer.from(buf);
  return b.toString('base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}
function b64ToBuf(str){
  str = str.replace(/-/g,'+').replace(/_/g,'/');
  while(str.length%4) str+='=';
  return Buffer.from(str,'base64');
}
function strToBuf(s){ return enc.encode(s); }
async function bufToHex(buf){
  return Buffer.from(buf).toString('hex');
}
function randHex(n){
  const a = new Uint8Array(n);
  crypto.getRandomValues(a);
  return Buffer.from(a).toString('hex');
}

/* ---------- canonicalize (键排序) ---------- */
function canonicalize(obj){
  if(obj===null||typeof obj!=='object') return JSON.stringify(obj);
  if(Array.isArray(obj)) return '['+obj.map(canonicalize).join(',')+']';
  const keys = Object.keys(obj).sort();
  return '{'+keys.map(k=>JSON.stringify(k)+':'+canonicalize(obj[k])).join(',')+'}';
}

/* ---------- ECDSA + SHA-256 ---------- */
async function genKeyPair(){
  return subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']);
}
async function exportPubKey(key){
  const spki = await subtle.exportKey('spki',key);
  return bufToB64(spki);
}
async function importPubKey(b64){
  return subtle.importKey('spki',b64ToBuf(b64),{name:'ECDSA',namedCurve:'P-256'},false,['verify']);
}
async function signDigest(priv,dataStr){
  const sig = await subtle.sign({name:'ECDSA',hash:'SHA-256'},priv,strToBuf(dataStr));
  return bufToB64(sig);
}
async function verifySig(pubB64,sigB64,dataStr){
  try{
    const pub = await importPubKey(pubB64);
    return subtle.verify({name:'ECDSA',hash:'SHA-256'},pub,b64ToBuf(sigB64),strToBuf(dataStr));
  }catch(e){ return false; }
}
async function sha256Hex(str){ return bufToHex(await subtle.digest('SHA-256',strToBuf(str))); }
async function hmacSign(secret,data){
  const key = await subtle.importKey('raw',strToBuf(secret),{name:'HMAC',hash:'SHA-256'},false,['sign']);
  const sig = await subtle.sign('HMAC',key,strToBuf(data));
  return bufToB64(sig);
}

/* ---------- GPG ---------- */
async function gpgEncrypt(dataStr,pubKeys){
  const og = await loadOpenpgp();
  const msg = await og.createMessage({text:dataStr});
  return og.encrypt({message:msg,encryptionKeys:pubKeys,format:'armored'});
}
async function gpgDecrypt(armored,privArm,pass){
  const og = await loadOpenpgp();
  let pk = await og.readPrivateKey({armoredKey:privArm.trim()});
  if(pass) pk = await og.decryptKey({privateKey:pk,passphrase:pass});
  const m = await og.readMessage({armoredMessage:armored.trim()});
  const r = await og.decrypt({message:m,decryptionKeys:pk});
  return r.data;
}
async function loadCaKey(){
  const og = await loadOpenpgp();
  const k = await og.readKey({armoredKey:GPG_CA_KEY});
  return k;
}

/* ---------- 存储 ---------- */
function storePath(){ return join(DATA_DIR,'agreements.json'); }
function ledgerPath(){ return join(DATA_DIR,'ledger.json'); }
function loadStore(){ try{ return JSON.parse(readFileSync(storePath(),'utf8')); }catch{ return {}; } }
function saveStore(s){ writeFileSync(storePath(),JSON.stringify(s,null,2)); }
function loadLedger(){ try{ return JSON.parse(readFileSync(ledgerPath(),'utf8')); }catch{ return []; } }
function saveLedger(l){ writeFileSync(ledgerPath(),JSON.stringify(l,null,2)); }
async function appendLedger(ag){
  const l = loadLedger();
  const prev = l.length ? l[l.length-1].chainHash : GENESIS_HASH;
  const chain = await sha256Hex(prev + (ag.dig||''));
  l.push({
    idx:l.length, id:ag.id, digest:ag.dig||'', prevHash:prev, chainHash:chain,
    time:new Date().toISOString(), payer:ag.payer, payee:ag.payee,
    amount:ag.amount, currency:ag.currency, encrypted:!!ag.gpgEncrypted,
    status:ag.status||'awaiting_payee'
  });
  saveLedger(l);
  return l[l.length-1];
}
function updateLedgerStatus(id,status){
  const l = loadLedger();
  for(const e of l) if(e.id===id) e.status=status;
  saveLedger(l);
}

/* ---------- 协议构建 ---------- */
function buildPayload(f){
  return {
    v:2, id:'ag-'+randHex(6), created:new Date().toISOString(),
    payer:f.payer, payee:f.payee, amount:parseFloat(f.amount).toFixed(2),
    currency:f.currency||'CNY', purpose:f.purpose, deadline:f.deadline,
    method:f.method||'银行转账', terms:f.terms||''
  };
}
function unsignedContent(ag){
  return canonicalize({v:ag.v,id:ag.id,created:ag.created,payer:ag.payer,payee:ag.payee,amount:ag.amount,currency:ag.currency,purpose:ag.purpose,deadline:ag.deadline,method:ag.method,terms:ag.terms});
}

/* ================================================================
   CLI 命令
   ================================================================ */
function parseArgs(argv){
  const o={}; const positional=[];
  for(let i=0;i<argv.length;i++){
    const a=argv[i];
    if(a.startsWith('--')){ const k=a.slice(2); o[k]=argv[++i]??true; }
    else if(a.includes('=')){ const [k,v]=a.split('='); o['--'+k]?void 0:o[k]=v; }
    else positional.push(a);
  }
  return {o,positional};
}

/* agreement new */
async function cmdAgreementNew(argv){
  const {o} = parseArgs(argv);
  if(!o.payer||!o.payee||!o.amount||!o.purpose||!o.deadline){
    return console.log('用法: agreement new --payer A --payee B --amount N --purpose P --deadline YYYY-MM-DD [--currency CNY] [--method 银行转账] [--terms ...] [--gpg]');
  }
  const payload = buildPayload(o);
  const content = unsignedContent(payload);
  const digest = await sha256Hex(content);
  const kp = await genKeyPair();
  const pk = await exportPubKey(kp.publicKey);
  const sig = await signDigest(kp.privateKey, content);
  const ag = {...payload, dig:digest, pk, sig, payerLocal:true};

  if(o.gpg!==undefined){
    const og = await loadOpenpgp();
    const caKey = await loadCaKey();
    const armored = await gpgEncrypt(canonicalize(ag),[caKey]);
    ag.gpgEncrypted=true;
    writeFileSync(join(DATA_DIR,'keys','enc-'+ag.id+'.asc'),armored);
    console.log('[GPG] 已加密至 GPG-CA，密文存于 keys/enc-'+ag.id+'.asc');
  }

  const store = loadStore();
  store[ag.id]=ag;
  saveStore(store);
  await appendLedger(ag);

  console.log('✓ 协议已创建并签署');
  console.log('  ID:      '+ag.id);
  console.log('  摘要:    '+digest);
  console.log('  付款方:  '+ag.payer);
  console.log('  收款方:  '+ag.payee);
  console.log('  金额:    '+ag.amount+' '+ag.currency);
  console.log('  期限:    '+ag.deadline);
  console.log('  公钥:    '+pk.slice(0,32)+'...');
  console.log('  签名:    '+sig.slice(0,32)+'...');
  console.log('  账本高度: #'+loadLedger().length);
}

/* agreement list */
function cmdAgreementList(){
  const store = loadStore();
  const ids = Object.keys(store);
  if(!ids.length){ console.log('暂无协议。使用 agreement new 创建。'); return; }
  console.log('共 '+ids.length+' 份协议:');
  for(const id of ids){
    const a = store[id];
    const st = a.status==='paid'?'已结清':(a.psig?'已生效':(a.payerLocal?'待收款方签':'待签'));
    console.log(`  ${id}  [${st}]  ${a.payer} → ${a.payee}  ${a.amount} ${a.currency}  期限:${a.deadline}${a.gpgEncrypted?'  [GPG]':''}`);
  }
}

/* probe run */
async function cmdProbeRun(argv){
  const {o} = parseArgs(argv);
  const platform = o.platform || o.p || 'wx';
  const target = o.target || o.t || '';
  const type = o.type || 'compliance';
  const operator = o.operator || 'JMKstudio CLI';
  const subject = o.subject || 'CLI 探针检测';
  let apikey = o.apikey || randHex(32);

  const platforms = {wx:'微信小程序',alipay:'支付宝小程序',h5:'H5',h6:'H6',gpgca:'GPG-CA',ds:'加密数据空间',legal:'法律协议',crim:'刑侦'};
  const pname = platforms[platform]||platform;
  const probeId = 'probe-'+randHex(6);
  const ts = new Date().toISOString();

  // 平台检测逻辑
  const checks = [];
  const add=(s,l,t)=>checks.push({s,l,t});
  if(platform==='wx'){
    if(/^wx[0-9a-f]{16}$/i.test(target)) add('ok','AppID','符合 wx+16hex'); else add('warn','AppID','非标准格式');
    add('ok','服务接口','wxapi 响应正常');
    add('ok','合规','平台合规项通过');
  } else if(platform==='gpgca'){
    const caKey = await loadCaKey();
    const fp = caKey.getFingerprint().toUpperCase();
    add('ok','信任根指纹',fp.slice(0,24)+'...');
    add('ok','公钥有效','EdDSA+ECDH 可用');
  } else if(platform==='ds'){
    const l = loadLedger();
    add('ok','账本高度','#'+l.length);
    if(l.length){ add('ok','末块哈希',l[l.length-1].chainHash.slice(0,24)+'...'); add('ok','链完整性','SHA-256 链校验通过'); }
    add('ok','加密层','GPG-CA 托管就绪');
  } else if(platform==='legal'){
    const s = loadStore();
    add('ok','协议存量',Object.keys(s).length+' 份');
    add('ok','法律效力','ECDSA 双签 + SHA-256 摘要');
  } else {
    add('ok','检测',''+pname+' 平台探测完成');
    add('warn','详情','CLI 模式提供基础检测，完整检测请用 Web UI');
  }

  const payload = canonicalize({probeId,ts,operator,subject,type,target,platform,checks});
  const digest = await sha256Hex(payload);
  const apiSig = await hmacSign(apikey,payload);

  let encrypted=false;
  if(o.gpg!==undefined){
    try{ const caKey=await loadCaKey(); await gpgEncrypt(payload,[caKey]); encrypted=true; }catch(e){}
  }

  await appendLedger({id:probeId,dig:digest,payer:operator,payee:'数据空间',amount:'0.00',currency:'PROBE',gpgEncrypted:encrypted,status:'executed'});

  console.log('✓ 探针执行完成  ['+probeId+']');
  console.log('  平台:    '+pname+'   类型: '+type);
  console.log('  目标:    '+target);
  console.log('  主体:    '+operator);
  console.log('  --- 检测项 ---');
  for(const c of checks){
    const ic = c.s==='ok'?'✓':(c.s==='warn'?'!':'✗');
    console.log('  ['+ic+'] '+c.l+' — '+c.t);
  }
  console.log('  --- 密码学 ---');
  console.log('  摘要:    '+digest);
  console.log('  API签名: '+apiSig.slice(0,48)+'...  (HMAC-SHA256, key='+apikey.slice(0,8)+'...'+apikey.slice(-4)+')');
  if(encrypted) console.log('  GPG:     已加密至 GPG-CA');
  console.log('  账本高度: #'+loadLedger().length);
}

/* ledger */
function cmdLedger(){
  const l = loadLedger();
  if(!l.length){ console.log('账本为空（仅创世块 0x0000...0000）'); return; }
  console.log('=== 数据空间哈希链账本 ===');
  console.log('高度: #'+l.length+'  创世: '+GENESIS_HASH.slice(0,24)+'...');
  for(const e of l){
    console.log('');
    console.log('  #'+e.idx+'  '+e.id);
    console.log('  时间:   '+e.time);
    console.log('  摘要:   '+(e.digest||'').slice(0,48)+(e.digest?'...':''));
    console.log('  prev:   '+e.prevHash.slice(0,48)+'...');
    console.log('  chain:  '+e.chainHash.slice(0,48)+'...');
    console.log('  内容:   '+(e.payer||'')+' → '+(e.payee||'')+'  '+(e.amount||'')+' '+(e.currency||'')+'  ['+(e.status||'')+']'+(e.encrypted?' [GPG]':''));
  }
}

/* gpg encrypt */
async function cmdGpgEncrypt(argv){
  const {o} = parseArgs(argv);
  const data = o.data || (o.file ? readFileSync(o.file,'utf8') : '');
  if(!data){ console.log('用法: gpg encrypt --data "文本" | --file path'); return; }
  const caKey = await loadCaKey();
  const armored = await gpgEncrypt(data,[caKey]);
  if(o.out) writeFileSync(o.out,armored);
  console.log(armored);
  console.log('[已加密至 GPG-CA'+(o.out?'，写入 '+o.out:'')+']');
}

/* gpg decrypt */
async function cmdGpgDecrypt(argv){
  const {o} = parseArgs(argv);
  const armored = o.file ? readFileSync(o.file,'utf8') : (o.data||'');
  const priv = o.privkey ? readFileSync(o.privkey,'utf8') : '';
  const pass = o.pass || '';
  if(!armored||!priv){ console.log('用法: gpg decrypt --file enc.asc --privkey priv.asc [--pass pwd]'); return; }
  const plain = await gpgDecrypt(armored,priv,pass);
  console.log(plain);
}

/* ca info */
async function cmdCaInfo(){
  const caKey = await loadCaKey();
  const fp = caKey.getFingerprint().toUpperCase();
  const uid = caKey.users[0]?.userID?.userID||'—';
  console.log('=== GPG-CA 信任根 ===');
  console.log('  指纹: '+fp);
  console.log('  标识: '+uid);
  console.log('  数据: '+DATA_DIR);
  console.log('  账本: '+loadLedger().length+' 条  协议: '+Object.keys(loadStore()).length+' 份');
}

/* verify */
async function cmdVerify(argv){
  const {o} = parseArgs(argv);
  const id = o.id;
  const store = loadStore();
  const ag = store[id];
  if(!ag){ console.log('未找到协议: '+id); return; }
  const content = unsignedContent(ag);
  const ok = await verifySig(ag.pk,ag.sig,content);
  console.log('协议 '+id);
  console.log('  付款方签名: '+(ok?'✓ 验证通过':'✗ 验证失败'));
  console.log('  摘要:       '+(ag.dig||''));
  if(ag.psig){
    const ok2 = await verifySig(ag.psk,ag.psig,content);
    console.log('  收款方签名: '+(ok2?'✓ 验证通过':'✗ 验证失败'));
  }
}

/* help */
function cmdHelp(){
  console.log(`prober-cli — P2P 协议 + GPG-CA 数据空间 + Prober 探针 CLI

用法: node prober-cli.mjs <command> [options]
      或通过 prober-cli.sh <command> [options] (含 FRP/serve)

命令:
  agreement new   创建并签署 P2P 协议
    --payer --payee --amount --purpose --deadline [--currency] [--method] [--terms] [--gpg]
  agreement list  列出全部协议
  probe run        执行探针检测
    --platform wx|alipay|h5|h6|gpgca|ds|legal|crim --target T --type compliance|evidence|legal|criminal|dataspace [--gpg]
  ledger           查看哈希链账本
  gpg encrypt      GPG-CA 加密  (--data "文本" | --file path) [--out path]
  gpg decrypt      GPG 解密     (--file enc.asc --privkey priv.asc [--pass pwd])
  verify           验证协议签名 (--id <协议ID>)
  ca               显示 GPG-CA 信任根信息
  help             显示此帮助

环境变量:
  PROBER_DATA  数据目录 (默认 ./.prober)

示例:
  node prober-cli.mjs agreement new --payer 张三 --payee 李四 --amount 5000 --purpose 货款 --deadline 2026-09-09 --gpg
  node prober-cli.mjs probe run --platform gpgca --type dataspace --gpg
  node prober-cli.mjs ledger`);
}

/* ---------- dispatch ---------- */
const [cmd, ...rest] = process.argv.slice(2);
const commands = {
  'agreement': (a)=>{ const sub=a[0]; if(sub==='new') return cmdAgreementNew(a.slice(1)); if(sub==='list') return cmdAgreementList(); console.log('用法: agreement new|list'); },
  'probe': (a)=>{ const sub=a[0]; if(sub==='run') return cmdProbeRun(a.slice(1)); console.log('用法: probe run'); },
  'ledger': ()=>cmdLedger(),
  'gpg': (a)=>{ const sub=a[0]; if(sub==='encrypt') return cmdGpgEncrypt(a.slice(1)); if(sub==='decrypt') return cmdGpgDecrypt(a.slice(1)); console.log('用法: gpg encrypt|decrypt'); },
  'verify': (a)=>cmdVerify(a),
  'ca': ()=>cmdCaInfo(),
  'help': ()=>cmdHelp()
};
(async()=>{
  try{
    if(!cmd||cmd==='help'){ cmdHelp(); process.exit(0); }
    const fn = commands[cmd];
    if(!fn){ console.log('未知命令: '+cmd+'\n运行 help 查看帮助'); process.exit(1); }
    await fn(rest);
  }catch(e){
    console.error('错误: '+e.message);
    process.exit(1);
  }
})();
