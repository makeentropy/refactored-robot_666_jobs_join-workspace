#!/usr/bin/env bash
# ================================================================
# prober-cli.sh — P2P 协议 + GPG-CA 数据空间 + Prober 探针 统一 CLI
# 编排层: gen / serve / frp / deps + 委托 prober-cli.mjs 处理密码学
# ================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NODE_BIN="${SCRIPT_DIR}/prober-cli.mjs"
DATA_DIR="${PROBER_DATA:-${SCRIPT_DIR}/.prober}"
FRP_DIR="${SCRIPT_DIR}/.frp"
FRPC_BIN="${FRP_DIR}/frpc"
FRPC_CFG="${FRP_DIR}/frpc.toml"
FRPC_PID="${FRP_DIR}/frpc.pid"
PORT="${PROBER_PORT:-8080}"
export PROBER_DATA="${DATA_DIR}"

# ---------- 颜色 ----------
if [[ -t 1 ]]; then
  C_G='\033[32m'; C_Y='\033[33m'; C_C='\033[36m'; C_R='\033[31m'; C_P='\033[35m'; C_0='\033[0m'
else
  C_G=''; C_Y=''; C_C=''; C_R=''; C_P=''; C_0=''
fi
log(){ printf "${C_C}[prober]${C_0} %s\n" "$*"; }
ok(){  printf "${C_G}[ok]${C_0} %s\n" "$*"; }
warn() { printf "${C_Y}[!]${C_0} %s\n" "$*"; }
err(){ printf "${C_R}[err]${C_0} %s\n" "$*" >&2; }

# ---------- 委托 Node 后端 ----------
run_node(){ node "${NODE_BIN}" "$@"; }

# ---------- deps: 安装 openpgp ----------
cmd_deps(){
  log "安装依赖 openpgp@5.11.0 ..."
  mkdir -p "${SCRIPT_DIR}/node_modules"
  if [[ -d /tmp/node_modules/openpgp ]]; then
    ln -sf /tmp/node_modules/openpgp "${SCRIPT_DIR}/node_modules/openpgp" 2>/dev/null || true
    ln -sf /tmp/node_modules/@openpgp "${SCRIPT_DIR}/node_modules/@openpgp" 2>/dev/null || true
    ok "openpgp 已链接 (来自 /tmp/node_modules)"
  else
    (cd "${SCRIPT_DIR}" && npm install openpgp@5.11.0 --no-save --silent 2>/dev/null) && ok "openpgp 已安装" || err "npm 安装失败，请手动 npm i openpgp"
  fi
  node -e "require('openpgp'); console.log('openpgp 可用')" 2>/dev/null && ok "依赖就绪" || warn "openpgp 暂未就绪，GPG 命令可能失败"
}

# ---------- gen: 生成/初始化应用 ----------
cmd_gen(){
  log "生成应用 (JMKstudio Prober + P2P 协议) ..."
  mkdir -p "${DATA_DIR}/keys"
  [[ -f "${SCRIPT_DIR}/index.html" ]] && ok "index.html 已存在" || { err "index.html 不存在"; return 1; }
  # 初始化数据文件
  [[ -f "${DATA_DIR}/agreements.json" ]] || echo '{}' > "${DATA_DIR}/agreements.json"
  [[ -f "${DATA_DIR}/ledger.json" ]] || echo '[]' > "${DATA_DIR}/ledger.json"
  cmd_deps
  ok "应用已就绪"
  echo ""
  echo "  数据目录:   ${DATA_DIR}"
  echo "  Web 应用:   ${SCRIPT_DIR}/index.html"
  echo "  CLI 后端:   ${NODE_BIN}"
  echo "  端口:       ${PORT}"
  echo ""
  echo "  下一步:"
  echo "    ${0} serve           # 启动本地服务"
  echo "    ${0} agreement new --payer A --payee B --amount 100 --purpose 测试 --deadline 2026-09-09"
  echo "    ${0} frp init        # 配置 FRP 公链"
}

# ---------- serve: 本地 HTTP 服务 ----------
SERVE_PID=""
cmd_serve(){
  local port="${1:-${PORT}}"
  log "启动本地 HTTP 服务 (端口 ${port}) ..."
  cd "${SCRIPT_DIR}"
  # 优先 python3，回退 node
  if command -v python3 &>/dev/null; then
    nohup python3 -m http.server "${port}" --bind 0.0.0.0 > "${DATA_DIR}/serve.log" 2>&1 &
    SERVE_PID=$!
  else
    nohup node -e "require('http').createServer((q,s)=>{const f=require('fs');const p='.'+q.url;f.readFile(p,(e,d)=>s.writeHead(e?404:200);s.end(e?'not found':d))}).listen(${port})" > "${DATA_DIR}/serve.log" 2>&1 &
    SERVE_PID=$!
  fi
  echo "${SERVE_PID}" > "${DATA_DIR}/serve.pid"
  sleep 1
  if kill -0 "${SERVE_PID}" 2>/dev/null; then
    ok "服务已启动: http://localhost:${port}  (PID ${SERVE_PID})"
    log "日志: ${DATA_DIR}/serve.log   停止: ${0} stop"
  else
    err "服务启动失败，查看日志: ${DATA_DIR}/serve.log"
    return 1
  fi
}

cmd_stop(){
  local pid_file="${DATA_DIR}/serve.pid"
  if [[ -f "${pid_file}" ]]; then
    local pid; pid=$(cat "${pid_file}")
    kill "${pid}" 2>/dev/null && ok "本地服务已停止 (PID ${pid})" || warn "服务未运行"
    rm -f "${pid_file}"
  else
    warn "未找到服务 PID 文件"
  fi
}

# ---------- FRP 公链 ----------
frp_arch(){
  case "$(uname -m)" in
    x86_64)  echo "amd64" ;;
    aarch64|arm64) echo "arm64" ;;
    *) echo "amd64" ;;
  esac
}

cmd_frp_init(){
  mkdir -p "${FRP_DIR}"
  log "FRP 公链配置 ..."
  # 下载 frpc
  if [[ ! -x "${FRPC_BIN}" ]]; then
    local arch; arch=$(frp_arch)
    # 自动探测最新版本，回退 0.61.0
    local ver="0.61.0"
    local url="https://github.com/fatedier/frp/releases/download/v${ver}/frp_${ver}_linux_${arch}.tar.gz"
    log "下载 frpc v${ver} (${arch}) ..."
    if curl -sL -o "${FRP_DIR}/frp.tar.gz" "${url}" && tar -xzf "${FRP_DIR}/frp.tar.gz" -C "${FRP_DIR}" 2>/dev/null; then
      cp "${FRP_DIR}/frp_${ver}_linux_${arch}/frpc" "${FRPC_BIN}" 2>/dev/null || \
        find "${FRP_DIR}" -name frpc -type f -exec cp {} "${FRPC_BIN}" \; 2>/dev/null
      chmod +x "${FRPC_BIN}" 2>/dev/null || true
      rm -f "${FRP_DIR}/frp.tar.gz"
      [[ -x "${FRPC_BIN}" ]] && ok "frpc 已下载" || { warn "下载失败，将使用配置模板"; }
    else
      warn "无法下载 frpc（网络受限）。可手动放置 frpc 至 ${FRPC_BIN}"
    fi
  else
    ok "frpc 已存在"
  fi

  # 生成配置
  local server_addr="${FRP_SERVER:-free.frp.io}"
  local server_port="${FRP_PORT:-7000}"
  local subdomain="${FRP_SUBDOMAIN:-prober-$(date +%s | tail -c 5)}"
  local remote_port="${FRP_REMOTE:-0}"

  cat > "${FRPC_CFG}" <<EOF
# FRP 客户端配置 — prober-cli 自动生成
serverAddr = "${server_addr}"
serverPort = ${server_port}

[[proxies]]
name = "prober-web"
type = "tcp"
localIP = "127.0.0.1"
localPort = ${PORT}
remotePort = ${remote_port}
EOF
  ok "FRP 配置已生成: ${FRPC_CFG}"
  echo "  服务端:   ${server_addr}:${server_port}"
  echo "  本地端口: 127.0.0.1:${PORT}"
  echo "  子域/远端口: ${subdomain} / ${remote_port}"
  echo ""
  echo "  自定义环境变量:"
  echo "    FRP_SERVER  公链服务器地址  (当前 ${server_addr})"
  echo "    FRP_PORT    公链服务器端口  (当前 ${server_port})"
  echo "    FRP_REMOTE  远程端口(0=随机) (当前 ${remote_port})"
  echo ""
  echo "  启动隧道: ${0} frp up"
}

cmd_frp_up(){
  if [[ ! -x "${FRPC_BIN}" ]]; then
    warn "frpc 未安装，先执行 init"
    cmd_frp_init
    [[ -x "${FRPC_BIN}" ]] || { err "frpc 不可用，无法启动公链隧道"; return 1; }
  fi
  [[ -f "${FRPC_CFG}" ]] || cmd_frp_init
  # 确保本地服务运行
  if [[ ! -f "${DATA_DIR}/serve.pid" ]] || ! kill -0 "$(cat "${DATA_DIR}/serve.pid" 2>/dev/null)" 2>/dev/null; then
    log "本地服务未运行，先启动 ..."
    cmd_serve
  fi
  log "启动 FRP 公链隧道 ..."
  nohup "${FRPC_BIN}" -c "${FRPC_CFG}" > "${DATA_DIR}/frpc.log" 2>&1 &
  local pid=$!
  echo "${pid}" > "${FRPC_PID}"
  sleep 2
  if kill -0 "${pid}" 2>/dev/null; then
    ok "FRP 隧道已启动 (PID ${pid})"
    log "公链入口将通过 FRP 服务端转发至本地 ${PORT}"
    echo "  日志: ${DATA_DIR}/frpc.log"
    echo "  状态: ${0} frp status"
    echo "  停止: ${0} frp down"
  else
    err "FRP 隧道启动失败，查看日志:"
    tail -20 "${DATA_DIR}/frpc.log" 2>/dev/null || true
    return 1
  fi
}

cmd_frp_down(){
  if [[ -f "${FRPC_PID}" ]]; then
    local pid; pid=$(cat "${FRPC_PID}")
    kill "${pid}" 2>/dev/null && ok "FRP 隧道已停止 (PID ${pid})" || warn "隧道未运行"
    rm -f "${FRPC_PID}"
  else
    warn "未找到 FRP PID 文件"
  fi
}

cmd_frp_status(){
  echo "=== FRP 公链状态 ==="
  if [[ -x "${FRPC_BIN}" ]]; then echo "  frpc:    已安装 (${FRPC_BIN})"; else echo "  frpc:    ${C_R}未安装${C_0} (运行 frp init)"; fi
  if [[ -f "${FRPC_CFG}" ]]; then echo "  配置:    ${FRPC_CFG}"; else echo "  配置:    ${C_Y}未生成${C_0}"; fi
  if [[ -f "${FRPC_PID}" ]] && kill -0 "$(cat "${FRPC_PID}" 2>/dev/null)" 2>/dev/null; then
    echo "  隧道:    ${C_G}运行中${C_0} (PID $(cat "${FRPC_PID}"))"
    echo "  日志尾部:"
    tail -5 "${DATA_DIR}/frpc.log" 2>/dev/null | sed 's/^/    /' || true
  else
    echo "  隧道:    ${C_Y}未运行${C_0}"
  fi
  echo ""
  echo "=== 本地服务 ==="
  if [[ -f "${DATA_DIR}/serve.pid" ]] && kill -0 "$(cat "${DATA_DIR}/serve.pid" 2>/dev/null)" 2>/dev/null; then
    echo "  服务:    ${C_G}运行中${C_0} (PID $(cat "${DATA_DIR}/serve.pid"))  端口 ${PORT}"
    if curl -s -o /dev/null -w "" "http://localhost:${PORT}/index.html" 2>/dev/null; then
      echo "  健康:    ${C_G}OK${C_0}  http://localhost:${PORT}"
    fi
  else
    echo "  服务:    ${C_Y}未运行${C_0}  (运行 ${0} serve)"
  fi
}

# ---------- gen-app: 脚手架新实例 ----------
cmd_gen_app(){
  local name="${1:-prober-instance}"
  local dir="${SCRIPT_DIR}/${name}"
  log "生成应用实例: ${dir}"
  mkdir -p "${dir}/data/keys"
  cp "${SCRIPT_DIR}/index.html" "${dir}/" 2>/dev/null || warn "index.html 模板缺失"
  cp "${SCRIPT_DIR}/prober-cli.mjs" "${dir}/" 2>/dev/null || true
  cp "${SCRIPT_DIR}/prober-cli.sh" "${dir}/" 2>/dev/null || true
  echo '{}' > "${dir}/data/agreements.json"
  echo '[]' > "${dir}/data/ledger.json"
  cat > "${dir}/README.txt" <<EOF
JMKstudio Prober 实例: ${name}
生成时间: $(date)
数据目录: ${dir}/data
启动: cd ${dir} && PROBER_DATA=${dir}/data PROBER_PORT=8090 bash prober-cli.sh serve
EOF
  ok "应用实例已生成: ${dir}"
  echo "  目录结构:"
  find "${dir}" -type f | sed 's/^/  /'
}

# ---------- 主分发 ----------
cmd="${1:-help}"
shift || true
case "${cmd}" in
  gen)            cmd_gen "$@" ;;
  gen-app)        cmd_gen_app "$@" ;;
  deps)           cmd_deps ;;
  serve)          cmd_serve "$@" ;;
  stop)           cmd_stop ;;
  frp)
    sub="${1:-status}"
    case "${sub}" in
      init)   cmd_frp_init ;;
      up)     cmd_frp_up ;;
      down)   cmd_frp_down ;;
      status) cmd_frp_status ;;
      *)      err "用法: ${0} frp init|up|down|status"; exit 1 ;;
    esac ;;
  # 以下委托 Node 后端
  agreement|probe|ledger|gpg|verify|ca|help)
    run_node "${cmd}" "$@" ;;
  status)
    cmd_frp_status ;;
  *)
    err "未知命令: ${cmd}"
    echo ""
    echo "用法: ${0} <command> [args]"
    echo ""
    echo "命令:"
    echo "  gen              生成/初始化应用"
    echo "  gen-app [name]   脚手架新应用实例"
    echo "  deps             安装依赖 (openpgp)"
    echo "  serve [port]     启动本地 HTTP 服务"
    echo "  stop             停止本地服务"
    echo "  frp init         下载 frpc + 生成公链配置"
    echo "  frp up           启动 FRP 公链隧道"
    echo "  frp down         停止隧道"
    echo "  frp status       查看公链+服务状态"
    echo "  agreement new|list   P2P 协议 (委托 Node)"
    echo "  probe run            探针检测 (委托 Node)"
    echo "  ledger               哈希链账本 (委托 Node)"
    echo "  gpg encrypt|decrypt  GPG-CA 加解密 (委托 Node)"
    echo "  verify --id          验证协议签名 (委托 Node)"
    echo "  ca                   GPG-CA 信任根信息 (委托 Node)"
    echo "  status               综合状态"
    echo "  help                 帮助"
    exit 1 ;;
esac
