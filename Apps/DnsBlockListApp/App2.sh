#!/bin/bash

# ====================================================
# fail2ban + 诱饵端口蜜罐（Debian 12）
# 前提：已用 App.sh 把 SSH 改到 61125，并且只允许公钥登录
#
# 功能：
#   1. 在 22 / 222 / 2222 / 22122 上运行低交互蜜罐：只记录来源 IP、回一个假的 SSH 版本号，
#      不做认证、不提供 shell。端口由 systemd 绑定，蜜罐进程以无特权的临时用户运行。
#   2. fail2ban 读取蜜罐日志：碰一次诱饵端口，就封禁该 IP 的全部端口
#      （默认 1 天，屡犯翻倍，最长 4 周）。
#   3. fail2ban 同时保护真实 SSH 端口 61125
#      （10 分钟内失败 5 次封 1 小时，屡犯翻倍）。
#
# 用法：
#   bash fail2ban-honeypot.sh               安装 / 重新安装
#   bash fail2ban-honeypot.sh --uninstall   卸载蜜罐和本脚本写入的 fail2ban 配置
#
# 可选环境变量：
#   WHITELIST_IPS="1.2.3.4 5.6.7.0/24"   永不封禁的 IP/网段（会自动加入当前 SSH 登录的来源 IP）
#   HONEYPOT_BAN_SCOPE=ssh                蜜罐命中后只封 SSH 端口（默认 all：封全部端口）
#   FORCE=1                               在非 Debian 12 系统上强制运行
# ====================================================

set -euo pipefail

SSH_PORT=61125
DECOY_PORTS=(22 222 2222 22122)
WHITELIST_IPS="${WHITELIST_IPS:-}"
HONEYPOT_BAN_SCOPE="${HONEYPOT_BAN_SCOPE:-all}"

HP_DIR=/usr/local/lib/ssh-honeypot
HP_SCRIPT=$HP_DIR/honeypot.py
HP_SOCKET=/etc/systemd/system/ssh-honeypot.socket
HP_SERVICE=/etc/systemd/system/ssh-honeypot.service
F2B_FILTER=/etc/fail2ban/filter.d/ssh-honeypot.conf
F2B_JAIL=/etc/fail2ban/jail.d/99-ssh-honeypot.local
F2B_MAIN=/etc/fail2ban/fail2ban.d/99-ssh-honeypot.local

info() { echo "[*] $*"; }
warn() { echo "[!] $*" >&2; }
die()  { echo "[x] 错误：$*" >&2; exit 1; }

uninstall() {
    info "停止并删除蜜罐..."
    systemctl disable --now ssh-honeypot.socket ssh-honeypot.service 2>/dev/null || true
    rm -f "$HP_SOCKET" "$HP_SERVICE"
    rm -rf "$HP_DIR"
    systemctl daemon-reload

    info "删除本脚本写入的 fail2ban 配置..."
    rm -f "$F2B_FILTER" "$F2B_JAIL" "$F2B_MAIN"
    if systemctl is-active --quiet fail2ban; then
        # Debian 12 默认的 sshd jail 会去找并不存在的 /var/log/auth.log，去掉本配置后可能起不来
        systemctl restart fail2ban || warn "fail2ban 重启失败。如不再需要，可执行：apt-get purge fail2ban"
    fi
    info "卸载完成。fail2ban 软件包仍保留。"
}

# 确保以 root 权限执行
if [ "$(id -u)" != "0" ]; then
    die "请使用 root 权限运行此脚本。"
fi

if [ "${1:-}" = "--uninstall" ]; then
    uninstall
    exit 0
fi

# ---------- 0. 运行前检查 ----------
. /etc/os-release
if [ "${ID:-}" != "debian" ] || [ "${VERSION_ID:-}" != "12" ]; then
    [ "${FORCE:-0}" = "1" ] || die "本脚本按 Debian 12 编写（当前：${PRETTY_NAME:-未知}）。确认继续请加 FORCE=1。"
fi

case "$HONEYPOT_BAN_SCOPE" in
    all) JAIL_PORT="0:65535";     JAIL_BANACTION="%(banaction_allports)s" ;;
    ssh) JAIL_PORT="$SSH_PORT";   JAIL_BANACTION="%(banaction)s" ;;
    *)   die "HONEYPOT_BAN_SCOPE 只能是 all 或 ssh。" ;;
esac

info "检查 SSH 配置..."
SSHD_PORTS=$(sshd -T 2>/dev/null | awk '$1 == "port" {print $2}') || true
[ -n "$SSHD_PORTS" ] || die "无法读取 sshd 配置（sshd -T 失败），请先检查 SSH 配置。"
if ! grep -qx "$SSH_PORT" <<<"$SSHD_PORTS"; then
    die "sshd 没有监听 $SSH_PORT，请先运行 App.sh。"
fi
for p in "${DECOY_PORTS[@]}"; do
    if grep -qx "$p" <<<"$SSHD_PORTS"; then
        die "sshd 仍在使用端口 $p，会和蜜罐冲突。请先运行 App.sh，让 SSH 只留在 $SSH_PORT。"
    fi
done
if systemctl is-active --quiet ssh.socket; then
    die "ssh.socket 已启用（它会占用 22 端口）。请先执行：systemctl disable --now ssh.socket && systemctl restart ssh"
fi
if [ -z "$(ss -Hltn "sport = :$SSH_PORT")" ]; then
    die "端口 $SSH_PORT 上没有服务在监听，sshd 可能没有正常运行。"
fi

# 重新安装时先停掉旧蜜罐，再检查端口是否被其他程序占用
systemctl stop ssh-honeypot.socket ssh-honeypot.service 2>/dev/null || true
for p in "${DECOY_PORTS[@]}"; do
    used=$(ss -Hltnp "sport = :$p")
    if [ -n "$used" ]; then
        die "端口 $p 已被占用：$used"
    fi
done

# 白名单：本机 + 当前 SSH 登录的来源 IP + WHITELIST_IPS
IGNORE_IPS=(127.0.0.1/8 ::1)
CLIENT_IP=""
if [ -n "${SSH_CONNECTION:-}" ]; then
    CLIENT_IP=${SSH_CONNECTION%% *}
    IGNORE_IPS+=("$CLIENT_IP")
fi
read -r -a EXTRA_IPS <<<"$WHITELIST_IPS"
IGNORE_IPS+=("${EXTRA_IPS[@]}")
if [ -z "$CLIENT_IP" ] && [ -z "$WHITELIST_IPS" ]; then
    warn "没有检测到当前 SSH 来源 IP，也没有设置 WHITELIST_IPS。"
    warn "如果你忘记加 -p $SSH_PORT 去连 22 端口，会把自己封掉（可以从 VPS 控制台解封）。"
fi

# ---------- 1. 蜜罐程序 ----------
info "写入蜜罐程序 $HP_SCRIPT ..."
mkdir -p "$HP_DIR"
cat > "$HP_SCRIPT" <<'PYEOF'
#!/usr/bin/env python3
# 低交互 SSH 蜜罐：记录连到诱饵端口的来源 IP，回一个假的 SSH 版本号，读一下客户端版本号就断开。
# 不做认证、不提供 shell。端口由 systemd（ssh-honeypot.socket）以 root 绑定后传进来，
# 本进程以临时用户运行，不持有任何特权。
#
# fail2ban 只认这一行（改格式时要同步修改 /etc/fail2ban/filter.d/ssh-honeypot.conf）：
#   HONEYPOT hit from <IP> port=<本地端口>
import asyncio
import ipaddress
import os
import socket
import sys

BANNER = b"SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3\r\n"
READ_TIMEOUT = 10     # 等客户端版本号的秒数
MAX_SESSIONS = 256    # 同时交互的连接上限，超出的只记录、不交互


def log(msg):
    print(msg, flush=True)


def normalize(addr):
    # 双栈监听时 IPv4 来源显示为 ::ffff:1.2.3.4，还原成普通 IPv4，fail2ban 才能正确封禁
    try:
        ip = ipaddress.ip_address(addr.split("%", 1)[0])
    except ValueError:
        return None
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return str(ip)


async def handle(reader, writer, slots):
    peer = writer.get_extra_info("peername")
    local = writer.get_extra_info("sockname")
    ip = normalize(peer[0]) if peer else None
    port = local[1] if local else 0
    try:
        if ip is None:
            return
        # 先记录再交互：TCP 三次握手已完成，来源 IP 无法伪造
        log(f"HONEYPOT hit from {ip} port={port}")
        if slots.locked():
            return
        async with slots:
            writer.write(BANNER)
            await writer.drain()
            data = await asyncio.wait_for(reader.read(256), READ_TIMEOUT)
            if data:
                # 对方可控的内容：截断并用 repr 转义，防止伪造日志行
                text = data.split(b"\n", 1)[0].strip()[:100].decode("ascii", "backslashreplace")
                log(f"HONEYPOT client ip={ip} port={port} banner={text!r}")
    except (asyncio.TimeoutError, OSError):
        pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass


def inherited_sockets():
    if os.environ.get("LISTEN_PID") != str(os.getpid()):
        sys.exit("no sockets passed by systemd; start ssh-honeypot.socket instead")
    count = int(os.environ.get("LISTEN_FDS", "0"))
    if count < 1:
        sys.exit("systemd passed no listening sockets")
    return [socket.socket(fileno=fd) for fd in range(3, 3 + count)]


async def main():
    slots = asyncio.Semaphore(MAX_SESSIONS)
    servers = []
    for sock in inherited_sockets():
        servers.append(await asyncio.start_server(
            lambda r, w: handle(r, w, slots), sock=sock))
    ports = sorted({s.sockets[0].getsockname()[1] for s in servers})
    log(f"HONEYPOT listening on ports {ports}")
    await asyncio.gather(*(s.serve_forever() for s in servers))


if __name__ == "__main__":
    asyncio.run(main())
PYEOF
chmod 755 "$HP_DIR"
chmod 644 "$HP_SCRIPT"

# ---------- 2. systemd 单元 ----------
info "写入 systemd 单元..."
cat > "$HP_SOCKET" <<EOF
[Unit]
Description=SSH honeypot decoy ports

[Socket]
$(printf 'ListenStream=%s\n' "${DECOY_PORTS[@]}")
BindIPv6Only=both
Backlog=256

[Install]
WantedBy=sockets.target
EOF

cat > "$HP_SERVICE" <<'EOF'
[Unit]
Description=Low-interaction SSH honeypot (logs decoy-port hits for fail2ban)
Requires=ssh-honeypot.socket
After=ssh-honeypot.socket

[Service]
ExecStart=/usr/bin/python3 -IB /usr/local/lib/ssh-honeypot/honeypot.py
SyslogIdentifier=ssh-honeypot
Restart=always
RestartSec=2

# 端口已由 socket 单元绑定，这里不需要任何权限
DynamicUser=yes
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
ProcSubset=pid
# AF_UNIX 是 asyncio 内部的 socketpair 需要的
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged
UMask=0077
MemoryMax=64M
TasksMax=16
EOF

# ---------- 3. fail2ban 配置 ----------
# 先写配置再安装软件包：Debian 12 没有 /var/log/auth.log，
# 默认配置的 fail2ban 装完后会启动失败，提前写好 backend=systemd 就能避免。
info "写入 fail2ban 配置..."
mkdir -p /etc/fail2ban/filter.d /etc/fail2ban/jail.d /etc/fail2ban/fail2ban.d

cat > "$F2B_FILTER" <<'EOF'
# 由 fail2ban-honeypot.sh 生成：匹配蜜罐的 "HONEYPOT hit from <IP>" 日志
# 行首锚定，蜜罐记录的客户端内容（banner=...）无法伪造出这一行
[INCLUDES]
before = common.conf

[Definition]
_daemon = ssh-honeypot
failregex = ^%(__prefix_line)sHONEYPOT hit from <ADDR> port=\d+
ignoreregex =

[Init]
journalmatch = _SYSTEMD_UNIT=ssh-honeypot.service
EOF

cat > "$F2B_JAIL" <<EOF
# 由 fail2ban-honeypot.sh 生成，重新运行脚本会覆盖本文件
# jail.d/*.local 最后加载，这里的设置优先于 jail.conf / jail.local
[DEFAULT]
ignoreip = ${IGNORE_IPS[*]}
# Debian 12 默认使用 nftables
banaction = nftables-multiport
banaction_allports = nftables-allports
# 屡犯翻倍：1 倍、2 倍、4 倍……最长 4 周
bantime.increment = true
bantime.maxtime = 4w

# 真实 SSH 端口
[sshd]
enabled  = true
backend  = systemd
port     = $SSH_PORT
mode     = aggressive
maxretry = 5
findtime = 10m
bantime  = 1h

# 诱饵端口：正常用户不会连这些端口，碰一次就封
[ssh-honeypot]
enabled   = true
backend   = systemd
filter    = ssh-honeypot
port      = $JAIL_PORT
banaction = $JAIL_BANACTION
maxretry  = 1
findtime  = 1d
bantime   = 1d
EOF

cat > "$F2B_MAIN" <<'EOF'
# 由 fail2ban-honeypot.sh 生成
# 封禁记录保留 30 天（默认 1 天），屡犯翻倍才能认出回头客
[Definition]
dbpurgeage = 30d
EOF

# ---------- 4. 安装软件包 ----------
info "安装 fail2ban、nftables..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq </dev/null
apt-get install -y -qq fail2ban python3 python3-systemd nftables </dev/null

# ---------- 5. 启动蜜罐 ----------
info "启动蜜罐..."
systemctl daemon-reload
systemctl enable --now ssh-honeypot.socket
systemctl restart ssh-honeypot.service

# ---------- 6. 校验并启动 fail2ban ----------
info "校验 fail2ban 配置..."
SAMPLE="Jan  1 00:00:00 $(hostname) ssh-honeypot[1]: HONEYPOT hit from 203.0.113.1 port=22"
REGEX_OUT=$(fail2ban-regex "$SAMPLE" "$F2B_FILTER" 2>&1) || true
if ! grep -q ", 1 matched," <<<"$REGEX_OUT"; then
    echo "$REGEX_OUT" >&2
    die "蜜罐过滤规则没有匹配到样例日志。"
fi
if ! fail2ban-client -t >/dev/null 2>&1; then
    fail2ban-client -t >&2 || true
    die "fail2ban 配置检查未通过。"
fi

info "启动 fail2ban..."
systemctl enable fail2ban >/dev/null 2>&1 || warn "fail2ban 设置开机自启失败，请手动执行：systemctl enable fail2ban"
systemctl restart fail2ban || die "fail2ban 启动失败，请查看：journalctl -u fail2ban -n 50"
for _ in $(seq 1 30); do
    fail2ban-client ping >/dev/null 2>&1 && break
    sleep 0.5
done
fail2ban-client ping >/dev/null 2>&1 || die "fail2ban 未能启动，请查看：journalctl -u fail2ban -n 50"

# ---------- 7. 本机防火墙 ----------
UFW_STATE=$(ufw status 2>/dev/null || true)
if [[ $UFW_STATE == "Status: active"* ]]; then
    info "检测到 ufw 已启用，放行诱饵端口..."
    for p in "${DECOY_PORTS[@]}"; do
        ufw allow "$p/tcp" >/dev/null
    done
fi

# ---------- 8. 自检 ----------
info "自检：从本机连接诱饵端口 ${DECOY_PORTS[0]}（127.0.0.1 在白名单中，不会被封）..."
TEST_START=$(date '+%Y-%m-%d %H:%M:%S')
GOT_BANNER=$(timeout 5 bash -c "exec 3<>/dev/tcp/127.0.0.1/${DECOY_PORTS[0]}; head -n1 <&3; printf 'SSH-2.0-selftest\r\n' >&3" 2>/dev/null) || true
sleep 1
if [[ $GOT_BANNER == SSH-2.0-* ]]; then
    info "蜜罐应答正常：${GOT_BANNER%$'\r'}"
else
    warn "蜜罐没有应答，请查看：journalctl -u ssh-honeypot -n 20"
fi
HIT_LOG=$(journalctl -u ssh-honeypot --since "$TEST_START" -o cat 2>/dev/null || true)
if grep -q "HONEYPOT hit from 127.0.0.1" <<<"$HIT_LOG"; then
    info "蜜罐日志已写入 journald。"
else
    warn "journald 中没有找到自检记录，请查看：journalctl -u ssh-honeypot -n 20"
fi
JOURNAL_OUT=$(fail2ban-regex systemd-journal "$F2B_FILTER" 2>&1) || true
if grep -Eq ', [1-9][0-9]* matched,' <<<"$JOURNAL_OUT"; then
    info "fail2ban 能从 journald 读到并识别蜜罐日志。"
else
    warn "fail2ban 没能从 journald 识别到蜜罐日志，请运行：fail2ban-regex systemd-journal $F2B_FILTER"
fi

echo "======================================================"
echo "配置完成！"
echo "诱饵端口：${DECOY_PORTS[*]}（低交互蜜罐）"
if [ "$HONEYPOT_BAN_SCOPE" = "all" ]; then
    echo "  命中一次即封禁该 IP 的全部端口：1 天起，屡犯翻倍，最长 4 周"
else
    echo "  命中一次即封禁该 IP 的 SSH 端口 $SSH_PORT：1 天起，屡犯翻倍，最长 4 周"
fi
echo "真实 SSH：$SSH_PORT（10 分钟内失败 5 次封 1 小时，屡犯翻倍）"
echo "白名单：${IGNORE_IPS[*]}"
echo
fail2ban-client status
echo
echo "常用命令："
echo "  fail2ban-client status ssh-honeypot            查看蜜罐封禁情况"
echo "  fail2ban-client status sshd                    查看 SSH 封禁情况"
echo "  journalctl -u ssh-honeypot -f                  实时查看蜜罐命中"
echo "  fail2ban-client set ssh-honeypot unbanip <IP>  解封某个 IP"
echo "  nft list table inet f2b-table                  查看防火墙中的封禁表"
echo
echo "提醒："
echo "  1. 连接本机务必带上 -p $SSH_PORT（建议写进 ~/.ssh/config），否则误碰 22 端口会被封（白名单 IP 除外）。"
echo "  2. 如果 VPS 有云防火墙/安全组，需要放行 ${DECOY_PORTS[*]}，否则蜜罐收不到连接。"
echo "======================================================"
