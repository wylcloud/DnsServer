#!/bin/sh
# Debian 12/13 (systemd): sh certbot-standalone.sh example.com
# 不带参数时提示输入域名。使用 Let's Encrypt 正式证书和 Certbot 默认目录。
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 022

EMAIL='vjk@vjk.com'
HOOK_DIR='/etc/letsencrypt/standalone-helper'
STATE='/run/certbot-standalone-helper/nginx-stopped'

die() { printf '错误：%s\n' "$*" >&2; exit 1; }

case "${1:-}" in
    -h|--help)
        printf '用法：sudo sh %s [域名]\n例如：sudo sh %s example.com\n' "$0" "$0"
        exit 0
        ;;
esac
[ "$#" -le 1 ] || die '一次只传入一个域名。'
[ "$(id -u)" -eq 0 ] || die '请使用 root 或 sudo 运行。'
[ -r /etc/os-release ] || die '无法识别操作系统。'
. /etc/os-release
[ "${ID:-}" = debian ] || die '此脚本适用于 Debian 12/13。'
case "${VERSION_ID:-}" in 12|13) ;; *) die '此脚本适用于 Debian 12/13。' ;; esac
[ -d /run/systemd/system ] || die '需要使用 systemd 的 Debian 主机。'

DOMAIN=${1:-}
if [ -z "$DOMAIN" ]; then
    printf '请输入域名（例如 example.com）：'
    IFS= read -r DOMAIN || die '未读取到域名。'
fi
DOMAIN=$(printf '%s' "$DOMAIN" | LC_ALL=C tr '[:upper:]' '[:lower:]')
DOMAIN=${DOMAIN%.}
# 只接受普通域名；国际化域名请使用 xn-- 开头的 Punycode。
printf '%s\n' "$DOMAIN" | LC_ALL=C awk '
    NR > 1 { exit 1 }
    length($0) > 253 || $0 !~ /^[a-z0-9.-]+$/ { exit 1 }
    {
        n = split($0, labels, ".")
        if (n < 2 || labels[n] !~ /[a-z]/) exit 1
        for (i = 1; i <= n; i++)
            if (length(labels[i]) < 1 || length(labels[i]) > 63 ||
                labels[i] ~ /^-/ || labels[i] ~ /-$/) exit 1
    }
' || die '请输入纯域名，不要带 https://、端口、路径或通配符。'

# 防止脚本本身重复执行；Certbot 另有自己的全局锁。
exec 9>/run/lock/certbot-standalone-setup.lock
flock -n 9 || die '另一个申请脚本正在运行，请稍后重试。'

if [ ! -x /usr/bin/certbot ]; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y certbot ca-certificates
fi

RENEWAL="/etc/letsencrypt/renewal/$DOMAIN.conf"
PRE="$HOOK_DIR/nginx-stop"
POST="$HOOK_DIR/nginx-start"
MIGRATE=0

# 对已有同名证书先检查，避免覆盖 nginx/DNS 插件或用户原有的钩子。
# ConfigObj 是 Debian Certbot 的依赖；这里只读配置，不手工修改续签文件。
if [ -f "$RENEWAL" ]; then
    if /usr/bin/python3 - "$RENEWAL" "$PRE" "$POST" "$DOMAIN" <<'PY'
import sys
from pathlib import Path
from configobj import ConfigObj
from cryptography import x509

config = ConfigObj(sys.argv[1])
cert = x509.load_pem_x509_certificate(Path(config['cert']).read_bytes())
names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
if sys.argv[4] not in [name.lower() for name in names.get_values_for_type(x509.DNSName)]:
    print('同名证书的域名列表不包含申请域名，请检查 certbot certificates。', file=sys.stderr)
    sys.exit(1)
params = config.get('renewalparams', {})
if params.get('authenticator') != 'standalone':
    print('同名证书使用了其他验证插件，请用原方式管理它。', file=sys.stderr)
    sys.exit(1)
for key, expected in [('pre_hook', sys.argv[2]), ('post_hook', sys.argv[3])]:
    if params.get(key) not in (None, '', expected):
        print(f'同名证书已有自定义 {key}，请先人工合并钩子。', file=sys.stderr)
        sys.exit(1)
sys.exit(0 if params.get('pre_hook') == sys.argv[2]
         and params.get('post_hook') == sys.argv[3] else 10)
PY
    then
        :
    else
        status=$?
        [ "$status" -eq 10 ] || die '未改动已有证书的续签设置。'
        MIGRATE=1
    fi
fi

# 钩子放在独立目录，通过证书自身配置调用，不影响其他证书的验证方式。
install -d -m 0755 "$HOOK_DIR"
TMP_HOOK=$(mktemp "$HOOK_DIR/.hook.XXXXXX")

# 首次申请被中断时也尝试恢复；只恢复本次调用停掉的服务。
CERTBOT_STANDALONE_OWNER=$$
export CERTBOT_STANDALONE_OWNER
cleanup() {
    status=$?
    trap - 0 HUP INT TERM
    if [ -f "$STATE" ] && [ "$(cat "$STATE")" = "$CERTBOT_STANDALONE_OWNER" ]; then
        "$POST" || status=1
    fi
    [ ! -f "$TMP_HOOK" ] || rm -f -- "$TMP_HOOK"
    exit "$status"
}
trap cleanup 0
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

cat > "$TMP_HOOK" <<'HOOK'
#!/bin/sh
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
state=/run/certbot-standalone-helper/nginx-stopped
if systemctl is-active --quiet nginx.service; then
    # 停止前先检查配置，降低随后启动失败的风险。
    nginx -t
    install -d -m 0700 /run/certbot-standalone-helper
    if [ ! -f "$state" ]; then
        printf '%s\n' "${CERTBOT_STANDALONE_OWNER:-renew}" > "$state"
    fi
    systemctl stop nginx.service
fi
HOOK
chmod 0755 "$TMP_HOOK"
mv -f "$TMP_HOOK" "$PRE"

TMP_HOOK=$(mktemp "$HOOK_DIR/.hook.XXXXXX")
cat > "$TMP_HOOK" <<'HOOK'
#!/bin/sh
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
state=/run/certbot-standalone-helper/nginx-stopped
if [ -f "$state" ]; then
    # systemd 兜底只恢复定时任务自己停掉的 Nginx，避免干扰手动申请。
    if [ "${1:-}" = systemd ] && [ "$(cat "$state")" != systemd-renew ]; then
        exit 0
    fi
    # 失败时保留标记，并让错误进入 Certbot 日志。
    if systemctl start nginx.service; then
        rm -f -- "$state"
    else
        printf '错误：Nginx 恢复失败，请检查 systemctl status nginx.service\n' >&2
        exit 1
    fi
fi
HOOK
chmod 0755 "$TMP_HOOK"
mv -f "$TMP_HOOK" "$POST"

# 定时任务即使被终止，systemd 仍会尝试恢复本次暂停的 Nginx。
# 保留现有服务设置，仅添加本脚本自己的恢复动作。
install -d -m 0755 /etc/systemd/system/certbot.service.d
cat > /etc/systemd/system/certbot.service.d/20-standalone-helper.conf <<EOF
[Service]
Environment=CERTBOT_STANDALONE_OWNER=systemd-renew
ExecStopPost=$POST systemd
EOF
systemctl daemon-reload

printf '\n申请域名：%s\n注册邮箱：%s\n' "$DOMAIN" "$EMAIL"
printf '请确保 DNS 指向本机，公网 TCP 80 端口可达。验证期间可能短暂停止 Nginx。\n\n'

# Debian 12 的 Certbot 2.1 没有 reconfigure：先测试，再续签一次保存钩子。
# 此分支仅在接管“已有 standalone 证书且缺少本脚本钩子”时执行。
if [ "$MIGRATE" -eq 1 ]; then
    version=$(/usr/bin/certbot --version)
    case "$version" in
        'certbot 2.0.'*|'certbot 2.1.'*)
            printf '正在为已有证书测试续签；测试成功后续签一次以保存停启设置。\n'
            /usr/bin/certbot renew --cert-name "$DOMAIN" --non-interactive \
                --standalone --pre-hook "$PRE" --post-hook "$POST" --dry-run
            /usr/bin/certbot renew --cert-name "$DOMAIN" --non-interactive \
                --standalone --pre-hook "$PRE" --post-hook "$POST" --force-renewal
            ;;
        *)
            /usr/bin/certbot reconfigure --cert-name "$DOMAIN" --non-interactive \
                --standalone --pre-hook "$PRE" --post-hook "$POST"
            # reconfigure 只测试并保存设置；已有证书到期时还需要正式续签。
            /usr/bin/certbot renew --cert-name "$DOMAIN" --non-interactive
            ;;
    esac
elif [ -f "$RENEWAL" ]; then
    # 保留已有证书中的全部域名，且未到续签时间时不重复签发。
    /usr/bin/certbot renew --cert-name "$DOMAIN" --non-interactive
else
    /usr/bin/certbot certonly --standalone \
        --preferred-challenges http --http-01-port 80 \
        --cert-name "$DOMAIN" -d "$DOMAIN" \
        --email "$EMAIL" --agree-tos --no-eff-email --non-interactive \
        --keep-until-expiring --pre-hook "$PRE" --post-hook "$POST"
fi

# Certbot 不一定因 post-hook 失败而返回非零，额外确认本次 Nginx 已恢复。
if [ -f "$STATE" ] && [ "$(cat "$STATE")" = "$CERTBOT_STANDALONE_OWNER" ]; then
    "$POST"
fi
[ -s "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ] || die '未找到完整证书链。'
[ -s "/etc/letsencrypt/live/$DOMAIN/privkey.pem" ] || die '未找到私钥。'

# 使用 Debian 包自带的定时器，每天检查两次；Certbot 自行判断是否需要续签。
systemctl enable --now certbot.timer
systemctl is-active --quiet certbot.timer || die '证书已申请，但自动续签定时器未启动。'

printf '\n完成，自动续签已启用。\n'
printf '完整证书链：/etc/letsencrypt/live/%s/fullchain.pem\n' "$DOMAIN"
printf '私钥：      /etc/letsencrypt/live/%s/privkey.pem\n' "$DOMAIN"
printf '\n查看定时任务：systemctl list-timers certbot.timer\n'
printf '测试自动续签：certbot renew --cert-name %s --dry-run\n' "$DOMAIN"
printf '查看续签日志：journalctl -u certbot.service\n'
