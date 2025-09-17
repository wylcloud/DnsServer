#!/bin/bash
set -e

echo "=== 安装前置依赖 ==="
apt update
apt install -y curl gnupg2 ca-certificates lsb-release debian-archive-keyring

echo "=== 导入 NGINX 官方 GPG key ==="
curl -fsSL https://nginx.org/keys/nginx_signing.key | gpg --dearmor \
  | tee /usr/share/keyrings/nginx-archive-keyring.gpg >/dev/null

echo "=== 验证 GPG key ==="
FINGERPRINT=$(gpg --dry-run --quiet --no-keyring --import --import-options import-show \
  /usr/share/keyrings/nginx-archive-keyring.gpg | grep -oE '[A-F0-9]{40}' || true)

if [[ "$FINGERPRINT" != "573BFD6B3D8FBC641079A6ABABF5BD827BD9BF62" ]]; then
  echo "❌ GPG 指纹不匹配，停止安装！"
  exit 1
else
  echo "✅ GPG 指纹验证通过：$FINGERPRINT"
fi

echo "=== 添加 NGINX 官方仓库 ==="
CODENAME=$(lsb_release -cs)
echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] http://nginx.org/packages/debian $CODENAME nginx" \
  | tee /etc/apt/sources.list.d/nginx.list

echo "=== 设置优先级 Pinning ==="
cat > /etc/apt/preferences.d/99nginx <<EOF
Package: *
Pin: origin nginx.org
Pin: release o=nginx
Pin-Priority: 900
EOF

echo "=== 更新并安装 NGINX ==="
apt update
apt install -y nginx

echo "=== 创建 sites-available / sites-enabled 目录 ==="
mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled

if ! grep -q "include /etc/nginx/sites-enabled/\*.conf;" /etc/nginx/nginx.conf; then
  echo "=== 修改 nginx.conf 引入 sites-enabled/*.conf ==="
  sed -i '/http {/a \    include /etc/nginx/sites-enabled/*.conf;' /etc/nginx/nginx.conf
fi

echo "=== NGINX 安装完成 ==="
nginx -t && systemctl enable nginx && systemctl restart nginx
systemctl status nginx --no-pager
