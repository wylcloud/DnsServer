#!/bin/bash
# 文件名: setup_dns_socat.sh
# 用途: 安装 socat, 转发本地 53 到远端 VPS 5353, 配置 systemd 并修改 resolv.conf

# -------------------------------
# 配置项，请修改为你的远端 VPS IP 和端口
REMOTE_VPS="202.81.231.172"
REMOTE_PORT="5353"
# -------------------------------

set -e

echo "1. 安装 socat..."
apt update
apt install -y socat

echo "2. 创建 systemd 服务文件..."
SERVICE_FILE="/etc/systemd/system/dns-socat.service"

cat > $SERVICE_FILE <<EOF
[Unit]
Description=DNS Forwarding via socat
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/socat UDP-LISTEN:53,fork,reuseaddr UDP:${REMOTE_VPS}:${REMOTE_PORT} \
          TCP-LISTEN:53,fork,reuseaddr TCP:${REMOTE_VPS}:${REMOTE_PORT}
Restart=always

[Install]
WantedBy=multi-user.target
EOF

echo "3. 重新加载 systemd 并启用服务..."
systemctl daemon-reload
systemctl enable dns-socat
systemctl restart dns-socat

echo "4. 修改 /etc/resolv.conf 指向本地 127.0.0.1..."
# 备份旧文件
cp /etc/resolv.conf /etc/resolv.conf.bak
cat > /etc/resolv.conf <<EOF
nameserver 127.0.0.1
EOF

echo "✅ 完成！本机 DNS 请求现在会通过 socat 转发到 ${REMOTE_VPS}:${REMOTE_PORT}"
echo "可用 dig 测试: dig @127.0.0.1 www.google.com"
