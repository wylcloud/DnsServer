#!/bin/bash
set -e

# === 配置参数（可根据需要修改）===
REALM_VERSION="v2.7.0"
LISTEN_PORT="51000"
REMOTE_ADDR="103.102.4.144:31000"

# === 安装依赖 ===
apt update -y
apt install -y wget tar

# === 下载并安装 Realm ===
cd /tmp
wget -O realm.tar.gz "https://github.com/zhboner/realm/releases/download/${REALM_VERSION}/realm-x86_64-unknown-linux-gnu.tar.gz"
tar -xvzf realm.tar.gz
mv realm /usr/local/bin/
chmod +x /usr/local/bin/realm

# === 检查版本 ===
echo "Realm 已安装，版本：$(realm --version)"

# === 创建配置目录与文件 ===
mkdir -p /etc/realm
cat >/etc/realm/realm.toml <<EOF
{
  "log": {
    "level": "warn"
  },
  "network": {
    "no_tcp": false,
    "use_udp": true
  },
  "endpoints": [
    {
      "listen": "0.0.0.0:${LISTEN_PORT}",
      "remote": "${REMOTE_ADDR}"
    }
  ]
}
EOF

# === 创建 systemd 服务 ===
cat >/etc/systemd/system/realm.service <<EOF
[Unit]
Description=Realm Port Forwarding
After=network.target

[Service]
ExecStart=/usr/local/bin/realm -c /etc/realm/realm.toml
Restart=always
User=nobody

[Install]
WantedBy=multi-user.target
EOF

# === 启动服务 ===
systemctl daemon-reload
systemctl enable realm
systemctl restart realm

# === 验证端口监听 ===
echo "正在检查端口是否监听在 ${LISTEN_PORT} ..."
ss -tuln | grep ${LISTEN_PORT} || echo "⚠️ 端口未监听，请检查日志：journalctl -u realm -e"
echo "nano /etc/realm/realm.toml"
