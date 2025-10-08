#!/bin/bash
set -e

DNS_FILE="/etc/resolv.conf"

apt install -y curl wget iperf3

curl -sSL https://raw.githubusercontent.com/wylcloud/DnsServer/refs/heads/master/DnsServerCore/setup_ssh.sh | bash

echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf && echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf && sysctl -p && sysctl net.ipv4.tcp_available_congestion_control && lsmod | grep bbr

wget https://raw.githubusercontent.com/wylcloud/DnsServer/refs/heads/master/Apps/Dns64App/all.sh && chmod +x all.sh

echo "=== 备份原始 resolv.conf ==="
cp -a $DNS_FILE ${DNS_FILE}.bak.$(date +%s)

echo "=== 写入自定义 DNS ==="
cat > $DNS_FILE <<EOF
nameserver 94.140.14.140
nameserver 94.140.14.141
nameserver 208.67.222.222
nameserver 1.1.1.1
nameserver 8.8.8.8
nameserver 2a10:50c0::1:ff
nameserver 2a10:50c0::2:ff
nameserver 2606:4700:4700::1111
nameserver 2001:4860:4860::8888
EOF

echo "=== 加上 chattr +i 锁定文件 ==="
chattr +i $DNS_FILE

echo "✅ DNS 修改完成，并已锁定。"
echo "如果要解除锁定，可运行： chattr -i $DNS_FILE"

bash <(wget -qO- https://raw.githubusercontent.com/wylcloud/DnsServer/master/bbr.sh)
