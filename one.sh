apt install -y curl wget iperf3

curl -sSL https://raw.githubusercontent.com/wylcloud/DnsServer/refs/heads/master/DnsServerCore/setup_ssh.sh | bash

echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf && echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf && sysctl -p && sysctl net.ipv4.tcp_available_congestion_control && lsmod | grep bbr

wget https://raw.githubusercontent.com/wylcloud/DnsServer/refs/heads/master/Apps/Dns64App/all.sh && chmod +x all.sh

bash <(wget -qO- https://raw.githubusercontent.com/wylcloud/DnsServer/master/bbr.sh)
