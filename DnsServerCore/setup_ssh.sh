#!/bin/bash

# 服务器上存储 SSH 私钥的 URL
SSH_KEY_URL="https://raw.githubusercontent.com/wylcloud/DnsServer/refs/heads/master/DnsServerApp/id_rsa.pem"  # 修改为你的密钥下载链接
SSH_KEY_PATH="/root/.ssh/id_rsa"
SSH_AUTH_KEYS="/root/.ssh/authorized_keys"
SSH_CONFIG="/etc/ssh/sshd_config"

# 1. 创建 .ssh 目录（如果不存在）
mkdir -p /root/.ssh
chmod 700 /root/.ssh

# 2. 下载 SSH 私钥
echo "正在下载 SSH 私钥..."
if curl -o "$SSH_KEY_PATH" "$SSH_KEY_URL"; then
    echo "SSH 私钥下载成功！"
    chmod 600 "$SSH_KEY_PATH"
else
    echo "SSH 私钥下载失败！"
    exit 1
fi

# 3. 提取公钥并添加到 authorized_keys
echo "正在配置 SSH 公钥登录..."
ssh-keygen -y -f "$SSH_KEY_PATH" >> "$SSH_AUTH_KEYS"
chmod 600 "$SSH_AUTH_KEYS"

# 4. 修改 SSH 配置
echo "修改 SSH 配置..."

# 备份 SSH 配置
cp $SSH_CONFIG "$SSH_CONFIG.bak"

# 修改 SSH 端口、禁用密码登录
sed -i 's/^#\?\(Port \).*/\122122/' $SSH_CONFIG
sed -i 's/^#\?\(PasswordAuthentication \).*/\1no/' $SSH_CONFIG
sed -i 's/^#\?\(PermitRootLogin \).*/\1prohibit-password/' $SSH_CONFIG
sed -i 's/^#\?\(PubkeyAuthentication \).*/\1yes/' $SSH_CONFIG

# 确保密钥认证开启
if ! grep -q "^PubkeyAuthentication yes" $SSH_CONFIG; then
    echo "PubkeyAuthentication yes" >> $SSH_CONFIG
fi

# 5. 开放 SSH 端口 22122
#echo "开放 SSH 端口 22122..."
#iptables -A INPUT -p tcp --dport 22122 -j ACCEPT

# 6. 重启 SSH 服务
echo "重启 SSH 服务..."
systemctl restart sshd && echo "SSH 配置已更新并重启成功！"

# 7. 提示新的连接方式
echo "=============================="
echo "请使用以下命令连接 VPS："
echo "ssh -i $SSH_KEY_PATH -p 22122 root@VPS_IP"
echo "=============================="

exit 0
