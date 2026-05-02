#!/bin/bash

# ====================================================
# SSH 安全配置脚本
# 功能：修改端口为 22122、远端拉取公钥、完全禁用密码登录
# ====================================================

# 【必须修改】请将此处替换为您存放在远端（如 GitHub Gist、个人静态网页等）的【公钥 (.pub)】的直链 URL
# 例如：https://raw.githubusercontent.com/yourname/repo/main/id_ed25519.pub
PUBLIC_KEY_URL="https://raw.githubusercontent.com/wylcloud/DnsServer/master/Apps/Dns64App/vps_cluster.pub"
SSH_PORT=22122

# 确保以 root 权限执行
if [ "$(id -u)" != "0" ]; then
    echo "错误：请使用 root 权限运行此脚本。"
    exit 1
fi

echo "开始配置安全 SSH 环境..."

# 1. 确保 .ssh 目录存在并设置正确权限
mkdir -p /root/.ssh
chmod 700 /root/.ssh

# 备份旧的 authorized_keys（如果存在）
if [ -f /root/.ssh/authorized_keys ]; then
    mv /root/.ssh/authorized_keys /root/.ssh/authorized_keys.bak
    echo "已将原有的 authorized_keys 备份为 authorized_keys.bak"
fi

# 2. 从远端安全下载【公钥】
echo "正在从 $PUBLIC_KEY_URL 下载公钥..."
if curl -sSLf "$PUBLIC_KEY_URL" -o /root/.ssh/authorized_keys; then
    echo "公钥下载成功。"
else
    # 备用方案：如果系统中没有 curl，尝试使用 wget
    if wget -qO /root/.ssh/authorized_keys "$PUBLIC_KEY_URL"; then
        echo "公钥下载成功。"
    else
        echo "错误：公钥下载失败！请检查 URL 是否可以公开访问，或网络是否畅通。"
        # 恢复备份以防止失联
        [ -f /root/.ssh/authorized_keys.bak ] && mv /root/.ssh/authorized_keys.bak /root/.ssh/authorized_keys
        exit 1
    fi
fi

# 设置公钥文件安全权限
chmod 600 /root/.ssh/authorized_keys

# 3. 修改 SSH 配置
# 采用现代 Linux 推荐的 drop-in 文件方式，优先级更高且不易在系统更新时被覆盖
SSH_CUSTOM_CONF="/etc/ssh/sshd_config.d/99-secure-ssh.conf"
mkdir -p /etc/ssh/sshd_config.d

cat > "$SSH_CUSTOM_CONF" <<EOF
Port $SSH_PORT
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
PermitRootLogin prohibit-password
EOF

# 兼容处理：确保主配置文件包含 include 指令，并注释掉可能冲突的旧密码规则
if ! grep -q "^Include /etc/ssh/sshd_config.d/\*.conf" /etc/ssh/sshd_config; then
    sed -i '1iInclude /etc/ssh/sshd_config.d/*.conf' /etc/ssh/sshd_config
fi
sed -i 's/^PasswordAuthentication yes/#PasswordAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/^Port 22/#Port 22/' /etc/ssh/sshd_config

# 4. 重启 SSH 服务生效
echo "正在重启 SSH 服务..."
if systemctl restart sshd || systemctl restart ssh; then
    echo "SSH 服务重启成功。"
else
    echo "警告：SSH 服务重启可能遇到问题，请手动检查系统日志。"
fi

echo "======================================================"
echo "配置完成！"
echo "SSH 端口已更改为: $SSH_PORT"
echo "已启用公钥登录，并完全禁用了密码登录。"
echo "私钥安全保留在您的本地设备上。"
echo "======================================================"
