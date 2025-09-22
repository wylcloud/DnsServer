#!/bin/bash

# TCP通用优化脚本 - BBR+多队列算法选择+全面调优
# 适用于大多数Linux服务器环境 (包含 Debian 13 Trixie 支持)
# Version: 2.0 - 添加 Debian 13 兼容性，使用 /etc/sysctl.d/ 配置方式

# 检测系统版本
detect_os_version() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_NAME="$NAME"
        OS_VERSION="$VERSION_ID"
        OS_VERSION_CODENAME="${VERSION_CODENAME:-}"
    elif [ -f /etc/debian_version ]; then
        OS_NAME="Debian"
        OS_VERSION=$(cat /etc/debian_version)
        OS_VERSION_CODENAME=""
    else
        OS_NAME="Unknown"
        OS_VERSION="Unknown"
        OS_VERSION_CODENAME=""
    fi
}

# --- 语言选择 ---
echo "----------------------------------------"
echo "Please select a language / 请选择语言:"
echo "1. English"
echo "2. 中文"
echo "----------------------------------------"

LANG_CHOICE="en"
read -p "Enter your choice (1 or 2, default: 1): " choice_num
if [[ "$choice_num" == "2" ]]; then
    LANG_CHOICE="zh"
fi

# 根据语言设置变量
if [[ "$LANG_CHOICE" == "zh" ]]; then
    MSG_WELCOME="TCP通用优化配置脚本 (队列算法可选版)"
    MSG_HEADER="配置内容: BBR + 可选队列算法(FQ/FQ_PIE/CAKE) + TCP全面优化"
    MSG_DEBIAN13_NOTICE="检测到 Debian 13 (Trixie) 系统"
    MSG_USING_SYSCTL_D="将使用 /etc/sysctl.d/ 目录配置方式（推荐）"
    MSG_USING_SYSCTL_CONF="将使用传统 /etc/sysctl.conf 配置方式"
    MSG_DEBIAN13_WARNINGS="⚠️ Debian 13 重要提醒:"
    MSG_DEBIAN13_TMP_WARNING="• /tmp 目录现在存储在内存中(tmpfs)，占用最多50%内存"
    MSG_DEBIAN13_NET_WARNING="• 网卡名称可能会发生改变，请注意检查"
    MSG_DEBIAN13_BOOT_WARNING="• 确保 /boot 分区至少有300MB空闲空间"
    MSG_CHECK_OPENSSH="检查 OpenSSH 版本..."
    MSG_OPENSSH_WARNING="⚠️ 警告: OpenSSH版本过低，远程升级可能中断！建议先更新OpenSSH"
    MSG_REPLACE_NOTICE="重要提示: 将创建新的优化配置，原有自定义配置将被保留。"
    MSG_ROOT_ERROR="请以root权限运行此脚本"
    MSG_SYSTEM_INFO="系统信息:"
    MSG_OS_DETECTED="检测到系统"
    MSG_TOTAL_MEM="内存总量"
    MSG_CPU_CORES="CPU核心数"
    MSG_CHECK_QDISC="检查队列算法支持状态:"
    MSG_SUPPORTED_QDISC="✓ %s - 支持"
    MSG_UNSUPPORTED_QDISC="✗ %s - 不支持"
    MSG_NO_QDISC_ERROR="错误: 系统不支持任何高级队列算法"
    MSG_SUGGEST_KERNEL="建议升级内核或安装相关模块"
    MSG_QDISC_SELECT_TITLE="队列算法选择:"
    MSG_FEATURES_COMPARE="算法特点对比:"
    MSG_QDISC_DESC_FQ="1. FQ (Fair Queue)\n   - 特点: CPU效率高，延迟低，BBR官方推荐\n   - 适用: 通用场景，高性能服务器\n   - 优势: 成熟稳定，资源占用少"
    MSG_QDISC_DESC_FQPIE="2. FQ_PIE (Fair Queue PIE)\n   - 特点: 主动队列管理，更好的缓冲膨胀控制\n   - 适用: 网络拥塞严重的环境\n   - 优势: 延迟控制更精确"
    MSG_QDISC_DESC_CAKE="3. CAKE (Common Applications Kept Enhanced)\n   - 特点: 全功能队列管理，内置流量整形\n   - 适用: 复杂网络环境，需要精细控制\n   - 优势: 功能最全面，但CPU开销较大"
    MSG_QDISC_OPTIONS="可选的队列算法:"
    MSG_FQ_RECOMMENDED=" (推荐)"
    MSG_SELECT_PROMPT="请选择队列算法 (1-%s): "
    MSG_INVALID_CHOICE="无效选择，请输入 1-%s 之间的数字"
    MSG_SELECTED_QDISC="已选择: %s (%s)"
    MSG_RP_FILTER_TITLE="反向路径过滤 (RP_FILTER) 选项:"
    MSG_RP_FILTER_DESC="rp_filter 用于验证数据包的源地址，以防欺骗。\n- 开启 (1): 推荐用于大多数服务器，增强安全性。\n- 关闭 (0): 适用于复杂的路由环境，如非对称路由或多出口NAT。\n注意: 关闭可能会带来安全风险。"
    MSG_RP_FILTER_PROMPT="是否关闭 rp_filter? (y/n, 默认 n): "
    MSG_INVALID_RP_CHOICE="无效选择，请输入 y 或 n"
    MSG_WARNING_NOTICE="提示: 此操作将创建新的优化配置文件"
    MSG_CONFIRM_PROMPT="是否继续? (Y/n): "
    MSG_CANCELLED="操作已取消"
    MSG_BACKUP="备份原配置到: %s"
    MSG_DYNAMIC_CONFIG="动态计算的配置值:"
    MSG_RP_FILTER_STATUS="反向路径过滤"
    MSG_RP_FILTER_ON="开启"
    MSG_RP_FILTER_OFF="关闭"
    MSG_RECV_MAX="接收缓冲区最大值"
    MSG_SEND_MAX="发送缓冲区最大值"
    MSG_NETDEV_QUEUE="网络设备队列"
    MSG_LISTEN_QUEUE="监听队列"
    MSG_WRITING_FILE="正在创建配置文件..."
    MSG_FILE_GENERATED="✓ 新的配置文件已生成"
    MSG_LOADING_MODULES="加载必要的内核模块..."
    MSG_APPLYING_CONFIG="正在应用配置..."
    MSG_VERIFY_RESULTS="验证配置结果:"
    MSG_COMPARISON_TITLE="参数对比 (修改前后):"
    MSG_OLD_VALUE="旧值"
    MSG_NEW_VALUE="新值"
    MSG_NOT_CONFIGURED="未配置"
    MSG_CONGESTION_CONTROL="拥塞控制算法"
    MSG_QDISC_ALGORITHM="队列调度算法"
    MSG_RECV_MAX_VERIFY="接收缓冲区最大"
    MSG_SEND_MAX_VERIFY="发送缓冲区最大"
    MSG_LISTEN_VERIFY="连接队列大小"
    MSG_IP_FORWARD_VERIFY="IP转发状态"
    MSG_QDISC_SUCCESS="✓ 队列算法 %s 配置成功"
    MSG_QDISC_WARN="⚠ 队列算法配置可能有问题 (期望: %s, 实际: %s)"
    MSG_SYS_LIMITS_TITLE="系统限制优化:"
    MSG_CHECKING_LIMITS="检查 /etc/security/limits.conf..."
    MSG_LIMITS_SELECT_TITLE="请根据您的服务器用途选择文件句柄和进程数限制:"
    MSG_LIMITS_DESC_GENERAL="1. 通用/中低负载服务器 (推荐值: 65536)\n   - 适用于大多数网站、应用或个人服务器。"
    MSG_LIMITS_DESC_HIGH_CONCURRENCY="2. 高并发/高负载服务器 (推荐值: 1048576)\n   - 适用于Web服务器(如Nginx)、数据库(如Redis)等。"
    MSG_LIMITS_PROMPT="请选择您的用途 (1 or 2): "
    MSG_LIMITS_ADDED="✓ 已添加到 limits.conf"
    MSG_LIMITS_OK="✓ limits.conf 已包含文件描述符优化"
    MSG_RELOGIN_NOTICE="提示: limits.conf 的更改需要您**重新登录**或**重启相关服务**后才能生效。"
    MSG_OPTIMIZATION_COMPLETE="优化完成!"
    MSG_CONFIG_FEATURES="配置特点:"
    MSG_MODERN_CONFIG="✓ 使用现代化配置方式 (/etc/sysctl.d/)"
    MSG_REPLACE_CONFIG="✓ 独立配置文件，不影响系统默认配置"
    MSG_BBR_QDISC="✓ 使用BBR+%s (已选择: %s)"
    MSG_RP_FILTER_FEATURE="✓ 反向路径过滤 (RP_FILTER): %s"
    MSG_IP_FORWARD_FEATURE="✓ 启用IP转发 (支持路由/代理)"
    MSG_RTT_ADAPTIVE="✓ 保持RTT相关参数完全自适应"
    MSG_DYNAMIC_BUFFER="✓ 动态缓冲区计算 (基于系统内存: %sMB)"
    MSG_FORWARDING_OPTIMIZED="✓ 转发性能优化 (路由表/邻居表)"
    MSG_IPV6_SUPPORT="✓ IPv6转发支持"
    MSG_CONNECTION_OPTIMIZED="✓ 连接处理优化"
    MSG_VM_OPTIMIZED="✓ 虚拟内存优化"
    MSG_FS_OPTIMIZED="✓ 文件系统优化"
    MSG_QDISC_FEATURES="队列算法特性:"
    MSG_FQ_FEATURE="FQ: 低延迟，高效率，CPU友好\n- 适合: 高性能服务器，通用场景"
    MSG_FQPIE_FEATURE="FQ_PIE: 主动队列管理，缓冲膨胀控制\n- 适合: 网络拥塞环境，延迟敏感应用"
    MSG_CAKE_FEATURE="CAKE: 全功能队列管理，内置流量整形\n- 适合: 复杂网络环境，需要精细控制"
    MSG_MEM_LEVEL="内存配置等级: %s"
    MSG_SMALL_MEM="小内存 (<1GB)"
    MSG_MEDIUM_MEM="中等内存 (1-4GB)"
    MSG_LARGE_MEM="大内存 (>4GB)"
    MSG_RTT_NOTES="RTT相关参数说明:"
    MSG_WINDOW_SIZES="所有窗口大小: 内核自动计算"
    MSG_TIMEOUTS="超时重传: 内核RTT测量决定"
    MSG_CONGESTION_WINDOW="拥塞窗口: BBR算法自动管理"
    MSG_ADAPTIVE_NOTE="确保在各种网络环境下最佳适配"
    MSG_INSTANT_REBOOT="配置立即生效，重启后永久生效"
    MSG_ROLLBACK_TITLE="回滚方法:"
    MSG_ROLLBACK_INSTRUCTIONS="如需回滚，执行以下命令:"
    MSG_CONFIG_LOCATION_TITLE="配置文件位置:"
    MSG_CURRENT_CONFIG="当前配置"
    MSG_BACKUP_FILE="备份文件: %s"
    MSG_THANKS="感谢您使用本脚本"
    MSG_THANKS_ISIF="感谢ISIF的杂鱼的宝贵意见"
    MSG_ISIF_LINK="(https://cloud.isif.net，中国优化线路服务器)"
else
    MSG_WELCOME="TCP Generic Optimization Script (Selectable Queue Discipline)"
    MSG_HEADER="Configuration: BBR + Selectable Queue Discipline (FQ/FQ_PIE/CAKE) + Full TCP Tuning"
    MSG_DEBIAN13_NOTICE="Detected Debian 13 (Trixie) system"
    MSG_USING_SYSCTL_D="Will use /etc/sysctl.d/ directory configuration (recommended)"
    MSG_USING_SYSCTL_CONF="Will use traditional /etc/sysctl.conf configuration"
    MSG_DEBIAN13_WARNINGS="⚠️ Debian 13 Important Notes:"
    MSG_DEBIAN13_TMP_WARNING="• /tmp directory is now stored in memory (tmpfs), using up to 50% of RAM"
    MSG_DEBIAN13_NET_WARNING="• Network interface names may change, please check carefully"
    MSG_DEBIAN13_BOOT_WARNING="• Ensure /boot partition has at least 300MB free space"
    MSG_CHECK_OPENSSH="Checking OpenSSH version..."
    MSG_OPENSSH_WARNING="⚠️ Warning: OpenSSH version too low, remote upgrade may fail! Recommend updating OpenSSH first"
    MSG_REPLACE_NOTICE="IMPORTANT: Will create new optimization config, existing custom configurations will be preserved."
    MSG_ROOT_ERROR="Please run this script as root"
    MSG_SYSTEM_INFO="System Information:"
    MSG_OS_DETECTED="Detected System"
    MSG_TOTAL_MEM="Total Memory"
    MSG_CPU_CORES="CPU Cores"
    MSG_CHECK_QDISC="Checking Queue Discipline Support:"
    MSG_SUPPORTED_QDISC="✓ %s - Supported"
    MSG_UNSUPPORTED_QDISC="✗ %s - Not Supported"
    MSG_NO_QDISC_ERROR="Error: System does not support any advanced queue disciplines."
    MSG_SUGGEST_KERNEL="Suggestion: Upgrade your kernel or install relevant modules."
    MSG_QDISC_SELECT_TITLE="Queue Discipline Selection:"
    MSG_FEATURES_COMPARE="Features comparison:"
    MSG_QDISC_DESC_FQ="1. FQ (Fair Queue)\n   - Features: High CPU efficiency, low latency, recommended by BBR developers.\n   - Use Case: General purpose, high-performance servers.\n   - Advantage: Mature, stable, and low resource usage."
    MSG_QDISC_DESC_FQPIE="2. FQ_PIE (Fair Queue PIE)\n   - Features: Active queue management, better bufferbloat control.\n   - Use Case: Environments with severe network congestion.\n   - Advantage: More precise latency control."
    MSG_QDISC_DESC_CAKE="3. CAKE (Common Applications Kept Enhanced)\n   - Features: All-in-one queue management with built-in traffic shaping.\n   - Use Case: Complex network environments requiring fine-grained control.\n   - Advantage: Most comprehensive features, but with higher CPU overhead."
    MSG_QDISC_OPTIONS="Available Queue Disciplines:"
    MSG_FQ_RECOMMENDED=" (recommended)"
    MSG_SELECT_PROMPT="Please select a queue discipline (1-%s): "
    MSG_INVALID_CHOICE="Invalid choice. Please enter a number between 1-%s"
    MSG_SELECTED_QDISC="Selected: %s (%s)"
    MSG_RP_FILTER_TITLE="Reverse Path Filtering (RP_FILTER) Option:"
    MSG_RP_FILTER_DESC="rp_filter validates the source address of packets to prevent spoofing.\n- Enabled (1): Recommended for most servers to enhance security.\n- Disabled (0): Suitable for complex routing environments like asymmetric routing or multi-homed NAT."
    MSG_RP_FILTER_PROMPT="Do you want to disable rp_filter? (y/n, default n): "
    MSG_INVALID_RP_CHOICE="Invalid choice. Please enter y or n"
    MSG_WARNING_NOTICE="Note: This operation will create a new optimization configuration file"
    MSG_CONFIRM_PROMPT="Continue? (Y/n): "
    MSG_CANCELLED="Operation cancelled"
    MSG_BACKUP="Backing up original config to: %s"
    MSG_DYNAMIC_CONFIG="Dynamically Calculated Configuration Values:"
    MSG_RP_FILTER_STATUS="Reverse Path Filtering"
    MSG_RP_FILTER_ON="Enabled"
    MSG_RP_FILTER_OFF="Disabled"
    MSG_RECV_MAX="Receive Buffer Max"
    MSG_SEND_MAX="Send Buffer Max"
    MSG_NETDEV_QUEUE="Network Device Queue"
    MSG_LISTEN_QUEUE="Listen Queue"
    MSG_WRITING_FILE="Creating configuration file..."
    MSG_FILE_GENERATED="✓ New configuration file has been generated"
    MSG_LOADING_MODULES="Loading necessary kernel modules..."
    MSG_APPLYING_CONFIG="Applying configuration..."
    MSG_VERIFY_RESULTS="Verifying Configuration:"
    MSG_COMPARISON_TITLE="Parameter Comparison (Before vs After):"
    MSG_OLD_VALUE="Old Value"
    MSG_NEW_VALUE="New Value"
    MSG_NOT_CONFIGURED="Not Configured"
    MSG_CONGESTION_CONTROL="Congestion Control Algorithm"
    MSG_QDISC_ALGORITHM="Queue Discipline Algorithm"
    MSG_RECV_MAX_VERIFY="Receive Buffer Max"
    MSG_SEND_MAX_VERIFY="Send Buffer Max"
    MSG_LISTEN_VERIFY="Listen Queue Size"
    MSG_IP_FORWARD_VERIFY="IP Forwarding Status"
    MSG_QDISC_SUCCESS="✓ Queue discipline %s configured successfully"
    MSG_QDISC_WARN="⚠ Queue discipline configuration may have an issue (Expected: %s, Actual: %s)"
    MSG_SYS_LIMITS_TITLE="System Limits Optimization:"
    MSG_CHECKING_LIMITS="Checking /etc/security/limits.conf..."
    MSG_LIMITS_SELECT_TITLE="Please select file descriptor and process limits based on your server's use case:"
    MSG_LIMITS_DESC_GENERAL="1. General / Low-to-medium Load Servers (Recommended: 65536)\n   - Suitable for most websites, applications, or personal servers."
    MSG_LIMITS_DESC_HIGH_CONCURRENCY="2. High-concurrency / High-load Servers (Recommended: 1048576)\n   - Suitable for Web servers (e.g., Nginx), databases (e.g., Redis), proxy services, etc."
    MSG_LIMITS_PROMPT="Please select your use case (1 or 2): "
    MSG_LIMITS_ADDED="✓ Added to limits.conf"
    MSG_LIMITS_OK="✓ limits.conf already contains file descriptor optimizations"
    MSG_RELOGIN_NOTICE="Note: changes to limits.conf require you to **log out and log back in** or **restart the relevant services** to take effect."
    MSG_OPTIMIZATION_COMPLETE="Optimization Complete!"
    MSG_CONFIG_FEATURES="Configuration Features:"
    MSG_MODERN_CONFIG="✓ Using modern configuration method (/etc/sysctl.d/)"
    MSG_REPLACE_CONFIG="✓ Independent configuration file, does not affect system defaults"
    MSG_BBR_QDISC="✓ Uses BBR+%s (Selected: %s)"
    MSG_RP_FILTER_FEATURE="✓ Reverse Path Filtering (RP_FILTER): %s"
    MSG_IP_FORWARD_FEATURE="✓ Enables IP forwarding (for routing/proxying)"
    MSG_RTT_ADAPTIVE="✓ RTT-related parameters are fully self-adaptive"
    MSG_DYNAMIC_BUFFER="✓ Dynamic buffer calculation (based on system memory: %sMB)"
    MSG_FORWARDING_OPTIMIZED="✓ Optimized forwarding performance (route/neighbor tables)"
    MSG_IPV6_SUPPORT="✓ IPv6 forwarding support"
    MSG_CONNECTION_OPTIMIZED="✓ Connection handling optimization"
    MSG_VM_OPTIMIZED="✓ Virtual memory optimization"
    MSG_FS_OPTIMIZED="✓ Filesystem optimization"
    MSG_QDISC_FEATURES="Queue Discipline Characteristics:"
    MSG_FQ_FEATURE="FQ: Low latency, high efficiency, CPU friendly\n- Suitable for: High-performance servers, general-purpose scenarios"
    MSG_FQPIE_FEATURE="FQ_PIE: Active queue management, bufferbloat control\n- Suitable for: Congested network environments, latency-sensitive applications"
    MSG_CAKE_FEATURE="CAKE: All-in-one queue management with built-in traffic shaping\n- Suitable for: Complex network environments needing fine-grained control"
    MSG_MEM_LEVEL="Memory Configuration Level: %s"
    MSG_SMALL_MEM="Small memory (<1GB)"
    MSG_MEDIUM_MEM="Medium memory (1-4GB)"
    MSG_LARGE_MEM="Large memory (>4GB)"
    MSG_RTT_NOTES="Notes on RTT Parameters:"
    MSG_WINDOW_SIZES="All window sizes: Calculated automatically by the kernel"
    MSG_TIMEOUTS="Retransmission timeouts: Determined by kernel RTT measurements"
    MSG_CONGESTION_WINDOW="Congestion window: Managed automatically by the BBR algorithm"
    MSG_ADAPTIVE_NOTE="Ensures optimal adaptation in various network environments"
    MSG_INSTANT_REBOOT="Configuration is effective immediately and persists after reboot"
    MSG_ROLLBACK_TITLE="Rollback Method:"
    MSG_ROLLBACK_INSTRUCTIONS="To roll back, execute the following commands:"
    MSG_CONFIG_LOCATION_TITLE="Configuration File Location:"
    MSG_CURRENT_CONFIG="Current config"
    MSG_BACKUP_FILE="Backup file: %s"
    MSG_THANKS="Thank you for using this script"
    MSG_THANKS_ISIF="Special thanks to ISIF的杂鱼 for the valuable suggestions"
    MSG_ISIF_LINK="(https://cloud.isif.net, servers with optimized China routes)"
fi

echo "$MSG_WELCOME"
echo "========================================"
echo "$MSG_HEADER"
echo ""

# 检测系统版本
detect_os_version
echo "$MSG_OS_DETECTED: $OS_NAME $OS_VERSION ${OS_VERSION_CODENAME:+(${OS_VERSION_CODENAME})}"

# 判断是否为 Debian 13 或更高版本
USE_SYSCTL_D=0
IS_DEBIAN13=0

if [[ "$OS_NAME" == *"Debian"* ]]; then
    # 检查是否为 Debian 13 (Trixie) 或更高版本
    if [[ "$OS_VERSION" == "13" ]] || [[ "$OS_VERSION_CODENAME" == "trixie" ]] || [[ "$OS_VERSION" == "testing" ]] || [[ "$OS_VERSION" == "unstable" ]]; then
        IS_DEBIAN13=1
        USE_SYSCTL_D=1
        echo ""
        echo "⭐ $MSG_DEBIAN13_NOTICE"
        echo "$MSG_USING_SYSCTL_D"
        
        # 显示 Debian 13 特有警告
        echo ""
        echo "$MSG_DEBIAN13_WARNINGS"
        echo "$MSG_DEBIAN13_TMP_WARNING"
        echo "$MSG_DEBIAN13_NET_WARNING"
        echo "$MSG_DEBIAN13_BOOT_WARNING"
        
        # 检查 OpenSSH 版本（如果通过 SSH 连接）
        if [ -n "$SSH_CONNECTION" ]; then
            echo ""
            echo "$MSG_CHECK_OPENSSH"
            if command -v ssh -V &> /dev/null; then
                SSH_VERSION=$(ssh -V 2>&1 | grep -oE 'OpenSSH_[0-9]+\.[0-9]+')
                SSH_MAJOR=$(echo $SSH_VERSION | cut -d'_' -f2 | cut -d'.' -f1)
                SSH_MINOR=$(echo $SSH_VERSION | cut -d'_' -f2 | cut -d'.' -f2)
                
                if [ "$SSH_MAJOR" -lt 9 ] || ([ "$SSH_MAJOR" -eq 9 ] && [ "$SSH_MINOR" -lt 2 ]); then
                    echo "$MSG_OPENSSH_WARNING"
                    echo "wget -O upgrade_openssh.sh https://gist.github.com/Seameee/2061e673132b05e5ed8dd6eb125f1fd1/raw/upgrade_openssh.sh && sudo chmod +x ./upgrade_openssh.sh && sudo ./upgrade_openssh.sh"
                fi
            fi
        fi
        
        # 检查 /boot 分区空间
        if df /boot &> /dev/null; then
            BOOT_FREE=$(df /boot | awk 'NR==2 {print $4}')
            if [ "$BOOT_FREE" -lt 307200 ]; then  # 300MB in KB
                echo ""
                echo "⚠️ /boot: ${BOOT_FREE}KB free (recommend >300MB)"
            fi
        fi
    elif [[ "$OS_VERSION" =~ ^(10|11|12)$ ]]; then
        # Debian 10, 11, 12 可以选择使用哪种方式
        echo ""
        if [[ "$LANG_CHOICE" == "zh" ]]; then
            echo "检测到 Debian $OS_VERSION，建议使用 /etc/sysctl.d/ 配置方式"
            read -p "使用现代配置方式? (Y/n): " use_modern
        else
            echo "Detected Debian $OS_VERSION, recommend using /etc/sysctl.d/ configuration"
            read -p "Use modern configuration method? (Y/n): " use_modern
        fi
        
        if [ "$use_modern" != "n" ] && [ "$use_modern" != "N" ]; then
            USE_SYSCTL_D=1
        fi
    fi
fi

# 对于其他发行版，也推荐使用 sysctl.d
if [[ "$USE_SYSCTL_D" -eq 0 ]] && [ -d /etc/sysctl.d ]; then
    if [[ "$LANG_CHOICE" == "zh" ]]; then
        echo ""
        echo "检测到系统支持 /etc/sysctl.d/ 目录"
        read -p "使用现代配置方式? (推荐) (Y/n): " use_modern
    else
        echo ""
        echo "System supports /etc/sysctl.d/ directory"
        read -p "Use modern configuration method? (recommended) (Y/n): " use_modern
    fi
    
    if [ "$use_modern" != "n" ] && [ "$use_modern" != "N" ]; then
        USE_SYSCTL_D=1
    fi
fi

# 设置配置文件路径
if [ "$USE_SYSCTL_D" -eq 1 ]; then
    CONFIG_FILE="/etc/sysctl.d/99-tcp-bbr-optimization.conf"
    echo "$MSG_USING_SYSCTL_D"
else
    CONFIG_FILE="/etc/sysctl.conf"
    echo "$MSG_USING_SYSCTL_CONF"
fi

echo ""
echo -e "$MSG_REPLACE_NOTICE"
echo ""

# 检查权限
if [ "$EUID" -ne 0 ]; then
    echo "$MSG_ROOT_ERROR"
    exit 1
fi

# 获取系统信息
TOTAL_MEM=$(free -m | awk 'NR==2{print $2}')
CPU_CORES=$(nproc)

echo "$MSG_SYSTEM_INFO"
echo "$MSG_TOTAL_MEM: ${TOTAL_MEM}MB"
echo "$MSG_CPU_CORES: ${CPU_CORES}"
echo ""

# 检查内核模块支持
echo "$MSG_CHECK_QDISC"
echo "======================"

# 检查可用的队列算法
FQ_AVAILABLE=0
FQ_PIE_AVAILABLE=0
CAKE_AVAILABLE=0

# Re-check for support and display properly
if modprobe sch_fq 2>/dev/null; then
    FQ_AVAILABLE=1
    printf "$MSG_SUPPORTED_QDISC\n" "FQ (Fair Queue)"
else
    printf "$MSG_UNSUPPORTED_QDISC\n" "FQ (Fair Queue)"
fi

if modprobe sch_fq_pie 2>/dev/null; then
    FQ_PIE_AVAILABLE=1
    printf "$MSG_SUPPORTED_QDISC\n" "FQ_PIE (Fair Queue PIE)"
else
    printf "$MSG_UNSUPPORTED_QDISC\n" "FQ_PIE (Fair Queue PIE)"
fi

if modprobe sch_cake 2>/dev/null; then
    CAKE_AVAILABLE=1
    printf "$MSG_SUPPORTED_QDISC\n" "CAKE (Common Applications Kept Enhanced)"
else
    printf "$MSG_UNSUPPORTED_QDISC\n" "CAKE (Common Applications Kept Enhanced)"
fi

echo ""

# 如果没有任何支持的算法，退出
if [ $FQ_AVAILABLE -eq 0 ] && [ $FQ_PIE_AVAILABLE -eq 0 ] && [ $CAKE_AVAILABLE -eq 0 ]; then
    echo "$MSG_NO_QDISC_ERROR"
    echo "$MSG_SUGGEST_KERNEL"
    exit 1
fi

# 队列算法选择
echo "$MSG_QDISC_SELECT_TITLE"
echo "=============="
echo ""
echo "$MSG_FEATURES_COMPARE"
echo "-------------"
echo -e "$MSG_QDISC_DESC_FQ"
echo ""
echo -e "$MSG_QDISC_DESC_FQPIE"
echo ""
echo -e "$MSG_QDISC_DESC_CAKE"
echo ""

# 生成选择菜单
QDISC_OPTIONS=()
QDISC_VALUES=()
if [ "$LANG_CHOICE" == "zh" ]; then
    FQ_RECOMMENDED=" (推荐)"
else
    FQ_RECOMMENDED=" (recommended)"
fi

if [ $FQ_AVAILABLE -eq 1 ]; then
    QDISC_OPTIONS+=("FQ$FQ_RECOMMENDED")
    QDISC_VALUES+=("fq")
fi

if [ $FQ_PIE_AVAILABLE -eq 1 ]; then
    QDISC_OPTIONS+=("FQ_PIE")
    QDISC_VALUES+=("fq_pie")
fi

if [ $CAKE_AVAILABLE -eq 1 ]; then
    QDISC_OPTIONS+=("CAKE")
    QDISC_VALUES+=("cake")
fi

echo "$MSG_QDISC_OPTIONS"
for i in "${!QDISC_OPTIONS[@]}"; do
    echo "$((i+1)). ${QDISC_OPTIONS[$i]}"
done
echo ""

# 用户选择
while true; do
    printf "$MSG_SELECT_PROMPT" "${#QDISC_OPTIONS[@]}"
    read choice
    if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le "${#QDISC_OPTIONS[@]}" ]; then
        SELECTED_QDISC="${QDISC_VALUES[$((choice-1))]}"
        SELECTED_NAME="${QDISC_OPTIONS[$((choice-1))]}"
        break
    else
        printf "$MSG_INVALID_CHOICE\n" "${#QDISC_OPTIONS[@]}"
    fi
done

echo ""
printf "$MSG_SELECTED_QDISC\n" "$SELECTED_NAME" "$SELECTED_QDISC"
echo ""

# RP Filter 选择
echo "$MSG_RP_FILTER_TITLE"
echo "=================================="
echo -e "$MSG_RP_FILTER_DESC"
echo ""

while true; do
    read -p "$MSG_RP_FILTER_PROMPT" disable_rp_filter
    disable_rp_filter=${disable_rp_filter:-n}
    if [ "$disable_rp_filter" = "y" ] || [ "$disable_rp_filter" = "Y" ]; then
        RP_FILTER_VALUE=0
        break
    elif [ "$disable_rp_filter" = "n" ] || [ "$disable_rp_filter" = "N" ]; then
        RP_FILTER_VALUE=1
        break
    else
        echo "$MSG_INVALID_RP_CHOICE"
    fi
done

echo ""
echo "$MSG_WARNING_NOTICE"
read -p "$MSG_CONFIRM_PROMPT" confirm
if [ "$confirm" = "n" ] || [ "$confirm" = "N" ]; then
    echo "$MSG_CANCELLED"
    exit 0
fi

# 备份配置
if [ "$USE_SYSCTL_D" -eq 1 ]; then
    # 如果使用 sysctl.d，备份已存在的同名文件
    if [ -f "$CONFIG_FILE" ]; then
        BACKUP_FILE="${CONFIG_FILE}.backup.$(date +%Y%m%d_%H%M%S)"
        printf "$MSG_BACKUP\n" "$BACKUP_FILE"
        cp "$CONFIG_FILE" "$BACKUP_FILE"
    fi
else
    # 备份原 sysctl.conf
    BACKUP_FILE="/etc/sysctl.conf.backup.$(date +%Y%m%d_%H%M%S)"
    printf "$MSG_BACKUP\n" "$BACKUP_FILE"
    cp /etc/sysctl.conf "$BACKUP_FILE"
fi

# 保存当前参数值用于比较
OLD_CONGESTION=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "$MSG_NOT_CONFIGURED")
OLD_QDISC=$(sysctl -n net.core.default_qdisc 2>/dev/null || echo "$MSG_NOT_CONFIGURED")
OLD_RMEM_MAX=$(sysctl -n net.core.rmem_max 2>/dev/null || echo "$MSG_NOT_CONFIGURED")
OLD_WMEM_MAX=$(sysctl -n net.core.wmem_max 2>/dev/null || echo "$MSG_NOT_CONFIGURED")
OLD_SOMAXCONN=$(sysctl -n net.core.somaxconn 2>/dev/null || echo "$MSG_NOT_CONFIGURED")
OLD_RP_FILTER=$(sysctl -n net.ipv4.conf.default.rp_filter 2>/dev/null || echo "$MSG_NOT_CONFIGURED")
OLD_IP_FORWARD=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo "$MSG_NOT_CONFIGURED")

# 计算动态值
# 基于内存计算缓冲区大小 (避免固定值导致的不适配)
if [ $TOTAL_MEM -lt 1048 ]; then
    # 小内存服务器 (<1GB)
    RMEM_MAX=16777216     # 16MB
    WMEM_MAX=16777216     # 16MB
    NETDEV_MAX_BACKLOG=2500
    SOMAXCONN=1024
    TCP_MEM="94500000 915000000 927000000"
    
    # Debian 13 小内存系统特别注意
    if [ "$IS_DEBIAN13" -eq 1 ]; then
        if [[ "$LANG_CHOICE" == "zh" ]]; then
            echo "⚠️ 注意: 小内存系统 + Debian 13 的 /tmp 在内存中，可能影响性能"
        else
            echo "⚠️ Note: Small memory system + Debian 13's /tmp in memory may affect performance"
        fi
    fi
elif [ $TOTAL_MEM -lt 4096 ]; then
    # 中等内存服务器 (1-4GB)
    RMEM_MAX=33554432     # 32MB
    WMEM_MAX=33554432     # 32MB
    NETDEV_MAX_BACKLOG=3000
    SOMAXCONN=2048
    TCP_MEM="131072000 1747626667 2097152000"
else
    # 大内存服务器 (>4GB)
    RMEM_MAX=67108864     # 64MB
    WMEM_MAX=67108864     # 64MB
    NETDEV_MAX_BACKLOG=5000
    SOMAXCONN=4096
    TCP_MEM="262144000 3495253333 4194304000"
fi

# 基于CPU核心数调整队列数量
NETDEV_BUDGET=$((CPU_CORES * 300))
if [ $NETDEV_BUDGET -gt 600 ]; then
    NETDEV_BUDGET=600
fi

echo "$MSG_DYNAMIC_CONFIG"
printf "$MSG_SELECTED_QDISC\n" "$SELECTED_QDISC" ""
printf "$MSG_RP_FILTER_STATUS: %s\n" "$(if [ $RP_FILTER_VALUE -eq 1 ]; then echo "$MSG_RP_FILTER_ON"; else echo "$MSG_RP_FILTER_OFF"; fi)"
echo "$MSG_RECV_MAX: $RMEM_MAX"
echo "$MSG_SEND_MAX: $WMEM_MAX"
echo "$MSG_NETDEV_QUEUE: $NETDEV_MAX_BACKLOG"
echo "$MSG_LISTEN_QUEUE: $SOMAXCONN"
echo ""

# 创建配置文件
echo "$MSG_WRITING_FILE"
cat > "$CONFIG_FILE" << EOF
# TCP通用优化配置 - BBR+${SELECTED_QDISC^^}+全面调优
# 生成时间: $(date)
# 系统: $OS_NAME $OS_VERSION ${OS_VERSION_CODENAME:+(${OS_VERSION_CODENAME})}
# 系统配置: ${TOTAL_MEM}MB RAM, ${CPU_CORES} CPU cores
# 队列算法: $SELECTED_QDISC ($SELECTED_NAME)
# RP_FILTER: $(if [ $RP_FILTER_VALUE -eq 1 ]; then echo "$MSG_RP_FILTER_ON"; else echo "$MSG_RP_FILTER_OFF"; fi)
# ===================================================

# ===================================
# BBR拥塞控制 + $SELECTED_QDISC 队列调度
# ===================================
net.core.default_qdisc = $SELECTED_QDISC
net.ipv4.tcp_congestion_control = bbr

# ===================================
# 网络核心参数优化
# ===================================
net.core.rmem_max = $RMEM_MAX
net.core.wmem_max = $WMEM_MAX
net.core.rmem_default = 262144
net.core.wmem_default = 262144
net.core.netdev_max_backlog = $NETDEV_MAX_BACKLOG
net.core.netdev_budget = $NETDEV_BUDGET
net.core.somaxconn = $SOMAXCONN

# ===================================
# TCP连接管理优化
# ===================================
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 3
net.ipv4.tcp_syn_retries = 3
net.ipv4.tcp_synack_retries = 3
net.ipv4.tcp_retries1 = 3
net.ipv4.tcp_retries2 = 8
net.ipv4.tcp_fin_timeout = 10
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_max_tw_buckets = 65536
net.ipv4.tcp_max_orphans = 65536
net.ipv4.tcp_max_syn_backlog = 8192

# ===================================
# TCP性能增强
# ===================================
net.ipv4.tcp_slow_start_after_idle = 0
$(if [ -e /proc/sys/net/ipv4/tcp_abc ]; then echo "net.ipv4.tcp_abc = 1"; fi)
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_fack = 1
net.ipv4.tcp_dsack = 1
net.ipv4.tcp_ecn = 1
net.ipv4.tcp_frto = 2
net.ipv4.tcp_low_latency = 1
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_moderate_rcvbuf = 1

# ===================================
# TCP内存管理 (RTT自适应缓冲区)
# ===================================
net.ipv4.tcp_rmem = 8192 131072 $RMEM_MAX
net.ipv4.tcp_wmem = 8192 131072 $WMEM_MAX
net.ipv4.tcp_mem = $TCP_MEM

# ===================================
# UDP缓冲区优化
# ===================================
net.ipv4.udp_rmem_min = 8192
net.ipv4.udp_wmem_min = 8192

# ===================================
# IP层优化
# ===================================
net.ipv4.ip_forward = 1
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.route.gc_timeout = 100

# ===================================
# 转发性能优化
# ===================================
net.ipv4.conf.all.forwarding = 1
net.ipv4.conf.default.forwarding = 1
net.ipv4.route.max_size = 2097152
net.ipv4.neigh.default.gc_thresh1 = 2048
net.ipv4.neigh.default.gc_thresh2 = 4096
net.ipv4.neigh.default.gc_thresh3 = 8192
net.ipv4.neigh.default.gc_stale_time = 120

# ===================================
# 网络安全优化 (转发环境适配)
# ===================================
net.ipv4.conf.default.rp_filter = $RP_FILTER_VALUE
net.ipv4.conf.all.rp_filter = $RP_FILTER_VALUE
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.default.log_martians = 0
net.ipv4.conf.all.log_martians = 0

# ===================================
# 转发环境ICMP优化
# ===================================
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.icmp_errors_use_inbound_ifaddr = 1

# ===================================
# IPv6转发支持
# ===================================
net.ipv6.conf.all.forwarding = 1
net.ipv6.conf.default.forwarding = 1
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# ===================================
# 文件系统优化
# ===================================
fs.file-max = 1048576
fs.nr_open = 1048576

# ===================================
# 进程优化
# ===================================
kernel.pid_max = 65536

# ===================================
# 虚拟内存优化
# ===================================
vm.swappiness = 10
vm.dirty_ratio = 15
vm.dirty_background_ratio = 5
vm.vfs_cache_pressure = 50

# ===================================
# 其他系统优化
# ===================================
kernel.shmmax = 4294967296
kernel.shmall = 1048576
kernel.msgmnb = 65536
kernel.msgmax = 65536

# TCP优化配置结束 - 队列算法: $SELECTED_QDISC
EOF

echo "$MSG_FILE_GENERATED"
echo ""

# 加载所需的内核模块
echo "$MSG_LOADING_MODULES"
modprobe tcp_bbr 2>/dev/null

case $SELECTED_QDISC in
    "fq")
        modprobe sch_fq 2>/dev/null
        ;;
    "fq_pie")
        modprobe sch_fq_pie 2>/dev/null
        ;;
    "cake")
        modprobe sch_cake 2>/dev/null
        ;;
esac

# 应用配置
echo "$MSG_APPLYING_CONFIG"
if [ "$USE_SYSCTL_D" -eq 1 ]; then
    # 使用 sysctl.d 时，只加载特定文件
    sysctl -p "$CONFIG_FILE"
else
    # 传统方式，加载整个 sysctl.conf
    sysctl -p
fi

# 参数对比功能
echo ""
echo "$MSG_COMPARISON_TITLE"
echo "=========================================================="
printf "%-30s | %-15s | %-15s\n" "Parameter" "$MSG_OLD_VALUE" "$MSG_NEW_VALUE"
printf -- "-%.0s" {1..65}; echo

# 显示参数对比
declare -A params
params[${MSG_CONGESTION_CONTROL}]="net.ipv4.tcp_congestion_control"
params[${MSG_QDISC_ALGORITHM}]="net.core.default_qdisc"
params[${MSG_RECV_MAX_VERIFY}]="net.core.rmem_max"
params[${MSG_SEND_MAX_VERIFY}]="net.core.wmem_max"
params[${MSG_LISTEN_VERIFY}]="net.core.somaxconn"
params[${MSG_RP_FILTER_STATUS}]="net.ipv4.conf.default.rp_filter"
params[${MSG_IP_FORWARD_VERIFY}]="net.ipv4.ip_forward"

for param_name in "${!params[@]}"; do
    key=${params[$param_name]}
    
    # 获取旧值（已在前面保存）
    case "$key" in
        "net.ipv4.tcp_congestion_control") OLD_VAL="$OLD_CONGESTION";;
        "net.core.default_qdisc") OLD_VAL="$OLD_QDISC";;
        "net.core.rmem_max") OLD_VAL="$OLD_RMEM_MAX";;
        "net.core.wmem_max") OLD_VAL="$OLD_WMEM_MAX";;
        "net.core.somaxconn") OLD_VAL="$OLD_SOMAXCONN";;
        "net.ipv4.conf.default.rp_filter") OLD_VAL="$OLD_RP_FILTER";;
        "net.ipv4.ip_forward") OLD_VAL="$OLD_IP_FORWARD";;
        *) OLD_VAL="$MSG_NOT_CONFIGURED";;
    esac
    
    # 获取新值
    NEW_VAL=$(sysctl -n "$key" 2>/dev/null || echo "$MSG_NOT_CONFIGURED")
    
    printf "%-30s | %-15s | %-15s\n" "$param_name" "$OLD_VAL" "$NEW_VAL"
done

echo ""

# 验证队列算法是否正确加载
CURRENT_QDISC=$(sysctl -n net.core.default_qdisc 2>/dev/null)
if [ "$CURRENT_QDISC" = "$SELECTED_QDISC" ]; then
    printf "$MSG_QDISC_SUCCESS\n" "$SELECTED_QDISC"
else
    printf "$MSG_QDISC_WARN\n" "$SELECTED_QDISC" "$CURRENT_QDISC"
fi
echo ""

# 系统限制优化
echo "$MSG_SYS_LIMITS_TITLE"
echo "=============="

# 检查并建议limits.conf优化
if [ -f /etc/security/limits.conf ]; then
    echo "$MSG_CHECKING_LIMITS"

    # 如果已经包含优化行，则跳过
    if grep -q "nofile.*1048576" /etc/security/limits.conf; then
        echo "$MSG_LIMITS_OK"
    else
        echo -e "$MSG_LIMITS_SELECT_TITLE"
        echo "----------------------------------------"
        echo -e "$MSG_LIMITS_DESC_GENERAL"
        echo -e "$MSG_LIMITS_DESC_HIGH_CONCURRENCY"
        echo ""

        while true; do
            read -p "$MSG_LIMITS_PROMPT" limits_choice
            case "$limits_choice" in
                1)
                    NOFILE_LIMIT=65536
                    break
                    ;;
                2)
                    NOFILE_LIMIT=1048576
                    break
                    ;;
                *)
                    echo "$MSG_INVALID_CHOICE 1 or 2"
                    ;;
            esac
        done

        LIMITS_CONTENT="
# TCP优化相关系统限制 - $(date)
* soft nofile $NOFILE_LIMIT
* hard nofile $NOFILE_LIMIT
* soft nproc $NOFILE_LIMIT
* hard nproc $NOFILE_LIMIT
"
        # 备份limits.conf
        cp /etc/security/limits.conf /etc/security/limits.conf.backup.$(date +%Y%m%d_%H%M%S)
        echo "$LIMITS_CONTENT" >> /etc/security/limits.conf
        echo "$MSG_LIMITS_ADDED"
        echo "$MSG_RELOGIN_NOTICE"
    fi
fi

echo ""
echo "$MSG_OPTIMIZATION_COMPLETE"
echo "=========="
echo ""
echo "$MSG_CONFIG_FEATURES"

if [ "$USE_SYSCTL_D" -eq 1 ]; then
    echo -e "- $MSG_MODERN_CONFIG"
else
    echo -e "- $MSG_REPLACE_CONFIG"
fi

printf -- "- $MSG_BBR_QDISC\n" "${SELECTED_QDISC^^}" "$SELECTED_NAME"
printf -- "- $MSG_RP_FILTER_FEATURE\n" "$(if [ $RP_FILTER_VALUE -eq 1 ]; then echo "$MSG_RP_FILTER_ON"; else echo "$MSG_RP_FILTER_OFF"; fi)"
echo -e "- $MSG_IP_FORWARD_FEATURE"
echo -e "- $MSG_RTT_ADAPTIVE"
printf -- "- $MSG_DYNAMIC_BUFFER\n" "$TOTAL_MEM"
echo -e "- $MSG_FORWARDING_OPTIMIZED"
echo -e "- $MSG_IPV6_SUPPORT"
echo -e "- $MSG_CONNECTION_OPTIMIZED"
echo -e "- $MSG_VM_OPTIMIZED"
echo -e "- $MSG_FS_OPTIMIZED"
echo ""
echo "$MSG_QDISC_FEATURES"
case $SELECTED_QDISC in
    "fq")
        echo -e "$MSG_FQ_FEATURE"
        ;;
    "fq_pie")
        echo -e "$MSG_FQPIE_FEATURE"
        ;;
    "cake")
        echo -e "$MSG_CAKE_FEATURE"
        ;;
esac
echo ""
printf "$MSG_MEM_LEVEL\n" "$(if [ $TOTAL_MEM -lt 1048 ]; then echo "$MSG_SMALL_MEM"; elif [ $TOTAL_MEM -lt 4096 ]; then echo "$MSG_MEDIUM_MEM"; else echo "$MSG_LARGE_MEM"; fi)"
echo ""
echo "$MSG_RTT_NOTES"
echo -e "- $MSG_WINDOW_SIZES"
echo -e "- $MSG_TIMEOUTS"
echo -e "- $MSG_CONGESTION_WINDOW"
echo -e "- $MSG_ADAPTIVE_NOTE"
echo ""
echo "$MSG_INSTANT_REBOOT"
echo ""
echo "$MSG_ROLLBACK_TITLE"
echo "=========="
echo "$MSG_ROLLBACK_INSTRUCTIONS"

if [ "$USE_SYSCTL_D" -eq 1 ]; then
    echo "rm $CONFIG_FILE"
    echo "sysctl --system"
    if [ -n "$BACKUP_FILE" ] && [ -f "$BACKUP_FILE" ]; then
        echo "# Or restore backup:"
        echo "cp $BACKUP_FILE $CONFIG_FILE"
        echo "sysctl --system"
    fi
else
    echo "cp $BACKUP_FILE /etc/sysctl.conf"
    echo "sysctl -p"
fi

echo ""
echo "$MSG_CONFIG_LOCATION_TITLE"
echo -e "- $MSG_CURRENT_CONFIG: $CONFIG_FILE"
if [ -n "$BACKUP_FILE" ] && [ -f "$BACKUP_FILE" ]; then
    printf -- "- $MSG_BACKUP_FILE\n" "$BACKUP_FILE"
fi
echo ""
echo "$MSG_THANKS"
echo "$MSG_THANKS_ISIF"
echo "$MSG_ISIF_LINK"
echo ""


## 如需回滚，执行以下命令:
## rm /etc/sysctl.d/99-tcp-bbr-optimization.conf
## sysctl --system

