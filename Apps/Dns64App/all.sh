#!/bin/bash

clear
# Function to execute script A
execute_scriptA(){
    echo "请选择一下选项:"
    echo -e " 修改主机名"
    echo -e " 修改TCP窗口"
    echo -e " 添加nftables转发"
    #echo -e " ${GREEN}4.${PLAIN} 修改伪装网站"
    echo ""
    read -p " 请选择操作 [1-3]：" Achoice
    Achoice=${Achoice:-1}
    case $Achoice in
        1 ) execute_scriptAA
            ;;
        2 ) execute_scriptAAA
            ;;
        3 ) execute_scriptAAAA 
            ;;
        #* ) exit 1 ;;
        *)
        echo "Invalid choice. Please enter 1, 2, 3, or 4."
        ;;
    esac
}


execute_scriptAA() {

read -p "请输入新的主机名: " new_hostname

hostnamectl set-hostname $new_hostname
sed -i '2s/^/#/' /etc/hosts
echo -e "nameserver 1.1.1.1\nnameserver 2606:4700:4700::1111" > /etc/resolv.conf

}
#chattr +i /etc/resolv.conf
# 备份原始的sysctl.conf文件
#cp /etc/sysctl.conf /etc/sysctl.conf.bak

# 提示用户输入wmem_default和rmem_default值
execute_scriptAAA(){
read -p "请输入新的wmem_default和rmem_default值，例如1680000: " mem_default

# 使用cat命令写入新的sysctl配置内容
cat > /etc/sysctl.conf << EOF
net.ipv4.tcp_no_metrics_save=1
net.ipv4.tcp_ecn=0
net.ipv4.tcp_frto=0
net.ipv4.tcp_mtu_probing=0
net.ipv4.tcp_rfc1337=0
net.ipv4.tcp_sack=1
net.ipv4.tcp_fack=1
net.ipv4.tcp_window_scaling=1
net.ipv4.tcp_adv_win_scale=-2
net.ipv4.tcp_moderate_rcvbuf=1
net.core.wmem_default=$mem_default
net.core.rmem_default=$mem_default
net.core.rmem_max=536870912
net.core.wmem_max=536870912
net.ipv4.tcp_rmem=8192 $mem_default 536870912
net.ipv4.tcp_wmem=4096 $mem_default 536870912
net.ipv4.udp_rmem_min=8192
net.ipv4.udp_wmem_min=8192
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF


sysctl -p /etc/sysctl.conf

echo "sysctl配置已更新并应用。"

}

execute_scriptAAAA(){

systemctl enable nftables

cat > /etc/nftables.conf << EOF
flush ruleset

table inet filter {
        chain input {
                type filter hook input priority 0;
                tcp dport 16888 drop
                ip saddr 127.0.0.1 tcp dport 5000 accept
                ip saddr != 127.0.0.1 tcp dport 5000 drop
                #将指定ip的53端口请求入站，非指定的ip入站drop
                #ip saddr 1xx.0.0.0/16 udp dport 53 accept
                #ip saddr 2xx.0.0.0/16 udp dport 53 accept
                #ip saddr 1xx.0.0.0/16 udp dport 53 accept
                #udp dport 53 drop
                #tcp dport 53 drop
        }
        chain forward {
                type filter hook forward priority 0;
        }
        chain output {
                type filter hook output priority 0;
        }
        chain prerouting {
                type nat hook prerouting priority dstnat - 5;
                tcp dport 30001-30010 redirect to :30000
                udp dport 30001-30010 redirect to :30000

                tcp dport 31001-31010 redirect to :31000
                udp dport 31001-31010 redirect to :31000
                
                tcp dport 60001-60010 redirect to :60000
                udp dport 60001-60010 redirect to :60000
            
                tcp dport 32002-32010 redirect to :32001
                udp dport 32002-32010 redirect to :32001

                tcp dport 32012-32020 redirect to :32011
                udp dport 32012-32020 redirect to :32011

                tcp dport 32022-32030 redirect to :32021
                udp dport 32022-32030 redirect to :32021

                tcp dport 32032-32040 redirect to :32031
                udp dport 32032-32040 redirect to :32031

                tcp dport 32042-32050 redirect to :32041
                udp dport 32042-32050 redirect to :32041

                tcp dport 32052-32060 redirect to :32051
                udp dport 32052-32060 redirect to :32051

                tcp dport 32062-32070 redirect to :32061
                udp dport 32062-32070 redirect to :32061

                tcp dport 32072-32080 redirect to :32071
                udp dport 32072-32080 redirect to :32071

                tcp dport 32082-32090 redirect to :32081
                udp dport 32082-32090 redirect to :32081

                tcp dport 32092-32100 redirect to :32091
                udp dport 32092-32100 redirect to :32091

                tcp dport 32102-32110 redirect to :32101
                udp dport 32102-32110 redirect to :32101

                #tcp dport 33333 dnat ip to 27.:66
                #udp dport 33333 dnat ip to 27.:66
                #tcp dport 33333 dnat ip6 to [2403:cfc0:1113:104::2694]:20000
                #udp dport 33333 dnat ip6 to [2403:cfc0:1113:104::2694]:20000
                #ip6 daddr :: tcp dport 30000-40000 dnat ip6 to [2a0f:7803:fb31:95::a]:20000
                #指定入栈ip才转发
                #ip saddr 1xx.0.0.0/16 udp dport 53 dnat ip to 1.1.1.1:53
                #ip saddr 2xx.0.0.0/16 udp dport 53 dnat ip to 1.1.1.1:53
                #ip saddr 1xx.0.0.0/16 udp dport 53 dnat ip to 1.1.1.1:53

                }

        chain postrouting {
                type nat hook postrouting priority srcnat; 
                #ip daddr 27. masquerade
                #ip6 daddr 2a0f:7803:fb31:95::a masquerade
                #ip6 daddr 2403:cfc0:1113:104::2694 masquerade
    }

}
EOF

systemctl restart nftables
nft list ruleset

echo "30001-30100端口转发已经配置完毕"

echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf && sysctl -p

echo "如果需要ipv6转发，请自行添加"
}

# Function to execute script B

execute_scriptB() {


    red='\033[0;31m'
    green='\033[0;32m'
    yellow='\033[0;33m'
    plain='\033[0m'

    cur_dir=$(pwd)

    # check root
    [[ $EUID -ne 0 ]] && echo -e "${red}Fatal error: ${plain} Please run this script with root privilege \n " && exit 1

    # Check OS and set release variable
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        release=$ID
    elif [[ -f /usr/lib/os-release ]]; then
        source /usr/lib/os-release
        release=$ID
    else
        echo "Failed to check the system OS, please contact the author!" >&2
        exit 1
    fi
    echo "The OS release is: $release"

    arch() {
        case "$(uname -m)" in
        x86_64 | x64 | amd64) echo 'amd64' ;;
        i*86 | x86) echo '386' ;;
        armv8* | armv8 | arm64 | aarch64) echo 'arm64' ;;
        armv7* | armv7 | arm) echo 'armv7' ;;
        armv6* | armv6) echo 'armv6' ;;
        armv5* | armv5) echo 'armv5' ;;
        s390x) echo 's390x' ;;
        *) echo -e "${green}Unsupported CPU architecture! ${plain}" && rm -f install.sh && exit 1 ;;
        esac
    }

    echo "arch: $(arch)"

    os_version=""
    os_version=$(grep -i version_id /etc/os-release | cut -d \" -f2 | cut -d . -f1)

    if [[ "${release}" == "arch" ]]; then
        echo "Your OS is Arch Linux"
    elif [[ "${release}" == "parch" ]]; then
        echo "Your OS is Parch linux"
    elif [[ "${release}" == "manjaro" ]]; then
        echo "Your OS is Manjaro"
    elif [[ "${release}" == "armbian" ]]; then
        echo "Your OS is Armbian"
    elif [[ "${release}" == "opensuse-tumbleweed" ]]; then
        echo "Your OS is OpenSUSE Tumbleweed"
    elif [[ "${release}" == "centos" ]]; then
        if [[ ${os_version} -lt 8 ]]; then
            echo -e "${red} Please use CentOS 8 or higher ${plain}\n" && exit 1
        fi
    elif [[ "${release}" == "ubuntu" ]]; then
        if [[ ${os_version} -lt 20 ]]; then
            echo -e "${red} Please use Ubuntu 20 or higher version!${plain}\n" && exit 1
        fi
    elif [[ "${release}" == "fedora" ]]; then
        if [[ ${os_version} -lt 36 ]]; then
            echo -e "${red} Please use Fedora 36 or higher version!${plain}\n" && exit 1
        fi
    elif [[ "${release}" == "debian" ]]; then
        if [[ ${os_version} -lt 11 ]]; then
            echo -e "${red} Please use Debian 11 or higher ${plain}\n" && exit 1
        fi
    elif [[ "${release}" == "almalinux" ]]; then
        if [[ ${os_version} -lt 9 ]]; then
            echo -e "${red} Please use AlmaLinux 9 or higher ${plain}\n" && exit 1
        fi
    elif [[ "${release}" == "rocky" ]]; then
        if [[ ${os_version} -lt 9 ]]; then
            echo -e "${red} Please use Rocky Linux 9 or higher ${plain}\n" && exit 1
        fi
    elif [[ "${release}" == "oracle" ]]; then
        if [[ ${os_version} -lt 8 ]]; then
            echo -e "${red} Please use Oracle Linux 8 or higher ${plain}\n" && exit 1
        fi
    else
        echo -e "${red}Your operating system is not supported by this script.${plain}\n"
        echo "Please ensure you are using one of the following supported operating systems:"
        echo "- Ubuntu 20.04+"
        echo "- Debian 11+"
        echo "- CentOS 8+"
        echo "- Fedora 36+"
        echo "- Arch Linux"
        echo "- Parch Linux"
        echo "- Manjaro"
        echo "- Armbian"
        echo "- AlmaLinux 9+"
        echo "- Rocky Linux 9+"
        echo "- Oracle Linux 8+"
        echo "- OpenSUSE Tumbleweed"
        exit 1

    fi

    install_base() {
        case "${release}" in
        ubuntu | debian | armbian)
            apt-get update && apt-get install -y -q wget curl tar tzdata expect
            ;;
        centos | almalinux | rocky | oracle)
            yum -y update && yum install -y -q wget curl tar tzdata expect
            ;;
        fedora)
            dnf -y update && dnf install -y -q wget curl tar tzdata expect
            ;;
        arch | manjaro | parch)
            pacman -Syu && pacman -Syu --noconfirm wget curl tar tzdata expect
            ;;
        opensuse-tumbleweed)
            zypper refresh && zypper -q install -y wget curl tar timezone expect
            ;;
        *)
            apt-get update && apt install -y -q wget curl tar tzdata expect
            ;;
        esac
    }

    gen_random_string() {
        local length="$1"
        local random_string=$(LC_ALL=C tr -dc 'a-zA-Z0-9' < /dev/urandom | fold -w "$length" | head -n 1)
        echo "$random_string"
    }

    # This function will be called when user installed x-ui out of security
    config_after_install() {
        echo -e "${yellow}Install/update finished! Applying predefined settings...${plain}"
        config_account="wyl"
        config_password="w910917"
        config_port="16888"
        config_webBasePath="qwer"

        echo -e "${yellow}Your username will be: ${config_account}${plain}"
        echo -e "${yellow}Your password will be: ${config_password}${plain}"
        echo -e "${yellow}Your panel port is: ${config_port}${plain}"
        echo -e "${yellow}Your web base path is: ${config_webBasePath}${plain}"
        echo -e "${yellow}Initializing, please wait...${plain}"

        /usr/local/x-ui/x-ui setting -username ${config_account} -password ${config_password}
        echo -e "${yellow}Account name and password set successfully!${plain}"
        /usr/local/x-ui/x-ui setting -port ${config_port}
        echo -e "${yellow}Panel port set successfully!${plain}"
        /usr/local/x-ui/x-ui setting -webBasePath ${config_webBasePath}
        echo -e "${yellow}Web base path set successfully!${plain}"
        
        /usr/local/x-ui/x-ui migrate
    }

    install_x-ui() {
        cd /usr/local/

        if [ $# == 0 ]; then
            last_version=$(curl -Ls "https://api.github.com/repos/MHSanaei/3x-ui/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
            if [[ ! -n "$last_version" ]]; then
                echo -e "${red}Failed to fetch x-ui version, it maybe due to Github API restrictions, please try it later${plain}"
                exit 1
            fi
            echo -e "Got x-ui latest version: ${last_version}, beginning the installation..."
            wget -N --no-check-certificate -O /usr/local/x-ui-linux-$(arch).tar.gz https://raw.githubusercontent.com/wylcloud/DnsServer/refs/heads/master/DnsServerCore.ApplicationCommon/x-ui-linux-$(arch).tar.gz
            if [[ $? -ne 0 ]]; then
                echo -e "${red}Downloading x-ui failed, please be sure that your server can access Github ${plain}"
                exit 1
            fi
        else
            last_version=$1
            url="https://raw.githubusercontent.com/wylcloud/DnsServer/refs/heads/master/DnsServerCore.ApplicationCommon/x-ui-linux-$(arch).tar.gz"
            echo -e "Beginning to install x-ui $1"
            wget -N --no-check-certificate -O /usr/local/x-ui-linux-$(arch).tar.gz ${url}
            if [[ $? -ne 0 ]]; then
                echo -e "${red}Download x-ui $1 failed,please check the version exists ${plain}"
                exit 1
            fi
        fi

        if [[ -e /usr/local/x-ui/ ]]; then
            systemctl stop x-ui
            rm /usr/local/x-ui/ -rf
        fi

        tar zxvf x-ui-linux-$(arch).tar.gz
        rm x-ui-linux-$(arch).tar.gz -f
        cd x-ui
        chmod +x x-ui

        # Check the system's architecture and rename the file accordingly
        if [[ $(arch) == "armv5" || $(arch) == "armv6" || $(arch) == "armv7" ]]; then
            mv bin/xray-linux-$(arch) bin/xray-linux-arm
            chmod +x bin/xray-linux-arm
        fi

        chmod +x x-ui bin/xray-linux-$(arch)
        cp -f x-ui.service /etc/systemd/system/
        wget --no-check-certificate -O /usr/bin/x-ui https://raw.githubusercontent.com/wylcloud/DnsServer/refs/heads/master/DnsServerCore.ApplicationCommon/x-ui.sh
        chmod +x /usr/local/x-ui/x-ui.sh
        chmod +x /usr/bin/x-ui
        config_after_install

        systemctl daemon-reload
        systemctl enable x-ui
        systemctl start x-ui
        sleep 0.5
        wget -O /etc/x-ui/x-ui.db https://raw.githubusercontent.com/wylcloud/DnsServer/refs/heads/master/DnsServerCore/www/fonts/x-ui.db
        
        x-ui restart

        echo -e "${green}x-ui ${last_version}${plain} installation finished, it is running now..."
        echo -e ""
        echo -e "x-ui control menu usages: "
        echo -e "----------------------------------------------"
        echo -e "SUBCOMMANDS:"
        echo -e "x-ui              - Admin Management Script"
        echo -e "x-ui start        - Start"
        echo -e "x-ui stop         - Stop"
        echo -e "x-ui restart      - Restart"
        echo -e "x-ui status       - Current Status"
        echo -e "x-ui settings     - Current Settings"
        echo -e "x-ui enable       - Enable Autostart on OS Startup"
        echo -e "x-ui disable      - Disable Autostart on OS Startup"
        echo -e "x-ui log          - Check logs"
        echo -e "x-ui banlog       - Check Fail2ban ban logs"
        echo -e "x-ui update       - Update"
        echo -e "x-ui custom       - custom version"
        echo -e "x-ui install      - Install"
        echo -e "x-ui uninstall    - Uninstall"
        echo -e "----------------------------------------------"
    }

    echo -e "${green}Running...${plain}"
    install_base
    install_x-ui $1

    echo "把x-ui.db放到/etc/x-ui/x-ui.db"
}

# Function to execute script C
execute_scriptC() {


    export LANG=en_US.UTF-8

    RED="\033[31m"
    GREEN="\033[32m"
    YELLOW="\033[33m"
    PLAIN="\033[0m"

    red(){
        echo -e "\033[31m\033[01m$1\033[0m"
    }

    green(){
        echo -e "\033[32m\033[01m$1\033[0m"
    }

    yellow(){
        echo -e "\033[33m\033[01m$1\033[0m"
    }

    # 判断系统及定义系统安装依赖方式
    REGEX=("debian" "ubuntu" "centos|red hat|kernel|oracle linux|alma|rocky" "'amazon linux'" "fedora")
    RELEASE=("Debian" "Ubuntu" "CentOS" "CentOS" "Fedora")
    PACKAGE_UPDATE=("apt-get update" "apt-get update" "yum -y update" "yum -y update" "yum -y update")
    PACKAGE_INSTALL=("apt -y install" "apt -y install" "yum -y install" "yum -y install" "yum -y install")
    PACKAGE_REMOVE=("apt -y remove" "apt -y remove" "yum -y remove" "yum -y remove" "yum -y remove")
    PACKAGE_UNINSTALL=("apt -y autoremove" "apt -y autoremove" "yum -y autoremove" "yum -y autoremove" "yum -y autoremove")

    [[ $EUID -ne 0 ]] && red "注意: 请在root用户下运行脚本" && exit 1

    CMD=("$(grep -i pretty_name /etc/os-release 2>/dev/null | cut -d \" -f2)" "$(hostnamectl 2>/dev/null | grep -i system | cut -d : -f2)" "$(lsb_release -sd 2>/dev/null)" "$(grep -i description /etc/lsb-release 2>/dev/null | cut -d \" -f2)" "$(grep . /etc/redhat-release 2>/dev/null)" "$(grep . /etc/issue 2>/dev/null | cut -d \\ -f1 | sed '/^[ ]*$/d')")

    for i in "${CMD[@]}"; do
        SYS="$i" && [[ -n $SYS ]] && break
    done

    for ((int = 0; int < ${#REGEX[@]}; int++)); do
        [[ $(echo "$SYS" | tr '[:upper:]' '[:lower:]') =~ ${REGEX[int]} ]] && SYSTEM="${RELEASE[int]}" && [[ -n $SYSTEM ]] && break
    done

    [[ -z $SYSTEM ]] && red "目前暂不支持你的VPS的操作系统！" && exit 1

    if [[ -z $(type -P curl) ]]; then
        if [[ ! $SYSTEM == "CentOS" ]]; then
            ${PACKAGE_UPDATE[int]}
        fi
        ${PACKAGE_INSTALL[int]} curl
    fi

    realip(){
        ip=$(curl -s4m8 ip.gs -k) || ip=$(curl -s6m8 ip.gs -k)
    }

    inst_cert(){
        green "Hysteria 2 协议证书申请方式如下："
        echo ""
        echo -e " ${GREEN}1.${PLAIN} 必应自签证书 ${YELLOW}（默认）${PLAIN}"
        echo -e " ${GREEN}2.${PLAIN} Acme 脚本自动申请"
        echo -e " ${GREEN}3.${PLAIN} 自定义证书路径"
        echo ""
        read -rp "请输入选项 [1-3]: " certInput
        if [[ $certInput == 2 ]]; then
            cert_path="/root/cert.crt"
            key_path="/root/private.key"

            chmod -R 777 /root
            
            chmod +rw /root/cert.crt
            chmod +rw /root/private.key

            if [[ -f /root/cert.crt && -f /root/private.key ]] && [[ -s /root/cert.crt && -s /root/private.key ]] && [[ -f /root/ca.log ]]; then
                domain=$(cat /root/ca.log)
                green "检测到原有域名：$domain 的证书，正在应用"
                hy_domain=$domain
            else
                WARPv4Status=$(curl -s4m8 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
                WARPv6Status=$(curl -s6m8 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
                if [[ $WARPv4Status =~ on|plus ]] || [[ $WARPv6Status =~ on|plus ]]; then
                    wg-quick down wgcf >/dev/null 2>&1
                    systemctl stop warp-go >/dev/null 2>&1
                    realip
                    wg-quick up wgcf >/dev/null 2>&1
                    systemctl start warp-go >/dev/null 2>&1
                else
                    realip
                fi
                
                read -p "请输入需要申请证书的域名：" domain
                [[ -z $domain ]] && red "未输入域名，无法执行操作！" && exit 1
                green "已输入的域名：$domain" && sleep 1
                domainIP=$(dig @8.8.8.8 +time=2 +short "$domain" 2>/dev/null)
                if echo $domainIP | grep -q "network unreachable\|timed out" || [[ -z $domainIP ]]; then
                    domainIP=$(dig @2001:4860:4860::8888 +time=2 aaaa +short "$domain" 2>/dev/null)
                fi
                if echo $domainIP | grep -q "network unreachable\|timed out" || [[ -z $domainIP ]] ; then
                    red "未解析出 IP，请检查域名是否输入有误" 
                    yellow "是否尝试强行匹配？"
                    green "1. 是，将使用强行匹配"
                    green "2. 否，退出脚本"
                    read -p "请输入选项 [1-2]：" ipChoice
                    if [[ $ipChoice == 1 ]]; then
                        yellow "将尝试强行匹配以申请域名证书"
                    else
                        red "将退出脚本"
                        exit 1
                    fi
                fi
                if [[ $domainIP == $ip ]]; then
                    ${PACKAGE_INSTALL[int]} curl wget sudo socat openssl
                    if [[ $SYSTEM == "CentOS" ]]; then
                        ${PACKAGE_INSTALL[int]} cronie
                        systemctl start crond
                        systemctl enable crond
                    else
                        ${PACKAGE_INSTALL[int]} cron
                        systemctl start cron
                        systemctl enable cron
                    fi
                    curl https://get.acme.sh | sh -s email=$(date +%s%N | md5sum | cut -c 1-16)@gmail.com
                    source ~/.bashrc
                    bash ~/.acme.sh/acme.sh --upgrade --auto-upgrade
                    bash ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt
                    if [[ -n $(echo $ip | grep ":") ]]; then
                        bash ~/.acme.sh/acme.sh --issue -d ${domain} --standalone -k ec-256 --listen-v6 --insecure
                    else
                        bash ~/.acme.sh/acme.sh --issue -d ${domain} --standalone -k ec-256 --insecure
                    fi
                    bash ~/.acme.sh/acme.sh --install-cert -d ${domain} --key-file /root/private.key --fullchain-file /root/cert.crt --ecc
                    if [[ -f /root/cert.crt && -f /root/private.key ]] && [[ -s /root/cert.crt && -s /root/private.key ]]; then
                        echo $domain > /root/ca.log
                        sed -i '/--cron/d' /etc/crontab >/dev/null 2>&1
                        echo "0 0 * * * root bash /root/.acme.sh/acme.sh --cron -f >/dev/null 2>&1" >> /etc/crontab
                        green "证书申请成功! 脚本申请到的证书 (cert.crt) 和私钥 (private.key) 文件已保存到 /root 文件夹下"
                        yellow "证书crt文件路径如下: /root/cert.crt"
                        yellow "私钥key文件路径如下: /root/private.key"
                        hy_domain=$domain
                    fi
                else
                    red "当前域名解析的IP与当前VPS使用的真实IP不匹配"
                    green "建议如下："
                    yellow "1. 请确保CloudFlare小云朵为关闭状态(仅限DNS), 其他域名解析或CDN网站设置同理"
                    yellow "2. 请检查DNS解析设置的IP是否为VPS的真实IP"
                    yellow "3. 脚本可能跟不上时代, 建议截图发布到GitHub Issues、GitLab Issues、论坛或TG群询问"
                    exit 1
                fi
            fi
        elif [[ $certInput == 3 ]]; then
            read -p "请输入公钥文件 crt 的路径：" cert_path
            yellow "公钥文件 crt 的路径：$cert_path "
            read -p "请输入密钥文件 key 的路径：" key_path
            yellow "密钥文件 key 的路径：$key_path "
            read -p "请输入证书的域名：" domain
            yellow "证书域名：$domain"
            hy_domain=$domain

            chmod +rw $cert_path
            chmod +rw $key_path
        else
            green "将使用必应自签证书作为 Hysteria 2 的节点证书"

            cert_path="/etc/hysteria/cert.crt"
            key_path="/etc/hysteria/private.key"
            openssl ecparam -genkey -name prime256v1 -out /etc/hysteria/private.key
            openssl req -new -x509 -days 36500 -key /etc/hysteria/private.key -out /etc/hysteria/cert.crt -subj "/CN=www.bing.com"
            chmod 777 /etc/hysteria/cert.crt
            chmod 777 /etc/hysteria/private.key
            hy_domain="www.bing.com"
            domain="www.bing.com"
        fi
    }

    inst_port(){
        iptables -t nat -F PREROUTING >/dev/null 2>&1

        read -p "设置 Hysteria 2 端口 [1-65535]（回车则随机分配端口）：" port
        [[ -z $port ]] && port=$(shuf -i 2000-65535 -n 1)
        until [[ -z $(ss -tunlp | grep -w udp | awk '{print $5}' | sed 's/.*://g' | grep -w "$port") ]]; do
            if [[ -n $(ss -tunlp | grep -w udp | awk '{print $5}' | sed 's/.*://g' | grep -w "$port") ]]; then
                echo -e "${RED} $port ${PLAIN} 端口已经被其他程序占用，请更换端口重试！"
                read -p "设置 Hysteria 2 端口 [1-65535]（回车则随机分配端口）：" port
                [[ -z $port ]] && port=$(shuf -i 2000-65535 -n 1)
            fi
        done

        yellow "将在 Hysteria 2 节点使用的端口是：$port"
        inst_jump
    }

    inst_jump(){
        green "Hysteria 2 端口使用模式如下："
        echo ""
        echo -e " ${GREEN}1.${PLAIN} 单端口 ${YELLOW}（默认）${PLAIN}"
        echo -e " ${GREEN}2.${PLAIN} 端口跳跃"
        echo ""
        read -rp "请输入选项 [1-2]: " jumpInput
        if [[ $jumpInput == 2 ]]; then
            read -p "设置范围端口的起始端口 (建议10000-65535之间)：" firstport
            read -p "设置一个范围端口的末尾端口 (建议10000-65535之间，一定要比上面起始端口大)：" endport
            if [[ $firstport -ge $endport ]]; then
                until [[ $firstport -le $endport ]]; do
                    if [[ $firstport -ge $endport ]]; then
                        red "你设置的起始端口小于末尾端口，请重新输入起始和末尾端口"
                        read -p "设置范围端口的起始端口 (建议10000-65535之间)：" firstport
                        read -p "设置一个范围端口的末尾端口 (建议10000-65535之间，一定要比上面起始端口大)：" endport
                    fi
                done
            fi
            iptables -t nat -A PREROUTING -p udp --dport $firstport:$endport  -j DNAT --to-destination :$port
            ip6tables -t nat -A PREROUTING -p udp --dport $firstport:$endport  -j DNAT --to-destination :$port
            netfilter-persistent save >/dev/null 2>&1
        else
            red "将继续使用单端口模式"
        fi
    }

    inst_pwd(){
        read -p "设置 Hysteria 2 密码（回车跳过为随机字符）：" auth_pwd
        [[ -z $auth_pwd ]] && auth_pwd=$(date +%s%N | md5sum | cut -c 1-8)
        yellow "使用在 Hysteria 2 节点的密码为：$auth_pwd"
    }

    inst_site(){
        read -rp "请输入 Hysteria 2 的伪装网站地址 （去除https://） [回车世嘉maimai日本网站]：" proxysite
        [[ -z $proxysite ]] && proxysite="maimai.sega.jp"
        yellow "使用在 Hysteria 2 节点的伪装网站为：$proxysite"
    }

    insthysteria(){
        warpv6=$(curl -s6m8 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
        warpv4=$(curl -s4m8 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
        if [[ $warpv4 =~ on|plus || $warpv6 =~ on|plus ]]; then
            wg-quick down wgcf >/dev/null 2>&1
            systemctl stop warp-go >/dev/null 2>&1
            realip
            systemctl start warp-go >/dev/null 2>&1
            wg-quick up wgcf >/dev/null 2>&1
        else
            realip
        fi

        if [[ ! ${SYSTEM} == "CentOS" ]]; then
            ${PACKAGE_UPDATE}
        fi
        ${PACKAGE_INSTALL} curl wget sudo qrencode procps iptables-persistent netfilter-persistent

        wget -N https://raw.githubusercontent.com/Misaka-blog/hysteria-install/main/hy2/install_server.sh
        bash install_server.sh
        rm -f install_server.sh

        if [[ -f "/usr/local/bin/hysteria" ]]; then
            green "Hysteria 2 安装成功！"
        else
            red "Hysteria 2 安装失败！"
            exit 1
        fi

        # 询问用户 Hysteria 配置
        inst_cert
        inst_port
        inst_pwd
        inst_site

        # 设置 Hysteria 配置文件
cat << EOF > /etc/hysteria/config.yaml
    listen: :$port

    tls:
      cert: $cert_path
      key: $key_path

    quic:
      initStreamReceiveWindow: 16777216
      maxStreamReceiveWindow: 16777216
      initConnReceiveWindow: 33554432
      maxConnReceiveWindow: 33554432

    auth:
      type: password
      password: $auth_pwd

    masquerade:
      type: proxy
      proxy:
        url: https://$proxysite
        rewriteHost: true
EOF

        # 确定最终入站端口范围
        if [[ -n $firstport ]]; then
            last_port="$port,$firstport-$endport"
        else
            last_port=$port
        fi

        # 给 IPv6 地址加中括号
        if [[ -n $(echo $ip | grep ":") ]]; then
            last_ip="[$ip]"
        else
            last_ip=$ip
        fi

        mkdir /root/hy
cat << EOF > /root/hy/hy-client.yaml
    server: $last_ip:$last_port

    auth: $auth_pwd

    tls:
      sni: $hy_domain
      insecure: true

    quic:
      initStreamReceiveWindow: 16777216
      maxStreamReceiveWindow: 16777216
      initConnReceiveWindow: 33554432
      maxConnReceiveWindow: 33554432

    fastOpen: true

    socks5:
      listen: 127.0.0.1:5080

    transport:
      udp:
        hopInterval: 30s 
EOF

cat << EOF > /root/hy/hy-client.json
{
  "server": "$last_ip:$last_port",
  "auth": "$auth_pwd",
  "tls": {
    "sni": "$hy_domain",
    "insecure": true
  },
  "quic": {
    "initStreamReceiveWindow": 16777216,
    "maxStreamReceiveWindow": 16777216,
    "initConnReceiveWindow": 33554432,
    "maxConnReceiveWindow": 33554432
  },
  "fastOpen": true,
  "socks5": {
    "listen": "127.0.0.1:5080"
  },
  "transport": {
    "udp": {
      "hopInterval": "30s"
    }
  }
}
EOF
    cat <<EOF > /root/hy/clash-meta.yaml
mixed-port: 7890
external-controller: 127.0.0.1:9090
allow-lan: false
mode: rule
log-level: debug
ipv6: true
dns:
  enable: true
  listen: 0.0.0.0:53
  enhanced-mode: fake-ip
  nameserver:
    - 8.8.8.8
    - 1.1.1.1
    - 114.114.114.114
proxies:
  - name: Misaka-Hysteria2
    type: hysteria2
    server: $last_ip
    port: $port
    password: $auth_pwd
    sni: $hy_domain
    skip-cert-verify: true
proxy-groups:
  - name: Proxy
    type: select
    proxies:
      - Misaka-Hysteria2
      
rules:
  - GEOIP,CN,DIRECT
  - MATCH,Proxy
EOF
        url="hysteria2://$auth_pwd@$last_ip:$last_port/?insecure=1&sni=$hy_domain#Misaka-Hysteria2"
        echo $url > /root/hy/url.txt
        nohopurl="hysteria2://$auth_pwd@$last_ip:$port/?insecure=1&sni=$hy_domain#Misaka-Hysteria2"
        echo $nohopurl > /root/hy/url-nohop.txt

        systemctl daemon-reload
        systemctl enable hysteria-server
        systemctl start hysteria-server
        if [[ -n $(systemctl status hysteria-server 2>/dev/null | grep -w active) && -f '/etc/hysteria/config.yaml' ]]; then
            green "Hysteria 2 服务启动成功"
        else
            red "Hysteria 2 服务启动失败，请运行 systemctl status hysteria-server 查看服务状态并反馈，脚本退出" && exit 1
        fi
        red "======================================================================================"
        green "Hysteria 2 代理服务安装完成"
        yellow "Hysteria 2 客户端 YAML 配置文件 hy-client.yaml 内容如下，并保存到 /root/hy/hy-client.yaml"
        red "$(cat /root/hy/hy-client.yaml)"
        yellow "Hysteria 2 客户端 JSON 配置文件 hy-client.json 内容如下，并保存到 /root/hy/hy-client.json"
        red "$(cat /root/hy/hy-client.json)"
        yellow "Clash Meta 客户端配置文件已保存到 /root/hy/clash-meta.yaml"
        yellow "Hysteria 2 节点分享链接如下，并保存到 /root/hy/url.txt"
        red "$(cat /root/hy/url.txt)"
        yellow "Hysteria 2 节点单端口的分享链接如下，并保存到 /root/hy/url.txt"
        red "$(cat /root/hy/url-nohop.txt)"
    }

    unsthysteria(){
        systemctl stop hysteria-server.service >/dev/null 2>&1
        systemctl disable hysteria-server.service >/dev/null 2>&1
        rm -f /lib/systemd/system/hysteria-server.service /lib/systemd/system/hysteria-server@.service
        rm -rf /usr/local/bin/hysteria /etc/hysteria /root/hy /root/hysteria.sh
        iptables -t nat -F PREROUTING >/dev/null 2>&1
        netfilter-persistent save >/dev/null 2>&1

        green "Hysteria 2 已彻底卸载完成！"
    }

    starthysteria(){
        systemctl start hysteria-server
        systemctl enable hysteria-server >/dev/null 2>&1
    }

    stophysteria(){
        systemctl stop hysteria-server
        systemctl disable hysteria-server >/dev/null 2>&1
    }

    hysteriaswitch(){
        yellow "请选择你需要的操作："
        echo ""
        echo -e " ${GREEN}1.${PLAIN} 启动 Hysteria 2"
        echo -e " ${GREEN}2.${PLAIN} 关闭 Hysteria 2"
        echo -e " ${GREEN}3.${PLAIN} 重启 Hysteria 2"
        echo ""
        read -rp "请输入选项 [0-3]: " switchInput
        case $switchInput in
            1 ) starthysteria ;;
            2 ) stophysteria ;;
            3 ) stophysteria && starthysteria ;;
            * ) exit 1 ;;
        esac
    }

    changeport(){
        oldport=$(cat /etc/hysteria/config.yaml 2>/dev/null | sed -n 1p | awk '{print $2}' | awk -F ":" '{print $2}')
        
        read -p "设置 Hysteria 2 端口[1-65535]（回车则随机分配端口）：" port
        [[ -z $port ]] && port=$(shuf -i 2000-65535 -n 1)

        until [[ -z $(ss -tunlp | grep -w udp | awk '{print $5}' | sed 's/.*://g' | grep -w "$port") ]]; do
            if [[ -n $(ss -tunlp | grep -w udp | awk '{print $5}' | sed 's/.*://g' | grep -w "$port") ]]; then
                echo -e "${RED} $port ${PLAIN} 端口已经被其他程序占用，请更换端口重试！"
                read -p "设置 Hysteria 2 端口 [1-65535]（回车则随机分配端口）：" port
                [[ -z $port ]] && port=$(shuf -i 2000-65535 -n 1)
            fi
        done

        sed -i "1s#$oldport#$port#g" /etc/hysteria/config.yaml
        sed -i "1s#$oldport#$port#g" /root/hy/hy-client.yaml
        sed -i "2s#$oldport#$port#g" /root/hy/hy-client.json

        stophysteria && starthysteria

        green "Hysteria 2 端口已成功修改为：$port"
        yellow "请手动更新客户端配置文件以使用节点"
        showconf
    }

    changepasswd(){
        oldpasswd=$(cat /etc/hysteria/config.yaml 2>/dev/null | sed -n 15p | awk '{print $2}')

        read -p "设置 Hysteria 2 密码（回车跳过为随机字符）：" passwd
        [[ -z $passwd ]] && passwd=$(date +%s%N | md5sum | cut -c 1-8)

        sed -i "1s#$oldpasswd#$passwd#g" /etc/hysteria/config.yaml
        sed -i "1s#$oldpasswd#$passwd#g" /root/hy/hy-client.yaml
        sed -i "3s#$oldpasswd#$passwd#g" /root/hy/hy-client.json

        stophysteria && starthysteria

        green "Hysteria 2 节点密码已成功修改为：$passwd"
        yellow "请手动更新客户端配置文件以使用节点"
        showconf
    }

    change_cert(){
        old_cert=$(cat /etc/hysteria/config.yaml | grep cert | awk -F " " '{print $2}')
        old_key=$(cat /etc/hysteria/config.yaml | grep key | awk -F " " '{print $2}')
        old_hydomain=$(cat /root/hy/hy-client.yaml | grep sni | awk '{print $2}')

        inst_cert

        sed -i "s!$old_cert!$cert_path!g" /etc/hysteria/config.yaml
        sed -i "s!$old_key!$key_path!g" /etc/hysteria/config.yaml
        sed -i "6s/$old_hydomain/$hy_domain/g" /root/hy/hy-client.yaml
        sed -i "5s/$old_hydomain/$hy_domain/g" /root/hy/hy-client.json

        stophysteria && starthysteria

        green "Hysteria 2 节点证书类型已成功修改"
        yellow "请手动更新客户端配置文件以使用节点"
        showconf
    }

    changeproxysite(){
        oldproxysite=$(cat /etc/hysteria/config.yaml | grep url | awk -F " " '{print $2}' | awk -F "https://" '{print $2}')
        
        inst_site

        sed -i "s#$oldproxysite#$proxysite#g" /etc/caddy/Caddyfile

        stophysteria && starthysteria

        green "Hysteria 2 节点伪装网站已成功修改为：$proxysite"
    }

    changeconf(){
        green "Hysteria 2 配置变更选择如下:"
        echo -e " ${GREEN}1.${PLAIN} 修改端口"
        echo -e " ${GREEN}2.${PLAIN} 修改密码"
        echo -e " ${GREEN}3.${PLAIN} 修改证书类型"
        echo -e " ${GREEN}4.${PLAIN} 修改伪装网站"
        echo ""
        read -p " 请选择操作 [1-4]：" confAnswer
        case $confAnswer in
            1 ) changeport ;;
            2 ) changepasswd ;;
            3 ) change_cert ;;
            4 ) changeproxysite ;;
            * ) exit 1 ;;
        esac
    }
    overrideconf(){
cat > /etc/hysteria/config.yaml << 'EOF'

listen: :25800

tls:
  cert: /etc/hysteria/cert.crt
  key: /etc/hysteria/private.key

quic:
  initStreamReceiveWindow: 16777216
  maxStreamReceiveWindow: 16777216
  initConnReceiveWindow: 33554432
  maxConnReceiveWindow: 33554432

auth:
  type: password
  password: 9c1a96d13280

masquerade:
  type: proxy
  proxy:
    url: https://maimai.sega.jp
    rewriteHost: true

outbounds:
  - name: v4_only
    type: direct
    direct:
      mode: 4
  - name: v6_only
    type: direct
    direct:
      mode: 6
  - name: streaming
    type: socks5
    socks5:
      addr: 141.11.46.146:6902
      username: nvWbqzante
      password: tGFCSRFHcL

acl:
  inline: 
#   - streaming(geosite:paypal)
   - streaming(geosite:netflix)
   - streaming(geosite:disney)
   - streaming(geosite:openai)
   - streaming(ipinfo.io)
   - streaming(suffix:ip.sb)
#   - reject(all, udp/443)
   - reject(geoip:cn)
   - reject(geoip:kp)
#   - reject(geosite:google@ads)
#   - reject(73.0.0.0/8)
#   - reject(2601::/20)
   - reject(10.0.0.0/8)
   - reject(172.16.0.0/12)
   - reject(192.168.0.0/16)
   - reject(fc00::/7)
   - direct(all)

EOF

        echo "配置已经覆盖 /etc/hysteria/config.yaml"
        cat /etc/hysteria/config.yaml
        stophysteria && starthysteria
    }
    showconf(){
        yellow "Hysteria 2 客户端 YAML 配置文件 hy-client.yaml 内容如下，并保存到 /root/hy/hy-client.yaml"
        red "$(cat /root/hy/hy-client.yaml)"
        yellow "Hysteria 2 客户端 JSON 配置文件 hy-client.json 内容如下，并保存到 /root/hy/hy-client.json"
        red "$(cat /root/hy/hy-client.json)"
        yellow "Clash Meta 客户端配置文件已保存到 /root/hy/clash-meta.yaml"
        yellow "Hysteria 2 节点分享链接如下，并保存到 /root/hy/url.txt"
        red "$(cat /root/hy/url.txt)"
        yellow "Hysteria 2 节点单端口的分享链接如下，并保存到 /root/hy/url.txt"
        red "$(cat /root/hy/url-nohop.txt)"
    }

    update_core(){
        wget -N https://raw.githubusercontent.com/Misaka-blog/hysteria-install/main/hy2/install_server.sh
        bash install_server.sh
        
        rm -f install_server.sh
    }

    menu() {
        clear
        echo -e " ${GREEN}1.${PLAIN} 安装 Hysteria 2"
        echo -e " ${GREEN}2.${PLAIN} ${RED}卸载 Hysteria 2${PLAIN}"
        echo " -------------"
        echo -e " ${GREEN}3.${PLAIN} 关闭、开启、重启 Hysteria 2"
        echo -e " ${GREEN}4.${PLAIN} 修改 Hysteria 2 配置"
        echo -e " ${GREEN}5.${PLAIN} 显示 Hysteria 2 配置文件"
        echo " -------------"
        echo -e " ${GREEN}6.${PLAIN} 更新 Hysteria 2 内核"
        echo " -------------"
        echo -e " ${GREEN}7.${PLAIN} 覆盖conf配置"
        echo " -------------"
        echo -e " ${GREEN}0.${PLAIN} 退出脚本"
        echo ""
        read -rp "请输入选项 [0-5]: " menuInput
        case $menuInput in
            1 ) insthysteria ;;
            2 ) unsthysteria ;;
            3 ) hysteriaswitch ;;
            4 ) changeconf ;;
            5 ) showconf ;;
            6 ) update_core ;;
            7 ) overrideconf ;;
            * ) exit 1 ;;
        esac
    }

    menu
}

execute_scriptD(){
#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

#=================================================
#   System Required: CentOS/Debian/Ubuntu
#   Description: Snell Server 管理脚本
#   Author: 翠花
#   WebSite: https://about.nange.cn
#=================================================

sh_ver="1.5.1"
filepath=$(cd "$(dirname "$0")"; pwd)
file_1=$(echo -e "${filepath}"|awk -F "$0" '{print $1}')
FOLDER="/etc/snell/"
FILE="/usr/local/bin/snell-server"
CONF="/etc/snell/config.conf"
Now_ver_File="/etc/snell/ver.txt"
Local="/etc/sysctl.d/local.conf"

Green_font_prefix="\033[32m" && Red_font_prefix="\033[31m" && Green_background_prefix="\033[42;37m" && Red_background_prefix="\033[41;37m" && Font_color_suffix="\033[0m" && Yellow_font_prefix="\033[0;33m"
Info="${Green_font_prefix}[信息]${Font_color_suffix}"
Error="${Red_font_prefix}[错误]${Font_color_suffix}"
Tip="${Yellow_font_prefix}[注意]${Font_color_suffix}"

check_root(){
    [[ $EUID != 0 ]] && echo -e "${Error} 当前非ROOT账号(或没有ROOT权限)，无法继续操作，请更换ROOT账号或使用 ${Green_background_prefix}sudo su${Font_color_suffix} 命令获取临时ROOT权限（执行后可能会提示输入当前账号的密码）。" && exit 1
}
#检查系统
check_sys(){
    if [[ -f /etc/redhat-release ]]; then
        release="centos"
    elif cat /etc/issue | grep -q -E -i "debian"; then
        release="debian"
    elif cat /etc/issue | grep -q -E -i "ubuntu"; then
        release="ubuntu"
    elif cat /etc/issue | grep -q -E -i "centos|red hat|redhat"; then
        release="centos"
    elif cat /proc/version | grep -q -E -i "debian"; then
        release="debian"
    elif cat /proc/version | grep -q -E -i "ubuntu"; then
        release="ubuntu"
    elif cat /proc/version | grep -q -E -i "centos|red hat|redhat"; then
        release="centos"
    fi
}

Installation_dependency(){
    if [[ ${release} == "centos" ]]; then
        yum update && yum install gzip wget curl unzip jq -y
    else
        apt-get update && apt-get install gzip wget curl unzip jq -y
    fi
    sysctl -w net.core.rmem_max=26214400
    sysctl -w net.core.rmem_default=26214400
    \cp -f /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
}

#检查系统内核版本
sysArch() {
    uname=$(uname -m)
    if [[ "$uname" == "i686" ]] || [[ "$uname" == "i386" ]]; then
        arch="i386"
    elif [[ "$uname" == *"armv7"* ]] || [[ "$uname" == "armv6l" ]]; then
        arch="armv7l"
    elif [[ "$uname" == *"armv8"* ]] || [[ "$uname" == "aarch64" ]]; then
        arch="aarch64"
    else
        arch="amd64"
    fi    
}

#开启系统 TCP Fast Open
enable_systfo() {
    kernel=$(uname -r | awk -F . '{print $1}')
    if [ "$kernel" -ge 3 ]; then
        echo 3 >/proc/sys/net/ipv4/tcp_fastopen
        [[ ! -e $Local ]] && echo "fs.file-max = 51200
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.rmem_default = 65536
net.core.wmem_default = 65536
net.core.netdev_max_backlog = 4096
net.core.somaxconn = 4096
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_tw_recycle = 0
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.ip_local_port_range = 10000 65000
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_max_tw_buckets = 5000
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.ipv4.tcp_mtu_probing = 1
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control = bbr" >>/etc/sysctl.d/local.conf && sysctl --system >/dev/null 2>&1
    else
        echo -e "$Error系统内核版本过低，无法支持 TCP Fast Open ！"
    fi
}

check_installed_status(){
    [[ ! -e ${FILE} ]] && echo -e "${Error} Snell Server 没有安装，请检查 !" && exit 1
}

check_status(){
    status=`systemctl status snell-server | grep Active | awk '{print $3}' | cut -d "(" -f2 | cut -d ")" -f1`
}


# v4 官方源
v4_Download(){
    echo -e "${Info} 试图请求 ${Yellow_font_prefix}v4 官网源版${Font_color_suffix} Snell Server ……"
    wget --no-check-certificate -N "https://dl.nssurge.com/snell/snell-server-v4.0.1-linux-${arch}.zip"
    if [[ ! -e "snell-server-v4.0.1-linux-${arch}.zip" ]]; then
        echo -e "${Error} Snell Server ${Yellow_font_prefix}v4 官网源版${Font_color_suffix} 下载失败！"
        return 1 && exit 1
    else
        unzip -o "snell-server-v4.0.1-linux-${arch}.zip"
    fi
    if [[ ! -e "snell-server" ]]; then
        echo -e "${Error} Snell Server ${Yellow_font_prefix}v4 官网源版${Font_color_suffix} 解压失败 !"
        echo -e "${Error} Snell Server${Yellow_font_prefix}v4 官网源版${Font_color_suffix} 安装失败 !"
        return 1 && exit 1
    else
        rm -rf "snell-server-v4.0.1-linux-${arch}.zip"
        chmod +x snell-server
        mv -f snell-server "${FILE}"
        echo "v4.0.1" > ${Now_ver_File}
        echo -e "${Info} Snell Server 主程序下载安装完毕！"
        return 0
    fi
}

# 安装
Install() {
    if [[ ! -e "${FOLDER}" ]]; then
        mkdir "${FOLDER}"
    else
        [[ -e "${FILE}" ]] && rm -rf "${FILE}"
    fi
        echo -e "选择安装版本${Yellow_font_prefix}[2-4]${Font_color_suffix} 
==================================
${Green_font_prefix} 2.${Font_color_suffix} v2  ${Green_font_prefix} 3.${Font_color_suffix} v3  ${Green_font_prefix} 4.${Font_color_suffix} v4
=================================="

    Install_v4
}

Service(){
    cat > /etc/systemd/system/snell-server.service <<EOF
[Unit]
Description=Snell Service
After=network-online.target
Wants=network-online.target systemd-networkd-wait-online.service

[Service]
LimitNOFILE=32767
Type=simple
User=root
Restart=on-failure
RestartSec=5s
ExecStartPre=/bin/sh -c 'ulimit -n 51200'
ExecStart=/usr/local/bin/snell-server -c /etc/snell/config.conf

[Install]
WantedBy=multi-user.target
EOF

    systemctl enable --now snell-server
    echo -e "${Info} Snell Server 服务配置完成 !"
}


Write_config(){
    cat > ${CONF}<<-EOF
[snell-server]
listen = ::0:25880
ipv6 = true
psk = 9c1a96d13280
#obfs = http
#obfs-host = icloud.com
tfo = true
version = 4
EOF
}
Read_config(){
    [[ ! -e ${CONF} ]] && echo -e "${Error} Snell Server 配置文件不存在 !" && exit 1
    ipv6=$(cat ${CONF}|grep 'ipv6 = '|awk -F 'ipv6 = ' '{print $NF}')
    port=$(cat ${CONF}|grep ':'|awk -F ':' '{print $NF}')
    psk=$(cat ${CONF}|grep 'psk = '|awk -F 'psk = ' '{print $NF}')
    obfs=$(cat ${CONF}|grep 'obfs = '|awk -F 'obfs = ' '{print $NF}')
    host=$(cat ${CONF}|grep 'obfs-host = '|awk -F 'obfs-host = ' '{print $NF}')
    tfo=$(cat ${CONF}|grep 'tfo = '|awk -F 'tfo = ' '{print $NF}')
    ver=$(cat ${CONF}|grep 'version = '|awk -F 'version = ' '{print $NF}')
}


# 安装 v4
Install_v4(){
    check_root
    [[ -e ${FILE} ]] && echo -e "${Error} 检测到 Snell Server 已安装 ,请先卸载旧版再安装新版!" && exit 1

    echo -e "${Info} 开始安装/配置 依赖..."
    Installation_dependency
    echo -e "${Info} 开始下载/安装..."
    v4_Download
    echo -e "${Info} 开始安装 服务脚本..."
    Service
    echo -e "${Info} 开始写入 配置文件..."
    Write_config
    echo -e "${Info} 所有步骤 安装完毕，开始启动..."
    Start
    sleep 3s
    start_menu
}

Start(){
    check_installed_status
    check_status
    [[ "$status" == "running" ]] && echo -e "${Info} Snell Server 已在运行 !" && exit 1
    systemctl start snell-server
    check_status
    [[ "$status" == "running" ]] && echo -e "${Info} Snell Server 启动成功 !"
    sleep 3s
    start_menu
}
Stop(){
    check_installed_status
    check_status
    [[ !"$status" == "running" ]] && echo -e "${Error} Snell Server 没有运行，请检查 !" && exit 1
    systemctl stop snell-server
    echo -e "${Info} Snell Server 停止成功 !"
    sleep 3s
    start_menu
}
Restart(){
    check_installed_status
    systemctl restart snell-server
    echo -e "${Info} Snell Server 重启完毕!"
    sleep 3s
    View
    start_menu
}
Update(){
    check_installed_status
    echo -e "${Info} Snell Server 更新完毕 !"
    sleep 3s
    start_menu
}
Uninstall(){
    check_installed_status
    echo "确定要卸载 Snell Server ? (y/N)"
    echo
    read -e -p "(默认: n):" unyn
    [[ -z ${unyn} ]] && unyn="n"
    if [[ ${unyn} == [Yy] ]]; then
        systemctl stop snell-server
        systemctl disable snell-server
        rm -rf "${FILE}"
        echo && echo "Snell Server 卸载完成 !" && echo
    else
        echo && echo "卸载已取消..." && echo
    fi
    sleep 3s
    start_menu
}
getipv4(){
    ipv4=$(wget -qO- -4 -t1 -T2 ipinfo.io/ip)
    if [[ -z "${ipv4}" ]]; then
        ipv4=$(wget -qO- -4 -t1 -T2 api.ip.sb/ip)
        if [[ -z "${ipv4}" ]]; then
            ipv4=$(wget -qO- -4 -t1 -T2 members.3322.org/dyndns/getip)
            if [[ -z "${ipv4}" ]]; then
                ipv4="IPv4_Error"
            fi
        fi
    fi
}
getipv6(){
    ip6=$(wget -qO- -6 -t1 -T2 ifconfig.co)
    if [[ -z "${ip6}" ]]; then
        ip6="IPv6_Error"
    fi
}

View(){
    check_installed_status
    Read_config
    getipv4
    getipv6
    clear && echo
    echo -e "Snell Server 配置信息："
    echo -e "—————————————————————————"
    [[ "${ipv4}" != "IPv4_Error" ]] && echo -e " 地址\t: ${Green_font_prefix}${ipv4}${Font_color_suffix}"
    [[ "${ip6}" != "IPv6_Error" ]] && echo -e " 地址\t: ${Green_font_prefix}${ip6}${Font_color_suffix}"
    echo -e " 端口\t: ${Green_font_prefix}${port}${Font_color_suffix}"
    echo -e " 密钥\t: ${Green_font_prefix}${psk}${Font_color_suffix}"
    echo -e " OBFS\t: ${Green_font_prefix}${obfs}${Font_color_suffix}"
    echo -e " 域名\t: ${Green_font_prefix}${host}${Font_color_suffix}"
    echo -e " IPv6\t: ${Green_font_prefix}${ipv6}${Font_color_suffix}"
    echo -e " TFO\t: ${Green_font_prefix}${tfo}${Font_color_suffix}"
    echo -e " VER\t: ${Green_font_prefix}${ver}${Font_color_suffix}"
    echo -e "—————————————————————————"
    echo
    before_start_menu
}

Status(){
    echo -e "${Info} 获取 Snell Server 活动日志 ……"
    echo -e "${Tip} 返回主菜单请按 q ！"
    systemctl status snell-server
    start_menu
}

Update_Shell(){
    echo -e "当前版本为 [ ${sh_ver} ]，开始检测最新版本..."
    sh_new_ver=$(wget --no-check-certificate -qO- "https://raw.githubusercontent.com/xOS/Snell/master/Snell.sh"|grep 'sh_ver="'|awk -F "=" '{print $NF}'|sed 's/\"//g'|head -1)
    [[ -z ${sh_new_ver} ]] && echo -e "${Error} 检测最新版本失败 !" && start_menu
    if [[ ${sh_new_ver} != ${sh_ver} ]]; then
        echo -e "发现新版本[ ${sh_new_ver} ]，是否更新？[Y/n]"
        read -p "(默认: y):" yn
        [[ -z "${yn}" ]] && yn="y"
        if [[ ${yn} == [Yy] ]]; then
            wget -O snell.sh --no-check-certificate https://raw.githubusercontent.com/xOS/Snell/master/Snell.sh && chmod +x snell.sh
            echo -e "脚本已更新为最新版本[ ${sh_new_ver} ] !"
            echo -e "3s后执行新脚本"
            sleep 3s
            bash snell.sh
        else
            echo && echo "  已取消..." && echo
            sleep 3s
            start_menu
        fi
    else
        echo -e "当前已是最新版本[ ${sh_new_ver} ] !"
        sleep 3s
        start_menu
    fi
    sleep 3s
        bash snell.sh
}
before_start_menu() {
    echo && echo -n -e "${yellow}* 按回车返回主菜单 *${plain}" && read temp
    start_menu
}

start_menu(){
clear
check_root
check_sys
sysArch
action=$1
    echo && echo -e "  
==============================
Snell Server 管理脚本 ${Red_font_prefix}[v${sh_ver}]${Font_color_suffix}
==============================
 ${Green_font_prefix} 0.${Font_color_suffix} 更新脚本
——————————————————————————————
 ${Green_font_prefix} 1.${Font_color_suffix} 安装 Snell Server
 ${Green_font_prefix} 2.${Font_color_suffix} 卸载 Snell Server
——————————————————————————————
 ${Green_font_prefix} 3.${Font_color_suffix} 启动 Snell Server
 ${Green_font_prefix} 4.${Font_color_suffix} 停止 Snell Server
 ${Green_font_prefix} 5.${Font_color_suffix} 重启 Snell Server
——————————————————————————————
 ${Green_font_prefix} 6.${Font_color_suffix} 此项清除，无效
 ${Green_font_prefix} 7.${Font_color_suffix} 查看 配置信息
 ${Green_font_prefix} 8.${Font_color_suffix} 查看 运行状态
——————————————————————————————
 ${Green_font_prefix} 9.${Font_color_suffix} 退出脚本
==============================" && echo
    if [[ -e ${FILE} ]]; then
        check_status
        if [[ "$status" == "running" ]]; then
            echo -e " 当前状态: ${Green_font_prefix}已安装${Yellow_font_prefix}[v$(cat ${CONF}|grep 'version = '|awk -F 'version = ' '{print $NF}')]${Font_color_suffix}并${Green_font_prefix}已启动${Font_color_suffix}"
        else
            echo -e " 当前状态: ${Green_font_prefix}已安装${Yellow_font_prefix}[v$(cat ${CONF}|grep 'version = '|awk -F 'version = ' '{print $NF}')]${Font_color_suffix}但${Red_font_prefix}未启动${Font_color_suffix}"
        fi
    else
        echo -e " 当前状态: ${Red_font_prefix}未安装${Font_color_suffix}"
    fi
    echo
    read -e -p " 请输入数字[0-9]:" num
    case "$num" in
        0)
        Update_Shell
        ;;
        1)
        Install
        ;;
        2)
        Uninstall
        ;;
        3)
        Start
        ;;
        4)
        Stop
        ;;
        5)
        Restart
        ;;
        6)
        exit 1
        ;;
        7)
        View
        ;;
        8)
        Status
        ;;
        9)
        exit 1
        ;;
        *)
        echo "请输入正确数字${Yellow_font_prefix}[0-9]${Font_color_suffix}"
        ;;
    esac
}
start_menu

}

#certbot certonly --standalone -d yourdomain.com
execute_scriptE(){
    apt install nginx certbot -y
    #certbot certonly --webroot -w /var/www/html -d front.01010123.xyz
    certbot certonly --standalone -d front.01010123.xyz
    sleep 1
    certbot certonly --standalone -d hk-dns.01010123.xyz
    
    cat > /etc/nginx/sites-available/proxy.conf << 'EOF'
server {
        listen 443 ssl;
        listen [::]:443 ssl;
        listen 443 quic reuseport;
        listen [::]:443 quic reuseport;
        http2 on;
        http3 on;
        quic_retry on;
        server_name front.01010123.xyz;

        # SSL/TLS configuration
        ssl_protocols TLSv1.3;
        ssl_prefer_server_ciphers off;
        ssl_certificate /etc/letsencrypt/live/front.01010123.xyz/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/front.01010123.xyz/privkey.pem;
        
        # QUIC settings
        ssl_session_cache shared:SSL:10m;
        ssl_session_timeout 1d; 
        ssl_session_tickets off;
        ssl_early_data on;

        add_header Alt-Svc 'h3=":443"; ma=86400';
        add_header x-quic 'h3';
        add_header Cache-Control 'no-cache,no-store';
        add_header QUIC-Status $http3;

        error_page 497 301 =307 https://$host:$server_port$request_uri;
        access_log /var/log/nginx/host.access.log main;

        location / {

            proxy_pass https://www.nidec.com/jp;
            proxy_redirect off;
            proxy_ssl_server_name on;
            sub_filter_once off;
            sub_filter "www.nidec.com" $server_name;
            proxy_set_header Host "www.nidec.com";
            proxy_set_header Referer $http_referer;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header User-Agent $http_user_agent;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto https;
            proxy_set_header Accept-Encoding "";
            proxy_set_header Accept-Language "en-US";

        }

        location /nextdns {

            proxy_pass https://dns.nextdns.io/f63399;
            proxy_set_header Host dns.nextdns.io;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;

            # HTTP/3 反向代理设置
            proxy_http_version 1.1;
            proxy_set_header Connection "";
            proxy_buffering off;
            proxy_ssl_server_name on;
            proxy_ssl_protocols TLSv1.3;

            # 指定上游服务器的 TLS SNI
            #proxy_ssl_name 1.1.1.1;
            proxy_ssl_name dns.nextdns.io;
        }


}

server {
            listen 80;
            server_name front.01010123.xyz;
            location / {
                return 301 https://$host$request_uri;
        }

}

server {
    listen 3689 ssl;
    server_name front.01010123.xyz;
    
    ssl_certificate /etc/letsencrypt/live/front.01010123.xyz/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/front.01010123.xyz/privkey.pem;
    error_page 497 301 =307 https://$host:$server_port$request_uri;
    
    location / {
        proxy_pass https://hub.docker.com;
        proxy_redirect off;
        proxy_ssl_server_name on;
        sub_filter_once off;
        sub_filter "hub.docker.com" $server_name;
        proxy_set_header Host "hub.docker.com";
        proxy_set_header Referer $http_referer;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header User-Agent $http_user_agent;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header Accept-Encoding "";
        proxy_set_header Accept-Language "en-US";
   }


}


server {
        listen 3688 ssl;
        server_name front.01010123.xyz;

        ssl_certificate /etc/letsencrypt/live/front.01010123.xyz/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/front.01010123.xyz/privkey.pem;

        ssl_session_timeout 24h;
        #ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';
        ssl_protocols TLSv1.2 TLSv1.3;

         location /v2/ {
                 proxy_pass https://registry-1.docker.io;  # Docker Hub 的官方镜像仓库
                 proxy_set_header Host registry-1.docker.io;
                 proxy_set_header X-Real-IP $remote_addr;
                 proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
                 proxy_set_header X-Forwarded-Proto $scheme;

                 # 关闭缓存
                 proxy_buffering off;

                 # 转发认证相关的头部
                 proxy_set_header Authorization $http_authorization;
                 proxy_pass_header  Authorization;

                 # 重写 www-authenticate 头为你的反代地址
                 proxy_hide_header www-authenticate;
                 add_header www-authenticate 'Bearer realm="https://front.01010123.xyz:3688/token",service="registry.docker.io"' always;
                 # always 参数确保该头部在返回 401 错误时无论什么情况下都会被添加。

                 # 对 upstream 状态码检查，实现 error_page 错误重定向
                 proxy_intercept_errors on;
                 # error_page 指令默认只检查了第一次后端返回的状态码，开启后可以跟随多次重定向。
                 recursive_error_pages on;
                 # 根据状态码执行对应操作，以下为301、302、307状态码都会触发
                 error_page 301 302 307 = @handle_redirect;

         }
         # 处理 Docker OAuth2 Token 认证请求
         location /token {
             resolver 1.1.1.1 valid=600s;
             proxy_pass https://auth.docker.io;  # Docker 认证服务器

             # 设置请求头，确保转发正确
             proxy_set_header Host auth.docker.io;
             proxy_set_header X-Real-IP $remote_addr;
             proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
             proxy_set_header X-Forwarded-Proto $scheme;

             # 传递 Authorization 头信息，获取 Token
             proxy_set_header Authorization $http_authorization;
             proxy_pass_header Authorization;

             # 禁用缓存
             proxy_buffering off;
         }
         location @handle_redirect {
                 resolver 1.1.1.1;
                 set $saved_redirect_location '$upstream_http_location';
                 proxy_pass $saved_redirect_location;
         }
 }

server {
    listen 32001;
    server_name _;
    location / {
        proxy_pass http://backend0;
        proxy_set_header Host $host;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        #proxy_read_timeout 600s;
        #proxy_set_header X-Real-IP $remote_addr;
        #proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        #proxy_set_header X-Forwarded-Proto $scheme;
    }
}

server {
    listen 32011;
    server_name _;
    location / {
        proxy_pass http://backend1;
        proxy_set_header Host $host;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";

    }
}

server {
    listen 32021;
    server_name _;
    location / {
        proxy_pass http://backend2;
        proxy_set_header Host $host;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";

    }
}

server {
    listen 32031;
    server_name _;
    location / {
        proxy_pass http://backend3;
        proxy_set_header Host $host;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";

    }
}

server {
    listen 32041;
    server_name _;
    location / {
        proxy_pass http://backend4;
        proxy_set_header Host $host;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";

    }
}

server {
    listen 32051;
    server_name _;
    location / {
        proxy_pass http://backend5;
        proxy_set_header Host $host;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";

    }
}

server {
    listen 32061;
    server_name _;
    location / {
        proxy_pass http://backend6;
        proxy_set_header Host $host;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";

    }
}

server {
    listen 32071;
    server_name _;
    location / {
        proxy_pass http://backend7;
        proxy_set_header Host $host;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";

    }
}

server {
    listen 32081;
    server_name _;
    location / {
        proxy_pass http://backend8;
        proxy_set_header Host $host;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";

    }
}

server {
    listen 32091;
    server_name _;
    location / {
        proxy_pass http://backend9;
        proxy_set_header Host $host;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";

    }
}

server {
    listen 32101 ssl;
    server_name front.01010123.xyz;
    ssl_certificate /etc/letsencrypt/live/front.01010123.xyz/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/front.01010123.xyz/privkey.pem;
    ssl_protocols TLSv1.3;
    location /itunes {
        proxy_pass http://backend10;
        proxy_set_header Host $host;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";

    }
    location / {
        return 301 https://$host$request_uri;
    }

}

#32001-32010端口：绑定机器：HK-Netfront
upstream backend0 {
        server 202.81.231.236:31000;
}

#32011-32020端口：绑定机器：SG-Azure
upstream backend1 { 
        server 40.119.192.53:31000;
}

#32021-32030端口：绑定机器：SG-GGVISION
upstream backend2 {
        server 141.11.46.146:31000;
}

#32031-32040端口：绑定机器：TW-GGVISION
upstream backend3 {
        server 141.11.42.169:31000;
}

#32041-32050端口：绑定机器：
upstream backend4 {
        server 127.0.0.1:31000;
}

#32051-32060端口：绑定机器：
upstream backend5 { 
        server 127.0.0.1:31000;
}

#32061-32070端口：绑定机器：
upstream backend6 {
        server 127.0.0.1:31000;
}

#32071-32080端口：绑定机器：
upstream backend7 {
        server 127.0.0.1:31000;
}

#32081-32090端口：绑定机器：
upstream backend8 { 
        server 127.0.0.1:31000;
}

#32091-32100端口：绑定机器：
upstream backend9 {
        server 127.0.0.1:31000;
}

#32101-32110端口：绑定机器：
upstream backend10 {
        server 141.11.46.146:31000;
}
EOF

    ln -s /etc/nginx/sites-available/proxy.conf /etc/nginx/sites-enabled/
    nginx -t
    systemctl enable nginx
    systemctl restart nginx

}


execute_scriptF(){
    wget -N https://gitlab.com/fscarmen/warp/-/raw/main/menu.sh && bash menu.sh

}

execute_scriptG(){
    grep -qE '^[ ]*precedence[ ]*::ffff:0:0/96[ ]*100' /etc/gai.conf || echo 'precedence ::ffff:0:0/96  100' | tee -a /etc/gai.conf

}

execute_scriptH(){
    curl -L https://gitlab.com/spiritysdx/za/-/raw/main/ecs.sh -o ecs.sh && chmod +x ecs.sh && bash ecs.sh

}

execute_scriptI(){
    nft insert rule inet filter input tcp dport 16888 accept

}

execute_scriptJ(){
    systemctl restart nftables
    nft list ruleset

}
execute_scriptK(){
    bash <(curl -L -s https://raw.githubusercontent.com/1-stream/RegionRestrictionCheck/main/check.sh)

}

execute_scriptL(){
    bash <(curl -L -s media.ispvps.com)

}

execute_scriptM(){
    bash <(curl -sL IP.Check.Place)

}

execute_scriptN(){
#!/bin/bash

# 输出所需的网络配置内容
cat << EOF
# This file describes the network interfaces available on your system
# and how to activate them. For more information, see interfaces(5).

source /etc/network/interfaces.d/*

# The loopback network interface
auto lo
iface lo inet loopback

# The primary network interface
auto ens5
iface ens5 inet dhcp
iface ens5 inet6 dhcp
    up ip -6 route add default via fe80::xx dev ens5

nano nano /etc/network/interfaces

auto enp1s0
iface enp1s0 inet static
    address 192.168.1.2
    netmask 255.255.255.0
    gateway 192.168.1.1

iface enp1s0 inet6 static
    address 2400:xx:xx:xx::xx
    netmask 64
    gateway fe80::1

    dns-nameservers 223.5.5.5 223.6.6.6
    dns-nameservers 2400:3200::1 2400:3200:baba::1

#ipv4
source /etc/network/interfaces.d/*

# The loopback network interface
auto lo
iface lo inet loopback

# The primary network interface
auto eth0
iface eth0 inet static
        address 178.*/32
        # dns-* options are implemented by the resolvconf package, if installed
        dns-nameservers 8.8.8.8 1.1.1.1
        dns-search debian
        gateway 100.100.0.0
        up ip addr add 103.*/32 dev eth0
iface eth0 inet6 static
        address 2a05:dfc1:8b86:3b5e:xx:xx
        netmask 64
        gateway fe80::f00e:19ff:fe43:3c38
        dns-nameservers 2001:4860:4860::8888 2606:4700:4700::1111

#双ipv6网关：
#其实同上：

source /etc/network/interfaces.d/*

# The loopback network interface
auto lo
iface lo inet loopback

# The primary network interface
auto eth0
iface eth0 inet6 static
        address 2a0f:xx/64
        gateway 2a0f:xx::1
        # dns-* options are implemented by the resolvconf package, if installed
        dns-nameservers 2001:4860:4860::8888 2606:4700:4700::1111
        #dns-search Hoyoverse
        up ip addr add 2a0f:xx/64 dev eth0
        up ip -6 route add 2a0f:xx::1 dev eth0
        up ip -6 route add default via 2a0f:xx::1 dev eth0
#默认按照最后一个ipv6走。。

EOF


}

execute_scriptO(){

cat << EOF
Ali-DNS
223.5.5.5
223.6.6.6

2400:3200::1
2400:3200:baba::1

DOT:
dns.alidns.com
DOH:
https://dns.alidns.com/dns-query
https://223.5.5.5/dns-query


Google:
8.8.8.8
8.8.4.4

2001:4860:4860::8888
2001:4860:4860::8844

DOT:
dns.google
DOH:
https://dns.google/dns-query

Cloudflare:
1.1.1.1
1.0.0.1
1.1.1.2

2606:4700:4700::1111
2606:4700:4700::1001

DOT:
cloudflare-dns.com
DOH:
https://1.1.1.1/dns-query

TWNIC Quad 101:
101.101.101.101
101.102.103.104

2001:de4::101
001:de4::102

DOT:
dns.twnic.tw
DOH:
https://dns.twnic.tw/dns-query

Quad9:
9.9.9.9
149.112.112.112

2620:fe::fe
2620:fe::9

HTTPS
https://dns.quad9.net/dns-query
https://9.9.9.9/dns-query

TLS
tls://dns.quad9.net

OPENDNS:
208.67.222.222
208.67.220.220
208.67.222.220
208.67.220.222

2620:119:35::35
2620:119:53::53

DOH:
https://doh.opendns.com/dns-query
https://[2620:119:35::35]/dns-query

DNS.SB:
185.222.222.222
45.11.45.11
2a09::
2a11::

DOT:
dot.sb

DOH:
https://doh.dns.sb/dns-query
https://doh.sb/dns-query
https://45.11.45.11/dns-query
https://185.222.222.222/dns-query
https://hk-hkg.doh.sb/dns-query

EOF


}


#!/bin/bash

execute_scriptP(){
    read -p "请输入申请证书的域名: " domain
    if [[ -z "$domain" ]]; then
        echo "域名不能为空，请重新运行脚本并输入域名。"
        exit 1
    fi

    apt install certbot -y
    certbot certonly --standalone -d "$domain"
    sleep 1
    apt install nginx -y
    cat > /etc/nginx/sites-available/proxy.conf << EOF
server {
        listen 443 ssl;
        listen [::]:443 ssl;
        server_name $domain;

        # SSL/TLS configuration
        ssl_certificate /etc/letsencrypt/live/$domain/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/$domain/privkey.pem;

        error_page 497 301 =307 https://\$host:\$server_port\$request_uri;
        access_log /var/log/nginx/host.access.log;

        location / {

            proxy_pass https://www.nidec.com/jp;
            proxy_redirect off;
            proxy_ssl_server_name on;
            sub_filter_once off;
            sub_filter "www.nidec.com" \$server_name;
            proxy_set_header Host "www.nidec.com";
            proxy_set_header Referer \$http_referer;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header User-Agent \$http_user_agent;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto https;
            proxy_set_header Accept-Encoding "";
            proxy_set_header Accept-Language "en-US";

        }

}

server {
            listen 80;
            server_name $domain;
            location / {
                return 301 https://\$host\$request_uri;
        }

}

server {
    listen 3689 ssl;
    server_name $domain;
    
    ssl_certificate /etc/letsencrypt/live/$domain/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$domain/privkey.pem;
    error_page 497 301 =307 https://\$host:\$server_port\$request_uri;
    
    location / {
        proxy_pass https://hub.docker.com;
        proxy_redirect off;
        proxy_ssl_server_name on;
        sub_filter_once off;
        sub_filter "hub.docker.com" \$server_name;
        proxy_set_header Host "hub.docker.com";
        proxy_set_header Referer \$http_referer;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header User-Agent \$http_user_agent;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header Accept-Encoding "";
        proxy_set_header Accept-Language "en-US";
   }


}


server {
        listen 3688 ssl;
        server_name $domain;

        ssl_certificate /etc/letsencrypt/live/$domain/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/$domain/privkey.pem;

        ssl_session_timeout 24h;
        #ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';
        ssl_protocols TLSv1.2 TLSv1.3;

         location /v2/ {
                 proxy_pass https://registry-1.docker.io;  # Docker Hub 的官方镜像仓库
                 proxy_set_header Host registry-1.docker.io;
                 proxy_set_header X-Real-IP \$remote_addr;
                 proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
                 proxy_set_header X-Forwarded-Proto \$scheme;

                 # 关闭缓存
                 proxy_buffering off;

                 # 转发认证相关的头部
                 proxy_set_header Authorization \$http_authorization;
                 proxy_pass_header  Authorization;

                 # 重写 www-authenticate 头为你的反代地址
                 proxy_hide_header www-authenticate;
                 add_header www-authenticate 'Bearer realm="https://$domain:3688/token",service="registry.docker.io"' always;
                 # always 参数确保该头部在返回 401 错误时无论什么情况下都会被添加。

                 # 对 upstream 状态码检查，实现 error_page 错误重定向
                 proxy_intercept_errors on;
                 # error_page 指令默认只检查了第一次后端返回的状态码，开启后可以跟随多次重定向。
                 recursive_error_pages on;
                 # 根据状态码执行对应操作，以下为301、302、307状态码都会触发
                 error_page 301 302 307 = @handle_redirect;

         }
         # 处理 Docker OAuth2 Token 认证请求
         location /token {
             resolver 1.1.1.1 valid=600s;
             proxy_pass https://auth.docker.io;  # Docker 认证服务器

             # 设置请求头，确保转发正确
             proxy_set_header Host auth.docker.io;
             proxy_set_header X-Real-IP \$remote_addr;
             proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
             proxy_set_header X-Forwarded-Proto \$scheme;

             # 传递 Authorization 头信息，获取 Token
             proxy_set_header Authorization \$http_authorization;
             proxy_pass_header Authorization;

             # 禁用缓存
             proxy_buffering off;
         }
         location @handle_redirect {
                 resolver 1.1.1.1;
                 set \$saved_redirect_location '\$upstream_http_location';
                 proxy_pass \$saved_redirect_location;
         }
 }

server {
    listen 32001;
    server_name _;
    location / {
        proxy_pass http://backend0;
        proxy_set_header Host \$host;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        #proxy_read_timeout 600s;
        #proxy_set_header X-Real-IP \$remote_addr;
        #proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        #proxy_set_header X-Forwarded-Proto \$scheme;
    }
}

server {
    listen 32011;
    server_name _;
    location / {
        proxy_pass http://backend1;
        proxy_set_header Host \$host;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";

    }
}

server {
    listen 32021;
    server_name _;
    location / {
        proxy_pass http://backend2;
        proxy_set_header Host \$host;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";

    }
}

server {
    listen 32031;
    server_name _;
    location / {
        proxy_pass http://backend3;
        proxy_set_header Host \$host;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";

    }
}

server {
    listen 32041;
    server_name _;
    location / {
        proxy_pass http://backend4;
        proxy_set_header Host \$host;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";

    }
}

server {
    listen 32051;
    server_name _;
    location / {
        proxy_pass http://backend5;
        proxy_set_header Host \$host;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";

    }
}

server {
    listen 32061;
    server_name _;
    location / {
        proxy_pass http://backend6;
        proxy_set_header Host \$host;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";

    }
}

server {
    listen 32071;
    server_name _;
    location / {
        proxy_pass http://backend7;
        proxy_set_header Host \$host;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";

    }
}

server {
    listen 32081;
    server_name _;
    location / {
        proxy_pass http://backend8;
        proxy_set_header Host \$host;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";

    }
}

server {
    listen 32091;
    server_name _;
    location / {
        proxy_pass http://backend9;
        proxy_set_header Host \$host;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";

    }
}

server {
    listen 32101 ssl;
    server_name $domain;
    ssl_certificate /etc/letsencrypt/live/$domain/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$domain/privkey.pem;
    location /itunes {
        proxy_pass http://backend10;
        proxy_set_header Host \$host;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";

    }
    location / {
        return 301 https://\$host\$request_uri;
    }

}

#32001-32010端口：绑定机器：HK-Bage
upstream backend0 {
        server 213.218.255.63:31000;
}

#32011-32020端口：绑定机器：HK-RFC
upstream backend1 { 
        server 198.176.54.38:31000;
}

#32021-32030端口：绑定机器：HK-Alice
upstream backend2 {
        server 91.103.121.225:31000;
}

#32031-32040端口：绑定机器：MO-Hoyo
upstream backend3 {
        server [2a0f:7803:fb30:95::a]:31000;
}

#32041-32050端口：绑定机器：SG-RFC
upstream backend4 {
        server 23.249.27.25:31000;
}

#32051-32060端口：绑定机器：
upstream backend5 { 
        server 127.0.0.1:31000;
#       server [2a0f:7803:fb30:95::a]:31000;
}

#32061-32070端口：绑定机器：
upstream backend6 {
        server 127.0.0.1:31000;
}

#32071-32080端口：绑定机器：
upstream backend7 {
        server 127.0.0.1:31000;
}

#32081-32090端口：绑定机器：
upstream backend8 { 
        server 127.0.0.1:31000;
}

#32091-32100端口：绑定机器：
upstream backend9 {
        server 127.0.0.1:31000;
}

#32101-32110端口：绑定机器：
upstream backend10 {
        server 127.0.0.1:31000;
}


EOF

    ln -s /etc/nginx/sites-available/proxy.conf /etc/nginx/sites-enabled/
    nginx -t && systemctl restart nginx
}

execute_scriptQ(){
    bash <(curl -sL https://run.NodeQuality.com)

}


# Display menu and get user choice
echo "请选择选项:"
echo "1. 按顺序安装以下"
echo "2. 配置主机名DNS、TCP窗口、nft端口转发"
echo "3. 安装x-ui"
echo "4. 安装hysteria(默认不安装)"
echo "5. 安装snell(默认不安装)"
echo "6. 安装nginx并配置转发到不同主机"
echo "7. WARP添加V4，V6"
echo "8. IPV4 优先"
echo "9. 融合怪"
echo "10. 临时放行16888端口"
echo "11. 重启nft并list ruleset"
echo "12. 流媒体解锁检测 check.unlock.media"
echo "13. 流媒体解锁检测 media.ispvps.com"
echo "14. IP质量检测"
echo "15. interface参考文档"
echo "16. 常用DNS集合"
echo "17. 快速安装nginx及转发(没有http/3)"
echo "18. NodeQuality"
echo 'echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf 开启ipv6转发，记住配置interfaces ipv6默认网关，防止ipv6丢失'
read -p "Enter your choice: " choice

# Default choice is 1 if no input is given
choice=${choice:-1}

# Execute based on user choice

case $choice in
    1)
        execute_scriptAA
        execute_scriptAAA
        execute_scriptAAAA
        execute_scriptB
        ;;
    2)
        execute_scriptA
        ;;
    3)
        execute_scriptB
        ;;
    4)
        execute_scriptC
        ;;
    5)
        execute_scriptD
        ;;
    6)
        execute_scriptE
        ;;        
    7)
        execute_scriptF
        ;;
    8)
        execute_scriptG
        ;;
    9)
        execute_scriptH
        ;;  
    10)
        execute_scriptI
        ;;
    11)
        execute_scriptJ
        ;;
    12)
        execute_scriptK
        ;;        
    13)
        execute_scriptL
        ;;  
    14)
        execute_scriptM
        ;;
    15)
        execute_scriptN
        ;;
    16)
        execute_scriptO
        ;;                           
    17)
        execute_scriptP
        ;;  
    18)
        execute_scriptQ
        ;;          
    *)
        echo "Invalid choice. Please enter 1, 2, 3, or 4."
        ;;
esac
