#!/bin/bash

SCRIPT_VERSION="v2.1.6"
REALM_VERSION="v2.9.2"

NAT_LISTEN_PORT=""
NAT_LISTEN_IP=""
NAT_THROUGH_IP="::"
REMOTE_IP=""
REMOTE_PORT=""
EXIT_LISTEN_PORT=""
FORWARD_TARGET=""

SECURITY_LEVEL=""
TLS_CERT_PATH=""
TLS_KEY_PATH=""
TLS_SERVER_NAME=""
WS_PATH=""
WS_HOST=""

RULE_ID=""
RULE_NAME=""

REQUIRED_TOOLS=("curl" "wget" "tar" "grep" "cut" "bc" "jq")

# 通用的字段初始化函数
init_rule_field() {
    local field_name="$1"
    local default_value="$2"

    if [ ! -d "$RULES_DIR" ]; then
        return 0
    fi

    for rule_file in "${RULES_DIR}"/rule-*.conf; do
        if [ -f "$rule_file" ]; then
            if ! grep -q "^${field_name}=" "$rule_file"; then
                echo "${field_name}=\"${default_value}\"" >> "$rule_file"
            fi
        fi
    done
}

# 通用的服务重启函数
restart_and_confirm() {
    local operation_name="$1"
    local batch_mode="$2"

    if [ "$batch_mode" != "batch" ]; then
        echo -e "${YELLOW}正在重启服务以应用${operation_name}...${NC}"
        if service_restart; then
            echo -e "${GREEN}✓ 服务重启成功，${operation_name}已生效${NC}"
            return 0
        else
            echo -e "${RED}✗ 服务重启失败，请检查配置${NC}"
            return 1
        fi
    fi
    return 0
}

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
WHITE='\033[1;37m'
NC='\033[0m'

# 多源下载策略：官方源优先，镜像源作为容错备选
DOWNLOAD_SOURCES=(
    ""
    "https://ghfast.top/"
    "https://gh.222322.xyz/"
    "https://ghproxy.gpnu.org/"
)

# 网络超时设计：短超时用于快速失败，长超时用于重要操作
SHORT_CONNECT_TIMEOUT=5
SHORT_MAX_TIMEOUT=7
LONG_CONNECT_TIMEOUT=15
LONG_MAX_TIMEOUT=20

REALM_PATH="/usr/local/bin/realm"
CONFIG_DIR="/etc/realm"
MANAGER_CONF="${CONFIG_DIR}/manager.conf"
CONFIG_PATH="${CONFIG_DIR}/config.json"
SYSTEMD_PATH="/etc/systemd/system/realm.service"
RULES_DIR="${CONFIG_DIR}/rules"

# 默认tls和host域名（加密解密需要相同SNI）
DEFAULT_SNI_DOMAIN="www.tesla.com"

# 生成network配置
generate_network_config() {
    local config_file="/etc/realm/config.json"
    local base_network='{
        "no_tcp": false,
        "use_udp": true
    }'

    if [ -f "$config_file" ]; then
        local existing_proxy=$(jq -r '.network | {send_proxy, send_proxy_version, accept_proxy, accept_proxy_timeout} | to_entries | map(select(.value != null)) | from_entries' "$config_file" 2>/dev/null || echo "{}")
        if [ -n "$existing_proxy" ] && [ "$existing_proxy" != "{}" ] && [ "$existing_proxy" != "null" ]; then
            echo "$base_network" | jq ". + $existing_proxy" 2>/dev/null || echo "$base_network"
            return
        fi
    fi

    echo "$base_network"
}

generate_complete_config() {
    local endpoints="$1"
    local config_path="${2:-$CONFIG_PATH}"

    local network_config=$(generate_network_config)
    if [ -z "$network_config" ]; then
        network_config='{"no_tcp": false, "use_udp": true}'
    fi

    cat > "$config_path" <<EOF
{
    "network": $network_config,
    "endpoints": [$endpoints
    ]
}
EOF
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}错误: 此脚本需要 root 权限运行。${NC}"
        exit 1
    fi
}

# 检测系统类型（仅支持Debian/Ubuntu）
detect_system() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$NAME
        VER=$VERSION_ID
    elif type lsb_release >/dev/null 2>&1; then
        OS=$(lsb_release -si)
        VER=$(lsb_release -sr)
    else
        OS=$(uname -s)
        VER=$(uname -r)
    fi

    if ! command -v apt-get >/dev/null 2>&1; then
        echo -e "${RED}错误: 当前仅支持 Ubuntu/Debian 系统${NC}"
        echo -e "${YELLOW}检测到系统: $OS $VER${NC}"
        exit 1
    fi
}

check_netcat_openbsd() {
    dpkg -l netcat-openbsd >/dev/null 2>&1
    return $?
}

# 强制使用netcat-openbsd：传统netcat缺少-z选项，会导致端口检测失败
manage_dependencies() {
    local mode="$1"
    local missing_tools=()

    for tool in "${REQUIRED_TOOLS[@]}"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            missing_tools+=("$tool")
        elif [ "$mode" = "install" ]; then
            echo -e "${GREEN}✓${NC} $tool 已安装"
        fi
    done

    if ! check_netcat_openbsd; then
        missing_tools+=("nc")
        if [ "$mode" = "install" ]; then
            echo -e "${YELLOW}✗${NC} nc 需要安装netcat-openbsd版本"
        fi
    elif [ "$mode" = "install" ]; then
        echo -e "${GREEN}✓${NC} nc (netcat-openbsd) 已安装"
    fi

    if [ ${#missing_tools[@]} -gt 0 ]; then
        if [ "$mode" = "check" ]; then
            echo -e "${RED}错误: 缺少必备工具: ${missing_tools[*]}${NC}"
            echo -e "${YELLOW}请先选择菜单选项1进行安装，或手动运行安装命令:${NC}"
            echo -e "${BLUE}curl -fsSL https://raw.githubusercontent.com/zywe03/realm-xwPF/main/xwPF.sh | sudo bash -s install${NC}"
            exit 1
        elif [ "$mode" = "install" ]; then
            echo -e "${YELLOW}需要安装以下工具: ${missing_tools[*]}${NC}"
            echo -e "${BLUE}使用 apt-get 安装依赖,下载中...${NC}"
            apt-get update -qq >/dev/null 2>&1

            for tool in "${missing_tools[@]}"; do
                case "$tool" in
                    "curl") apt-get install -y curl >/dev/null 2>&1 && echo -e "${GREEN}✓${NC} curl 安装成功" ;;
                    "wget") apt-get install -y wget >/dev/null 2>&1 && echo -e "${GREEN}✓${NC} wget 安装成功" ;;
                    "tar") apt-get install -y tar >/dev/null 2>&1 && echo -e "${GREEN}✓${NC} tar 安装成功" ;;
                    "bc") apt-get install -y bc >/dev/null 2>&1 && echo -e "${GREEN}✓${NC} bc 安装成功" ;;
                    "jq") apt-get install -y jq >/dev/null 2>&1 && echo -e "${GREEN}✓${NC} jq 安装成功" ;;
                    "nc")
                        apt-get remove -y netcat-traditional >/dev/null 2>&1
                        apt-get install -y netcat-openbsd >/dev/null 2>&1 && echo -e "${GREEN}✓${NC} nc (netcat-openbsd) 安装成功"
                        ;;
                esac
            done
        fi
    elif [ "$mode" = "install" ]; then
        echo -e "${GREEN}所有必备工具已安装完成${NC}"
    fi

    [ "$mode" = "install" ] && echo ""
}

check_dependencies() {
    manage_dependencies "check"
}

# 获取本机公网IP
get_public_ip() {
    local ip_type="$1"
    local ip=""
    local curl_opts=""

    if [ "$ip_type" = "ipv6" ]; then
        curl_opts="-6"
    fi

    ip=$(curl -s --connect-timeout $SHORT_CONNECT_TIMEOUT --max-time $SHORT_MAX_TIMEOUT $curl_opts https://ipinfo.io/ip 2>/dev/null | tr -d '\n\r ')
    if [ -n "$ip" ] && [[ "$ip" =~ ^[0-9a-fA-F.:]+$ ]]; then
        echo "$ip"
        return 0
    fi

    ip=$(curl -s --connect-timeout $SHORT_CONNECT_TIMEOUT --max-time $SHORT_MAX_TIMEOUT $curl_opts https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null | grep "ip=" | cut -d'=' -f2 | tr -d '\n\r ')
    if [ -n "$ip" ] && [[ "$ip" =~ ^[0-9a-fA-F.:]+$ ]]; then
        echo "$ip"
        return 0
    fi

    echo ""
}

# 写入状态文件
write_manager_conf() {
    mkdir -p "$CONFIG_DIR"

    cat > "$MANAGER_CONF" <<EOF
ROLE=$ROLE
INSTALL_TIME="$(get_gmt8_time '+%Y-%m-%d %H:%M:%S')"
SECURITY_LEVEL=$SECURITY_LEVEL
TLS_CERT_PATH=$TLS_CERT_PATH
TLS_KEY_PATH=$TLS_KEY_PATH
TLS_SERVER_NAME=$TLS_SERVER_NAME
WS_PATH=$WS_PATH
WS_HOST=$WS_HOST
EOF

    echo -e "${GREEN}✓ 状态文件已保存: $MANAGER_CONF${NC}"
}

read_manager_conf() {
    if [ ! -f "$MANAGER_CONF" ]; then
        echo -e "${RED}错误: 状态文件不存在，请先运行安装${NC}"
        echo -e "${YELLOW}运行命令: ${GREEN}pf install${NC}"
        exit 1
    fi

    source "$MANAGER_CONF"

    if [ -z "$ROLE" ]; then
        echo -e "${RED}错误: 状态文件损坏，请重新安装${NC}"
        exit 1
    fi

}

# 支持realm单端口多规则复用，避免误报端口冲突
check_port_usage() {
    local port="$1"
    local service_name="$2"

    if [ -z "$port" ]; then
        return 0
    fi

    local port_check_cmd="ss -tulnp"
    local port_output=$($port_check_cmd 2>/dev/null | grep ":${port} ")

    if [ -n "$port_output" ]; then
        if echo "$port_output" | grep -q "realm"; then
            echo -e "${GREEN}✓ 端口 $port 已被realm服务占用，支持单端口中转多落地配置${NC}"
            return 1
        else
            echo -e "${YELLOW}警告: 端口 $port 已被其他服务占用${NC}"
            echo -e "${BLUE}占用进程信息:${NC}"
            echo "$port_output" | while read line; do
                echo "  $line"
            done

            read -p "是否继续配置？(y/n): " continue_config
            if [[ ! "$continue_config" =~ ^[Yy]$ ]]; then
                echo "配置已取消"
                exit 1
            fi
        fi
    fi
    return 0
}

check_connectivity() {
    local target="$1"
    local port="$2"
    local timeout="${3:-3}"

    if [ -z "$target" ] || [ -z "$port" ]; then
        return 1
    fi

    nc -z -w"$timeout" "$target" "$port" >/dev/null 2>&1
    return $?
}

validate_port() {
    local port="$1"
    if [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ]; then
        return 0
    else
        return 1
    fi
}

validate_ports() {
    local ports_input="$1"

    ports_input=$(echo "$ports_input" | tr -d ' ')

    if [ -z "$ports_input" ]; then
        return 1
    fi

    IFS=',' read -ra PORT_ARRAY <<< "$ports_input"
    for port in "${PORT_ARRAY[@]}"; do
        if ! validate_port "$port"; then
            return 1
        fi
    done

    return 0
}

# 为中转服务器创建多端口规则
create_nat_rules_for_ports() {
    local listen_ports="$1"
    local remote_ports="$2"

    listen_ports=$(echo "$listen_ports" | tr -d ' ')
    remote_ports=$(echo "$remote_ports" | tr -d ' ')

    IFS=',' read -ra LISTEN_PORT_ARRAY <<< "$listen_ports"
    IFS=',' read -ra REMOTE_PORT_ARRAY <<< "$remote_ports"

    local listen_count=${#LISTEN_PORT_ARRAY[@]}
    local remote_count=${#REMOTE_PORT_ARRAY[@]}

    for i in "${!LISTEN_PORT_ARRAY[@]}"; do
        local listen_port="${LISTEN_PORT_ARRAY[$i]}"
        local remote_port

        if [ "$remote_count" -eq 1 ]; then
            remote_port="${REMOTE_PORT_ARRAY[0]}"
        else
            if [ "$i" -lt "$remote_count" ]; then
                remote_port="${REMOTE_PORT_ARRAY[$i]}"
            else
                remote_port="${REMOTE_PORT_ARRAY[0]}"
            fi
        fi

        create_single_nat_rule "$listen_port" "$remote_port"
    done

    if [ ${#LISTEN_PORT_ARRAY[@]} -gt 1 ]; then
        echo -e "${BLUE}多端口配置完成，共创建 ${#LISTEN_PORT_ARRAY[@]} 个中转规则${NC}"
    fi
}

create_exit_rules_for_ports() {
    local listen_ports="$1"
    local forward_ports="$2"

    listen_ports=$(echo "$listen_ports" | tr -d ' ')
    forward_ports=$(echo "$forward_ports" | tr -d ' ')

    IFS=',' read -ra LISTEN_PORT_ARRAY <<< "$listen_ports"
    IFS=',' read -ra FORWARD_PORT_ARRAY <<< "$forward_ports"

    local listen_count=${#LISTEN_PORT_ARRAY[@]}
    local forward_count=${#FORWARD_PORT_ARRAY[@]}

    for i in "${!LISTEN_PORT_ARRAY[@]}"; do
        local listen_port="${LISTEN_PORT_ARRAY[$i]}"
        local forward_port

        if [ "$forward_count" -eq 1 ]; then
            forward_port="${FORWARD_PORT_ARRAY[0]}"
        else
            if [ "$i" -lt "$forward_count" ]; then
                forward_port="${FORWARD_PORT_ARRAY[$i]}"
            else
                forward_port="${FORWARD_PORT_ARRAY[0]}"
            fi
        fi

        create_single_exit_rule "$listen_port" "$forward_port"
    done

    if [ ${#LISTEN_PORT_ARRAY[@]} -gt 1 ]; then
        echo -e "${BLUE}多端口配置完成，共创建 ${#LISTEN_PORT_ARRAY[@]} 个落地规则${NC}"
    fi
}

create_single_nat_rule() {
    local listen_port="$1"
    local remote_port="$2"

    local rule_id=$(generate_rule_id)
    local rule_file="${RULES_DIR}/rule-${rule_id}.conf"
    local rule_name="中转"

    cat > "$rule_file" <<EOF
RULE_ID=$rule_id
RULE_NAME="$rule_name"
RULE_ROLE="1"
SECURITY_LEVEL="$SECURITY_LEVEL"
LISTEN_PORT="$listen_port"
LISTEN_IP="${NAT_LISTEN_IP:-::}"
THROUGH_IP="$NAT_THROUGH_IP"
REMOTE_HOST="$REMOTE_IP"
REMOTE_PORT="$remote_port"
TLS_SERVER_NAME="$TLS_SERVER_NAME"
TLS_CERT_PATH="$TLS_CERT_PATH"
TLS_KEY_PATH="$TLS_KEY_PATH"
WS_PATH="$WS_PATH"
WS_HOST="$WS_HOST"
RULE_NOTE="$RULE_NOTE"
ENABLED="true"
CREATED_TIME="$(get_gmt8_time '+%Y-%m-%d %H:%M:%S')"

BALANCE_MODE="off"
TARGET_STATES=""
WEIGHTS=""

FAILOVER_ENABLED="false"
HEALTH_CHECK_INTERVAL="4"
FAILURE_THRESHOLD="2"
SUCCESS_THRESHOLD="2"
CONNECTION_TIMEOUT="3"

MPTCP_MODE="off"
PROXY_MODE="off"
EOF

    echo -e "${GREEN}✓ 中转配置已创建 (ID: $rule_id) 端口: $listen_port->$REMOTE_IP:$remote_port${NC}"
}

create_single_exit_rule() {
    local listen_port="$1"
    local forward_port="$2"

    local rule_id=$(generate_rule_id)
    local rule_file="${RULES_DIR}/rule-${rule_id}.conf"
    local rule_name="落地"
    local forward_target="$FORWARD_TARGET:$forward_port"

    cat > "$rule_file" <<EOF
RULE_ID=$rule_id
RULE_NAME="$rule_name"
RULE_ROLE="2"
SECURITY_LEVEL="$SECURITY_LEVEL"
LISTEN_PORT="$listen_port"
FORWARD_TARGET="$forward_target"
TLS_SERVER_NAME="$TLS_SERVER_NAME"
TLS_CERT_PATH="$TLS_CERT_PATH"
TLS_KEY_PATH="$TLS_KEY_PATH"
WS_PATH="$WS_PATH"
WS_HOST="$WS_HOST"
RULE_NOTE="$RULE_NOTE"
ENABLED="true"
CREATED_TIME="$(get_gmt8_time '+%Y-%m-%d %H:%M:%S')"

BALANCE_MODE="off"
TARGET_STATES=""
WEIGHTS=""

FAILOVER_ENABLED="false"
HEALTH_CHECK_INTERVAL="4"
FAILURE_THRESHOLD="2"
SUCCESS_THRESHOLD="2"
CONNECTION_TIMEOUT="3"

MPTCP_MODE="off"
PROXY_MODE="off"
EOF

    echo -e "${GREEN}✓ 落地配置已创建 (ID: $rule_id) 端口: $listen_port->$forward_target${NC}"
}

validate_ip() {
    local ip="$1"

    if [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        IFS='.' read -ra ADDR <<< "$ip"
        for i in "${ADDR[@]}"; do
            if [ "$i" -gt 255 ]; then
                return 1
            fi
        done
        return 0
    fi

    if [[ "$ip" =~ ^[0-9a-fA-F:]+$ ]] && [[ "$ip" == *":"* ]]; then
        return 0
    fi
    return 1
}

validate_target_address() {
    local target="$1"

    if [ -z "$target" ]; then
        return 1
    fi

    if [[ "$target" == *","* ]]; then
        IFS=',' read -ra ADDRESSES <<< "$target"
        for addr in "${ADDRESSES[@]}"; do
            addr=$(echo "$addr" | xargs)
            if ! validate_single_address "$addr"; then
                return 1
            fi
        done
        return 0
    else
        validate_single_address "$target"
    fi
}

validate_single_address() {
    local addr="$1"

    if validate_ip "$addr"; then
        return 0
    fi

    if [[ "$addr" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]] || [[ "$addr" == "localhost" ]]; then
        return 0
    fi

    return 1
}

# 根据角色和安全级别生成对应的传输配置，确保客户端和服务端配置匹配 1=中转服务器(客户端), 2=出口服务器(服务端)
get_transport_config() {
    local security_level="$1"
    local server_name="$2"
    local cert_path="$3"
    local key_path="$4"
    local role="$5"
    local ws_path="$6"

    case "$security_level" in
        "standard")
            echo ""
            ;;
        "ws")
            local ws_path_param="${ws_path:-/ws}"
            local ws_host_param="${server_name:-$DEFAULT_SNI_DOMAIN}"
            if [ "$role" = "1" ]; then
                echo '"remote_transport": "ws;host='$ws_host_param';path='$ws_path_param'"'
            elif [ "$role" = "2" ]; then
                echo '"listen_transport": "ws;host='$ws_host_param';path='$ws_path_param'"'
            fi
            ;;
        "tls_self")
            local sni_name="${server_name:-$DEFAULT_SNI_DOMAIN}"
            if [ "$role" = "1" ]; then
                echo '"remote_transport": "tls;sni='$sni_name';insecure"'
            elif [ "$role" = "2" ]; then
                echo '"listen_transport": "tls;servername='$sni_name'"'
            fi
            ;;
        "tls_ca")
            if [ "$role" = "1" ]; then
                local sni_name="${server_name:-$DEFAULT_SNI_DOMAIN}"
                echo '"remote_transport": "tls;sni='$sni_name'"'
            elif [ "$role" = "2" ]; then
                if [ -n "$cert_path" ] && [ -n "$key_path" ]; then
                    echo '"listen_transport": "tls;cert='$cert_path';key='$key_path'"'
                else
                    echo ""
                fi
            fi
            ;;
        "ws_tls_self")
            local ws_host_param="${server_name:-$DEFAULT_SNI_DOMAIN}"
            local ws_path_param="${ws_path:-/ws}"
            local sni_name="${TLS_SERVER_NAME:-$DEFAULT_SNI_DOMAIN}"
            if [ "$role" = "1" ]; then
                echo '"remote_transport": "ws;host='$ws_host_param';path='$ws_path_param';tls;sni='$sni_name';insecure"'
            elif [ "$role" = "2" ]; then
                echo '"listen_transport": "ws;host='$ws_host_param';path='$ws_path_param';tls;servername='$sni_name'"'
            fi
            ;;
        "ws_tls_ca")
            local ws_host_param="${server_name:-$DEFAULT_SNI_DOMAIN}"
            local ws_path_param="${ws_path:-/ws}"
            local sni_name="${TLS_SERVER_NAME:-$DEFAULT_SNI_DOMAIN}"
            if [ "$role" = "1" ]; then
                echo '"remote_transport": "ws;host='$ws_host_param';path='$ws_path_param';tls;sni='$sni_name'"'
            elif [ "$role" = "2" ]; then
                if [ -n "$cert_path" ] && [ -n "$key_path" ]; then
                    echo '"listen_transport": "ws;host='$ws_host_param';path='$ws_path_param';tls;cert='$cert_path';key='$key_path'"'
                else
                    echo ""
                fi
            fi
            ;;
        *)
            echo ""
            ;;
    esac
}

# 支持多地址负载均衡：主地址+额外地址的realm配置格式
generate_forward_endpoints_config() {
    local target="$FORWARD_TARGET"
    local listen_ip="::"

    local transport_config=$(get_transport_config "$SECURITY_LEVEL" "$TLS_SERVER_NAME" "$TLS_CERT_PATH" "$TLS_KEY_PATH" "2" "$WS_PATH")
    local transport_line=""
    if [ -n "$transport_config" ]; then
        transport_line=",
            $transport_config"
    fi

    if [[ "$target" == *","* ]]; then
        local port="${target##*:}"
        local addresses_part="${target%:*}"
        IFS=',' read -ra ip_addresses <<< "$addresses_part"

        local main_address="${ip_addresses[0]}:$port"
        local extra_addresses=""

        if [ ${#ip_addresses[@]} -gt 1 ]; then
            for ((i=1; i<${#ip_addresses[@]}; i++)); do
                if [ -n "$extra_addresses" ]; then
                    extra_addresses="$extra_addresses, "
                fi
                extra_addresses="$extra_addresses\"${ip_addresses[i]}:$port\""
            done

            extra_addresses=",
        \"extra_remotes\": [$extra_addresses]"
        fi

        echo "
        {
            \"listen\": \"${listen_ip}:${EXIT_LISTEN_PORT}\",
            \"remote\": \"${main_address}\"${extra_addresses}${transport_line}
        }"
    else
        echo "
        {
            \"listen\": \"${listen_ip}:${EXIT_LISTEN_PORT}\",
            \"remote\": \"${target}\"${transport_line}
        }"
    fi
}

init_rules_dir() {
    mkdir -p "$RULES_DIR"
    if [ ! -f "${RULES_DIR}/.initialized" ]; then
        touch "${RULES_DIR}/.initialized"
        echo -e "${GREEN}✓ 规则目录已初始化: $RULES_DIR${NC}"
    fi
}

validate_rule_ids() {
    local rule_ids="$1"
    local valid_ids=()
    local invalid_ids=()

    local ids_array
    IFS=',' read -ra ids_array <<< "$rule_ids"

    for id in "${ids_array[@]}"; do
        id=$(echo "$id" | xargs)
        if [[ "$id" =~ ^[0-9]+$ ]]; then
            local rule_file="${RULES_DIR}/rule-${id}.conf"
            if [ -f "$rule_file" ]; then
                valid_ids+=("$id")
            else
                invalid_ids+=("$id")
            fi
        else
            invalid_ids+=("$id")
        fi
    done

    echo "${#valid_ids[@]}|${#invalid_ids[@]}|${valid_ids[*]}|${invalid_ids[*]}"
}

parse_rule_ids() {
    local input="$1"
    echo "$input" | tr -d ' '
}

get_active_rules_count() {
    local count=0
    if [ -d "$RULES_DIR" ]; then
        for rule_file in "${RULES_DIR}"/rule-*.conf; do
            if [ -f "$rule_file" ]; then
                if read_rule_file "$rule_file"; then
                    count=$((count + 1))
                fi
            fi
        done
    fi
    echo "$count"
}

# 规则重排序后同步更新健康监控记录，保持数据一致性
sync_health_status_ids() {
    local health_status_file="/etc/realm/health/health_status.conf"

    if [ ! -f "$health_status_file" ]; then
        return 0
    fi

    local temp_health_file="${health_status_file}.tmp"
    grep "^#" "$health_status_file" > "$temp_health_file" 2>/dev/null || true

    while IFS='|' read -r old_rule_id target status fail_count success_count last_check failure_start_time; do
        [[ "$old_rule_id" =~ ^#.*$ ]] && continue
        [[ -z "$old_rule_id" ]] && continue

        local new_rule_id=""
        for rule_file in "${RULES_DIR}"/rule-*.conf; do
            if [ -f "$rule_file" ] && read_rule_file "$rule_file"; then
                if [ "$RULE_ROLE" = "1" ]; then
                    if [[ "$REMOTE_HOST" == *"$target"* ]] || [[ "$target" == "${REMOTE_HOST}:${REMOTE_PORT}" ]]; then
                        new_rule_id="$RULE_ID"
                        break
                    fi
                else
                    if [[ "$FORWARD_TARGET" == "$target" ]]; then
                        new_rule_id="$RULE_ID"
                        break
                    fi
                fi
            fi
        done

        if [ -n "$new_rule_id" ]; then
            echo "${new_rule_id}|${target}|${status}|${fail_count}|${success_count}|${last_check}|${failure_start_time}" >> "$temp_health_file"
        fi

    done < <(grep -v "^#" "$health_status_file" 2>/dev/null || true)

    if [ -f "$temp_health_file" ]; then
        mv "$temp_health_file" "$health_status_file"
    fi
}

# 按端口和角色排序规则ID，提升配置可读性和管理效率
reorder_rule_ids() {
    if [ ! -d "$RULES_DIR" ]; then
        return 0
    fi

    local rule_count=$(ls -1 "${RULES_DIR}"/rule-*.conf 2>/dev/null | wc -l)
    if [ "$rule_count" -eq 0 ]; then
        return 0
    fi

    local temp_file=$(mktemp)

    for rule_file in "${RULES_DIR}"/rule-*.conf; do
        if [ -f "$rule_file" ]; then
            if read_rule_file "$rule_file"; then
                echo "${LISTEN_PORT}|${RULE_ROLE}|${RULE_ID}|${rule_file}" >> "$temp_file"
            fi
        fi
    done

    local sorted_rules=($(sort -t'|' -k1,1n -k2,2n -k3,3n "$temp_file"))
    rm -f "$temp_file"

    if [ ${#sorted_rules[@]} -eq 0 ]; then
        return 0
    fi

    local temp_dir=$(mktemp -d)
    local new_id=1
    local reorder_needed=false

    for rule_data in "${sorted_rules[@]}"; do
        IFS='|' read -r port role old_id old_file <<< "$rule_data"
        if [ "$old_id" -ne "$new_id" ]; then
            reorder_needed=true
            break
        fi
        new_id=$((new_id + 1))
    done

    if [ "$reorder_needed" = false ]; then
        rmdir "$temp_dir"
        return 0
    fi

    new_id=1
    for rule_data in "${sorted_rules[@]}"; do
        IFS='|' read -r port role old_id old_file <<< "$rule_data"

        local temp_new_file="${temp_dir}/rule-${new_id}.conf"

        if cp "$old_file" "$temp_new_file"; then
            sed -i "s/^RULE_ID=.*/RULE_ID=$new_id/" "$temp_new_file"
        else
            echo -e "${RED}错误: 无法复制规则文件${NC}" >&2
            rm -rf "$temp_dir"
            return 1
        fi

        new_id=$((new_id + 1))
    done

    # 原子性操作：避免中间状态导致的配置不一致
    if rm -f "${RULES_DIR}"/rule-*.conf && mv "${temp_dir}"/rule-*.conf "${RULES_DIR}/"; then
        rmdir "$temp_dir"
        sync_health_status_ids
        return 0
    else
        echo -e "${RED}错误: 规则重排序失败${NC}" >&2
        rm -rf "$temp_dir"
        return 1
    fi
}

generate_rule_id() {
    local max_id=0
    if [ -d "$RULES_DIR" ]; then
        for rule_file in "${RULES_DIR}"/rule-*.conf; do
            if [ -f "$rule_file" ]; then
                local id=$(basename "$rule_file" | sed 's/rule-\([0-9]*\)\.conf/\1/')
                if [ "$id" -gt "$max_id" ]; then
                    max_id=$id
                fi
            fi
        done
    fi
    echo $((max_id + 1))
}

read_rule_file() {
    local rule_file="$1"
    if [ -f "$rule_file" ]; then
        source "$rule_file"
        RULE_NOTE="${RULE_NOTE:-}"
        MPTCP_MODE="${MPTCP_MODE:-off}"
        PROXY_MODE="${PROXY_MODE:-off}"
        return 0
    else
        return 1
    fi
}

get_balance_info_display() {
    local remote_host="$1"
    local balance_mode="$2"

    local balance_info=""
    case "$balance_mode" in
        "roundrobin")
            balance_info=" ${YELLOW}[轮询]${NC}"
            ;;
        "iphash")
            balance_info=" ${BLUE}[IP哈希]${NC}"
            ;;
        *)
            balance_info=" ${WHITE}[off]${NC}"
            ;;
    esac
    echo "$balance_info"
}

# 动态计算权重百分比，支持bc和awk两种计算方式确保兼容性
get_balance_info_with_weight() {
    local remote_host="$1"
    local balance_mode="$2"
    local weights="$3"
    local target_index="$4"

    local balance_info=""
    case "$balance_mode" in
        "roundrobin")
            balance_info=" ${YELLOW}[轮询]${NC}"
            ;;
        "iphash")
            balance_info=" ${BLUE}[IP哈希]${NC}"
            ;;
        *)
            balance_info=" ${WHITE}[off]${NC}"
            return 0
            ;;
    esac

    if [[ "$remote_host" == *","* ]]; then
        local weight_array
        if [ -n "$weights" ]; then
            IFS=',' read -ra weight_array <<< "$weights"
        else
            IFS=',' read -ra host_array <<< "$remote_host"
            for ((i=0; i<${#host_array[@]}; i++)); do
                weight_array[i]=1
            done
        fi

        local total_weight=0
        for w in "${weight_array[@]}"; do
            total_weight=$((total_weight + w))
        done

        local current_weight="${weight_array[$((target_index-1))]:-1}"

        local percentage
        if [ "$total_weight" -gt 0 ]; then
            if command -v bc >/dev/null 2>&1; then
                percentage=$(echo "scale=1; $current_weight * 100 / $total_weight" | bc 2>/dev/null || echo "0.0")
            else
                percentage=$(awk "BEGIN {printf \"%.1f\", $current_weight * 100 / $total_weight}")
            fi
        else
            percentage="0.0"
        fi

        balance_info="$balance_info ${GREEN}[权重: $current_weight]${NC} ${BLUE}($percentage%)${NC}"
    fi

    echo "$balance_info"
}

is_target_enabled() {
    local target_index="$1"
    local target_states="$2"
    local state_key="target_${target_index}"

    if [[ "$target_states" == *"$state_key:false"* ]]; then
        echo "false"
    else
        echo "true"
    fi
}

read_and_check_relay_rule() {
    local rule_file="$1"
    if read_rule_file "$rule_file" && [ "$RULE_ROLE" = "1" ]; then
        return 0
    else
        return 1
    fi
}

# 根据显示模式调整规则列表格式，支持管理、MPTCP、Proxy三种视图
list_rules_with_info() {
    local display_mode="${1:-management}"

    if [ ! -d "$RULES_DIR" ] || [ -z "$(ls -A "$RULES_DIR"/*.conf 2>/dev/null)" ]; then
        echo -e "${BLUE}暂无转发规则${NC}"
        return 1
    fi

    case "$display_mode" in
        "mptcp")
            echo -e "${BLUE}当前规则列表:${NC}"
            echo ""
            ;;
        "proxy")
            echo -e "${BLUE}当前规则列表:${NC}"
            echo ""
            ;;
        "management"|*)
            ;;
    esac

    local has_relay_rules=false
    local relay_count=0

    if [ "$display_mode" = "management" ]; then
        for rule_file in "${RULES_DIR}"/rule-*.conf; do
            if [ -f "$rule_file" ]; then
                if read_and_check_relay_rule "$rule_file"; then
                    if [ "$has_relay_rules" = false ]; then
                        echo -e "${GREEN}中转服务器:${NC}"
                        has_relay_rules=true
                    fi
                    relay_count=$((relay_count + 1))
                    display_single_rule_info "$rule_file" "$display_mode"
                fi
            fi
        done
    fi

    local has_exit_rules=false
    local exit_count=0
    local has_rules=false

    for rule_file in "${RULES_DIR}"/rule-*.conf; do
        if [ -f "$rule_file" ]; then
            if read_rule_file "$rule_file"; then
                has_rules=true

                if [ "$display_mode" = "management" ]; then
                    if [ "$RULE_ROLE" = "2" ]; then
                        if [ "$has_exit_rules" = false ]; then
                            if [ "$has_relay_rules" = true ]; then
                                echo ""
                            fi
                            echo -e "${GREEN}落地服务器 (双端Realm架构):${NC}"
                            has_exit_rules=true
                        fi
                        exit_count=$((exit_count + 1))
                        display_single_rule_info "$rule_file" "$display_mode"
                    fi
                else
                    display_single_rule_info "$rule_file" "$display_mode"
                fi
            fi
        fi
    done

    if [ "$display_mode" != "management" ] && [ "$has_rules" = false ]; then
        echo -e "${BLUE}暂无转发规则${NC}"
        return 1
    fi

    return 0
}

get_rule_status_display() {
    local security_display="$1"
    local note_display="$2"

    local mptcp_mode="${MPTCP_MODE:-off}"
    local mptcp_display=""
    if [ "$mptcp_mode" != "off" ]; then
        local mptcp_text=$(get_mptcp_mode_display "$mptcp_mode")
        local mptcp_color=$(get_mptcp_mode_color "$mptcp_mode")
        mptcp_display=" | MPTCP: ${mptcp_color}$mptcp_text${NC}"
    fi

    local proxy_mode="${PROXY_MODE:-off}"
    local proxy_display=""
    if [ "$proxy_mode" != "off" ]; then
        local proxy_text=$(get_proxy_mode_display "$proxy_mode")
        local proxy_color=$(get_proxy_mode_color "$proxy_mode")
        proxy_display=" | Proxy: ${proxy_color}$proxy_text${NC}"
    fi

    echo -e "    安全: ${YELLOW}$security_display${NC}${mptcp_display}${proxy_display}${note_display}"
}

display_single_rule_info() {
    local rule_file="$1"
    local display_mode="$2"

    if ! read_rule_file "$rule_file"; then
        return 1
    fi

    local status_color="${GREEN}"
    local status_text="启用"
    if [ "$ENABLED" != "true" ]; then
        status_color="${RED}"
        status_text="禁用"
    fi

    # 基础信息显示
    case "$display_mode" in
        "mptcp")
            local mptcp_mode="${MPTCP_MODE:-off}"
            local mptcp_display=$(get_mptcp_mode_display "$mptcp_mode")
            local mptcp_color=$(get_mptcp_mode_color "$mptcp_mode")
            echo -e "ID ${BLUE}$RULE_ID${NC}: $RULE_NAME | 状态: ${status_color}$status_text${NC} | MPTCP: ${mptcp_color}$mptcp_display${NC}"
            ;;
        "proxy")
            local proxy_mode="${PROXY_MODE:-off}"
            local proxy_display=$(get_proxy_mode_display "$proxy_mode")
            local proxy_color=$(get_proxy_mode_color "$proxy_mode")
            echo -e "ID ${BLUE}$RULE_ID${NC}: $RULE_NAME | 状态: ${status_color}$status_text${NC} | Proxy: ${proxy_color}$proxy_display${NC}"
            ;;
        "management"|*)
            if [ "$RULE_ROLE" = "2" ]; then
                local target_host="${FORWARD_TARGET%:*}"
                local target_port="${FORWARD_TARGET##*:}"
                local display_target=$(smart_display_target "$target_host")
                local rule_display_name="$RULE_NAME"
                echo -e "  ID ${BLUE}$RULE_ID${NC}: ${GREEN}$rule_display_name${NC} ($LISTEN_PORT → $display_target:$target_port) [${status_color}$status_text${NC}]"
            else
                local display_target=$(smart_display_target "$REMOTE_HOST")
                local rule_display_name="$RULE_NAME"
                local through_display="${THROUGH_IP:-::}"
                echo -e "  ID ${BLUE}$RULE_ID${NC}: ${GREEN}$rule_display_name${NC} ($LISTEN_PORT → $through_display → $display_target:$REMOTE_PORT) [${status_color}$status_text${NC}]"
            fi
            return 0
            ;;
    esac

    if [ "$RULE_ROLE" = "2" ]; then
        local target_host="${FORWARD_TARGET%:*}"
        local target_port="${FORWARD_TARGET##*:}"
        local display_target=$(smart_display_target "$target_host")
        local display_ip="::"
        echo -e "  监听: ${LISTEN_IP:-$display_ip}:$LISTEN_PORT → $display_target:$target_port"
    else
        local display_target=$(smart_display_target "$REMOTE_HOST")
        local display_ip="${NAT_LISTEN_IP:-::}"
        local through_display="${THROUGH_IP:-::}"
        echo -e "  监听: ${LISTEN_IP:-$display_ip}:$LISTEN_PORT → $through_display → $display_target:$REMOTE_PORT"
    fi
    echo ""
}

list_all_rules() {
    echo -e "${YELLOW}=== 所有转发规则 ===${NC}"
    echo ""

    if [ ! -d "$RULES_DIR" ] || [ -z "$(ls -A "$RULES_DIR"/*.conf 2>/dev/null)" ]; then
        echo -e "${BLUE}暂无转发规则${NC}"
        return 0
    fi

    local count=0
    for rule_file in "${RULES_DIR}"/rule-*.conf; do
        if [ -f "$rule_file" ]; then
            if read_rule_file "$rule_file"; then
                count=$((count + 1))
                local status_color="${GREEN}"
                local status_text="启用"
                if [ "$ENABLED" != "true" ]; then
                    status_color="${RED}"
                    status_text="禁用"
                fi

                echo -e "ID ${BLUE}$RULE_ID${NC}: $RULE_NAME"
                local security_display=$(get_security_display "$SECURITY_LEVEL" "$WS_PATH" "$WS_HOST")
                local note_display=""
                if [ -n "$RULE_NOTE" ]; then
                    note_display=" | 备注: ${GREEN}$RULE_NOTE${NC}"
                fi
                echo -e "  通用配置: ${YELLOW}$security_display${NC}${note_display} | 状态: ${status_color}$status_text${NC}"

                if [ "$RULE_ROLE" = "2" ]; then
                    local display_ip="::"
                    echo -e "  监听: ${GREEN}${LISTEN_IP:-$display_ip}:$LISTEN_PORT${NC} → 转发: ${GREEN}$FORWARD_TARGET${NC}"
                else
                    local display_ip="${NAT_LISTEN_IP:-::}"
                    local through_display="${THROUGH_IP:-::}"
                    echo -e "  中转: ${GREEN}${LISTEN_IP:-$display_ip}:$LISTEN_PORT${NC} → ${GREEN}$through_display${NC} → ${GREEN}$REMOTE_HOST:$REMOTE_PORT${NC}"
                fi
                echo -e "  创建时间: $CREATED_TIME"
                echo ""
            fi
        fi
    done

    echo -e "${BLUE}共找到 $count 个配置${NC}"
}

# 编辑现有规则
edit_rule_interactive() {
    echo -e "${YELLOW}=== 编辑配置 ===${NC}"
    echo ""
    
    if ! list_rules_with_info "management"; then
        read -p "按回车键返回..."
        return 1
    fi
    
    echo ""
    read -p "请输入要编辑的规则ID: " rule_id
    
    if [ -z "$rule_id" ]; then
        echo -e "${RED}未输入规则ID${NC}"
        read -p "按回车键返回..."
        return 1
    fi
    
    if ! [[ "$rule_id" =~ ^[0-9]+$ ]]; then
        echo -e "${RED}无效的规则ID${NC}"
        read -p "按回车键返回..."
        return 1
    fi
    
    local rule_file="${RULES_DIR}/rule-${rule_id}.conf"
    if [ ! -f "$rule_file" ]; then
        echo -e "${RED}规则 $rule_id 不存在${NC}"
        read -p "按回车键返回..."
        return 1
    fi
    
    if ! read_rule_file "$rule_file"; then
        echo -e "${RED}无法读取规则文件${NC}"
        read -p "按回车键返回..."
        return 1
    fi
    
    echo ""
    echo -e "${GREEN}正在编辑规则: $RULE_NAME (ID: $rule_id)${NC}"
    echo ""
    
    if [ "$RULE_ROLE" = "1" ]; then
        edit_nat_server_config "$rule_file"
    elif [ "$RULE_ROLE" = "2" ]; then
        edit_exit_server_config "$rule_file"
    fi
    
    if [ $? -eq 0 ]; then
        echo -e "${YELLOW}正在重启服务以应用配置更改...${NC}"
        service_restart
    fi
    
    read -p "按回车键返回..."
}

# 编辑中转服务器配置
edit_nat_server_config() {
    local rule_file="$1"
    read_rule_file "$rule_file"
    
    echo -e "${YELLOW}=== 编辑中转服务器配置 ===${NC}"
    echo ""
    
    local new_listen_port
    while true; do
        echo -ne "请输入本地监听端口 (客户端连接的端口，回车默认${GREEN}${LISTEN_PORT}${NC}): "
        read new_listen_port
        if [ -z "$new_listen_port" ]; then
            new_listen_port="$LISTEN_PORT"
            break
        fi
        if validate_port "$new_listen_port"; then
            break
        else
            echo -e "${RED}无效端口号${NC}"
        fi
    done
    
    local new_listen_ip
    echo -ne "自定义(指定)入口监听IP地址(客户端连接IP,回车默认${GREEN}${LISTEN_IP:-::}${NC}): "
    read new_listen_ip
    if [ -z "$new_listen_ip" ]; then
        new_listen_ip="${LISTEN_IP:-::}"
    elif ! validate_ip "$new_listen_ip"; then
        echo -e "${RED}无效IP地址，保持原值${NC}"
        new_listen_ip="${LISTEN_IP:-::}"
    fi
    
    local new_through_ip
    echo -ne "自定义(指定)出口IP地址(适用于中转多IP出口情况,回车默认${GREEN}${THROUGH_IP:-::}${NC}): "
    read new_through_ip
    if [ -z "$new_through_ip" ]; then
        new_through_ip="${THROUGH_IP:-::}"
    elif ! validate_ip "$new_through_ip"; then
        echo -e "${RED}无效IP地址，保持原值${NC}"
        new_through_ip="${THROUGH_IP:-::}"
    fi
    
    echo ""
    echo -e "${YELLOW}=== 编辑出口服务器信息配置 ===${NC}"
    
    local new_remote_host
    echo -ne "出口服务器的IP地址或域名(回车默认${GREEN}${REMOTE_HOST}${NC}): "
    read new_remote_host
    if [ -z "$new_remote_host" ]; then
        new_remote_host="$REMOTE_HOST"
    elif ! validate_single_address "$new_remote_host"; then
        echo -e "${RED}无效地址，保持原值${NC}"
        new_remote_host="$REMOTE_HOST"
    fi
    
    local new_remote_port
    while true; do
        echo -ne "出口服务器的监听端口(回车默认${GREEN}${REMOTE_PORT}${NC}): "
        read new_remote_port
        if [ -z "$new_remote_port" ]; then
            new_remote_port="$REMOTE_PORT"
            break
        fi
        if validate_port "$new_remote_port"; then
            break
        else
            echo -e "${RED}无效端口号${NC}"
        fi
    done
    
    sed -i "s/^LISTEN_PORT=.*/LISTEN_PORT=\"$new_listen_port\"/" "$rule_file"
    sed -i "s|^LISTEN_IP=.*|LISTEN_IP=\"$new_listen_ip\"|" "$rule_file"
    sed -i "s|^THROUGH_IP=.*|THROUGH_IP=\"$new_through_ip\"|" "$rule_file"
    sed -i "s/^REMOTE_HOST=.*/REMOTE_HOST=\"$new_remote_host\"/" "$rule_file"
    sed -i "s/^REMOTE_PORT=.*/REMOTE_PORT=\"$new_remote_port\"/" "$rule_file"
    
    echo ""
    echo -e "${GREEN}✓ 配置已更新${NC}"
    return 0
}

# 编辑落地服务器配置
edit_exit_server_config() {
    local rule_file="$1"
    read_rule_file "$rule_file"
    
    echo -e "${YELLOW}=== 编辑解密并转发服务器配置 (双端Realm架构) ===${NC}"
    echo ""
    
    local new_listen_port
    while true; do
        echo -ne "请输入监听端口 (回车默认${GREEN}${LISTEN_PORT}${NC}): "
        read new_listen_port
        if [ -z "$new_listen_port" ]; then
            new_listen_port="$LISTEN_PORT"
            break
        fi
        if validate_port "$new_listen_port"; then
            break
        else
            echo -e "${RED}无效端口号${NC}"
        fi
    done
    
    local current_target_host="${FORWARD_TARGET%:*}"
    local current_target_port="${FORWARD_TARGET##*:}"
    
    local new_target_host
    echo -ne "转发目标IP地址(回车默认${GREEN}${current_target_host}${NC}): "
    read new_target_host
    if [ -z "$new_target_host" ]; then
        new_target_host="$current_target_host"
    elif ! validate_target_address "$new_target_host"; then
        echo -e "${RED}无效地址，保持原值${NC}"
        new_target_host="$current_target_host"
    fi
    
    local new_target_port
    while true; do
        echo -ne "转发目标业务端口(回车默认${GREEN}${current_target_port}${NC}): "
        read new_target_port
        if [ -z "$new_target_port" ]; then
            new_target_port="$current_target_port"
            break
        fi
        if validate_port "$new_target_port"; then
            break
        else
            echo -e "${RED}无效端口号${NC}"
        fi
    done
    
    sed -i "s/^LISTEN_PORT=.*/LISTEN_PORT=\"$new_listen_port\"/" "$rule_file"
    sed -i "s|^FORWARD_TARGET=.*|FORWARD_TARGET=\"${new_target_host}:${new_target_port}\"|" "$rule_file"
    
    echo ""
    echo -e "${GREEN}✓ 配置已更新${NC}"
    return 0
}

interactive_add_rule() {
    echo -e "${YELLOW}=== 添加新转发配置 ===${NC}"
    echo ""

    echo "请选择新配置的角色:"
    echo -e "${GREEN}[1]${NC} 中转服务器"
    echo -e "${GREEN}[2]${NC} 服务端(落地)服务器 (解密并转发)"
    echo "双端架构用于一方加密一方解密：隧道,MPTCP，Proxy Protocol等"
    echo ""
    local RULE_ROLE
    while true; do
        read -p "请输入数字 [1-2]: " RULE_ROLE
        case $RULE_ROLE in
            1)
                echo -e "${GREEN}已选择: 中转服务器${NC}"
                break
                ;;
            2)
                echo -e "${GREEN}已选择: 服务端(落地)服务器 (解密并转发)${NC}"
                break
                ;;
            *)
                echo -e "${RED}无效选择，请输入 1-2${NC}"
                ;;
        esac
    done
    echo ""

    # 保护全局变量不被污染，确保多次配置操作的独立性
    local ORIG_ROLE="$ROLE"
    local ORIG_NAT_LISTEN_PORT="$NAT_LISTEN_PORT"
    local ORIG_REMOTE_IP="$REMOTE_IP"
    local ORIG_REMOTE_PORT="$REMOTE_PORT"
    local ORIG_EXIT_LISTEN_PORT="$EXIT_LISTEN_PORT"
    local ORIG_FORWARD_TARGET="$FORWARD_TARGET"
    local ORIG_SECURITY_LEVEL="$SECURITY_LEVEL"
    local ORIG_TLS_SERVER_NAME="$TLS_SERVER_NAME"
    local ORIG_TLS_CERT_PATH="$TLS_CERT_PATH"
    local ORIG_TLS_KEY_PATH="$TLS_KEY_PATH"

    ROLE="$RULE_ROLE"

    if [ "$RULE_ROLE" -eq 1 ]; then
        configure_nat_server
        if [ $? -ne 0 ]; then
            echo "配置已取消"
            return 1
        fi
    elif [ "$RULE_ROLE" -eq 2 ]; then
        configure_exit_server
        if [ $? -ne 0 ]; then
            echo "配置已取消"
            return 1
        fi
    fi

    echo -e "${YELLOW}正在创建转发配置...${NC}"
    init_rules_dir

    if [ "$RULE_ROLE" -eq 1 ]; then
        create_nat_rules_for_ports "$NAT_LISTEN_PORT" "$REMOTE_PORT"
    elif [ "$RULE_ROLE" -eq 2 ]; then
        local forward_port="${FORWARD_TARGET##*:}"
        local forward_address="${FORWARD_TARGET%:*}"

        local temp_forward_target="$FORWARD_TARGET"
        FORWARD_TARGET="$forward_address"

        create_exit_rules_for_ports "$EXIT_LISTEN_PORT" "$forward_port"

        FORWARD_TARGET="$temp_forward_target"
    fi

    ROLE="$ORIG_ROLE"
    NAT_LISTEN_PORT="$ORIG_NAT_LISTEN_PORT"
    REMOTE_IP="$ORIG_REMOTE_IP"
    REMOTE_PORT="$ORIG_REMOTE_PORT"
    EXIT_LISTEN_PORT="$ORIG_EXIT_LISTEN_PORT"
    FORWARD_TARGET="$ORIG_FORWARD_TARGET"
    SECURITY_LEVEL="$ORIG_SECURITY_LEVEL"
    TLS_SERVER_NAME="$ORIG_TLS_SERVER_NAME"
    TLS_CERT_PATH="$ORIG_TLS_CERT_PATH"
    TLS_KEY_PATH="$ORIG_TLS_KEY_PATH"

    echo ""

    echo -e "${BLUE}正在规则排序...${NC}"
    if reorder_rule_ids; then
        echo -e "${GREEN}✓ 规则排序优化完成${NC}"
    fi

    return 0
}

delete_rule() {
    local rule_id="$1"
    local skip_confirm="${2:-false}"
    local rule_file="${RULES_DIR}/rule-${rule_id}.conf"

    if [ ! -f "$rule_file" ]; then
        echo -e "${RED}错误: 规则 $rule_id 不存在${NC}"
        return 1
    fi

    if read_rule_file "$rule_file"; then
        if [ "$skip_confirm" != "true" ]; then
            echo -e "${YELLOW}即将删除规则:${NC}"
            echo -e "${BLUE}规则ID: ${GREEN}$RULE_ID${NC}"
            echo -e "${BLUE}规则名称: ${GREEN}$RULE_NAME${NC}"
            echo -e "${BLUE}监听端口: ${GREEN}$LISTEN_PORT${NC}"
            echo ""

            read -p "确认删除此规则？(y/n): " confirm
            if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
                echo "删除已取消"
                return 1
            fi
        fi

        if rm -f "$rule_file"; then
            echo -e "${GREEN}✓ 规则 $rule_id 已删除${NC}"

            if [ "$skip_confirm" != "true" ]; then
                echo -e "${BLUE}正在规则排序...${NC}"
                if reorder_rule_ids; then
                    echo -e "${GREEN}✓ 规则排序优化完成${NC}"
                fi
            fi

            return 0
        else
            echo -e "${RED}✗ 规则 $rule_id 删除失败${NC}"
            return 1
        fi
    else
        echo -e "${RED}错误: 无法读取规则文件${NC}"
        return 1
    fi
}

batch_delete_rules() {
    local rule_ids="$1"

    local validation_result=$(validate_rule_ids "$rule_ids")
    IFS='|' read -r valid_count invalid_count valid_ids invalid_ids <<< "$validation_result"

    if [ "$invalid_count" -gt 0 ]; then
        echo -e "${RED}错误: 以下规则ID无效或不存在: $invalid_ids${NC}"
        return 1
    fi

    if [ "$valid_count" -eq 0 ]; then
        echo -e "${RED}错误: 没有找到有效的规则ID${NC}"
        return 1
    fi

    local valid_ids_array
    IFS=' ' read -ra valid_ids_array <<< "$valid_ids"

    echo -e "${YELLOW}即将删除以下规则:${NC}"
    echo ""
    for id in "${valid_ids_array[@]}"; do
        local rule_file="${RULES_DIR}/rule-${id}.conf"
        if read_rule_file "$rule_file"; then
            echo -e "${BLUE}规则ID: ${GREEN}$RULE_ID${NC} | ${BLUE}规则名称: ${GREEN}$RULE_NAME${NC} | ${BLUE}监听端口: ${GREEN}$LISTEN_PORT${NC}"
        fi
    done
    echo ""

    read -p "确认删除以上 $valid_count 个规则？(y/n): " confirm
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        local deleted_count=0
        for id in "${valid_ids_array[@]}"; do
            if delete_rule "$id" "true"; then
                deleted_count=$((deleted_count + 1))
            fi
        done
        echo ""
        echo -e "${GREEN}批量删除完成，共删除 $deleted_count 个规则${NC}"

        echo -e "${BLUE}正在规则排序...${NC}"
        if reorder_rule_ids; then
            echo -e "${GREEN}✓ 规则排序优化完成${NC}"
        fi

        return 0
    else
        echo "批量删除已取消"
        return 1
    fi
}

toggle_rule() {
    local rule_id="$1"
    local rule_file="${RULES_DIR}/rule-${rule_id}.conf"

    if [ ! -f "$rule_file" ]; then
        echo -e "${RED}错误: 规则 $rule_id 不存在${NC}"
        return 1
    fi

    if read_rule_file "$rule_file"; then
        local new_status
        if [ "$ENABLED" = "true" ]; then
            new_status="false"
            echo -e "${YELLOW}正在禁用规则: $RULE_NAME${NC}"
        else
            new_status="true"
            echo -e "${YELLOW}正在启用规则: $RULE_NAME${NC}"
        fi

        sed -i "s/ENABLED=\".*\"/ENABLED=\"$new_status\"/" "$rule_file"

        if [ "$new_status" = "true" ]; then
            echo -e "${GREEN}✓ 规则已启用${NC}"
        else
            echo -e "${GREEN}✓ 规则已禁用${NC}"
        fi

        return 0
    else
        echo -e "${RED}错误: 无法读取规则文件${NC}"
        return 1
    fi
}

generate_export_metadata() {
    local metadata_file="$1"
    local rules_count="$2"

    cat > "$metadata_file" <<EOF
EXPORT_TIME=$(get_gmt8_time '+%Y-%m-%d %H:%M:%S')
SCRIPT_VERSION=$SCRIPT_VERSION
EXPORT_HOST=$(hostname 2>/dev/null || echo "unknown")
RULES_COUNT=$rules_count
HAS_MANAGER_CONF=$([ -f "$MANAGER_CONF" ] && echo "true" || echo "false")
HAS_HEALTH_STATUS=$([ -f "$HEALTH_STATUS_FILE" ] && echo "true" || echo "false")
PACKAGE_VERSION=1.0
EOF
}

export_config_package() {
    echo -e "${YELLOW}=== 导出配置包 ===${NC}"
    echo ""

    local rules_count=$(get_active_rules_count)

    local has_manager_conf=false
    [ -f "$MANAGER_CONF" ] && has_manager_conf=true

    if [ $rules_count -eq 0 ] && [ "$has_manager_conf" = false ]; then
        echo -e "${RED}没有可导出的配置数据${NC}"
        echo ""
        read -p "按回车键返回..."
        return 1
    fi

    echo -e "${BLUE}将要导出的完整配置：${NC}"
    echo -e "  转发规则: ${GREEN}$rules_count 条${NC}"
    [ "$has_manager_conf" = true ] && echo -e "  管理状态: ${GREEN}包含${NC}"
    [ -f "$HEALTH_STATUS_FILE" ] && echo -e "  健康监控: ${GREEN}包含${NC}"
    echo -e "  备注权重: ${GREEN}完整保留${NC}"
    echo ""

    read -p "确认导出配置包？(y/n): " confirm
    if ! echo "$confirm" | grep -qE "^[Yy]$"; then
        echo -e "${BLUE}已取消导出操作${NC}"
        read -p "按回车键返回..."
        return
    fi

    local export_dir="/usr/local/bin"
    local timestamp=$(get_gmt8_time '+%Y%m%d_%H%M%S')
    local export_filename="xwPF_config_${timestamp}.tar.gz"
    local export_path="${export_dir}/${export_filename}"

    local temp_dir=$(mktemp -d)
    local package_dir="${temp_dir}/xwPF_config"
    mkdir -p "$package_dir"

    echo ""
    echo -e "${YELLOW}正在收集配置数据...${NC}"

    generate_export_metadata "${package_dir}/metadata.txt" "$rules_count"

    if [ $rules_count -gt 0 ]; then
        mkdir -p "${package_dir}/rules"
        cp "${RULES_DIR}"/rule-*.conf "${package_dir}/rules/" 2>/dev/null
        echo -e "${GREEN}✓${NC} 已收集 $rules_count 个规则文件"
    fi

    if [ -f "$MANAGER_CONF" ]; then
        cp "$MANAGER_CONF" "${package_dir}/"
        echo -e "${GREEN}✓${NC} 已收集管理配置文件"
    fi

    if [ -f "$HEALTH_STATUS_FILE" ]; then
        cp "$HEALTH_STATUS_FILE" "${package_dir}/health_status.conf"
        echo -e "${GREEN}✓${NC} 已收集健康状态文件"
    fi

    local mptcp_conf="/etc/sysctl.d/90-enable-MPTCP.conf"
    if [ -f "$mptcp_conf" ]; then
        cp "$mptcp_conf" "${package_dir}/90-enable-MPTCP.conf"
        echo -e "${GREEN}✓${NC} 已收集MPTCP系统配置文件"
    fi

    # 导出运行时MPTCP端点配置，便于在新环境中快速恢复
    if command -v ip >/dev/null 2>&1 && /usr/bin/ip mptcp endpoint show >/dev/null 2>&1; then
        local endpoints_output=$(/usr/bin/ip mptcp endpoint show 2>/dev/null)
        if [ -n "$endpoints_output" ]; then
            echo "$endpoints_output" > "${package_dir}/mptcp_endpoints.conf"
            echo -e "${GREEN}✓${NC} 已收集MPTCP端点配置"
        fi
    fi

    echo -e "${YELLOW}正在创建压缩包...${NC}"
    cd "$temp_dir"
    if tar -czf "$export_path" xwPF_config/ >/dev/null 2>&1; then
        echo -e "${GREEN}✓ 配置包导出成功${NC}"
        echo ""
        echo -e "${BLUE}导出信息：${NC}"
        echo -e "  文件名: ${GREEN}$export_filename${NC}"
        echo -e "  路径: ${GREEN}$export_path${NC}"
        echo -e "  大小: ${GREEN}$(du -h "$export_path" 2>/dev/null | cut -f1)${NC}"
    else
        echo -e "${RED}✗ 配置包创建失败${NC}"
        rm -rf "$temp_dir"
        read -p "按回车键返回..."
        return 1
    fi

    rm -rf "$temp_dir"

    echo ""
    read -p "按回车键返回..."
}

export_config_with_view() {
    echo -e "${YELLOW}=== 查看配置文件 ===${NC}"
    echo -e "${BLUE}当前生效配置文件:${NC}"
    echo -e "${YELLOW}文件: $CONFIG_PATH${NC}"
    echo ""

    if [ -f "$CONFIG_PATH" ]; then
        cat "$CONFIG_PATH" | sed 's/^/  /'
    else
        echo -e "${RED}配置文件不存在${NC}"
    fi

    echo ""
    echo "是否一键导出当前全部文件架构？"
    echo -e "${GREEN}1.${NC}  一键导出为压缩包 "
    echo -e "${GREEN}0.${NC} 返回菜单"
    echo ""
    read -p "请输入选择 [0-1]: " export_choice
    echo ""

    case $export_choice in
        1)
            export_config_package
            ;;
        0)
            ;;
        *)
            echo -e "${RED}无效选择${NC}"
            read -p "按回车键继续..."
            ;;
    esac
}

# 简化验证逻辑，返回配置目录路径供后续使用
validate_config_package_content() {
    local package_file="$1"
    local temp_dir=$(mktemp -d)

    if ! tar -xzf "$package_file" -C "$temp_dir" >/dev/null 2>&1; then
        rm -rf "$temp_dir"
        return 1
    fi

    local config_dir=""
    for dir in "$temp_dir"/*; do
        if [ -d "$dir" ] && [ -f "$dir/metadata.txt" ]; then
            config_dir="$dir"
            break
        fi
    done

    if [ -z "$config_dir" ]; then
        rm -rf "$temp_dir"
        return 1
    fi

    echo "$config_dir"
    return 0
}

import_config_package() {
    echo -e "${YELLOW}=== 导入配置包 ===${NC}"
    echo ""

    read -p "请输入配置包的完整路径：" package_path
    echo ""

    if [ -z "$package_path" ]; then
        echo -e "${BLUE}已取消操作${NC}"
        read -p "按回车键返回..."
        return
    fi

    if [ ! -f "$package_path" ]; then
        echo -e "${RED}文件不存在: $package_path${NC}"
        read -p "按回车键返回..."
        return
    fi

    echo -e "${YELLOW}正在验证配置包...${NC}"
    local config_dir=$(validate_config_package_content "$package_path")
    if [ $? -ne 0 ] || [ -z "$config_dir" ]; then
        echo -e "${RED}无效的配置包文件${NC}"
        read -p "按回车键返回..."
        return
    fi

    local selected_filename=$(basename "$package_path")

    echo -e "${BLUE}配置包: ${GREEN}$selected_filename${NC}"

    if [ -f "${config_dir}/metadata.txt" ]; then
        source "${config_dir}/metadata.txt"
        echo -e "${BLUE}配置包信息：${NC}"
        echo -e "  导出时间: ${GREEN}$EXPORT_TIME${NC}"
        echo -e "  脚本版本: ${GREEN}$SCRIPT_VERSION${NC}"
        echo -e "  规则数量: ${GREEN}$RULES_COUNT${NC}"
        echo ""
    fi

    local current_rules=$(get_active_rules_count)

    echo -e "${YELLOW}当前规则数量: $current_rules${NC}"
    echo -e "${YELLOW}即将导入规则: $RULES_COUNT${NC}"
    echo ""
    echo -e "${RED}警告: 导入操作将覆盖所有现有配置！${NC}"
    echo ""

    read -p "确认导入配置包？(y/n): " confirm
    if ! echo "$confirm" | grep -qE "^[Yy]$"; then
        echo -e "${BLUE}已取消导入操作${NC}"
        rm -rf "$(dirname "$config_dir")"
        read -p "按回车键返回..."
        return
    fi

    echo ""
    echo -e "${YELLOW}正在导入配置...${NC}"

    echo -e "${BLUE}正在清理现有配置...${NC}"
    if [ -d "$RULES_DIR" ]; then
        rm -f "${RULES_DIR}"/rule-*.conf 2>/dev/null
    fi
    rm -f "$MANAGER_CONF" 2>/dev/null
    rm -f "$HEALTH_STATUS_FILE" 2>/dev/null

    init_rules_dir

    local imported_count=0

    if [ -d "${config_dir}/rules" ]; then
        for rule_file in "${config_dir}/rules"/rule-*.conf; do
            if [ -f "$rule_file" ]; then
                local rule_name=$(basename "$rule_file")
                cp "$rule_file" "${RULES_DIR}/"
                imported_count=$((imported_count + 1))
                echo -e "${GREEN}✓${NC} 恢复规则文件: $rule_name"
            fi
        done
    fi

    if [ -f "${config_dir}/manager.conf" ]; then
        cp "${config_dir}/manager.conf" "$MANAGER_CONF"
        echo -e "${GREEN}✓${NC} 恢复管理配置文件"
    fi

    if [ -f "${config_dir}/health_status.conf" ]; then
        cp "${config_dir}/health_status.conf" "$HEALTH_STATUS_FILE"
        echo -e "${GREEN}✓${NC} 恢复健康状态文件"
    fi

    if [ -f "${config_dir}/90-enable-MPTCP.conf" ]; then
        local mptcp_conf="/etc/sysctl.d/90-enable-MPTCP.conf"
        cp "${config_dir}/90-enable-MPTCP.conf" "$mptcp_conf"
        echo -e "${GREEN}✓${NC} 恢复MPTCP系统配置文件"
        sysctl -p "$mptcp_conf" >/dev/null 2>&1
    fi

    # 精确解析MPTCP端点配置格式，支持三种端点模式
    if [ -f "${config_dir}/mptcp_endpoints.conf" ] && command -v ip >/dev/null 2>&1; then
        echo -e "${YELLOW}正在恢复MPTCP端点配置...${NC}"
        /usr/bin/ip mptcp endpoint flush 2>/dev/null

        while IFS= read -r line; do
            if [ -n "$line" ]; then
                local addr=$(echo "$line" | awk '{print $1}')
                local dev=$(echo "$line" | awk '/dev/ {for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}')

                local flags=""
                if echo "$line" | grep -q "subflow.*fullmesh"; then
                    flags="subflow fullmesh"
                elif echo "$line" | grep -q "subflow.*backup"; then
                    flags="subflow backup"
                elif echo "$line" | grep -q "signal"; then
                    flags="signal"
                fi

                if [ -n "$addr" ] && [ -n "$dev" ] && [ -n "$flags" ]; then
                    /usr/bin/ip mptcp endpoint add "$addr" dev "$dev" $flags 2>/dev/null
                fi
            fi
        done < "${config_dir}/mptcp_endpoints.conf"
        echo -e "${GREEN}✓${NC} 恢复MPTCP端点配置"
    fi

    rm -rf "$(dirname "$config_dir")"

    if [ $imported_count -gt 0 ]; then
        echo -e "${GREEN}✓ 配置导入成功，共恢复 $imported_count 个规则${NC}"
        echo ""
        echo -e "${YELLOW}正在重启服务以应用新配置...${NC}"
        service_restart
        echo ""
        echo -e "${GREEN}配置导入完成！${NC}"
    else
        echo -e "${RED}✗ 配置导入失败${NC}"
    fi

    echo ""
    read -p "按回车键返回..."
}

# 确保每次使用最新版本的OCR脚本，避免功能滞后
download_realm_ocr_script() {
    local script_url="https://raw.githubusercontent.com/zywe03/realm-xwPF/main/xw_realm_OCR.sh"
    local target_path="/etc/realm/xw_realm_OCR.sh"

    echo -e "${GREEN}正在下载最新realm配置识别脚本...${NC}"

    mkdir -p "$(dirname "$target_path")"

    if download_from_sources "$script_url" "$target_path"; then
        chmod +x "$target_path"
        return 0
    else
        echo -e "${RED}请检查网络连接${NC}"
        return 1
    fi
}

import_realm_config() {
    local ocr_script="/etc/realm/xw_realm_OCR.sh"

    if ! download_realm_ocr_script; then
        echo -e "${RED}无法下载配置识别脚本，功能暂时不可用${NC}"
        read -p "按回车键返回..."
        return 1
    fi

    bash "$ocr_script" "$RULES_DIR"

    echo ""
    read -p "按回车键返回..."
}

rules_management_menu() {
    while true; do
        clear
        echo -e "${GREEN}=== 转发配置管理 ===${NC}"
        echo ""

        local status=$(systemctl is-active realm 2>/dev/null)
        if [ "$status" = "active" ]; then
            echo -e "服务状态: ${GREEN}●${NC} 运行中"
        else
            echo -e "服务状态: ${RED}●${NC} 已停止"
        fi

        local enabled_count=0
        local disabled_count=0
        if [ -d "$RULES_DIR" ]; then
            for rule_file in "${RULES_DIR}"/rule-*.conf; do
                if [ -f "$rule_file" ]; then
                    if read_rule_file "$rule_file"; then
                        if [ "$ENABLED" = "true" ]; then
                            enabled_count=$((enabled_count + 1))
                        else
                            disabled_count=$((disabled_count + 1))
                        fi
                    fi
                fi
            done
        fi

        if [ "$enabled_count" -gt 0 ] || [ "$disabled_count" -gt 0 ]; then
            local total_count=$((enabled_count + disabled_count))
            echo -e "配置模式: ${GREEN}多规则模式${NC} (${GREEN}$enabled_count${NC} 启用 / ${YELLOW}$disabled_count${NC} 禁用 / 共 $total_count 个)"

            if [ "$enabled_count" -gt 0 ]; then
                local has_relay_rules=false
                local relay_count=0
                for rule_file in "${RULES_DIR}"/rule-*.conf; do
                    if [ -f "$rule_file" ]; then
                        if read_rule_file "$rule_file" && [ "$ENABLED" = "true" ] && [ "$RULE_ROLE" = "1" ]; then
                            if [ "$has_relay_rules" = false ]; then
                                echo -e "${GREEN}中转服务器:${NC}"
                                has_relay_rules=true
                            fi
                            relay_count=$((relay_count + 1))
                            local security_display=$(get_security_display "$SECURITY_LEVEL" "$WS_PATH" "$WS_HOST")
                            local display_target=$(smart_display_target "$REMOTE_HOST")
                            local rule_display_name="$RULE_NAME"
                            local display_ip="${NAT_LISTEN_IP:-::}"
                            local through_display="${THROUGH_IP:-::}"
                            echo -e "  • ${GREEN}$rule_display_name${NC}: ${LISTEN_IP:-$display_ip}:$LISTEN_PORT → $through_display → $display_target:$REMOTE_PORT"
                            local note_display=""
                            if [ -n "$RULE_NOTE" ]; then
                                note_display=" | 备注: ${GREEN}$RULE_NOTE${NC}"
                            fi
                            get_rule_status_display "$security_display" "$note_display"

                        fi
                    fi
                done

                local has_exit_rules=false
                local exit_count=0
                for rule_file in "${RULES_DIR}"/rule-*.conf; do
                    if [ -f "$rule_file" ]; then
                        if read_rule_file "$rule_file" && [ "$ENABLED" = "true" ] && [ "$RULE_ROLE" = "2" ]; then
                            if [ "$has_exit_rules" = false ]; then
                                if [ "$has_relay_rules" = true ]; then
                                    echo ""
                                fi
                                echo -e "${GREEN}落地服务器 (双端Realm架构):${NC}"
                                has_exit_rules=true
                            fi
                            exit_count=$((exit_count + 1))
                            local security_display=$(get_security_display "$SECURITY_LEVEL" "$WS_PATH" "$WS_HOST")
                            # 落地服务器使用FORWARD_TARGET而不是REMOTE_HOST
                            local target_host="${FORWARD_TARGET%:*}"
                            local target_port="${FORWARD_TARGET##*:}"
                            local display_target=$(smart_display_target "$target_host")
                            local rule_display_name="$RULE_NAME"
                            local display_ip="::"
                            echo -e "  • ${GREEN}$rule_display_name${NC}: ${LISTEN_IP:-$display_ip}:$LISTEN_PORT → $display_target:$target_port"
                            local note_display=""
                            if [ -n "$RULE_NOTE" ]; then
                                note_display=" | 备注: ${GREEN}$RULE_NOTE${NC}"
                            fi
                            get_rule_status_display "$security_display" "$note_display"

                        fi
                    fi
                done
            fi

            if [ "$disabled_count" -gt 0 ]; then
                echo -e "${YELLOW}禁用的规则:${NC}"
                for rule_file in "${RULES_DIR}"/rule-*.conf; do
                    if [ -f "$rule_file" ]; then
                        if read_rule_file "$rule_file" && [ "$ENABLED" = "false" ]; then
                            if [ "$RULE_ROLE" = "2" ]; then
                                local target_host="${FORWARD_TARGET%:*}"
                                local target_port="${FORWARD_TARGET##*:}"
                                local display_target=$(smart_display_target "$target_host")
                                echo -e "  • ${GRAY}$RULE_NAME${NC}: $LISTEN_PORT → $display_target:$target_port (已禁用)"
                            else
                                local display_target=$(smart_display_target "$REMOTE_HOST")
                                local through_display="${THROUGH_IP:-::}"
                                echo -e "  • ${GRAY}$RULE_NAME${NC}: $LISTEN_PORT → $through_display → $display_target:$REMOTE_PORT (已禁用)"
                            fi
                        fi
                    fi
                done
            fi
        else
            echo -e "配置模式: ${BLUE}暂无配置${NC}"
        fi
        echo ""

        echo "请选择操作:"
        echo -e "${GREEN}1.${NC} 一键导出/导入配置"
        echo -e "${GREEN}2.${NC} 添加新配置"
        echo -e "${GREEN}3.${NC} 编辑现有规则"
        echo -e "${GREEN}4.${NC} 删除配置"
        echo -e "${GREEN}5.${NC} 启用/禁用中转规则"
        echo -e "${BLUE}6.${NC} 负载均衡管理"
        echo -e "${YELLOW}7.${NC} 开启/关闭 MPTCP"
        echo -e "${CYAN}8.${NC} 开启/关闭 Proxy Protocol"
        echo -e "${GREEN}0.${NC} 返回主菜单"
        echo ""

        read -p "请输入选择 [0-8]: " choice
        echo ""

        case $choice in
            1)
                while true; do
                    clear
                    echo -e "${GREEN}=== 配置文件管理 ===${NC}"
                    echo ""
                    echo "请选择操作:"
                    echo -e "${GREEN}1.${NC} 导出配置包(包含查看配置)"
                    echo -e "${GREEN}2.${NC} 导入配置包"
                    echo -e "${GREEN}3.${NC} 识别realm配置文件并导入"
                    echo -e "${GREEN}0.${NC} 返回上级菜单"
                    echo ""
                    read -p "请输入选择 [0-3]: " sub_choice
                    echo ""

                    case $sub_choice in
                        1)
                            export_config_with_view
                            ;;
                        2)
                            import_config_package
                            ;;
                        3)
                            import_realm_config
                            ;;
                        0)
                            break
                            ;;
                        *)
                            echo -e "${RED}无效选择，请重新输入${NC}"
                            read -p "按回车键继续..."
                            ;;
                    esac
                done
                ;;
            2)
                interactive_add_rule
                if [ $? -eq 0 ]; then
                    echo -e "${YELLOW}正在重启服务以应用新配置...${NC}"
                    service_restart
                fi
                read -p "按回车键继续..."
                ;;
            3)
                edit_rule_interactive
                ;;
            4)
                echo -e "${YELLOW}=== 删除配置 ===${NC}"
                echo ""
                if list_rules_with_info "management"; then
                    echo ""
                    read -p "请输入要删除的规则ID(多ID使用逗号,分隔): " rule_input

                    if [ -z "$rule_input" ]; then
                        echo -e "${RED}错误: 请输入规则ID${NC}"
                    else
                        if [[ "$rule_input" == *","* ]]; then
                            batch_delete_rules "$rule_input"
                        else
                            if [[ "$rule_input" =~ ^[0-9]+$ ]]; then
                                delete_rule "$rule_input"
                            else
                                echo -e "${RED}无效的规则ID${NC}"
                            fi
                        fi

                        if [ $? -eq 0 ]; then
                            echo -e "${YELLOW}正在重启服务以应用配置更改...${NC}"
                            service_restart
                        fi
                    fi
                fi
                read -p "按回车键继续..."
                ;;
            5)
                echo -e "${YELLOW}=== 启用/禁用中转规则 ===${NC}"
                echo ""
                if list_rules_with_info "management"; then
                    echo ""
                    read -p "请输入要切换状态的规则ID: " rule_id
                    if [[ "$rule_id" =~ ^[0-9]+$ ]]; then
                        toggle_rule "$rule_id"
                        if [ $? -eq 0 ]; then
                            echo -e "${YELLOW}正在重启服务以应用状态更改...${NC}"
                            service_restart
                        fi
                    else
                        echo -e "${RED}无效的规则ID${NC}"
                    fi
                fi
                read -p "按回车键继续..."
                ;;
            6)
                load_balance_management_menu
                ;;
            7)
                mptcp_management_menu
                ;;
            8)
                proxy_management_menu
                ;;
            0)
                break
                ;;
            *)
                echo -e "${RED}无效选择，请输入 0-8${NC}"
                read -p "按回车键继续..."
                ;;
        esac
    done
}

# 内核版本检查，确保MPTCP功能可用性
check_mptcp_support() {
    local kernel_version=$(uname -r | cut -d. -f1,2)
    local major=$(echo $kernel_version | cut -d. -f1)
    local minor=$(echo $kernel_version | cut -d. -f2)

    if [ "$major" -lt 5 ] || ([ "$major" -eq 5 ] && [ "$minor" -le 6 ]); then
        return 1
    fi

    if [ -f "/proc/sys/net/mptcp/enabled" ]; then
        local enabled=$(cat /proc/sys/net/mptcp/enabled 2>/dev/null)
        [ "$enabled" = "1" ]
    else
        return 1
    fi
}

enable_mptcp() {
    echo -e "${BLUE}正在启用MPTCP并进行配置...${NC}"
    echo ""

    echo -e "${YELLOW}步骤1: 检查并升级iproute2包...${NC}"
    upgrade_iproute2_for_mptcp

    echo -e "${YELLOW}步骤2: 启用系统MPTCP...${NC}"
    local mptcp_conf="/etc/sysctl.d/90-enable-MPTCP.conf"

    cat > "$mptcp_conf" << EOF
# MPTCP基础配置
net.mptcp.enabled=1

# 强制使用内核路径管理器
net.mptcp.pm_type=0

# 优化反向路径过滤
net.ipv4.conf.all.rp_filter=2
net.ipv4.conf.default.rp_filter=2
EOF

    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ MPTCP配置文件已创建: $mptcp_conf${NC}"

        if sysctl -p "$mptcp_conf" >/dev/null 2>&1; then
            echo -e "${GREEN}✓ MPTCP已成功启用并保存生效${NC}"
        else
            echo -e "${YELLOW}配置文件已创建，但立即应用失败${NC}"
            echo -e "${YELLOW}请手动执行: sysctl -p $mptcp_conf${NC}"
            return 1
        fi
    else
        echo -e "${RED}错误: 无法创建MPTCP配置文件${NC}"
        return 1
    fi

    echo -e "${YELLOW}步骤3: 优化MPTCP系统参数...${NC}"

    if sysctl -w net.mptcp.pm_type=0 >/dev/null 2>&1; then
        echo -e "${GREEN}✓ 已切换到内核路径管理器${NC}"
    else
        echo -e "${YELLOW}⚠ 无法设置路径管理器类型${NC}"
    fi

    # 避免mptcpd服务与内核路径管理器冲突
    if systemctl is-active mptcpd >/dev/null 2>&1; then
        echo -e "${YELLOW}检测到mptcpd服务，正在停止...${NC}"
        systemctl stop mptcpd 2>/dev/null || true
        systemctl disable mptcpd 2>/dev/null || true
        echo -e "${GREEN}✓ 已停止mptcpd服务${NC}"
    fi

    sysctl -w net.ipv4.conf.all.rp_filter=2 >/dev/null 2>&1
    sysctl -w net.ipv4.conf.default.rp_filter=2 >/dev/null 2>&1
    echo -e "${GREEN}✓ 已优化反向路径过滤设置${NC}"

    if /usr/bin/ip mptcp limits set subflows 8 add_addr_accepted 8 2>/dev/null; then
        echo -e "${GREEN}✓ MPTCP连接限制已设置为最大值 (subflows=8, add_addr_accepted=8)${NC}"
    else
        echo -e "${YELLOW}⚠ 无法设置MPTCP连接限制，使用默认值 (subflows=2, add_addr_accepted=0)${NC}"
    fi

    echo ""
    echo -e "${GREEN}✓ MPTCP基础配置完成！${NC}"
    echo -e "${BLUE}配置将自动加载${NC}"
    return 0
}

# 确保iproute2版本支持MPTCP功能
upgrade_iproute2_for_mptcp() {
    local current_version=$(/usr/bin/ip -V 2>/dev/null | grep -oP 'iproute2-\K[^,\s]+' || echo "unknown")
    echo -e "${BLUE}当前iproute2版本: $current_version${NC}"

    local mptcp_help_output=$(/usr/bin/ip mptcp help 2>&1)
    if echo "$mptcp_help_output" | grep -q "endpoint\|limits"; then
        echo -e "${GREEN}✓ 当前版本已支持MPTCP${NC}"
        return 0
    fi

    echo -e "${YELLOW}当前版本不支持MPTCP，开始升级...${NC}"

    echo -e "${BLUE}正在使用包管理器升级...${NC}"
    local apt_output
    apt_output=$(apt update 2>&1 && apt install -y iproute2 2>&1)

    local mptcp_help_output=$(/usr/bin/ip mptcp help 2>&1)
    if [ $? -eq 0 ] && echo "$mptcp_help_output" | grep -q "endpoint\|limits"; then
        echo -e "${GREEN}✓ 升级成功，MPTCP现在可用${NC}"
        return 0
    else
        echo -e "${YELLOW}⚠ 升级后仍不支持MPTCP${NC}"
        echo -e "${YELLOW}当前系统版本过低，请尝试手动更新iproute2${NC}"
        return 1
    fi
}

disable_mptcp() {
    echo -e "${BLUE}正在禁用MPTCP并清理配置...${NC}"
    echo ""

    echo -e "${YELLOW}步骤1: 清理MPTCP端点...${NC}"
    if /usr/bin/ip mptcp endpoint show >/dev/null 2>&1; then
        local endpoints_output=$(/usr/bin/ip mptcp endpoint show 2>/dev/null)
        if [ -n "$endpoints_output" ]; then
            /usr/bin/ip mptcp endpoint flush 2>/dev/null
            echo -e "${GREEN}✓ 已清理所有MPTCP端点${NC}"
        else
            echo -e "${BLUE}  无MPTCP端点需要清理${NC}"
        fi
    else
        echo -e "${YELLOW}⚠ ip mptcp命令不可用，跳过端点清理${NC}"
    fi

    echo -e "${YELLOW}步骤2: 禁用系统MPTCP...${NC}"
    if echo 0 > /proc/sys/net/mptcp/enabled 2>/dev/null; then
        echo -e "${GREEN}✓ MPTCP已立即禁用${NC}"
    else
        echo -e "${YELLOW}立即禁用MPTCP失败，但将删除配置文件${NC}"
    fi

    echo -e "${YELLOW}步骤3: 删除配置文件...${NC}"
    local mptcp_conf="/etc/sysctl.d/90-enable-MPTCP.conf"
    if [ -f "$mptcp_conf" ]; then
        if rm -f "$mptcp_conf" 2>/dev/null; then
            echo -e "${GREEN}✓ MPTCP配置文件已删除${NC}"
        else
            echo -e "${YELLOW}无法删除配置文件: $mptcp_conf${NC}"
            echo -e "${YELLOW}请手动删除以防止重启后自动启用${NC}"
        fi
    else
        echo -e "${BLUE}  无配置文件需要删除${NC}"
    fi

    echo ""
    echo -e "${GREEN}✓ MPTCP已完全禁用！${NC}"
    echo -e "${BLUE}重启后MPTCP将保持禁用状态,恢复TCP${NC}"
    return 0
}

get_mptcp_mode_display() {
    local mode="$1"
    case "$mode" in
        "off")
            echo "关闭"
            ;;
        "send")
            echo "发送"
            ;;
        "accept")
            echo "接收"
            ;;
        "both")
            echo "双向"
            ;;
        *)
            echo "关闭"
            ;;
    esac
}

get_mptcp_mode_color() {
    local mode="$1"
    case "$mode" in
        "off")
            echo "${WHITE}"
            ;;
        "send")
            echo "${BLUE}"
            ;;
        "accept")
            echo "${YELLOW}"
            ;;
        "both")
            echo "${GREEN}"
            ;;
        *)
            echo "${WHITE}"
            ;;
    esac
}

get_network_interfaces_detailed() {
    local interfaces_info=""

    for interface in $(ip link show | grep -E '^[0-9]+:' | cut -d: -f2 | tr -d ' ' | grep -v lo); do
        local ipv4_info=""
        local ipv6_info=""

        local ipv4_addrs=$(ip -4 addr show "$interface" 2>/dev/null | grep -oP 'inet \K[^/]+/[0-9]+' | head -1)
        if [ -n "$ipv4_addrs" ]; then
            ipv4_info="$ipv4_addrs (IPv4)"
        else
            ipv4_info="未配置IPv4"
        fi

        local ipv6_addrs=$(ip -6 addr show "$interface" 2>/dev/null | grep -oP 'inet6 \K[^/]+/[0-9]+' | grep -v '^fe80:' | head -1)
        if [ -n "$ipv6_addrs" ]; then
            ipv6_info="$ipv6_addrs (IPv6)"
        else
            ipv6_info="未配置IPv6"
        fi

        local vlan_info=""
        if [[ "$interface" == *"."* ]]; then
            vlan_info=" (VLAN)"
        fi

        interfaces_info="${interfaces_info}  网卡 $interface: $ipv4_info | $ipv6_info$vlan_info\n"
    done

    echo -e "$interfaces_info"
}

get_mptcp_endpoints_status() {
    local endpoints_output=$(/usr/bin/ip mptcp endpoint show 2>/dev/null)
    local endpoint_count=0
    local endpoints_info=""

    if [ -n "$endpoints_output" ]; then
        while IFS= read -r line; do
            if [ -n "$line" ]; then
                endpoint_count=$((endpoint_count + 1))
                local id=$(echo "$line" | grep -oP 'id \K[0-9]+' || echo "")
                local addr=$(echo "$line" | grep -oP '^[^ ]+' || echo "")
                local dev=$(echo "$line" | grep -oP 'dev \K[^ ]+' || echo "")
                # 解析MPTCP端点类型：脚本支持的三种模式
                local flags=""
                if echo "$line" | grep -q "subflow.*fullmesh"; then
                    flags="[subflow fullmesh]"
                elif echo "$line" | grep -q "subflow.*backup"; then
                    flags="[subflow backup]"
                elif echo "$line" | grep -q "signal"; then
                    flags="[signal]"
                else
                    flags="[unknown]"
                fi

                if [ -n "$addr" ]; then
                    endpoints_info="${endpoints_info}  ID $id: $addr dev $dev $flags\n"
                fi
            fi
        done <<< "$endpoints_output"
    fi

    echo -e "${BLUE}MPTCP端点配置:${NC}"
    if [ $endpoint_count -gt 0 ]; then
        echo -e "$endpoints_info"
    else
        echo -e "  ${YELLOW}暂无MPTCP端点配置${NC}"
    fi

    return $endpoint_count
}

get_mptcp_connections_stats() {
    local ss_output=$(ss -M 2>/dev/null)
    local mptcp_connections=0
    local subflows=0

    if [ -n "$ss_output" ]; then
        mptcp_connections=$(echo "$ss_output" | grep -c ESTAB 2>/dev/null)

        # 统计子流数量 (总行数减1，最少为0)
        local total_lines=$(echo "$ss_output" | wc -l)
        subflows=$(( total_lines > 1 ? total_lines - 1 : 0 ))
    fi

    if [ "$mptcp_connections" -eq 0 ] && [ "$subflows" -eq 0 ]; then
        echo "活跃连接: 0个 | 子流: 0个 (无连接时为0正常现象)"
    else
        echo "活跃连接: ${mptcp_connections}个 | 子流: ${subflows}个"
    fi
}

# MPTCP管理主菜单
mptcp_management_menu() {
    # 初始化MPTCP字段（确保向后兼容）
    init_mptcp_fields

    while true; do
        clear
        echo -e "${GREEN}=== MPTCP 管理 ===${NC}"
        echo ""

        if ! check_mptcp_support; then
            local kernel_version=$(uname -r)
            local kernel_major=$(echo $kernel_version | cut -d. -f1)
            local kernel_minor=$(echo $kernel_version | cut -d. -f2)

            echo -e "${RED}系统不支持MPTCP或未启用${NC}"
            echo ""
            echo -e "${YELLOW}MPTCP要求：${NC}"
            echo -e "  • Linux内核版本 > 5.6"
            echo -e "  • net.mptcp.enabled=1"
            echo ""

            echo -e "${BLUE}当前内核版本: ${GREEN}$kernel_version${NC}"

            if [ "$kernel_major" -lt 5 ] || ([ "$kernel_major" -eq 5 ] && [ "$kernel_minor" -le 6 ]); then
                echo -e "${RED}✗ 内核版本不支持MPTCP${NC}(需要 > 5.6)"
            else
                echo -e "${GREEN}✓ 内核版本支持MPTCP${NC}"
            fi

            if [ -f "/proc/sys/net/mptcp/enabled" ]; then
                local enabled=$(cat /proc/sys/net/mptcp/enabled 2>/dev/null)
                if [ "$enabled" = "1" ]; then
                    echo -e "${GREEN}✓ MPTCP已启用${NC}(net.mptcp.enabled=$enabled)"
                else
                    echo -e "${RED}✗ MPTCP未启用${NC}(net.mptcp.enabled=$enabled，需要为1)"
                fi
            else
                echo -e "${RED}✗ 系统不支持MPTCP${NC}(/proc/sys/net/mptcp/enabled 不存在)"
            fi

            echo ""
            read -p "是否尝试启用MPTCP? [y/N]: " enable_choice
            if [[ "$enable_choice" =~ ^[Yy]$ ]]; then
                enable_mptcp
            fi
            echo ""
            read -p "按回车键返回..."
            return
        fi

        local current_status=$(cat /proc/sys/net/mptcp/enabled 2>/dev/null)
        local config_file="/etc/sysctl.d/90-enable-MPTCP.conf"

        echo -e "${GREEN}✓ 系统支持MPTCP${NC}(net.mptcp.enabled=$current_status)"

        if [ "$current_status" = "1" ]; then
            if [ -f "$config_file" ]; then
                echo -e "${GREEN}✓ 系统已开启MPTCP${NC}(MPTCP配置已设置)"
            else
                echo -e "${YELLOW}⚠ 系统已开启MPTCP${NC}(临时开启，重启后可能失效)"
                echo ""
                read -p "是否保存为配置文件重启依旧生效？[y/N]: " save_config
                if [[ "$save_config" =~ ^[Yy]$ ]]; then
                    if echo "net.mptcp.enabled=1" > "$config_file" 2>/dev/null; then
                        echo -e "${GREEN}✓ MPTCP配置已保存: $config_file${NC}"

                        if sysctl -p "$config_file" >/dev/null 2>&1; then
                            echo -e "${GREEN}✓ 配置已立即生效，重启后自动加载${NC}"
                        else
                            echo -e "${YELLOW}配置文件已保存，但立即应用失败${NC}"
                            echo -e "${BLUE}手动应用配置: sysctl -p $config_file${NC}"
                        fi
                        echo ""
                        read -p "按回车键刷新状态显示..."
                        continue
                    else
                        echo -e "${RED}✗ 保存MPTCP配置失败${NC}"
                        echo -e "${YELLOW}请手动执行: echo 'net.mptcp.enabled=1' > $config_file${NC}"
                    fi
                fi
            fi
        else
            echo -e "${RED}✗ 系统未开启MPTCP${NC}(当前为普通TCP模式)"
        fi
        echo ""

        echo -e "${BLUE}网络环境状态:${NC}"
        get_network_interfaces_detailed
        echo ""

        get_mptcp_endpoints_status
        local connections_stats=$(get_mptcp_connections_stats)
        echo -e "${BLUE}MPTCP连接统计:${NC}"
        echo -e "  $connections_stats"
        echo ""

        if ! list_rules_with_info "mptcp"; then
            echo ""
            read -p "按回车键返回..."
            return
        fi

        echo ""
        echo -e "${RED}规则ID 0: 关闭系统MPTCP，回退普通TCP模式${NC}"
        echo -e "${BLUE}输入 add: 添加MPTCP端点 | del: 删除MPTCP端点 | look: 查看MPTCP详细状态${NC}"
        read -p "请输入要配置的规则ID(多ID使用逗号,分隔，0为关闭系统MPTCP): " rule_input
        if [ -z "$rule_input" ]; then
            return
        fi

        case "$rule_input" in
            "add")
                add_mptcp_endpoint_interactive
                read -p "按回车键继续..."
                continue
                ;;
            "del")
                delete_mptcp_endpoint_interactive
                read -p "按回车键继续..."
                continue
                ;;
            "look")
                show_mptcp_detailed_status
                read -p "按回车键继续..."
                continue
                ;;
        esac

        if [ "$rule_input" = "0" ]; then
            echo ""
            echo -e "${YELLOW}确认关闭系统MPTCP？这将影响所有MPTCP连接。${NC}"
            read -p "继续? [y/N]: " confirm
            if [[ "$confirm" =~ ^[Yy]$ ]]; then
                set_mptcp_mode "0" ""
            fi
            read -p "按回车键继续..."
            continue
        fi

        echo ""
        echo -e "${BLUE}请选择新的 MPTCP 模式:${NC}"
        echo -e "${WHITE}1.${NC} off (关闭)"
        echo -e "${BLUE}2.${NC} 仅发送"
        echo -e "${YELLOW}3.${NC} 仅接收"
        echo -e "${GREEN}4.${NC} 双向(发送+接收)"
        echo ""

        read -p "请选择MPTCP模式 [1-4]: " mode_choice
        if [ -z "$mode_choice" ]; then
            continue
        fi

        if [[ "$rule_input" == *","* ]]; then
            batch_set_mptcp_mode "$rule_input" "$mode_choice"
        else
            if [[ "$rule_input" =~ ^[0-9]+$ ]]; then
                set_mptcp_mode "$rule_input" "$mode_choice"
            else
                echo -e "${RED}无效的规则ID${NC}"
            fi
        fi
        read -p "按回车键继续..."
    done
}

batch_set_mptcp_mode() {
    local rule_ids="$1"
    local mode_choice="$2"

    local validation_result=$(validate_rule_ids "$rule_ids")
    IFS='|' read -r valid_count invalid_count valid_ids invalid_ids <<< "$validation_result"

    if [ "$invalid_count" -gt 0 ]; then
        echo -e "${RED}错误: 以下规则ID无效或不存在: $invalid_ids${NC}"
        return 1
    fi

    if [ "$valid_count" -eq 0 ]; then
        echo -e "${RED}错误: 没有找到有效的规则ID${NC}"
        return 1
    fi

    local valid_ids_array
    IFS=' ' read -ra valid_ids_array <<< "$valid_ids"

    echo -e "${YELLOW}即将为以下规则设置MPTCP模式:${NC}"
    echo ""
    for id in "${valid_ids_array[@]}"; do
        local rule_file="${RULES_DIR}/rule-${id}.conf"
        if read_rule_file "$rule_file"; then
            echo -e "${BLUE}规则ID: ${GREEN}$RULE_ID${NC} | ${BLUE}规则名称: ${GREEN}$RULE_NAME${NC}"
        fi
    done
    echo ""

    read -p "确认为以上 $valid_count 个规则设置MPTCP模式？(y/n): " confirm
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        local success_count=0
        for id in "${valid_ids_array[@]}"; do
            if set_mptcp_mode "$id" "$mode_choice" "batch"; then
                success_count=$((success_count + 1))
            fi
        done

        if [ $success_count -gt 0 ]; then
            echo -e "${GREEN}✓ 成功设置 $success_count 个规则的MPTCP模式${NC}"
            echo -e "${YELLOW}正在重启服务以应用配置更改...${NC}"
            if service_restart; then
                echo -e "${GREEN}✓ 服务重启成功，MPTCP配置已生效${NC}"
            else
                echo -e "${RED}✗ 服务重启失败，请检查配置${NC}"
            fi
            return 0
        else
            echo -e "${RED}✗ 没有成功设置任何规则${NC}"
            return 1
        fi
    else
        echo -e "${YELLOW}操作已取消${NC}"
        return 1
    fi
}

set_mptcp_mode() {
    local rule_id="$1"
    local mode_choice="$2"
    local batch_mode="$3"

    # 特殊处理规则ID 0：关闭系统MPTCP
    if [ "$rule_id" = "0" ]; then
        echo -e "${YELLOW}正在关闭系统MPTCP...${NC}"
        disable_mptcp
        echo -e "${GREEN}✓ 系统MPTCP已关闭，所有连接将使用普通TCP模式${NC}"
        return 0
    fi

    local rule_file="${RULES_DIR}/rule-${rule_id}.conf"
    if [ ! -f "$rule_file" ]; then
        echo -e "${RED}错误: 规则 $rule_id 不存在${NC}"
        return 1
    fi

    if ! read_rule_file "$rule_file"; then
        echo -e "${RED}错误: 读取规则文件失败${NC}"
        return 1
    fi

    local new_mode
    case "$mode_choice" in
        "1")
            new_mode="off"
            ;;
        "2")
            new_mode="send"
            ;;
        "3")
            new_mode="accept"
            ;;
        "4")
            new_mode="both"
            ;;
        *)
            echo -e "${RED}无效的模式选择${NC}"
            return 1
            ;;
    esac

    local mode_display=$(get_mptcp_mode_display "$new_mode")
    local mode_color=$(get_mptcp_mode_color "$new_mode")

    if [ "$batch_mode" != "batch" ]; then
        echo -e "${YELLOW}正在为规则 '$RULE_NAME' 设置MPTCP模式为: ${mode_color}$mode_display${NC}"
    fi

    local temp_file="${rule_file}.tmp.$$"

    if grep -q "^MPTCP_MODE=" "$rule_file"; then
        grep -v "^MPTCP_MODE=" "$rule_file" > "$temp_file"
        echo "MPTCP_MODE=\"$new_mode\"" >> "$temp_file"
        mv "$temp_file" "$rule_file"
    else
        echo "MPTCP_MODE=\"$new_mode\"" >> "$rule_file"
    fi

    if [ $? -eq 0 ]; then
        if [ "$batch_mode" != "batch" ]; then
            echo -e "${GREEN}✓ MPTCP模式已更新为: ${mode_color}$mode_display${NC}"
        fi
        restart_and_confirm "MPTCP配置" "$batch_mode"
        return $?
    else
        if [ "$batch_mode" != "batch" ]; then
            echo -e "${RED}✗ 更新MPTCP模式失败${NC}"
        fi
        return 1
    fi
}



# 初始化所有规则文件的MPTCP字段（确保向后兼容）
init_mptcp_fields() {
    init_rule_field "MPTCP_MODE" "off"
}

add_mptcp_endpoint_interactive() {
    echo -e "${GREEN}=== 添加MPTCP端点 ===${NC}"
    echo ""

    echo -e "${BLUE}当前MPTCP端点:${NC}"
    get_mptcp_endpoints_status
    echo ""

    local interfaces=()
    local interface_names=()
    local interface_count=0

    for interface in $(ip link show | grep -E '^[0-9]+:' | cut -d: -f2 | tr -d ' ' | grep -v lo); do
        local ipv4_addrs=$(ip -4 addr show "$interface" 2>/dev/null | grep -oP 'inet \K[^/]+' | tr '\n' ' ')
        local ipv6_addrs=$(ip -6 addr show "$interface" 2>/dev/null | grep -oP 'inet6 \K[^/]+' | grep -v '^fe80:' | tr '\n' ' ')

        if [ -n "$ipv4_addrs" ] || [ -n "$ipv6_addrs" ]; then
            interface_count=$((interface_count + 1))
            interfaces+=("$interface")

            local display_info="$interface: "
            if [ -n "$ipv4_addrs" ]; then
                display_info="${display_info}${ipv4_addrs}(IPv4)"
            else
                display_info="${display_info}未配置IPv4"
            fi

            display_info="${display_info} | "

            if [ -n "$ipv6_addrs" ]; then
                display_info="${display_info}${ipv6_addrs}(IPv6)"
            else
                display_info="${display_info}未配置IPv6"
            fi

            interface_names+=("$display_info")
        fi
    done

    if [ $interface_count -eq 0 ]; then
        echo -e "${RED}未找到配置IP地址的网络接口${NC}"
        return 1
    fi

    echo -e "${BLUE}当前网络接口:${NC}"
    for i in $(seq 0 $((interface_count - 1))); do
        echo -e "${GREEN}$((i + 1)).${NC} ${interface_names[$i]}"
    done
    echo ""

    read -p "请选择网卡 [1-$interface_count]: " interface_choice
    if [[ ! "$interface_choice" =~ ^[0-9]+$ ]] || [ "$interface_choice" -lt 1 ] || [ "$interface_choice" -gt $interface_count ]; then
        echo -e "${RED}无效的选择${NC}"
        return 1
    fi

    local selected_interface="${interfaces[$((interface_choice - 1))]}"
    echo -e "${BLUE}已选择网卡: $selected_interface${NC}"
    echo ""

    local selected_ips=()
    local ip_display=()
    local ip_count=0

    local ipv4_list=$(ip -4 addr show "$selected_interface" 2>/dev/null | grep -oP 'inet \K[^/]+')
    if [ -n "$ipv4_list" ]; then
        while IFS= read -r ip; do
            if [ -n "$ip" ]; then
                ip_count=$((ip_count + 1))
                selected_ips+=("$ip")
                ip_display+=("$ip (IPv4)")
            fi
        done <<< "$ipv4_list"
    fi

    local ipv6_list=$(ip -6 addr show "$selected_interface" 2>/dev/null | grep -oP 'inet6 \K[^/]+' | grep -v '^fe80:')
    if [ -n "$ipv6_list" ]; then
        while IFS= read -r ip; do
            if [ -n "$ip" ]; then
                ip_count=$((ip_count + 1))
                selected_ips+=("$ip")
                ip_display+=("$ip (IPv6)")
            fi
        done <<< "$ipv6_list"
    fi

    if [ $ip_count -eq 0 ]; then
        echo -e "${RED}选中的网卡没有可用的IP地址${NC}"
        return 1
    fi

    echo -e "${BLUE}${selected_interface} 的可用IP地址:${NC}"
    for i in $(seq 0 $((ip_count - 1))); do
        echo -e "${GREEN}$((i + 1)).${NC} ${ip_display[$i]}"
    done
    echo ""

    read -p "请选择IP地址(回车默认全选): " ip_choice

    local selected_ip_list=()
    if [ -z "$ip_choice" ]; then
        selected_ip_list=("${selected_ips[@]}")
        echo -e "${BLUE}已选择全部IP地址${NC}"
    else
        if [[ ! "$ip_choice" =~ ^[0-9]+$ ]] || [ "$ip_choice" -lt 1 ] || [ "$ip_choice" -gt $ip_count ]; then
            echo -e "${RED}无效的选择${NC}"
            return 1
        fi
        selected_ip_list=("${selected_ips[$((ip_choice - 1))]}")
        echo -e "${BLUE}已选择IP地址: ${selected_ips[$((ip_choice - 1))]}${NC}"
    fi
    echo ""

    echo ""
    echo -e "${BLUE}请选择MPTCP端点类型:${NC}"
    echo ""
    echo -e "${YELLOW}建议:${NC}"
    echo -e "  • 中转机/客户端: 选择 subflow fullmesh"
    echo -e "  • 落地机/服务端: 选择 signal (可选)"
    echo -e "  • 备用路径: 选择 subflow backup (仅在主路径故障时使用)"
    echo ""
    echo -e "${GREEN}1.${NC} subflow fullmesh (客户端模式 - 全网格连接)"
    echo -e "${BLUE}2.${NC} signal (服务端模式 - 通告地址给客户端)"
    echo -e "${YELLOW}3.${NC} subflow backup (备用模式)"
    echo ""

    read -p "请选择端点类型(回车默认 1) [1-3]: " type_choice

    if [ -z "$type_choice" ]; then
        type_choice="1"
    fi

    local endpoint_type
    local type_description
    case "$type_choice" in
        "1")
            endpoint_type="subflow fullmesh"
            type_description="subflow fullmesh (全网格模式)"
            ;;
        "2")
            endpoint_type="signal"
            type_description="signal (服务端模式)"
            ;;
        "3")
            endpoint_type="subflow backup"
            type_description="subflow backup (备用模式)"
            ;;
        *)
            echo -e "${RED}无效的选择，请重新输入${NC}"
            return 1
            ;;
    esac

    echo -e "${YELLOW}正在添加MPTCP端点...${NC}"
    local success_count=0
    local total_count=${#selected_ip_list[@]}

    for ip_address in "${selected_ip_list[@]}"; do
        echo -e "${BLUE}执行命令: /usr/bin/ip mptcp endpoint add $ip_address dev $selected_interface $endpoint_type${NC}"

        local error_output
        error_output=$(/usr/bin/ip mptcp endpoint add "$ip_address" dev "$selected_interface" $endpoint_type 2>&1)
        local exit_code=$?

        if [ $exit_code -eq 0 ]; then
            echo -e "${GREEN}✓ MPTCP端点添加成功: $ip_address${NC}"
            success_count=$((success_count + 1))
        else
            echo -e "${RED}✗ MPTCP端点添加失败: $ip_address${NC}"
            echo -e "${RED}错误信息: $error_output${NC}"
        fi
    done

    echo ""
    echo -e "${BLUE}添加结果: 成功 $success_count/$total_count${NC}"
    echo -e "${BLUE}网络接口: $selected_interface${NC}"
    echo -e "${BLUE}端点模式: $type_description${NC}"

    if [ $success_count -gt 0 ]; then
        echo ""
        echo -e "${BLUE}更新后的MPTCP端点:${NC}"
        get_mptcp_endpoints_status
    else
        echo -e "${YELLOW}可能的原因:${NC}"
        echo -e "  • 系统过低导致iproute2版本不支持MPTCP"
        echo -e "  • IP地址已存在"
        echo -e "  • 网络接口配置问题"
    fi
}

delete_mptcp_endpoint_interactive() {
    echo -e "${GREEN}=== 删除MPTCP端点 ===${NC}"
    echo ""

    echo -e "${BLUE}当前MPTCP端点:${NC}"
    local endpoints_output=$(/usr/bin/ip mptcp endpoint show 2>/dev/null)

    if [ -z "$endpoints_output" ]; then
        echo -e "${YELLOW}暂无MPTCP端点配置${NC}"
        return 0
    fi

    local endpoint_count=0
    local endpoints_list=()

    while IFS= read -r line; do
        if [ -n "$line" ]; then
            endpoint_count=$((endpoint_count + 1))
            endpoints_list+=("$line")

            local id=$(echo "$line" | grep -oP 'id \K[0-9]+' || echo "")
            local addr=$(echo "$line" | grep -oP '^[^ ]+' || echo "")
            local dev=$(echo "$line" | grep -oP 'dev \K[^ ]+' || echo "")
            # 解析MPTCP端点类型：脚本支持的三种模式
            local flags=""
            if echo "$line" | grep -q "subflow.*fullmesh"; then
                flags="[subflow fullmesh]"
            elif echo "$line" | grep -q "subflow.*backup"; then
                flags="[subflow backup]"
            elif echo "$line" | grep -q "signal"; then
                flags="[signal]"
            else
                flags="[unknown]"
            fi

            echo -e "  ${endpoint_count}. ID $id: $addr dev $dev $flags"
        fi
    done <<< "$endpoints_output"

    if [ $endpoint_count -eq 0 ]; then
        echo -e "${YELLOW}暂无MPTCP端点配置${NC}"
        return 0
    fi

    echo ""
    read -p "请选择要删除的端点编号 [1-$endpoint_count]: " choice

    if ! [[ "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -lt 1 ] || [ "$choice" -gt $endpoint_count ]; then
        echo -e "${RED}无效的选择${NC}"
        return 1
    fi

    local selected_line="${endpoints_list[$((choice-1))]}"
    local endpoint_id=$(echo "$selected_line" | grep -oP 'id \K[0-9]+' || echo "")
    local endpoint_addr=$(echo "$selected_line" | grep -oP '^[^ ]+' || echo "")

    echo ""
    echo -e "${YELLOW}确认删除MPTCP端点:${NC}"
    echo -e "  ID: $endpoint_id"
    echo -e "  地址: $endpoint_addr"
    read -p "继续删除? [y/N]: " confirm

    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}正在删除MPTCP端点...${NC}"
        if /usr/bin/ip mptcp endpoint delete id "$endpoint_id" 2>/dev/null; then
            echo -e "${GREEN}✓ MPTCP端点删除成功${NC}"

            echo ""
            echo -e "${BLUE}更新后的MPTCP端点:${NC}"
            get_mptcp_endpoints_status
        else
            echo -e "${RED}✗ MPTCP端点删除失败${NC}"
            return 1
        fi
    else
        echo -e "${BLUE}已取消删除操作${NC}"
    fi
}

show_mptcp_detailed_status() {
    echo -e "${GREEN}=== MPTCP详细状态 ===${NC}"
    echo ""

    echo -e "${BLUE}系统MPTCP状态:${NC}"
    local mptcp_enabled=$(cat /proc/sys/net/mptcp/enabled 2>/dev/null || echo "0")
    if [ "$mptcp_enabled" = "1" ]; then
        echo -e "  ✓ MPTCP已启用 (net.mptcp.enabled=$mptcp_enabled)"
    else
        echo -e "  ✗ MPTCP未启用 (net.mptcp.enabled=$mptcp_enabled)"
    fi
    echo ""

    echo -e "${BLUE}MPTCP连接限制:${NC}"
    local limits_output=$(/usr/bin/ip mptcp limits show 2>/dev/null)
    if [ -n "$limits_output" ]; then
        echo "  $limits_output"
    else
        echo -e "  ${YELLOW}无法获取连接限制信息${NC}"
    fi
    echo ""

    echo -e "${BLUE}网络接口状态:${NC}"
    get_network_interfaces_detailed
    echo ""

    get_mptcp_endpoints_status
    echo ""

    echo -e "${BLUE}MPTCP连接统计:${NC}"
    local connections_stats=$(get_mptcp_connections_stats)
    echo -e "  $connections_stats"
    echo ""

    echo -e "${BLUE}活跃MPTCP连接详情:${NC}"
    local mptcp_connections=$(ss -M 2>/dev/null)
    if [ -n "$mptcp_connections" ] && [ "$(echo "$mptcp_connections" | wc -l)" -gt 1 ]; then
        echo "$mptcp_connections"
    else
        echo -e "  ${YELLOW}暂无活跃MPTCP连接${NC}"
    fi
    echo ""

    echo -e "${BLUE}实时MPTCP事件监控:${NC}"
    echo -e "${YELLOW}正在启动实时监控，按 Ctrl+C 退出...${NC}"
    echo ""
    ip mptcp monitor || echo -e "  ${YELLOW}MPTCP事件监控不可用${NC}"
}

get_proxy_mode_display() {
    local mode="$1"
    case "$mode" in
        "off")
            echo "关闭"
            ;;
        "v1_send")
            echo "v1发送"
            ;;
        "v1_accept")
            echo "v1接收"
            ;;
        "v1_both")
            echo "v1双向"
            ;;
        "v2_send")
            echo "v2发送"
            ;;
        "v2_accept")
            echo "v2接收"
            ;;
        "v2_both")
            echo "v2双向"
            ;;
        *)
            echo "关闭"
            ;;
    esac
}

get_proxy_mode_color() {
    local mode="$1"
    case "$mode" in
        "off")
            echo "${WHITE}"
            ;;
        "v1_send"|"v2_send")
            echo "${BLUE}"
            ;;
        "v1_accept"|"v2_accept")
            echo "${YELLOW}"
            ;;
        "v1_both"|"v2_both")
            echo "${GREEN}"
            ;;
        *)
            echo "${WHITE}"
            ;;
    esac
}

# 初始化所有规则文件的Proxy字段
init_proxy_fields() {
    init_rule_field "PROXY_MODE" "off"
}

proxy_management_menu() {
    init_proxy_fields

    while true; do
        clear
        echo -e "${GREEN}=== Proxy Protocol 管理 ===${NC}"
        echo ""

        local config_file="/etc/realm/config.json"
        local global_send_proxy=$(jq -r '.network.send_proxy // false' "$config_file" 2>/dev/null)
        if [ "$global_send_proxy" = "true" ]; then
            echo -e "${GREEN}全局[开启]${NC}"
        else
            echo -e "${RED}全局[关闭]${NC}"
        fi
        echo ""
        echo "当前规则列表(可单独开启或关闭覆盖全局):"
        echo ""

        if ! list_rules_with_info "proxy"; then
            echo ""
            read -p "按回车键返回..."
            return
        fi

        echo ""
        echo "多ID使用逗号,分隔"
        read -p "请输入要配置的规则ID（输入0切换全局状态）: " rule_input
        if [ -z "$rule_input" ]; then
            return
        fi

        # 处理全局状态切换（输入0）
        if [ "$rule_input" = "0" ]; then
            echo ""
            local config_file="/etc/realm/config.json"
            local current_status=$(jq -r '.network.send_proxy // false' "$config_file" 2>/dev/null)
            local temp_config=$(mktemp)

            if [ "$current_status" = "true" ]; then
                echo -e "${YELLOW}关闭全局Proxy Protocol...${NC}"
                jq 'del(.network.send_proxy) |
                    del(.network.send_proxy_version) |
                    del(.network.accept_proxy) |
                    del(.network.accept_proxy_timeout)' "$config_file" > "$temp_config"
                mv "$temp_config" "$config_file"
                echo -e "${GREEN}✓ 已关闭全局Proxy Protocol${NC}"
            else
                echo -e "${YELLOW}开启全局Proxy Protocol...${NC}"
                jq '.network.send_proxy = true |
                    .network.send_proxy_version = 2 |
                    .network.accept_proxy = true |
                    .network.accept_proxy_timeout = 5' "$config_file" > "$temp_config"
                mv "$temp_config" "$config_file"
                echo -e "${GREEN}✓ 已开启全局Proxy Protocol${NC}"
            fi

            restart_realm_service true

            read -p "按回车键继续..."
            continue
        fi

        echo ""
        echo -e "${BLUE}请选择 Proxy 协议版本:${NC}"
        echo -e "${WHITE}1.${NC} off (关闭)"
        echo -e "${BLUE}2.${NC} 协议v1"
        echo -e "${GREEN}3.${NC} 协议v2"
        echo ""

        read -p "请选择协议版本（回车默认v2） [1-3]: " version_choice
        if [ -z "$version_choice" ]; then
            version_choice="3"
        fi

        if [ "$version_choice" = "1" ]; then
            if [[ "$rule_input" == *","* ]]; then
                batch_set_proxy_mode "$rule_input" "off" ""
            else
                if [[ "$rule_input" =~ ^[0-9]+$ ]]; then
                    set_proxy_mode "$rule_input" "off" ""
                else
                    echo -e "${RED}无效的规则ID${NC}"
                fi
            fi
            read -p "按回车键继续..."
            continue
        fi

        echo ""
        echo -e "${BLUE}请选择 Proxy 方向:${NC}"
        echo -e "${BLUE}1.${NC} 仅发送 (send_proxy)"
        echo -e "${YELLOW}2.${NC} 仅接收 (accept_proxy)"
        echo -e "${GREEN}3.${NC} 双向 (send + accept)"
        echo ""

        read -p "请选择方向 [1-3]: " direction_choice
        if [ -z "$direction_choice" ]; then
            continue
        fi

        if [[ "$rule_input" == *","* ]]; then
            batch_set_proxy_mode "$rule_input" "$version_choice" "$direction_choice"
        else
            if [[ "$rule_input" =~ ^[0-9]+$ ]]; then
                set_proxy_mode "$rule_input" "$version_choice" "$direction_choice"
            else
                echo -e "${RED}无效的规则ID${NC}"
            fi
        fi
        read -p "按回车键继续..."
    done
}

batch_set_proxy_mode() {
    local rule_ids="$1"
    local version_choice="$2"
    local direction_choice="$3"

    local validation_result=$(validate_rule_ids "$rule_ids")
    IFS='|' read -r valid_count invalid_count valid_ids invalid_ids <<< "$validation_result"

    if [ "$invalid_count" -gt 0 ]; then
        echo -e "${RED}错误: 以下规则ID无效或不存在: $invalid_ids${NC}"
        return 1
    fi

    if [ "$valid_count" -eq 0 ]; then
        echo -e "${RED}错误: 没有找到有效的规则ID${NC}"
        return 1
    fi

    local valid_ids_array
    IFS=' ' read -ra valid_ids_array <<< "$valid_ids"

    echo -e "${YELLOW}即将为以下规则设置Proxy模式:${NC}"
    echo ""
    for id in "${valid_ids_array[@]}"; do
        local rule_file="${RULES_DIR}/rule-${id}.conf"
        if read_rule_file "$rule_file"; then
            echo -e "${BLUE}规则ID: ${GREEN}$RULE_ID${NC} | ${BLUE}规则名称: ${GREEN}$RULE_NAME${NC}"
        fi
    done
    echo ""

    read -p "确认为以上 $valid_count 个规则设置Proxy模式？(y/n): " confirm
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        local success_count=0
        for id in "${valid_ids_array[@]}"; do
            if set_proxy_mode "$id" "$version_choice" "$direction_choice" "batch"; then
                success_count=$((success_count + 1))
            fi
        done

        if [ $success_count -gt 0 ]; then
            echo -e "${GREEN}✓ 成功设置 $success_count 个规则的Proxy模式${NC}"
            echo -e "${YELLOW}正在重启服务以应用配置更改...${NC}"
            if service_restart; then
                echo -e "${GREEN}✓ 服务重启成功，Proxy配置已生效${NC}"
            else
                echo -e "${RED}✗ 服务重启失败，请检查配置${NC}"
            fi
            return 0
        else
            echo -e "${RED}✗ 没有成功设置任何规则${NC}"
            return 1
        fi
    else
        echo -e "${YELLOW}操作已取消${NC}"
        return 1
    fi
}

set_proxy_mode() {
    local rule_id="$1"
    local version_choice="$2"
    local direction_choice="$3"
    local batch_mode="$4"

    local rule_file="${RULES_DIR}/rule-${rule_id}.conf"
    if [ ! -f "$rule_file" ]; then
        echo -e "${RED}错误: 规则 $rule_id 不存在${NC}"
        return 1
    fi

    if ! read_rule_file "$rule_file"; then
        echo -e "${RED}错误: 读取规则文件失败${NC}"
        return 1
    fi

    if [ "$version_choice" = "off" ]; then
        local new_mode="off"
        local mode_display=$(get_proxy_mode_display "$new_mode")
        local mode_color=$(get_proxy_mode_color "$new_mode")

        if [ "$batch_mode" != "batch" ]; then
            echo -e "${YELLOW}正在为规则 '$RULE_NAME' 关闭Proxy功能${NC}"
        fi

        update_proxy_mode_in_file "$rule_file" "$new_mode"

        if [ $? -eq 0 ]; then
            if [ "$batch_mode" != "batch" ]; then
                echo -e "${GREEN}✓ Proxy已关闭${NC}"
                restart_service_for_proxy
            fi
        fi
        return $?
    fi

    local version=""
    case "$version_choice" in
        "2")
            version="v1"
            ;;
        "3")
            version="v2"
            ;;
        *)
            echo -e "${RED}无效的版本选择${NC}"
            return 1
            ;;
    esac

    local direction=""
    case "$direction_choice" in
        "1")
            direction="send"
            ;;
        "2")
            direction="accept"
            ;;
        "3")
            direction="both"
            ;;
        *)
            echo -e "${RED}无效的方向选择${NC}"
            return 1
            ;;
    esac

    local new_mode="${version}_${direction}"
    local mode_display=$(get_proxy_mode_display "$new_mode")
    local mode_color=$(get_proxy_mode_color "$new_mode")

    if [ "$batch_mode" != "batch" ]; then
        echo -e "${YELLOW}正在为规则 '$RULE_NAME' 设置Proxy模式为: ${mode_color}$mode_display${NC}"
    fi

    update_proxy_mode_in_file "$rule_file" "$new_mode"

    if [ $? -eq 0 ]; then
        if [ "$batch_mode" != "batch" ]; then
            echo -e "${GREEN}✓ Proxy模式已更新为: ${mode_color}$mode_display${NC}"
            restart_service_for_proxy
        fi
        return 0
    else
        if [ "$batch_mode" != "batch" ]; then
            echo -e "${RED}✗ 更新Proxy模式失败${NC}"
        fi
        return 1
    fi
}

update_proxy_mode_in_file() {
    local rule_file="$1"
    local new_mode="$2"
    local temp_file="${rule_file}.tmp.$$"

    if grep -q "^PROXY_MODE=" "$rule_file"; then
        grep -v "^PROXY_MODE=" "$rule_file" > "$temp_file"
        echo "PROXY_MODE=\"$new_mode\"" >> "$temp_file"
        mv "$temp_file" "$rule_file"
    else
        echo "PROXY_MODE=\"$new_mode\"" >> "$rule_file"
    fi
}

restart_service_for_proxy() {
    echo -e "${YELLOW}正在重启服务以应用Proxy配置...${NC}"
    if service_restart; then
        echo -e "${GREEN}✓ 服务重启成功，Proxy配置已生效${NC}"
        return 0
    else
        echo -e "${RED}✗ 服务重启失败，请检查配置${NC}"
        return 1
    fi
}

load_balance_management_menu() {
    while true; do
        clear
        echo -e "${GREEN}=== 负载均衡管理(按端口组管理) ===${NC}"
        echo ""

        if [ ! -d "$RULES_DIR" ] || [ -z "$(ls -A "$RULES_DIR"/*.conf 2>/dev/null)" ]; then
            echo -e "${YELLOW}暂无转发规则，请先创建转发规则${NC}"
            echo ""
            read -p "按回车键返回..."
            return
        fi

        # 按端口分组收集中转服务器规则，只显示有多个服务器的端口组
        declare -A port_groups
        declare -A port_configs
        declare -A port_balance_modes
        declare -A port_weights
        declare -A port_failover_status

        for rule_file in "${RULES_DIR}"/rule-*.conf; do
            if [ -f "$rule_file" ]; then
                if read_rule_file "$rule_file" && [ "$RULE_ROLE" = "1" ]; then
                    local port_key="$LISTEN_PORT"

                    if [ -z "${port_configs[$port_key]}" ]; then
                        port_configs[$port_key]="$RULE_NAME"
                        port_balance_modes[$port_key]="${BALANCE_MODE:-off}"
                        port_weights[$port_key]="$WEIGHTS"
                        port_failover_status[$port_key]="${FAILOVER_ENABLED:-false}"
                    fi

                    if [[ "$REMOTE_HOST" == *","* ]]; then
                        IFS=',' read -ra host_array <<< "$REMOTE_HOST"
                        for host in "${host_array[@]}"; do
                            local target="$host:$REMOTE_PORT"
                            if [[ "${port_groups[$port_key]}" != *"$target"* ]]; then
                                if [ -z "${port_groups[$port_key]}" ]; then
                                    port_groups[$port_key]="$target"
                                else
                                    port_groups[$port_key]="${port_groups[$port_key]},$target"
                                fi
                            fi
                        done
                    else
                        local target="$REMOTE_HOST:$REMOTE_PORT"
                        if [[ "${port_groups[$port_key]}" != *"$target"* ]]; then
                            if [ -z "${port_groups[$port_key]}" ]; then
                                port_groups[$port_key]="$target"
                            else
                                port_groups[$port_key]="${port_groups[$port_key]},$target"
                            fi
                        fi
                    fi
                fi
            fi
        done

        local has_balance_groups=false
        echo -e "${GREEN}中转服务器:${NC}"

        for port_key in $(printf '%s\n' "${!port_groups[@]}" | sort -n); do
            IFS=',' read -ra targets <<< "${port_groups[$port_key]}"
            local target_count=${#targets[@]}

            if [ $target_count -gt 1 ]; then
                has_balance_groups=true

                local balance_mode="${port_balance_modes[$port_key]}"
                local balance_info=$(get_balance_info_display "${port_groups[$port_key]}" "$balance_mode")

                # 显示端口组标题
                echo -e "  ${BLUE}端口 $port_key${NC}: ${GREEN}${port_configs[$port_key]}${NC} [$balance_info] - $target_count个服务器"

                # 显示每个服务器及其权重
                for ((i=0; i<target_count; i++)); do
                    local target="${targets[i]}"

                    # 获取权重信息
                    local current_weight=1
                    local weights_str="${port_weights[$port_key]}"

                    if [ -n "$weights_str" ] && [[ "$weights_str" == *","* ]]; then
                        IFS=',' read -ra weight_array <<< "$weights_str"
                        current_weight="${weight_array[i]:-1}"
                    elif [ -n "$weights_str" ] && [[ "$weights_str" != *","* ]]; then
                        current_weight="$weights_str"
                    fi

                    # 计算权重百分比
                    local total_weight=0
                    if [ -n "$weights_str" ] && [[ "$weights_str" == *","* ]]; then
                        IFS=',' read -ra weight_array <<< "$weights_str"
                        for w in "${weight_array[@]}"; do
                            total_weight=$((total_weight + w))
                        done
                    else
                        total_weight=$((target_count * current_weight))
                    fi

                    local percentage
                    if [ "$total_weight" -gt 0 ]; then
                        if command -v bc >/dev/null 2>&1; then
                            percentage=$(echo "scale=1; $current_weight * 100 / $total_weight" | bc 2>/dev/null || echo "100.0")
                        else
                            percentage=$(awk "BEGIN {printf \"%.1f\", $current_weight * 100 / $total_weight}")
                        fi
                    else
                        percentage="100.0"
                    fi

                    # 构建故障转移状态信息
                    local failover_info=""
                    if [ "$balance_mode" != "off" ] && [ "${port_failover_status[$port_key]}" = "true" ]; then
                        local health_status_file="/etc/realm/health/health_status.conf"
                        local node_status="healthy"

                        if [ -f "$health_status_file" ]; then
                            local host_only=$(echo "$target" | cut -d':' -f1)
                            local health_key="*|${host_only}"
                            local found_status=$(grep "^.*|${host_only}|" "$health_status_file" 2>/dev/null | cut -d'|' -f3 | head -1)
                            if [ "$found_status" = "failed" ]; then
                                node_status="failed"
                            fi
                        fi

                        case "$node_status" in
                            "healthy") failover_info=" ${GREEN}[健康]${NC}" ;;
                            "failed") failover_info=" ${RED}[故障]${NC}" ;;
                        esac
                    fi

                    # 显示服务器信息（只在负载均衡模式下显示权重）
                    if [ "$balance_mode" != "off" ]; then
                        echo -e "    ${BLUE}$((i+1)).${NC} $target ${GREEN}[权重: $current_weight]${NC} ${BLUE}($percentage%)${NC}$failover_info"
                    else
                        echo -e "    ${BLUE}$((i+1)).${NC} $target$failover_info"
                    fi
                done
                echo ""
            fi
        done

        if [ "$has_balance_groups" = false ]; then
            echo -e "${YELLOW}暂无符合条件的负载均衡组${NC}"
            echo -e "${BLUE}提示: 只显示单端口有至少两台服务器的中转规则${NC}"
            echo ""
            read -p "按回车键返回..."
            return
        fi

        echo ""
        echo "请选择操作:"
        echo -e "${GREEN}1.${NC} 切换负载均衡模式"
        echo -e "${BLUE}2.${NC} 权重配置管理"
        echo -e "${YELLOW}3.${NC} 开启/关闭故障转移"
        echo -e "${RED}0.${NC} 返回上级菜单"
        echo ""

        read -p "请输入选择 [0-3]: " choice
        echo ""

        case $choice in
            1)
                # 切换负载均衡模式
                switch_balance_mode
                ;;
            2)
                # 权重配置管理
                weight_management_menu
                ;;
            3)
                # 开启/关闭故障转移
                failover_management_menu
                ;;
            0)
                # 返回上级菜单
                break
                ;;
            *)
                echo -e "${RED}无效选择，请输入 0-3${NC}"
                read -p "按回车键继续..."
                ;;
        esac
    done
}

# 切换负载均衡模式（按端口分组管理）
switch_balance_mode() {
    while true; do
        clear
        echo -e "${YELLOW}=== 切换负载均衡模式 ===${NC}"
        echo ""

        # 按端口分组收集中转服务器规则
        # 清空并重新初始化关联数组
        unset port_groups port_configs port_balance_modes
        declare -A port_groups
        declare -A port_configs
        declare -A port_balance_modes

        for rule_file in "${RULES_DIR}"/rule-*.conf; do
            if [ -f "$rule_file" ]; then
                if read_rule_file "$rule_file" && [ "$RULE_ROLE" = "1" ]; then
                    local port_key="$LISTEN_PORT"

                    # 存储端口配置（使用第一个规则的配置作为基准）
                    if [ -z "${port_configs[$port_key]}" ]; then
                        port_configs[$port_key]="$RULE_NAME"
                        port_balance_modes[$port_key]="${BALANCE_MODE:-off}"
                    fi

                    # 正确处理REMOTE_HOST中可能包含多个地址的情况
                    if [[ "$REMOTE_HOST" == *","* ]]; then
                        # REMOTE_HOST包含多个地址，分别添加
                        IFS=',' read -ra host_array <<< "$REMOTE_HOST"
                        for host in "${host_array[@]}"; do
                            local target="$host:$REMOTE_PORT"
                            # 检查是否已存在，避免重复添加
                            if [[ "${port_groups[$port_key]}" != *"$target"* ]]; then
                                if [ -z "${port_groups[$port_key]}" ]; then
                                    port_groups[$port_key]="$target"
                                else
                                    port_groups[$port_key]="${port_groups[$port_key]},$target"
                                fi
                            fi
                        done
                    else
                        # REMOTE_HOST是单个地址
                        local target="$REMOTE_HOST:$REMOTE_PORT"
                        # 检查是否已存在，避免重复添加
                        if [[ "${port_groups[$port_key]}" != *"$target"* ]]; then
                            if [ -z "${port_groups[$port_key]}" ]; then
                                port_groups[$port_key]="$target"
                            else
                                port_groups[$port_key]="${port_groups[$port_key]},$target"
                            fi
                        fi
                    fi
                fi
            fi
        done

        # 显示端口组列表（只显示有多个目标服务器的端口组）
        local has_balance_rules=false
        declare -a rule_ports
        declare -a rule_names

        for port_key in "${!port_groups[@]}"; do
            # 计算目标服务器总数
            IFS=',' read -ra targets <<< "${port_groups[$port_key]}"
            local target_count=${#targets[@]}

            # 只显示有多个目标服务器的端口组
            if [ "$target_count" -gt 1 ]; then
                if [ "$has_balance_rules" = false ]; then
                    echo "请选择要切换负载均衡模式的规则组 (仅显示多目标服务器的规则组):"
                    has_balance_rules=true
                fi

                # 使用数字ID
                local rule_number=$((${#rule_ports[@]} + 1))
                rule_ports+=("$port_key")
                rule_names+=("${port_configs[$port_key]}")

                local balance_mode="${port_balance_modes[$port_key]}"
                local balance_display=""
                case "$balance_mode" in
                    "roundrobin")
                        balance_display="${YELLOW}[轮询]${NC}"
                        ;;
                    "iphash")
                        balance_display="${BLUE}[IP哈希]${NC}"
                        ;;
                    *)
                        balance_display="${WHITE}[off]${NC}"
                        ;;
                esac

                echo -e "${GREEN}$rule_number.${NC} ${port_configs[$port_key]} (端口: $port_key) $balance_display - $target_count个目标服务器"
            fi
        done

        if [ "$has_balance_rules" = false ]; then
            echo -e "${YELLOW}暂无多目标服务器的规则组${NC}"
            echo -e "${BLUE}提示: 只有具有多个目标服务器的规则组才能配置负载均衡${NC}"
            echo ""
            echo -e "${BLUE}负载均衡的前提条件：${NC}"
            echo -e "${BLUE}  1. 规则类型为中转服务器${NC}"
            echo -e "${BLUE}  2. 有多个目标服务器（单规则多地址或多规则单地址）${NC}"
            echo ""
            echo -e "${YELLOW}如果您需要添加更多目标服务器：${NC}"
            echo -e "${BLUE}  请到 '转发配置管理' → '添加转发规则' 创建更多规则${NC}"
            echo ""
            read -p "按回车键返回..."
            return
        fi

        echo ""
        echo -e "${WHITE}注意: 负载均衡模式将应用到选定端口组的所有相关规则${NC}"
        echo ""
        read -p "请输入规则编号 [1-${#rule_ports[@]}] (或按回车返回): " choice

        if [ -z "$choice" ]; then
            return
        fi

        # 验证数字输入
        if ! [[ "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -lt 1 ] || [ "$choice" -gt ${#rule_ports[@]} ]; then
            echo -e "${RED}无效的规则编号${NC}"
            read -p "按回车键继续..."
            continue
        fi

        # 计算数组索引（从0开始）
        local selected_index=$((choice - 1))
        local selected_port="${rule_ports[$selected_index]}"
        local current_balance_mode="${port_balance_modes[$selected_port]}"

        echo ""
        echo -e "${GREEN}当前选择: ${port_configs[$selected_port]} (端口: $selected_port)${NC}"
        echo -e "${BLUE}当前负载均衡模式: $current_balance_mode${NC}"
        echo ""
        echo "请选择新的负载均衡模式:"
        echo -e "${GREEN}1.${NC} 关闭负载均衡（off）"
        echo -e "${YELLOW}2.${NC} 轮询 (roundrobin)"
        echo -e "${BLUE}3.${NC} IP哈希 (iphash)"
        echo ""

        read -p "请输入选择 [1-3]: " mode_choice

        local new_mode=""
        local mode_display=""
        case $mode_choice in
            1)
                new_mode="off"
                mode_display="关闭"
                ;;
            2)
                new_mode="roundrobin"
                mode_display="轮询"
                ;;
            3)
                new_mode="iphash"
                mode_display="IP哈希"
                ;;
            *)
                echo -e "${RED}无效选择${NC}"
                read -p "按回车键继续..."
                continue
                ;;
        esac

        # 更新选定端口组下所有相关规则的负载均衡模式
        local updated_count=0
        for rule_file in "${RULES_DIR}"/rule-*.conf; do
            if [ -f "$rule_file" ]; then
                if read_rule_file "$rule_file" && [ "$RULE_ROLE" = "1" ] && [ "$LISTEN_PORT" = "$selected_port" ]; then
                    sed -i "s/BALANCE_MODE=\".*\"/BALANCE_MODE=\"$new_mode\"/" "$rule_file"
                    updated_count=$((updated_count + 1))
                fi
            fi
        done

        if [ $updated_count -gt 0 ]; then
            echo -e "${GREEN}✓ 已将端口 $selected_port 的 $updated_count 个规则的负载均衡模式更新为: $mode_display${NC}"
            echo -e "${YELLOW}正在重启服务以应用更改...${NC}"

            # 重启realm服务
            if service_restart; then
                echo -e "${GREEN}✓ 服务重启成功，负载均衡模式已生效${NC}"
            else
                echo -e "${RED}✗ 服务重启失败，请检查配置${NC}"
            fi
        else
            echo -e "${RED}✗ 未找到相关规则文件${NC}"
        fi

        read -p "按回车键继续..."
    done
}

# 启用/禁用中转规则
toggle_target_server() {
    echo -e "${YELLOW}=== 启用/禁用中转规则 ===${NC}"
    echo ""

    # 显示所有中转服务器规则（支持规则级别的启用/禁用）
    local has_relay_rules=false
    for rule_file in "${RULES_DIR}"/rule-*.conf; do
        if [ -f "$rule_file" ]; then
            if read_and_check_relay_rule "$rule_file"; then
                if [ "$has_relay_rules" = false ]; then
                    echo -e "${GREEN}中转服务器:${NC}"
                    has_relay_rules=true
                fi

                local status_color="${GREEN}"
                local status_text="启用"
                if [ "$ENABLED" != "true" ]; then
                    status_color="${RED}"
                    status_text="禁用"
                fi

                local display_target=$(smart_display_target "$REMOTE_HOST")
                local balance_mode="${BALANCE_MODE:-off}"
                local balance_info=$(get_balance_info_display "$REMOTE_HOST" "$balance_mode")

                if [ "$RULE_ROLE" = "2" ]; then
                    local display_ip="::"
                else
                    local display_ip="${NAT_LISTEN_IP:-::}"
                fi
                local through_display="${THROUGH_IP:-::}"
                echo -e "  ID ${BLUE}$RULE_ID${NC}: ${GREEN}$RULE_NAME${NC} (${LISTEN_IP:-$display_ip}:$LISTEN_PORT → $through_display → $display_target:$REMOTE_PORT) [${status_color}$status_text${NC}]$balance_info"
            fi
        fi
    done

    if [ "$has_relay_rules" = false ]; then
        echo -e "${YELLOW}没有配置中转服务器规则${NC}"
        echo -e "${BLUE}提示: 需要先创建中转服务器规则才能进行启用/禁用操作${NC}"
        read -p "按回车键返回..."
        return
    fi

    echo ""
    read -p "请输入要配置的规则ID: " selected_rule_id

    if ! [[ "$selected_rule_id" =~ ^[0-9]+$ ]]; then
        echo -e "${RED}无效的规则ID${NC}"
        read -p "按回车键返回..."
        return
    fi

    local rule_file="${RULES_DIR}/rule-${selected_rule_id}.conf"

    if ! read_rule_file "$rule_file" || [ "$RULE_ROLE" != "1" ]; then
        echo -e "${RED}规则不存在或不是中转服务器规则${NC}"
        read -p "按回车键返回..."
        return
    fi

    echo ""
    echo -e "${BLUE}规则: $RULE_NAME${NC}"
    echo -e "${BLUE}当前状态: ${ENABLED}${NC}"

    # 检查是否为单规则多目标（包含逗号）
    if [[ "$REMOTE_HOST" == *","* ]]; then
        echo -e "${BLUE}操作类型: 单规则内目标服务器启用/禁用${NC}"
        echo -e "${BLUE}目标服务器列表:${NC}"

        IFS=',' read -ra targets <<< "$REMOTE_HOST"
        local target_states="${TARGET_STATES:-}"

        for i in "${!targets[@]}"; do
            local target="${targets[i]}"
            local is_enabled=$(is_target_enabled "$i" "$target_states")

            local status_color="${GREEN}"
            local status_text="启用"
            if [ "$is_enabled" = "false" ]; then
                status_color="${RED}"
                status_text="禁用"
            fi

            echo -e "${GREEN}$((i + 1)).${NC} $target:$REMOTE_PORT [${status_color}$status_text${NC}]"
        done

        echo ""
        read -p "请输入要切换状态的目标编号 [1-${#targets[@]}]: " target_choice

        if ! [[ "$target_choice" =~ ^[0-9]+$ ]] || [ "$target_choice" -lt 1 ] || [ "$target_choice" -gt ${#targets[@]} ]; then
            echo -e "${RED}无效选择${NC}"
            read -p "按回车键返回..."
            return
        fi

        local target_index=$((target_choice - 1))
        local state_key="target_${target_index}"
        local current_enabled=$(is_target_enabled "$target_index" "$target_states")

        # 切换状态
        local new_enabled="true"
        if [ "$current_enabled" = "true" ]; then
            new_enabled="false"
        fi

        # 更新TARGET_STATES
        local new_target_states=""
        if [ -z "$target_states" ]; then
            new_target_states="$state_key:$new_enabled"
        else
            if [[ "$target_states" == *"$state_key:"* ]]; then
                # 替换现有状态
                new_target_states=$(echo "$target_states" | sed "s/$state_key:[^,]*/$state_key:$new_enabled/g")
            else
                # 添加新状态
                new_target_states="$target_states,$state_key:$new_enabled"
            fi
        fi

        # 更新规则文件
        sed -i "s/TARGET_STATES=\".*\"/TARGET_STATES=\"$new_target_states\"/" "$rule_file"

        local target_name="${targets[$target_index]}"
        if [ "$new_enabled" = "true" ]; then
            echo -e "${GREEN}✓ 目标服务器 $target_name:$REMOTE_PORT 已启用${NC}"
        else
            echo -e "${YELLOW}✓ 目标服务器 $target_name:$REMOTE_PORT 已禁用${NC}"
        fi
    else
        # 单目标规则，切换整个规则的启用/禁用状态
        echo -e "${BLUE}操作类型: 整个规则启用/禁用${NC}"
        echo -e "${BLUE}目标: $REMOTE_HOST:$REMOTE_PORT${NC}"

        local current_status="$ENABLED"
        local new_status="false"
        local action_text="禁用"
        local color="${RED}"

        if [ "$current_status" != "true" ]; then
            new_status="true"
            action_text="启用"
            color="${GREEN}"
        fi

        echo ""
        read -p "确认要${action_text}此规则吗？(y/n): " confirm

        if [[ "$confirm" =~ ^[Yy]$ ]]; then
            # 更新规则文件
            sed -i "s/ENABLED=\".*\"/ENABLED=\"$new_status\"/" "$rule_file"
            echo -e "${color}✓ 规则 $RULE_NAME 已${action_text}${NC}"
        else
            echo "操作已取消"
        fi
    fi

    echo -e "${YELLOW}正在重启服务以应用更改...${NC}"
    service_restart

    read -p "按回车键继续..."
}

# 中转服务器交互配置
configure_nat_server() {
    echo -e "${YELLOW}=== 中转服务器配置(不了解入口出口一般回车默认即可) ===${NC}"
    echo ""

echo -e "${BLUE}多端口使用,逗号分隔(回车随机端口)${NC}"
while true; do
    read -p "请输入本地监听端口 (客户端连接的端口，nat机需使用分配的端口): " NAT_LISTEN_PORT

    if [[ -z "$NAT_LISTEN_PORT" ]]; then
        NAT_LISTEN_PORT=$((RANDOM % 64512 + 1024))
    fi

    if validate_ports "$NAT_LISTEN_PORT"; then
        echo -e "${GREEN}监听端口设置为: $NAT_LISTEN_PORT${NC}"
        break
    else
        echo -e "${RED}无效端口号，请输入 1-65535 之间的数字，多端口用逗号分隔${NC}"
    fi
done

    # 检查是否为多端口
    local is_multi_port=false
    local port_status=0

    if [[ "$NAT_LISTEN_PORT" == *","* ]]; then
        is_multi_port=true
        echo -e "${BLUE}检测到多端口配置，跳过端口占用检测${NC}"
        port_status=0  # 多端口不检测占用
    else
        # 单端口检测
        check_port_usage "$NAT_LISTEN_PORT" "中转服务器监听"
        port_status=$?
    fi

    # 如果端口被realm占用，跳过IP地址、协议、传输方式配置
    if [ $port_status -eq 1 ]; then
        echo -e "${BLUE}检测到端口已被realm占用，读取现有配置，直接进入出口服务器配置${NC}"
        echo ""

        # 读取现有同端口规则的配置
        for rule_file in "${RULES_DIR}"/rule-*.conf; do
            if [ -f "$rule_file" ]; then
                if read_rule_file "$rule_file" && [ "$LISTEN_PORT" = "$NAT_LISTEN_PORT" ] && [ "$RULE_ROLE" = "1" ]; then
                    # 找到同端口的中转服务器规则，使用其配置
                    NAT_LISTEN_IP="${LISTEN_IP}"
                    NAT_THROUGH_IP="${THROUGH_IP:-::}"
                    SECURITY_LEVEL="${SECURITY_LEVEL}"
                    TLS_SERVER_NAME="${TLS_SERVER_NAME}"
                    TLS_CERT_PATH="${TLS_CERT_PATH}"
                    TLS_KEY_PATH="${TLS_KEY_PATH}"
                    WS_PATH="${WS_PATH}"
                    WS_HOST="${WS_HOST}"
                    RULE_NOTE="${RULE_NOTE:-}"  # 复用现有备注
                    echo -e "${GREEN}已读取端口 $NAT_LISTEN_PORT 的现有配置${NC}"
                    break
                fi
            fi
        done

        # 直接跳转到远程服务器配置
    else
        # 清空可能残留的备注变量（新端口配置）
        RULE_NOTE=""
        echo ""

        while true; do
            read -p "自定义(指定)入口监听IP地址(客户端连接IP,回车默认全部监听 ::): " listen_ip_input

            if [ -z "$listen_ip_input" ]; then
                # 使用默认值：双栈监听
                NAT_LISTEN_IP="::"
                echo -e "${GREEN}使用默认监听IP: :: (全部监听)${NC}"
                break
            else
                # 验证自定义输入
                if validate_ip "$listen_ip_input"; then
                    NAT_LISTEN_IP="$listen_ip_input"
                    echo -e "${GREEN}监听IP设置为: $NAT_LISTEN_IP${NC}"
                    break
                else
                    echo -e "${RED}无效IP地址格式${NC}"
                    echo -e "${YELLOW}示例: 192.168.1.100 或 2001:db8::1 或 0.0.0.0 或 ::${NC}"
                fi
            fi
        done

        echo ""

        while true; do
            read -p "自定义(指定)出口IP地址(适用于中转多IP出口情况,回车默认全部监听 ::): " through_ip_input

            if [ -z "$through_ip_input" ]; then
                NAT_THROUGH_IP="::"
                echo -e "${GREEN}使用默认出口IP: :: (全部监听)${NC}"
                break
            else
                # 验证自定义输入
                if validate_ip "$through_ip_input"; then
                    NAT_THROUGH_IP="$through_ip_input"
                    echo -e "${GREEN}出口IP设置为: $NAT_THROUGH_IP${NC}"
                    break
                else
                    echo -e "${RED}无效IP地址格式${NC}"
                    echo -e "${YELLOW}示例: 192.168.1.100 或 2001:db8::1 或 0.0.0.0 或 ::${NC}"
                fi
            fi
        done

        echo ""
    fi

    # 配置远程服务器
    echo -e "${YELLOW}=== 出口服务器信息配置 ===${NC}"
    echo ""
    
    while true; do
        read -p "出口服务器的IP地址或域名: " REMOTE_IP
        if [ -n "$REMOTE_IP" ]; then
            if validate_ip "$REMOTE_IP" || [[ "$REMOTE_IP" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
                break
            else
                echo -e "${RED}请输入有效的IP地址或域名${NC}"
            fi
        else
            echo -e "${RED}IP地址或域名不能为空${NC}"
        fi
    done

    while true; do
        read -p "出口服务器的监听端口(多端口使用,逗号分隔): " REMOTE_PORT
        if validate_ports "$REMOTE_PORT"; then
            break
        else
            echo -e "${RED}无效端口号，请输入 1-65535 之间的数字，多端口用逗号分隔${NC}"
        fi
    done

    # 测试连通性
    local connectivity_ok=true

    # 检查是否为多端口
    if [[ "$REMOTE_PORT" == *","* ]]; then
        echo -e "${BLUE}多端口配置，跳过连通性测试${NC}"
    else
        echo -e "${YELLOW}正在测试与出口服务器的连通性...${NC}"
        if check_connectivity "$REMOTE_IP" "$REMOTE_PORT"; then
            echo -e "${GREEN}✓ 连接测试成功！${NC}"
        else
            echo -e "${RED}✗ 连接测试失败，请检查出口服务器是否已启动并确认IP和端口正确${NC}"
            connectivity_ok=false
        fi
    fi

    # 处理连接失败的情况
    if [ "$connectivity_ok" = false ]; then

        # 检查是否为域名，给出DDNS特别提醒
        if ! validate_ip "$REMOTE_IP" && [[ "$REMOTE_IP" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
            echo -e "${YELLOW}检测到您使用的是域名地址，如果是DDNS域名：${NC}"
            echo -e "${YELLOW}确认域名和端口正确后，直接继续配置无需担心${NC}"
        fi

        read -p "是否继续配置？(y/n): " continue_config
        if [[ ! "$continue_config" =~ ^[Yy]$ ]]; then
            echo "配置已取消"
            exit 1
        fi
    fi

    # 如果端口被realm占用，跳过协议和传输配置
    if [ $port_status -eq 1 ]; then

        echo -e "${BLUE}使用默认配置完成设置${NC}"
    else

    echo ""
    echo "请选择传输模式:"
    echo -e "${GREEN}[1]${NC} 默认传输 (不加密，理论最快)"
    echo -e "${GREEN}[2]${NC} WebSocket (ws)"
    echo -e "${GREEN}[3]${NC} TLS (自签证书，自动生成)"
    echo -e "${GREEN}[4]${NC} TLS (CA签发证书)"
    echo -e "${GREEN}[5]${NC} TLS+WebSocket (自签证书)"
    echo -e "${GREEN}[6]${NC} TLS+WebSocket (CA证书)"
    echo ""

    while true; do
        read -p "请输入选择 [1-6]: " transport_choice
        case $transport_choice in
            1)
                SECURITY_LEVEL="standard"
                echo -e "${GREEN}已选择: 默认传输${NC}"
                break
                ;;
            2)
                SECURITY_LEVEL="ws"
                echo -e "${GREEN}已选择: WebSocket${NC}"

                echo ""
                read -p "请输入WebSocket Host [默认: $DEFAULT_SNI_DOMAIN]: " WS_HOST
                if [ -z "$WS_HOST" ]; then
                    WS_HOST="$DEFAULT_SNI_DOMAIN"
                fi
                echo -e "${GREEN}WebSocket Host设置为: $WS_HOST${NC}"

                echo ""
                read -p "请输入WebSocket路径 [默认: /ws]: " WS_PATH
                if [ -z "$WS_PATH" ]; then
                    WS_PATH="/ws"
                fi
                echo -e "${GREEN}WebSocket路径设置为: $WS_PATH${NC}"
                break
                ;;
            3)
                SECURITY_LEVEL="tls_self"
                echo -e "${GREEN}已选择: TLS自签证书${NC}"

                echo ""
                read -p "请输入TLS服务器名称 (SNI) [默认$DEFAULT_SNI_DOMAIN]: " TLS_SERVER_NAME
                if [ -z "$TLS_SERVER_NAME" ]; then
                    TLS_SERVER_NAME="$DEFAULT_SNI_DOMAIN"
                fi
                echo -e "${GREEN}TLS服务器名称设置为: $TLS_SERVER_NAME${NC}"
                break
                ;;
            4)
                SECURITY_LEVEL="tls_ca"
                echo -e "${GREEN}已选择: TLS CA证书${NC}"

                echo ""
                while true; do
                    read -p "请输入证书文件路径: " TLS_CERT_PATH
                    if [ -f "$TLS_CERT_PATH" ]; then
                        break
                    else
                        echo -e "${RED}证书文件不存在，请检查路径${NC}"
                    fi
                done

                while true; do
                    read -p "请输入私钥文件路径: " TLS_KEY_PATH
                    if [ -f "$TLS_KEY_PATH" ]; then
                        break
                    else
                        echo -e "${RED}私钥文件不存在，请检查路径${NC}"
                    fi
                done

                read -p "请输入TLS服务器名称 (SNI): " TLS_SERVER_NAME
                echo -e "${GREEN}TLS配置完成${NC}"
                break
                ;;
            5)
                SECURITY_LEVEL="ws_tls_self"
                echo -e "${GREEN}已选择: TLS+WebSocket自签证书${NC}"

                echo ""
                read -p "请输入WebSocket Host [默认: $DEFAULT_SNI_DOMAIN]: " WS_HOST
                if [ -z "$WS_HOST" ]; then
                    WS_HOST="$DEFAULT_SNI_DOMAIN"
                fi
                echo -e "${GREEN}WebSocket Host设置为: $WS_HOST${NC}"

                echo ""
                read -p "请输入TLS服务器名称 (SNI) [默认$DEFAULT_SNI_DOMAIN]: " TLS_SERVER_NAME
                if [ -z "$TLS_SERVER_NAME" ]; then
                    TLS_SERVER_NAME="$DEFAULT_SNI_DOMAIN"
                fi
                echo -e "${GREEN}TLS服务器名称设置为: $TLS_SERVER_NAME${NC}"

                read -p "请输入WebSocket路径 [默认: /ws]: " WS_PATH
                if [ -z "$WS_PATH" ]; then
                    WS_PATH="/ws"
                fi
                echo -e "${GREEN}WebSocket路径设置为: $WS_PATH${NC}"
                break
                ;;
            6)
                SECURITY_LEVEL="ws_tls_ca"
                echo -e "${GREEN}已选择: TLS+WebSocket CA证书${NC}"

                echo ""
                read -p "请输入WebSocket Host [默认: $DEFAULT_SNI_DOMAIN]: " WS_HOST
                if [ -z "$WS_HOST" ]; then
                    WS_HOST="$DEFAULT_SNI_DOMAIN"
                fi
                echo -e "${GREEN}WebSocket Host设置为: $WS_HOST${NC}"

                echo ""
                while true; do
                    read -p "请输入证书文件路径: " TLS_CERT_PATH
                    if [ -f "$TLS_CERT_PATH" ]; then
                        break
                    else
                        echo -e "${RED}证书文件不存在，请检查路径${NC}"
                    fi
                done

                while true; do
                    read -p "请输入私钥文件路径: " TLS_KEY_PATH
                    if [ -f "$TLS_KEY_PATH" ]; then
                        break
                    else
                        echo -e "${RED}私钥文件不存在，请检查路径${NC}"
                    fi
                done

                read -p "请输入TLS服务器名称 (SNI): " TLS_SERVER_NAME

                read -p "请输入WebSocket路径 [默认: /ws]: " WS_PATH
                if [ -z "$WS_PATH" ]; then
                    WS_PATH="/ws"
                fi
                echo -e "${GREEN}TLS+WebSocket配置完成${NC}"
                break
                ;;
            *)
                echo -e "${RED}无效选择，请输入 1-6${NC}"
                ;;
        esac
    done

    fi

    echo ""
    echo -e "${BLUE}=== 规则备注配置 ===${NC}"

    # 检查是否有现有备注（端口复用情况）
    if [ -n "$RULE_NOTE" ]; then
        read -p "请输入新的备注(回车使用现有备注$RULE_NOTE): " new_note
        new_note=$(echo "$new_note" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | cut -c1-50)
        if [ -n "$new_note" ]; then
            RULE_NOTE="$new_note"
            echo -e "${GREEN}备注设置为: $RULE_NOTE${NC}"
        else
            echo -e "${GREEN}使用现有备注: $RULE_NOTE${NC}"
        fi
    else
        read -p "请输入当前规则备注(可选，直接回车跳过): " RULE_NOTE
        # 去除前后空格并限制长度
        RULE_NOTE=$(echo "$RULE_NOTE" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | cut -c1-50)
        if [ -n "$RULE_NOTE" ]; then
            echo -e "${GREEN}备注设置为: $RULE_NOTE${NC}"
        else
            echo -e "${BLUE}未设置备注${NC}"
        fi
    fi

    echo ""
}

# 出口服务器交互配置
configure_exit_server() {
    echo -e "${YELLOW}=== 解密并转发服务器配置 (双端Realm架构) ===${NC}"
    echo ""

    echo "正在获取本机公网IP..."
    local ipv4=$(get_public_ip "ipv4")
    local ipv6=$(get_public_ip "ipv6")

    if [ -n "$ipv4" ]; then
        echo -e "${GREEN}本机IPv4地址: $ipv4${NC}"
    fi
    if [ -n "$ipv6" ]; then
        echo -e "${GREEN}本机IPv6地址: $ipv6${NC}"
    fi

    if [ -z "$ipv4" ] && [ -z "$ipv6" ]; then
        echo -e "${YELLOW}无法自动获取公网IP，请手动确认${NC}"
    fi
    echo ""

    echo -e "${BLUE}多端口使用,逗号分隔${NC}"
    while true; do
        read -p "请输入监听端口 (等待中转服务器连接的端口，NAT VPS需使用商家分配的端口): " EXIT_LISTEN_PORT
        if validate_ports "$EXIT_LISTEN_PORT"; then
            echo -e "${GREEN}监听端口设置为: $EXIT_LISTEN_PORT${NC}"
            break
        else
            echo -e "${RED}无效端口号，请输入 1-65535 之间的数字，多端口用逗号分隔${NC}"
        fi
    done

    local is_multi_port=false

    if [[ "$EXIT_LISTEN_PORT" == *","* ]]; then
        is_multi_port=true
        echo -e "${BLUE}检测到多端口配置，跳过端口占用检测${NC}"
    else

        check_port_usage "$EXIT_LISTEN_PORT" "出口服务器监听"
    fi

    echo ""

    # 配置转发目标
    echo "内循环本地转发目标或者远端服务器业务:"
    echo ""
    echo -e "${YELLOW}本地业务输入: IPv4: 127.0.0.1 | IPv6: ::1 | 双栈: localhost${NC}"
    echo -e "${YELLOW}远端业务输入:对应服务器IP ${NC}"
    echo ""

    # 转发目标地址配置
    while true; do
        read -p "转发目标IP地址(默认:127.0.0.1): " input_target
        if [ -z "$input_target" ]; then
            input_target="127.0.0.1"
        fi

        if validate_target_address "$input_target"; then
            FORWARD_TARGET="$input_target"
            echo -e "${GREEN}转发目标设置为: $FORWARD_TARGET${NC}"
            break
        else
            echo -e "${RED}无效地址格式${NC}"
            echo -e "${YELLOW}支持格式: IP地址、域名、或多个地址用逗号分隔${NC}"
            echo -e "${YELLOW}示例: 127.0.0.1,::1 或 localhost 或 192.168.1.100${NC}"
        fi
    done

    # 转发目标端口配置
    local forward_port
    while true; do
        read -p "转发目标业务端口(多端口使用,逗号分隔): " forward_port
        if validate_ports "$forward_port"; then
            echo -e "${GREEN}转发端口设置为: $forward_port${NC}"
            break
        else
            echo -e "${RED}无效端口号，请输入 1-65535 之间的数字，多端口用逗号分隔${NC}"
        fi
    done

    # 组合完整的转发目标（包含端口）
    FORWARD_TARGET="$FORWARD_TARGET:$forward_port"

    # 测试转发目标连通性
    local connectivity_ok=true

    # 检查是否为多端口，多端口跳过连通性测试
    if [[ "$forward_port" == *","* ]]; then
        echo -e "${BLUE}多端口配置，跳过转发目标连通性测试${NC}"
    else
        echo -e "${YELLOW}正在测试转发目标连通性...${NC}"

        # 解析并测试每个地址
        local addresses_part="${FORWARD_TARGET%:*}"
        local target_port="${FORWARD_TARGET##*:}"
        IFS=',' read -ra TARGET_ADDRESSES <<< "$addresses_part"
        for addr in "${TARGET_ADDRESSES[@]}"; do
            addr=$(echo "$addr" | xargs)  # 去除空格
            echo -e "${BLUE}测试连接: $addr:$target_port${NC}"
            if check_connectivity "$addr" "$target_port"; then
                echo -e "${GREEN}✓ $addr:$target_port 连接成功${NC}"
            else
                echo -e "${RED}✗ $addr:$target_port 连接失败${NC}"
                connectivity_ok=false
            fi
        done
    fi

    # 只有单端口且连通性测试失败时才处理
    if ! $connectivity_ok && [[ "$forward_port" != *","* ]]; then
        echo -e "${RED}部分或全部转发目标连接测试失败，请确认代理服务是否正常运行${NC}"

        # 检查是否包含域名，给出DDNS特别提醒
        local has_domain=false
        local addresses_part="${FORWARD_TARGET%:*}"
        IFS=',' read -ra TARGET_ADDRESSES <<< "$addresses_part"
        for addr in "${TARGET_ADDRESSES[@]}"; do
            addr=$(echo "$addr" | xargs)
            if ! validate_ip "$addr" && [[ "$addr" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
                has_domain=true
                break
            fi
        done

        if $has_domain; then
            echo -e "${YELLOW}检测到您使用的是域名地址，如果是DDNS域名：${NC}"
            echo -e "${YELLOW}确认域名和端口正确，可以直接继续配置无需担心${NC}"
            echo -e "${YELLOW}DDNS域名无法进行连通性测试${NC}"
        fi

        read -p "是否继续配置？(y/n): " continue_config
        if [[ ! "$continue_config" =~ ^[Yy]$ ]]; then
            echo "配置已取消"
            exit 1
        fi
    else
        echo -e "${GREEN}✓ 所有转发目标连接测试成功！${NC}"
    fi

    echo ""
    echo "请选择传输模式:"
    echo -e "${GREEN}[1]${NC} 默认传输 (不加密，理论最快)"
    echo -e "${GREEN}[2]${NC} WebSocket (ws)"
    echo -e "${GREEN}[3]${NC} TLS (自签证书，自动生成)"
    echo -e "${GREEN}[4]${NC} TLS (CA签发证书)"
    echo -e "${GREEN}[5]${NC} TLS+WebSocket (自签证书)"
    echo -e "${GREEN}[6]${NC} TLS+WebSocket (CA证书)"
    echo ""

    while true; do
        read -p "请输入选择 [1-6]: " transport_choice
        case $transport_choice in
            1)
                SECURITY_LEVEL="standard"
                echo -e "${GREEN}已选择: 默认传输${NC}"
                break
                ;;
            2)
                SECURITY_LEVEL="ws"
                echo -e "${GREEN}已选择: WebSocket${NC}"

                echo ""
                read -p "请输入WebSocket Host [默认: $DEFAULT_SNI_DOMAIN]: " WS_HOST
                if [ -z "$WS_HOST" ]; then
                    WS_HOST="$DEFAULT_SNI_DOMAIN"
                fi
                echo -e "${GREEN}WebSocket Host设置为: $WS_HOST${NC}"

                echo ""
                read -p "请输入WebSocket路径 [默认: /ws]: " WS_PATH
                if [ -z "$WS_PATH" ]; then
                    WS_PATH="/ws"
                fi
                echo -e "${GREEN}WebSocket路径设置为: $WS_PATH${NC}"
                break
                ;;
            3)
                SECURITY_LEVEL="tls_self"
                echo -e "${GREEN}已选择: TLS自签证书${NC}"

                echo ""
                read -p "请输入TLS服务器名称 (SNI) [默认$DEFAULT_SNI_DOMAIN]: " TLS_SERVER_NAME
                if [ -z "$TLS_SERVER_NAME" ]; then
                    TLS_SERVER_NAME="$DEFAULT_SNI_DOMAIN"
                fi
                echo -e "${GREEN}TLS服务器名称设置为: $TLS_SERVER_NAME${NC}"
                break
                ;;
            3)
                SECURITY_LEVEL="tls_self"
                echo -e "${GREEN}已选择: TLS自签证书${NC}"

                echo ""
                read -p "请输入TLS服务器名称 (SNI) [默认$DEFAULT_SNI_DOMAIN]: " TLS_SERVER_NAME
                if [ -z "$TLS_SERVER_NAME" ]; then
                    TLS_SERVER_NAME="$DEFAULT_SNI_DOMAIN"
                fi
                echo -e "${GREEN}TLS服务器名称设置为: $TLS_SERVER_NAME${NC}"
                break
                ;;
            4)
                SECURITY_LEVEL="tls_ca"
                echo -e "${GREEN}已选择: TLS CA证书${NC}"

                echo ""
                while true; do
                    read -p "请输入证书文件路径: " TLS_CERT_PATH
                    if [ -f "$TLS_CERT_PATH" ]; then
                        break
                    else
                        echo -e "${RED}证书文件不存在，请检查路径${NC}"
                    fi
                done

                while true; do
                    read -p "请输入私钥文件路径: " TLS_KEY_PATH
                    if [ -f "$TLS_KEY_PATH" ]; then
                        break
                    else
                        echo -e "${RED}私钥文件不存在，请检查路径${NC}"
                    fi
                done

                read -p "请输入TLS服务器名称 (SNI): " TLS_SERVER_NAME
                echo -e "${GREEN}TLS配置完成${NC}"
                break
                ;;
            5)
                SECURITY_LEVEL="ws_tls_self"
                echo -e "${GREEN}已选择: TLS+WebSocket自签证书${NC}"

                echo ""
                read -p "请输入WebSocket Host [默认: $DEFAULT_SNI_DOMAIN]: " WS_HOST
                if [ -z "$WS_HOST" ]; then
                    WS_HOST="$DEFAULT_SNI_DOMAIN"
                fi
                echo -e "${GREEN}WebSocket Host设置为: $WS_HOST${NC}"

                echo ""
                read -p "请输入TLS服务器名称 (SNI) [默认$DEFAULT_SNI_DOMAIN]: " TLS_SERVER_NAME
                if [ -z "$TLS_SERVER_NAME" ]; then
                    TLS_SERVER_NAME="$DEFAULT_SNI_DOMAIN"
                fi
                echo -e "${GREEN}TLS服务器名称设置为: $TLS_SERVER_NAME${NC}"

                read -p "请输入WebSocket路径 [默认: /ws]: " WS_PATH
                if [ -z "$WS_PATH" ]; then
                    WS_PATH="/ws"
                fi
                echo -e "${GREEN}WebSocket路径设置为: $WS_PATH${NC}"
                break
                ;;
            6)
                SECURITY_LEVEL="ws_tls_ca"
                echo -e "${GREEN}已选择: TLS+WebSocket CA证书${NC}"

                echo ""
                read -p "请输入WebSocket Host [默认: $DEFAULT_SNI_DOMAIN]: " WS_HOST
                if [ -z "$WS_HOST" ]; then
                    WS_HOST="$DEFAULT_SNI_DOMAIN"
                fi
                echo -e "${GREEN}WebSocket Host设置为: $WS_HOST${NC}"

                echo ""
                while true; do
                    read -p "请输入证书文件路径: " TLS_CERT_PATH
                    if [ -f "$TLS_CERT_PATH" ]; then
                        break
                    else
                        echo -e "${RED}证书文件不存在，请检查路径${NC}"
                    fi
                done

                while true; do
                    read -p "请输入私钥文件路径: " TLS_KEY_PATH
                    if [ -f "$TLS_KEY_PATH" ]; then
                        break
                    else
                        echo -e "${RED}私钥文件不存在，请检查路径${NC}"
                    fi
                done

                read -p "请输入TLS服务器名称 (SNI): " TLS_SERVER_NAME

                read -p "请输入WebSocket路径 [默认: /ws]: " WS_PATH
                if [ -z "$WS_PATH" ]; then
                    WS_PATH="/ws"
                fi
                echo -e "${GREEN}TLS+WebSocket配置完成${NC}"
                break
                ;;
            *)
                echo -e "${RED}无效选择，请输入 1-6${NC}"
                ;;
        esac
    done

    echo ""
    echo -e "${BLUE}=== 规则备注配置 ===${NC}"

    read -p "请输入当前规则备注(可选，直接回车跳过): " RULE_NOTE
    # 去除前后空格并限制长度
    RULE_NOTE=$(echo "$RULE_NOTE" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | cut -c1-50)
    if [ -n "$RULE_NOTE" ]; then
        echo -e "${GREEN}备注设置为: $RULE_NOTE${NC}"
    else
        echo -e "${BLUE}未设置备注${NC}"
    fi

    echo ""
}

# 检测虚拟化环境
detect_virtualization() {
    local virt_type="物理机"

    # 检测各种虚拟化技术
    if [ -f /proc/vz/version ]; then
        virt_type="OpenVZ"
    elif [ -d /proc/vz ]; then
        virt_type="OpenVZ容器"
    elif grep -q "lxc" /proc/1/cgroup 2>/dev/null; then
        virt_type="LXC容器"
    elif [ -f /.dockerenv ]; then
        virt_type="Docker容器"
    elif command -v systemd-detect-virt >/dev/null 2>&1; then
        local detected=$(systemd-detect-virt 2>/dev/null)
        case "$detected" in
            "kvm") virt_type="KVM虚拟机" ;;
            "qemu") virt_type="QEMU虚拟机" ;;
            "vmware") virt_type="VMware虚拟机" ;;
            "xen") virt_type="Xen虚拟机" ;;
            "lxc") virt_type="LXC容器" ;;
            "docker") virt_type="Docker容器" ;;
            "openvz") virt_type="OpenVZ容器" ;;
            "none") virt_type="物理机" ;;
            *) virt_type="未知虚拟化($detected)" ;;
        esac
    elif [ -e /proc/user_beancounters ]; then
        virt_type="OpenVZ容器"
    elif dmesg 2>/dev/null | grep -i "hypervisor detected" >/dev/null; then
        virt_type="虚拟机"
    fi

    echo "$virt_type"
}

# 获取适合的临时目录（针对不同虚拟化环境）
get_temp_dir() {
    local virt_env=$(detect_virtualization)
    local temp_candidates=()

    # 根据虚拟化环境选择最佳临时目录
    case "$virt_env" in
        *"LXC"*|*"OpenVZ"*)
            # 容器环境优先使用 /var/tmp，避免权限问题
            temp_candidates=("/var/tmp" "/tmp" ".")
            ;;
        *"Docker"*)
            # Docker 环境优先使用当前目录
            temp_candidates=("." "/tmp" "/var/tmp")
            ;;
        *)
            # 其他环境使用标准顺序
            temp_candidates=("/tmp" "/var/tmp" ".")
            ;;
    esac

    # 测试每个候选目录
    for dir in "${temp_candidates[@]}"; do
        if [ -w "$dir" ]; then
            local test_file="${dir}/test_write_$$"
            if echo "test" > "$test_file" 2>/dev/null; then
                rm -f "$test_file"
                echo "$dir"
                return 0
            fi
        fi
    done

    # 如果都不可用，返回当前目录
    echo "."
}

# 系统诊断函数 - 虚拟化适配
diagnose_system() {
    echo -e "${YELLOW}=== 系统诊断信息 ===${NC}"

    # 检测虚拟化环境
    local virt_env=$(detect_virtualization)
    echo -e "${BLUE}虚拟化环境: ${GREEN}${virt_env}${NC}"

    # 检查磁盘空间
    echo -e "${BLUE}磁盘空间:${NC}"
    df -h . 2>/dev/null | head -2 || echo "无法获取磁盘信息"

    # 检查内存使用
    echo -e "${BLUE}内存使用:${NC}"
    free -h 2>/dev/null | head -2 || echo "无法获取内存信息"

    # 检查文件系统类型
    echo -e "${BLUE}文件系统类型:${NC}"
    local fs_type=$(df -T . 2>/dev/null | tail -1 | awk '{print $2}' || echo "未知")
    echo "当前目录文件系统: $fs_type"

    # 针对不同虚拟化环境的特殊检查
    case "$virt_env" in
        *"LXC"*|*"OpenVZ"*)
            echo -e "${BLUE}容器特殊检查:${NC}"
            echo "容器ID: $(cat /proc/self/cgroup 2>/dev/null | head -1 | cut -d: -f3 || echo '未知')"
            echo "用户命名空间: $(readlink /proc/self/ns/user 2>/dev/null || echo '未知')"
            # LXC/OpenVZ 特有的权限检查
            if [ -e /proc/user_beancounters ]; then
                echo "OpenVZ beancounters: 存在"
            fi
            ;;
        *"Docker"*)
            echo -e "${BLUE}Docker特殊检查:${NC}"
            echo "容器ID: $(hostname 2>/dev/null || echo '未知')"
            ;;
    esac

    # 测试文件写入（多个位置）
    echo -e "${BLUE}文件写入测试:${NC}"
    local write_locations=("." "/tmp" "/var/tmp")

    for location in "${write_locations[@]}"; do
        if [ -w "$location" ]; then
            local test_file="${location}/test_write_$$"
            if echo "test" > "$test_file" 2>/dev/null; then
                echo -e "${GREEN}✓ ${location} 可写${NC}"
                rm -f "$test_file"
            else
                echo -e "${RED}✗ ${location} 写入失败${NC}"
            fi
        else
            echo -e "${YELLOW}⚠ ${location} 无写入权限${NC}"
        fi
    done

    # 推荐的临时目录
    local recommended_temp=$(get_temp_dir)
    echo -e "${BLUE}推荐临时目录: ${GREEN}${recommended_temp}${NC}"

    echo ""
}


# 统一多源下载函数
download_from_sources() {
    local url="$1"
    local target_path="$2"

    for proxy in "${DOWNLOAD_SOURCES[@]}"; do
        local full_url="${proxy}${url}"
        local source_name

        if [ -z "$proxy" ]; then
            source_name="GitHub官方源"
        else
            source_name="加速源: $(echo "$proxy" | sed 's|https://||' | sed 's|/$||')"
        fi

        # 将状态消息重定向到 stderr (>&2)
        echo -e "${BLUE}尝试 $source_name${NC}" >&2

        if curl -fsSL --connect-timeout $SHORT_CONNECT_TIMEOUT --max-time $SHORT_MAX_TIMEOUT "$full_url" -o "$target_path"; then
            echo -e "${GREEN}✓ $source_name 下载成功${NC}" >&2
            return 0
        else

            echo -e "${YELLOW}✗ $source_name 下载失败，尝试下一个源...${NC}" >&2
        fi
    done

    echo -e "${RED}✗ 所有下载源均失败${NC}" >&2
    return 1
}

# 获取realm最新版本号
get_latest_realm_version() {
    echo -e "${YELLOW}获取最新版本信息...${NC}" >&2

    local latest_version=$(curl -sL --connect-timeout $SHORT_CONNECT_TIMEOUT --max-time $SHORT_MAX_TIMEOUT "https://github.com/zhboner/realm/releases" 2>/dev/null | \
        head -2100 | \
        sed -n 's|.*releases/tag/v\([0-9.]*\).*|v\1|p' | head -1)

    if [ -z "$latest_version" ]; then
        echo -e "${YELLOW}使用当前最新版本 ${REALM_VERSION}${NC}" >&2
        latest_version="$REALM_VERSION"
    fi

    echo -e "${GREEN}✓ 检测到最新版本: ${latest_version}${NC}" >&2
    echo "$latest_version"
}

# 智能重启realm服务
restart_realm_service() {
    local was_running="$1"
    local is_update="${2:-false}"  # 是否为更新场景

    if [ "$was_running" = true ] || [ "$is_update" = true ]; then
        echo -e "${YELLOW}正在启动realm服务...${NC}"
        if systemctl start realm >/dev/null 2>&1; then
            echo -e "${GREEN}✓ realm服务已启动${NC}"
        else
            echo -e "${YELLOW}服务启动失败，尝试重新初始化...${NC}"
            start_empty_service
        fi
    else
        # 首次安装，启动空服务完成安装
        start_empty_service
    fi
}

# 比较realm版本并询问更新
compare_and_ask_update() {
    local current_version="$1"
    local latest_version="$2"

    # 提取当前版本号进行比较
    local current_ver=$(echo "$current_version" | grep -oE 'v?[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    if [ -z "$current_ver" ]; then
        current_ver="v0.0.0"
    fi

    # 统一版本格式（添加v前缀）
    if [[ ! "$current_ver" =~ ^v ]]; then
        current_ver="v$current_ver"
    fi
    if [[ ! "$latest_version" =~ ^v ]]; then
        latest_version="v$latest_version"
    fi

    # 比较版本
    if [ "$current_ver" = "$latest_version" ]; then
        echo -e "${GREEN}✓ 当前版本已是最新版本${NC}"
        return 1
    else
        echo -e "${YELLOW}发现新版本: ${current_ver} → ${latest_version}${NC}"
        read -p "是否更新到最新版本？(y/n) [默认: n]: " update_choice
        if [[ ! "$update_choice" =~ ^[Yy]$ ]]; then
            echo -e "${BLUE}使用现有的 realm 安装${NC}"
            return 1
        fi
        echo -e "${YELLOW}将更新到最新版本...${NC}"
        return 0
    fi
}

# 安全停止realm服务
safe_stop_realm_service() {
    local service_was_running=false

    if systemctl is-active realm >/dev/null 2>&1; then
        echo -e "${BLUE}检测到realm服务正在运行，正在停止服务...${NC}"
        if systemctl stop realm >/dev/null 2>&1; then
            echo -e "${GREEN}✓ realm服务已停止${NC}"
            service_was_running=true
        else
            echo -e "${RED}✗ 停止realm服务失败，无法安全更新${NC}"
            return 1
        fi
    fi

    echo "$service_was_running"
}

# 安装 realm - 虚拟化适配
install_realm() {
    echo -e "${GREEN}正在检查 realm 安装状态...${NC}"

    # 检测虚拟化环境并显示
    local virt_env=$(detect_virtualization)
    echo -e "${BLUE}检测到虚拟化环境: ${GREEN}${virt_env}${NC}"

    # 检查是否已安装realm
    if [ -f "${REALM_PATH}" ] && [ -x "${REALM_PATH}" ]; then
        # 检查程序完整性（基本可执行性测试）
        if ! ${REALM_PATH} --help >/dev/null 2>&1; then
            echo -e "${YELLOW}检测到 realm 文件存在但可能已损坏，将重新安装...${NC}"
        else
            # 尝试获取版本信息
            local current_version=""
            local version_output=""
            if version_output=$(${REALM_PATH} --version 2>&1); then
                current_version="$version_output"
            elif version_output=$(${REALM_PATH} -v 2>&1); then
                current_version="$version_output"
            else
                current_version="realm (版本检查失败，可能架构不匹配)"
                echo -e "${YELLOW}警告: 版本检查失败，错误信息: ${version_output}${NC}"
            fi

            echo -e "${GREEN}✓ 检测到已安装的 realm: ${current_version}${NC}"
            echo ""

            # 获取最新版本号进行比较
            LATEST_VERSION=$(get_latest_realm_version)

            # 比较版本并询问更新
            if ! compare_and_ask_update "$current_version" "$LATEST_VERSION"; then
                return 0
            fi
        fi
    else
        echo -e "${YELLOW}未检测到 realm 安装，开始下载安装...${NC}"

        # 获取最新版本号
        LATEST_VERSION=$(get_latest_realm_version)
    fi

    # 离线安装选项
    local download_file=""
    read -p "离线安装realm输入完整路径(回车默认自动下载): " local_package_path
    
    if [ -n "$local_package_path" ] && [ -f "$local_package_path" ]; then
        echo -e "${GREEN}✓ 使用本地文件: $local_package_path${NC}"
        download_file="$local_package_path"
    else
        if [ -n "$local_package_path" ]; then
            echo -e "${RED}✗ 文件不存在，继续在线下载${NC}"
        fi
        
        ARCH=$(uname -m)
        case $ARCH in
            x86_64)
                ARCH="x86_64-unknown-linux-gnu"
                ;;
            aarch64)
                ARCH="aarch64-unknown-linux-gnu"
                ;;
            armv7l|armv6l|arm)
                ARCH="armv7-unknown-linux-gnueabihf"
                ;;
            *)
                echo -e "${RED}不支持的CPU架构: ${ARCH}${NC}"
                echo -e "${YELLOW}支持的架构: x86_64, aarch64, armv7l${NC}"
                exit 1
                ;;
        esac

        DOWNLOAD_URL="https://github.com/zhboner/realm/releases/download/${LATEST_VERSION}/realm-${ARCH}.tar.gz"
        echo -e "${BLUE}目标文件: realm-${ARCH}.tar.gz${NC}"

        local file_path="$(pwd)/realm.tar.gz"
        if download_from_sources "$DOWNLOAD_URL" "$file_path"; then
            echo -e "${GREEN}✓ 下载成功: ${file_path}${NC}"
            download_file="$file_path"
        else
            echo -e "${RED}✗ 下载失败${NC}"
            exit 1
        fi
    fi

    # 解压安装
    echo -e "${YELLOW}正在解压安装...${NC}"

    local service_was_running=$(safe_stop_realm_service)
    if [ $? -ne 0 ]; then
        return 1
    fi

    local work_dir=$(dirname "$download_file")
    local archive_name=$(basename "$download_file")

    if (cd "$work_dir" && tar -xzf "$archive_name" && cp realm ${REALM_PATH} && chmod +x ${REALM_PATH}); then
        echo -e "${GREEN}✓ realm 安装成功${NC}"
        
        # 只删除自动下载的文件，保留用户提供的本地文件
        if [ -z "$local_package_path" ]; then
            rm -f "$download_file"
        fi
        rm -f "${work_dir}/realm"

        restart_realm_service "$service_was_running" true
    else
        echo -e "${RED}✗ 安装失败${NC}"
        exit 1
    fi
}

# 生成单个规则的endpoint配置（支持多地址和负载均衡）
generate_rule_endpoint_config() {
    local remote_host="$1"
    local remote_port="$2"
    local listen_port="$3"
    local security_level="$4"
    local tls_server_name="$5"
    local tls_cert_path="$6"
    local tls_key_path="$7"
    local balance_mode="$8"
    local target_states="$9"

    local endpoint_config=""

    # 检查是否为多地址
    if [[ "$remote_host" == *","* ]]; then
        # 多地址配置：使用主地址+额外地址
        IFS=',' read -ra addresses <<< "$remote_host"
        local main_address="${addresses[0]}"
        local extra_addresses=""
        local enabled_addresses=()

        # 根据TARGET_STATES过滤启用的地址
        enabled_addresses+=("$main_address")  # 主地址默认启用

        if [ ${#addresses[@]} -gt 1 ]; then
            for ((i=1; i<${#addresses[@]}; i++)); do
                local is_enabled=$(is_target_enabled "$i" "$target_states")

                if [ "$is_enabled" = "true" ]; then
                    enabled_addresses+=("${addresses[i]}")
                fi
            done
        fi

        # 构建额外地址字符串（只包含启用的地址）
        if [ ${#enabled_addresses[@]} -gt 1 ]; then
            for ((i=1; i<${#enabled_addresses[@]}; i++)); do
                if [ -n "$extra_addresses" ]; then
                    extra_addresses="$extra_addresses, "
                fi
                extra_addresses="$extra_addresses\"${enabled_addresses[i]}:${remote_port}\""
            done

            extra_addresses=",
            \"extra_remotes\": [$extra_addresses]"
        fi

        endpoint_config="
        {
            \"listen\": \"${LISTEN_IP:-${NAT_LISTEN_IP:-::}}:${listen_port}\",
            \"remote\": \"${enabled_addresses[0]}:${remote_port}\"${extra_addresses}"
    else
        # 单地址配置
        endpoint_config="
        {
            \"listen\": \"${LISTEN_IP:-${NAT_LISTEN_IP:-::}}:${listen_port}\",
            \"remote\": \"${remote_host}:${remote_port}\""
    fi

    # 添加through字段（仅中转服务器）
    local role="${RULE_ROLE:-1}"
    if [ "$role" = "1" ] && [ -n "$THROUGH_IP" ] && [ "$THROUGH_IP" != "::" ]; then
        endpoint_config="$endpoint_config,
            \"through\": \"$THROUGH_IP\""
    fi

    # 添加负载均衡配置（仅用于单规则多地址情况）
    if [ -n "$balance_mode" ] && [ "$balance_mode" != "off" ] && [[ "$remote_host" == *","* ]]; then
        # 计算地址数量并生成权重
        IFS=',' read -ra addr_array <<< "$remote_host"
        local weights=""
        for ((i=0; i<${#addr_array[@]}; i++)); do
            if [ -n "$weights" ]; then
                weights="$weights, "
            fi
            weights="${weights}1"  # 默认权重为1（相等权重）
        done

        endpoint_config="$endpoint_config,
            \"balance\": \"$balance_mode: $weights\""
    fi

    # 添加传输配置 - 需要角色信息
    # 通过全局变量RULE_ROLE获取角色，如果没有则通过REMOTE_HOST判断
    local role="${RULE_ROLE:-1}"  # 默认为中转服务器
    if [ -z "$RULE_ROLE" ]; then
        # 如果没有RULE_ROLE，通过是否有FORWARD_TARGET判断
        if [ -n "$FORWARD_TARGET" ]; then
            role="2"  # 出口服务器
        fi
    fi

    local transport_config=$(get_transport_config "$security_level" "$TLS_SERVER_NAME" "$tls_cert_path" "$tls_key_path" "$role" "$WS_PATH")
    if [ -n "$transport_config" ]; then
        endpoint_config="$endpoint_config,
            $transport_config"
    fi

    endpoint_config="$endpoint_config
        }"

    echo "$endpoint_config"
}

# 从规则生成endpoints配置（支持负载均衡合并和故障转移）
generate_endpoints_from_rules() {
    local endpoints=""
    local count=0

    if [ ! -d "$RULES_DIR" ]; then
        return 0
    fi

    # 确保规则ID排序是最优的
    reorder_rule_ids

    # 健康状态读取（直接读取健康状态文件）
    declare -A health_status
    local health_status_file="/etc/realm/health/health_status.conf"

    if [ -f "$health_status_file" ]; then
        while read -r line; do
            # 跳过注释行和空行
            [[ "$line" =~ ^#.*$ ]] && continue
            [[ -z "$line" ]] && continue

            # 解析格式: RULE_ID|TARGET|STATUS|...
            if [[ "$line" =~ ^[0-9]+\|([^|]+)\|([^|]+)\| ]]; then
                local host="${BASH_REMATCH[1]}"
                local status="${BASH_REMATCH[2]}"
                health_status["$host"]="$status"
            fi
        done < "$health_status_file"
    fi

    # 按监听端口分组规则
    declare -A port_groups
    declare -A port_configs
    declare -A port_weights
    declare -A port_roles

    # 第一步：收集所有启用的规则并按端口分组（不进行故障转移过滤）
    declare -A port_rule_files
    for rule_file in "${RULES_DIR}"/rule-*.conf; do
        if [ -f "$rule_file" ]; then
            if read_rule_file "$rule_file" && [ "$ENABLED" = "true" ]; then
                local port_key="$LISTEN_PORT"

                # 存储端口配置（使用第一个规则的配置作为基准）
                if [ -z "${port_configs[$port_key]}" ]; then
                    # 根据角色决定默认监听IP
                    local default_listen_ip
                    if [ "$RULE_ROLE" = "2" ]; then
                        # 落地服务器使用双栈监听
                        default_listen_ip="::"
                    else
                        # 中转服务器使用动态输入的IP
                        default_listen_ip="${NAT_LISTEN_IP:-::}"
                    fi
                    port_configs[$port_key]="$SECURITY_LEVEL|$TLS_SERVER_NAME|$TLS_CERT_PATH|$TLS_KEY_PATH|$BALANCE_MODE|${LISTEN_IP:-$default_listen_ip}|$THROUGH_IP"
                    # 存储权重配置和角色信息
                    port_weights[$port_key]="$WEIGHTS"
                    port_roles[$port_key]="$RULE_ROLE"
                elif [ "${port_roles[$port_key]}" != "$RULE_ROLE" ]; then
                    # 检测到同一端口有不同角色的规则，跳过此规则
                    echo -e "${YELLOW}警告: 端口 $port_key 已被角色 ${port_roles[$port_key]} 的规则占用，跳过角色 $RULE_ROLE 的规则${NC}" >&2
                    continue
                fi

                # 收集目标：根据规则角色使用不同的字段
                local targets_to_add=""

                if [ "$RULE_ROLE" = "2" ]; then
                    # 落地服务器使用FORWARD_TARGET
                    targets_to_add="$FORWARD_TARGET"
                else
                    # 中转服务器：优先使用TARGET_STATES，否则使用REMOTE_HOST
                    if [ "$BALANCE_MODE" != "off" ] && [ -n "$TARGET_STATES" ]; then
                        # 负载均衡模式且有TARGET_STATES，使用TARGET_STATES
                        targets_to_add="$TARGET_STATES"
                    else
                        # 非负载均衡模式或无TARGET_STATES，使用REMOTE_HOST:REMOTE_PORT
                        if [[ "$REMOTE_HOST" == *","* ]]; then
                            # REMOTE_HOST包含多个地址
                            IFS=',' read -ra host_list <<< "$REMOTE_HOST"
                            for host in "${host_list[@]}"; do
                                host=$(echo "$host" | xargs)  # 去除空格
                                if [ -n "$targets_to_add" ]; then
                                    targets_to_add="$targets_to_add,$host:$REMOTE_PORT"
                                else
                                    targets_to_add="$host:$REMOTE_PORT"
                                fi
                            done
                        else
                            # REMOTE_HOST是单个地址
                            targets_to_add="$REMOTE_HOST:$REMOTE_PORT"
                        fi
                    fi
                fi

                # 将目标添加到端口组（避免重复）
                if [ -n "$targets_to_add" ]; then
                    IFS=',' read -ra target_list <<< "$targets_to_add"
                    for target in "${target_list[@]}"; do
                        target=$(echo "$target" | xargs)  # 去除空格
                        if [[ "${port_groups[$port_key]}" != *"$target"* ]]; then
                            if [ -z "${port_groups[$port_key]}" ]; then
                                port_groups[$port_key]="$target"
                            else
                                port_groups[$port_key]="${port_groups[$port_key]},$target"
                            fi
                        fi
                    done
                fi

                # 记录规则文件以便后续检查故障转移状态
                if [ -z "${port_rule_files[$port_key]}" ]; then
                    port_rule_files[$port_key]="$rule_file"
                fi
            fi
        fi
    done

    # 第二步：对每个端口组应用故障转移过滤
    for port_key in "${!port_groups[@]}"; do
        # 检查该端口的所有规则，只要有一个启用故障转移就应用过滤
        local failover_enabled="false"

        for rule_file in "${RULES_DIR}"/rule-*.conf; do
            if [ -f "$rule_file" ] && read_rule_file "$rule_file" && [ "$ENABLED" = "true" ] && [ "$LISTEN_PORT" = "$port_key" ]; then
                if [ "${FAILOVER_ENABLED:-false}" = "true" ]; then
                    failover_enabled="true"
                    break
                fi
            fi
        done

        if [ "$failover_enabled" = "true" ]; then
            # 应用故障转移过滤
            IFS=',' read -ra all_targets <<< "${port_groups[$port_key]}"
            local filtered_targets=""
            local filtered_indices=()

            # 记录健康节点的索引位置
            for i in "${!all_targets[@]}"; do
                local target="${all_targets[i]}"
                local host="${target%:*}"
                local node_status="${health_status[$host]:-healthy}"

                if [ "$node_status" != "failed" ]; then
                    if [ -n "$filtered_targets" ]; then
                        filtered_targets="$filtered_targets,$target"
                    else
                        filtered_targets="$target"
                    fi
                    filtered_indices+=($i)
                fi
            done

            # 如果所有节点都故障，保留第一个节点避免服务完全中断
            if [ -z "$filtered_targets" ]; then
                filtered_targets="${all_targets[0]}"
                filtered_indices=(0)
            fi

            # 更新端口组为过滤后的目标
            port_groups[$port_key]="$filtered_targets"

            # 同步调整权重配置以匹配过滤后的目标数量
            local original_weights="${port_weights[$port_key]}"

            if [ -n "$original_weights" ]; then
                IFS=',' read -ra weight_array <<< "$original_weights"
                local adjusted_weights=""

                # 只保留健康节点对应的权重
                for index in "${filtered_indices[@]}"; do
                    if [ $index -lt ${#weight_array[@]} ]; then
                        local weight="${weight_array[index]}"
                        # 清理权重值（去除空格）
                        weight=$(echo "$weight" | tr -d ' ')
                        if [ -n "$adjusted_weights" ]; then
                            adjusted_weights="$adjusted_weights,$weight"
                        else
                            adjusted_weights="$weight"
                        fi
                    else
                        # 如果权重数组长度不足，使用默认权重1
                        if [ -n "$adjusted_weights" ]; then
                            adjusted_weights="$adjusted_weights,1"
                        else
                            adjusted_weights="1"
                        fi
                    fi
                done

                # 更新权重配置
                port_weights[$port_key]="$adjusted_weights"
            fi
        fi
    done

    # 为每个端口组生成endpoint配置
    for port_key in "${!port_groups[@]}"; do
        if [ $count -gt 0 ]; then
            endpoints="$endpoints,"
        fi

        # 解析端口配置
        IFS='|' read -r security_level tls_server_name tls_cert_path tls_key_path balance_mode listen_ip through_ip <<< "${port_configs[$port_key]}"
        # 如果没有listen_ip字段（向后兼容），根据角色使用对应的默认值
        if [ -z "$listen_ip" ]; then
            local role="${port_roles[$port_key]:-1}"
            if [ "$role" = "2" ]; then
                # 落地服务器使用双栈监听
                listen_ip="::"
            else
                # 中转服务器使用动态输入的IP
                listen_ip="${NAT_LISTEN_IP:-::}"
            fi
        fi

        # 如果没有through_ip字段（向后兼容），使用默认值
        if [ -z "$through_ip" ]; then
            through_ip="::"
        fi

        # 解析目标地址
        IFS=',' read -ra targets <<< "${port_groups[$port_key]}"
        local main_target="${targets[0]}"
        local main_host="${main_target%:*}"
        local main_port="${main_target##*:}"

        # 构建extra_remotes
        local extra_remotes=""
        if [ ${#targets[@]} -gt 1 ]; then
            for ((i=1; i<${#targets[@]}; i++)); do
                if [ -n "$extra_remotes" ]; then
                    extra_remotes="$extra_remotes, "
                fi
                extra_remotes="$extra_remotes\"${targets[i]}\""
            done
        fi

        # 生成endpoint配置
        local endpoint_config="
        {
            \"listen\": \"${listen_ip}:${port_key}\",
            \"remote\": \"${main_target}\""

        # 添加extra_remotes（如果有多个目标）
        if [ -n "$extra_remotes" ]; then
            endpoint_config="$endpoint_config,
            \"extra_remotes\": [$extra_remotes]"
        fi

        # 添加负载均衡配置（如果有多个目标且设置了负载均衡）
        if [ -n "$extra_remotes" ] && [ -n "$balance_mode" ] && [ "$balance_mode" != "off" ]; then
            # 生成权重配置
            local weight_config=""
            local rule_weights="${port_weights[$port_key]}"

            if [ -n "$rule_weights" ]; then
                # 使用存储的权重（已在故障转移过滤中处理）
                weight_config=$(echo "$rule_weights" | sed 's/,/, /g')
            else
                # 使用默认相等权重
                for ((i=0; i<${#targets[@]}; i++)); do
                    if [ -n "$weight_config" ]; then
                        weight_config="$weight_config, "
                    fi
                    weight_config="${weight_config}1"
                done
            fi

            endpoint_config="$endpoint_config,
            \"balance\": \"$balance_mode: $weight_config\""
        fi

        # 添加through字段（仅中转服务器）
        local role="${port_roles[$port_key]:-1}"  # 使用存储的角色，默认为中转服务器
        if [ "$role" = "1" ] && [ -n "$through_ip" ] && [ "$through_ip" != "::" ]; then
            endpoint_config="$endpoint_config,
            \"through\": \"$through_ip\""
        fi

        # 添加传输配置 - 使用存储的规则角色信息
        local transport_config=$(get_transport_config "$security_level" "$tls_server_name" "$tls_cert_path" "$tls_key_path" "$role" "$WS_PATH")
        if [ -n "$transport_config" ]; then
            endpoint_config="$endpoint_config,
            $transport_config"
        fi

        # 添加MPTCP网络配置 - 从对应的规则文件读取MPTCP设置
        local mptcp_config=""
        local rule_file_for_port="${port_rule_files[$port_key]}"

        if [ -f "$rule_file_for_port" ]; then
            # 临时保存当前变量状态
            local saved_vars=$(declare -p RULE_ID RULE_NAME MPTCP_MODE 2>/dev/null || true)

            # 读取该端口对应的规则文件
            if read_rule_file "$rule_file_for_port"; then
                local mptcp_mode="${MPTCP_MODE:-off}"
                local send_mptcp="false"
                local accept_mptcp="false"

                case "$mptcp_mode" in
                    "send")
                        send_mptcp="true"
                        ;;
                    "accept")
                        accept_mptcp="true"
                        ;;
                    "both")
                        send_mptcp="true"
                        accept_mptcp="true"
                        ;;
                esac

                # 只有在需要MPTCP时才添加network配置
                if [ "$send_mptcp" = "true" ] || [ "$accept_mptcp" = "true" ]; then
                    mptcp_config=",
            \"network\": {
                \"send_mptcp\": $send_mptcp,
                \"accept_mptcp\": $accept_mptcp
            }"
                fi
            fi

            # 恢复变量状态（如果有保存的话）
            if [ -n "$saved_vars" ]; then
                eval "$saved_vars" 2>/dev/null || true
            fi
        fi

        # 添加Proxy网络配置 - 从对应的规则文件读取Proxy设置
        local proxy_config=""
        if [ -f "$rule_file_for_port" ]; then
            # 临时保存当前变量状态
            local saved_vars=$(declare -p RULE_ID RULE_NAME PROXY_MODE 2>/dev/null || true)

            # 读取该端口对应的规则文件
            if read_rule_file "$rule_file_for_port"; then
                local proxy_mode="${PROXY_MODE:-off}"
                local send_proxy="false"
                local accept_proxy="false"
                local send_proxy_version="2"

                case "$proxy_mode" in
                    "v1_send")
                        send_proxy="true"
                        send_proxy_version="1"
                        ;;
                    "v1_accept")
                        accept_proxy="true"
                        send_proxy_version="1"
                        ;;
                    "v1_both")
                        send_proxy="true"
                        accept_proxy="true"
                        send_proxy_version="1"
                        ;;
                    "v2_send")
                        send_proxy="true"
                        send_proxy_version="2"
                        ;;
                    "v2_accept")
                        accept_proxy="true"
                        send_proxy_version="2"
                        ;;
                    "v2_both")
                        send_proxy="true"
                        accept_proxy="true"
                        send_proxy_version="2"
                        ;;
                esac

                # 只有在需要Proxy时才添加配置
                if [ "$send_proxy" = "true" ] || [ "$accept_proxy" = "true" ]; then
                    local proxy_fields=""
                    if [ "$send_proxy" = "true" ]; then
                        proxy_fields="\"send_proxy\": $send_proxy,
                \"send_proxy_version\": $send_proxy_version"
                    fi
                    if [ "$accept_proxy" = "true" ]; then
                        if [ -n "$proxy_fields" ]; then
                            proxy_fields="$proxy_fields,
                \"accept_proxy\": $accept_proxy,
                \"accept_proxy_timeout\": 5"
                        else
                            proxy_fields="\"accept_proxy\": $accept_proxy,
                \"accept_proxy_timeout\": 5"
                        fi
                    fi

                    if [ -n "$mptcp_config" ]; then
                        # 如果已有MPTCP配置，在network内添加Proxy配置
                        proxy_config=",
                $proxy_fields"
                    else
                        # 如果没有MPTCP配置，创建新的network配置
                        proxy_config=",
            \"network\": {
                $proxy_fields
            }"
                    fi
                fi
            fi

            # 恢复变量状态（如果有保存的话）
            if [ -n "$saved_vars" ]; then
                eval "$saved_vars" 2>/dev/null || true
            fi
        fi

        # 合并MPTCP和Proxy配置
        local network_config=""
        if [ -n "$mptcp_config" ] && [ -n "$proxy_config" ]; then
            # 两者都有，合并到一个network块中
            network_config=$(echo "$mptcp_config" | sed 's/}//')
            network_config="$network_config$proxy_config
            }"
        elif [ -n "$mptcp_config" ]; then
            network_config="$mptcp_config"
        elif [ -n "$proxy_config" ]; then
            network_config="$proxy_config"
        fi

        endpoint_config="$endpoint_config$network_config
        }"

        endpoints="$endpoints$endpoint_config"
        count=$((count + 1))
    done

    echo "$endpoints"
}

generate_realm_config() {
    echo -e "${YELLOW}正在生成 Realm 配置文件...${NC}"

    mkdir -p "$CONFIG_DIR"

    init_rules_dir

    # 检查是否有启用的规则
    local has_rules=false
    local enabled_count=0

    if [ -d "$RULES_DIR" ]; then
        for rule_file in "${RULES_DIR}"/rule-*.conf; do
            if [ -f "$rule_file" ]; then
                if read_rule_file "$rule_file" && [ "$ENABLED" = "true" ]; then
                    has_rules=true
                    enabled_count=$((enabled_count + 1))
                fi
            fi
        done
    fi

    if [ "$has_rules" = false ]; then
        echo -e "${BLUE}未找到启用的规则，生成空配置${NC}"
        generate_complete_config ""
        echo -e "${GREEN}✓ 空配置文件已生成${NC}"
        return 0
    fi

    # 生成基于规则的配置
    echo -e "${BLUE}找到 $enabled_count 个启用的规则，生成多规则配置${NC}"

    # 获取所有启用规则的endpoints
    local endpoints=$(generate_endpoints_from_rules)

    # 使用统一模板生成多规则配置
    generate_complete_config "$endpoints"

    echo -e "${GREEN}✓ 多规则配置文件已生成${NC}"
    echo -e "${BLUE}配置详情: $enabled_count 个启用的转发规则${NC}"

    # 显示规则摘要
    for rule_file in "${RULES_DIR}"/rule-*.conf; do
        if [ -f "$rule_file" ]; then
            if read_rule_file "$rule_file" && [ "$ENABLED" = "true" ]; then
                # 根据规则角色使用不同的字段
                if [ "$RULE_ROLE" = "2" ]; then
                    # 落地服务器使用FORWARD_TARGET
                    local target_host="${FORWARD_TARGET%:*}"
                    local target_port="${FORWARD_TARGET##*:}"
                    local display_target=$(smart_display_target "$target_host")
                    local display_ip="::"
                    echo -e "  ${GREEN}$RULE_NAME${NC}: ${LISTEN_IP:-$display_ip}:$LISTEN_PORT → $display_target:$target_port"
                else
                    # 中转服务器使用REMOTE_HOST
                    local display_target=$(smart_display_target "$REMOTE_HOST")
                    local display_ip="${NAT_LISTEN_IP:-::}"
                    local through_display="${THROUGH_IP:-::}"
                    echo -e "  ${GREEN}$RULE_NAME${NC}: ${LISTEN_IP:-$display_ip}:$LISTEN_PORT → $through_display → $display_target:$REMOTE_PORT"
                fi
            fi
        fi
    done
}

generate_systemd_service() {
    echo -e "${YELLOW}正在生成 systemd 服务文件...${NC}"
    cat > "$SYSTEMD_PATH" <<EOF
[Unit]
Description=Realm TCP Relay Service
Documentation=https://github.com/zywe03/realm-xwPF
After=network.target nss-lookup.target
Wants=network.target

[Service]
Type=simple
User=root
Group=root
ExecStart=${REALM_PATH} -c ${CONFIG_PATH}
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=5s
RestartPreventExitStatus=23

# 资源限制优化
LimitNOFILE=1048576
LimitNPROC=1048576

# 安全设置
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${CONFIG_DIR}

# 日志管理（使用systemd journal）
StandardOutput=journal
StandardError=journal
SyslogIdentifier=realm

[Install]
WantedBy=multi-user.target
EOF

    echo -e "${GREEN}✓ systemd 服务文件已生成${NC}"
    systemctl daemon-reload
    echo -e "${GREEN}✓ systemd 服务已重新加载${NC}"
}

# 启动空服务（让脚本能识别已安装状态）
start_empty_service() {
    echo -e "${YELLOW}正在初始化配置以完成安装...${NC}"

    mkdir -p "$CONFIG_DIR"

    cat > "$CONFIG_PATH" <<EOF
{
    "endpoints": []
}
EOF

    generate_systemd_service

    systemctl enable realm >/dev/null 2>&1
    systemctl start realm >/dev/null 2>&1
}

# 自安装脚本到系统
self_install() {
    echo -e "${YELLOW}正在安装脚本到系统...${NC}"

    local script_name="xwPF.sh"
    local install_dir="/usr/local/bin"
    local shortcut_name="pf"

    mkdir -p "$install_dir"

    if [ -f "${install_dir}/${script_name}" ]; then
        echo -e "${GREEN}✓ 检测到系统已安装脚本，正在更新...${NC}"

        echo -e "${BLUE}正在从GitHub下载最新脚本...${NC}"
        local base_script_url="https://raw.githubusercontent.com/zywe03/realm-xwPF/main/xwPF.sh"

        if download_from_sources "$base_script_url" "${install_dir}/${script_name}"; then
            chmod +x "${install_dir}/${script_name}"
        else
            echo -e "${RED}✗ 脚本更新失败，手动更新wget -qO- https://raw.githubusercontent.com/zywe03/realm-xwPF/main/xwPF.sh | sudo bash -s install${NC}"
            echo -e "${BLUE}使用现有脚本版本${NC}"
        fi
    elif [ -f "$0" ]; then
        # 首次安装：复制脚本到系统目录
        cp "$0" "${install_dir}/${script_name}"
        chmod +x "${install_dir}/${script_name}"
        echo -e "${GREEN}✓ 脚本已安装到: ${install_dir}/${script_name}${NC}"
    else
        # 如果是通过管道运行的，需要重新下载
        echo -e "${BLUE}正在从GitHub下载脚本...${NC}"
        local base_script_url="https://raw.githubusercontent.com/zywe03/realm-xwPF/main/xwPF.sh"

        if download_from_sources "$base_script_url" "${install_dir}/${script_name}"; then
            chmod +x "${install_dir}/${script_name}"
        else
            echo -e "${RED}✗ 脚本下载失败${NC}"
            return 1
        fi
    fi

    # 创建快捷命令
    cat > "${install_dir}/${shortcut_name}" <<EOF
#!/bin/bash
# Realm 端口转发快捷启动脚本
# 优先检测当前目录的脚本，如果不存在则使用系统安装的脚本

# 检查当前目录是否有xwPF.sh
if [ -f "\$(pwd)/xwPF.sh" ]; then
    exec bash "\$(pwd)/xwPF.sh" "\$@"
else
    exec bash "${install_dir}/${script_name}" "\$@"
fi
EOF

    chmod +x "${install_dir}/${shortcut_name}"
    echo -e "${GREEN}✓ 快捷命令已创建: ${shortcut_name}${NC}"

    # 检查PATH
    if [[ ":$PATH:" != *":${install_dir}:"* ]]; then
        echo -e "${YELLOW}注意: ${install_dir} 不在 PATH 中${NC}"
        echo -e "${BLUE}建议将以下行添加到 ~/.bashrc:${NC}"
        echo -e "${GREEN}export PATH=\"\$PATH:${install_dir}\"${NC}"
        echo ""
    fi

    return 0
}

# 安装和配置流程
smart_install() {
    echo -e "${GREEN}=== xwPF Realm 一键脚本智能安装 $SCRIPT_VERSION ===${NC}"
    echo ""

    detect_system
    echo -e "${BLUE}检测到系统: ${GREEN}$OS $VER${NC}"
    echo ""

    # 安装依赖
    manage_dependencies "install"

    # 自安装脚本
    if ! self_install; then
        echo -e "${RED}脚本安装失败${NC}"
        exit 1
    fi

    echo -e "${GREEN}=== 脚本安装完成！ ===${NC}"
    echo ""

    # 下载最新的 realm 主程序
    if install_realm; then
        echo -e "${GREEN}=== 安装完成！ ===${NC}"
        echo -e "${YELLOW}输入快捷命令 ${GREEN}pf${YELLOW} 进入脚本交互界面${NC}"
    else
        echo -e "${RED}错误: realm安装失败${NC}"
        echo -e "${YELLOW}输入快捷命令 ${GREEN}pf${YELLOW} 可进入脚本交互界面${NC}"
    fi
}

# 服务管理 - 启动
service_start() {
    echo -e "${YELLOW}正在启动 Realm 服务...${NC}"

    if systemctl start realm; then
        echo -e "${GREEN}✓ Realm 服务启动成功${NC}"
    else
        echo -e "${RED}✗ Realm 服务启动失败${NC}"
        echo -e "${BLUE}查看详细错误信息:${NC}"
        systemctl status realm --no-pager -l
        return 1
    fi
}

# 服务管理 - 停止
service_stop() {
    echo -e "${YELLOW}正在停止 Realm 服务...${NC}"

    if systemctl stop realm; then
        echo -e "${GREEN}✓ Realm 服务已停止${NC}"
    else
        echo -e "${RED}✗ Realm 服务停止失败${NC}"
        return 1
    fi
}

service_restart() {
    echo -e "${YELLOW}正在重启 Realm 服务...${NC}"

    # 重排序规则ID以保持最优排序
    echo -e "${BLUE}正在规则排序...${NC}"
    if reorder_rule_ids; then
        echo -e "${GREEN}✓ 规则排序优化完成${NC}"
    fi

    # 重新生成配置文件
    echo -e "${BLUE}重新生成配置文件...${NC}"
    generate_realm_config

    if systemctl restart realm; then
        echo -e "${GREEN}✓ Realm 服务重启成功${NC}"
    else
        echo -e "${RED}✗ Realm 服务重启失败${NC}"
        echo -e "${BLUE}查看详细错误信息:${NC}"
        systemctl status realm --no-pager -l
        return 1
    fi
}

# 服务管理
service_status() {
    echo -e "${YELLOW}Realm 服务状态:${NC}"
    echo ""

    # 获取服务状态
    local status=$(systemctl is-active realm 2>/dev/null)
    local enabled=$(systemctl is-enabled realm 2>/dev/null)

    # 显示基本状态
    if [ "$status" = "active" ]; then
        echo -e "运行状态: ${GREEN}●${NC} 运行中"
    elif [ "$status" = "inactive" ]; then
        echo -e "运行状态: ${RED}●${NC} 已停止"
    elif [ "$status" = "failed" ]; then
        echo -e "运行状态: ${RED}●${NC} 运行失败"
    else
        echo -e "运行状态: ${YELLOW}●${NC} $status"
    fi

    if [ "$enabled" = "enabled" ]; then
        echo -e "开机启动: ${GREEN}已启用${NC}"
    else
        echo -e "开机启动: ${YELLOW}未启用${NC}"
    fi

    echo ""
    echo -e "${BLUE}配置信息:${NC}"

    # 检查是否有规则配置
    local has_rules=false
    local enabled_count=0

    if [ -d "$RULES_DIR" ]; then
        for rule_file in "${RULES_DIR}"/rule-*.conf; do
            if [ -f "$rule_file" ]; then
                if read_rule_file "$rule_file" && [ "$ENABLED" = "true" ]; then
                    has_rules=true
                    enabled_count=$((enabled_count + 1))
                fi
            fi
        done
    fi

    if [ "$has_rules" = true ]; then
        echo -e "配置模式: ${GREEN}多规则模式${NC}"
        echo -e "启用规则: ${GREEN}$enabled_count${NC} 个"
        echo ""
        echo -e "${BLUE}活跃规则列表:${NC}"

        for rule_file in "${RULES_DIR}"/rule-*.conf; do
            if [ -f "$rule_file" ]; then
                if read_rule_file "$rule_file" && [ "$ENABLED" = "true" ]; then
                    # 根据规则角色使用不同的字段
                    if [ "$RULE_ROLE" = "2" ]; then
                        # 落地服务器使用FORWARD_TARGET
                        local target_host="${FORWARD_TARGET%:*}"
                        local target_port="${FORWARD_TARGET##*:}"
                        local display_target=$(smart_display_target "$target_host")
                        local display_ip="::"
                        echo -e "  ${GREEN}$RULE_NAME${NC}: ${LISTEN_IP:-$display_ip}:$LISTEN_PORT → $display_target:$target_port"
                    else
                        # 中转服务器使用REMOTE_HOST
                        local display_target=$(smart_display_target "$REMOTE_HOST")
                        local display_ip="${NAT_LISTEN_IP:-::}"
                        local through_display="${THROUGH_IP:-::}"
                        echo -e "  ${GREEN}$RULE_NAME${NC}: ${LISTEN_IP:-$display_ip}:$LISTEN_PORT → $through_display → $display_target:$REMOTE_PORT"
                    fi
                    # 构建安全级别显示
                    local security_display=$(get_security_display "$SECURITY_LEVEL" "$WS_PATH" "$WS_HOST")
                    local note_display=""
                    if [ -n "$RULE_NOTE" ]; then
                        note_display=" | 备注: ${GREEN}$RULE_NOTE${NC}"
                    fi
                    # 显示状态信息
                    get_rule_status_display "$security_display" "$note_display"

                fi
            fi
        done
    fi

    # 显示端口监听状态
    echo ""
    echo -e "${BLUE}端口监听状态:${NC}"

    local port_check_cmd="ss -tlnp"

    # 检查端口监听状态
    if [ "$has_rules" = true ]; then
        # 多规则模式：检查所有启用规则的端口
        for rule_file in "${RULES_DIR}"/rule-*.conf; do
            if [ -f "$rule_file" ]; then
                if read_rule_file "$rule_file" && [ "$ENABLED" = "true" ]; then
                    if [ "$RULE_ROLE" = "2" ]; then
                        local display_ip="::"
                    else
                        local display_ip="${NAT_LISTEN_IP:-::}"
                    fi
                    if $port_check_cmd 2>/dev/null | grep -q ":${LISTEN_PORT} "; then
                        echo -e "端口 ${LISTEN_IP:-$display_ip}:$LISTEN_PORT ($RULE_NAME): ${GREEN}正在监听${NC}"
                    else
                        echo -e "端口 ${LISTEN_IP:-$display_ip}:$LISTEN_PORT ($RULE_NAME): ${RED}未监听${NC}"
                    fi
                fi
            fi
        done
    fi

    echo ""
    echo -e "${BLUE}详细状态信息:${NC}"
    systemctl status realm --no-pager -l
}

# 卸载函数
uninstall_realm() {
    echo -e "${RED}⚠️  警告: 即将分阶段卸载 Realm 端口转发服务${NC}"
    echo ""

    # 第一阶段：Realm 服务和配置
    echo -e "${YELLOW}=== 第一阶段：Realm 相关全部服务和配置文件 ===${NC}"
    read -p "确认删除 Realm 服务和配置？(y/n): " confirm_realm
    if [[ "$confirm_realm" =~ ^[Yy]$ ]]; then
        uninstall_realm_stage_one
        echo -e "${GREEN}✓ 第一阶段完成${NC}"
    else
        echo -e "${BLUE}第一阶段已取消${NC}"
        return 0
    fi

    echo ""
    # 第二阶段：脚本文件
    echo -e "${YELLOW}=== 第二阶段：xwPF 脚本相关全部文件 ===${NC}"
    read -p "确认删除脚本文件？(y/n): " confirm_script
    if [[ "$confirm_script" =~ ^[Yy]$ ]]; then
        uninstall_script_files
        echo -e "${GREEN}🗑️  完全卸载完成${NC}"
    else
        echo -e "${BLUE}脚本文件保留，可继续使用 pf 命令${NC}"
    fi
}

# 第一阶段：清理 Realm 相关
uninstall_realm_stage_one() {
    # 停止服务
    systemctl is-active realm >/dev/null 2>&1 && systemctl stop realm
    systemctl is-enabled realm >/dev/null 2>&1 && systemctl disable realm >/dev/null 2>&1
    # 停止健康检查服务（通过xwFailover.sh）
    if [ -f "/etc/realm/xwFailover.sh" ]; then
        bash "/etc/realm/xwFailover.sh" stop >/dev/null 2>&1
    fi
    pgrep "realm" >/dev/null 2>&1 && { pkill -f "realm"; sleep 2; pkill -9 -f "realm" 2>/dev/null; }

    # 清理文件
    cleanup_files_by_paths "$REALM_PATH" "$CONFIG_DIR" "$SYSTEMD_PATH" "/etc/realm"
    cleanup_files_by_pattern "realm" "/var/log /tmp /var/tmp"

    # 清理xwFailover.sh相关文件
    rm -f "/etc/realm/xwFailover.sh"

    # 清理系统配置
    [ -f "/etc/sysctl.d/90-enable-MPTCP.conf" ] && rm -f "/etc/sysctl.d/90-enable-MPTCP.conf"
    command -v ip >/dev/null 2>&1 && ip mptcp endpoint flush 2>/dev/null
    systemctl daemon-reload
}

# 第二阶段：清理脚本文件
uninstall_script_files() {
    cleanup_files_by_pattern "xwPF.sh" "/"

    # 清理 pf 命令（验证后删除）
    local exec_dirs=("/usr/local/bin" "/usr/bin" "/bin" "/opt/bin" "/root/bin")
    for dir in "${exec_dirs[@]}"; do
        [ -f "$dir/pf" ] && grep -q "xwPF" "$dir/pf" 2>/dev/null && rm -f "$dir/pf"
        [ -L "$dir/pf" ] && [[ "$(readlink "$dir/pf" 2>/dev/null)" == *"xwPF"* ]] && rm -f "$dir/pf"
    done
}

# 文件路径清理函数
cleanup_files_by_paths() {
    for path in "$@"; do
        if [ -f "$path" ]; then
            rm -f "$path"
        elif [ -d "$path" ]; then
            rm -rf "$path"
        fi
    done
}

# 文件模式清理函数
cleanup_files_by_pattern() {
    local pattern="$1"
    local search_dirs="${2:-/}"

    IFS=' ' read -ra dirs_array <<< "$search_dirs"
    for dir in "${dirs_array[@]}"; do
        [ -d "$dir" ] && find "$dir" -name "*${pattern}*" -type f 2>/dev/null | while read -r file; do
            [ -f "$file" ] && rm -f "$file"
        done &
    done
    wait
}

# 查看当前配置
show_config() {
    echo -e "${YELLOW}=== 当前配置信息 ===${NC}"
    echo ""

    # 检查配置文件是否存在
    if [ ! -f "$CONFIG_PATH" ]; then
        echo -e "${RED}配置文件不存在，请先运行安装配置${NC}"
        return 1
    fi

    # 显示配置文件路径
    echo -e "${BLUE}配置文件位置:${NC}"
    echo -e "  主配置: ${GREEN}$CONFIG_PATH${NC}"
    echo -e "  管理配置: ${GREEN}$MANAGER_CONF${NC}"
    echo -e "  规则目录: ${GREEN}$RULES_DIR${NC}"
    echo ""

    # 显示规则信息
    if [ -d "$RULES_DIR" ]; then
        local total_rules=0
        local enabled_rules=0

        for rule_file in "${RULES_DIR}"/rule-*.conf; do
            if [ -f "$rule_file" ]; then
                total_rules=$((total_rules + 1))
                if read_rule_file "$rule_file" && [ "$ENABLED" = "true" ]; then
                    enabled_rules=$((enabled_rules + 1))
                fi
            fi
        done

        echo -e "${BLUE}规则统计:${NC}"
        echo -e "  总规则数: ${GREEN}$total_rules${NC}"
        echo -e "  启用规则: ${GREEN}$enabled_rules${NC}"
        echo -e "  禁用规则: ${YELLOW}$((total_rules - enabled_rules))${NC}"
        echo ""

        if [ $total_rules -gt 0 ]; then
            echo -e "${BLUE}规则详情:${NC}"
            for rule_file in "${RULES_DIR}"/rule-*.conf; do
                if [ -f "$rule_file" ]; then
                    if read_rule_file "$rule_file"; then
                        local status_color="${GREEN}"
                        local status_text="启用"
                        if [ "$ENABLED" != "true" ]; then
                            status_color="${RED}"
                            status_text="禁用"
                        fi

                        echo -e "  规则 $RULE_ID: ${status_color}$status_text${NC} - $RULE_NAME"
                        # 根据规则角色使用不同的字段
                        if [ "$RULE_ROLE" = "2" ]; then
                            # 落地服务器使用FORWARD_TARGET
                            local target_host="${FORWARD_TARGET%:*}"
                            local target_port="${FORWARD_TARGET##*:}"
                            local display_target=$(smart_display_target "$target_host")
                            local display_ip="::"
                            echo -e "    监听: ${LISTEN_IP:-$display_ip}:$LISTEN_PORT → $display_target:$target_port"
                        else
                            # 中转服务器使用REMOTE_HOST
                            local display_target=$(smart_display_target "$REMOTE_HOST")
                            local display_ip="${NAT_LISTEN_IP:-::}"
                            local through_display="${THROUGH_IP:-::}"
                            echo -e "    中转: ${LISTEN_IP:-$display_ip}:$LISTEN_PORT → $through_display → $display_target:$REMOTE_PORT"
                        fi
                        local security_display=$(get_security_display "$SECURITY_LEVEL" "$WS_PATH" "$WS_HOST")
                        local note_display=""
                        if [ -n "$RULE_NOTE" ]; then
                            note_display=" | 备注: ${GREEN}$RULE_NOTE${NC}"
                        fi
                        # 显示状态信息
                        get_rule_status_display "$security_display" "$note_display"
                        echo ""
                    fi
                fi
            done
        fi
    else
        echo -e "${BLUE}规则信息:${NC} 使用传统配置模式"
        echo ""
    fi
}

# 显示转发目标地址（处理本地地址和多地址）
smart_display_target() {
    local target="$1"

    # 处理多地址情况
    if [[ "$target" == *","* ]]; then
        # 分割多地址
        IFS=',' read -ra addresses <<< "$target"
        local display_addresses=()

        for addr in "${addresses[@]}"; do
            addr=$(echo "$addr" | xargs)  # 去除空格
            local display_addr="$addr"

            if [[ "$addr" == "127.0.0.1" ]] || [[ "$addr" == "localhost" ]]; then
                # IPv4本地地址时显示IPv4公网IP
                local public_ipv4=$(get_public_ip ipv4)
                if [ -n "$public_ipv4" ]; then
                    display_addr="$public_ipv4"
                fi
            elif [[ "$addr" == "::1" ]]; then
                # IPv6本地地址时显示IPv6公网IP
                local public_ipv6=$(get_public_ip ipv6)
                if [ -n "$public_ipv6" ]; then
                    display_addr="$public_ipv6"
                fi
            fi

            display_addresses+=("$display_addr")
        done

        # 重新组合地址
        local result=""
        for i in "${!display_addresses[@]}"; do
            if [ $i -gt 0 ]; then
                result="$result,"
            fi
            result="$result${display_addresses[i]}"
        done
        echo "$result"
    else
        # 单地址处理
        if [[ "$target" == "127.0.0.1" ]] || [[ "$target" == "localhost" ]]; then
            # IPv4本地地址时显示IPv4公网IP
            local public_ipv4=$(get_public_ip ipv4)
            if [ -n "$public_ipv4" ]; then
                echo "$public_ipv4"
            else
                echo "$target"
            fi
        elif [[ "$target" == "::1" ]]; then
            # IPv6本地地址时显示IPv6公网IP
            local public_ipv6=$(get_public_ip ipv6)
            if [ -n "$public_ipv6" ]; then
                echo "$public_ipv6"
            else
                echo "$target"
            fi
        else
            echo "$target"
        fi
    fi
}

# 显示简要状态信息（避免网络请求）
show_brief_status() {
    echo ""
    echo -e "${BLUE}=== 当前状态 ===${NC}"

    # 检查 realm 二进制文件是否存在
    if [ ! -f "${REALM_PATH}" ] || [ ! -x "${REALM_PATH}" ]; then
        echo -e " Realm状态：${RED} 未安装 ${NC}"
        echo -e "${YELLOW}请选择 1. 安装(更新)程序,脚本 ${NC}"
        return
    fi

    # 检查配置文件是否存在
    if [ ! -f "$CONFIG_PATH" ]; then
        echo -e "${YELLOW}=== 配置缺失 ===${NC}"
        echo -e "${BLUE}Realm 已安装但配置缺失，请运行 安装配置/添加配置 来初始化配置${NC}"
        return
    fi

    # 正常状态显示
    local status=$(systemctl is-active realm 2>/dev/null)
    if [ "$status" = "active" ]; then
        echo -e "服务状态: ${GREEN}●${NC} 运行中"
    else
        echo -e "服务状态: ${RED}●${NC} 已停止"
    fi

    # 检查是否有多规则配置
    local has_rules=false
    local enabled_count=0
    local disabled_count=0
    if [ -d "$RULES_DIR" ]; then
        for rule_file in "${RULES_DIR}"/rule-*.conf; do
            if [ -f "$rule_file" ]; then
                if read_rule_file "$rule_file"; then
                    if [ "$ENABLED" = "true" ]; then
                        has_rules=true
                        enabled_count=$((enabled_count + 1))
                    else
                        disabled_count=$((disabled_count + 1))
                    fi
                fi
            fi
        done
    fi

    if [ "$has_rules" = true ] || [ "$disabled_count" -gt 0 ]; then
        # 多规则模式
        local total_count=$((enabled_count + disabled_count))
        echo -e "配置模式: ${GREEN}多规则模式${NC} (${GREEN}$enabled_count${NC} 启用 / ${YELLOW}$disabled_count${NC} 禁用 / 共 $total_count 个)"

        # 按服务器类型分组显示启用的规则
        if [ "$enabled_count" -gt 0 ]; then
            # 中转服务器规则
            local has_relay_rules=false
            local relay_count=0
            for rule_file in "${RULES_DIR}"/rule-*.conf; do
                if [ -f "$rule_file" ]; then
                    if read_rule_file "$rule_file" && [ "$ENABLED" = "true" ] && [ "$RULE_ROLE" = "1" ]; then
                        if [ "$has_relay_rules" = false ]; then
                            echo -e "${GREEN}中转服务器:${NC}"
                            has_relay_rules=true
                        fi
                        relay_count=$((relay_count + 1))
                        # 显示详细的转发配置信息
                        local security_display=$(get_security_display "$SECURITY_LEVEL" "$WS_PATH" "$WS_HOST")
                        local display_target=$(smart_display_target "$REMOTE_HOST")
                        local rule_display_name="$RULE_NAME"
                        local display_ip="${NAT_LISTEN_IP:-::}"
                        local through_display="${THROUGH_IP:-::}"
                        echo -e "  • ${GREEN}$rule_display_name${NC}: ${LISTEN_IP:-$display_ip}:$LISTEN_PORT → $through_display → $display_target:$REMOTE_PORT"
                        local note_display=""
                        if [ -n "$RULE_NOTE" ]; then
                            note_display=" | 备注: ${GREEN}$RULE_NOTE${NC}"
                        fi
                        # 显示状态信息
                        get_rule_status_display "$security_display" "$note_display"

                    fi
                fi
            done

            # 落地服务器规则
            local has_exit_rules=false
            local exit_count=0
            for rule_file in "${RULES_DIR}"/rule-*.conf; do
                if [ -f "$rule_file" ]; then
                    if read_rule_file "$rule_file" && [ "$ENABLED" = "true" ] && [ "$RULE_ROLE" = "2" ]; then
                        if [ "$has_exit_rules" = false ]; then
                            if [ "$has_relay_rules" = true ]; then
                                echo ""
                            fi
                            echo -e "${GREEN}落地服务器 (双端Realm架构):${NC}"
                            has_exit_rules=true
                        fi
                        exit_count=$((exit_count + 1))
                        # 显示详细的转发配置信息
                        local security_display=$(get_security_display "$SECURITY_LEVEL" "$WS_PATH" "$WS_HOST")
                        # 落地服务器使用FORWARD_TARGET而不是REMOTE_HOST
                        local target_host="${FORWARD_TARGET%:*}"
                        local target_port="${FORWARD_TARGET##*:}"
                        local display_target=$(smart_display_target "$target_host")
                        local rule_display_name="$RULE_NAME"
                        local display_ip="::"
                        echo -e "  • ${GREEN}$rule_display_name${NC}: ${LISTEN_IP:-$display_ip}:$LISTEN_PORT → $display_target:$target_port"
                        local note_display=""
                        if [ -n "$RULE_NOTE" ]; then
                            note_display=" | 备注: ${GREEN}$RULE_NOTE${NC}"
                        fi
                        # 显示状态信息
                        get_rule_status_display "$security_display" "$note_display"

                    fi
                fi
            done
        fi

        # 显示禁用的规则（简要）
        if [ "$disabled_count" -gt 0 ]; then
            echo -e "${YELLOW}禁用的规则:${NC}"
            for rule_file in "${RULES_DIR}"/rule-*.conf; do
                if [ -f "$rule_file" ]; then
                    if read_rule_file "$rule_file" && [ "$ENABLED" = "false" ]; then
                        # 根据规则角色使用不同的字段
                        if [ "$RULE_ROLE" = "2" ]; then
                            # 落地服务器使用FORWARD_TARGET
                            local target_host="${FORWARD_TARGET%:*}"
                            local target_port="${FORWARD_TARGET##*:}"
                            local display_target=$(smart_display_target "$target_host")
                            echo -e "  • ${WHITE}$RULE_NAME${NC}: $LISTEN_PORT → $display_target:$target_port (已禁用)"
                        else
                            # 中转服务器使用REMOTE_HOST
                            local display_target=$(smart_display_target "$REMOTE_HOST")
                            local through_display="${THROUGH_IP:-::}"
                            echo -e "  • ${WHITE}$RULE_NAME${NC}: $LISTEN_PORT → $through_display → $display_target:$REMOTE_PORT (已禁用)"
                        fi
                    fi
                fi
            done
        fi
    else
        echo -e "转发规则: ${YELLOW}暂无${NC} (可通过 '转发配置管理' 添加)"
    fi
    echo ""
}

# 获取安全级别显示文本
get_security_display() {
    local security_level="$1"
    local ws_path="$2"
    local tls_server_name="$3"

    case "$security_level" in
        "standard")
            echo "默认传输"
            ;;
        "ws")
            echo "ws (host: $tls_server_name) (路径: $ws_path)"
            ;;
        "tls_self")
            local display_sni="${tls_server_name:-$DEFAULT_SNI_DOMAIN}"
            echo "TLS自签证书 (SNI: $display_sni)"
            ;;
        "tls_ca")
            echo "TLS CA证书 (域名: $tls_server_name)"
            ;;
        "ws_tls_self")
            local display_sni="${TLS_SERVER_NAME:-$DEFAULT_SNI_DOMAIN}"
            echo "wss 自签证书 (host: $tls_server_name) (路径: $ws_path) (SNI: $display_sni)"
            ;;
        "ws_tls_ca")
            local display_sni="${TLS_SERVER_NAME:-$DEFAULT_SNI_DOMAIN}"
            echo "wss CA证书 (host: $tls_server_name) (路径: $ws_path) (SNI: $display_sni)"
            ;;
        "ws_"*)
            echo "$security_level (路径: $ws_path)"
            ;;
        *)
            echo "$security_level"
            ;;
    esac
}

get_gmt8_time() {
    TZ='GMT-8' date "$@"
}

# 下载故障转移管理脚本
download_failover_script() {
    local script_url="https://raw.githubusercontent.com/zywe03/realm-xwPF/main/xwFailover.sh"
    local target_path="/etc/realm/xwFailover.sh"

    echo -e "${GREEN}正在下载最新故障转移脚本...${NC}"

    mkdir -p "$(dirname "$target_path")"

    if download_from_sources "$script_url" "$target_path"; then
        chmod +x "$target_path"
        return 0
    else
        echo -e "${RED}请检查网络连接${NC}"
        return 1
    fi
}

# 下载中转网络链路测试脚本
download_speedtest_script() {
    local script_url="https://raw.githubusercontent.com/zywe03/realm-xwPF/main/speedtest.sh"
    local target_path="/etc/realm/speedtest.sh"

    echo -e "${GREEN}正在下载最新测速脚本...${NC}"

    mkdir -p "$(dirname "$target_path")"

    if download_from_sources "$script_url" "$target_path"; then
        chmod +x "$target_path"
        return 0
    else
        echo -e "${RED}请检查网络连接${NC}"
        return 1
    fi
}
# 中转网络链路测试菜单
speedtest_menu() {
    local speedtest_script="/etc/realm/speedtest.sh"

    if ! download_speedtest_script; then
        echo -e "${RED}无法下载测速脚本，功能暂时不可用${NC}"
        read -p "按回车键返回主菜单..."
        return 1
    fi

    echo -e "${BLUE}启动测速工具...${NC}"
    echo ""
    bash "$speedtest_script"

    echo ""
    read -p "按回车键返回主菜单..."
}

# 故障转移管理菜单
failover_management_menu() {
    local failover_script="/etc/realm/xwFailover.sh"

    if ! download_failover_script; then
        echo -e "${RED}无法下载故障转移脚本，功能暂时不可用${NC}"
        read -p "按回车键返回主菜单..."
        return 1
    fi

    # 直接调用故障转移配置功能
    bash "$failover_script" toggle
}

# 端口流量狗
port_traffic_dog_menu() {
    local script_url="https://raw.githubusercontent.com/zywe03/realm-xwPF/main/port-traffic-dog.sh"
    local dog_script="/usr/local/bin/port-traffic-dog.sh"

    # 脚本不存在或不可执行时才下载
    if [[ ! -f "$dog_script" || ! -x "$dog_script" ]]; then
        echo -e "${GREEN}正在下载端口流量狗脚本...${NC}"
        mkdir -p "$(dirname "$dog_script")"
        if ! download_from_sources "$script_url" "$dog_script"; then
            echo -e "${RED}无法下载端口流量狗脚本，请检查网络连接${NC}"
            read -p "按回车键返回主菜单..."
            return 1
        fi
        chmod +x "$dog_script"
    fi

    echo -e "${BLUE}启动端口流量狗...${NC}"
    echo ""
    bash "$dog_script"
    echo ""
    read -p "按回车键返回主菜单..."
}

show_menu() {
    while true; do
        clear
        echo -e "${GREEN}=== xwPF Realm全功能一键脚本 $SCRIPT_VERSION ===${NC}"
        echo -e "${GREEN}作者主页:https://zywe.de${NC}"
        echo -e "${GREEN}项目开源:https://github.com/zywe03/realm-xwPF${NC}"
        echo -e "${GREEN}一个开箱即用、轻量可靠、灵活可控的 Realm 转发管理工具${NC}"
        echo -e "${GREEN}官方realm的全部功能+故障转移 | 快捷命令: pf${NC}"

        show_brief_status

        echo "请选择操作:"
        echo -e "${GREEN}1.${NC} 安装(更新)程序,脚本"
        echo -e "${BLUE}2.${NC} 转发配置管理"
        echo -e "${GREEN}3.${NC} 重启服务"
        echo -e "${GREEN}4.${NC} 停止服务"
        echo -e "${GREEN}5.${NC} 查看日志"
        echo -e "${BLUE}6.${NC} 端口流量狗（统计端口流量）"
        echo -e "${BLUE}7.${NC} 中转网络链路测试"
        echo -e "${RED}8.${NC} 卸载服务"
        echo -e "${YELLOW}0.${NC} 退出"
        echo ""

        read -p "请输入选择 [0-8]: " choice
        echo ""

        case $choice in
            1)
                smart_install
                exit 0
                ;;
            2)
                check_dependencies
                rules_management_menu
                ;;
            3)
                check_dependencies
                service_restart
                read -p "按回车键继续..."
                ;;
            4)
                check_dependencies
                service_stop
                read -p "按回车键继续..."
                ;;
            5)
                check_dependencies
                echo -e "${YELLOW}实时查看 Realm 日志 (按 Ctrl+C 返回菜单):${NC}"
                echo ""
                journalctl -u realm -f --no-pager
                ;;
            6)
                port_traffic_dog_menu
                ;;
            7)
                check_dependencies
                speedtest_menu
                ;;
            8)
                check_dependencies
                uninstall_realm
                read -p "按回车键继续..."
                ;;
            0)
                echo -e "${BLUE}感谢使用xwPF 网络转发管理脚本！${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}无效选择，请输入 0-8${NC}"
                read -p "按回车键继续..."
                ;;
        esac
    done
}

# 内置清理机制
cleanup_temp_files() {
    # 清理缓存文件（>10MB截断保留5MB）
    local cache_file="/tmp/realm_path_cache"
    if [ -f "$cache_file" ]; then
        local size=$(stat -c%s "$cache_file" 2>/dev/null || echo 0)
        if [ "$size" -gt 10485760 ]; then
            tail -c 5242880 "$cache_file" > "$cache_file.tmp" && mv "$cache_file.tmp" "$cache_file" 2>/dev/null
        fi
    fi

    # 清理过期标记文件（>5分钟）
    find /tmp -name "realm_config_update_needed" -mmin +5 -delete 2>/dev/null

    # 清理realm临时文件（>60分钟）
    find /tmp -name "*realm*" -type f -mmin +60 ! -path "*/realm/config*" ! -path "*/realm/rules*" -delete 2>/dev/null
}

# ---- 主逻辑 ----
main() {
    # 内置清理：启动时清理临时文件
    cleanup_temp_files

    # 检查特殊参数
    if [ "$1" = "--generate-config-only" ]; then
        # 只生成配置文件，不显示菜单
        generate_realm_config
        exit 0
    elif [ "$1" = "--restart-service" ]; then
        # 重启服务接口（供外部调用）
        service_restart
        exit $?
    fi

    check_root

    case "$1" in
        install)
            # 安装模式：自动安装依赖和脚本
            smart_install
            ;;
        *)
            # 默认显示菜单界面
            show_menu
            ;;
    esac
}


# 权重配置管理菜单
weight_management_menu() {
    while true; do
        clear
        echo -e "${GREEN}=== 权重配置管理 ===${NC}"
        echo ""

        # 按端口分组收集启用负载均衡的中转服务器规则
        declare -A port_groups
        declare -A port_configs
        declare -A port_weights
        declare -A port_balance_modes

        for rule_file in "${RULES_DIR}"/rule-*.conf; do
            if [ -f "$rule_file" ]; then
                if read_rule_file "$rule_file" && [ "$RULE_ROLE" = "1" ] && [ "$BALANCE_MODE" != "off" ]; then
                    local port_key="$LISTEN_PORT"

                    # 存储端口配置（优先使用包含完整权重的规则）
                    if [ -z "${port_configs[$port_key]}" ]; then
                        port_configs[$port_key]="$RULE_NAME"
                        port_weights[$port_key]="$WEIGHTS"
                        port_balance_modes[$port_key]="$BALANCE_MODE"
                    elif [[ "$WEIGHTS" == *","* ]] && [[ "${port_weights[$port_key]}" != *","* ]]; then
                        # 如果当前规则有完整权重而已存储的没有，更新为完整权重
                        port_weights[$port_key]="$WEIGHTS"
                    fi

                    # 正确处理REMOTE_HOST中可能包含多个地址的情况
                    if [[ "$REMOTE_HOST" == *","* ]]; then
                        # REMOTE_HOST包含多个地址，分别添加
                        IFS=',' read -ra host_array <<< "$REMOTE_HOST"
                        for host in "${host_array[@]}"; do
                            local target="$host:$REMOTE_PORT"
                            # 检查是否已存在，避免重复添加
                            if [[ "${port_groups[$port_key]}" != *"$target"* ]]; then
                                if [ -z "${port_groups[$port_key]}" ]; then
                                    port_groups[$port_key]="$target"
                                else
                                    port_groups[$port_key]="${port_groups[$port_key]},$target"
                                fi
                            fi
                        done
                    else
                        # REMOTE_HOST是单个地址
                        local target="$REMOTE_HOST:$REMOTE_PORT"
                        # 检查是否已存在，避免重复添加
                        if [[ "${port_groups[$port_key]}" != *"$target"* ]]; then
                            if [ -z "${port_groups[$port_key]}" ]; then
                                port_groups[$port_key]="$target"
                            else
                                port_groups[$port_key]="${port_groups[$port_key]},$target"
                            fi
                        fi
                    fi
                fi
            fi
        done

        # 检查是否有需要权重配置的端口组（多目标服务器）
        local has_balance_rules=false
        local rule_ports=()
        local rule_names=()

        for port_key in "${!port_groups[@]}"; do
            # 计算目标服务器总数
            IFS=',' read -ra targets <<< "${port_groups[$port_key]}"
            local target_count=${#targets[@]}

            # 只显示有多个目标服务器的端口组
            if [ "$target_count" -gt 1 ]; then
                if [ "$has_balance_rules" = false ]; then
                    echo "请选择要配置权重的规则组 (仅显示多目标服务器的负载均衡规则):"
                    has_balance_rules=true
                fi

                # 使用数字ID
                local rule_number=$((${#rule_ports[@]} + 1))
                rule_ports+=("$port_key")
                rule_names+=("${port_configs[$port_key]}")

                local balance_mode="${port_balance_modes[$port_key]}"
                echo -e "${GREEN}$rule_number.${NC} ${port_configs[$port_key]} (端口: $port_key) [$balance_mode] - $target_count个目标服务器"
            fi
        done

        if [ "$has_balance_rules" = false ]; then
            echo -e "${YELLOW}暂无需要权重配置的规则组${NC}"
            echo ""
            echo -e "${BLUE}权重配置的前提条件：${NC}"
            echo -e "  1. 必须是中转服务器规则"
            echo -e "  2. 必须已启用负载均衡模式 (roundrobin/iphash)"
            echo -e "  3. 必须有多个目标服务器"
            echo ""
            echo -e "${YELLOW}如果您有多目标规则但未启用负载均衡：${NC}"
            echo -e "  请先选择 '切换负载均衡模式' 启用负载均衡，然后再配置权重"
            echo ""
            read -p "按回车键返回..."
            return
        fi

        echo ""
        echo -e "${GRAY}注意: 只有多个目标服务器的规则组才需要权重配置${NC}"
        echo ""
        read -p "请输入规则编号 [1-${#rule_ports[@]}] (或按回车返回): " selected_number

        if [ -z "$selected_number" ]; then
            break
        fi

        # 验证数字输入
        if ! [[ "$selected_number" =~ ^[0-9]+$ ]] || [ "$selected_number" -lt 1 ] || [ "$selected_number" -gt ${#rule_ports[@]} ]; then
            echo -e "${RED}无效的规则编号${NC}"
            read -p "按回车键继续..."
            continue
        fi

        # 计算数组索引（从0开始）
        local selected_index=$((selected_number - 1))

        # 配置选中端口组的权重
        local selected_port="${rule_ports[$selected_index]}"
        local selected_name="${rule_names[$selected_index]}"
        configure_port_group_weights "$selected_port" "$selected_name" "${port_groups[$selected_port]}" "${port_weights[$selected_port]}"
    done
}

# 配置端口组权重
configure_port_group_weights() {
    local port="$1"
    local rule_name="$2"
    local targets_str="$3"
    local current_weights_str="$4"

    clear
    echo -e "${GREEN}=== 权重配置: $rule_name ===${NC}"
    echo ""

    # 解析目标服务器
    IFS=',' read -ra targets <<< "$targets_str"
    local target_count=${#targets[@]}

    echo "规则组: $rule_name (端口: $port)"
    echo "目标服务器列表:"

    # 解析当前权重
    local current_weights
    if [ -n "$current_weights_str" ]; then
        IFS=',' read -ra current_weights <<< "$current_weights_str"
    else
        # 默认相等权重
        for ((i=0; i<target_count; i++)); do
            current_weights[i]=1
        done
    fi

    # 显示当前配置
    for ((i=0; i<target_count; i++)); do
        local weight="${current_weights[i]:-1}"
        echo -e "  $((i+1)). ${targets[i]} [当前权重: $weight]"
    done

    echo ""
    echo "请输入权重序列 (用逗号分隔):"
    echo -e "${WHITE}格式说明: 按服务器顺序输入权重值，如 \"2,1,3\"${NC}"
    echo -e "${WHITE}权重范围: 1-10，数值越大分配流量越多${NC}"
    echo ""

    read -p "权重序列: " weight_input

    if [ -z "$weight_input" ]; then
        echo -e "${YELLOW}未输入权重，保持原配置${NC}"
        read -p "按回车键返回..."
        return
    fi

    if ! validate_weight_input "$weight_input" "$target_count"; then
        read -p "按回车键返回..."
        return
    fi

    # 预览配置
    preview_port_group_weight_config "$port" "$rule_name" "$weight_input" "${targets[@]}"
}

# 验证权重输入
validate_weight_input() {
    local weight_input="$1"
    local expected_count="$2"

    # 检查格式
    if ! [[ "$weight_input" =~ ^[0-9]+(,[0-9]+)*$ ]]; then
        echo -e "${RED}权重格式错误，请使用数字和逗号，如: 2,1,3${NC}"
        return 1
    fi

    # 解析权重数组
    IFS=',' read -ra weights <<< "$weight_input"

    # 检查数量
    if [ "${#weights[@]}" -ne "$expected_count" ]; then
        echo -e "${RED}权重数量不匹配，需要 $expected_count 个权重值，实际输入 ${#weights[@]} 个${NC}"
        return 1
    fi

    # 检查权重值范围
    for weight in "${weights[@]}"; do
        if [ "$weight" -lt 1 ] || [ "$weight" -gt 10 ]; then
            echo -e "${RED}权重值 $weight 超出范围，请使用 1-10 之间的数值${NC}"
            return 1
        fi
    done

    return 0
}

# 预览端口组权重配置
preview_port_group_weight_config() {
    local port="$1"
    local rule_name="$2"
    local weight_input="$3"
    shift 3
    local targets=("$@")

    clear
    echo -e "${GREEN}=== 配置预览 ===${NC}"
    echo ""
    echo "规则组: $rule_name (端口: $port)"
    echo "权重配置变更:"

    # 获取当前权重（从第一个相关规则文件读取）
    local current_weights
    local first_rule_file=""
    for rule_file in "${RULES_DIR}"/rule-*.conf; do
        if [ -f "$rule_file" ]; then
            if read_rule_file "$rule_file" && [ "$RULE_ROLE" = "1" ] && [ "$LISTEN_PORT" = "$port" ]; then
                first_rule_file="$rule_file"
                if [ -n "$WEIGHTS" ]; then
                    if [[ "$WEIGHTS" == *","* ]]; then
                        # 完整权重字符串
                        IFS=',' read -ra current_weights <<< "$WEIGHTS"
                    else
                        # 单个权重值，需要查找完整权重
                        local found_full_weights=false
                        for check_rule_file in "${RULES_DIR}"/rule-*.conf; do
                            if [ -f "$check_rule_file" ]; then
                                if read_rule_file "$check_rule_file" && [ "$RULE_ROLE" = "1" ] && [ "$LISTEN_PORT" = "$port" ] && [[ "$WEIGHTS" == *","* ]]; then
                                    IFS=',' read -ra current_weights <<< "$WEIGHTS"
                                    found_full_weights=true
                                    break
                                fi
                            fi
                        done

                        if [ "$found_full_weights" = false ]; then
                            # 默认相等权重
                            for ((i=0; i<${#targets[@]}; i++)); do
                                current_weights[i]=1
                            done
                        fi
                    fi
                else
                    # 默认相等权重
                    for ((i=0; i<${#targets[@]}; i++)); do
                        current_weights[i]=1
                    done
                fi
                break
            fi
        fi
    done

    # 解析新权重
    IFS=',' read -ra new_weights <<< "$weight_input"

    # 计算总权重
    local total_weight=0
    for weight in "${new_weights[@]}"; do
        total_weight=$((total_weight + weight))
    done

    # 显示变更详情
    for ((i=0; i<${#targets[@]}; i++)); do
        local old_weight="${current_weights[i]:-1}"
        local new_weight="${new_weights[i]}"
        local percentage
        if command -v bc >/dev/null 2>&1; then
            percentage=$(echo "scale=1; $new_weight * 100 / $total_weight" | bc 2>/dev/null || echo "0.0")
        else
            percentage=$(awk "BEGIN {printf \"%.1f\", $new_weight * 100 / $total_weight}")
        fi

        if [ "$old_weight" != "$new_weight" ]; then
            echo -e "  $((i+1)). ${targets[i]}: $old_weight → ${GREEN}$new_weight${NC} ${BLUE}($percentage%)${NC}"
        else
            echo -e "  $((i+1)). ${targets[i]}: $new_weight ${BLUE}($percentage%)${NC}"
        fi
    done

    echo ""
    read -p "确认应用此配置? [y/n]: " confirm

    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        # 应用权重配置到该端口的所有相关规则
        apply_port_group_weight_config "$port" "$weight_input"
    else
        echo -e "${YELLOW}已取消配置更改${NC}"
        read -p "按回车键返回..."
    fi
}

# 应用端口组权重配置
apply_port_group_weight_config() {
    local port="$1"
    local weight_input="$2"

    local updated_count=0

    # 更新该端口的所有相关规则文件
    for rule_file in "${RULES_DIR}"/rule-*.conf; do
        if [ -f "$rule_file" ]; then
            if read_rule_file "$rule_file" && [ "$RULE_ROLE" = "1" ] && [ "$LISTEN_PORT" = "$port" ]; then
                # 更新规则文件中的权重配置
                # 对于第一个规则，存储完整权重；对于其他规则，存储对应的单个权重
                local rule_index=0
                local target_weight="$weight_input"

                # 计算当前规则在同端口规则中的索引
                for check_rule_file in "${RULES_DIR}"/rule-*.conf; do
                    if [ -f "$check_rule_file" ]; then
                        if read_rule_file "$check_rule_file" && [ "$RULE_ROLE" = "1" ] && [ "$LISTEN_PORT" = "$port" ]; then
                            if [ "$check_rule_file" = "$rule_file" ]; then
                                break
                            fi
                            rule_index=$((rule_index + 1))
                        fi
                    fi
                done

                # 根据规则索引确定要存储的权重
                if [ $rule_index -eq 0 ]; then
                    # 第一个规则存储完整权重
                    target_weight="$weight_input"
                else
                    # 其他规则存储对应位置的单个权重
                    IFS=',' read -ra weight_array <<< "$weight_input"
                    target_weight="${weight_array[$rule_index]:-1}"
                fi

                if grep -q "^WEIGHTS=" "$rule_file"; then
                    # 更新现有的WEIGHTS字段
                    if command -v sed >/dev/null 2>&1; then
                        sed -i.bak "s/^WEIGHTS=.*/WEIGHTS=\"$target_weight\"/" "$rule_file" && rm -f "$rule_file.bak"
                    else
                        # 如果没有sed，使用awk替代
                        awk -v new_weights="WEIGHTS=\"$target_weight\"" '
                            /^WEIGHTS=/ { print new_weights; next }
                            { print }
                        ' "$rule_file" > "$rule_file.tmp" && mv "$rule_file.tmp" "$rule_file"
                    fi
                else
                    # 如果没有WEIGHTS字段，在文件末尾添加
                    echo "WEIGHTS=\"$target_weight\"" >> "$rule_file"
                fi
                updated_count=$((updated_count + 1))
            fi
        fi
    done

    if [ $updated_count -gt 0 ]; then
        echo -e "${GREEN}✓ 已更新 $updated_count 个规则文件的权重配置${NC}"
        echo -e "${YELLOW}正在重启服务以应用更改...${NC}"

        if service_restart; then
            echo -e "${GREEN}✓ 服务重启成功，权重配置已生效${NC}"
        else
            echo -e "${RED}✗ 服务重启失败，请检查配置${NC}"
        fi
    else
        echo -e "${RED}✗ 未找到相关规则文件${NC}"
    fi

    read -p "按回车键返回..."
}

main "$@"
