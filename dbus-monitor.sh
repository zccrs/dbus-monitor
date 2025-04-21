#!/bin/bash

# 颜色定义
BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# 错误处理函数
handle_error() {
    echo -e "${RED}错误: $1${NC}" >&2
}

# 检查必要的命令是否存在
for cmd in dbus-monitor dbus-send awk; do
    if ! command -v $cmd >/dev/null 2>&1; then
        handle_error "找不到命令: $cmd"
        exit 1
    fi
done

# 检查是否有 root 权限
check_root() {
    if [ "$EUID" -ne 0 ]; then
        handle_error "监控 system bus 需要 root 权限"
        return 1
    fi
    return 0
}

# 获取 DBus 服务的实际名称
get_service_name() {
    local bus_type="$1"
    local bus_id="$2"

    if [[ "$bus_id" =~ ^: ]]; then
        # 首先尝试获取服务的所有名称
        local names
        names=$(dbus-send --"$bus_type" --dest=org.freedesktop.DBus --type=method_call --print-reply \
            /org/freedesktop/DBus org.freedesktop.DBus.ListNames 2>/dev/null)

        if [ $? -eq 0 ]; then
            # 查找匹配的服务名称
            local real_name
            real_name=$(echo "$names" | awk -v id="$bus_id" '
                /string/ {
                    name=$2
                    gsub(/"/, "", name)
                    if (name !~ /^:/) {
                        # 检查这个名称是否属于目标服务
                        cmd = "dbus-send --" ENVIRON["bus_type"] " --dest=org.freedesktop.DBus --type=method_call --print-reply /org/freedesktop/DBus org.freedesktop.DBus.GetNameOwner string:" name " 2>/dev/null"
                        if ((cmd | getline owner) > 0) {
                            if (owner ~ id) {
                                print name
                                exit
                            }
                        }
                        close(cmd)
                    }
                }
            ')

            if [ ! -z "$real_name" ]; then
                echo "$real_name"
                return
            fi
        fi
    fi

    # 如果找不到实际名称，返回原始ID
    echo "$bus_id"
}

# 提取 DBus 消息中的目标服务名
extract_destination() {
    echo "$1" | sed -n 's/.*destination=\([^ ]*\).*/\1/p'
}

# 提取 DBus 消息中的路径
extract_path() {
    echo "$1" | sed -n 's/.*path=\([^;]*\).*/\1/p'
}

# 提取 DBus 消息中的接口
extract_interface() {
    echo "$1" | sed -n 's/.*interface=\([^;]*\).*/\1/p'
}

# 判断是否为需要忽略的接口或服务
should_ignore() {
    local interface="$1"
    local service="$2"
    local path="$3"

    # 忽略输入法相关的调用
    [[ "$interface" == *"fcitx"* ]] && return 0
    [[ "$interface" == *"inputcontext"* ]] && return 0
    [[ "$service" == *"fcitx"* ]] && return 0

    # 忽略一些常见的系统调用
    [[ "$interface" == "org.freedesktop.DBus.Properties" ]] && return 0
    [[ "$interface" == "org.freedesktop.DBus.Introspectable" ]] && return 0
    [[ "$path" == "/org/freedesktop/DBus" && "$interface" == "org.freedesktop.DBus" ]] && return 0

    # 忽略一些频繁的空闲监控调用
    [[ "$interface" == *"IdleMonitor"* ]] && return 0

    return 1
}

# 生成调用的唯一标识符
generate_call_id() {
    local cmdline="$1"
    local service="$2"
    local path="$3"
    local interface="$4"
    echo "$cmdline|$service|$path|$interface"
}

# 监控总线的函数
monitor_bus() {
    local bus_type="$1"
    declare -A seen_calls
    local last_output_time=0

    # 如果是 system bus，检查权限
    if [ "$bus_type" = "system" ]; then
        if ! check_root; then
            echo -e "${YELLOW}[警告]${NC} 没有 root 权限，将只监控 session bus" >&2
            return 1
        fi
    fi

    dbus-monitor --"$bus_type" "type='method_call'" 2>/dev/null | \
    while IFS= read -r line; do
        if [[ $line =~ ^method.call.* ]]; then
            # 直接从方法调用行提取所需信息
            local sender destination path interface
            sender=$(echo "$line" | sed -n 's/.*sender=\([^ ]*\).*/\1/p')
            destination=$(extract_destination "$line")
            path=$(extract_path "$line")
            interface=$(extract_interface "$line")

            # 检查是否应该忽略这个调用
            if should_ignore "$interface" "$destination" "$path"; then
                continue
            fi

            if [[ $sender =~ ^:[0-9]+\.[0-9]+$ ]] && [ ! -z "$destination" ] && [ ! -z "$path" ] && [ ! -z "$interface" ]; then
                local pid
                pid=$(dbus-send --"$bus_type" --dest=org.freedesktop.DBus \
                    --type=method_call --print-reply /org/freedesktop/DBus \
                    org.freedesktop.DBus.GetConnectionUnixProcessID "string:$sender" 2>/dev/null |
                    awk '/uint32/{print $2}')

                if [ ! -z "$pid" ] && [ -e "/proc/$pid/cmdline" ]; then
                    local cmdline service_name call_id timestamp current_time
                    cmdline=$(tr '\0' ' ' < "/proc/$pid/cmdline" | sed 's/ $//')
                    service_name=$(get_service_name "$bus_type" "$destination")
                    current_time=$(date +%s)
                    timestamp=$(date '+%H:%M:%S')

                    # 生成调用的唯一标识符并检查是否已经看到过这个调用
                    call_id=$(generate_call_id "$cmdline" "$service_name" "$path" "$interface")

                    # 如果这个调用已经超过5秒没有出现过，重置其状态
                    if [ -n "${seen_calls[$call_id]}" ]; then
                        local last_time=${seen_calls[$call_id]}
                        if [ $((current_time - last_time)) -ge 5 ]; then
                            unset seen_calls[$call_id]
                        fi
                    fi

                    if [ -z "${seen_calls[$call_id]}" ]; then
                        seen_calls[$call_id]=$current_time
                        echo -e "${YELLOW}[$timestamp]${NC} ${GREEN}[$bus_type]${NC} ${BLUE}$cmdline${NC} -> \"$service_name\" \"$path\" \"$interface\""
                    fi
                fi
            fi
        fi
    done
}

# 显示用法信息
show_usage() {
    echo "用法: $(basename "$0") [选项]"
    echo "选项:"
    echo "  -s, --system    只监控系统总线 (需要 root 权限)"
    echo "  -u, --user      只监控用户会话总线"
    echo "  -h, --help      显示此帮助信息"
    echo ""
    echo "不带参数运行时:"
    echo "- 如果有 root 权限，将同时监控系统总线和会话总线"
    echo "- 如果没有 root 权限，将只监控会话总线"
}

# 参数解析
MONITOR_SYSTEM=true
MONITOR_SESSION=true

while [[ $# -gt 0 ]]; do
    case $1 in
        -s|--system)
            MONITOR_SESSION=false
            shift
            ;;
        -u|--user)
            MONITOR_SYSTEM=false
            shift
            ;;
        -h|--help)
            show_usage
            exit 0
            ;;
        *)
            handle_error "未知选项: $1"
            show_usage
            exit 1
            ;;
    esac
done

# 使用粗体显示标题
echo -e "\033[1m开始监控 DBus 调用...\033[0m" >&2
echo -e "\033[1m当前监控范围:\033[0m" >&2
if [ "$MONITOR_SYSTEM" = true ]; then
    if check_root; then
        echo -e "- ${GREEN}系统总线${NC} (已启用)" >&2
    else
        echo -e "- ${RED}系统总线${NC} (需要 root 权限)" >&2
        MONITOR_SYSTEM=false
    fi
fi
if [ "$MONITOR_SESSION" = true ]; then
    echo -e "- ${GREEN}会话总线${NC} (已启用)" >&2
fi
echo -e "\033[1m输出格式:\033[0m" >&2
echo -e "${YELLOW}[时间]${NC} ${GREEN}[总线类型]${NC} ${BLUE}调用方命令行${NC} -> \"服务名称\" \"对象路径\" \"接口名称\"" >&2
echo -e "\033[1m按 Ctrl+C 停止监控\033[0m" >&2
echo "-----------------------------------------" >&2

# 启动监控进程
if [ "$MONITOR_SYSTEM" = true ]; then
    monitor_bus "system" &
fi
if [ "$MONITOR_SESSION" = true ]; then
    monitor_bus "session" &
fi

# 如果没有启动任何监控，退出
if [ "$MONITOR_SYSTEM" = false ] && [ "$MONITOR_SESSION" = false ]; then
    handle_error "没有启动任何监控。如需监控系统总线，请使用 root 权限运行。"
    exit 1
fi

# 捕获 Ctrl+C 信号
trap 'echo -e "\n\033[1m监控已停止\033[0m" >&2; kill $(jobs -p) 2>/dev/null; exit 0' INT

# 等待后台进程
wait
