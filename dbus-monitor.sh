#!/bin/bash

# 颜色定义
BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# 声明关联数组来存储会话监控的进程 ID
declare -A SESSION_MONITORS

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

# 获取会话总线地址
get_session_bus_address() {
    local user="$1"
    local xdg_runtime_dir="/run/user/$(id -u $user)"

    if [ -e "$xdg_runtime_dir/bus" ]; then
        echo "unix:path=$xdg_runtime_dir/bus"
        return 0
    fi

    return 1
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
    # [[ "$interface" == *"fcitx"* ]] && return 0
    # [[ "$interface" == *"inputcontext"* ]] && return 0
    # [[ "$service" == *"fcitx"* ]] && return 0

    # 忽略一些常见的系统调用
    # [[ "$interface" == "org.freedesktop.DBus.Properties" ]] && return 0
    [[ "$interface" == "org.freedesktop.DBus.Introspectable" ]] && return 0
    [[ "$path" == "/org/freedesktop/DBus" && "$interface" == "org.freedesktop.DBus" ]] && return 0

    # 忽略一些频繁的空闲监控调用
    # [[ "$interface" == *"IdleMonitor"* ]] && return 0

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

# 获取会话环境变量
get_session_environment() {
    local session_path="$1"
    local user_id environment

    # 从 logind 获取用户 ID
    user_id=$(dbus-send --system --print-reply --dest=org.freedesktop.login1 \
        "$session_path" org.freedesktop.DBus.Properties.Get \
        string:'org.freedesktop.login1.Session' string:'User' 2>/dev/null | \
        awk '/uint32/{print $2}')

    if [ -z "$user_id" ]; then
        echo -e "${YELLOW}[警告]${NC} 无法获取会话用户 ID" >&2
        return 1
    fi

    # 获取用户名
    local username=$(getent passwd "$user_id" | cut -d: -f1)
    if [ -z "$username" ]; then
        echo -e "${YELLOW}[警告]${NC} 无法获取用户名 (UID: $user_id)" >&2
        return 1
    fi

    # 查找用户的 dbus-broker 或 dbus-daemon 进程
    local dbus_pid
    # 首先尝试 dbus-broker
    dbus_pid=$(pgrep -u "$username" dbus-broker | head -n 1)

    # 如果没有找到 dbus-broker，尝试 dbus-daemon
    if [ -z "$dbus_pid" ]; then
        dbus_pid=$(pgrep -u "$username" dbus-daemon | head -n 1)
    fi

    if [ -z "$dbus_pid" ]; then
        echo -e "${YELLOW}[警告]${NC} 无法找到用户 $username 的 dbus-broker 或 dbus-daemon 进程" >&2
        return 1
    fi

    echo -e "${GREEN}[信息]${NC} 找到用户 $username 的 DBus 进程 (PID: $dbus_pid)" >&2

    # 从进程环境变量中读取
    environment=$(tr '\0' '\n' < "/proc/$dbus_pid/environ" 2>/dev/null)

    if [ -z "$environment" ]; then
        echo -e "${YELLOW}[警告]${NC} 无法读取进程 $dbus_pid 的环境变量" >&2
        return 1
    fi

    echo "$environment"
}

# 从环境变量列表中提取 DBUS_SESSION_BUS_ADDRESS
extract_dbus_address() {
    local environment="$1"
    local dbus_address

    # 首先尝试直接获取 DBUS_SESSION_BUS_ADDRESS
    dbus_address=$(echo "$environment" | grep '^DBUS_SESSION_BUS_ADDRESS=' | cut -d'=' -f2-)

    if [ -z "$dbus_address" ]; then
        # 如果没有直接的地址，尝试从 XDG_RUNTIME_DIR 构造
        local xdg_runtime_dir=$(echo "$environment" | grep '^XDG_RUNTIME_DIR=' | cut -d'=' -f2-)
        if [ ! -z "$xdg_runtime_dir" ] && [ -e "$xdg_runtime_dir/bus" ]; then
            dbus_address="unix:path=$xdg_runtime_dir/bus"
            echo -e "${YELLOW}[调试]${NC} 使用 XDG_RUNTIME_DIR 构造的地址: $dbus_address" >&2
        fi
    fi

    echo "$dbus_address"
}

# 启动对指定会话的监控
start_session_monitor() {
    local session_id="$1"
    local session_path="$2"
    local environment user_id

    environment=$(get_session_environment "$session_path")
    if [ -z "$environment" ]; then
        echo -e "${YELLOW}[警告]${NC} 无法获取会话 $session_id 的环境变量" >&2
        return 1
    fi

    local dbus_address=$(extract_dbus_address "$environment")
    if [ -z "$dbus_address" ]; then
        echo -e "${YELLOW}[警告]${NC} 无法获取会话 $session_id 的 DBus 地址" >&2
        return 1
    fi

    # 获取会话用户 ID
    user_id=$(dbus-send --system --print-reply --dest=org.freedesktop.login1 \
        "$session_path" org.freedesktop.DBus.Properties.Get \
        string:'org.freedesktop.login1.Session' string:'User' 2>/dev/null | \
        awk '/uint32/{print $2}')

    if [ -z "$user_id" ]; then
        echo -e "${YELLOW}[警告]${NC} 无法获取会话 $session_id 的用户 ID" >&2
        return 1
    fi

    # 启动会话监控
    DBUS_SESSION_BUS_ADDRESS="$dbus_address" monitor_bus "session" "$session_id" &
    SESSION_MONITORS[$session_id]=$!

    echo -e "${GREEN}[信息]${NC} 开始监控会话 $session_id (PID: ${SESSION_MONITORS[$session_id]})" >&2
}

# 停止对指定会话的监控
stop_session_monitor() {
    local session_id="$1"

    if [ -n "${SESSION_MONITORS[$session_id]}" ]; then
        local pid=${SESSION_MONITORS[$session_id]}
        kill $pid 2>/dev/null
        unset SESSION_MONITORS[$session_id]
        echo -e "${GREEN}[信息]${NC} 停止监控会话 $session_id" >&2
    fi
}

# 监控系统会话变化
monitor_sessions() {
    # 获取现有会话并启动监控
    local sessions
    sessions=$(dbus-send --system --print-reply --dest=org.freedesktop.login1 \
        /org/freedesktop/login1 org.freedesktop.login1.Manager.ListSessions 2>/dev/null | \
        awk '/object path/{gsub(/^[ \t]*object path "|"[ \t]*$/, ""); print $1}')

    for session_path in $sessions; do
        local session_id=$(basename "$session_path")
        start_session_monitor "$session_id" "$session_path"
    done

    # 监听会话变化
    dbus-monitor --system "type='signal',sender='org.freedesktop.login1',interface='org.freedesktop.login1.Manager'" | \
    while read -r line; do
        if [[ $line =~ "SessionNew" ]]; then
            read -r session_id
            read -r session_path
            session_id=$(echo "$session_id" | awk -F'"' '{print $2}')
            session_path=$(echo "$session_path" | awk -F'"' '{print $2}')
            start_session_monitor "$session_id" "$session_path"
        elif [[ $line =~ "SessionRemoved" ]]; then
            read -r session_id
            session_id=$(echo "$session_id" | awk -F'"' '{print $2}')
            stop_session_monitor "$session_id"
        fi
    done
}

# 获取进程信息（保留monitor_login1_release_session_simple.sh的格式）
get_process_info() {
    local pid="$1"
    if [[ -d "/proc/$pid" ]]; then
        echo "  Process Info:"
        echo "    PID: $pid"
        if [[ -r "/proc/$pid/cmdline" ]]; then
            local cmdline=$(tr '\0' ' ' < "/proc/$pid/cmdline" | sed 's/ $//')
            echo "    Command: $cmdline"
        fi
        if [[ -r "/proc/$pid/comm" ]]; then
            echo "    Name: $(cat /proc/$pid/comm)"
        fi
        if [[ -r "/proc/$pid/exe" ]]; then
            local exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null)
            [[ -n "$exe" ]] && echo "    Executable: $exe"
        fi
    else
        echo "  Process not found or access denied"
    fi
}

# 获取 DBus 连接的进程 ID
get_connection_pid() {
    local bus_type="$1"
    local sender="$2"
    local user="$3"
    local pid

    if [ "$bus_type" = "session" ] && [ ! -z "$user" ]; then
        # 对于会话总线，需要使用正确的用户权限和环境
        local xdg_runtime_dir="/run/user/$(id -u $user)"
        if [ -e "$xdg_runtime_dir/bus" ]; then
            # 由于可能出现权限问题，暂时不输出错误信息
            pid=$(sudo -u "$user" DBUS_SESSION_BUS_ADDRESS="unix:path=$xdg_runtime_dir/bus" \
                dbus-send --session --print-reply --dest=org.freedesktop.DBus \
                /org/freedesktop/DBus org.freedesktop.DBus.GetConnectionUnixProcessID \
                string:"$sender" 2>/dev/null | awk '/uint32/{print $2}')

            # 如果获取失败，尝试从进程命令行中匹配
            if [ -z "$pid" ]; then
                for p in $(pgrep -u "$user"); do
                    if [ -e "/proc/$p/cmdline" ]; then
                        local cmdline=$(tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null)
                        if [[ "$cmdline" == *"dbus-daemon"* ]] || [[ "$cmdline" == *"dbus-broker"* ]]; then
                            continue
                        fi
                        pid="$p"
                        break
                    fi
                done
            fi
        fi
    else
        # 系统总线直接获取
        pid=$(dbus-send --"$bus_type" --print-reply --dest=org.freedesktop.DBus \
            /org/freedesktop/DBus org.freedesktop.DBus.GetConnectionUnixProcessID \
            string:"$sender" 2>/dev/null | awk '/uint32/{print $2}')
    fi

    # 如果还是获取失败，返回空
    if [ -z "$pid" ]; then
        # 减少错误输出的频率，只在特定条件下输出
        if [[ ! "$sender" =~ ^:[0-9]+\.[0-9]+$ ]]; then
            echo -e "${YELLOW}[调试]${NC} 无法获取进程 ID: $sender" >&2
        fi
        return 1
    fi

    echo "$pid"
}

# 监控总线的函数
monitor_bus() {
    local bus_type="$1"
    declare -A seen_calls
    local last_output_time=0

    # 添加调试信息
    echo -e "${GREEN}[信息]${NC} 正在启动 $bus_type bus 监控..." >&2

    # 检查是否启用了过滤模式（类似monitor_login1_release_session_simple.sh）
    local is_filtered_mode=false
    if [ ! -z "$FILTER_BUS_NAME" ] || [ ! -z "$FILTER_OBJECT_PATH" ] || [ ! -z "$FILTER_INTERFACE" ] || [ ! -z "$FILTER_METHOD" ]; then
        is_filtered_mode=true
    fi

    # 构建监控命令
    local filter_conditions="type='method_call'"
    
    # 如果指定了过滤参数，添加到监控条件中
    if [ ! -z "$FILTER_BUS_NAME" ]; then
        filter_conditions="${filter_conditions},destination='${FILTER_BUS_NAME}'"
    fi
    if [ ! -z "$FILTER_OBJECT_PATH" ]; then
        filter_conditions="${filter_conditions},path='${FILTER_OBJECT_PATH}'"
    fi
    if [ ! -z "$FILTER_INTERFACE" ]; then
        filter_conditions="${filter_conditions},interface='${FILTER_INTERFACE}'"
    fi
    if [ ! -z "$FILTER_METHOD" ]; then
        filter_conditions="${filter_conditions},member='${FILTER_METHOD}'"
    fi

    if [ "$bus_type" = "system" ]; then
        if ! check_root; then
            echo -e "${YELLOW}[警告]${NC} 没有 root 权限，将只监控 session bus" >&2
            return 1
        fi
        # 系统总线监控命令
        monitor_cmd="dbus-monitor --system ${filter_conditions}"
    else
        # session 总线监控需要特殊处理
        if [ ! -z "$SUDO_USER" ]; then
            local session_bus_addr=$(get_session_bus_address "$SUDO_USER")
            if [ -z "$session_bus_addr" ]; then
                echo -e "${RED}[错误]${NC} 无法获取 session bus 地址" >&2
                return 1
            fi
            # 使用 sudo -u 运行 session 总线监控
            monitor_cmd="sudo -u $SUDO_USER DBUS_SESSION_BUS_ADDRESS='$session_bus_addr' dbus-monitor --session ${filter_conditions}"
        else
            monitor_cmd="dbus-monitor --session ${filter_conditions}"
        fi
    fi

    # 使用管道执行监控命令
    ( eval "$monitor_cmd" 2>/dev/null || echo -e "${RED}[错误]${NC} dbus-monitor 命令执行失败" >&2 ) | \
    while IFS= read -r line; do
        # 添加调试信息（仅输出前几行以确认监控正在工作）
        if [ $last_output_time -eq 0 ]; then
            echo -e "${GREEN}[信息]${NC} $bus_type bus 监控已开始接收数据" >&2
            last_output_time=$(date +%s)
        fi

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
                if [ "$bus_type" = "session" ] && [ ! -z "$SUDO_USER" ]; then
                    pid=$(get_connection_pid "$bus_type" "$sender" "$SUDO_USER")
                else
                    pid=$(get_connection_pid "$bus_type" "$sender")
                fi

                # 根据是否启用过滤模式选择输出格式
                if [ "$is_filtered_mode" = true ]; then
                    # 使用monitor_login1_release_session_simple.sh的输出格式
                    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
                    echo "[$timestamp] $interface method call detected"
                    echo "  Sender: $sender"
                    
                    # 如果sender是unique name，获取PID
                    if [[ "$sender" =~ ^: ]]; then
                        echo "  Getting PID for sender: $sender"
                        if [ ! -z "$pid" ] && [[ "$pid" =~ ^[0-9]+$ ]]; then
                            echo "  Found PID: '$pid'"
                            echo "  Process ID: $pid"
                            get_process_info "$pid"
                        else
                            echo "  Failed to get PID"
                        fi
                    fi
                    echo "----------------------------------------"
                else
                    # 使用原有的输出格式
                    local timestamp=$(date '+%H:%M:%S')
                    local service_name=$(get_service_name "$bus_type" "$destination")
                    local cmdline=""

                    if [ ! -z "$pid" ] && [ -e "/proc/$pid/cmdline" ]; then
                        cmdline=$(tr '\0' ' ' < "/proc/$pid/cmdline" | sed 's/ $//')
                    else
                        cmdline="[未知进程]"
                    fi

                    # 生成调用的唯一标识符并检查是否已经看到过这个调用
                    call_id=$(generate_call_id "$cmdline" "$service_name" "$path" "$interface")
                    current_time=$(date +%s)

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

    # 如果监控进程异常退出，输出错误信息
    if [ $? -ne 0 ]; then
        echo -e "${RED}[错误]${NC} $bus_type bus 监控意外停止" >&2
        return 1
    fi
}

# 显示用法信息
show_usage() {
    echo "用法: $(basename "$0") [选项]"
    echo "选项:"
    echo "  -s, --system    只监控系统总线 (需要 root 权限)"
    echo "  -u, --user      只监控用户会话总线"
    echo "  --session       只监控用户级服务（会话总线）"
    echo "  --system        只监控系统级服务（系统总线）"
    echo "  -n <名称>       指定要监控的BUS名称 (默认: 监控所有)"
    echo "  -p <路径>       指定要监控的对象路径 (默认: 监控所有)"
    echo "  -i <接口>       指定要监控的接口 (默认: 监控所有)"
    echo "  -m <方法>       指定要监控的方法 (默认: 监控所有)"
    echo "  -h, --help      显示此帮助信息"
    echo ""
    echo "不带参数运行时:"
    echo "- 如果有 root 权限，将同时监控系统总线和会话总线"
    echo "- 如果没有 root 权限，将只监控会话总线"
    echo ""
    echo "使用 -n/-p/-i/-m 参数时，将只监控匹配的DBus调用"
}

# 参数解析
MONITOR_SYSTEM=true
MONITOR_SESSION=true
# 新增过滤参数
FILTER_BUS_NAME=""
FILTER_OBJECT_PATH=""
FILTER_INTERFACE=""
FILTER_METHOD=""

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
        --session)
            MONITOR_SYSTEM=false
            MONITOR_SESSION=true
            shift
            ;;
        --system)
            MONITOR_SESSION=false
            MONITOR_SYSTEM=true
            shift
            ;;
        -n)
            FILTER_BUS_NAME="$2"
            shift 2
            ;;
        -p)
            FILTER_OBJECT_PATH="$2"
            shift 2
            ;;
        -i)
            FILTER_INTERFACE="$2"
            shift 2
            ;;
        -m)
            FILTER_METHOD="$2"
            shift 2
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

# 显示过滤条件
if [ ! -z "$FILTER_BUS_NAME" ] || [ ! -z "$FILTER_OBJECT_PATH" ] || [ ! -z "$FILTER_INTERFACE" ] || [ ! -z "$FILTER_METHOD" ]; then
    echo -e "\033[1m过滤条件:\033[0m" >&2
    [ ! -z "$FILTER_BUS_NAME" ] && echo -e "- BUS名称: ${YELLOW}$FILTER_BUS_NAME${NC}" >&2
    [ ! -z "$FILTER_OBJECT_PATH" ] && echo -e "- 对象路径: ${YELLOW}$FILTER_OBJECT_PATH${NC}" >&2
    [ ! -z "$FILTER_INTERFACE" ] && echo -e "- 接口: ${YELLOW}$FILTER_INTERFACE${NC}" >&2
    [ ! -z "$FILTER_METHOD" ] && echo -e "- 方法: ${YELLOW}$FILTER_METHOD${NC}" >&2
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
    monitor_sessions &
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
```
</copilot-edited-file>
```bash
#!/bin/bash

# 颜色定义
BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# 声明关联数组来存储会话监控的进程 ID
declare -A SESSION_MONITORS

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

# 获取会话总线地址
get_session_bus_address() {
    local user="$1"
    local xdg_runtime_dir="/run/user/$(id -u $user)"

    if [ -e "$xdg_runtime_dir/bus" ]; then
        echo "unix:path=$xdg_runtime_dir/bus"
        return 0
    fi

    return 1
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
    # [[ "$interface" == *"fcitx"* ]] && return 0
    # [[ "$interface" == *"inputcontext"* ]] && return 0
    # [[ "$service" == *"fcitx"* ]] && return 0

    # 忽略一些常见的系统调用
    # [[ "$interface" == "org.freedesktop.DBus.Properties" ]] && return 0
    [[ "$interface" == "org.freedesktop.DBus.Introspectable" ]] && return 0
    [[ "$path" == "/org/freedesktop/DBus" && "$interface" == "org.freedesktop.DBus" ]] && return 0

    # 忽略一些频繁的空闲监控调用
    # [[ "$interface" == *"IdleMonitor"* ]] && return 0

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

# 获取会话环境变量
get_session_environment() {
    local session_path="$1"
    local user_id environment

    # 从 logind 获取用户 ID
    user_id=$(dbus-send --system --print-reply --dest=org.freedesktop.login1 \
        "$session_path" org.freedesktop.DBus.Properties.Get \
        string:'org.freedesktop.login1.Session' string:'User' 2>/dev/null | \
        awk '/uint32/{print $2}')

    if [ -z "$user_id" ]; then
        echo -e "${YELLOW}[警告]${NC} 无法获取会话用户 ID" >&2
        return 1
    fi

    # 获取用户名
    local username=$(getent passwd "$user_id" | cut -d: -f1)
    if [ -z "$username" ]; then
        echo -e "${YELLOW}[警告]${NC} 无法获取用户名 (UID: $user_id)" >&2
        return 1
    fi

    # 查找用户的 dbus-broker 或 dbus-daemon 进程
    local dbus_pid
    # 首先尝试 dbus-broker
    dbus_pid=$(pgrep -u "$username" dbus-broker | head -n 1)

    # 如果没有找到 dbus-broker，尝试 dbus-daemon
    if [ -z "$dbus_pid" ]; then
        dbus_pid=$(pgrep -u "$username" dbus-daemon | head -n 1)
    fi

    if [ -z "$dbus_pid" ]; then
        echo -e "${YELLOW}[警告]${NC} 无法找到用户 $username 的 dbus-broker 或 dbus-daemon 进程" >&2
        return 1
    fi

    echo -e "${GREEN}[信息]${NC} 找到用户 $username 的 DBus 进程 (PID: $dbus_pid)" >&2

    # 从进程环境变量中读取
    environment=$(tr '\0' '\n' < "/proc/$dbus_pid/environ" 2>/dev/null)

    if [ -z "$environment" ]; then
        echo -e "${YELLOW}[警告]${NC} 无法读取进程 $dbus_pid 的环境变量" >&2
        return 1
    fi

    echo "$environment"
}

# 从环境变量列表中提取 DBUS_SESSION_BUS_ADDRESS
extract_dbus_address() {
    local environment="$1"
    local dbus_address

    # 首先尝试直接获取 DBUS_SESSION_BUS_ADDRESS
    dbus_address=$(echo "$environment" | grep '^DBUS_SESSION_BUS_ADDRESS=' | cut -d'=' -f2-)

    if [ -z "$dbus_address" ]; then
        # 如果没有直接的地址，尝试从 XDG_RUNTIME_DIR 构造
        local xdg_runtime_dir=$(echo "$environment" | grep '^XDG_RUNTIME_DIR=' | cut -d'=' -f2-)
        if [ ! -z "$xdg_runtime_dir" ] && [ -e "$xdg_runtime_dir/bus" ]; then
            dbus_address="unix:path=$xdg_runtime_dir/bus"
            echo -e "${YELLOW}[调试]${NC} 使用 XDG_RUNTIME_DIR 构造的地址: $dbus_address" >&2
        fi
    fi

    echo "$dbus_address"
}

# 启动对指定会话的监控
start_session_monitor() {
    local session_id="$1"
    local session_path="$2"
    local environment user_id

    environment=$(get_session_environment "$session_path")
    if [ -z "$environment" ]; then
        echo -e "${YELLOW}[警告]${NC} 无法获取会话 $session_id 的环境变量" >&2
        return 1
    fi

    local dbus_address=$(extract_dbus_address "$environment")
    if [ -z "$dbus_address" ]; then
        echo -e "${YELLOW}[警告]${NC} 无法获取会话 $session_id 的 DBus 地址" >&2
        return 1
    fi

    # 获取会话用户 ID
    user_id=$(dbus-send --system --print-reply --dest=org.freedesktop.login1 \
        "$session_path" org.freedesktop.DBus.Properties.Get \
        string:'org.freedesktop.login1.Session' string:'User' 2>/dev/null | \
        awk '/uint32/{print $2}')

    if [ -z "$user_id" ]; then
        echo -e "${YELLOW}[警告]${NC} 无法获取会话 $session_id 的用户 ID" >&2
        return 1
    fi

    # 启动会话监控
    DBUS_SESSION_BUS_ADDRESS="$dbus_address" monitor_bus "session" "$session_id" &
    SESSION_MONITORS[$session_id]=$!

    echo -e "${GREEN}[信息]${NC} 开始监控会话 $session_id (PID: ${SESSION_MONITORS[$session_id]})" >&2
}

# 停止对指定会话的监控
stop_session_monitor() {
    local session_id="$1"

    if [ -n "${SESSION_MONITORS[$session_id]}" ]; then
        local pid=${SESSION_MONITORS[$session_id]}
        kill $pid 2>/dev/null
        unset SESSION_MONITORS[$session_id]
        echo -e "${GREEN}[信息]${NC} 停止监控会话 $session_id" >&2
    fi
}

# 监控系统会话变化
monitor_sessions() {
    # 获取现有会话并启动监控
    local sessions
    sessions=$(dbus-send --system --print-reply --dest=org.freedesktop.login1 \
        /org/freedesktop/login1 org.freedesktop.login1.Manager.ListSessions 2>/dev/null | \
        awk '/object path/{gsub(/^[ \t]*object path "|"[ \t]*$/, ""); print $1}')

    for session_path in $sessions; do
        local session_id=$(basename "$session_path")
        start_session_monitor "$session_id" "$session_path"
    done

    # 监听会话变化
    dbus-monitor --system "type='signal',sender='org.freedesktop.login1',interface='org.freedesktop.login1.Manager'" | \
    while read -r line; do
        if [[ $line =~ "SessionNew" ]]; then
            read -r session_id
            read -r session_path
            session_id=$(echo "$session_id" | awk -F'"' '{print $2}')
            session_path=$(echo "$session_path" | awk -F'"' '{print $2}')
            start_session_monitor "$session_id" "$session_path"
        elif [[ $line =~ "SessionRemoved" ]]; then
            read -r session_id
            session_id=$(echo "$session_id" | awk -F'"' '{print $2}')
            stop_session_monitor "$session_id"
        fi
    done
}

# 获取 DBus 连接的进程 ID
get_connection_pid() {
    local bus_type="$1"
    local sender="$2"
    local user="$3"
    local pid

    if [ "$bus_type" = "session" ] && [ ! -z "$user" ]; then
        # 对于会话总线，需要使用正确的用户权限和环境
        local xdg_runtime_dir="/run/user/$(id -u $user)"
        if [ -e "$xdg_runtime_dir/bus" ]; then
            # 由于可能出现权限问题，暂时不输出错误信息
            pid=$(sudo -u "$user" DBUS_SESSION_BUS_ADDRESS="unix:path=$xdg_runtime_dir/bus" \
                dbus-send --session --print-reply --dest=org.freedesktop.DBus \
                /org/freedesktop/DBus org.freedesktop.DBus.GetConnectionUnixProcessID \
                string:"$sender" 2>/dev/null | awk '/uint32/{print $2}')

            # 如果获取失败，尝试从进程命令行中匹配
            if [ -z "$pid" ]; then
                for p in $(pgrep -u "$user"); do
                    if [ -e "/proc/$p/cmdline" ]; then
                        local cmdline=$(tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null)
                        if [[ "$cmdline" == *"dbus-daemon"* ]] || [[ "$cmdline" == *"dbus-broker"* ]]; then
                            continue
                        fi
                        pid="$p"
                        break
                    fi
                done
            fi
        fi
    else
        # 系统总线直接获取
        pid=$(dbus-send --"$bus_type" --print-reply --dest=org.freedesktop.DBus \
            /org/freedesktop/DBus org.freedesktop.DBus.GetConnectionUnixProcessID \
            string:"$sender" 2>/dev/null | awk '/uint32/{print $2}')
    fi

    # 如果还是获取失败，返回空
    if [ -z "$pid" ]; then
        # 减少错误输出的频率，只在特定条件下输出
        if [[ ! "$sender" =~ ^:[0-9]+\.[0-9]+$ ]]; then
            echo -e "${YELLOW}[调试]${NC} 无法获取进程 ID: $sender" >&2
        fi
        return 1
    fi

    echo "$pid"
}

# 监控总线的函数（参考monitor_login1_release_session_simple.sh的实现）
monitor_bus() {
    local bus_type="$1"
    declare -A seen_calls
    local last_output_time=0

    # 添加调试信息
    echo -e "${GREEN}[信息]${NC} 正在启动 $bus_type bus 监控..." >&2

    # 检查是否启用了过滤模式（类似monitor_login1_release_session_simple.sh）
    local is_filtered_mode=false
    if [ ! -z "$FILTER_BUS_NAME" ] || [ ! -z "$FILTER_OBJECT_PATH" ] || [ ! -z "$FILTER_INTERFACE" ] || [ ! -z "$FILTER_METHOD" ]; then
        is_filtered_mode=true
    fi

    # 构建监控命令
    local filter_conditions="type='method_call'"
    
    # 如果指定了过滤参数，添加到监控条件中
    if [ ! -z "$FILTER_BUS_NAME" ]; then
        filter_conditions="${filter_conditions},destination='${FILTER_BUS_NAME}'"
    fi
    if [ ! -z "$FILTER_OBJECT_PATH" ]; then
        filter_conditions="${filter_conditions},path='${FILTER_OBJECT_PATH}'"
    fi
    if [ ! -z "$FILTER_INTERFACE" ]; then
        filter_conditions="${filter_conditions},interface='${FILTER_INTERFACE}'"
    fi
    if [ ! -z "$FILTER_METHOD" ]; then
        filter_conditions="${filter_conditions},member='${FILTER_METHOD}'"
    fi

    if [ "$bus_type" = "system" ]; then
        if ! check_root; then
            echo -e "${YELLOW}[警告]${NC} 没有 root 权限，将只监控 session bus" >&2
            return 1
        fi
        # 系统总线监控命令
        monitor_cmd="dbus-monitor --system ${filter_conditions}"
    else
        # session 总线监控需要特殊处理
        if [ ! -z "$SUDO_USER" ]; then
            local session_bus_addr=$(get_session_bus_address "$SUDO_USER")
            if [ -z "$session_bus_addr" ]; then
                echo -e "${RED}[错误]${NC} 无法获取 session bus 地址" >&2
                return 1
            fi
            # 使用 sudo -u 运行 session 总线监控
            monitor_cmd="sudo -u $SUDO_USER DBUS_SESSION_BUS_ADDRESS='$session_bus_addr' dbus-monitor --session ${filter_conditions}"
        else
            monitor_cmd="dbus-monitor --session ${filter_conditions}"
        fi
    fi

    # 使用管道执行监控命令
    ( eval "$monitor_cmd" 2>/dev/null || echo -e "${RED}[错误]${NC} dbus-monitor 命令执行失败" >&2 ) | \
    while IFS= read -r line; do
        # 添加调试信息（仅输出前几行以确认监控正在工作）
        if [ $last_output_time -eq 0 ]; then
            echo -e "${GREEN}[信息]${NC} $bus_type bus 监控已开始接收数据" >&2
            last_output_time=$(date +%s)
        fi

        if [[ $line =~ method[[:space:]]+call ]]; then
            # 根据是否启用过滤模式选择不同的处理方式
            if [ "$is_filtered_mode" = true ]; then
                # 使用monitor_login1_release_session_simple.sh的输出格式
                local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
                echo "[$timestamp] $FILTER_INTERFACE method call detected"
                
                # 提取sender从行中
                local sender
                if [[ "$line" =~ sender=([^[:space:]]+) ]]; then
                    sender="${BASH_REMATCH[1]}"
                    echo "  Sender: $sender"
                    
                    # 如果sender是unique name，获取PID
                    if [[ "$sender" =~ ^: ]]; then
                        echo "  Getting PID for sender: $sender"
                        local pid
                        # 使用busctl如果可用，否则使用dbus-send
                        if command -v busctl >/dev/null; then
                            pid=$(busctl --system call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus GetConnectionUnixProcessID s "$sender" 2>/dev/null | grep -o '[0-9]\+')
                        else
                            pid=$(dbus-send --print-reply --system --dest=org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus.GetConnectionUnixProcessID string:"$sender" 2>/dev/null | grep uint32 | awk '{print $3}')
                        fi
                        echo "  Found PID: '$pid'"
                        if [[ -n "$pid" ]] && [[ "$pid" =~ ^[0-9]+$ ]]; then
                            echo "  Process ID: $pid"
                            get_process_info "$pid"
                        else
                            echo "  Failed to get PID"
                        fi
                    fi
                fi
                echo "----------------------------------------"
            else
                # 使用原有的输出格式
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
                    if [ "$bus_type" = "session" ] && [ ! -z "$SUDO_USER" ]; then
                        pid=$(get_connection_pid "$bus_type" "$sender" "$SUDO_USER")
                    else
                        pid=$(get_connection_pid "$bus_type" "$sender")
                    fi

                    # 即使获取不到 pid，也尝试输出调用信息
                    local timestamp=$(date '+%H:%M:%S')
                    local service_name=$(get_service_name "$bus_type" "$destination")
                    local cmdline=""

                    if [ ! -z "$pid" ] && [ -e "/proc/$pid/cmdline" ]; then
                        cmdline=$(tr '\0' ' ' < "/proc/$pid/cmdline" | sed 's/ $//')
                    else
                        cmdline="[未知进程]"
                    fi

                    # 生成调用的唯一标识符并检查是否已经看到过这个调用
                    call_id=$(generate_call_id "$cmdline" "$service_name" "$path" "$interface")
                    current_time=$(date +%s)

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

    # 如果监控进程异常退出，输出错误信息
    if [ $? -ne 0 ]; then
        echo -e "${RED}[错误]${NC} $bus_type bus 监控意外停止" >&2
        return 1
    fi
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
    monitor_sessions &
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
