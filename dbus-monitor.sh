#!/bin/bash

# 错误处理函数
handle_error() {
    echo "错误: $1" >&2
}

# 检查必要的命令是否存在
for cmd in dbus-monitor dbus-send awk; do
    if ! command -v $cmd >/dev/null 2>&1; then
        handle_error "找不到命令: $cmd"
        exit 1
    fi
done

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

# 监控总线的函数
monitor_bus() {
    local bus_type="$1"

    dbus-monitor --"$bus_type" "type='method_call'" 2>/dev/null | \
    while IFS= read -r line; do
        if [[ $line =~ ^method.call.* ]]; then
            # 直接从方法调用行提取所需信息
            local sender destination path interface
            sender=$(echo "$line" | sed -n 's/.*sender=\([^ ]*\).*/\1/p')
            destination=$(extract_destination "$line")
            path=$(extract_path "$line")
            interface=$(extract_interface "$line")

            if [[ $sender =~ ^:[0-9]+\.[0-9]+$ ]] && [ ! -z "$destination" ] && [ ! -z "$path" ] && [ ! -z "$interface" ]; then
                local pid
                pid=$(dbus-send --"$bus_type" --dest=org.freedesktop.DBus \
                    --type=method_call --print-reply /org/freedesktop/DBus \
                    org.freedesktop.DBus.GetConnectionUnixProcessID "string:$sender" 2>/dev/null |
                    awk '/uint32/{print $2}')

                if [ ! -z "$pid" ] && [ -e "/proc/$pid/cmdline" ]; then
                    local cmdline
                    cmdline=$(tr '\0' ' ' < "/proc/$pid/cmdline" | sed 's/ $//')
                    printf "\"%s\" \"%s\" \"%s\" \"%s\"\n" "$cmdline" "$destination" "$path" "$interface"
                fi
            fi
        fi
    done
}

echo "开始监控 DBus 调用..." >&2
echo "系统总线和会话总线的方法调用将被显示在下面:" >&2
echo "格式: \"调用方命令行\" \"服务名称\" \"对象路径\" \"接口名称\"" >&2
echo "按 Ctrl+C 停止监控" >&2
echo "-----------------------------------------" >&2

# 启动监控进程
monitor_bus "system" &
monitor_bus "session" &

# 捕获 Ctrl+C 信号
trap 'echo -e "\n监控已停止" >&2; kill $(jobs -p) 2>/dev/null; exit 0' INT

# 等待后台进程
wait
