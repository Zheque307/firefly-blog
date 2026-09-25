#!/bin/bash
# DSH: 供内容后台调用的 fail2ban 封禁管理助手
#
# 安装位置：/usr/local/sbin/dsh-fail2ban-admin
# 权限：root:root 0750（仅 root 与 sudo 白名单中的 blogadmin 可执行）
#
# 设计要点：
#   - 只接受固定子命令，参数经过严格 IP 校验，杜绝命令注入
#   - 通过 sudoers 白名单授权给低权限的 blogadmin 用户，避免整个后台跑在 root
#
# 用法：
#   dsh-fail2ban-admin list             列出封禁情况（JSON）
#   dsh-fail2ban-admin unban <IP>       解封
#   dsh-fail2ban-admin ban <IP>         手动封禁
set -uo pipefail

F2B=/usr/bin/fail2ban-client
# 需要管理的 jail：后台登录防护 + 累犯永久封禁
JAILS="blog-admin recidive"

ipv4_re='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
ipv6_re='^[0-9a-fA-F:]{2,45}$'

valid_ip() {
  local ip="$1"
  if [[ "$ip" =~ $ipv4_re ]]; then
    local IFS='.'
    # shellcheck disable=SC2206
    local parts=($ip)
    for p in "${parts[@]}"; do
      [ "$p" -le 255 ] || return 1
    done
    return 0
  fi
  [[ "$ip" =~ $ipv6_re ]] && return 0
  return 1
}

json_escape() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }

jail_json() {
  local jail="$1"
  local raw banned="" count=0
  raw=$($F2B status "$jail" 2>/dev/null) || { printf '{"jail":"%s","error":"jail 未启用"}' "$(json_escape "$jail")"; return; }
  local line
  line=$(printf '%s\n' "$raw" | grep 'Banned IP list:' | sed 's/.*Banned IP list:[[:space:]]*//')
  for ip in $line; do
    [ -z "$ip" ] && continue
    banned="${banned}${banned:+,}\"$(json_escape "$ip")\""
    count=$((count + 1))
  done
  printf '{"jail":"%s","enabled":true,"count":%d,"banned":[%s]}' \
    "$(json_escape "$jail")" "$count" "$banned"
}

cmd_list() {
  local out="" first=1
  for j in $JAILS; do
    [ $first -eq 1 ] || out="${out},"
    first=0
    out="${out}$(jail_json "$j")"
  done
  printf '{"ok":true,"jails":[%s],"ts":%s}\n' "$out" "$(date +%s)"
}

cmd_unban() {
  local ip="${1:-}"
  valid_ip "$ip" || { printf '{"ok":false,"error":"非法 IP 地址"}\n'; exit 1; }
  local done_any=0 detail=""
  for j in $JAILS; do
    $F2B status "$j" >/dev/null 2>&1 || continue
    if $F2B status "$j" 2>/dev/null | grep -q "$ip"; then
      if $F2B set "$j" unbanip "$ip" >/dev/null 2>&1; then
        done_any=1
        detail="${detail}${detail:+,}${j}"
      fi
    fi
  done
  if [ "$done_any" -eq 1 ]; then
    printf '{"ok":true,"action":"unban","ip":"%s","jails":"%s"}\n' "$(json_escape "$ip")" "$detail"
  else
    printf '{"ok":false,"error":"该 IP 当前未被封禁"}\n'
  fi
}

cmd_ban() {
  local ip="${1:-}"
  valid_ip "$ip" || { printf '{"ok":false,"error":"非法 IP 地址"}\n'; exit 1; }
  if $F2B set blog-admin banip "$ip" >/dev/null 2>&1; then
    printf '{"ok":true,"action":"ban","ip":"%s","jail":"blog-admin"}\n' "$(json_escape "$ip")"
  else
    printf '{"ok":false,"error":"封禁失败"}\n'
  fi
}

case "${1:-}" in
  list)  cmd_list ;;
  unban) cmd_unban "${2:-}" ;;
  ban)   cmd_ban "${2:-}" ;;
  *)
    printf '{"ok":false,"error":"用法: list | unban <IP> | ban <IP>"}\n'
    exit 1
    ;;
esac
