#!/bin/bash
# DSH: 供内容后台调用的密码重置助手
#
# 安装位置：/usr/local/sbin/dsh-set-password
# 权限：root:root 0750（仅 root 与 sudo 白名单中的 blogadmin 可执行）
#
# 设计要点：
#   - 只接受一个 stdin 输入（新密码），不接受命令行参数，避免密码出现在进程列表
#   - 校验密码强度（长度、字符种类）
#   - 备份旧配置后再原子写入
#   - 通过 sudoers 白名单授权，避免整个后台跑在 root
#
# 用法： printf '%s' '新密码' | dsh-set-password
set -uo pipefail

ENVFILE=/etc/default/blog-admin

# 从 stdin 读取新密码（不落盘、不进进程列表）
NEWPW=$(cat)
NEWPW=${NEWPW%$'\n'}   # 去掉可能的行尾换行

# ---- 强度校验 ----
if [ ${#NEWPW} -lt 10 ]; then
  echo '{"ok":false,"error":"密码长度至少 10 位"}'
  exit 1
fi
if [ ${#NEWPW} -gt 128 ]; then
  echo '{"ok":false,"error":"密码过长（最多 128 位）"}'
  exit 1
fi
# 必须包含字母和数字
if ! printf '%s' "$NEWPW" | grep -q '[A-Za-z]' || ! printf '%s' "$NEWPW" | grep -q '[0-9]'; then
  echo '{"ok":false,"error":"密码需同时包含字母和数字"}'
  exit 1
fi
# 禁止会破坏 EnvironmentFile 解析的字符
case "$NEWPW" in
  *[\ \'\"\\\$\`]*)
    echo '{"ok":false,"error":"密码不能包含空格、引号、反斜杠、$ 或反引号"}'
    exit 1
    ;;
esac

# ---- 备份 ----
BACKUP="${ENVFILE}.bak-$(date +%F-%H%M%S)"
cp -a "$ENVFILE" "$BACKUP" 2>/dev/null || true

# ---- 原子写入（先写临时文件再 rename，避免半写状态）----
TMP=$(mktemp)
chmod 600 "$TMP"
printf 'ADMIN_PASSWORD=%s\n' "$NEWPW" > "$TMP"
if ! chown root:root "$TMP" 2>/dev/null; then :; fi
mv -f "$TMP" "$ENVFILE"
chmod 600 "$ENVFILE"

# ---- 日志（不记录密码本身）----
logger -t dsh-set-password "admin password changed (backup: $BACKUP)"
echo '{"ok":true,"message":"密码已更新","backup":"'"$BACKUP"'"}'
