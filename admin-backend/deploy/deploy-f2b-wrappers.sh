#!/usr/bin/env bash
# DSH: 部署 fail2ban 操作 wrapper + 正确的 sudoers 白名单
#
# 背景：sudoers 的 Command 字段是「完整命令行 + glob 通配」，
# 直接对 /usr/local/sbin/dsh-fail2ban-admin ban 1.2.3.4 授权既难写又容易出错
# （之前误用正则字符类 [0-9A-Fa-f:.]* 导致整个 sudoers 文件语法错误）。
#
# 方案：为每个操作建一个固定路径、**不接受任何参数**的 wrapper，
# 数据通过环境变量 DSH_IP 传入（在 sudoers 中用 env_keep 保留）。
# sudoers 里每条都以 "" 结尾，表示不允许任何附加参数。
set -uo pipefail

echo "########## 部署 fail2ban wrapper 与 sudoers $(date -Is) ##########"

echo
echo "===== [1] 写入三个无参数 wrapper ====="

cat > /usr/local/sbin/dsh-f2b-list <<'EOF'
#!/bin/bash
# 列出被封禁的 IP（无参数）
exec /usr/local/sbin/dsh-fail2ban-admin list
EOF

cat > /usr/local/sbin/dsh-f2b-ban <<'EOF'
#!/bin/bash
# 封禁环境变量 DSH_IP 指定的地址（无参数）
# 严格校验：仅允许 IPv4/IPv6 字面量，杜绝注入
set -uo pipefail
IP="${DSH_IP:-}"
if [ -z "$IP" ]; then
  echo '{"ok":false,"error":"未提供 IP"}'; exit 1
fi
case "$IP" in
  *[!0-9A-Fa-f:.]*)
    echo '{"ok":false,"error":"非法 IP 地址"}'; exit 1 ;;
esac
if ! printf '%s' "$IP" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}$|^[0-9A-Fa-f:]+$'; then
  echo '{"ok":false,"error":"非法 IP 地址"}'; exit 1
fi
exec /usr/local/sbin/dsh-fail2ban-admin ban "$IP"
EOF

cat > /usr/local/sbin/dsh-f2b-unban <<'EOF'
#!/bin/bash
# 解除环境变量 DSH_IP 指定的地址封禁（无参数）
set -uo pipefail
IP="${DSH_IP:-}"
if [ -z "$IP" ]; then
  echo '{"ok":false,"error":"未提供 IP"}'; exit 1
fi
case "$IP" in
  *[!0-9A-Fa-f:.]*)
    echo '{"ok":false,"error":"非法 IP 地址"}'; exit 1 ;;
esac
if ! printf '%s' "$IP" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}$|^[0-9A-Fa-f:]+$'; then
  echo '{"ok":false,"error":"非法 IP 地址"}'; exit 1
fi
exec /usr/local/sbin/dsh-fail2ban-admin unban "$IP"
EOF

for f in dsh-f2b-list dsh-f2b-ban dsh-f2b-unban; do
  chmod 0750 "/usr/local/sbin/$f"
  chown root:root "/usr/local/sbin/$f"
  bash -n "/usr/local/sbin/$f" && echo "  $f 语法 OK  $(stat -c '%A' /usr/local/sbin/$f)"
done

echo
echo "===== [2] 写入 sudoers（每条均禁止附加参数）====="
cat > /etc/sudoers.d/blog-admin-fail2ban <<'EOF'
# 内容后台（低权限用户 blogadmin）可执行的特权操作。
#
# 要点：
#   1. sudoers 的 Command 字段按「完整命令行」匹配，且用的是 glob 不是正则。
#   2. 每条末尾的 "" 表示【不允许任何附加参数】，彻底堵死参数滥用。
#   3. IP 等数据通过环境变量传入，因此用 env_keep 保留这几个变量。
#
# 被授权的脚本都已做严格入参校验，不构成任意命令执行。
Defaults:blogadmin env_keep += "DSH_IP"
Defaults:blogadmin env_keep += "DSH_ACTION"

blogadmin ALL=(root) NOPASSWD: /usr/local/sbin/dsh-f2b-list ""
blogadmin ALL=(root) NOPASSWD: /usr/local/sbin/dsh-f2b-ban ""
blogadmin ALL=(root) NOPASSWD: /usr/local/sbin/dsh-f2b-unban ""
blogadmin ALL=(root) NOPASSWD: /usr/local/sbin/dsh-set-password ""
EOF
chmod 0440 /etc/sudoers.d/blog-admin-fail2ban
echo "  内容:"
grep -vE '^\s*#|^\s*$' /etc/sudoers.d/blog-admin-fail2ban | sed 's/^/    /'
echo
echo "  --- 语法校验（关键）---"
if visudo -c 2>&1 | grep -q 'parsed OK'; then
  visudo -c 2>&1 | grep 'blog-admin' | sed 's/^/    /'
  echo "    ✓ sudoers 语法正常"
else
  echo "    !!! 语法错误，输出如下:"
  visudo -c 2>&1 | sed 's/^/      /'
  exit 1
fi

echo
echo "===== [3] 验证允许的操作 ====="
printf '  dsh-f2b-list                 -> '
sudo -u blogadmin sudo -n /usr/local/sbin/dsh-f2b-list 2>&1 | head -c 70
echo
printf '  dsh-f2b-ban (DSH_IP=1.1.1.1) -> '
sudo -u blogadmin env DSH_IP=1.1.1.1 sudo -n /usr/local/sbin/dsh-f2b-ban 2>&1 | head -c 80
echo
printf '  dsh-f2b-unban (1.1.1.1)      -> '
sudo -u blogadmin env DSH_IP=1.1.1.1 sudo -n /usr/local/sbin/dsh-f2b-unban 2>&1 | head -c 80
echo
printf '  dsh-set-password (弱密码)    -> '
sudo -u blogadmin bash -c "printf 'short' | sudo -n /usr/local/sbin/dsh-set-password" 2>&1 | head -c 60
echo

echo
echo "===== [4] 验证被拒绝的操作 ====="
for t in "/usr/local/sbin/dsh-f2b-list extra" "/usr/local/sbin/dsh-f2b-ban 1.1.1.1" "/usr/local/sbin/dsh-set-password -h" "/usr/local/sbin/dsh-set-password extra" "/bin/bash" "id" "cat /etc/shadow"; do
  printf '  %-44s -> ' "$t"
  sudo -u blogadmin sudo -n $t 2>&1 | head -1 | head -c 50
  echo
done

echo
echo "===== [5] wrapper 的 IP 注入防护 ====="
for bad in "1.1.1.1; id" '$(id)' '../../etc/passwd' 'not-an-ip'; do
  printf '  DSH_IP=%-18s -> ' "$bad"
  sudo -u blogadmin env DSH_IP="$bad" sudo -n /usr/local/sbin/dsh-f2b-ban 2>&1 | head -c 70
  echo
done

echo
echo "===== [6] 清理测试封禁 ====="
fail2ban-client set blog-admin unbanip 1.1.1.1 >/dev/null 2>&1
fail2ban-client banned 2>/dev/null | sed 's/^/  /'
