# 服务器端部署资产

## dsh-fail2ban-admin.sh
fail2ban 封禁管理助手，部署到 /usr/local/sbin/dsh-fail2ban-admin（0750 root:root）。

由 /etc/sudoers.d/blog-admin-fail2ban 白名单授权给低权限用户 blogadmin：

`
blogadmin ALL=(root) NOPASSWD: /usr/local/sbin/dsh-fail2ban-admin
`

只接受三种固定调用，IP 参数在脚本内做严格校验：

| 命令 | 作用 |
|---|---|
| dsh-fail2ban-admin list | 输出 JSON 封禁名单 |
| dsh-fail2ban-admin unban <IP> | 解除封禁 |
| dsh-fail2ban-admin ban <IP> | 手动封禁 |

## fail2ban 配置

- /etc/fail2ban/filter.d/blog-admin.conf —— 匹配 [blog-admin-auth] <IP> - ... 日志
- /etc/fail2ban/jail.local —— blog-admin（5 次/1 小时）、recidive（3 次/永久）、sshd
