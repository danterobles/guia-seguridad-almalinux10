# AlmaLinux 10 服务器安装与加固指南

**目标：** 在 **AlmaLinux 10** 上从零构建一台**高安全性**生产服务器，能够同时托管 **Laravel (PHP 8.5 / Filament)** 和 **Node.js (LTS 24)** 应用，运行于 Apache 之后，配置 Let's Encrypt SSL、SELinux *强制（Enforcing）*模式以及 Fail2Ban 主动防御。

**技术栈：** AlmaLinux 10 · Apache 2.4 (MPM event + HTTP/2) · PHP 8.5 (php-fpm，via Remi) · MySQL 8.4 · Valkey 8 · Node.js 24 LTS · Let's Encrypt · firewalld · SELinux · Fail2Ban · Cloudflare Turnstile

> **如何使用本文档。** 本文档既是可重复执行的*操作手册（runbook）*，也是审计参考。请将占位符 `your-domain.com`、`myapp`、`your.public.ip.here` 及用户名/数据库名替换为实际值。以 `root` 身份或在命令前加 `sudo` 执行。

---

## 目录

1. [约定与架构](#1-约定与架构)
2. [基础系统准备](#2-基础系统准备)
3. [管理员用户与 SSH 密钥访问](#3-管理员用户与-ssh-密钥访问)
4. [安全 SSH（端口 4428 + 加固）](#4-安全-ssh端口-4428--加固)
5. [防火墙（firewalld）](#5-防火墙firewalld)
6. [必须了解的 SELinux 基础](#6-必须了解的-selinux-基础)
7. [Apache（Web 服务器 / 反向代理）](#7-apacheweb-服务器--反向代理)
8. [PHP 8.5 + PHP-FPM（用于 Laravel）](#8-php-85--php-fpm用于-laravel)
9. [最小权限 MySQL 8](#9-最小权限-mysql-8)
10. [Composer](#10-composer)
11. [部署 Laravel 项目](#11-部署-laravel-项目)
12. [Node.js 24 LTS 服务化 + 反向代理](#12-nodejs-24-lts-服务化--反向代理)
13. [Let's Encrypt（SSL）与自动续期](#13-lets-encryptssl与自动续期)
14. [HTTP 安全响应头](#14-http-安全响应头)
15. [隐藏版本信息（信息泄露）](#15-隐藏版本信息信息泄露)
16. [按 User-Agent 和漏洞路径屏蔽爬虫](#16-按-user-agent-和漏洞路径屏蔽爬虫)
17. [Fail2Ban：主动防御](#17-fail2ban主动防御)
18. [security.txt 与 robots.txt](#18-securitytxt-与-robotstxt)
19. [Git 部署工作流](#19-git-部署工作流)
20. [自动更新与维护](#20-自动更新与维护)
21. [Valkey（缓存、会话与队列）](#21-valkey缓存会话与队列)
22. [公开表单保护（Turnstile + 限流）](#22-公开表单保护turnstile--限流)
23. [性能优化](#23-性能优化)
24. [最终验证检查清单](#24-最终验证检查清单)
25. [附录：DNSSEC、GeoIP 与 PGP](#25-附录dnssecgeoip-与-pgp)

---

## 1. 约定与架构

**推荐目录结构。** 所有内容置于 `/var/www` 下，这是 SELinux 原生为 Apache 预设的上下文：

```
/var/www/
├── myapp-laravel/          # Laravel 项目
│   ├── public/             # <- Apache DocumentRoot（唯一对外暴露的目录）
│   ├── storage/            # 可写（httpd_sys_rw_content_t）
│   ├── bootstrap/cache/    # 可写（httpd_sys_rw_content_t）
│   └── .env                # 绝不放在 public/ 内
└── myapp-node/             # Node 项目
    ├── dist/ 或 build/
    └── .env
```

**核心原则（AlmaLinux 10 上的 SELinux 黄金法则）：** 面对任何新增内容，牢记三大支柱 ——
- **端口** → `semanage port`
- **文件/目录** → `restorecon` / `semanage fcontext`
- **动作权限** → `setsebool`

**网络架构：**
- Apache 监听 `80` 和 `443`（唯一对外开放的 Web 端口）。
- PHP-FPM 通过本地 Unix Socket 运行（不对外暴露）。
- MySQL **仅**监听 `127.0.0.1:3306`（永不对外暴露）。
- 每个 Node 应用运行在*回环*端口（如 `127.0.0.1:3000`），Apache 以 TLS **反向代理**方式对外提供服务。Node 端口**不在**防火墙中开放。

---

## 2. 基础系统准备

```bash
# 必要时确保网络连通
nmtui

# 更新整个系统
dnf update -y

# 基础仓库与工具
dnf install -y epel-release dnf-utils
dnf install -y vim git wget curl tar policycoreutils-python-utils setroubleshoot-server

# 时区（根据您的地区调整）
timedatectl set-timezone Asia/Shanghai

# 时间同步
systemctl enable --now chronyd
```

> `policycoreutils-python-utils` 提供 `semanage`；`setroubleshoot-server` 提供 `sealert`，即 SELinux 错误翻译器。二者对于在不禁用 SELinux 的前提下进行管理不可或缺。

**不要使用 `net-tools`（已过时）。** AlmaLinux 10 已包含 `iproute2`：用 `ss -tulpn` 替代 `netstat`。

**确认 SELinux 处于 Enforcing 模式**（永远不要禁用它）：

```bash
getenforce        # 应返回：Enforcing
sestatus
```

---

## 3. 管理员用户与 SSH 密钥访问

以 `root` 通过 SSH 操作是机器人首先攻击的入口。创建一个具有 `sudo` 权限的用户，始终以该用户身份连接。

**在服务器上：**

```bash
adduser dante
passwd dante                 # 强密码
usermod -aG wheel dante      # 'wheel' = AlmaLinux 上的 sudo 组
```

**在本地机器上**（如尚未生成密钥对，先生成）：

```bash
ssh-keygen -t ed25519 -C "dante@laptop"
# 将公钥复制到服务器（此时仍使用端口 22）
ssh-copy-id dante@your.public.ip.here
```

在继续之前，请验证可以**无需密码**通过密钥登录。如果密钥不起作用，**不要**在下一步禁用密码认证，否则会将自己锁在门外。

---

## 4. 安全 SSH（端口 4428 + 加固）

在 AlmaLinux 10 上，现代 SSH 配置通过 `/etc/ssh/sshd_config.d/` 内的*附加（drop-in）*文件完成（比编辑主配置文件更干净，也更不易被更新覆盖）。

```bash
cat > /etc/ssh/sshd_config.d/99-hardening.conf <<'EOF'
# 非标准端口（减少自动扫描噪音）
Port 4428

# 按需选择 IPv4/IPv6
# AddressFamily inet

# 加固
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no
MaxAuthTries 3
LoginGraceTime 30
X11Forwarding no
AllowUsers dante
EOF
```

> **重要：** 仅修改 SSH 端口是不够的；即使防火墙放行，SELinux 也会阻止新端口。必须为其打标签。

```bash
# 告知 SELinux 新的 SSH 端口
semanage port -a -t ssh_port_t -p tcp 4428

# 验证语法并重启
sshd -t && systemctl restart sshd
```

在关闭当前会话**之前**，先用端口 4428 开启**第二个** SSH 会话，确认能够登录：

```bash
ssh -p 4428 dante@your.public.ip.here
```

---

## 5. 防火墙（firewalld）

不要禁用 `firewalld`：在 AlmaLinux 10 上，它与 SELinux 和 Fail2Ban 完美集成。

```bash
systemctl enable --now firewalld

# 移除标准 SSH 服务（端口 22），开放 4428
firewall-cmd --permanent --remove-service=ssh
firewall-cmd --permanent --add-port=4428/tcp

# 开放 Web 端口
firewall-cmd --permanent --add-service=http
firewall-cmd --permanent --add-service=https

# 应用规则
firewall-cmd --reload

# 验证
firewall-cmd --list-all
```

预期结果：仅开放 `4428/tcp`、`http` 和 `https`。端口 `22`、`3306`（MySQL）和 Node 内部端口**不应出现**。外部扫描器应将其显示为关闭/过滤状态。

---

## 6. 必须了解的 SELinux 基础

SELinux 并非"随意"阻止服务：它确保每个进程只能访问其被授权的内容（*默认拒绝*策略）。

**无需配置的场景：**
- 通过 80/443 端口提供 `/var/www` 下的内容。在那里创建的文件会自动继承 `httpd_sys_content_t` 标签。

**最常见的"但是"：** 如果您用 `mv` 将文件从 `/home/user` **移动**到 `/var/www`，它们会保留原始标签，Apache 将返回 **403 Forbidden**。通用解决方案：

```bash
restorecon -Rv /var/www/myapp
```

**您将用到的动作权限（布尔值）：**

| 场景 | 命令 |
|---|---|
| Laravel 连接本地 MySQL | `setsebool -P httpd_can_network_connect_db on` |
| Apache 反向代理 Node 应用 | `setsebool -P httpd_can_network_connect on` |
| Apache 读取非标准目录 | `setsebool -P httpd_enable_homedirs on` |

**Apache/Laravel 需要写入的目录：**

```bash
semanage fcontext -a -t httpd_sys_rw_content_t "/var/www/myapp/storage(/.*)?"
semanage fcontext -a -t httpd_sys_rw_content_t "/var/www/myapp/bootstrap/cache(/.*)?"
restorecon -Rv /var/www/myapp
```

> `setsebool` 中的 `-P` 标志**至关重要**：它使更改在重启后持久生效。

**诊断工具（而非禁用 SELinux）：**

```bash
# 实时查看拒绝日志
tail -f /var/log/audit/audit.log | grep denied

# 人类可读的错误翻译
sealert -a /var/log/audit/audit.log
```

---

## 7. Apache（Web 服务器 / 反向代理）

```bash
dnf install -y httpd mod_ssl
systemctl enable --now httpd
```

确保代理模块（Node 所需）和 rewrite 模块（用于爬虫屏蔽）已加载：

```bash
# 在 AlmaLinux 10 上通常已激活；验证：
httpd -M | grep -E "proxy_module|proxy_http|proxy_wstunnel|rewrite|headers|ssl"
```

若有缺失，模块位于 `/etc/httpd/conf.modules.d/`。通常 `proxy`、`proxy_http`、`rewrite`、`headers` 和 `ssl` 已启用；`proxy_wstunnel` 可能需要为 WebSocket 手动添加。

---

## 8. PHP 8.5 + PHP-FPM（用于 Laravel）

PHP 8.5 已作为稳定模块由 Remi 为 Enterprise Linux 10 提供。

```bash
# AlmaLinux 10 的 Remi 仓库
dnf install -y https://rpms.remirepo.net/enterprise/remi-release-10.rpm

# 选择 PHP 8.5 模块流
dnf module reset php -y
dnf module enable php:remi-8.5 -y

# 安装 PHP-FPM 及 Laravel/Filament 常用扩展
dnf install -y php php-cli php-common php-fpm \
  php-mysqlnd php-pdo php-mbstring php-xml php-curl \
  php-gd php-zip php-bcmath php-intl php-opcache php-redis

systemctl enable --now php-fpm
php -v   # 确认 8.5.x
```

**以 Apache 用户运行的 PHP-FPM 池。** 编辑 `/etc/php-fpm.d/www.conf` 确保以下配置：

```ini
user = apache
group = apache
listen = /run/php-fpm/www.sock
listen.owner = apache
listen.group = apache
listen.mode = 0660
```

该软件包会安装 `/etc/httpd/conf.d/php.conf`，通过 `SetHandler "proxy:unix:/run/php-fpm/www.sock|fcgi://localhost"` 将 `.php` 请求路由到 PHP-FPM Socket，无需手动配置（特殊情况除外）。

```bash
systemctl restart php-fpm httpd
```

---

## 9. 最小权限 MySQL 8

```bash
dnf install -y mysql-server
systemctl enable --now mysqld

# 安全初始化（设置 root 密码、删除匿名用户等）
mysql_secure_installation
```

**将 MySQL 绑定到仅本地监听**（不对外网监听）。在 `/etc/my.cnf.d/mysql-server.cnf` 的 `[mysqld]` 下：

```ini
bind-address = 127.0.0.1
```

```bash
systemctl restart mysqld
```

**创建数据库和最小权限用户**（不要对应用使用 `*.*` 或 `WITH GRANT OPTION`，那是旧指南中的危险模式）：

```sql
CREATE DATABASE myapp CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE USER 'myapp'@'localhost' IDENTIFIED BY 'AStrongRandomPassword_2026!';

-- 仅授予其自有数据库的权限，仅此而已
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, INDEX, DROP, REFERENCES
  ON myapp.* TO 'myapp'@'localhost';

FLUSH PRIVILEGES;
```

> MySQL 8 默认使用 `caching_sha2_password`，这是推荐方式。仅当旧版库需要时才回退到 `mysql_native_password`。

如果 Laravel 连接数据库时返回 500 错误，几乎总是 SELinux 布尔值的问题：

```bash
setsebool -P httpd_can_network_connect_db on
```

---

## 10. Composer

现代 Laravel 需要 Composer 2.x（而非旧指南中的 1.9）：

```bash
php -r "copy('https://getcomposer.org/installer', 'composer-setup.php');"
php composer-setup.php --install-dir=/usr/local/bin --filename=composer
rm composer-setup.php
composer --version
```

---

## 11. 部署 Laravel 项目

```bash
mkdir -p /var/www/myapp
chown -R apache:apache /var/www/myapp

# 克隆或上传项目到 /var/www/myapp（Git 流程见第 19 节）
cd /var/www/myapp
composer install --no-dev --optimize-autoloader

# Laravel 写入权限（Linux + SELinux）
chown -R apache:apache storage bootstrap/cache
semanage fcontext -a -t httpd_sys_rw_content_t "/var/www/myapp/storage(/.*)?"
semanage fcontext -a -t httpd_sys_rw_content_t "/var/www/myapp/bootstrap/cache(/.*)?"
restorecon -Rv /var/www/myapp

# Laravel 优化
php artisan config:cache
php artisan route:cache
php artisan view:cache
```

**Laravel VirtualHost** `/etc/httpd/conf.d/myapp.conf`（HTTP 重定向到 HTTPS；443 块由 Certbot 补全，见第 13、14 节）：

```apache
<VirtualHost *:80>
    ServerName your-domain.com
    DocumentRoot /var/www/myapp/public
    Redirect permanent / https://your-domain.com/
</VirtualHost>
```

> `DocumentRoot` 指向 `public/`，使 `.env`、`vendor/` 及其余代码不在 Web 可访问范围内。

**Laravel 调度器 Cron** —— 必须以 Apache 用户运行，以避免权限问题：

```bash
# crontab -u apache -e
* * * * * cd /var/www/myapp && php artisan schedule:run >> /dev/null 2>&1
```

---

## 12. Node.js 24 LTS 服务化 + 反向代理

截至 2026 年 5 月，**Node.js 24 是当前活跃 LTS 版本**，推荐用于生产（Node 26 处于 *Current* 阶段，尚非 LTS）。

### 12.1 安装 Node 24

```bash
# NodeSource 官方 24.x 分支仓库
curl -fsSL https://rpm.nodesource.com/setup_24.x | bash -
dnf install -y nodejs
node -v    # v24.x
npm -v
```

> 替代方案：`dnf module enable nodejs:24 && dnf install nodejs`（来自 AppStream），若不希望添加外部仓库（可能落后一两个次版本）。

### 12.2 专用用户与代码

不要以 `root` 运行 Node。创建一个无登录 Shell 的系统用户：

```bash
useradd --system --create-home --home-dir /var/www/myapp-node --shell /usr/sbin/nologin nodeapp
# 上传/克隆应用到 /var/www/myapp-node 并构建
cd /var/www/myapp-node
sudo -u nodeapp npm ci --omit=dev
sudo -u nodeapp npm run build   # 如适用
```

### 12.3 systemd 服务（比以 root 运行 PM2 更干净、更安全）

创建 `/etc/systemd/system/myapp-node.service`：

```ini
[Unit]
Description=My Node App
After=network.target

[Service]
Type=simple
User=nodeapp
Group=nodeapp
WorkingDirectory=/var/www/myapp-node
# 应用必须监听回环地址：host 127.0.0.1，port 3000
Environment=NODE_ENV=production
Environment=PORT=3000
Environment=HOST=127.0.0.1
ExecStart=/usr/bin/node dist/server.js
Restart=on-failure
RestartSec=5

# 服务加固
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable --now myapp-node
systemctl status myapp-node
ss -tlpn | grep 3000      # 必须仅监听 127.0.0.1:3000
```

> 确保应用读取 `process.env.HOST` 和 `process.env.PORT`，并**监听 `127.0.0.1`**，而非 `0.0.0.0`。这样端口 3000 永远无法从互联网直接访问，只有 Apache 可以连接。

### 12.4 在 SELinux 中允许代理

让 Apache 能够向 Node 端口建立网络连接：

```bash
setsebool -P httpd_can_network_connect on
```

### 12.5 反向代理 VirtualHost

`/etc/httpd/conf.d/myapp-node.conf`：

```apache
<VirtualHost *:80>
    ServerName node.your-domain.com
    Redirect permanent / https://node.your-domain.com/
</VirtualHost>

<VirtualHost *:443>
    ServerName node.your-domain.com

    ProxyPreserveHost On
    ProxyPass        / http://127.0.0.1:3000/
    ProxyPassReverse / http://127.0.0.1:3000/

    # WebSocket 支持（若您的应用使用：Socket.io 等）
    RewriteEngine On
    RewriteCond %{HTTP:Upgrade} =websocket [NC]
    RewriteRule /(.*) ws://127.0.0.1:3000/$1 [P,L]

    # （第 14 节的安全响应头同样适用于此）
    # （Certbot 将在此添加 SSL 指令）

    ErrorLog  /var/log/httpd/myapp-node-error.log
    CustomLog /var/log/httpd/myapp-node-access.log combined
</VirtualHost>
```

```bash
apachectl configtest && systemctl restart httpd
```

> **不要在 firewalld 中开放端口 3000。** 流量通过 443（Apache，带 TLS）进入并在内部转发。Node 保持隔离。

---

## 13. Let's Encrypt（SSL）与自动续期

```bash
dnf install -y certbot python3-certbot-apache

# 每个域名/子域名一张证书
certbot --apache -d your-domain.com
certbot --apache -d node.your-domain.com
```

Certbot 会自动将 `SSLCertificateFile`、`SSLCertificateKeyFile` 和 `Include /etc/letsencrypt/options-ssl-apache.conf` 指令插入您的 443 VirtualHost。

**自动续期。** 软件包会安装一个 systemd *定时器*，无需干预自动续期。验证它：

```bash
systemctl list-timers | grep certbot
certbot renew --dry-run     # 演习确认续期功能正常
```

---

## 14. HTTP 安全响应头

这些响应头修复 web-check.xyz 等扫描器的典型发现（HSTS、点击劫持、MIME 嗅探、XSS、CSP）。将其添加到每个站点的 `<VirtualHost *:443>` 块中。

```apache
# HSTS：强制 HTTPS 两年（符合预加载列表条件）
Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"

# 防点击劫持
Header always set X-Frame-Options "SAMEORIGIN"

# 防 MIME 嗅探
Header always set X-Content-Type-Options "nosniff"

# 引用策略
Header always set Referrer-Policy "strict-origin-when-cross-origin"

# Permissions-Policy（限制浏览器 API）
Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"

# Content-Security-Policy：防 XSS 最强手段。
# 调整您实际使用的外部域名（字体、地图、分析服务等）。
Header always set Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://fonts.googleapis.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self';"

# 移除版本泄露
ServerSignature Off
Header unset X-Powered-By
```

> **关于 `X-XSS-Protection`：** 该响应头已过时，现代浏览器会忽略它（有些建议设为 `0`）。今天真正的 XSS 防护是良好的 **CSP**。如果您的扫描器仍要求它，可以添加 `Header set X-XSS-Protection "1; mode=block"`，但这不是安全的核心所在。

> **CSP 是迭代的。** 先用上面的策略；如果某些内容停止加载（外部脚本、地图、Google Analytics），将该域名添加到对应指令中。对于 Filament，通常 `'self' 'unsafe-inline' 'unsafe-eval'` 就足够了。

```bash
apachectl configtest && systemctl restart httpd
```

---

## 15. 隐藏版本信息（信息泄露）

告诉全世界"我在使用 PHP 8.5.6 和 Apache 2.4.63"，相当于给攻击者提供了精确的漏洞利用地图。

**Apache** —— 创建 `/etc/httpd/conf.d/00-security.conf`：

```apache
ServerTokens Prod
ServerSignature Off
TraceEnable Off
```

**PHP** —— 在 `/etc/php.ini` 中：

```ini
expose_php = Off
```

```bash
systemctl restart php-fpm httpd
```

此后，`Server` 响应头将仅显示 `Apache`（无版本号），`X-Powered-By: PHP/...` 将消失。

---

## 16. 按 User-Agent 和漏洞路径屏蔽爬虫

真实日志显示两类自动化噪音：以已知 User-Agent 自我标识的扫描器（`l9scan`、`zgrab`、`Nikto`、`CensysInspect`），以及请求应用中不存在路径的爬虫（`/.env`、`/.git/config`、`/vendor/phpunit/.../eval-stdin.php`、`/wp-config.php`）。值得在 **VirtualHost 层面**同时拦截两类，在请求到达 PHP 之前截断。

> **经验教训 —— 不要用 `^` 锚定 User-Agent。** 旧版本使用 `RewriteCond %{HTTP_USER_AGENT} ^Nmap`，只有当 UA *精确以*该字符串*开头*时才匹配。像 `l9scan` 这样的爬虫自我标识为 `Mozilla/5.0 (l9scan/2.0...)`，因此锚定让它们漏过去了。正确的规则应在 User-Agent **任意位置**搜索该字符串。

将屏蔽规则直接置于 `<VirtualHost *:443>` 下，而非 `<Directory>` 内。服务器上下文在 Laravel 的 `.htaccess` 之前独立求值，因此屏蔽适用于所有请求，无论 Laravel 后续如何处理。此上下文需要显式的 `RewriteEngine On`：

```apache
RewriteEngine On

# 1) 按 User-Agent 屏蔽 —— 不使用 ^ 锚定，在字符串任意位置匹配
#    （如 "Mozilla/5.0 (l9scan/...)" 不再漏过）
RewriteCond %{HTTP_USER_AGENT} (l9explore|l9scan|l9tcpid|Nmap|Masscan|zgrab|Nikto|CensysInspect|leakix|libredtail|Gh0st) [NC]
RewriteRule ^ - [F,L]

# 2) 非根路径请求中的空 User-Agent（原始爬虫）
RewriteCond %{HTTP_USER_AGENT} ^-?$
RewriteCond %{REQUEST_URI} !^/$
RewriteRule ^ - [F,L]

# 3) 屏蔽隐藏文件（.env、.git 等）
#    但 /.well-known 除外（Let's Encrypt 续期所需）
RewriteRule "(^|/)\.(?!well-known)" - [F,L]

# 4) 已知漏洞路径（PHPUnit eval-stdin、vendor、垃圾 .php）
RewriteCond %{REQUEST_URI} (eval-stdin\.php|/vendor/|/phpunit|/wp-|xmlrpc\.php|/phpinfo|/\.aws|/\.ssh) [NC]
RewriteRule ^ - [F,L]
```

> **`/.well-known` 至关重要。** 如果不加例外地屏蔽所有点文件，会破坏 Certbot 的 ACME 挑战（`/.well-known/acme-challenge/`），导致证书无法续期。`(?!well-known)` 保护了它。

> **不要按 User-Agent 屏蔽 `curl`。** 虽然它出现在扫描中，但它也是您自己用于测试和健康检查的工具。这种行为最好交给 Fail2Ban 处理（按行为封禁，而非按名称），见第 17 节。

从此，这些爬虫将收到 **403 Forbidden** 而非 404。这很好：Fail2Ban（下一节）会封禁任何累积 403 的 IP。

```bash
apachectl configtest && systemctl restart httpd
```

**可量化的结果。** 在本服务器的真实案例中，应用屏蔽后，日志每天记录数百个针对 `/.env`、`/.git/config`、`/wp-config.php` 和 `/.aws/credentials` 扫描的 `403`，这些请求此前以无害的 `404` 形式通过，但实际上到达了 PHP。单个激进扫描 IP（`45.148.10.95`）在一天内累积了 220 次封禁，而未触碰应用程序。

---

## 17. Fail2Ban：主动防御

防火墙是被动的墙；Fail2Ban 是读取日志并在网络层封禁惯犯 IP 的守卫。

```bash
dnf install -y fail2ban fail2ban-firewalld
```

**主配置** —— 永远不要编辑 `jail.conf`；创建 `/etc/fail2ban/jail.local`：

```ini
[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 5
# 通过 firewalld 封禁（AlmaLinux 10 原生集成）
banaction = firewallcmd-rich-rules
# 重要：添加您自己的固定 IP，避免自封
ignoreip = 127.0.0.1/8 ::1 your.public.ip.here

[sshd]
enabled = true
port    = 4428
backend = systemd

[apache-auth]
enabled = true
port    = http,https
logpath = %(apache_error_log)s

[apache-noscript]
enabled = true
port    = http,https
logpath = %(apache_error_log)s

[apache-overflows]
enabled  = true
port     = http,https
logpath  = %(apache_error_log)s
maxretry = 2
```

**自定义过滤器**，用于捕获 `.env`/`.git` 扫描和 User-Agent 屏蔽产生的 403。创建 `/etc/fail2ban/filter.d/laravel-vulnerabilities.conf`：

```ini
[Definition]
# 捕获 404（敏感文件探测）和 403（User-Agent / 点文件屏蔽）
failregex = ^<HOST> -.*"GET .*\.(env|git|aws|yml|yaml|json).* HTTP/.*" (404|403)
            ^<HOST> -.*"GET .*(\.git|config|credentials).* HTTP/.*" (404|403)
            ^<HOST> -.*"(GET|POST) .* HTTP/.*" 403
ignoreregex =
```

> **关于公开表单滥用（注册、联系表单）。** 反复轮询 `POST /register` 的 IP 会轮换地址并使用真实浏览器 User-Agent，因此 403 过滤器无法捕获它们：在 HTTP 层，它们与真实用户无法区分。针对此类情况，**正确的防御不是 Fail2Ban**，而是 Cloudflare Turnstile + 限流 + 邮件验证（见第 22 节）。如果您仍希望 Fail2Ban 对最顽固的 IP 做出响应，可以添加一个按 IP 统计 `429`（Laravel 限流响应）的过滤器，但这是次级防御，不是主要手段。

**Jail**，将该过滤器应用于访问日志（将路径调整为您的 `CustomLog`）。在 `jail.local` 末尾添加：

```ini
[laravel-scan]
enabled  = true
port     = http,https
filter   = laravel-vulnerabilities
logpath  = /var/log/httpd/myapp-access.log
maxretry = 2
bantime  = 48h
findtime = 1h
```

**启用并验证：**

```bash
systemctl enable --now fail2ban
fail2ban-client status
fail2ban-client status laravel-scan

# 对当前日志测试过滤器（统计"Hits"数）
fail2ban-regex /var/log/httpd/myapp-access.log /etc/fail2ban/filter.d/laravel-vulnerabilities.conf
```

**SELinux 与自定义日志。** 若 Fail2Ban 无法读取您的自命名日志，检查其上下文：

```bash
ls -Z /var/log/httpd/myapp-access.log   # 应为 httpd_log_t
restorecon -v /var/log/httpd/myapp-access.log
```

> 如需解封自己：`fail2ban-client set laravel-scan unbanip 1.2.3.4`。

至此您拥有**纵深防御**：Apache 识别爬虫并关门（403）→ 记录到日志 → Fail2Ban 检测惯犯 IP 并在 firewalld 中封禁。

---

## 18. security.txt 与 robots.txt

**security.txt**（安全研究人员负责任披露漏洞的标准）：

```bash
mkdir -p /var/www/myapp/public/.well-known
cat > /var/www/myapp/public/.well-known/security.txt <<'EOF'
Contact: mailto:security@your-domain.com
Expires: 2027-01-01T00:00:00.000Z
Preferred-Languages: zh, en
EOF
restorecon -Rv /var/www/myapp/public/.well-known
```

**robots.txt** —— 用于劝阻合法爬虫索引管理后台（这仅是对合法爬虫的*建议*；`/admin` 真正的安全来自 Laravel/Filament 登录）：

```
User-agent: *
Disallow: /admin/
Disallow: /admin
Allow: /
```

---

## 19. Git 部署工作流

**经典错误：** `fatal: detected dubious ownership in repository`。原因是目录归 `apache` 所有，但您以其他用户身份运行 Git。

```bash
git config --global --add safe.directory /var/www/myapp
```

**真正的问题：** `git pull` 后，新文件会失去 `apache` 所有者和/或 SELinux 上下文，Apache 返回 403/500。正确的生产部署流程：

```bash
git pull origin main
chown -R apache:apache /var/www/myapp
restorecon -Rv /var/www/myapp        # 恢复 SELinux 标签
php /var/www/myapp/artisan optimize
```

**用部署脚本自动化**（`/usr/local/bin/deploy-myapp`）：

```bash
#!/usr/bin/env bash
set -euo pipefail
cd /var/www/myapp
git pull origin main
composer install --no-dev --optimize-autoloader
php artisan migrate --force
php artisan config:cache && php artisan route:cache && php artisan view:cache
chown -R apache:apache /var/www/myapp
restorecon -Rv /var/www/myapp
echo "Deploy OK"
```

```bash
chmod +x /usr/local/bin/deploy-myapp
```

> **`restorecon` 为何至关重要：** Git 为新文件分配临时标签；若不运行 `restorecon`，即使 `chmod`/`chown` 完全正确，SELinux 也可能以 403 阻止对其的读取。

对于 Node，等效操作是重启服务：`... && systemctl restart myapp-node`。

---

## 20. 自动更新与维护

**自动安全补丁：**

```bash
dnf install -y dnf-automatic
# 在 /etc/dnf/automatic.conf 中 -> apply_updates = yes（或仅通知）
systemctl enable --now dnf-automatic.timer
```

**推荐的手动例行检查：**

```bash
dnf update --security        # 安全补丁
certbot renew --dry-run      # 确认 SSL 续期
fail2ban-client status       # 查看封禁情况
```

**备份（最小可行方案）：** 安排每日 MySQL 转储以及 `/var/www` 和 `/etc/httpd` 的备份：

```bash
mysqldump --single-transaction --routines myapp | gzip > /backups/myapp-$(date +\%F).sql.gz
```

---

## 21. Valkey（缓存、会话与队列）

为让 Laravel/Filament 在生产中表现良好，将缓存、会话和队列从数据库迁移到内存存储。**AlmaLinux 10 不再包含 Redis**（Redis Labs 在 7.4 版本更改为非 FOSS 许可证，该发行版已将其从仓库中移除）；AppStream 中的官方替代品是 **Valkey**，一个 FOSS 许可证的分支。它是*直接替换（drop-in）*：phpredis 和 Laravel 的 `redis` 驱动无需修改任何应用代码即可与 Valkey 通信。

> **为什么选 Valkey 而非通过 Remi 使用 Redis。** Redis 在 8.0 版本回归了开源许可证（AGPLv3），且 `remi-modular` 中有 RPM，但这会将一个*数据存储*（将存储会话）的安全更新绑定到第三方仓库。来自官方 AppStream 的 Valkey 按照发行版的正常周期接收补丁，维护开销更低。除非您需要 Redis 8.x 的某个很新的功能，否则 Valkey 是推荐选择。

### 21.1 安装

```bash
dnf install -y valkey
valkey-server --version
```

### 21.2 安全配置

Redis/Valkey 的经典威胁模型是"无密码暴露在互联网上的实例"。由于这里 Valkey 与 Laravel 运行在**同一台服务器**上，最安全的做法是**完全不将其暴露在网络上**：Unix Socket + 无 TCP 端口。先生成一个强密码：

```bash
openssl rand -base64 48
```

编辑 `/etc/valkey/valkey.conf`（许多指令已以注释形式存在；找到它们并调整）：

```conf
# --- 网络：不暴露给任何接口 ---
bind 127.0.0.1 -::1
protected-mode yes
port 0                              # 完全禁用 TCP；仅使用 Unix Socket

# --- Unix Socket：Laravel 的连接方式 ---
unixsocket /run/valkey/valkey.sock
unixsocketperm 770

# --- 认证 ---
requirepass "PASTE_GENERATED_PASSWORD_HERE"

# --- 内存与策略 ---
maxmemory 2gb                       # 根据您分配的内存调整
maxmemory-policy allkeys-lru        # 注意拼写：是 allkeys-lru（含 'a'）

# --- 持久化（重启后不丢失会话/队列）---
appendonly yes
appendfsync everysec

# --- 危险命令 ---
rename-command FLUSHALL ""
rename-command FLUSHDB ""
rename-command KEYS ""                  # KEYS 在生产中会阻塞服务器；Laravel 不使用它
rename-command CONFIG "CONFIG_a8f3k2"   # 重命名为不可预测的名称，而非直接删除
```

> **一个拼写错误会导致启动失败。** 若 Valkey 无法启动，检查 `systemctl status valkey`：`FATAL CONFIG FILE ERROR` 消息会指出错误的精确行号。一个拼写错误的值（如 `llkeys-lru` 而非 `allkeys-lru`）会阻止启动，进而导致 Socket 永远不会创建 —— 因此连接时出现的 `No such file or directory` 是症状，而非原因。

### 21.3 Socket 目录、权限与 SELinux

`/run` 中的 Socket 目录是临时的；用 tmpfiles 持久化创建，使其在重启后存活：

```bash
echo 'd /run/valkey 0750 valkey valkey -' > /etc/tmpfiles.d/valkey.conf
systemd-tmpfiles --create
```

为使 PHP-FPM（以及 Netdata，如果使用）能读取 Socket，将这些用户添加到 `valkey` 组 —— 与 `apache` 的组成员逻辑相同：

```bash
usermod -aG valkey apache
usermod -aG valkey dante         # 若您的 FPM 池以 dante 运行
usermod -aG valkey netdata       # 若您使用 Netdata 监控
```

SELinux：启用 Web 连接布尔值，若有拒绝则为 Socket 目录打标签：

```bash
setsebool -P httpd_can_network_connect 1
semanage fcontext -a -t redis_var_run_t "/run/valkey(/.*)?" 2>/dev/null || true
restorecon -Rv /run/valkey

# 若 Valkey 因 SELinux 失败，检查拒绝并生成针对性策略：
ausearch -m avc -ts recent | grep -iE "valkey|redis"
```

### 21.4 服务加固（systemd）

用附加（drop-in）文件而非编辑原始 unit 来强化隔离：

```bash
systemctl edit valkey
```

```ini
[Service]
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
NoNewPrivileges=true
ReadWritePaths=/var/lib/valkey /run/valkey /var/log/valkey
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
MemoryDenyWriteExecute=true
```

### 21.5 启动与验证

```bash
systemctl enable --now valkey
systemctl status valkey --no-pager

# 通过 Socket 带认证连接
valkey-cli -s /run/valkey/valkey.sock
#   AUTH "your_password"
#   PING            -> 应响应 PONG
#   exit

# 确认没有 TCP 端口在监听（应为空）
ss -tlnp | grep 6379
```

### 21.6 与 Laravel 集成

确认 phpredis 扩展（C 编译，比 Predis 更快；使用此方式无需通过 Composer 安装 `predis/predis`）：

```bash
php -m | grep -i redis
# 若缺失：
dnf install -y php-redis && systemctl reload php-fpm
```

在每个平台的 `.env` 中，指向 Socket 并**分离**可驱逐数据（缓存，使用一个 DB）与不应消失的数据（会话/队列，使用另一个 DB）。使用 Unix Socket 时，`REDIS_PORT` 必须为 `0`：

```env
REDIS_CLIENT=phpredis
REDIS_HOST=/run/valkey/valkey.sock
REDIS_PORT=0
REDIS_PASSWORD="your_password"

REDIS_DB=0          # 会话和队列（不应被驱逐）
REDIS_CACHE_DB=1    # 缓存（可用 allkeys-lru 驱逐）

CACHE_STORE=redis
SESSION_DRIVER=redis
QUEUE_CONNECTION=redis
```

> **多平台时 `prefix` 很重要。** 所有应用共享同一个 Valkey 实例。Laravel 的默认键前缀来自 `APP_NAME`，因此确保每个平台有不同的 `APP_NAME`（或显式的 `REDIS_PREFIX`），否则一个应用的缓存键会覆盖另一个的。

由于您已缓存配置，**对 `.env` 的修改在重新生成缓存之前不会生效**：

```bash
php artisan config:clear && php artisan config:cache

php artisan tinker
>>> Cache::store('redis')->put('test', 'ok', 60); Cache::store('redis')->get('test');   # -> "ok"
```

> **变量仍然叫 `REDIS_*`，驱动名仍是 `redis`**：这只是客户端名称。底层它在与 Valkey 通信，而无需知晓或在意。

**键检查。** 由于禁用了 `KEYS`，使用 `SCAN`（不阻塞服务器）。在 Shell 中，`--scan` 自动迭代：

```bash
export REDISCLI_AUTH="your_password"     # 避免在 Shell 历史中暴露密码
valkey-cli -s /run/valkey/valkey.sock -n 1 --scan                        # 所有缓存键（DB 1）
valkey-cli -s /run/valkey/valkey.sock -n 1 --scan --pattern "myapp_*"    # 按应用前缀过滤
valkey-cli -s /run/valkey/valkey.sock INFO keyspace                      # 一目了然地统计各 DB 键数
```

> **安全顺序：** 先完整安装并验证 Valkey（直到 `PING` 响应 `PONG`），**再**修改 `.env` 文件。这样，若连接出现问题，不会让应用陷入无缓存、无会话的状态。

---

## 22. 公开表单保护（Turnstile + 限流）

公开注册表单是批量自动创建虚假账户的攻击目标。在本服务器上，日志显示多个 IP（来自托管服务提供商 IP 段，非真实用户）持续成功发送 `POST /register`。仅靠限流**远远不够**，因为爬虫会轮换 IP：每个 IP 都保持在阈值以下。有效防御必须是多层的。

### 22.1 Cloudflare Turnstile（核心组件）

Turnstile 是免费且尊重隐私的 CAPTCHA。关键在于验证必须在**服务端**进行，而不仅仅是渲染 Widget：直接发送 POST 请求而不经过浏览器的爬虫必须同样被拒绝。

验证服务（`app/Services/TurnstileService.php`）：

```php
public function verify(string $token, string $ip): bool
{
    // 廉价守卫：空 token = 根本不调用 Cloudflare。
    // 避免在最常见的滥用场景（无 token 的 POST）中产生网络往返（及其超时）。
    if ($token === '') {
        return false;
    }

    try {
        $response = Http::asForm()->timeout(5)->post(self::VERIFY_URL, [
            'secret'   => config('services.turnstile.secret_key'),
            'response' => $token,
            'remoteip' => $ip,
        ]);

        return $response->successful() && $response->json('success') === true;
    } catch (\Illuminate\Http\Client\ConnectionException) {
        return false;   // fail-closed：若 Cloudflare 无响应，则无人能注册
    }
}
```

在控制器中，在验证或操作数据库**之前**进行验证：

```php
if (! $this->turnstile->verify((string) $request->input('cf-turnstile-response'), $request->ip())) {
    return back()->withInput()->withErrors(['captcha' => '无法验证您是人类，请重试。']);
}
```

两个需要有意识的设计决策：`catch` 返回 `false`（**fail-closed**），对于阻止滥用是正确的，但意味着 Cloudflare 网络故障会阻止合法注册；如果您有**多个注册路由**（如主机端和客户端），**两者**都必须进行验证，否则爬虫会使用未保护的那个。

### 22.2 针对性限流（次级防御层）

添加 Turnstile 时不要删除限流器；二者相辅相成。对注册路由，比默认设置更严格：

```php
RateLimiter::for('register', function (Request $request) {
    return [
        Limit::perMinute(3)->by($request->ip()),
        Limit::perDay(10)->by($request->ip()),
    ];
});
```

### 22.3 强制邮件验证（遏制）

即使某个账户成功注册，在验证邮箱之前也不应能做任何事。在 `User` 模型上使用 `MustVerifyEmail`，在受保护路由上使用 `verified` 中间件。这将任何漏网的垃圾账户变成无效账户。

### 22.4 如何验证其是否生效（日志具有误导性）

Apache 日志**无法区分**成功注册和 Turnstile 拒绝：两者都产生 `302`（成功重定向到 `/verification.notice`；拒绝用 `back()` 返回表单）。因此，看到 `/register` 上有数百个 `302` **并不意味着**正在创建账户。真正的温度计是数据库：

```sql
SELECT COUNT(*) FROM users WHERE created_at >= CURDATE();
```

如果在日志持续显示尝试的同时，该计数保持在您预期的真实数字（或零，如果您不期望有合法注册），说明 Turnstile 正在发挥作用。**爬虫不会停止尝试** —— 您将继续看到 `302` 和 `POST` —— 但它们不会创建账户。不要被日志噪音惊扰；关注 `COUNT`。

> **真正的纵深防御：** Turnstile 消灭自动化注册，限流器捕获最顽固的，VHost 屏蔽（第 16 节）在到达 PHP 之前阻止扫描，Fail2Ban（第 17 节）在防火墙层封禁惯犯。每一层都弥补其他层的不足。

---

## 23. 性能优化

服务器安全配置完成后，以下是 Laravel/Filament 的性能调优方向。**用数据说话，而非凭感觉：** 在固定数值之前，先在负载下测量实际消耗，每次只应用一个更改并验证其效果。

> **第零步（关键）：** 确认每个应用处于生产模式。`php artisan about` 必须显示 `Environment = production` 和 `Debug Mode = OFF`。在公开服务器上设置 `APP_DEBUG=true`，任何异常都会向访问者暴露凭据和环境变量 —— 这既是安全漏洞，也是性能损耗。

### 23.1 OPcache

默认值（`memory_consumption=128`、`max_accelerated_files=10000`）对于多个 Laravel + Filament 应用来说严重不足：单个项目加上其 `vendor/` 大约有 8–12k 个文件，两个应用就会导致 OPcache 持续驱逐。在 `/etc/php.d/10-opcache.ini` 中：

```ini
opcache.enable=1
opcache.memory_consumption=512        ; 从 128 提升
opcache.interned_strings_buffer=32    ; 从 8 提升
opcache.max_accelerated_files=65000   ; 从 10000 提升
opcache.save_comments=1               ; 不要关闭：Filament/Laravel 使用属性
opcache.validate_timestamps=0         ; 仅在部署时重置 OPcache 时使用（见下文）
opcache.revalidate_freq=0
```

并启用 PCRE JIT（加速路由/验证的正则引擎），通常默认禁用：

```ini
; /etc/php.d/30-pcre.ini
pcre.jit=1
```

> `validate_timestamps=0` 仅当您的部署脚本（第 19 节）以 OPcache 重置结束时才使用（`cachetool opcache:reset` 或 `systemctl reload php-fpm`）；否则部署后代码更改不会反映出来。**PHP JIT**（与 PCRE JIT 不同）可以保持禁用：对于像 Laravel 这样的 I/O 密集型负载，收益微乎其微。

### 23.2 PHP-FPM：每平台一个池

所有应用共享单个 `www` 池是脆弱的：一个应用的流量峰值可能耗尽其他应用的 Worker，而且所有应用以相同的 `apache` 用户运行并共享日志。正确做法是**每个平台一个池**，各自有独立用户。在 `/etc/php-fpm.d/myapp.conf` 中：

```ini
[myapp]
user = dante
group = apache
listen = /run/php-fpm/myapp.sock
listen.owner = apache
listen.group = apache
listen.mode = 0660

pm = ondemand                          ; 低/中流量：空闲时释放内存
pm.max_children = 20
pm.process_idle_timeout = 30s
pm.max_requests = 500                  ; 回收 Worker -> 避免内存泄漏

php_admin_value[memory_limit] = 384M   ; 按池设置，而非全局的 1024M
slowlog = /var/log/php-fpm/myapp-slow.log
request_slowlog_timeout = 5s
pm.status_path = /status
```

> 高全局 `memory_limit`（如 1024M）对 Web 很危险：50 个子进程 × 1 GB = 理论上 50 GB。CLI（迁移、导出）可以保持高值，但按池限制。在负载下测量每个进程的实际内存占用以确定 `max_children`：
> ```bash
> ps --no-headers -o rss -C php-fpm | awk '{s+=$1;n++} END {printf "%.0f MB 均值, %d 进程\n", s/n/1024, n}'
> ```

### 23.3 MySQL 8.4

> **方法论提示：** 数据量少时对 MySQL 进行深度调优是过早优化。初期最有价值的是**启用慢查询日志**，以便在真实流量到来时有据可查。

在 `/etc/my.cnf.d/optimization.cnf` 中：

```ini
[mysqld]
# 诊断（初期最重要）
slow_query_log = ON
long_query_time = 1
log_queries_not_using_indexes = ON     ; 噪音较多；初期阶段后关闭

# Redo 日志（8.4 中替代 innodb_log_file_size；默认约 48M 太小）
innodb_redo_log_capacity = 1G          ; 需要重启 MySQL

# 适合硬件（SATA SSD，非 NVMe）。10000 对这类磁盘不切实际。
innodb_io_capacity = 2000
innodb_io_capacity_max = 4000

tmp_table_size = 64M
max_heap_table_size = 64M
```

> **不要将 `innodb_flush_log_at_trx_commit` 降至 1 以下**（如果您处理财务/会计数据）：不要为了微基准测试而牺牲事务完整性。随着数据增长，再逐步提高 `innodb_buffer_pool_size`（默认值可能不足）；您有足够的内存。

### 23.4 Apache MPM event 与 HTTP/2

使用 PHP-FPM 时，MPM 必须是 **event**（非 prefork）。明确定义限制并确认 HTTP/2 和压缩：

```apache
<IfModule mpm_event_module>
    StartServers             3
    ServerLimit              16
    ThreadLimit              64
    ThreadsPerChild          25
    MaxRequestWorkers        400
    MinSpareThreads          75
    MaxSpareThreads          250
    MaxConnectionsPerChild   10000
</IfModule>

Protocols h2 h2c http/1.1
KeepAlive On
MaxKeepAliveRequests 100
KeepAliveTimeout 5
```

并在 VirtualHost 中对 Vite 编译的资源进行激进缓存（带 hash 的文件名 → 不可变）：

```apache
<LocationMatch "^/build/.*\.(js|css|woff2?|svg|png|jpe?g|webp|avif)$">
    Header set Cache-Control "public, max-age=31536000, immutable"
</LocationMatch>
```

### 23.5 安全的应用顺序

1. `APP_ENV=production` + `APP_DEBUG=false` → `artisan optimize` + `filament:optimize`。
2. Valkey 用于缓存/会话/队列（第 21 节）。
3. OPcache（内存、文件、`pcre.jit`）→ `reload php-fpm`。
4. 每个平台的 FPM 池，逐一配置。
5. MySQL：先开启慢查询日志（无需重启），再配置 redo log + io_capacity（需重启）。
6. `opcache.validate_timestamps=0` **仅在**部署已重置 OPcache 时使用。
7. Apache MPM/HTTP2/压缩 → `reload httpd`。

用 `ab`/`wrk` 对代表性端点进行前后对比测量，查看 FPM 的 `pm.status_path`，并在真实使用数小时后检查 `SHOW ENGINE INNODB STATUS`。

---

## 24. 最终验证检查清单

| 检查项 | 期望状态 | 验证方法 |
|---|---|---|
| SELinux | Enforcing（永不 permissive/disabled） | `getenforce` |
| SSH | 端口 4428，无 root，仅密钥 | `ssh -p 4428`，检查 `sshd_config.d/` |
| 防火墙 | 仅 4428、http、https | `firewall-cmd --list-all` |
| 已关闭端口 | 22、3306、3000 不可从外部访问 | 外部扫描器 / `ss -tlpn` |
| MySQL | 绑定 127.0.0.1，用户最小权限 | `ss -tlpn \| grep 3306` |
| PHP | 8.5.x，`expose_php = Off` | `php -v`，HTTP 响应头 |
| Node | 监听 127.0.0.1，以 `nodeapp` 运行 | `ss -tlpn \| grep 3000` |
| SSL | 有效证书，80→443 重定向 | `certbot certificates` |
| 响应头 | HSTS、CSP、X-Frame、X-Content-Type、Referrer | Web 扫描器 / `curl -I` |
| 版本泄露 | `Server` 和 `X-Powered-By` 中无版本 | `curl -I https://your-domain.com` |
| Fail2Ban | sshd + apache + laravel-scan jail 均激活 | `fail2ban-client status` |
| Valkey | 仅 Unix Socket，无 6379 端口，有认证 | `ss -tlnp \| grep 6379`（空），`valkey-cli -s ... PING` |
| Laravel 缓存/会话 | `redis` 驱动指向 Socket | `php artisan about`，`tinker` 中 `Cache::store('redis')` |
| Turnstile | 所有注册路由均有服务端验证 | `COUNT(*) users WHERE created_at >= CURDATE()` 稳定 |
| OPcache | 内存/文件按多应用场景调整 | `php -i \| grep opcache.max_accelerated_files` |
| MySQL 慢查询日志 | 已激活用于诊断 | `SHOW VARIABLES LIKE 'slow_query_log'` |
| security.txt | 已存在 | 访问 `/.well-known/security.txt` |
| SSL 续期 | 定时器已激活 | `systemctl list-timers \| grep certbot` |
| 自动更新 | dnf-automatic 已激活 | `systemctl status dnf-automatic.timer` |

---

## 25. 附录：DNSSEC、GeoIP 与 PGP

**DNSSEC / "lame delegation" 错误（RRSIG）。** 此错误**不在服务器上修复**，而在您的域名注册商控制面板中修复。通常意味着您启用了 DNSSEC，但 **DS**（委派签名者）记录与您的名称服务器密钥不匹配。操作：在域名控制面板中，确认 DNSSEC 在您的 DNS 提供商处正确配置；如果您不打算严格使用它，禁用它以消除该错误。

**GeoIP（可选）。** 如果某门户仅供特定国家使用，可在防火墙/Apache 层（mod_maxminddb）按国家封锁，从而大幅减少来自境外数据中心的扫描流量。实施成本较高；评估您的使用场景是否有必要。

**security.txt 的 PGP 签名（可选）。** 用 PGP 密钥签署 `security.txt` 可防止文件被篡改后漏洞报告流向冒充者。对于 MVP 或内部门户**不紧迫**；对于政府或金融门户**推荐实施**。如果实施：用 `gpg` 生成密钥对，发布公钥，并将 `Encryption: https://your-domain.com/pgp-key.asc` 添加到文件中。

---
