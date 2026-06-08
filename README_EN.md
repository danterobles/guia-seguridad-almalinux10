# AlmaLinux 10 Server Installation and Hardening Guide

**Goal:** Build from scratch a **highly secure** production server on **AlmaLinux 10**, capable of hosting both **Laravel (PHP 8.5 / Filament)** and **Node.js (LTS 24)** applications, behind Apache, with Let's Encrypt SSL, SELinux in *Enforcing* mode, and active defense with Fail2Ban.

**Technology stack:** AlmaLinux 10 · Apache 2.4 (MPM event + HTTP/2) · PHP 8.5 (php-fpm via Remi) · MySQL 8.4 · Valkey 8 · Node.js 24 LTS · Let's Encrypt · firewalld · SELinux · Fail2Ban · Cloudflare Turnstile

> **How to use this document.** It is designed as a *runbook* (reproducible step-by-step) and as an audit reference. Replace the placeholders `your-domain.com`, `myapp`, `your.public.ip.here`, and usernames/DB names with real values. Run commands as `root` or prefixed with `sudo`.

---

## Table of Contents

1. [Conventions and architecture](#1-conventions-and-architecture)
2. [Base system preparation](#2-base-system-preparation)
3. [Administrative user and SSH key access](#3-administrative-user-and-ssh-key-access)
4. [Secure SSH (port 4428 + hardening)](#4-secure-ssh-port-4428--hardening)
5. [Firewall (firewalld)](#5-firewall-firewalld)
6. [SELinux fundamentals you must understand](#6-selinux-fundamentals-you-must-understand)
7. [Apache (web server / reverse proxy)](#7-apache-web-server--reverse-proxy)
8. [PHP 8.5 + PHP-FPM (for Laravel)](#8-php-85--php-fpm-for-laravel)
9. [MySQL 8 with minimum privileges](#9-mysql-8-with-minimum-privileges)
10. [Composer](#10-composer)
11. [Deploying a Laravel project](#11-deploying-a-laravel-project)
12. [Node.js 24 LTS as a service + reverse proxy](#12-nodejs-24-lts-as-a-service--reverse-proxy)
13. [Let's Encrypt (SSL) and automatic renewal](#13-lets-encrypt-ssl-and-automatic-renewal)
14. [HTTP security headers](#14-http-security-headers)
15. [Hiding versions (information leakage)](#15-hiding-versions-information-leakage)
16. [Blocking bots by User-Agent and exploit paths](#16-blocking-bots-by-user-agent-and-exploit-paths)
17. [Fail2Ban: active defense](#17-fail2ban-active-defense)
18. [security.txt and robots.txt](#18-securitytxt-and-robotstxt)
19. [Git deployment workflow](#19-git-deployment-workflow)
20. [Automatic updates and maintenance](#20-automatic-updates-and-maintenance)
21. [Valkey (cache, sessions, and queues)](#21-valkey-cache-sessions-and-queues)
22. [Public form protection (Turnstile + rate limiting)](#22-public-form-protection-turnstile--rate-limiting)
23. [Performance optimization](#23-performance-optimization)
24. [Final verification checklist](#24-final-verification-checklist)
25. [Appendix: DNSSEC, GeoIP, and PGP](#25-appendix-dnssec-geoip-and-pgp)

---

## 1. Conventions and architecture

**Recommended directory structure.** Everything lives under `/var/www`, the context SELinux already knows for Apache out of the box:

```
/var/www/
├── myapp-laravel/          # Laravel project
│   ├── public/             # <- Apache DocumentRoot (only exposed folder)
│   ├── storage/            # writable (httpd_sys_rw_content_t)
│   ├── bootstrap/cache/    # writable (httpd_sys_rw_content_t)
│   └── .env                # NEVER inside public/
└── myapp-node/             # Node project
    ├── dist/ or build/
    └── .env
```

**Guiding principle (the SELinux golden rule on AlmaLinux 10):** whenever something new is added, remember the three pillars —
- **Port** → `semanage port`
- **File/folder** → `restorecon` / `semanage fcontext`
- **Action permission** → `setsebool`

**Network architecture:**
- Apache listens on `80` and `443` (the only web ports open externally).
- PHP-FPM runs over a local Unix socket (not exposed).
- MySQL listens **only** on `127.0.0.1:3306` (never exposed).
- Each Node app runs on a *loopback* port (e.g. `127.0.0.1:3000`) and Apache acts as a **reverse proxy** with TLS. The Node port is **not opened** in the firewall.

---

## 2. Base system preparation

```bash
# Ensure network connectivity if needed
nmtui

# Update the entire system
dnf update -y

# Base repositories and utilities
dnf install -y epel-release dnf-utils
dnf install -y vim git wget curl tar policycoreutils-python-utils setroubleshoot-server

# Timezone (adjust to your region)
timedatectl set-timezone America/Monterrey

# Time synchronization
systemctl enable --now chronyd
```

> `policycoreutils-python-utils` provides `semanage`; `setroubleshoot-server` provides `sealert`, the SELinux error translator. Both are essential for managing SELinux without disabling it.

**Do not use `net-tools` (obsolete).** AlmaLinux 10 already includes `iproute2`: use `ss -tulpn` instead of `netstat`.

**Confirm SELinux is active in Enforcing mode** (never disable it):

```bash
getenforce        # should respond: Enforcing
sestatus
```

---

## 3. Administrative user and SSH key access

Working as `root` over SSH is the first door bots attack. Create a user with `sudo` and always connect as that user.

**On the server:**

```bash
adduser dante
passwd dante                 # strong password
usermod -aG wheel dante      # 'wheel' = sudo group on AlmaLinux
```

**On your local machine** (generate the key pair if you don't have one):

```bash
ssh-keygen -t ed25519 -C "dante@laptop"
# Copy the public key to the server (still on port 22 for now)
ssh-copy-id dante@your.public.ip.here
```

Verify that you can log in **without a password** using the key before continuing. If the key doesn't work, do **not** disable password authentication in the next step or you'll lock yourself out.

---

## 4. Secure SSH (port 4428 + hardening)

On AlmaLinux 10, modern SSH configuration is done with *drop-in* files inside `/etc/ssh/sshd_config.d/` (cleaner and update-safe compared to editing the main file).

```bash
cat > /etc/ssh/sshd_config.d/99-hardening.conf <<'EOF'
# Non-standard port (reduces noise from automated scans)
Port 4428

# IPv4/IPv6 only as needed
# AddressFamily inet

# Hardening
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

> **Important:** changing the SSH port is not enough; SELinux will block the new port even if the firewall allows it. You must label it.

```bash
# Inform SELinux of the new SSH port
semanage port -a -t ssh_port_t -p tcp 4428

# Validate syntax and restart
sshd -t && systemctl restart sshd
```

Open a **second** SSH session on port 4428 **before** closing the current one, to confirm access:

```bash
ssh -p 4428 dante@your.public.ip.here
```

---

## 5. Firewall (firewalld)

Do not disable `firewalld`: on AlmaLinux 10 it integrates perfectly with SELinux and Fail2Ban.

```bash
systemctl enable --now firewalld

# Remove the standard SSH service (port 22) and open 4428
firewall-cmd --permanent --remove-service=ssh
firewall-cmd --permanent --add-port=4428/tcp

# Open web ports
firewall-cmd --permanent --add-service=http
firewall-cmd --permanent --add-service=https

# Apply
firewall-cmd --reload

# Verify
firewall-cmd --list-all
```

Expected result: only `4428/tcp`, `http`, and `https` open. Ports `22`, `3306` (MySQL), and the internal Node ports **must not** appear. An external scanner should see them as closed/filtered.

---

## 6. SELinux fundamentals you must understand

SELinux doesn't block services "arbitrarily": it ensures each process only touches what it's allowed to (*deny by default* policy).

**What does NOT require configuration:**
- Serving content in `/var/www` over ports 80/443. Files created there automatically inherit the `httpd_sys_content_t` label.

**The most common "but":** if you **move** files from `/home/user` to `/var/www` using `mv`, they retain the source label and Apache will return **403 Forbidden**. Universal fix:

```bash
restorecon -Rv /var/www/myapp
```

**Action permissions (booleans) you will need:**

| Scenario | Command |
|---|---|
| Laravel connects to local MySQL | `setsebool -P httpd_can_network_connect_db on` |
| Apache reverse-proxies to a Node app | `setsebool -P httpd_can_network_connect on` |
| Apache reads folders outside the standard path | `setsebool -P httpd_enable_homedirs on` |

**Folders where Apache/Laravel need write access:**

```bash
semanage fcontext -a -t httpd_sys_rw_content_t "/var/www/myapp/storage(/.*)?"
semanage fcontext -a -t httpd_sys_rw_content_t "/var/www/myapp/bootstrap/cache(/.*)?"
restorecon -Rv /var/www/myapp
```

> The `-P` flag in `setsebool` is **critical**: it makes the change persist after a reboot.

**Diagnostic tools (instead of disabling SELinux):**

```bash
# Real-time denials
tail -f /var/log/audit/audit.log | grep denied

# Human-readable error translator
sealert -a /var/log/audit/audit.log
```

---

## 7. Apache (web server / reverse proxy)

```bash
dnf install -y httpd mod_ssl
systemctl enable --now httpd
```

Make sure the proxy modules (needed for Node) and rewrite (for bot blocking) are loaded:

```bash
# On AlmaLinux 10 these are usually active; verify:
httpd -M | grep -E "proxy_module|proxy_http|proxy_wstunnel|rewrite|headers|ssl"
```

If any are missing, modules live in `/etc/httpd/conf.modules.d/`. Normally `proxy`, `proxy_http`, `rewrite`, `headers`, and `ssl` are already enabled; `proxy_wstunnel` may need to be added for WebSockets.

---

## 8. PHP 8.5 + PHP-FPM (for Laravel)

PHP 8.5 is available as a stable module from Remi for Enterprise Linux 10.

```bash
# Remi repository for AlmaLinux 10
dnf install -y https://rpms.remirepo.net/enterprise/remi-release-10.rpm

# Select the PHP 8.5 module stream
dnf module reset php -y
dnf module enable php:remi-8.5 -y

# Install PHP-FPM and typical Laravel/Filament extensions
dnf install -y php php-cli php-common php-fpm \
  php-mysqlnd php-pdo php-mbstring php-xml php-curl \
  php-gd php-zip php-bcmath php-intl php-opcache php-redis

systemctl enable --now php-fpm
php -v   # confirm 8.5.x
```

**PHP-FPM pool running under the Apache user.** Edit `/etc/php-fpm.d/www.conf` and ensure:

```ini
user = apache
group = apache
listen = /run/php-fpm/www.sock
listen.owner = apache
listen.group = apache
listen.mode = 0660
```

The package installs `/etc/httpd/conf.d/php.conf`, which routes `.php` requests to the PHP-FPM socket via `SetHandler "proxy:unix:/run/php-fpm/www.sock|fcgi://localhost"`. No manual configuration is needed unless for special cases.

```bash
systemctl restart php-fpm httpd
```

---

## 9. MySQL 8 with minimum privileges

```bash
dnf install -y mysql-server
systemctl enable --now mysqld

# Secure the installation (set root password, remove anonymous users, etc.)
mysql_secure_installation
```

**Bind MySQL to localhost only** (no network listening). In `/etc/my.cnf.d/mysql-server.cnf`, inside `[mysqld]`:

```ini
bind-address = 127.0.0.1
```

```bash
systemctl restart mysqld
```

**Create the database and a user with minimum privileges** (do NOT use `*.*` or `WITH GRANT OPTION` for apps; that's the dangerous pattern from old guides):

```sql
CREATE DATABASE myapp CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE USER 'myapp'@'localhost' IDENTIFIED BY 'ALongAndRandomPassword_2026!';

-- Only privileges on ITS own database, nothing else
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, INDEX, DROP, REFERENCES
  ON myapp.* TO 'myapp'@'localhost';

FLUSH PRIVILEGES;
```

> MySQL 8 uses `caching_sha2_password` by default, which is recommended. Only fall back to `mysql_native_password` if a legacy library requires it.

If Laravel returns 500 errors when connecting to the database, it's almost always the SELinux boolean:

```bash
setsebool -P httpd_can_network_connect_db on
```

---

## 10. Composer

Modern Laravel requires Composer 2.x (not the 1.9 from old guides):

```bash
php -r "copy('https://getcomposer.org/installer', 'composer-setup.php');"
php composer-setup.php --install-dir=/usr/local/bin --filename=composer
rm composer-setup.php
composer --version
```

---

## 11. Deploying a Laravel project

```bash
mkdir -p /var/www/myapp
chown -R apache:apache /var/www/myapp

# Clone or upload your project to /var/www/myapp (see section 19 for Git)
cd /var/www/myapp
composer install --no-dev --optimize-autoloader

# Write permissions for Laravel (Linux + SELinux)
chown -R apache:apache storage bootstrap/cache
semanage fcontext -a -t httpd_sys_rw_content_t "/var/www/myapp/storage(/.*)?"
semanage fcontext -a -t httpd_sys_rw_content_t "/var/www/myapp/bootstrap/cache(/.*)?"
restorecon -Rv /var/www/myapp

# Laravel optimization
php artisan config:cache
php artisan route:cache
php artisan view:cache
```

**Laravel VirtualHost** in `/etc/httpd/conf.d/myapp.conf` (HTTP redirecting to HTTPS; the 443 block will be completed by Certbot, see sections 13 and 14):

```apache
<VirtualHost *:80>
    ServerName your-domain.com
    DocumentRoot /var/www/myapp/public
    Redirect permanent / https://your-domain.com/
</VirtualHost>
```

> The `DocumentRoot` points to `public/`, keeping `.env`, `vendor/`, and the rest of the code out of web reach.

**Laravel Scheduler cron** — must run as the Apache user to avoid permission issues:

```bash
# crontab -u apache -e
* * * * * cd /var/www/myapp && php artisan schedule:run >> /dev/null 2>&1
```

---

## 12. Node.js 24 LTS as a service + reverse proxy

As of May 2026, **Node.js 24 is the active LTS version** recommended for production (Node 26 is in *Current* phase, not yet LTS).

### 12.1 Install Node 24

```bash
# Official NodeSource repository for the 24.x branch
curl -fsSL https://rpm.nodesource.com/setup_24.x | bash -
dnf install -y nodejs
node -v    # v24.x
npm -v
```

> Alternative: `dnf module enable nodejs:24 && dnf install nodejs` from AppStream, if you prefer not to add external repos (may be one or two *minor* versions behind).

### 12.2 Dedicated user and code

Do not run Node as `root`. Create a system user with no login shell:

```bash
useradd --system --create-home --home-dir /var/www/myapp-node --shell /usr/sbin/nologin nodeapp
# Upload/clone your app to /var/www/myapp-node and build it
cd /var/www/myapp-node
sudo -u nodeapp npm ci --omit=dev
sudo -u nodeapp npm run build   # if applicable
```

### 12.3 systemd service (cleaner and more secure than PM2 as root)

Create `/etc/systemd/system/myapp-node.service`:

```ini
[Unit]
Description=My Node App
After=network.target

[Service]
Type=simple
User=nodeapp
Group=nodeapp
WorkingDirectory=/var/www/myapp-node
# The app MUST listen on loopback: host 127.0.0.1, port 3000
Environment=NODE_ENV=production
Environment=PORT=3000
Environment=HOST=127.0.0.1
ExecStart=/usr/bin/node dist/server.js
Restart=on-failure
RestartSec=5

# Service hardening
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
ss -tlpn | grep 3000      # must listen ONLY on 127.0.0.1:3000
```

> Make sure your app reads `process.env.HOST` and `process.env.PORT` and **listens on `127.0.0.1`**, not `0.0.0.0`. This way port 3000 is never accessible from the internet, only from Apache.

### 12.4 Allow the proxy in SELinux

For Apache to open a network connection to the Node port:

```bash
setsebool -P httpd_can_network_connect on
```

### 12.5 Reverse proxy VirtualHost

`/etc/httpd/conf.d/myapp-node.conf`:

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

    # WebSocket support (if your app uses it: Socket.io, etc.)
    RewriteEngine On
    RewriteCond %{HTTP:Upgrade} =websocket [NC]
    RewriteRule /(.*) ws://127.0.0.1:3000/$1 [P,L]

    # (Security headers from section 14 apply here too)
    # (Certbot will add SSL directives here)

    ErrorLog  /var/log/httpd/myapp-node-error.log
    CustomLog /var/log/httpd/myapp-node-access.log combined
</VirtualHost>
```

```bash
apachectl configtest && systemctl restart httpd
```

> **Do not open port 3000 in firewalld.** Traffic enters via 443 (Apache, with TLS) and is forwarded internally. Node remains isolated.

---

## 13. Let's Encrypt (SSL) and automatic renewal

```bash
dnf install -y certbot python3-certbot-apache

# One certificate per domain/subdomain
certbot --apache -d your-domain.com
certbot --apache -d node.your-domain.com
```

Certbot automatically inserts the `SSLCertificateFile`, `SSLCertificateKeyFile`, and `Include /etc/letsencrypt/options-ssl-apache.conf` directives into your 443 VirtualHosts.

**Automatic renewal.** The package installs a systemd *timer* that renews without intervention. Verify it:

```bash
systemctl list-timers | grep certbot
certbot renew --dry-run     # dry run to confirm renewal works
```

---

## 14. HTTP security headers

These headers fix the typical findings from scanners like web-check.xyz (HSTS, Clickjacking, MIME sniffing, XSS, CSP). Add them inside the `<VirtualHost *:443>` block for each site.

```apache
# HSTS: enforces HTTPS for 2 years (eligible for preload list)
Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"

# Anti-clickjacking
Header always set X-Frame-Options "SAMEORIGIN"

# Prevent MIME sniffing
Header always set X-Content-Type-Options "nosniff"

# Referrer policy
Header always set Referrer-Policy "strict-origin-when-cross-origin"

# Permissions-Policy (restricts browser APIs)
Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"

# Content-Security-Policy: the most powerful protection against XSS.
# Adjust the external domains you actually use (fonts, maps, analytics).
Header always set Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://fonts.googleapis.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self';"

# Remove version leaks
ServerSignature Off
Header unset X-Powered-By
```

> **Note on `X-XSS-Protection`:** this header is obsolete and modern browsers ignore it (some recommend `0`). Real XSS protection today is a good **CSP**. If your scanner still asks for it, you can add `Header set X-XSS-Protection "1; mode=block"`, but that's not where real security lives.

> **CSP is iterative.** Start with the policy above; if something stops loading (an external script, a map, Google Analytics), add that domain to the appropriate directive. For Filament, `'self' 'unsafe-inline' 'unsafe-eval'` usually suffices.

```bash
apachectl configtest && systemctl restart httpd
```

---

## 15. Hiding versions (information leakage)

Telling the world "I'm running PHP 8.5.6 and Apache 2.4.63" hands attackers the exact map of which exploits to try.

**Apache** — create `/etc/httpd/conf.d/00-security.conf`:

```apache
ServerTokens Prod
ServerSignature Off
TraceEnable Off
```

**PHP** — in `/etc/php.ini`:

```ini
expose_php = Off
```

```bash
systemctl restart php-fpm httpd
```

After this, the `Server` header will only say `Apache` (no version) and `X-Powered-By: PHP/...` will disappear.

---

## 16. Blocking bots by User-Agent and exploit paths

Real-world logs show two types of automated noise: scanners that identify themselves with known User-Agents (`l9scan`, `zgrab`, `Nikto`, `CensysInspect`) and bots requesting paths that don't exist in the app (`/.env`, `/.git/config`, `/vendor/phpunit/.../eval-stdin.php`, `/wp-config.php`). It's worth cutting both **at the VirtualHost level**, before the request ever reaches PHP.

> **Lesson learned — don't anchor the User-Agent with `^`.** An earlier version used `RewriteCond %{HTTP_USER_AGENT} ^Nmap`, which only matches if the UA *starts* with exactly that string. Bots like `l9scan` announce themselves as `Mozilla/5.0 (l9scan/2.0...)`, so the anchor let them through. The correct rule searches for the string **anywhere** in the User-Agent.

Place the block directly under `<VirtualHost *:443>`, not inside the `<Directory>`. The server context is evaluated first and independently of Laravel's `.htaccess`, so the block applies to every request without depending on what Laravel processes afterward. Requires an explicit `RewriteEngine On` in this context:

```apache
RewriteEngine On

# 1) Block by User-Agent — NO ^ anchor, to catch them anywhere
#    in the string (e.g. "Mozilla/5.0 (l9scan/...)" no longer slips through)
RewriteCond %{HTTP_USER_AGENT} (l9explore|l9scan|l9tcpid|Nmap|Masscan|zgrab|Nikto|CensysInspect|leakix|libredtail|Gh0st) [NC]
RewriteRule ^ - [F,L]

# 2) Empty User-Agent on requests other than root (raw bots)
RewriteCond %{HTTP_USER_AGENT} ^-?$
RewriteCond %{REQUEST_URI} !^/$
RewriteRule ^ - [F,L]

# 3) Block hidden files (.env, .git, etc.)
#    EXCEPT /.well-known (required for Let's Encrypt renewal)
RewriteRule "(^|/)\.(?!well-known)" - [F,L]

# 4) Known exploit paths (PHPUnit eval-stdin, vendor, junk .php)
RewriteCond %{REQUEST_URI} (eval-stdin\.php|/vendor/|/phpunit|/wp-|xmlrpc\.php|/phpinfo|/\.aws|/\.ssh) [NC]
RewriteRule ^ - [F,L]
```

> **The `/.well-known` exception is critical.** If you blocked all dotfiles without exception, you'd break the Certbot ACME challenge (`/.well-known/acme-challenge/`) and your certificate would stop renewing. The `(?!well-known)` protects it.

> **Don't block `curl` by User-Agent.** Even though it appears in scans, it's the tool you use yourself for testing and health checks. That behavior is better left to Fail2Ban (bans by behavior, not by name), see section 17.

From this point on, those bots receive **403 Forbidden** instead of a 404. That's good: Fail2Ban (next section) bans anyone who accumulates 403s.

```bash
apachectl configtest && systemctl restart httpd
```

**Measurable result.** In a real case on this server, after applying the block, the log went from recording hundreds of 403s daily against scanning for `/.env`, `/.git/config`, `/wp-config.php`, and `/.aws/credentials` that previously passed through as harmless 404s but reached PHP. A single aggressive scanning IP (`45.148.10.95`) accumulated 220 blocks in one day without touching the application.

---

## 17. Fail2Ban: active defense

The firewall is a passive wall; Fail2Ban is a guard that reads logs and bans repeat-offender IPs at the network level.

```bash
dnf install -y fail2ban fail2ban-firewalld
```

**Main configuration** — never edit `jail.conf`; create `/etc/fail2ban/jail.local`:

```ini
[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 5
# Ban using firewalld (native integration on AlmaLinux 10)
banaction = firewallcmd-rich-rules
# IMPORTANT: add YOUR fixed IP to avoid self-banning
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

**Custom filter** to catch `.env`/`.git` scanning and 403s from User-Agent blocking. Create `/etc/fail2ban/filter.d/laravel-vulnerabilities.conf`:

```ini
[Definition]
# Catches 404 (sensitive file hunting) and 403 (User-Agent / dotfile blocks)
failregex = ^<HOST> -.*"GET .*\.(env|git|aws|yml|yaml|json).* HTTP/.*" (404|403)
            ^<HOST> -.*"GET .*(\.git|config|credentials).* HTTP/.*" (404|403)
            ^<HOST> -.*"(GET|POST) .* HTTP/.*" 403
ignoreregex =
```

> **On public form abuse (registration, contact).** IPs hammering `POST /register` rotate addresses and use real-browser User-Agents, so a 403 filter won't catch them: at the HTTP level they're indistinguishable from a human. The right defense for that is **not Fail2Ban** but Cloudflare Turnstile + rate limiting + email verification (see section 22). If you still want Fail2Ban to react to the most persistent offenders, you can add a filter that counts `429` responses (Laravel rate limit) per IP, but that's a secondary defense, not the primary one.

**Jail** using that filter against your access log (adjust the path to your `CustomLog`). Add it at the end of `jail.local`:

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

**Enable and verify:**

```bash
systemctl enable --now fail2ban
fail2ban-client status
fail2ban-client status laravel-scan

# Test the filter against your current log (counts "Hits")
fail2ban-regex /var/log/httpd/myapp-access.log /etc/fail2ban/filter.d/laravel-vulnerabilities.conf
```

**SELinux and the custom log.** If Fail2Ban can't read your custom-named log, check its context:

```bash
ls -Z /var/log/httpd/myapp-access.log   # should be httpd_log_t
restorecon -v /var/log/httpd/myapp-access.log
```

> If you need to unban yourself: `fail2ban-client set laravel-scan unbanip 1.2.3.4`.

With this you have **layered defense**: Apache identifies the bot and closes the door (403) → the attempt is logged → Fail2Ban detects the repeat-offender IP and blocks it in firewalld.

---

## 18. security.txt and robots.txt

**security.txt** (standard for letting researchers report vulnerabilities responsibly):

```bash
mkdir -p /var/www/myapp/public/.well-known
cat > /var/www/myapp/public/.well-known/security.txt <<'EOF'
Contact: mailto:security@your-domain.com
Expires: 2027-01-01T00:00:00.000Z
Preferred-Languages: en, es
EOF
restorecon -Rv /var/www/myapp/public/.well-known
```

**robots.txt** — to discourage indexing of the admin panel (this is only a *suggestion* for legitimate crawlers; real security for `/admin` is the Laravel/Filament login):

```
User-agent: *
Disallow: /admin/
Disallow: /admin
Allow: /
```

---

## 19. Git deployment workflow

**Classic error:** `fatal: detected dubious ownership in repository`. Occurs because the folder belongs to `apache` but you run Git as a different user.

```bash
git config --global --add safe.directory /var/www/myapp
```

**The real problem:** after `git pull`, new files lose the `apache` owner and/or SELinux context, and Apache returns 403/500. The correct production workflow:

```bash
git pull origin main
chown -R apache:apache /var/www/myapp
restorecon -Rv /var/www/myapp        # restore SELinux labels
php /var/www/myapp/artisan optimize
```

**Automate it with a deploy script** (`/usr/local/bin/deploy-myapp`):

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

> **Why `restorecon` is vital:** Git assigns a temporary label to new files; without `restorecon`, SELinux may block their reading with a 403 even if `chmod`/`chown` are perfect.

For Node, the equivalent restarts the service: `... && systemctl restart myapp-node`.

---

## 20. Automatic updates and maintenance

**Automatic security patches:**

```bash
dnf install -y dnf-automatic
# In /etc/dnf/automatic.conf -> apply_updates = yes (or notify only)
systemctl enable --now dnf-automatic.timer
```

**Recommended manual routine:**

```bash
dnf update --security        # security patches
certbot renew --dry-run      # confirm SSL renewal
fail2ban-client status       # review bans
```

**Backups (minimum viable):** schedule a daily MySQL dump and a backup of `/var/www` and `/etc/httpd`:

```bash
mysqldump --single-transaction --routines myapp | gzip > /backups/myapp-$(date +\%F).sql.gz
```

---

## 21. Valkey (cache, sessions, and queues)

For Laravel/Filament to perform well in production, move cache, sessions, and queues away from the database to an in-memory store. **AlmaLinux 10 no longer includes Redis** (Redis Labs switched to non-FOSS licensing in version 7.4 and the distro removed it from its repos); the official replacement in AppStream is **Valkey**, a FOSS-licensed fork. It's a *drop-in*: phpredis and Laravel's `redis` driver talk to Valkey without changing any application code.

> **Why Valkey and not Redis via Remi.** Redis returned to an open source license (AGPLv3) in 8.0 and there are RPMs in `remi-modular`, but that ties security updates of a *datastore* (which will store sessions) to a third-party repo. Valkey from the official AppStream receives patches through the normal distro cycle, with less maintenance overhead. Unless you need a very new Redis 8.x feature, Valkey is the recommended option.

### 21.1 Installation

```bash
dnf install -y valkey
valkey-server --version
```

### 21.2 Secure configuration

The classic Redis/Valkey threat model is "internet-exposed instance with no password." Since Valkey here lives on the **same server** as Laravel, the most secure approach is to **not expose it to the network at all**: Unix socket + no TCP port. Generate a strong password first:

```bash
openssl rand -base64 48
```

Edit `/etc/valkey/valkey.conf` (many directives already exist commented out; find them and adjust):

```conf
# --- NETWORK: don't expose to any interface ---
bind 127.0.0.1 -::1
protected-mode yes
port 0                              # disable TCP entirely; Unix socket only

# --- UNIX SOCKET: how Laravel connects ---
unixsocket /run/valkey/valkey.sock
unixsocketperm 770

# --- AUTHENTICATION ---
requirepass "PASTE_THE_GENERATED_PASSWORD_HERE"

# --- MEMORY AND POLICY ---
maxmemory 2gb                       # adjust to what you allocate
maxmemory-policy allkeys-lru        # watch the typo: it's allkeys-lru (with 'a')

# --- PERSISTENCE (to not lose sessions/queues on restart) ---
appendonly yes
appendfsync everysec

# --- DANGEROUS COMMANDS ---
rename-command FLUSHALL ""
rename-command FLUSHDB ""
rename-command KEYS ""                  # KEYS blocks the server in prod; Laravel doesn't use it
rename-command CONFIG "CONFIG_a8f3k2"   # rename to something unpredictable instead of deleting
```

> **A typo aborts startup.** If Valkey won't start, check `systemctl status valkey`: the `FATAL CONFIG FILE ERROR` message gives the exact line number of the error. A misspelled value (e.g. `llkeys-lru` instead of `allkeys-lru`) prevents startup, and as a consequence the socket is never created — hence a `No such file or directory` error when trying to connect, which is a symptom, not the cause.

### 21.3 Socket directory, permissions, and SELinux

The socket directory in `/run` is ephemeral; create it persistently with tmpfiles so it survives reboots:

```bash
echo 'd /run/valkey 0750 valkey valkey -' > /etc/tmpfiles.d/valkey.conf
systemd-tmpfiles --create
```

For PHP-FPM (and Netdata, if you use it) to read the socket, add those users to the `valkey` group — same group membership logic as with `apache`:

```bash
usermod -aG valkey apache
usermod -aG valkey dante         # if your FPM pools run as dante
usermod -aG valkey netdata       # if you monitor with Netdata
```

SELinux: enable the web connect boolean and label the socket directory if there are denials:

```bash
setsebool -P httpd_can_network_connect 1
semanage fcontext -a -t redis_var_run_t "/run/valkey(/.*)?" 2>/dev/null || true
restorecon -Rv /run/valkey

# If Valkey fails due to SELinux, review denials and generate a targeted policy:
ausearch -m avc -ts recent | grep -iE "valkey|redis"
```

### 21.4 Service hardening (systemd)

Strengthen isolation with a drop-in instead of editing the original unit:

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

### 21.5 Start and verify

```bash
systemctl enable --now valkey
systemctl status valkey --no-pager

# Socket connection with auth
valkey-cli -s /run/valkey/valkey.sock
#   AUTH "your_password"
#   PING            -> should respond PONG
#   exit

# Confirm there is NO TCP port listening (should be empty)
ss -tlnp | grep 6379
```

### 21.6 Laravel integration

Confirm the phpredis extension (compiled in C, faster than Predis; no need for `predis/predis` via Composer if using this):

```bash
php -m | grep -i redis
# if missing:
dnf install -y php-redis && systemctl reload php-fpm
```

In each platform's `.env`, pointing to the socket and **separating** evictable data (cache, in one DB) from non-evictable data (sessions/queues, in another). With Unix socket, `REDIS_PORT` must be `0`:

```env
REDIS_CLIENT=phpredis
REDIS_HOST=/run/valkey/valkey.sock
REDIS_PORT=0
REDIS_PASSWORD="your_password"

REDIS_DB=0          # sessions and queues (must not be evicted)
REDIS_CACHE_DB=1    # cache (evictable with allkeys-lru)

CACHE_STORE=redis
SESSION_DRIVER=redis
QUEUE_CONNECTION=redis
```

> **The `prefix` matters with multiple platforms.** All your apps share the same Valkey instance. Laravel's default key prefix derives from `APP_NAME`, so make sure each platform has a different `APP_NAME` (or an explicit `REDIS_PREFIX`) or one app's cache keys will overwrite another's.

Since you have cached config, **`.env` changes won't take effect until you regenerate the cache**:

```bash
php artisan config:clear && php artisan config:cache

php artisan tinker
>>> Cache::store('redis')->put('test', 'ok', 60); Cache::store('redis')->get('test');   # -> "ok"
```

> **The variables are still called `REDIS_*` and the driver is `redis`**: it's just the client name. Under the hood it's talking to Valkey without knowing or caring.

**Key inspection.** Since we disabled `KEYS`, use `SCAN` (doesn't block the server). From the shell, `--scan` iterates on its own:

```bash
export REDISCLI_AUTH="your_password"     # avoids exposing the password in shell history
valkey-cli -s /run/valkey/valkey.sock -n 1 --scan                       # all cache keys (DB 1)
valkey-cli -s /run/valkey/valkey.sock -n 1 --scan --pattern "myapp_*"   # filter by app prefix
valkey-cli -s /run/valkey/valkey.sock INFO keyspace                     # count per DB at a glance
```

> **Safe order:** install and verify Valkey completely (until `PING` responds `PONG`) **before** changing the `.env` files. That way, if something fails in the connection, you don't leave apps without cache or session.

---

## 22. Public form protection (Turnstile + rate limiting)

Public registration forms are a target for mass automated fake account creation. On this server, logs showed multiple IPs (ranges from hosting providers, not real users) making successful `POST /register` requests continuously. Rate limiting alone **is not enough** because bots rotate IPs: each one stays below the threshold. Effective defense is layered.

### 22.1 Cloudflare Turnstile (the main piece)

Turnstile is a free, privacy-respecting CAPTCHA. The critical part is that validation happens **on the server**, not just rendering the widget: a bot making a direct POST without going through the browser must be rejected just the same.

Verification service (`app/Services/TurnstileService.php`):

```php
public function verify(string $token, string $ip): bool
{
    // Cheap guard: empty token = don't even call Cloudflare.
    // Avoids the round-trip (with its timeout) in the most common abuse case (POST with no token).
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
        return false;   // fail-closed: if Cloudflare doesn't respond, nobody registers
    }
}
```

In the controller, verify **before** validating or touching the database:

```php
if (! $this->turnstile->verify((string) $request->input('cf-turnstile-response'), $request->ip())) {
    return back()->withInput()->withErrors(['captcha' => 'We could not verify you are human.']);
}
```

Two design decisions to be aware of: the `catch` returns `false` (**fail-closed**), correct for stopping abuse but implies a Cloudflare network failure would block legitimate registrations; and if you have **multiple registration routes** (e.g. host and client), **both** must carry the verification, or bots will use the unprotected one.

### 22.2 Specific rate limiting (secondary layer)

Don't remove the rate limiter when adding Turnstile; they're complementary. For the registration route, something more aggressive than the default:

```php
RateLimiter::for('register', function (Request $request) {
    return [
        Limit::perMinute(3)->by($request->ip()),
        Limit::perDay(10)->by($request->ip()),
    ];
});
```

### 22.3 Mandatory email verification (containment)

Even if an account manages to register, it should not be able to do anything until its email is verified. Use `MustVerifyEmail` on the `User` model and the `verified` middleware on protected routes. This turns any junk account that slips through into an inert account.

### 22.4 How to verify it's working (logs are misleading)

The Apache log **does not distinguish** a successful registration from a Turnstile rejection: both produce a `302` (success redirects to `/verification.notice`; rejection returns to the form with `back()`). So, seeing hundreds of `302`s on `/register` **does not mean** accounts are being created. The real thermometer is the database:

```sql
SELECT COUNT(*) FROM users WHERE created_at >= CURDATE();
```

If that count stays at your expected real numbers (or at zero, if you weren't expecting legitimate signups) while the log keeps showing attempts, Turnstile is doing its job. **Bots won't stop trying** — you'll keep seeing the `302`s and `POST`s — but they won't create accounts. Don't be alarmed by the log noise; watch the `COUNT`.

> **Real defense in depth:** Turnstile kills automated registration, the rate limiter catches the most persistent ones, the vhost block (section 16) stops scanning before it reaches PHP, and Fail2Ban (section 17) bans repeat offenders at the firewall level. Each layer covers the gaps of the others.

---

## 23. Performance optimization

Once the server is secured, these are the performance levers for Laravel/Filament. **Size with data, not guesswork:** measure real consumption under load before setting values, and apply one change at a time validating that it helped.

> **Step zero (critical):** confirm each app is in production mode. `php artisan about` must show `Environment = production` and `Debug Mode = OFF`. With `APP_DEBUG=true` on a public server, any exception exposes credentials and environment variables to the visitor — it's both a security leak and a performance cost.

### 23.1 OPcache

The default (`memory_consumption=128`, `max_accelerated_files=10000`) falls short for multiple Laravel + Filament apps: a single project with its `vendor/` has around 8–12k files, so with two apps OPcache is constantly evicting. In `/etc/php.d/10-opcache.ini`:

```ini
opcache.enable=1
opcache.memory_consumption=512        ; increase from 128
opcache.interned_strings_buffer=32    ; increase from 8
opcache.max_accelerated_files=65000   ; increase from 10000
opcache.save_comments=1               ; do NOT disable: Filament/Laravel use attributes
opcache.validate_timestamps=0         ; ONLY if deploy resets OPcache (see below)
opcache.revalidate_freq=0
```

And enable the PCRE JIT (accelerates the regex engine for routes/validation), which is usually disabled:

```ini
; /etc/php.d/30-pcre.ini
pcre.jit=1
```

> `validate_timestamps=0` only when your deploy script (section 19) ends with an OPcache reset (`cachetool opcache:reset` or `systemctl reload php-fpm`); otherwise, code changes wouldn't be reflected after a deploy. The **PHP JIT** (different from PCRE's) can stay disabled: for I/O-bound load like Laravel, the benefit is marginal.

### 23.2 PHP-FPM: one pool per platform

A single `www` pool shared by all apps is fragile: a spike in one can starve the others of workers, and they all run as `apache` with the same log. The correct approach is **one pool per platform**, each with its own user. In `/etc/php-fpm.d/myapp.conf`:

```ini
[myapp]
user = dante
group = apache
listen = /run/php-fpm/myapp.sock
listen.owner = apache
listen.group = apache
listen.mode = 0660

pm = ondemand                          ; low/medium traffic: frees RAM when idle
pm.max_children = 20
pm.process_idle_timeout = 30s
pm.max_requests = 500                  ; recycles workers -> avoids memory leaks

php_admin_value[memory_limit] = 384M   ; per pool, NOT the global 1024M
slowlog = /var/log/php-fpm/myapp-slow.log
request_slowlog_timeout = 5s
pm.status_path = /status
```

> A high global `memory_limit` (e.g. 1024M) is dangerous for web: 50 children × 1 GB = 50 GB theoretical. Keep it high for CLI (migrations, exports) but cap it per pool. Measure the real memory per process under load to size `max_children`:
> ```bash
> ps --no-headers -o rss -C php-fpm | awk '{s+=$1;n++} END {printf "%.0f MB avg, %d procs\n", s/n/1024, n}'
> ```

### 23.3 MySQL 8.4

> **Methodology warning:** deeply tuning a MySQL instance with little data is premature. The highest-value thing at the start is **enabling the slow query log** to have something to work with when real traffic arrives.

In `/etc/my.cnf.d/optimization.cnf`:

```ini
[mysqld]
# Diagnostics (most important at the start)
slow_query_log = ON
long_query_time = 1
log_queries_not_using_indexes = ON     ; noisy; disable after the initial phase

# Redo log (in 8.4 replaces innodb_log_file_size; the default ~48M is small)
innodb_redo_log_capacity = 1G          ; requires MySQL restart

# Appropriate for the hardware (SATA SSD, not NVMe). 10000 is unrealistic for those disks.
innodb_io_capacity = 2000
innodb_io_capacity_max = 4000

tmp_table_size = 64M
max_heap_table_size = 64M
```

> **Don't lower `innodb_flush_log_at_trx_commit` below 1** if you handle financial/accounting data (invoicing, tax): don't sacrifice transactional integrity for a microbenchmark. Increase `innodb_buffer_pool_size` (the default may fall short) only as data grows; you have plenty of RAM.

### 23.4 Apache MPM event and HTTP/2

With PHP-FPM, the MPM must be **event** (not prefork). Define explicit limits and confirm HTTP/2 and compression:

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

And aggressively cache Vite-compiled assets (hash-named → immutable), inside the VirtualHost:

```apache
<LocationMatch "^/build/.*\.(js|css|woff2?|svg|png|jpe?g|webp|avif)$">
    Header set Cache-Control "public, max-age=31536000, immutable"
</LocationMatch>
```

### 23.5 Safe application order

1. `APP_ENV=production` + `APP_DEBUG=false` → `artisan optimize` + `filament:optimize`.
2. Valkey for cache/session/queue (section 21).
3. OPcache (memory, files, `pcre.jit`) → `reload php-fpm`.
4. FPM pools per platform, one at a time.
5. MySQL: slow log first (no restart required), then redo log + io_capacity (restart required).
6. `opcache.validate_timestamps=0` ONLY when deploy already resets OPcache.
7. Apache MPM/HTTP2/compression → `reload httpd`.

Measure before/after with `ab`/`wrk` against a representative endpoint, the FPM `pm.status_path`, and `SHOW ENGINE INNODB STATUS` after hours of real usage.

---

## 24. Final verification checklist

| Area | Desired state | How to verify |
|---|---|---|
| SELinux | Enforcing (never permissive/disabled) | `getenforce` |
| SSH | Port 4428, no root, keys only | `ssh -p 4428`, review `sshd_config.d/` |
| Firewall | Only 4428, http, https | `firewall-cmd --list-all` |
| Closed ports | 22, 3306, 3000 NOT externally accessible | external scanner / `ss -tlpn` |
| MySQL | Bind 127.0.0.1, user with minimum privileges | `ss -tlpn \| grep 3306` |
| PHP | 8.5.x, `expose_php = Off` | `php -v`, HTTP headers |
| Node | Listens on 127.0.0.1, runs as `nodeapp` | `ss -tlpn \| grep 3000` |
| SSL | Valid certificate, 80→443 redirect | `certbot certificates` |
| Headers | HSTS, CSP, X-Frame, X-Content-Type, Referrer | web scanner / `curl -I` |
| Version leaks | No version in `Server` or `X-Powered-By` | `curl -I https://your-domain.com` |
| Fail2Ban | sshd + apache + laravel-scan jails active | `fail2ban-client status` |
| Valkey | Unix socket only, no port 6379, with auth | `ss -tlnp \| grep 6379` (empty), `valkey-cli -s ... PING` |
| Laravel cache/session | `redis` driver pointing to the socket | `php artisan about`, `tinker` with `Cache::store('redis')` |
| Turnstile | Server-side verification on ALL registration routes | `COUNT(*) users WHERE created_at >= CURDATE()` stable |
| OPcache | memory/files sized for multi-app | `php -i \| grep opcache.max_accelerated_files` |
| MySQL slow log | Active for diagnostics | `SHOW VARIABLES LIKE 'slow_query_log'` |
| security.txt | Present | visit `/.well-known/security.txt` |
| SSL renewal | Timer active | `systemctl list-timers \| grep certbot` |
| Updates | dnf-automatic active | `systemctl status dnf-automatic.timer` |

---

## 25. Appendix: DNSSEC, GeoIP, and PGP

**DNSSEC / "lame delegation" error (RRSIG).** This error **is not fixed on the server**, but in your domain registrar's panel. It usually means you enabled DNSSEC but the **DS** (Delegation Signer) records don't match your nameserver keys. Action: in the domain panel, verify that DNSSEC is correctly configured against your DNS provider; if you won't be using it strictly, disable it to eliminate the error.

**GeoIP (optional).** If a portal is for exclusive use in one country, you can block by country at the firewall/Apache level (mod_maxminddb) to dramatically reduce scanning traffic from foreign data centers. Higher-effort implementation; evaluate whether the use case justifies it.

**PGP signature of security.txt (optional).** Signing `security.txt` with a PGP key prevents someone who altered the file from having vulnerability reports go to an impersonator. For an MVP or internal portal **it's not urgent**; for government or financial portals **it is recommended**. If you implement it: generate the key pair with `gpg`, publish the public key, and add `Encryption: https://your-domain.com/pgp-key.asc` to the file.

---
