# AlmaLinux 10 Server-Installations- und Härtungsleitfaden

**Ziel:** Einen **hochsicheren** Produktionsserver auf **AlmaLinux 10** von Grund auf aufbauen, der sowohl **Laravel (PHP 8.5 / Filament)**- als auch **Node.js (LTS 24)**-Anwendungen hinter Apache mit Let's Encrypt SSL, SELinux im *Enforcing*-Modus und aktiver Verteidigung durch Fail2Ban hosten kann.

**Technologie-Stack:** AlmaLinux 10 · Apache 2.4 (MPM event + HTTP/2) · PHP 8.5 (php-fpm via Remi) · MySQL 8.4 · Valkey 8 · Node.js 24 LTS · Let's Encrypt · firewalld · SELinux · Fail2Ban · Cloudflare Turnstile

> **Verwendung dieses Dokuments.** Es ist als *Runbook* (reproduzierbare Schritt-für-Schritt-Anleitung) und als Audit-Referenz konzipiert. Ersetzen Sie die Platzhalter `ihre-domain.com`, `meineapp`, `ihre.oeffentliche.ip.hier` sowie die Benutzer-/Datenbanknamen durch die tatsächlichen Werte. Führen Sie Befehle als `root` oder mit vorangestelltem `sudo` aus.

---

## Inhaltsverzeichnis

1. [Konventionen und Architektur](#1-konventionen-und-architektur)
2. [Vorbereitung des Basissystems](#2-vorbereitung-des-basissystems)
3. [Administrativer Benutzer und SSH-Schlüsselzugang](#3-administrativer-benutzer-und-ssh-schlüsselzugang)
4. [Sicheres SSH (Port 4428 + Härtung)](#4-sicheres-ssh-port-4428--härtung)
5. [Firewall (firewalld)](#5-firewall-firewalld)
6. [SELinux-Grundlagen, die Sie verstehen müssen](#6-selinux-grundlagen-die-sie-verstehen-müssen)
7. [Apache (Webserver / Reverse Proxy)](#7-apache-webserver--reverse-proxy)
8. [PHP 8.5 + PHP-FPM (für Laravel)](#8-php-85--php-fpm-für-laravel)
9. [MySQL 8 mit minimalen Rechten](#9-mysql-8-mit-minimalen-rechten)
10. [Composer](#10-composer)
11. [Deployment eines Laravel-Projekts](#11-deployment-eines-laravel-projekts)
12. [Node.js 24 LTS als Dienst + Reverse Proxy](#12-nodejs-24-lts-als-dienst--reverse-proxy)
13. [Let's Encrypt (SSL) und automatische Erneuerung](#13-lets-encrypt-ssl-und-automatische-erneuerung)
14. [HTTP-Sicherheits-Header](#14-http-sicherheits-header)
15. [Versionen verbergen (Informationsleck)](#15-versionen-verbergen-informationsleck)
16. [Bot-Blockierung nach User-Agent und Exploit-Pfaden](#16-bot-blockierung-nach-user-agent-und-exploit-pfaden)
17. [Fail2Ban: Aktive Verteidigung](#17-fail2ban-aktive-verteidigung)
18. [security.txt und robots.txt](#18-securitytxt-und-robotstxt)
19. [Deployment-Workflow mit Git](#19-deployment-workflow-mit-git)
20. [Automatische Updates und Wartung](#20-automatische-updates-und-wartung)
21. [Valkey (Cache, Sitzungen und Warteschlangen)](#21-valkey-cache-sitzungen-und-warteschlangen)
22. [Schutz öffentlicher Formulare (Turnstile + Rate Limiting)](#22-schutz-öffentlicher-formulare-turnstile--rate-limiting)
23. [Leistungsoptimierung](#23-leistungsoptimierung)
24. [Abschließende Verifikations-Checkliste](#24-abschließende-verifikations-checkliste)
25. [Anhang: DNSSEC, GeoIP und PGP](#25-anhang-dnssec-geoip-und-pgp)

---

## 1. Konventionen und Architektur

**Empfohlene Verzeichnisstruktur.** Alles liegt unter `/var/www`, dem Kontext, den SELinux für Apache bereits von Haus aus kennt:

```
/var/www/
├── meineapp-laravel/       # Laravel-Projekt
│   ├── public/             # <- Apache DocumentRoot (einziger exponierter Ordner)
│   ├── storage/            # schreibbar (httpd_sys_rw_content_t)
│   ├── bootstrap/cache/    # schreibbar (httpd_sys_rw_content_t)
│   └── .env                # NIE innerhalb von public/
└── meineapp-node/          # Node-Projekt
    ├── dist/ oder build/
    └── .env
```

**Leitprinzip (die goldene SELinux-Regel unter AlmaLinux 10):** Bei allem Neuen stets die drei Säulen beachten —
- **Port** → `semanage port`
- **Datei/Ordner** → `restorecon` / `semanage fcontext`
- **Aktionsberechtigung** → `setsebool`

**Netzwerkarchitektur:**
- Apache lauscht auf `80` und `443` (einzige nach außen geöffnete Web-Ports).
- PHP-FPM läuft über einen lokalen Unix-Socket (nicht exponiert).
- MySQL lauscht **ausschließlich** auf `127.0.0.1:3306` (niemals exponiert).
- Jede Node-App läuft auf einem *Loopback*-Port (z.B. `127.0.0.1:3000`) und Apache fungiert als **Reverse Proxy** mit TLS. Der Node-Port wird **nicht** in der Firewall geöffnet.

---

## 2. Vorbereitung des Basissystems

```bash
# Netzwerkkonnektivität sicherstellen, falls nötig
nmtui

# Gesamtes System aktualisieren
dnf update -y

# Basis-Repositories und Hilfsprogramme
dnf install -y epel-release dnf-utils
dnf install -y vim git wget curl tar policycoreutils-python-utils setroubleshoot-server

# Zeitzone (an Ihre Region anpassen)
timedatectl set-timezone Europe/Berlin

# Zeitsynchronisation
systemctl enable --now chronyd
```

> `policycoreutils-python-utils` stellt `semanage` bereit; `setroubleshoot-server` stellt `sealert` bereit, den SELinux-Fehlerübersetzer. Beide sind unverzichtbar für die Verwaltung von SELinux ohne es zu deaktivieren.

**Verwenden Sie nicht `net-tools` (veraltet).** AlmaLinux 10 enthält bereits `iproute2`: Verwenden Sie `ss -tulpn` statt `netstat`.

**Bestätigen Sie, dass SELinux im Enforcing-Modus aktiv ist** (deaktivieren Sie es niemals):

```bash
getenforce        # muss antworten: Enforcing
sestatus
```

---

## 3. Administrativer Benutzer und SSH-Schlüsselzugang

Als `root` über SSH zu arbeiten ist die erste Tür, die Bots angreifen. Erstellen Sie einen Benutzer mit `sudo` und verbinden Sie sich immer über diesen.

**Auf dem Server:**

```bash
adduser dante
passwd dante                 # starkes Passwort
usermod -aG wheel dante      # 'wheel' = sudo-Gruppe unter AlmaLinux
```

**Auf Ihrem lokalen Rechner** (Schlüsselpaar generieren, falls noch nicht vorhanden):

```bash
ssh-keygen -t ed25519 -C "dante@laptop"
# Öffentlichen Schlüssel auf den Server kopieren (noch auf Port 22)
ssh-copy-id dante@ihre.oeffentliche.ip.hier
```

Stellen Sie sicher, dass Sie sich **ohne Passwort** mit dem Schlüssel anmelden können, bevor Sie fortfahren. Falls der Schlüssel nicht funktioniert, deaktivieren Sie **nicht** die Passwortauthentifizierung im nächsten Schritt, sonst sperren Sie sich aus.

---

## 4. Sicheres SSH (Port 4428 + Härtung)

Unter AlmaLinux 10 erfolgt die moderne SSH-Konfiguration über *Drop-in*-Dateien in `/etc/ssh/sshd_config.d/` (sauberer und update-sicher im Vergleich zur Bearbeitung der Hauptdatei).

```bash
cat > /etc/ssh/sshd_config.d/99-hardening.conf <<'EOF'
# Nicht-Standardport (reduziert Lärm durch automatisierte Scans)
Port 4428

# Nur IPv4/IPv6 je nach Bedarf
# AddressFamily inet

# Härtung
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

> **Wichtig:** Den SSH-Port zu ändern reicht nicht; SELinux blockiert den neuen Port auch dann, wenn die Firewall ihn erlaubt. Er muss entsprechend etikettiert werden.

```bash
# SELinux über den neuen SSH-Port informieren
semanage port -a -t ssh_port_t -p tcp 4428

# Syntax validieren und neu starten
sshd -t && systemctl restart sshd
```

Öffnen Sie eine **zweite** SSH-Sitzung auf Port 4428 **bevor** Sie die aktuelle schließen, um den Zugang zu bestätigen:

```bash
ssh -p 4428 dante@ihre.oeffentliche.ip.hier
```

---

## 5. Firewall (firewalld)

Deaktivieren Sie `firewalld` nicht: Unter AlmaLinux 10 integriert es sich perfekt mit SELinux und Fail2Ban.

```bash
systemctl enable --now firewalld

# Standard-SSH-Dienst (Port 22) entfernen und 4428 öffnen
firewall-cmd --permanent --remove-service=ssh
firewall-cmd --permanent --add-port=4428/tcp

# Web öffnen
firewall-cmd --permanent --add-service=http
firewall-cmd --permanent --add-service=https

# Anwenden
firewall-cmd --reload

# Überprüfen
firewall-cmd --list-all
```

Erwartetes Ergebnis: Nur `4428/tcp`, `http` und `https` geöffnet. Die Ports `22`, `3306` (MySQL) und die internen Node-Ports **dürfen nicht erscheinen**. Ein externer Scanner sollte sie als geschlossen/gefiltert sehen.

---

## 6. SELinux-Grundlagen, die Sie verstehen müssen

SELinux blockiert Dienste nicht „willkürlich": Es stellt sicher, dass jeder Prozess nur das berührt, wozu er berechtigt ist (*deny by default*-Politik).

**Was keine Konfiguration erfordert:**
- Inhalte in `/var/www` über die Ports 80/443 bereitstellen. Dort erstellte Dateien erben automatisch das Label `httpd_sys_content_t`.

**Das häufigste „Aber":** Wenn Sie Dateien mit `mv` von `/home/benutzer` nach `/var/www` **verschieben**, behalten sie das ursprüngliche Label und Apache gibt **403 Forbidden** zurück. Universelle Lösung:

```bash
restorecon -Rv /var/www/meineapp
```

**Aktionsberechtigungen (Boolesche Werte), die Sie benötigen werden:**

| Szenario | Befehl |
|---|---|
| Laravel verbindet sich mit lokalem MySQL | `setsebool -P httpd_can_network_connect_db on` |
| Apache fungiert als Reverse Proxy zu einer Node-App | `setsebool -P httpd_can_network_connect on` |
| Apache liest Ordner außerhalb des Standards | `setsebool -P httpd_enable_homedirs on` |

**Ordner, in die Apache/Laravel schreiben müssen:**

```bash
semanage fcontext -a -t httpd_sys_rw_content_t "/var/www/meineapp/storage(/.*)?"
semanage fcontext -a -t httpd_sys_rw_content_t "/var/www/meineapp/bootstrap/cache(/.*)?"
restorecon -Rv /var/www/meineapp
```

> Das Flag `-P` bei `setsebool` ist **entscheidend**: Es macht die Änderung nach einem Neustart persistent.

**Diagnose-Werkzeuge (statt SELinux zu deaktivieren):**

```bash
# Verweigerungen in Echtzeit
tail -f /var/log/audit/audit.log | grep denied

# Menschenlesbarer Fehlerübersetzer
sealert -a /var/log/audit/audit.log
```

---

## 7. Apache (Webserver / Reverse Proxy)

```bash
dnf install -y httpd mod_ssl
systemctl enable --now httpd
```

Stellen Sie sicher, dass die Proxy-Module (für Node benötigt) und Rewrite (für Bot-Blockierung) geladen sind:

```bash
# Unter AlmaLinux 10 sind sie üblicherweise aktiv; überprüfen Sie:
httpd -M | grep -E "proxy_module|proxy_http|proxy_wstunnel|rewrite|headers|ssl"
```

Falls eines fehlt, liegen die Module in `/etc/httpd/conf.modules.d/`. Normalerweise sind `proxy`, `proxy_http`, `rewrite`, `headers` und `ssl` bereits aktiviert; `proxy_wstunnel` muss möglicherweise für WebSockets hinzugefügt werden.

---

## 8. PHP 8.5 + PHP-FPM (für Laravel)

PHP 8.5 ist als stabiles Remi-Modul für Enterprise Linux 10 verfügbar.

```bash
# Remi-Repository für AlmaLinux 10
dnf install -y https://rpms.remirepo.net/enterprise/remi-release-10.rpm

# PHP-8.5-Modulstream auswählen
dnf module reset php -y
dnf module enable php:remi-8.5 -y

# PHP-FPM und typische Laravel/Filament-Erweiterungen installieren
dnf install -y php php-cli php-common php-fpm \
  php-mysqlnd php-pdo php-mbstring php-xml php-curl \
  php-gd php-zip php-bcmath php-intl php-opcache php-redis

systemctl enable --now php-fpm
php -v   # 8.5.x bestätigen
```

**PHP-FPM-Pool unter dem Apache-Benutzer.** Bearbeiten Sie `/etc/php-fpm.d/www.conf` und stellen Sie sicher:

```ini
user = apache
group = apache
listen = /run/php-fpm/www.sock
listen.owner = apache
listen.group = apache
listen.mode = 0660
```

Das Paket installiert `/etc/httpd/conf.d/php.conf`, das `.php`-Anfragen über `SetHandler "proxy:unix:/run/php-fpm/www.sock|fcgi://localhost"` an den PHP-FPM-Socket weiterleitet. Eine manuelle Konfiguration ist außer in Sonderfällen nicht erforderlich.

```bash
systemctl restart php-fpm httpd
```

---

## 9. MySQL 8 mit minimalen Rechten

```bash
dnf install -y mysql-server
systemctl enable --now mysqld

# Installation absichern (Root-Passwort setzen, anonyme Benutzer entfernen, usw.)
mysql_secure_installation
```

**Binden Sie MySQL nur an localhost** (kein Netzwerk-Listening). In `/etc/my.cnf.d/mysql-server.cnf`, unter `[mysqld]`:

```ini
bind-address = 127.0.0.1
```

```bash
systemctl restart mysqld
```

**Erstellen Sie die Datenbank und einen Benutzer mit minimalen Rechten** (Verwenden Sie NICHT `*.*` oder `WITH GRANT OPTION` für Apps; das ist das gefährliche Muster alter Anleitungen):

```sql
CREATE DATABASE meineapp CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE USER 'meineapp'@'localhost' IDENTIFIED BY 'EinLangesZufaelligesPasswort_2026!';

-- Nur Rechte auf der EIGENEN Datenbank, nichts weiter
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, INDEX, DROP, REFERENCES
  ON meineapp.* TO 'meineapp'@'localhost';

FLUSH PRIVILEGES;
```

> MySQL 8 verwendet standardmäßig `caching_sha2_password`, was empfohlen wird. Greifen Sie nur auf `mysql_native_password` zurück, wenn eine ältere Bibliothek es erfordert.

Wenn Laravel beim Verbinden mit der DB 500-Fehler zurückgibt, liegt es fast immer am SELinux-Booleschen Wert:

```bash
setsebool -P httpd_can_network_connect_db on
```

---

## 10. Composer

Modernes Laravel erfordert Composer 2.x (nicht das 1.9 aus alten Anleitungen):

```bash
php -r "copy('https://getcomposer.org/installer', 'composer-setup.php');"
php composer-setup.php --install-dir=/usr/local/bin --filename=composer
rm composer-setup.php
composer --version
```

---

## 11. Deployment eines Laravel-Projekts

```bash
mkdir -p /var/www/meineapp
chown -R apache:apache /var/www/meineapp

# Klonen oder laden Sie Ihr Projekt nach /var/www/meineapp (siehe Abschnitt 19 für Git)
cd /var/www/meineapp
composer install --no-dev --optimize-autoloader

# Schreibberechtigungen für Laravel (Linux + SELinux)
chown -R apache:apache storage bootstrap/cache
semanage fcontext -a -t httpd_sys_rw_content_t "/var/www/meineapp/storage(/.*)?"
semanage fcontext -a -t httpd_sys_rw_content_t "/var/www/meineapp/bootstrap/cache(/.*)?"
restorecon -Rv /var/www/meineapp

# Laravel-Optimierung
php artisan config:cache
php artisan route:cache
php artisan view:cache
```

**Laravel-VirtualHost** in `/etc/httpd/conf.d/meineapp.conf` (HTTP leitet zu HTTPS weiter; den 443-Block vervollständigt Certbot, siehe Abschnitte 13 und 14):

```apache
<VirtualHost *:80>
    ServerName ihre-domain.com
    DocumentRoot /var/www/meineapp/public
    Redirect permanent / https://ihre-domain.com/
</VirtualHost>
```

> Das `DocumentRoot` zeigt auf `public/`, wodurch `.env`, `vendor/` und der restliche Code außer Web-Reichweite bleiben.

**Laravel-Scheduler-Cron** — muss als Apache-Benutzer laufen, um keine Berechtigungsprobleme zu verursachen:

```bash
# crontab -u apache -e
* * * * * cd /var/www/meineapp && php artisan schedule:run >> /dev/null 2>&1
```

---

## 12. Node.js 24 LTS als Dienst + Reverse Proxy

Stand Mai 2026 ist **Node.js 24 die aktive LTS-Version**, die für die Produktion empfohlen wird (Node 26 befindet sich in der *Current*-Phase, noch kein LTS).

### 12.1 Node 24 installieren

```bash
# Offizielles NodeSource-Repository für den 24.x-Branch
curl -fsSL https://rpm.nodesource.com/setup_24.x | bash -
dnf install -y nodejs
node -v    # v24.x
npm -v
```

> Alternative: `dnf module enable nodejs:24 && dnf install nodejs` aus AppStream, wenn Sie keine externen Repositories hinzufügen möchten (kann eine oder zwei *Minor*-Versionen hinterher sein).

### 12.2 Dedizierter Benutzer und Code

Betreiben Sie Node nicht als `root`. Erstellen Sie einen Systembenutzer ohne Login-Shell:

```bash
useradd --system --create-home --home-dir /var/www/meineapp-node --shell /usr/sbin/nologin nodeapp
# Laden/klonen Sie Ihre App nach /var/www/meineapp-node und bauen Sie sie
cd /var/www/meineapp-node
sudo -u nodeapp npm ci --omit=dev
sudo -u nodeapp npm run build   # falls zutreffend
```

### 12.3 systemd-Dienst (sauberer und sicherer als PM2 als Root)

Erstellen Sie `/etc/systemd/system/meineapp-node.service`:

```ini
[Unit]
Description=Meine Node-App
After=network.target

[Service]
Type=simple
User=nodeapp
Group=nodeapp
WorkingDirectory=/var/www/meineapp-node
# Die App MUSS auf Loopback lauschen: Host 127.0.0.1, Port 3000
Environment=NODE_ENV=production
Environment=PORT=3000
Environment=HOST=127.0.0.1
ExecStart=/usr/bin/node dist/server.js
Restart=on-failure
RestartSec=5

# Dienst-Härtung
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable --now meineapp-node
systemctl status meineapp-node
ss -tlpn | grep 3000      # muss NUR auf 127.0.0.1:3000 lauschen
```

> Stellen Sie sicher, dass Ihre App `process.env.HOST` und `process.env.PORT` liest und **auf `127.0.0.1`** lauscht, nicht auf `0.0.0.0`. So ist Port 3000 niemals vom Internet aus erreichbar, nur von Apache.

### 12.4 Proxy in SELinux erlauben

Damit Apache eine Netzwerkverbindung zum Node-Port öffnen kann:

```bash
setsebool -P httpd_can_network_connect on
```

### 12.5 Reverse-Proxy-VirtualHost

`/etc/httpd/conf.d/meineapp-node.conf`:

```apache
<VirtualHost *:80>
    ServerName node.ihre-domain.com
    Redirect permanent / https://node.ihre-domain.com/
</VirtualHost>

<VirtualHost *:443>
    ServerName node.ihre-domain.com

    ProxyPreserveHost On
    ProxyPass        / http://127.0.0.1:3000/
    ProxyPassReverse / http://127.0.0.1:3000/

    # WebSocket-Unterstützung (falls Ihre App es nutzt: Socket.io, usw.)
    RewriteEngine On
    RewriteCond %{HTTP:Upgrade} =websocket [NC]
    RewriteRule /(.*) ws://127.0.0.1:3000/$1 [P,L]

    # (Die Sicherheits-Header aus Abschnitt 14 gelten hier ebenfalls)
    # (Certbot fügt die SSL-Direktiven hier ein)

    ErrorLog  /var/log/httpd/meineapp-node-error.log
    CustomLog /var/log/httpd/meineapp-node-access.log combined
</VirtualHost>
```

```bash
apachectl configtest && systemctl restart httpd
```

> **Öffnen Sie Port 3000 nicht in firewalld.** Der Datenverkehr gelangt über 443 (Apache, mit TLS) und wird intern weitergeleitet. Node bleibt isoliert.

---

## 13. Let's Encrypt (SSL) und automatische Erneuerung

```bash
dnf install -y certbot python3-certbot-apache

# Ein Zertifikat pro Domain/Subdomain
certbot --apache -d ihre-domain.com
certbot --apache -d node.ihre-domain.com
```

Certbot fügt automatisch die Direktiven `SSLCertificateFile`, `SSLCertificateKeyFile` und `Include /etc/letsencrypt/options-ssl-apache.conf` in Ihre 443-VirtualHosts ein.

**Automatische Erneuerung.** Das Paket installiert einen systemd-*Timer*, der ohne Eingriff erneuert. Überprüfen Sie ihn:

```bash
systemctl list-timers | grep certbot
certbot renew --dry-run     # Probelauf zur Bestätigung, dass die Erneuerung funktioniert
```

---

## 14. HTTP-Sicherheits-Header

Diese Header beheben typische Findings von Scannern wie web-check.xyz (HSTS, Clickjacking, MIME-Sniffing, XSS, CSP). Fügen Sie sie im `<VirtualHost *:443>`-Block jeder Website hinzu.

```apache
# HSTS: erzwingt HTTPS für 2 Jahre (berechtigt für die Preload-Liste)
Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"

# Anti-Clickjacking
Header always set X-Frame-Options "SAMEORIGIN"

# MIME-Sniffing verhindern
Header always set X-Content-Type-Options "nosniff"

# Referrer-Politik
Header always set Referrer-Policy "strict-origin-when-cross-origin"

# Permissions-Policy (schränkt Browser-APIs ein)
Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"

# Content-Security-Policy: die mächtigste Schutzmaßnahme gegen XSS.
# Passen Sie die externen Domains an, die Sie tatsächlich nutzen (Schriften, Karten, Analytics).
Header always set Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://fonts.googleapis.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self';"

# Versions-Lecks entfernen
ServerSignature Off
Header unset X-Powered-By
```

> **Hinweis zu `X-XSS-Protection`:** Dieser Header ist veraltet und wird von modernen Browsern ignoriert (manche empfehlen `0`). Der echte XSS-Schutz heute ist eine gute **CSP**. Falls Ihr Scanner ihn noch verlangt, können Sie `Header set X-XSS-Protection "1; mode=block"` hinzufügen, aber dort liegt die echte Sicherheit nicht.

> **CSP ist iterativ.** Beginnen Sie mit der obigen Richtlinie; wenn etwas aufhört zu laden (ein externes Skript, eine Karte, Google Analytics), fügen Sie diese Domain zur entsprechenden Direktive hinzu. Für Filament reicht meist `'self' 'unsafe-inline' 'unsafe-eval'`.

```bash
apachectl configtest && systemctl restart httpd
```

---

## 15. Versionen verbergen (Informationsleck)

Der Welt mitzuteilen „ich verwende PHP 8.5.6 und Apache 2.4.63" ist gleichbedeutend damit, Angreifern die genaue Karte der auszuprobierenden Exploits zu liefern.

**Apache** — erstellen Sie `/etc/httpd/conf.d/00-security.conf`:

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

Danach gibt der `Server`-Header nur noch `Apache` (ohne Version) an und `X-Powered-By: PHP/...` verschwindet.

---

## 16. Bot-Blockierung nach User-Agent und Exploit-Pfaden

Echte Logs zeigen zwei Arten automatisierten Rauschens: Scanner, die sich mit bekannten User-Agents identifizieren (`l9scan`, `zgrab`, `Nikto`, `CensysInspect`), und Bots, die Pfade anfragen, die in der App nicht existieren (`/.env`, `/.git/config`, `/vendor/phpunit/.../eval-stdin.php`, `/wp-config.php`). Es lohnt sich, beide **auf VirtualHost-Ebene** abzuschneiden, bevor die Anfrage PHP erreicht.

> **Gelernte Lektion — verankern Sie den User-Agent nicht mit `^`.** Eine frühere Version verwendete `RewriteCond %{HTTP_USER_AGENT} ^Nmap`, das nur übereinstimmt, wenn der UA *genau* mit dieser Zeichenkette *beginnt*. Bots wie `l9scan` identifizieren sich als `Mozilla/5.0 (l9scan/2.0...)`, so ließ der Anker sie durch. Die korrekte Regel sucht die Zeichenkette **an beliebiger Stelle** im User-Agent.

Platzieren Sie die Blockierung direkt unter `<VirtualHost *:443>`, nicht innerhalb des `<Directory>`. Der Server-Kontext wird zuerst und unabhängig vom `.htaccess` von Laravel ausgewertet, sodass die Blockierung auf jede Anfrage angewendet wird, unabhängig davon, was Laravel danach verarbeitet. Erfordert ein explizites `RewriteEngine On` in diesem Kontext:

```apache
RewriteEngine On

# 1) Blockierung nach User-Agent — OHNE Anker ^, um sie überall
#    in der Zeichenkette zu erfassen (z.B. "Mozilla/5.0 (l9scan/...)" kommt nicht mehr durch)
RewriteCond %{HTTP_USER_AGENT} (l9explore|l9scan|l9tcpid|Nmap|Masscan|zgrab|Nikto|CensysInspect|leakix|libredtail|Gh0st) [NC]
RewriteRule ^ - [F,L]

# 2) Leerer User-Agent bei Anfragen außer der Wurzel (rohe Bots)
RewriteCond %{HTTP_USER_AGENT} ^-?$
RewriteCond %{REQUEST_URI} !^/$
RewriteRule ^ - [F,L]

# 3) Blockierung versteckter Dateien (.env, .git, usw.)
#    AUSSER /.well-known (notwendig für Let's Encrypt-Erneuerung)
RewriteRule "(^|/)\.(?!well-known)" - [F,L]

# 4) Bekannte Exploit-Pfade (PHPUnit eval-stdin, vendor, .php-Müll)
RewriteCond %{REQUEST_URI} (eval-stdin\.php|/vendor/|/phpunit|/wp-|xmlrpc\.php|/phpinfo|/\.aws|/\.ssh) [NC]
RewriteRule ^ - [F,L]
```

> **Das `/.well-known` ist kritisch.** Würden Sie alle Dotfiles ohne Ausnahme blockieren, würden Sie die ACME-Herausforderung von Certbot (`/.well-known/acme-challenge/`) unterbrechen und Ihr Zertifikat würde nicht mehr erneuert werden. Das `(?!well-known)` schützt es.

> **Blockieren Sie `curl` nicht nach User-Agent.** Auch wenn es in Scans erscheint, ist es das Werkzeug, das Sie selbst für Tests und Health Checks verwenden. Dieses Verhalten überlässt man besser Fail2Ban (sperrt nach Verhalten, nicht nach Name), siehe Abschnitt 17.

Ab jetzt erhalten diese Bots **403 Forbidden** statt einer 404. Das ist gut: Fail2Ban (nächster Abschnitt) sperrt jeden, der 403er ansammelt.

```bash
apachectl configtest && systemctl restart httpd
```

**Messbares Ergebnis.** In einem realen Fall auf diesem Server zeigte das Log nach Anwendung der Blockierung täglich Hunderte von `403`-Einträgen gegen das Scannen von `/.env`, `/.git/config`, `/wp-config.php` und `/.aws/credentials`, die zuvor als harmlose `404` durchkamen, aber PHP erreichten. Eine einzige aggressive Scan-IP (`45.148.10.95`) häufte 220 Blockierungen an einem Tag an, ohne die Anwendung zu berühren.

---

## 17. Fail2Ban: Aktive Verteidigung

Die Firewall ist eine passive Mauer; Fail2Ban ist ein Wächter, der Logs liest und wiederholte IP-Adressen auf Netzwerkebene sperrt.

```bash
dnf install -y fail2ban fail2ban-firewalld
```

**Hauptkonfiguration** — bearbeiten Sie niemals `jail.conf`; erstellen Sie `/etc/fail2ban/jail.local`:

```ini
[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 5
# Sperrung über firewalld (native Integration unter AlmaLinux 10)
banaction = firewallcmd-rich-rules
# WICHTIG: Fügen Sie IHRE feste IP hinzu, um sich nicht selbst zu sperren
ignoreip = 127.0.0.1/8 ::1 ihre.oeffentliche.ip.hier

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

**Benutzerdefinierter Filter** zum Abfangen von `.env`/`.git`-Scans und 403-Fehlern aus der User-Agent-Blockierung. Erstellen Sie `/etc/fail2ban/filter.d/laravel-vulnerabilities.conf`:

```ini
[Definition]
# Erfasst 404 (Suche nach sensiblen Dateien) und 403 (User-Agent / Dotfile-Blockierungen)
failregex = ^<HOST> -.*"GET .*\.(env|git|aws|yml|yaml|json).* HTTP/.*" (404|403)
            ^<HOST> -.*"GET .*(\.git|config|credentials).* HTTP/.*" (404|403)
            ^<HOST> -.*"(GET|POST) .* HTTP/.*" 403
ignoreregex =
```

> **Zum Missbrauch öffentlicher Formulare (Registrierung, Kontakt).** IPs, die `POST /registrierung` hämmern, rotieren Adressen und verwenden echte Browser-User-Agents, sodass ein 403-Filter sie nicht erfasst: Auf HTTP-Ebene sind sie von einem Menschen nicht zu unterscheiden. Die richtige Verteidigung dagegen **ist nicht Fail2Ban**, sondern Cloudflare Turnstile + Rate Limiting + E-Mail-Verifizierung (siehe Abschnitt 22). Wenn Sie trotzdem möchten, dass Fail2Ban auf die hartnäckigsten reagiert, können Sie einen Filter hinzufügen, der `429`-Antworten (Laravel-Rate-Limit) pro IP zählt, aber das ist sekundäre Verteidigung, nicht die primäre.

**Jail**, das diesen Filter auf Ihr Zugriffslog anwendet (passen Sie den Pfad an Ihren `CustomLog` an). Am Ende von `jail.local` hinzufügen:

```ini
[laravel-scan]
enabled  = true
port     = http,https
filter   = laravel-vulnerabilities
logpath  = /var/log/httpd/meineapp-access.log
maxretry = 2
bantime  = 48h
findtime = 1h
```

**Aktivieren und überprüfen:**

```bash
systemctl enable --now fail2ban
fail2ban-client status
fail2ban-client status laravel-scan

# Filter gegen Ihr aktuelles Log testen (zählt "Hits")
fail2ban-regex /var/log/httpd/meineapp-access.log /etc/fail2ban/filter.d/laravel-vulnerabilities.conf
```

**SELinux und das benutzerdefinierte Log.** Falls Fail2Ban Ihr benanntes Log nicht lesen kann, prüfen Sie dessen Kontext:

```bash
ls -Z /var/log/httpd/meineapp-access.log   # sollte httpd_log_t sein
restorecon -v /var/log/httpd/meineapp-access.log
```

> Falls Sie sich entsperren müssen: `fail2ban-client set laravel-scan unbanip 1.2.3.4`.

Damit haben Sie **Verteidigung in Schichten**: Apache identifiziert den Bot und schließt die Tür (403) → der Versuch landet im Log → Fail2Ban erkennt die wiederholte IP und sperrt sie in firewalld.

---

## 18. security.txt und robots.txt

**security.txt** (Standard, damit Forscher Schwachstellen verantwortungsvoll melden können):

```bash
mkdir -p /var/www/meineapp/public/.well-known
cat > /var/www/meineapp/public/.well-known/security.txt <<'EOF'
Contact: mailto:sicherheit@ihre-domain.com
Expires: 2027-01-01T00:00:00.000Z
Preferred-Languages: de, en
EOF
restorecon -Rv /var/www/meineapp/public/.well-known
```

**robots.txt** — um die Indexierung des Admin-Panels zu entmutigen (das ist nur ein *Hinweis* für legitime Crawler; die echte Sicherheit von `/admin` ist der Laravel/Filament-Login):

```
User-agent: *
Disallow: /admin/
Disallow: /admin
Allow: /
```

---

## 19. Deployment-Workflow mit Git

**Klassischer Fehler:** `fatal: detected dubious ownership in repository`. Tritt auf, weil der Ordner `apache` gehört, Sie Git aber als anderer Benutzer ausführen.

```bash
git config --global --add safe.directory /var/www/meineapp
```

**Das eigentliche Problem:** Nach `git pull` verlieren neue Dateien den Eigentümer `apache` und/oder den SELinux-Kontext, und Apache gibt 403/500 zurück. Der korrekte Produktions-Workflow:

```bash
git pull origin main
chown -R apache:apache /var/www/meineapp
restorecon -Rv /var/www/meineapp        # SELinux-Labels wiederherstellen
php /var/www/meineapp/artisan optimize
```

**Automatisieren Sie es mit einem Deploy-Skript** (`/usr/local/bin/deploy-meineapp`):

```bash
#!/usr/bin/env bash
set -euo pipefail
cd /var/www/meineapp
git pull origin main
composer install --no-dev --optimize-autoloader
php artisan migrate --force
php artisan config:cache && php artisan route:cache && php artisan view:cache
chown -R apache:apache /var/www/meineapp
restorecon -Rv /var/www/meineapp
echo "Deploy OK"
```

```bash
chmod +x /usr/local/bin/deploy-meineapp
```

> **Warum `restorecon` entscheidend ist:** Git weist neuen Dateien ein temporäres Label zu; ohne `restorecon` kann SELinux deren Lesen mit einem 403 blockieren, selbst wenn `chmod`/`chown` korrekt sind.

Für Node startet das Äquivalent den Dienst neu: `... && systemctl restart meineapp-node`.

---

## 20. Automatische Updates und Wartung

**Automatische Sicherheits-Patches:**

```bash
dnf install -y dnf-automatic
# In /etc/dnf/automatic.conf -> apply_updates = yes (oder nur benachrichtigen)
systemctl enable --now dnf-automatic.timer
```

**Empfohlene manuelle Routine:**

```bash
dnf update --security        # Sicherheits-Patches
certbot renew --dry-run      # SSL-Erneuerung bestätigen
fail2ban-client status       # Sperrungen überprüfen
```

**Backups (Mindestanforderung):** Planen Sie ein tägliches MySQL-Dump und ein Backup von `/var/www` und `/etc/httpd`:

```bash
mysqldump --single-transaction --routines meineapp | gzip > /backups/meineapp-$(date +\%F).sql.gz
```

---

## 21. Valkey (Cache, Sitzungen und Warteschlangen)

Damit Laravel/Filament in der Produktion gut performen, verlagern Sie Cache, Sitzungen und Warteschlangen von der Datenbank auf einen In-Memory-Speicher. **AlmaLinux 10 enthält Redis nicht mehr** (Redis Labs wechselte in Version 7.4 zu Nicht-FOSS-Lizenzen und die Distro entfernte es aus ihren Repositories); der offizielle Ersatz im AppStream ist **Valkey**, ein Fork mit FOSS-Lizenz. Es ist ein *Drop-in*: phpredis und Laravels `redis`-Treiber kommunizieren mit Valkey, ohne irgendwelchen Anwendungscode zu ändern.

> **Warum Valkey und nicht Redis via Remi.** Redis kehrte mit 8.0 zu einer Open-Source-Lizenz (AGPLv3) zurück und es gibt RPMs in `remi-modular`, aber das würde Sicherheitsupdates eines *Datastores* (der Sitzungen speichern wird) an ein Drittanbieter-Repository binden. Valkey aus dem offiziellen AppStream erhält Patches im normalen Distro-Zyklus, mit geringerem Wartungsaufwand. Solange Sie keine sehr neue Redis-8.x-Funktion benötigen, ist Valkey die empfohlene Option.

### 21.1 Installation

```bash
dnf install -y valkey
valkey-server --version
```

### 21.2 Sichere Konfiguration

Das klassische Redis/Valkey-Bedrohungsmodell ist „Internet-exponierte Instanz ohne Passwort". Da Valkey hier auf **demselben Server** wie Laravel läuft, ist das Sicherste, es **überhaupt nicht dem Netzwerk auszusetzen**: Unix-Socket + kein TCP-Port. Generieren Sie zunächst ein starkes Passwort:

```bash
openssl rand -base64 48
```

Bearbeiten Sie `/etc/valkey/valkey.conf` (viele Direktiven existieren bereits auskommentiert; suchen und anpassen):

```conf
# --- NETZWERK: keiner Schnittstelle aussetzen ---
bind 127.0.0.1 -::1
protected-mode yes
port 0                              # TCP vollständig deaktivieren; nur Unix-Socket

# --- UNIX-SOCKET: so verbindet sich Laravel ---
unixsocket /run/valkey/valkey.sock
unixsocketperm 770

# --- AUTHENTIFIZIERUNG ---
requirepass "HIER_DAS_GENERIERTE_PASSWORT_EINFUEGEN"

# --- SPEICHER UND RICHTLINIE ---
maxmemory 2gb                       # an Ihre Zuweisung anpassen
maxmemory-policy allkeys-lru        # Tippfehler beachten: es ist allkeys-lru (mit 'a')

# --- PERSISTENZ (um Sitzungen/Warteschlangen bei Neustart nicht zu verlieren) ---
appendonly yes
appendfsync everysec

# --- GEFÄHRLICHE BEFEHLE ---
rename-command FLUSHALL ""
rename-command FLUSHDB ""
rename-command KEYS ""                  # KEYS blockiert den Server in Prod; Laravel nutzt es nicht
rename-command CONFIG "CONFIG_a8f3k2"   # in etwas Unvorhersehbares umbenennen statt löschen
```

> **Ein Tippfehler verhindert den Start.** Wenn Valkey nicht startet, prüfen Sie `systemctl status valkey`: Die Meldung `FATAL CONFIG FILE ERROR` gibt die genaue Zeilennummer des Fehlers an. Ein falsch geschriebener Wert (z.B. `llkeys-lru` statt `allkeys-lru`) verhindert den Start, und als Folge wird der Socket nie erstellt — daher ein `No such file or directory` beim Verbindungsversuch, was ein Symptom ist, nicht die Ursache.

### 21.3 Socket-Verzeichnis, Berechtigungen und SELinux

Das Socket-Verzeichnis in `/run` ist flüchtig; erstellen Sie es persistent mit tmpfiles, damit es Neustarts überlebt:

```bash
echo 'd /run/valkey 0750 valkey valkey -' > /etc/tmpfiles.d/valkey.conf
systemd-tmpfiles --create
```

Damit PHP-FPM (und Netdata, falls verwendet) den Socket lesen können, fügen Sie diese Benutzer zur Gruppe `valkey` hinzu — gleiche Gruppenlogik wie bei `apache`:

```bash
usermod -aG valkey apache
usermod -aG valkey dante         # wenn Ihre FPM-Pools als dante laufen
usermod -aG valkey netdata       # wenn Sie mit Netdata überwachen
```

SELinux: Aktivieren Sie den Web-Connect-Booleschen Wert und etikettieren Sie das Socket-Verzeichnis bei Verweigerungen:

```bash
setsebool -P httpd_can_network_connect 1
semanage fcontext -a -t redis_var_run_t "/run/valkey(/.*)?" 2>/dev/null || true
restorecon -Rv /run/valkey

# Falls Valkey wegen SELinux scheitert, Verweigerungen prüfen und gezielte Richtlinie generieren:
ausearch -m avc -ts recent | grep -iE "valkey|redis"
```

### 21.4 Dienst-Härtung (systemd)

Verstärken Sie die Isolierung mit einem Drop-in statt den originalen Unit zu bearbeiten:

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

### 21.5 Start und Überprüfung

```bash
systemctl enable --now valkey
systemctl status valkey --no-pager

# Socket-Verbindung mit Authentifizierung
valkey-cli -s /run/valkey/valkey.sock
#   AUTH "ihr_passwort"
#   PING            -> muss PONG antworten
#   exit

# Bestätigen, dass KEIN TCP-Port lauscht (muss leer sein)
ss -tlnp | grep 6379
```

### 21.6 Laravel-Integration

Bestätigen Sie die phpredis-Erweiterung (in C kompiliert, schneller als Predis; kein `predis/predis` via Composer nötig, wenn Sie diese verwenden):

```bash
php -m | grep -i redis
# falls fehlend:
dnf install -y php-redis && systemctl reload php-fpm
```

In der `.env` jeder Plattform, die auf den Socket zeigt und **evictierbare** Daten (Cache, in einer DB) von nicht-evictierbaren (Sitzungen/Warteschlangen, in einer anderen) **trennt**. Mit Unix-Socket muss `REDIS_PORT` `0` sein:

```env
REDIS_CLIENT=phpredis
REDIS_HOST=/run/valkey/valkey.sock
REDIS_PORT=0
REDIS_PASSWORD="ihr_passwort"

REDIS_DB=0          # Sitzungen und Warteschlangen (dürfen nicht evictiert werden)
REDIS_CACHE_DB=1    # Cache (evictierbar mit allkeys-lru)

CACHE_STORE=redis
SESSION_DRIVER=redis
QUEUE_CONNECTION=redis
```

> **Das `prefix` zählt bei mehreren Plattformen.** Alle Ihre Apps teilen dasselbe Valkey. Laravels Standard-Schlüssel-Präfix leitet sich von `APP_NAME` ab, also stellen Sie sicher, dass jede Plattform einen anderen `APP_NAME` (oder ein explizites `REDIS_PREFIX`) hat, oder Cache-Schlüssel einer App überschreiben die einer anderen.

Da Sie den Config zwischengespeichert haben, **wirken `.env`-Änderungen erst, wenn Sie den Cache neu generieren**:

```bash
php artisan config:clear && php artisan config:cache

php artisan tinker
>>> Cache::store('redis')->put('test', 'ok', 60); Cache::store('redis')->get('test');   # -> "ok"
```

> **Die Variablen heißen weiterhin `REDIS_*` und der Treiber ist `redis`**: Das ist nur der Client-Name. Im Hintergrund spricht er mit Valkey, ohne es zu wissen oder sich darum zu kümmern.

**Schlüssel-Inspektion.** Da wir `KEYS` deaktiviert haben, verwenden Sie `SCAN` (blockiert den Server nicht). Aus der Shell iteriert `--scan` alleine:

```bash
export REDISCLI_AUTH="ihr_passwort"     # vermeidet das Exponieren des Passworts in der Shell-History
valkey-cli -s /run/valkey/valkey.sock -n 1 --scan                        # alle Cache-Schlüssel (DB 1)
valkey-cli -s /run/valkey/valkey.sock -n 1 --scan --pattern "meineapp_*" # nach App-Präfix filtern
valkey-cli -s /run/valkey/valkey.sock INFO keyspace                      # Anzahl pro DB auf einen Blick
```

> **Sichere Reihenfolge:** Installieren und überprüfen Sie Valkey vollständig (bis `PING` mit `PONG` antwortet) **bevor** Sie die `.env`-Dateien ändern. So lassen Sie die Apps bei einem Verbindungsproblem nicht ohne Cache oder Sitzung.

---

## 22. Schutz öffentlicher Formulare (Turnstile + Rate Limiting)

Öffentliche Registrierungsformulare sind das Ziel massiver automatisierter Erstellung gefälschter Konten. Auf diesem Server zeigten die Logs mehrere IPs (Bereiche von Hosting-Anbietern, keine echten Benutzer), die `POST /registrierung` dauerhaft erfolgreich ausführten. Rate Limiting allein **reicht nicht**, weil Bots IPs rotieren: Jede bleibt unter dem Schwellenwert. Die effektive Verteidigung ist mehrschichtig.

### 22.1 Cloudflare Turnstile (das Hauptelement)

Turnstile ist ein kostenloser, datenschutzfreundlicher CAPTCHA-Dienst. Der kritische Punkt ist, dass die Validierung **serverseitig** erfolgt, nicht nur durch das Rendern des Widgets: Ein Bot, der direkt POST sendet, ohne den Browser zu durchlaufen, muss gleichfalls abgelehnt werden.

Verifizierungs-Service (`app/Services/TurnstileService.php`):

```php
public function verify(string $token, string $ip): bool
{
    // Günstige Prüfung: leerer Token = Cloudflare wird gar nicht aufgerufen.
    // Vermeidet den Round-Trip (mit seinem Timeout) im häufigsten Missbrauchsfall (POST ohne Token).
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
        return false;   // fail-closed: wenn Cloudflare nicht antwortet, registriert sich niemand
    }
}
```

Im Controller, verifizieren Sie **bevor** Sie validieren oder die Datenbank berühren:

```php
if (! $this->turnstile->verify((string) $request->input('cf-turnstile-response'), $request->ip())) {
    return back()->withInput()->withErrors(['captcha' => 'Wir konnten nicht verifizieren, dass Sie ein Mensch sind.']);
}
```

Zwei Designentscheidungen, die Sie bedenken sollten: Der `catch` gibt `false` zurück (**fail-closed**), korrekt um Missbrauch zu stoppen, impliziert aber, dass ein Netzwerkfehler mit Cloudflare legitime Registrierungen blockieren würde; und wenn Sie **mehrere Registrierungsrouten** haben (z.B. Host und Kunde), müssen **beide** die Verifizierung tragen, oder Bots nutzen die ungeschützte.

### 22.2 Spezifisches Rate Limiting (sekundäre Schicht)

Entfernen Sie den Rate Limiter nicht, wenn Sie Turnstile hinzufügen; sie ergänzen sich. Für die Registrierungsroute, etwas aggressiver als der Standard:

```php
RateLimiter::for('registrierung', function (Request $request) {
    return [
        Limit::perMinute(3)->by($request->ip()),
        Limit::perDay(10)->by($request->ip()),
    ];
});
```

### 22.3 Obligatorische E-Mail-Verifizierung (Eindämmung)

Selbst wenn ein Konto es schafft, sich zu registrieren, sollte es nichts tun können, bis seine E-Mail verifiziert ist. Verwenden Sie `MustVerifyEmail` im `User`-Modell und das `verified`-Middleware auf geschützten Routen. Das macht jeden Müll-Account, der durchkommt, zu einem inerten Account.

### 22.4 Wie man überprüft, ob es funktioniert (die Logs täuschen)

Das Apache-Log **unterscheidet nicht** zwischen einer erfolgreichen Registrierung und einer Turnstile-Ablehnung: Beide produzieren einen `302` (der Erfolg leitet zu `/verification.notice` weiter; die Ablehnung kehrt mit `back()` zum Formular zurück). Hunderte von `302`-Einträgen auf `/registrierung` zu sehen **bedeutet nicht**, dass Konten erstellt werden. Das echte Thermometer ist die Datenbank:

```sql
SELECT COUNT(*) FROM users WHERE created_at >= CURDATE();
```

Wenn dieser Zähler bei Ihren erwarteten realen Zahlen bleibt (oder bei null, wenn Sie keine legitimen Registrierungen erwartet haben), während das Log weiterhin Versuche zeigt, tut Turnstile seine Arbeit. **Bots werden nicht aufhören zu versuchen** — Sie werden weiterhin die `302`-Einträge und `POST`-Anfragen sehen — aber sie werden keine Konten erstellen. Lassen Sie sich nicht vom Log-Rauschen alarmieren; beobachten Sie den `COUNT`.

> **Echte Defense in Depth:** Turnstile eliminiert automatisierte Registrierung, der Rate Limiter fängt die hartnäckigsten ab, die VHost-Blockierung (Abschnitt 16) stoppt Scans bevor PHP erreicht wird, und Fail2Ban (Abschnitt 17) sperrt Wiederholungstäter auf Firewall-Ebene. Jede Schicht schließt die Lücken der anderen.

---

## 23. Leistungsoptimierung

Sobald der Server gesichert ist, sind dies die Leistungshebel für Laravel/Filament. **Dimensionieren Sie mit Daten, nicht nach Gefühl:** Messen Sie den tatsächlichen Verbrauch unter Last, bevor Sie Werte festlegen, und wenden Sie eine Änderung nach der anderen an und validieren, dass sie geholfen hat.

> **Schritt null (kritisch):** Bestätigen Sie, dass jede App im Produktionsmodus ist. `php artisan about` muss `Environment = production` und `Debug Mode = OFF` anzeigen. Mit `APP_DEBUG=true` auf einem öffentlichen Server exponiert jede Ausnahme Zugangsdaten und Umgebungsvariablen dem Besucher — das ist gleichzeitig ein Sicherheitsleck und ein Leistungskostenfaktor.

### 23.1 OPcache

Der Standard (`memory_consumption=128`, `max_accelerated_files=10000`) reicht für mehrere Laravel + Filament-Apps nicht aus: Ein einzelnes Projekt mit seinem `vendor/` hat rund 8–12k Dateien, also verdrängt OPcache mit zwei Apps ständig. In `/etc/php.d/10-opcache.ini`:

```ini
opcache.enable=1
opcache.memory_consumption=512        ; von 128 erhöhen
opcache.interned_strings_buffer=32    ; von 8 erhöhen
opcache.max_accelerated_files=65000   ; von 10000 erhöhen
opcache.save_comments=1               ; NICHT deaktivieren: Filament/Laravel verwenden Attribute
opcache.validate_timestamps=0         ; NUR wenn Deploy OPcache zurücksetzt (siehe unten)
opcache.revalidate_freq=0
```

Und aktivieren Sie den PCRE-JIT (beschleunigt die Regex-Engine für Routen/Validierung), der üblicherweise deaktiviert ist:

```ini
; /etc/php.d/30-pcre.ini
pcre.jit=1
```

> `validate_timestamps=0` nur wenn Ihr Deploy-Skript (Abschnitt 19) mit einem OPcache-Reset endet (`cachetool opcache:reset` oder `systemctl reload php-fpm`); andernfalls würden Code-Änderungen nach einem Deploy nicht reflektiert werden. Der **PHP-JIT** (anders als der PCRE-JIT) kann deaktiviert bleiben: Für I/O-gebundene Last wie Laravel ist der Vorteil marginal.

### 23.2 PHP-FPM: ein Pool pro Plattform

Ein einziger `www`-Pool für alle Apps ist fragil: Ein Spitzenwert bei einer kann die anderen von Workers berauben, und alle laufen als `apache` mit demselben Log. Die richtige Vorgehensweise ist **ein Pool pro Plattform**, jeder mit eigenem Benutzer. In `/etc/php-fpm.d/meineapp.conf`:

```ini
[meineapp]
user = dante
group = apache
listen = /run/php-fpm/meineapp.sock
listen.owner = apache
listen.group = apache
listen.mode = 0660

pm = ondemand                          ; niedriger/mittlerer Traffic: gibt RAM frei, wenn inaktiv
pm.max_children = 20
pm.process_idle_timeout = 30s
pm.max_requests = 500                  ; recycelt Workers -> verhindert Speicherlecks

php_admin_value[memory_limit] = 384M   ; pro Pool, NICHT das globale 1024M
slowlog = /var/log/php-fpm/meineapp-slow.log
request_slowlog_timeout = 5s
pm.status_path = /status
```

> Ein hohes globales `memory_limit` (z.B. 1024M) ist für Web gefährlich: 50 Children × 1 GB = 50 GB theoretisch. Lassen Sie es hoch für CLI (Migrationen, Exporte), begrenzen Sie es aber pro Pool. Messen Sie das tatsächliche Gewicht pro Prozess unter Last, um `max_children` zu dimensionieren:
> ```bash
> ps --no-headers -o rss -C php-fpm | awk '{s+=$1;n++} END {printf "%.0f MB Durchschn, %d Proz\n", s/n/1024, n}'
> ```

### 23.3 MySQL 8.4

> **Methodologische Warnung:** Ein MySQL mit wenig Daten tiefgreifend zu optimieren ist verfrüht. Was am Anfang den größten Wert bringt, ist das **Aktivieren des Slow-Query-Logs**, um Material zu haben, wenn echter Traffic kommt.

In `/etc/my.cnf.d/optimization.cnf`:

```ini
[mysqld]
# Diagnose (am wichtigsten zu Beginn)
slow_query_log = ON
long_query_time = 1
log_queries_not_using_indexes = ON     ; laut; nach der Anfangsphase deaktivieren

# Redo-Log (in 8.4 ersetzt innodb_log_file_size; der Standard ~48M ist klein)
innodb_redo_log_capacity = 1G          ; erfordert MySQL-Neustart

# Passend zur Hardware (SATA SSD, kein NVMe). 10000 ist für diese Platten unrealistisch.
innodb_io_capacity = 2000
innodb_io_capacity_max = 4000

tmp_table_size = 64M
max_heap_table_size = 64M
```

> **Senken Sie `innodb_flush_log_at_trx_commit` nicht unter 1**, wenn Sie steuerliche/buchhalterische Daten verwalten: Opfern Sie transaktionale Integrität nicht für einen Mikro-Benchmark. Erhöhen Sie `innodb_buffer_pool_size` (der Standard kann zu klein sein) nur wenn die Daten wachsen; Sie haben genug RAM.

### 23.4 Apache MPM event und HTTP/2

Mit PHP-FPM muss das MPM **event** sein (nicht prefork). Definieren Sie explizite Limits und bestätigen Sie HTTP/2 und Komprimierung:

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

Und cachen Sie Vite-kompilierte Assets aggressiv (Hash-Namen → unveränderlich), im VirtualHost:

```apache
<LocationMatch "^/build/.*\.(js|css|woff2?|svg|png|jpe?g|webp|avif)$">
    Header set Cache-Control "public, max-age=31536000, immutable"
</LocationMatch>
```

### 23.5 Sichere Anwendungsreihenfolge

1. `APP_ENV=production` + `APP_DEBUG=false` → `artisan optimize` + `filament:optimize`.
2. Valkey für Cache/Sitzung/Warteschlange (Abschnitt 21).
3. OPcache (Speicher, Dateien, `pcre.jit`) → `reload php-fpm`.
4. FPM-Pools pro Plattform, einen nach dem anderen.
5. MySQL: Slow-Log zuerst (kein Neustart erforderlich), dann Redo-Log + io_capacity (Neustart erforderlich).
6. `opcache.validate_timestamps=0` NUR wenn Deploy OPcache bereits zurücksetzt.
7. Apache MPM/HTTP2/Komprimierung → `reload httpd`.

Messen Sie vor/nach mit `ab`/`wrk` gegen einen repräsentativen Endpunkt, den FPM-`pm.status_path` und `SHOW ENGINE INNODB STATUS` nach Stunden echter Nutzung.

---

## 24. Abschließende Verifikations-Checkliste

| Bereich | Gewünschter Zustand | Wie überprüfen |
|---|---|---|
| SELinux | Enforcing (niemals permissive/disabled) | `getenforce` |
| SSH | Port 4428, kein Root, nur Schlüssel | `ssh -p 4428`, `sshd_config.d/` prüfen |
| Firewall | Nur 4428, http, https | `firewall-cmd --list-all` |
| Geschlossene Ports | 22, 3306, 3000 NICHT extern erreichbar | Externer Scanner / `ss -tlpn` |
| MySQL | Bind 127.0.0.1, Benutzer mit minimalen Rechten | `ss -tlpn \| grep 3306` |
| PHP | 8.5.x, `expose_php = Off` | `php -v`, HTTP-Header |
| Node | Lauscht auf 127.0.0.1, läuft als `nodeapp` | `ss -tlpn \| grep 3000` |
| SSL | Gültiges Zertifikat, 80→443-Weiterleitung | `certbot certificates` |
| Header | HSTS, CSP, X-Frame, X-Content-Type, Referrer | Web-Scanner / `curl -I` |
| Versions-Lecks | Keine Version in `Server` oder `X-Powered-By` | `curl -I https://ihre-domain.com` |
| Fail2Ban | Jails sshd + apache + laravel-scan aktiv | `fail2ban-client status` |
| Valkey | Nur Unix-Socket, kein Port 6379, mit Auth | `ss -tlnp \| grep 6379` (leer), `valkey-cli -s ... PING` |
| Laravel Cache/Sitzung | `redis`-Treiber zeigt auf den Socket | `php artisan about`, `tinker` mit `Cache::store('redis')` |
| Turnstile | Serverseitige Verifizierung auf ALLEN Registrierungsrouten | `COUNT(*) users WHERE created_at >= CURDATE()` stabil |
| OPcache | Speicher/Dateien für Multi-App dimensioniert | `php -i \| grep opcache.max_accelerated_files` |
| MySQL Slow Log | Aktiv für Diagnose | `SHOW VARIABLES LIKE 'slow_query_log'` |
| security.txt | Vorhanden | `/.well-known/security.txt` besuchen |
| SSL-Erneuerung | Timer aktiv | `systemctl list-timers \| grep certbot` |
| Updates | dnf-automatic aktiv | `systemctl status dnf-automatic.timer` |

---

## 25. Anhang: DNSSEC, GeoIP und PGP

**DNSSEC / „Lame Delegation"-Fehler (RRSIG).** Dieser Fehler **wird nicht auf dem Server behoben**, sondern im Panel Ihres Domain-Registrars. Meist bedeutet es, dass Sie DNSSEC aktiviert haben, aber die **DS**-Einträge (Delegation Signer) nicht mit den Schlüsseln Ihrer Nameserver übereinstimmen. Maßnahme: Überprüfen Sie im Domain-Panel, ob DNSSEC korrekt bei Ihrem DNS-Anbieter konfiguriert ist; wenn Sie es nicht strikt verwenden werden, deaktivieren Sie es, um den Fehler zu beseitigen.

**GeoIP (optional).** Wenn ein Portal ausschließlich in einem Land genutzt wird, können Sie auf Firewall/Apache-Ebene (mod_maxminddb) nach Land blockieren, um den Scan-Traffic aus ausländischen Rechenzentren drastisch zu reduzieren. Implementierung mit höherem Aufwand; bewerten Sie, ob der Anwendungsfall es rechtfertigt.

**PGP-Signatur der security.txt (optional).** Das Signieren von `security.txt` mit einem PGP-Schlüssel verhindert, dass bei einer Dateiänderung Schwachstellen-Meldungen an einen Betrüger gehen. Für ein MVP oder ein internes Portal **ist es nicht dringend**; für Behörden- oder Finanzportale **wird es empfohlen**. Bei der Implementierung: Generieren Sie das Paar mit `gpg`, veröffentlichen Sie den öffentlichen Schlüssel und fügen Sie `Encryption: https://ihre-domain.com/pgp-key.asc` zur Datei hinzu.

---
