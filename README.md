# Guía de Instalación y Hardening de un Servidor AlmaLinux 10

**Objetivo:** Levantar desde cero un servidor de producción **muy seguro** sobre **AlmaLinux 10**, capaz de hospedar tanto aplicaciones **Laravel (PHP 8.5 / Filament)** como aplicaciones **Node.js (LTS 24)**, detrás de Apache, con SSL de Let's Encrypt, SELinux en modo *Enforcing* y defensa activa con Fail2Ban.

**Pila tecnológica:** AlmaLinux 10 · Apache 2.4 · PHP 8.5 (php-fpm vía Remi) · MySQL 8 · Node.js 24 LTS · Let's Encrypt · firewalld · SELinux · Fail2Ban

> **Cómo usar este documento.** Está pensado como *runbook* (paso a paso reproducible) y como referencia de auditoría. Sustituye los marcadores `tu-dominio.com`, `miapp`, `tu.ip.publica.aqui` y los nombres de usuario/BD por los reales. Ejecuta los comandos como `root` o anteponiendo `sudo`.

---

## Índice

1. [Convenciones y arquitectura](#1-convenciones-y-arquitectura)
2. [Preparación del sistema base](#2-preparación-del-sistema-base)
3. [Usuario administrativo y acceso SSH por llaves](#3-usuario-administrativo-y-acceso-ssh-por-llaves)
4. [SSH seguro (puerto 4428 + endurecimiento)](#4-ssh-seguro-puerto-4428--endurecimiento)
5. [Firewall (firewalld)](#5-firewall-firewalld)
6. [Fundamentos de SELinux que debes entender](#6-fundamentos-de-selinux-que-debes-entender)
7. [Apache (servidor web / reverse proxy)](#7-apache-servidor-web--reverse-proxy)
8. [PHP 8.5 + PHP-FPM (para Laravel)](#8-php-85--php-fpm-para-laravel)
9. [MySQL 8 con privilegios mínimos](#9-mysql-8-con-privilegios-mínimos)
10. [Composer](#10-composer)
11. [Despliegue de un proyecto Laravel](#11-despliegue-de-un-proyecto-laravel)
12. [Node.js 24 LTS como servicio + reverse proxy](#12-nodejs-24-lts-como-servicio--reverse-proxy)
13. [Let's Encrypt (SSL) y renovación automática](#13-lets-encrypt-ssl-y-renovación-automática)
14. [Cabeceras de seguridad HTTP](#14-cabeceras-de-seguridad-http)
15. [Ocultar versiones (information leakage)](#15-ocultar-versiones-information-leakage)
16. [Bloqueo de bots por User-Agent](#16-bloqueo-de-bots-por-user-agent)
17. [Fail2Ban: defensa activa](#17-fail2ban-defensa-activa)
18. [security.txt y robots.txt](#18-securitytxt-y-robotstxt)
19. [Flujo de despliegue con Git](#19-flujo-de-despliegue-con-git)
20. [Actualizaciones automáticas y mantenimiento](#20-actualizaciones-automáticas-y-mantenimiento)
21. [Checklist final de verificación](#21-checklist-final-de-verificación)
22. [Apéndice: DNSSEC, GeoIP y PGP](#22-apéndice-dnssec-geoip-y-pgp)

---

## 1. Convenciones y arquitectura

**Estructura de directorios recomendada.** Todo vive bajo `/var/www`, que es el contexto que SELinux ya conoce de fábrica para Apache:

```
/var/www/
├── miapp-laravel/          # proyecto Laravel
│   ├── public/             # <- DocumentRoot de Apache (única carpeta expuesta)
│   ├── storage/            # escritura (httpd_sys_rw_content_t)
│   ├── bootstrap/cache/    # escritura (httpd_sys_rw_content_t)
│   └── .env                # NUNCA dentro de public/
└── miapp-node/             # proyecto Node
    ├── dist/ o build/
    └── .env
```

**Principio rector (regla de oro de SELinux en AlmaLinux 10):** ante cualquier cosa nueva, recuerda los tres pilares —
- **Puerto** → `semanage port`
- **Archivo/carpeta** → `restorecon` / `semanage fcontext`
- **Permiso de acción** → `setsebool`

**Arquitectura de red:**
- Apache escucha en `80` y `443` (únicos puertos web abiertos al exterior).
- PHP-FPM corre por socket Unix local (no expuesto).
- MySQL escucha **solo** en `127.0.0.1:3306` (nunca expuesto).
- Cada app Node corre en un puerto *loopback* (ej. `127.0.0.1:3000`) y Apache hace de **reverse proxy** con TLS. El puerto de Node **no se abre** en el firewall.

---

## 2. Preparación del sistema base

```bash
# Asegurar conectividad de red si hace falta
nmtui

# Actualizar todo el sistema
dnf update -y

# Repositorios base y utilidades
dnf install -y epel-release dnf-utils
dnf install -y vim git wget curl tar policycoreutils-python-utils setroubleshoot-server

# Zona horaria (ajusta a tu región)
timedatectl set-timezone America/Monterrey

# Sincronización de hora
systemctl enable --now chronyd
```

> `policycoreutils-python-utils` aporta `semanage`; `setroubleshoot-server` aporta `sealert`, el traductor de errores de SELinux. Son imprescindibles para administrar SELinux sin desactivarlo.

**No uses `net-tools` (obsoleto).** AlmaLinux 10 ya incluye `iproute2`: usa `ss -tulpn` en lugar de `netstat`.

**Confirma que SELinux está activo en modo Enforcing** (no lo desactives nunca):

```bash
getenforce        # debe responder: Enforcing
sestatus
```

---

## 3. Usuario administrativo y acceso SSH por llaves

Trabajar como `root` por SSH es la primera puerta que atacan los bots. Crea un usuario con `sudo` y entra siempre con él.

**En el servidor:**

```bash
adduser dante
passwd dante                 # contraseña fuerte
usermod -aG wheel dante      # 'wheel' = grupo sudo en AlmaLinux
```

**En tu máquina local** (genera el par de llaves si no lo tienes):

```bash
ssh-keygen -t ed25519 -C "dante@laptop"
# Copia la llave pública al servidor (todavía en el puerto 22 por ahora)
ssh-copy-id dante@tu.ip.publica.aqui
```

Verifica que puedes entrar **sin contraseña** con la llave antes de continuar. Si no funciona la llave, **no** deshabilites la contraseña en el paso siguiente o te quedarás fuera.

---

## 4. SSH seguro (puerto 4428 + endurecimiento)

En AlmaLinux 10 la configuración moderna de SSH se hace con archivos *drop-in* dentro de `/etc/ssh/sshd_config.d/` (más limpio y a prueba de actualizaciones que editar el archivo principal).

```bash
cat > /etc/ssh/sshd_config.d/99-hardening.conf <<'EOF'
# Puerto no estándar (reduce ruido de escaneos automatizados)
Port 4428

# Solo IPv4/IPv6 según tu caso
# AddressFamily inet

# Endurecimiento
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

> **Importante:** cambiar el puerto en SSH no basta; SELinux bloqueará el puerto nuevo aunque el firewall lo permita. Hay que etiquetarlo.

```bash
# Informar a SELinux del nuevo puerto SSH
semanage port -a -t ssh_port_t -p tcp 4428

# Validar la sintaxis y reiniciar
sshd -t && systemctl restart sshd
```

Abre una **segunda** sesión SSH en el puerto 4428 **antes** de cerrar la actual, para confirmar que entras:

```bash
ssh -p 4428 dante@tu.ip.publica.aqui
```

---

## 5. Firewall (firewalld)

No desactives `firewalld`: en AlmaLinux 10 se integra perfectamente con SELinux y con Fail2Ban.

```bash
systemctl enable --now firewalld

# Quitar el servicio SSH estándar (puerto 22) y abrir el 4428
firewall-cmd --permanent --remove-service=ssh
firewall-cmd --permanent --add-port=4428/tcp

# Abrir web
firewall-cmd --permanent --add-service=http
firewall-cmd --permanent --add-service=https

# Aplicar
firewall-cmd --reload

# Verificar
firewall-cmd --list-all
```

El resultado esperado: solo `4428/tcp`, `http` y `https` abiertos. Los puertos `22`, `3306` (MySQL) y los puertos internos de Node **no** deben aparecer. Un escáner externo debe verlos como cerrados/filtrados.

---

## 6. Fundamentos de SELinux que debes entender

SELinux no bloquea servicios "por capricho": se asegura de que cada proceso solo toque lo que tiene permitido (política *deny by default*).

**Lo que NO requiere configuración:**
- Servir contenido en `/var/www` por los puertos 80/443. Los archivos creados ahí heredan la etiqueta `httpd_sys_content_t` automáticamente.

**El "pero" más común:** si **mueves** archivos desde `/home/usuario` a `/var/www` con `mv`, conservan la etiqueta de origen y Apache dará **403 Forbidden**. Solución universal:

```bash
restorecon -Rv /var/www/miapp
```

**Permisos de acción (booleanos) que sí necesitarás:**

| Escenario | Comando |
|---|---|
| Laravel se conecta a MySQL local | `setsebool -P httpd_can_network_connect_db on` |
| Apache hace reverse proxy a una app Node | `setsebool -P httpd_can_network_connect on` |
| Apache lee carpetas fuera de lo estándar | `setsebool -P httpd_enable_homedirs on` |

**Carpetas donde Apache/Laravel necesitan escribir:**

```bash
semanage fcontext -a -t httpd_sys_rw_content_t "/var/www/miapp/storage(/.*)?"
semanage fcontext -a -t httpd_sys_rw_content_t "/var/www/miapp/bootstrap/cache(/.*)?"
restorecon -Rv /var/www/miapp
```

> El flag `-P` en `setsebool` es **crucial**: hace que el cambio persista tras reiniciar.

**Herramientas de diagnóstico (en vez de apagar SELinux):**

```bash
# Denegaciones en tiempo real
tail -f /var/log/audit/audit.log | grep denied

# Traductor humano de errores
sealert -a /var/log/audit/audit.log
```

---

## 7. Apache (servidor web / reverse proxy)

```bash
dnf install -y httpd mod_ssl
systemctl enable --now httpd
```

Asegúrate de que estén cargados los módulos de proxy (los necesitarás para Node) y rewrite (para el bloqueo de bots):

```bash
# En AlmaLinux 10 suelen venir activos; verifícalo:
httpd -M | grep -E "proxy_module|proxy_http|proxy_wstunnel|rewrite|headers|ssl"
```

Si falta alguno, los módulos viven en `/etc/httpd/conf.modules.d/`. Normalmente `proxy`, `proxy_http`, `rewrite`, `headers` y `ssl` ya están habilitados; `proxy_wstunnel` puede requerir agregarse para WebSockets.

---

## 8. PHP 8.5 + PHP-FPM (para Laravel)

PHP 8.5 ya está disponible como módulo estable de Remi para Enterprise Linux 10.

```bash
# Repositorio Remi para AlmaLinux 10
dnf install -y https://rpms.remirepo.net/enterprise/remi-release-10.rpm

# Seleccionar el flujo de módulo PHP 8.5
dnf module reset php -y
dnf module enable php:remi-8.5 -y

# Instalar PHP-FPM y extensiones típicas de Laravel/Filament
dnf install -y php php-cli php-common php-fpm \
  php-mysqlnd php-pdo php-mbstring php-xml php-curl \
  php-gd php-zip php-bcmath php-intl php-opcache php-redis

systemctl enable --now php-fpm
php -v   # confirmar 8.5.x
```

**Pool de PHP-FPM bajo el usuario de Apache.** Edita `/etc/php-fpm.d/www.conf` y asegúrate de:

```ini
user = apache
group = apache
listen = /run/php-fpm/www.sock
listen.owner = apache
listen.group = apache
listen.mode = 0660
```

El paquete instala `/etc/httpd/conf.d/php.conf`, que enruta los `.php` al socket de PHP-FPM mediante `SetHandler "proxy:unix:/run/php-fpm/www.sock|fcgi://localhost"`. No necesitas configurarlo manualmente salvo casos especiales.

```bash
systemctl restart php-fpm httpd
```

---

## 9. MySQL 8 con privilegios mínimos

```bash
dnf install -y mysql-server
systemctl enable --now mysqld

# Asegurar instalación (define root, elimina anónimos, etc.)
mysql_secure_installation
```

**Vincula MySQL solo a localhost** (que no escuche en la red). En `/etc/my.cnf.d/mysql-server.cnf`, dentro de `[mysqld]`:

```ini
bind-address = 127.0.0.1
```

```bash
systemctl restart mysqld
```

**Crea la base de datos y un usuario con privilegios mínimos** (NO uses `*.*` ni `WITH GRANT OPTION` para apps; eso es el patrón peligroso de la guía vieja):

```sql
CREATE DATABASE miapp CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE USER 'miapp'@'localhost' IDENTIFIED BY 'UnaPasswordLargaYAleatoria_2026!';

-- Solo privilegios sobre SU base de datos, nada más
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, INDEX, DROP, REFERENCES
  ON miapp.* TO 'miapp'@'localhost';

FLUSH PRIVILEGES;
```

> MySQL 8 usa `caching_sha2_password` por defecto, que es lo recomendado. Solo recurre a `mysql_native_password` si una librería antigua lo exige.

Si Laravel devuelve errores 500 al conectar a la BD, casi siempre es el booleano de SELinux:

```bash
setsebool -P httpd_can_network_connect_db on
```

---

## 10. Composer

Laravel moderno requiere Composer 2.x (no la 1.9 de la guía vieja):

```bash
php -r "copy('https://getcomposer.org/installer', 'composer-setup.php');"
php composer-setup.php --install-dir=/usr/local/bin --filename=composer
rm composer-setup.php
composer --version
```

---

## 11. Despliegue de un proyecto Laravel

```bash
mkdir -p /var/www/miapp
chown -R apache:apache /var/www/miapp

# Clona o sube tu proyecto a /var/www/miapp (ver sección 19 para Git)
cd /var/www/miapp
composer install --no-dev --optimize-autoloader

# Permisos de escritura para Laravel (Linux + SELinux)
chown -R apache:apache storage bootstrap/cache
semanage fcontext -a -t httpd_sys_rw_content_t "/var/www/miapp/storage(/.*)?"
semanage fcontext -a -t httpd_sys_rw_content_t "/var/www/miapp/bootstrap/cache(/.*)?"
restorecon -Rv /var/www/miapp

# Optimización de Laravel
php artisan config:cache
php artisan route:cache
php artisan view:cache
```

**VirtualHost de Laravel** en `/etc/httpd/conf.d/miapp.conf` (HTTP que redirige a HTTPS; el bloque 443 lo completará Certbot, ver sección 13 y 14):

```apache
<VirtualHost *:80>
    ServerName tu-dominio.com
    DocumentRoot /var/www/miapp/public
    Redirect permanent / https://tu-dominio.com/
</VirtualHost>
```

> El `DocumentRoot` apunta a `public/`, así el `.env`, `vendor/` y el resto del código quedan fuera del alcance web.

**Cron de Laravel (Scheduler)** — debe correr con el usuario de Apache para no romper permisos:

```bash
# crontab -u apache -e
* * * * * cd /var/www/miapp && php artisan schedule:run >> /dev/null 2>&1
```

---

## 12. Node.js 24 LTS como servicio + reverse proxy

A mayo de 2026, **Node.js 24 es la versión LTS activa** recomendada para producción (Node 26 está en fase *Current*, aún no LTS).

### 12.1 Instalar Node 24

```bash
# Repositorio oficial NodeSource para la rama 24.x
curl -fsSL https://rpm.nodesource.com/setup_24.x | bash -
dnf install -y nodejs
node -v    # v24.x
npm -v
```

> Alternativa: `dnf module enable nodejs:24 && dnf install nodejs` desde AppStream, si prefieres no agregar repos externos (puede ir una o dos *minor* por detrás).

### 12.2 Usuario dedicado y código

No corras Node como `root`. Crea un usuario de sistema sin shell de login:

```bash
useradd --system --create-home --home-dir /var/www/miapp-node --shell /usr/sbin/nologin nodeapp
# Sube/clona tu app a /var/www/miapp-node y compila
cd /var/www/miapp-node
sudo -u nodeapp npm ci --omit=dev
sudo -u nodeapp npm run build   # si aplica
```

### 12.3 Servicio systemd (más limpio y seguro que PM2 como root)

Crea `/etc/systemd/system/miapp-node.service`:

```ini
[Unit]
Description=Mi App Node
After=network.target

[Service]
Type=simple
User=nodeapp
Group=nodeapp
WorkingDirectory=/var/www/miapp-node
# La app DEBE escuchar en loopback: host 127.0.0.1, puerto 3000
Environment=NODE_ENV=production
Environment=PORT=3000
Environment=HOST=127.0.0.1
ExecStart=/usr/bin/node dist/server.js
Restart=on-failure
RestartSec=5

# Endurecimiento del servicio
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable --now miapp-node
systemctl status miapp-node
ss -tlpn | grep 3000      # debe escuchar SOLO en 127.0.0.1:3000
```

> Asegúrate de que tu app lea `process.env.HOST` y `process.env.PORT` y **escuche en `127.0.0.1`**, no en `0.0.0.0`. Así el puerto 3000 nunca es accesible desde Internet, solo desde Apache.

### 12.4 Permitir el proxy en SELinux

Para que Apache pueda abrir una conexión de red hacia el puerto de Node:

```bash
setsebool -P httpd_can_network_connect on
```

### 12.5 VirtualHost reverse proxy

`/etc/httpd/conf.d/miapp-node.conf`:

```apache
<VirtualHost *:80>
    ServerName node.tu-dominio.com
    Redirect permanent / https://node.tu-dominio.com/
</VirtualHost>

<VirtualHost *:443>
    ServerName node.tu-dominio.com

    ProxyPreserveHost On
    ProxyPass        / http://127.0.0.1:3000/
    ProxyPassReverse / http://127.0.0.1:3000/

    # Soporte WebSocket (si tu app lo usa: Socket.io, etc.)
    RewriteEngine On
    RewriteCond %{HTTP:Upgrade} =websocket [NC]
    RewriteRule /(.*) ws://127.0.0.1:3000/$1 [P,L]

    # (Las cabeceras de seguridad de la sección 14 también aplican aquí)
    # (Certbot agregará las directivas SSL aquí)

    ErrorLog  /var/log/httpd/miapp-node-error.log
    CustomLog /var/log/httpd/miapp-node-access.log combined
</VirtualHost>
```

```bash
apachectl configtest && systemctl restart httpd
```

> **No abras el puerto 3000 en firewalld.** El tráfico entra por 443 (Apache, con TLS) y se reenvía internamente. Node queda aislado.

---

## 13. Let's Encrypt (SSL) y renovación automática

```bash
dnf install -y certbot python3-certbot-apache

# Un certificado por dominio/subdominio
certbot --apache -d tu-dominio.com
certbot --apache -d node.tu-dominio.com
```

Certbot inserta automáticamente las directivas `SSLCertificateFile`, `SSLCertificateKeyFile` e `Include /etc/letsencrypt/options-ssl-apache.conf` en tus VirtualHost de 443.

**Renovación automática.** El paquete instala un *timer* de systemd que renueva sin intervención. Verifícalo:

```bash
systemctl list-timers | grep certbot
certbot renew --dry-run     # prueba en seco que la renovación funciona
```

---

## 14. Cabeceras de seguridad HTTP

Estas cabeceras corrigen los hallazgos típicos de escáneres como web-check.xyz (HSTS, Clickjacking, MIME sniffing, XSS, CSP). Agrégalas dentro del bloque `<VirtualHost *:443>` de cada sitio.

```apache
# HSTS: obliga HTTPS por 2 años (elegible para preload list)
Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"

# Anti-clickjacking
Header always set X-Frame-Options "SAMEORIGIN"

# Evitar MIME sniffing
Header always set X-Content-Type-Options "nosniff"

# Política de referencia
Header always set Referrer-Policy "strict-origin-when-cross-origin"

# Permissions-Policy (limita APIs del navegador)
Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"

# Content-Security-Policy: la más potente contra XSS.
# Ajusta los dominios externos que realmente uses (fuentes, mapas, analytics).
Header always set Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://fonts.googleapis.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self';"

# Eliminar fugas de versión
ServerSignature Off
Header unset X-Powered-By
```

> **Nota sobre `X-XSS-Protection`:** esa cabecera está obsoleta y los navegadores modernos la ignoran (algunos recomiendan `0`). La protección real contra XSS hoy es una buena **CSP**. Si tu escáner aún la pide, puedes añadir `Header set X-XSS-Protection "1; mode=block"`, pero no es donde está la seguridad.

> **CSP es iterativa.** Empieza con la política de arriba; si algo deja de cargar (un script externo, un mapa, Google Analytics), agrega ese dominio a la directiva correspondiente. Para Filament suele bastar con `'self' 'unsafe-inline' 'unsafe-eval'`.

```bash
apachectl configtest && systemctl restart httpd
```

---

## 15. Ocultar versiones (information leakage)

Decirle al mundo "uso PHP 8.5.6 y Apache 2.4.63" es regalarle a los atacantes el mapa exacto de qué exploits probar.

**Apache** — crea `/etc/httpd/conf.d/00-security.conf`:

```apache
ServerTokens Prod
ServerSignature Off
TraceEnable Off
```

**PHP** — en `/etc/php.ini`:

```ini
expose_php = Off
```

```bash
systemctl restart php-fpm httpd
```

Tras esto, la cabecera `Server` dirá solo `Apache` (sin versión) y desaparecerá `X-Powered-By: PHP/...`.

---

## 16. Bloqueo de bots por User-Agent

Los logs reales muestran bots como `l9explore` y `l9tcpid` rastreando `.env`, `.git/config` y credenciales de AWS. Bloquéalos en Apache (dentro del `<Directory>` del sitio, para cortar antes de que Laravel procese nada):

```apache
<Directory /var/www/miapp/public>
    RewriteEngine On

    RewriteCond %{HTTP_USER_AGENT} ^l9explore   [NC,OR]
    RewriteCond %{HTTP_USER_AGENT} ^l9tcpid      [NC,OR]
    RewriteCond %{HTTP_USER_AGENT} ^Nmap         [NC,OR]
    RewriteCond %{HTTP_USER_AGENT} ^Masscan      [NC,OR]
    RewriteCond %{HTTP_USER_AGENT} ^zgrab        [NC,OR]
    RewriteCond %{HTTP_USER_AGENT} ^Nikto        [NC,OR]
    RewriteCond %{HTTP_USER_AGENT} ^User-Agent   [NC,OR]
    RewriteCond %{HTTP_USER_AGENT} (libwww|Wget|LWP|Python|urllib|scan) [NC]
    RewriteRule ^ - [F,L]

    Options -Indexes +FollowSymLinks
    AllowOverride All
    Require all granted
</Directory>
```

A partir de aquí, esos bots reciben **403 Forbidden** en lugar de un 404. Eso es bueno: en la sección siguiente haremos que Fail2Ban banee a cualquiera que acumule 403.

```bash
apachectl configtest && systemctl restart httpd
```

---

## 17. Fail2Ban: defensa activa

El firewall es un muro pasivo; Fail2Ban es un guardia que lee los logs y banea IPs reincidentes a nivel de red.

```bash
dnf install -y fail2ban fail2ban-firewalld
```

**Configuración principal** — nunca edites `jail.conf`; crea `/etc/fail2ban/jail.local`:

```ini
[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 5
# Banea usando firewalld (integración nativa de AlmaLinux 10)
banaction = firewallcmd-rich-rules
# IMPORTANTE: agrega TU IP fija para no auto-bloquearte
ignoreip = 127.0.0.1/8 ::1 tu.ip.publica.aqui

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

**Filtro personalizado** para cazar el escaneo de `.env`/`.git` y los 403 del bloqueo de User-Agent. Crea `/etc/fail2ban/filter.d/laravel-vulnerabilities.conf`:

```ini
[Definition]
# Captura 404 (búsqueda de archivos sensibles) y 403 (bloqueos por User-Agent)
failregex = ^<HOST> -.*"GET .*\.(env|git|aws|yml|yaml|json).* HTTP/.*" (404|403)
            ^<HOST> -.*"GET .*(\.git|config|credentials).* HTTP/.*" (404|403)
            ^<HOST> -.*"(GET|POST) .* HTTP/.*" 403
ignoreregex =
```

**Cárcel** que usa ese filtro sobre tu log de acceso (ajusta la ruta a tu `CustomLog`). Añádela al final de `jail.local`:

```ini
[laravel-scan]
enabled  = true
port     = http,https
filter   = laravel-vulnerabilities
logpath  = /var/log/httpd/miapp-access.log
maxretry = 2
bantime  = 48h
findtime = 1h
```

**Activar y verificar:**

```bash
systemctl enable --now fail2ban
fail2ban-client status
fail2ban-client status laravel-scan

# Probar el filtro contra tu log actual (cuenta "Hits")
fail2ban-regex /var/log/httpd/miapp-access.log /etc/fail2ban/filter.d/laravel-vulnerabilities.conf
```

**SELinux y el log personalizado.** Si Fail2Ban no lee tu log con nombre propio, revisa su contexto:

```bash
ls -Z /var/log/httpd/miapp-access.log   # debería ser httpd_log_t
restorecon -v /var/log/httpd/miapp-access.log
```

> Si necesitas desbanearte: `fail2ban-client set laravel-scan unbanip 1.2.3.4`.

Con esto tienes **defensa en capas**: Apache identifica al bot y le cierra la puerta (403) → el intento queda en el log → Fail2Ban detecta la IP reincidente y la bloquea en firewalld.

---

## 18. security.txt y robots.txt

**security.txt** (estándar para que investigadores reporten vulnerabilidades de forma responsable):

```bash
mkdir -p /var/www/miapp/public/.well-known
cat > /var/www/miapp/public/.well-known/security.txt <<'EOF'
Contact: mailto:seguridad@tu-dominio.com
Expires: 2027-01-01T00:00:00.000Z
Preferred-Languages: es, en
EOF
restorecon -Rv /var/www/miapp/public/.well-known
```

**robots.txt** — para desalentar el indexado del panel admin (es solo una *sugerencia* para buscadores legítimos; la seguridad real del `/admin` es el login de Laravel/Filament):

```
User-agent: *
Disallow: /admin/
Disallow: /admin
Allow: /
```

---

## 19. Flujo de despliegue con Git

**Error clásico:** `fatal: detected dubious ownership in repository`. Ocurre porque la carpeta es de `apache` pero tú ejecutas Git como otro usuario.

```bash
git config --global --add safe.directory /var/www/miapp
```

**El problema real:** tras `git pull`, los archivos nuevos pierden el dueño `apache` y/o el contexto de SELinux, y Apache devuelve 403/500. El flujo correcto en producción:

```bash
git pull origin main
chown -R apache:apache /var/www/miapp
restorecon -Rv /var/www/miapp        # recupera etiquetas SELinux
php /var/www/miapp/artisan optimize
```

**Automatízalo con un script de deploy** (`/usr/local/bin/deploy-miapp`):

```bash
#!/usr/bin/env bash
set -euo pipefail
cd /var/www/miapp
git pull origin main
composer install --no-dev --optimize-autoloader
php artisan migrate --force
php artisan config:cache && php artisan route:cache && php artisan view:cache
chown -R apache:apache /var/www/miapp
restorecon -Rv /var/www/miapp
echo "Deploy OK"
```

```bash
chmod +x /usr/local/bin/deploy-miapp
```

> **Por qué `restorecon` es vital:** Git asigna a los archivos nuevos una etiqueta temporal; sin `restorecon`, SELinux puede bloquear su lectura con un 403 aunque `chmod`/`chown` estén perfectos.

Para Node, el equivalente reinicia el servicio: `... && systemctl restart miapp-node`.

---

## 20. Actualizaciones automáticas y mantenimiento

**Parches de seguridad automáticos:**

```bash
dnf install -y dnf-automatic
# En /etc/dnf/automatic.conf -> apply_updates = yes (o solo notificar)
systemctl enable --now dnf-automatic.timer
```

**Rutina manual recomendada:**

```bash
dnf update --security        # parches de seguridad
certbot renew --dry-run      # confirmar renovación SSL
fail2ban-client status       # revisar baneos
```

**Backups (mínimo viable):** programa un volcado diario de MySQL y un respaldo de `/var/www` y `/etc/httpd`:

```bash
mysqldump --single-transaction --routines miapp | gzip > /backups/miapp-$(date +\%F).sql.gz
```

---

## 21. Checklist final de verificación

| Área | Estado deseado | Cómo verificar |
|---|---|---|
| SELinux | Enforcing (nunca permissive/disabled) | `getenforce` |
| SSH | Puerto 4428, sin root, solo llaves | `ssh -p 4428`, revisar `sshd_config.d/` |
| Firewall | Solo 4428, http, https | `firewall-cmd --list-all` |
| Puertos cerrados | 22, 3306, 3000 NO accesibles externamente | escáner externo / `ss -tlpn` |
| MySQL | Bind 127.0.0.1, usuario con privilegios mínimos | `ss -tlpn \| grep 3306` |
| PHP | 8.5.x, `expose_php = Off` | `php -v`, cabeceras HTTP |
| Node | Escucha en 127.0.0.1, corre como `nodeapp` | `ss -tlpn \| grep 3000` |
| SSL | Certificado válido, redirección 80→443 | `certbot certificates` |
| Cabeceras | HSTS, CSP, X-Frame, X-Content-Type, Referrer | escáner web / `curl -I` |
| Fugas de versión | Sin versión en `Server` ni `X-Powered-By` | `curl -I https://tu-dominio.com` |
| Fail2Ban | Jails sshd + apache + laravel-scan activos | `fail2ban-client status` |
| security.txt | Presente | visitar `/.well-known/security.txt` |
| Renovación SSL | Timer activo | `systemctl list-timers \| grep certbot` |
| Actualizaciones | dnf-automatic activo | `systemctl status dnf-automatic.timer` |

---

## 22. Apéndice: DNSSEC, GeoIP y PGP

**DNSSEC / error "lame delegation" (RRSIG).** Este error **no se arregla en el servidor**, sino en el panel de tu registrador de dominio. Suele significar que activaste DNSSEC pero los registros **DS** (Delegation Signer) no coinciden con las llaves de tus servidores de nombres. Acción: en el panel del dominio, verifica que DNSSEC esté correctamente configurado contra tu proveedor DNS; si no lo usarás estrictamente, desactívalo para eliminar el error.

**GeoIP (opcional).** Si un portal es de uso exclusivo en México, puedes bloquear por país a nivel de firewall/Apache (mod_maxminddb) para reducir drásticamente el tráfico de escaneo proveniente de data centers extranjeros. Implementación de mayor esfuerzo; evalúa si el caso lo amerita.

**Firma PGP del security.txt (opcional).** Firmar `security.txt` con una llave PGP evita que, si alguien alterara el archivo, los reportes de vulnerabilidad lleguen a un impostor. Para un MVP o portal interno **no es urgente**; para portales gubernamentales o financieros **sí** se recomienda. Si lo implementas: genera el par con `gpg`, publica la llave pública y añade `Encryption: https://tu-dominio.com/pgp-key.asc` al archivo.

---


