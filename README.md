# Guía de Instalación y Hardening de un Servidor AlmaLinux 10

**Objetivo:** Levantar desde cero un servidor de producción **muy seguro** sobre **AlmaLinux 10**, capaz de hospedar tanto aplicaciones **Laravel (PHP 8.5 / Filament)** como aplicaciones **Node.js (LTS 24)**, detrás de Apache, con SSL de Let's Encrypt, SELinux en modo *Enforcing* y defensa activa con Fail2Ban.

**Pila tecnológica:** AlmaLinux 10 · Apache 2.4 (MPM event + HTTP/2) · PHP 8.5 (php-fpm vía Remi) · MySQL 8.4 · Valkey 8 · Node.js 24 LTS · Let's Encrypt · firewalld · SELinux · Fail2Ban · Cloudflare Turnstile

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
16. [Bloqueo de bots por User-Agent y rutas de exploit](#16-bloqueo-de-bots-por-user-agent-y-rutas-de-exploit)
17. [Fail2Ban: defensa activa](#17-fail2ban-defensa-activa)
18. [security.txt y robots.txt](#18-securitytxt-y-robotstxt)
19. [Flujo de despliegue con Git](#19-flujo-de-despliegue-con-git)
20. [Actualizaciones automáticas y mantenimiento](#20-actualizaciones-automáticas-y-mantenimiento)
21. [Valkey (caché, sesiones y colas)](#21-valkey-caché-sesiones-y-colas)
22. [Protección de formularios públicos (Turnstile + rate limiting)](#22-protección-de-formularios-públicos-turnstile--rate-limiting)
23. [Optimización de rendimiento](#23-optimización-de-rendimiento)
24. [Checklist final de verificación](#24-checklist-final-de-verificación)
25. [Apéndice: DNSSEC, GeoIP y PGP](#25-apéndice-dnssec-geoip-y-pgp)

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

## 16. Bloqueo de bots por User-Agent y rutas de exploit

Los logs reales muestran dos tipos de ruido automatizado: escáneres que se identifican con User-Agents conocidos (`l9scan`, `zgrab`, `Nikto`, `CensysInspect`) y bots que piden rutas que no existen en la app (`/.env`, `/.git/config`, `/vendor/phpunit/.../eval-stdin.php`, `/wp-config.php`). Conviene cortar ambos **a nivel del VirtualHost**, antes de que la petición llegue a PHP.

> **Lección aprendida — no ancles el User-Agent con `^`.** Una versión anterior usaba `RewriteCond %{HTTP_USER_AGENT} ^Nmap`, que solo coincide si el UA *empieza* exactamente con esa cadena. Bots como `l9scan` se anuncian como `Mozilla/5.0 (l9scan/2.0...)`, así que el ancla los dejaba pasar. La regla correcta busca la cadena en **cualquier parte** del User-Agent.

Coloca el bloqueo directamente bajo el `<VirtualHost *:443>`, no dentro del `<Directory>`. El contexto de servidor se evalúa antes y de forma independiente del `.htaccess` de Laravel, así que el bloqueo aplica a toda petición sin depender de qué procese Laravel después. Requiere `RewriteEngine On` explícito en este contexto:

```apache
RewriteEngine On

# 1) Bloqueo por User-Agent — SIN ancla ^, para cazarlos en cualquier
#    parte de la cadena (ej. "Mozilla/5.0 (l9scan/...)" ya no se cuela)
RewriteCond %{HTTP_USER_AGENT} (l9explore|l9scan|l9tcpid|Nmap|Masscan|zgrab|Nikto|CensysInspect|leakix|libredtail|Gh0st) [NC]
RewriteRule ^ - [F,L]

# 2) User-Agent vacío en peticiones que no sean a la raíz (bots crudos)
RewriteCond %{HTTP_USER_AGENT} ^-?$
RewriteCond %{REQUEST_URI} !^/$
RewriteRule ^ - [F,L]

# 3) Bloqueo de archivos ocultos (.env, .git, etc.)
#    EXCEPTO /.well-known (necesario para la renovación de Let's Encrypt)
RewriteRule "(^|/)\.(?!well-known)" - [F,L]

# 4) Rutas de exploit conocidas (PHPUnit eval-stdin, vendor, basura .php)
RewriteCond %{REQUEST_URI} (eval-stdin\.php|/vendor/|/phpunit|/wp-|xmlrpc\.php|/phpinfo|/\.aws|/\.ssh) [NC]
RewriteRule ^ - [F,L]
```

> **El `/.well-known` es crítico.** Si bloquearas todos los dotfiles sin excepción, romperías el reto ACME de Certbot (`/.well-known/acme-challenge/`) y tu certificado dejaría de renovarse. El `(?!well-known)` lo protege.

> **No bloquees `curl` por User-Agent.** Aunque aparezca en escaneos, es la herramienta con la que tú mismo haces pruebas y health checks. Ese comportamiento es mejor dejárselo a Fail2Ban (banea por conducta, no por nombre), ver sección 17.

A partir de aquí, esos bots reciben **403 Forbidden** en lugar de un 404. Eso es bueno: Fail2Ban (siguiente sección) banea a cualquiera que acumule 403.

```bash
apachectl configtest && systemctl restart httpd
```

**Resultado medible.** En un caso real de este servidor, tras aplicar el bloqueo el log pasó a registrar cientos de `403` diarios contra escaneo de `/.env`, `/.git/config`, `/wp-config.php` y `/.aws/credentials` que antes pasaban como `404` inofensivos pero llegaban hasta PHP. Una sola IP de escaneo agresivo (`45.148.10.95`) acumuló 220 bloqueos en un día sin tocar la aplicación.

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
# Captura 404 (búsqueda de archivos sensibles) y 403 (bloqueos por User-Agent / dotfiles)
failregex = ^<HOST> -.*"GET .*\.(env|git|aws|yml|yaml|json).* HTTP/.*" (404|403)
            ^<HOST> -.*"GET .*(\.git|config|credentials).* HTTP/.*" (404|403)
            ^<HOST> -.*"(GET|POST) .* HTTP/.*" 403
ignoreregex =
```

> **Sobre el abuso de formularios públicos (registro, contacto).** Las IPs que martillan `POST /registro` rotan direcciones y usan User-Agents de navegador real, así que un filtro por 403 no las atrapa: a nivel HTTP son indistinguibles de un humano. La defensa correcta para eso **no es Fail2Ban** sino Cloudflare Turnstile + rate limiting + verificación de email (ver sección 22). Si aun así quieres que Fail2Ban reaccione a los más insistentes, puedes añadir un filtro que cuente los `429` (rate-limit de Laravel) por IP, pero es defensa secundaria, no la principal.

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

## 21. Valkey (caché, sesiones y colas)

Para que Laravel/Filament rindan en producción, mueve la caché, las sesiones y las colas de la base de datos a un almacén en memoria. **AlmaLinux 10 ya no incluye Redis** (Redis Labs cambió a licencias no-FOSS en la versión 7.4 y la distro lo retiró de sus repos); el reemplazo oficial en el AppStream es **Valkey**, un fork con licencia FOSS. Es *drop-in*: phpredis y el driver `redis` de Laravel hablan con Valkey sin cambiar nada en el código de la aplicación.

> **Por qué Valkey y no Redis vía Remi.** Redis volvió a una licencia open source (AGPLv3) en la 8.0 y hay RPMs en `remi-modular`, pero eso ataría las actualizaciones de seguridad de un *datastore* (que guardará sesiones) a un repo de terceros. Valkey desde el AppStream oficial recibe parches por el ciclo normal de la distro, con menos superficie de mantenimiento. Salvo que necesites una función muy nueva de Redis 8.x, Valkey es la opción recomendada.

### 21.1 Instalación

```bash
dnf install -y valkey
valkey-server --version
```

### 21.2 Configuración segura

El modelo de amenaza clásico de Redis/Valkey es "instancia expuesta a internet sin contraseña". Como aquí Valkey vive en el **mismo servidor** que Laravel, lo más seguro es **no exponerlo a la red en absoluto**: socket Unix + sin puerto TCP. Genera primero una contraseña fuerte:

```bash
openssl rand -base64 48
```

Edita `/etc/valkey/valkey.conf` (muchas directivas ya existen comentadas; búscalas y ajústalas):

```conf
# --- RED: no exponer a ninguna interfaz ---
bind 127.0.0.1 -::1
protected-mode yes
port 0                              # desactiva TCP por completo; solo socket Unix

# --- SOCKET UNIX: así se conecta Laravel ---
unixsocket /run/valkey/valkey.sock
unixsocketperm 770

# --- AUTENTICACIÓN ---
requirepass "PEGA_AQUI_LA_PASSWORD_GENERADA"

# --- MEMORIA Y POLÍTICA ---
maxmemory 2gb                       # ajústalo a cuánto le destines
maxmemory-policy allkeys-lru        # cuidado con el typo: es allkeys-lru (con 'a')

# --- PERSISTENCIA (para no perder sesiones/colas al reiniciar) ---
appendonly yes
appendfsync everysec

# --- COMANDOS PELIGROSOS ---
rename-command FLUSHALL ""
rename-command FLUSHDB ""
rename-command KEYS ""                  # KEYS bloquea el servidor en prod; Laravel no lo usa
rename-command CONFIG "CONFIG_a8f3k2"   # renómbralo a algo impredecible en vez de borrarlo
```

> **Un typo aborta el arranque.** Si Valkey no levanta, revisa `systemctl status valkey`: el mensaje `FATAL CONFIG FILE ERROR` indica el número de línea exacto del error. Un valor mal escrito (ej. `llkeys-lru` en vez de `allkeys-lru`) impide el arranque, y como consecuencia el socket nunca se crea — de ahí un `No such file or directory` al intentar conectar, que es síntoma, no la causa.

### 21.3 Directorio del socket, permisos y SELinux

El directorio del socket en `/run` es efímero; créalo de forma persistente con tmpfiles para que sobreviva reinicios:

```bash
echo 'd /run/valkey 0750 valkey valkey -' > /etc/tmpfiles.d/valkey.conf
systemd-tmpfiles --create
```

Para que PHP-FPM (y Netdata, si lo usas) lean el socket, agrega esos usuarios al grupo `valkey` —misma lógica de pertenencia a grupos que con `apache`:

```bash
usermod -aG valkey apache
usermod -aG valkey dante         # si tus pools FPM corren como dante
usermod -aG valkey netdata       # si monitoreas con Netdata
```

SELinux: activa el booleano de conexión web y etiqueta el directorio del socket si hay denials:

```bash
setsebool -P httpd_can_network_connect 1
semanage fcontext -a -t redis_var_run_t "/run/valkey(/.*)?" 2>/dev/null || true
restorecon -Rv /run/valkey

# Si Valkey falla por SELinux, revisa denials y genera política puntual:
ausearch -m avc -ts recent | grep -iE "valkey|redis"
```

### 21.4 Hardening del servicio (systemd)

Refuerza el aislamiento con un drop-in en vez de editar el unit original:

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

### 21.5 Arranque y verificación

```bash
systemctl enable --now valkey
systemctl status valkey --no-pager

# Conexión por socket con auth
valkey-cli -s /run/valkey/valkey.sock
#   AUTH "tu_password"
#   PING            -> debe responder PONG
#   exit

# Confirma que NO hay puerto TCP escuchando (debe salir vacío)
ss -tlnp | grep 6379
```

### 21.6 Integración con Laravel

Confirma la extensión phpredis (compilada en C, más rápida que Predis; no necesitas `predis/predis` por Composer si usas esta):

```bash
php -m | grep -i redis
# si falta:
dnf install -y php-redis && systemctl reload php-fpm
```

En el `.env` de cada plataforma, apuntando al socket y **separando** lo evictable (caché, en una DB) de lo que no debe desaparecer (sesiones/colas, en otra). Con socket Unix, `REDIS_PORT` debe ser `0`:

```env
REDIS_CLIENT=phpredis
REDIS_HOST=/run/valkey/valkey.sock
REDIS_PORT=0
REDIS_PASSWORD="tu_password"

REDIS_DB=0          # sesiones y colas (no deben desalojarse)
REDIS_CACHE_DB=1    # caché (evictable con allkeys-lru)

CACHE_STORE=redis
SESSION_DRIVER=redis
QUEUE_CONNECTION=redis
```

> **El `prefix` importa con multi-plataforma.** Todas tus apps comparten el mismo Valkey. El default de Laravel deriva el prefijo de claves de `APP_NAME`, así que asegúrate de que cada plataforma tenga un `APP_NAME` distinto (o un `REDIS_PREFIX` explícito) o las claves de caché de una pisarán las de otra.

Como tienes la config cacheada, **los cambios al `.env` no surten efecto hasta regenerar el caché**:

```bash
php artisan config:clear && php artisan config:cache

php artisan tinker
>>> Cache::store('redis')->put('test', 'ok', 60); Cache::store('redis')->get('test');   # -> "ok"
```

> **Las variables siguen llamándose `REDIS_*` y el driver `redis`**: es solo el nombre del cliente. Por debajo está hablando con Valkey sin saberlo ni importarle.

**Inspección de claves.** Como desactivamos `KEYS`, usa `SCAN` (no bloquea el servidor). Desde la shell, `--scan` itera solo:

```bash
export REDISCLI_AUTH="tu_password"     # evita exponer la password en el historial
valkey-cli -s /run/valkey/valkey.sock -n 1 --scan                       # todas las de caché (DB 1)
valkey-cli -s /run/valkey/valkey.sock -n 1 --scan --pattern "miapp_*"   # filtra por prefijo de app
valkey-cli -s /run/valkey/valkey.sock INFO keyspace                     # conteo por DB de un vistazo
```

> **Orden seguro:** instala y verifica Valkey por completo (hasta que `PING` responda `PONG`) **antes** de cambiar los `.env`. Así, si algo falla en la conexión, no dejas las apps sin caché ni sesión.

---

## 22. Protección de formularios públicos (Turnstile + rate limiting)

Los formularios de registro públicos son blanco de registro masivo automatizado de cuentas falsas. En este servidor, los logs mostraron múltiples IPs (rangos de proveedores de hosting, no usuarios reales) haciendo `POST /registro` exitoso de forma sostenida. El rate limiting por sí solo **no basta** porque los bots rotan IPs: cada una se mantiene por debajo del umbral. La defensa efectiva es por capas.

### 22.1 Cloudflare Turnstile (la pieza principal)

Turnstile es un CAPTCHA gratuito y respetuoso de la privacidad. Lo crítico es que la validación ocurra **en el servidor**, no solo renderizar el widget: un bot que haga POST directo sin pasar por el navegador debe ser rechazado igualmente.

Service de verificación (`app/Services/TurnstileService.php`):

```php
public function verify(string $token, string $ip): bool
{
    // Guarda barata: token vacío = ni siquiera llamamos a Cloudflare.
    // Evita el round-trip (con su timeout) en el caso más común de abuso (POST sin token).
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
        return false;   // fail-closed: si Cloudflare no responde, nadie se registra
    }
}
```

En el controlador, verifica **antes** de validar o tocar la base de datos:

```php
if (! $this->turnstile->verify((string) $request->input('cf-turnstile-response'), $request->ip())) {
    return back()->withInput()->withErrors(['captcha' => 'No se pudo verificar que eres humano.']);
}
```

Dos decisiones de diseño a tener conscientes: el `catch` devuelve `false` (**fail-closed**), correcto para frenar abuso pero implica que un fallo de red con Cloudflare bloquearía registros legítimos; y si tienes **varias rutas de registro** (ej. host y cliente), las **dos** deben llevar la verificación, o los bots usarán la desprotegida.

### 22.2 Rate limiting específico (capa secundaria)

No quites el rate limiter al poner Turnstile; son complementarios. Para la ruta de registro, algo más agresivo que el default:

```php
RateLimiter::for('registro', function (Request $request) {
    return [
        Limit::perMinute(3)->by($request->ip()),
        Limit::perDay(10)->by($request->ip()),
    ];
});
```

### 22.3 Verificación de email obligatoria (contención)

Aunque una cuenta logre registrarse, no debe poder hacer nada hasta verificar su email. Usa `MustVerifyEmail` en el modelo `User` y el middleware `verified` en las rutas protegidas. Esto convierte cualquier cuenta basura que se cuele en una cuenta inerte.

### 22.4 Cómo verificar que funciona (el log engaña)

El log de Apache **no distingue** un registro exitoso de un rechazo de Turnstile: ambos producen un `302` (el éxito redirige a `/verification.notice`; el rechazo regresa al formulario con `back()`). Por eso, ver cientos de `302` en `/registro` **no significa** que entren cuentas. El termómetro real es la base de datos:

```sql
SELECT COUNT(*) FROM users WHERE created_at >= CURDATE();
```

Si ese conteo se mantiene en tus números reales esperados (o en cero, si no esperabas altas legítimas) mientras el log sigue mostrando intentos, Turnstile está haciendo su trabajo. **Los bots no dejarán de intentar** —seguirás viendo los `302` y los `POST`— pero no crearán cuentas. No te alarmes por el ruido del log; vigila el `COUNT`.

> **Defensa en profundidad real:** Turnstile mata el registro automatizado, el rate limiter atrapa a los más insistentes, el bloqueo del vhost (sección 16) frena el escaneo antes de PHP, y Fail2Ban (sección 17) banea reincidentes a nivel firewall. Cada capa cubre el hueco de las otras.

---

## 23. Optimización de rendimiento

Una vez asegurado el servidor, estas son las palancas de rendimiento para Laravel/Filament. **Dimensiona con datos, no a ojo:** mide el consumo real bajo carga antes de fijar valores, y aplica un cambio a la vez validando que ayudó.

> **Paso cero (crítico):** confirma que cada app esté en producción. `php artisan about` debe mostrar `Environment = production` y `Debug Mode = OFF`. Con `APP_DEBUG=true` en un server público, cualquier excepción expone credenciales y variables de entorno al visitante — es a la vez fuga de seguridad y costo de rendimiento.

### 23.1 OPcache

El default (`memory_consumption=128`, `max_accelerated_files=10000`) se queda corto para varias apps Laravel + Filament: un solo proyecto con su `vendor/` ronda los 8–12k archivos, así que con dos se desaloja OPcache constantemente. En `/etc/php.d/10-opcache.ini`:

```ini
opcache.enable=1
opcache.memory_consumption=512        ; subir de 128
opcache.interned_strings_buffer=32    ; subir de 8
opcache.max_accelerated_files=65000   ; subir de 10000
opcache.save_comments=1               ; NO apagar: Filament/Laravel usan atributos
opcache.validate_timestamps=0         ; SOLO si el deploy resetea OPcache (ver abajo)
opcache.revalidate_freq=0
```

Y habilita el JIT de PCRE (acelera el motor de regex de rutas/validación), que suele venir apagado:

```ini
; /etc/php.d/30-pcre.ini
pcre.jit=1
```

> `validate_timestamps=0` solo cuando tu script de deploy (sección 19) termine con un reset de OPcache (`cachetool opcache:reset` o `systemctl reload php-fpm`); de lo contrario, los cambios de código no se reflejarían tras un deploy. El **JIT de PHP** (distinto del de PCRE) lo puedes dejar desactivado: para carga ligada a I/O como Laravel el beneficio es marginal.

### 23.2 PHP-FPM: un pool por plataforma

Un solo pool `www` compartido por todas las apps es frágil: un pico en una puede dejar sin workers a las demás, y todas corren como `apache` con el mismo log. Lo correcto es **un pool por plataforma**, cada uno con su usuario. En `/etc/php-fpm.d/miapp.conf`:

```ini
[miapp]
user = dante
group = apache
listen = /run/php-fpm/miapp.sock
listen.owner = apache
listen.group = apache
listen.mode = 0660

pm = ondemand                          ; tráfico bajo/medio: libera RAM al estar ocioso
pm.max_children = 20
pm.process_idle_timeout = 30s
pm.max_requests = 500                  ; recicla workers -> evita fugas de memoria

php_admin_value[memory_limit] = 384M   ; por pool, NO el 1024M global
slowlog = /var/log/php-fpm/miapp-slow.log
request_slowlog_timeout = 5s
pm.status_path = /status
```

> El `memory_limit` global alto (ej. 1024M) es peligroso para web: 50 children × 1 GB = 50 GB teóricos. Déjalo alto para CLI (migraciones, exports) pero acótalo por pool. Mide el peso real por proceso bajo carga para dimensionar `max_children`:
> ```bash
> ps --no-headers -o rss -C php-fpm | awk '{s+=$1;n++} END {printf "%.0f MB prom, %d procs\n", s/n/1024, n}'
> ```

### 23.3 MySQL 8.4

> **Advertencia de método:** afinar a fondo un MySQL con poca data es prematuro. Lo de mayor valor al inicio es **encender el slow query log** para tener con qué trabajar cuando llegue tráfico real.

En `/etc/my.cnf.d/optimization.cnf`:

```ini
[mysqld]
# Diagnóstico (lo más importante al inicio)
slow_query_log = ON
long_query_time = 1
log_queries_not_using_indexes = ON     ; ruidoso; apágalo tras la fase inicial

# Redo log (en 8.4 reemplaza a innodb_log_file_size; el default de ~48M es chico)
innodb_redo_log_capacity = 1G          ; requiere reinicio de MySQL

# Acorde al hardware (SSD SATA, no NVMe). 10000 es irreal para esos discos.
innodb_io_capacity = 2000
innodb_io_capacity_max = 4000

tmp_table_size = 64M
max_heap_table_size = 64M
```

> **No bajes `innodb_flush_log_at_trx_commit` de 1** si manejas datos fiscales/contables (CFDI, SAT): no sacrifiques integridad transaccional por un microbenchmark. Sube `innodb_buffer_pool_size` (default puede quedar corto) solo conforme crezcan los datos; tienes RAM de sobra.

### 23.4 Apache MPM event y HTTP/2

Con PHP-FPM, el MPM debe ser **event** (no prefork). Define los límites explícitos y confirma HTTP/2 y compresión:

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

Y cachea agresivamente los assets compilados de Vite (nombres con hash → inmutables), dentro del VirtualHost:

```apache
<LocationMatch "^/build/.*\.(js|css|woff2?|svg|png|jpe?g|webp|avif)$">
    Header set Cache-Control "public, max-age=31536000, immutable"
</LocationMatch>
```

### 23.5 Orden de aplicación seguro

1. `APP_ENV=production` + `APP_DEBUG=false` → `artisan optimize` + `filament:optimize`.
2. Valkey para caché/sesión/cola (sección 21).
3. OPcache (memoria, files, `pcre.jit`) → `reload php-fpm`.
4. Pools FPM por plataforma, uno a la vez.
5. MySQL: slow log primero (sin reinicio), luego redo log + io_capacity (con reinicio).
6. `opcache.validate_timestamps=0` SOLO cuando el deploy ya resetee OPcache.
7. Apache MPM/HTTP2/compresión → `reload httpd`.

Mide antes/después con `ab`/`wrk` contra un endpoint representativo, el `pm.status_path` de FPM, y `SHOW ENGINE INNODB STATUS` tras horas de uso real.

---

## 24. Checklist final de verificación

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
| Valkey | Solo socket Unix, sin puerto 6379, con auth | `ss -tlnp \| grep 6379` (vacío), `valkey-cli -s ... PING` |
| Caché/sesión Laravel | Driver `redis` apuntando al socket | `php artisan about`, `tinker` con `Cache::store('redis')` |
| Turnstile | Verificación server-side en TODAS las rutas de registro | `COUNT(*) users WHERE created_at >= CURDATE()` estable |
| OPcache | memory/files dimensionados para multi-app | `php -i \| grep opcache.max_accelerated_files` |
| MySQL slow log | Activo para diagnóstico | `SHOW VARIABLES LIKE 'slow_query_log'` |
| security.txt | Presente | visitar `/.well-known/security.txt` |
| Renovación SSL | Timer activo | `systemctl list-timers \| grep certbot` |
| Actualizaciones | dnf-automatic activo | `systemctl status dnf-automatic.timer` |

---

## 25. Apéndice: DNSSEC, GeoIP y PGP

**DNSSEC / error "lame delegation" (RRSIG).** Este error **no se arregla en el servidor**, sino en el panel de tu registrador de dominio. Suele significar que activaste DNSSEC pero los registros **DS** (Delegation Signer) no coinciden con las llaves de tus servidores de nombres. Acción: en el panel del dominio, verifica que DNSSEC esté correctamente configurado contra tu proveedor DNS; si no lo usarás estrictamente, desactívalo para eliminar el error.

**GeoIP (opcional).** Si un portal es de uso exclusivo en México, puedes bloquear por país a nivel de firewall/Apache (mod_maxminddb) para reducir drásticamente el tráfico de escaneo proveniente de data centers extranjeros. Implementación de mayor esfuerzo; evalúa si el caso lo amerita.

**Firma PGP del security.txt (opcional).** Firmar `security.txt` con una llave PGP evita que, si alguien alterara el archivo, los reportes de vulnerabilidad lleguen a un impostor. Para un MVP o portal interno **no es urgente**; para portales gubernamentales o financieros **sí** se recomienda. Si lo implementas: genera el par con `gpg`, publica la llave pública y añade `Encryption: https://tu-dominio.com/pgp-key.asc` al archivo.

---


