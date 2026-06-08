# Guide d'Installation et de Durcissement d'un Serveur AlmaLinux 10

**Objectif :** Construire de zéro un serveur de production **hautement sécurisé** sur **AlmaLinux 10**, capable d'héberger à la fois des applications **Laravel (PHP 8.5 / Filament)** et des applications **Node.js (LTS 24)**, derrière Apache, avec SSL Let's Encrypt, SELinux en mode *Enforcing* et une défense active avec Fail2Ban.

**Stack technologique :** AlmaLinux 10 · Apache 2.4 (MPM event + HTTP/2) · PHP 8.5 (php-fpm via Remi) · MySQL 8.4 · Valkey 8 · Node.js 24 LTS · Let's Encrypt · firewalld · SELinux · Fail2Ban · Cloudflare Turnstile

> **Comment utiliser ce document.** Il est conçu comme un *runbook* (procédure reproductible étape par étape) et comme référence d'audit. Remplacez les marqueurs `votre-domaine.com`, `monapp`, `votre.ip.publique.ici` ainsi que les noms d'utilisateur/BD par les valeurs réelles. Exécutez les commandes en tant que `root` ou en les préfixant par `sudo`.

---

## Table des matières

1. [Conventions et architecture](#1-conventions-et-architecture)
2. [Préparation du système de base](#2-préparation-du-système-de-base)
3. [Utilisateur administratif et accès SSH par clés](#3-utilisateur-administratif-et-accès-ssh-par-clés)
4. [SSH sécurisé (port 4428 + durcissement)](#4-ssh-sécurisé-port-4428--durcissement)
5. [Pare-feu (firewalld)](#5-pare-feu-firewalld)
6. [Fondamentaux de SELinux à comprendre](#6-fondamentaux-de-selinux-à-comprendre)
7. [Apache (serveur web / reverse proxy)](#7-apache-serveur-web--reverse-proxy)
8. [PHP 8.5 + PHP-FPM (pour Laravel)](#8-php-85--php-fpm-pour-laravel)
9. [MySQL 8 avec privilèges minimaux](#9-mysql-8-avec-privilèges-minimaux)
10. [Composer](#10-composer)
11. [Déploiement d'un projet Laravel](#11-déploiement-dun-projet-laravel)
12. [Node.js 24 LTS en tant que service + reverse proxy](#12-nodejs-24-lts-en-tant-que-service--reverse-proxy)
13. [Let's Encrypt (SSL) et renouvellement automatique](#13-lets-encrypt-ssl-et-renouvellement-automatique)
14. [En-têtes de sécurité HTTP](#14-en-têtes-de-sécurité-http)
15. [Masquer les versions (fuite d'information)](#15-masquer-les-versions-fuite-dinformation)
16. [Blocage des bots par User-Agent et chemins d'exploit](#16-blocage-des-bots-par-user-agent-et-chemins-dexploit)
17. [Fail2Ban : défense active](#17-fail2ban--défense-active)
18. [security.txt et robots.txt](#18-securitytxt-et-robotstxt)
19. [Flux de déploiement avec Git](#19-flux-de-déploiement-avec-git)
20. [Mises à jour automatiques et maintenance](#20-mises-à-jour-automatiques-et-maintenance)
21. [Valkey (cache, sessions et files d'attente)](#21-valkey-cache-sessions-et-files-dattente)
22. [Protection des formulaires publics (Turnstile + rate limiting)](#22-protection-des-formulaires-publics-turnstile--rate-limiting)
23. [Optimisation des performances](#23-optimisation-des-performances)
24. [Checklist finale de vérification](#24-checklist-finale-de-vérification)
25. [Annexe : DNSSEC, GeoIP et PGP](#25-annexe--dnssec-geoip-et-pgp)

---

## 1. Conventions et architecture

**Structure de répertoires recommandée.** Tout se trouve sous `/var/www`, le contexte que SELinux connaît déjà nativement pour Apache :

```
/var/www/
├── monapp-laravel/         # projet Laravel
│   ├── public/             # <- DocumentRoot Apache (seul dossier exposé)
│   ├── storage/            # écriture (httpd_sys_rw_content_t)
│   ├── bootstrap/cache/    # écriture (httpd_sys_rw_content_t)
│   └── .env                # JAMAIS dans public/
└── monapp-node/            # projet Node
    ├── dist/ ou build/
    └── .env
```

**Principe directeur (règle d'or de SELinux sur AlmaLinux 10) :** face à toute nouveauté, souvenez-vous des trois piliers —
- **Port** → `semanage port`
- **Fichier/dossier** → `restorecon` / `semanage fcontext`
- **Permission d'action** → `setsebool`

**Architecture réseau :**
- Apache écoute sur `80` et `443` (seuls ports web ouverts vers l'extérieur).
- PHP-FPM tourne via un socket Unix local (non exposé).
- MySQL écoute **uniquement** sur `127.0.0.1:3306` (jamais exposé).
- Chaque app Node tourne sur un port *loopback* (ex. `127.0.0.1:3000`) et Apache fait office de **reverse proxy** avec TLS. Le port Node **n'est pas ouvert** dans le pare-feu.

---

## 2. Préparation du système de base

```bash
# Assurer la connectivité réseau si nécessaire
nmtui

# Mettre à jour l'ensemble du système
dnf update -y

# Dépôts de base et utilitaires
dnf install -y epel-release dnf-utils
dnf install -y vim git wget curl tar policycoreutils-python-utils setroubleshoot-server

# Fuseau horaire (adaptez à votre région)
timedatectl set-timezone Europe/Paris

# Synchronisation de l'heure
systemctl enable --now chronyd
```

> `policycoreutils-python-utils` fournit `semanage` ; `setroubleshoot-server` fournit `sealert`, le traducteur d'erreurs SELinux. Ces deux outils sont indispensables pour administrer SELinux sans le désactiver.

**N'utilisez pas `net-tools` (obsolète).** AlmaLinux 10 inclut déjà `iproute2` : utilisez `ss -tulpn` à la place de `netstat`.

**Confirmez que SELinux est actif en mode Enforcing** (ne le désactivez jamais) :

```bash
getenforce        # doit répondre : Enforcing
sestatus
```

---

## 3. Utilisateur administratif et accès SSH par clés

Travailler en tant que `root` via SSH est la première porte que les bots attaquent. Créez un utilisateur avec `sudo` et connectez-vous toujours avec lui.

**Sur le serveur :**

```bash
adduser dante
passwd dante                 # mot de passe fort
usermod -aG wheel dante      # 'wheel' = groupe sudo sur AlmaLinux
```

**Sur votre machine locale** (générez la paire de clés si vous ne l'avez pas) :

```bash
ssh-keygen -t ed25519 -C "dante@laptop"
# Copiez la clé publique sur le serveur (encore sur le port 22 pour l'instant)
ssh-copy-id dante@votre.ip.publique.ici
```

Vérifiez que vous pouvez vous connecter **sans mot de passe** avec la clé avant de continuer. Si la clé ne fonctionne pas, ne désactivez **pas** l'authentification par mot de passe à l'étape suivante, ou vous serez bloqué.

---

## 4. SSH sécurisé (port 4428 + durcissement)

Sur AlmaLinux 10, la configuration SSH moderne se fait avec des fichiers *drop-in* dans `/etc/ssh/sshd_config.d/` (plus propre et résistant aux mises à jour que d'éditer le fichier principal).

```bash
cat > /etc/ssh/sshd_config.d/99-hardening.conf <<'EOF'
# Port non standard (réduit le bruit des scans automatisés)
Port 4428

# IPv4/IPv6 uniquement selon votre cas
# AddressFamily inet

# Durcissement
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

> **Important :** changer le port SSH ne suffit pas ; SELinux bloquera le nouveau port même si le pare-feu le permet. Il faut l'étiqueter.

```bash
# Informer SELinux du nouveau port SSH
semanage port -a -t ssh_port_t -p tcp 4428

# Valider la syntaxe et redémarrer
sshd -t && systemctl restart sshd
```

Ouvrez une **deuxième** session SSH sur le port 4428 **avant** de fermer la session actuelle, pour confirmer l'accès :

```bash
ssh -p 4428 dante@votre.ip.publique.ici
```

---

## 5. Pare-feu (firewalld)

Ne désactivez pas `firewalld` : sur AlmaLinux 10 il s'intègre parfaitement avec SELinux et Fail2Ban.

```bash
systemctl enable --now firewalld

# Supprimer le service SSH standard (port 22) et ouvrir le 4428
firewall-cmd --permanent --remove-service=ssh
firewall-cmd --permanent --add-port=4428/tcp

# Ouvrir le web
firewall-cmd --permanent --add-service=http
firewall-cmd --permanent --add-service=https

# Appliquer
firewall-cmd --reload

# Vérifier
firewall-cmd --list-all
```

Résultat attendu : seuls `4428/tcp`, `http` et `https` ouverts. Les ports `22`, `3306` (MySQL) et les ports internes de Node **ne doivent pas apparaître**. Un scanner externe doit les voir comme fermés/filtrés.

---

## 6. Fondamentaux de SELinux à comprendre

SELinux ne bloque pas les services « arbitrairement » : il garantit que chaque processus ne touche que ce qu'il est autorisé à toucher (politique *deny by default*).

**Ce qui ne nécessite pas de configuration :**
- Servir du contenu dans `/var/www` sur les ports 80/443. Les fichiers créés là héritent automatiquement de l'étiquette `httpd_sys_content_t`.

**Le « mais » le plus courant :** si vous **déplacez** des fichiers depuis `/home/utilisateur` vers `/var/www` avec `mv`, ils conservent l'étiquette d'origine et Apache retournera **403 Forbidden**. Solution universelle :

```bash
restorecon -Rv /var/www/monapp
```

**Permissions d'action (booléens) dont vous aurez besoin :**

| Scénario | Commande |
|---|---|
| Laravel se connecte à MySQL local | `setsebool -P httpd_can_network_connect_db on` |
| Apache fait du reverse proxy vers une app Node | `setsebool -P httpd_can_network_connect on` |
| Apache lit des dossiers hors du standard | `setsebool -P httpd_enable_homedirs on` |

**Dossiers où Apache/Laravel ont besoin d'écrire :**

```bash
semanage fcontext -a -t httpd_sys_rw_content_t "/var/www/monapp/storage(/.*)?"
semanage fcontext -a -t httpd_sys_rw_content_t "/var/www/monapp/bootstrap/cache(/.*)?"
restorecon -Rv /var/www/monapp
```

> Le flag `-P` dans `setsebool` est **crucial** : il rend le changement persistant après un redémarrage.

**Outils de diagnostic (plutôt que de désactiver SELinux) :**

```bash
# Refus en temps réel
tail -f /var/log/audit/audit.log | grep denied

# Traducteur humain des erreurs
sealert -a /var/log/audit/audit.log
```

---

## 7. Apache (serveur web / reverse proxy)

```bash
dnf install -y httpd mod_ssl
systemctl enable --now httpd
```

Assurez-vous que les modules proxy (nécessaires pour Node) et rewrite (pour le blocage de bots) sont chargés :

```bash
# Sur AlmaLinux 10 ils sont généralement actifs ; vérifiez :
httpd -M | grep -E "proxy_module|proxy_http|proxy_wstunnel|rewrite|headers|ssl"
```

S'il en manque, les modules se trouvent dans `/etc/httpd/conf.modules.d/`. Normalement `proxy`, `proxy_http`, `rewrite`, `headers` et `ssl` sont déjà activés ; `proxy_wstunnel` peut nécessiter d'être ajouté pour les WebSockets.

---

## 8. PHP 8.5 + PHP-FPM (pour Laravel)

PHP 8.5 est disponible en tant que module stable de Remi pour Enterprise Linux 10.

```bash
# Dépôt Remi pour AlmaLinux 10
dnf install -y https://rpms.remirepo.net/enterprise/remi-release-10.rpm

# Sélectionner le flux de module PHP 8.5
dnf module reset php -y
dnf module enable php:remi-8.5 -y

# Installer PHP-FPM et les extensions typiques de Laravel/Filament
dnf install -y php php-cli php-common php-fpm \
  php-mysqlnd php-pdo php-mbstring php-xml php-curl \
  php-gd php-zip php-bcmath php-intl php-opcache php-redis

systemctl enable --now php-fpm
php -v   # confirmer 8.5.x
```

**Pool PHP-FPM sous l'utilisateur Apache.** Éditez `/etc/php-fpm.d/www.conf` et assurez-vous que :

```ini
user = apache
group = apache
listen = /run/php-fpm/www.sock
listen.owner = apache
listen.group = apache
listen.mode = 0660
```

Le paquet installe `/etc/httpd/conf.d/php.conf`, qui route les `.php` vers le socket PHP-FPM via `SetHandler "proxy:unix:/run/php-fpm/www.sock|fcgi://localhost"`. Aucune configuration manuelle n'est nécessaire sauf dans des cas particuliers.

```bash
systemctl restart php-fpm httpd
```

---

## 9. MySQL 8 avec privilèges minimaux

```bash
dnf install -y mysql-server
systemctl enable --now mysqld

# Sécuriser l'installation (définir root, supprimer les anonymes, etc.)
mysql_secure_installation
```

**Liez MySQL uniquement à localhost** (sans écoute réseau). Dans `/etc/my.cnf.d/mysql-server.cnf`, dans `[mysqld]` :

```ini
bind-address = 127.0.0.1
```

```bash
systemctl restart mysqld
```

**Créez la base de données et un utilisateur avec privilèges minimaux** (n'utilisez PAS `*.*` ni `WITH GRANT OPTION` pour les apps ; c'est le modèle dangereux des anciens guides) :

```sql
CREATE DATABASE monapp CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE USER 'monapp'@'localhost' IDENTIFIED BY 'UnMotDePasseLongEtAleatoire_2026!';

-- Seulement les privilèges sur SA propre base, rien d'autre
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, INDEX, DROP, REFERENCES
  ON monapp.* TO 'monapp'@'localhost';

FLUSH PRIVILEGES;
```

> MySQL 8 utilise `caching_sha2_password` par défaut, ce qui est recommandé. Revenez à `mysql_native_password` uniquement si une bibliothèque ancienne l'exige.

Si Laravel retourne des erreurs 500 lors de la connexion à la BD, c'est presque toujours le booléen SELinux :

```bash
setsebool -P httpd_can_network_connect_db on
```

---

## 10. Composer

Laravel moderne nécessite Composer 2.x (pas le 1.9 des anciens guides) :

```bash
php -r "copy('https://getcomposer.org/installer', 'composer-setup.php');"
php composer-setup.php --install-dir=/usr/local/bin --filename=composer
rm composer-setup.php
composer --version
```

---

## 11. Déploiement d'un projet Laravel

```bash
mkdir -p /var/www/monapp
chown -R apache:apache /var/www/monapp

# Clonez ou envoyez votre projet dans /var/www/monapp (voir section 19 pour Git)
cd /var/www/monapp
composer install --no-dev --optimize-autoloader

# Permissions d'écriture pour Laravel (Linux + SELinux)
chown -R apache:apache storage bootstrap/cache
semanage fcontext -a -t httpd_sys_rw_content_t "/var/www/monapp/storage(/.*)?"
semanage fcontext -a -t httpd_sys_rw_content_t "/var/www/monapp/bootstrap/cache(/.*)?"
restorecon -Rv /var/www/monapp

# Optimisation de Laravel
php artisan config:cache
php artisan route:cache
php artisan view:cache
```

**VirtualHost Laravel** dans `/etc/httpd/conf.d/monapp.conf` (HTTP redirigeant vers HTTPS ; le bloc 443 sera complété par Certbot, voir sections 13 et 14) :

```apache
<VirtualHost *:80>
    ServerName votre-domaine.com
    DocumentRoot /var/www/monapp/public
    Redirect permanent / https://votre-domaine.com/
</VirtualHost>
```

> Le `DocumentRoot` pointe vers `public/`, gardant `.env`, `vendor/` et le reste du code hors de portée web.

**Cron du Laravel Scheduler** — doit tourner avec l'utilisateur Apache pour ne pas casser les permissions :

```bash
# crontab -u apache -e
* * * * * cd /var/www/monapp && php artisan schedule:run >> /dev/null 2>&1
```

---

## 12. Node.js 24 LTS en tant que service + reverse proxy

En mai 2026, **Node.js 24 est la version LTS active** recommandée pour la production (Node 26 est en phase *Current*, pas encore LTS).

### 12.1 Installer Node 24

```bash
# Dépôt officiel NodeSource pour la branche 24.x
curl -fsSL https://rpm.nodesource.com/setup_24.x | bash -
dnf install -y nodejs
node -v    # v24.x
npm -v
```

> Alternative : `dnf module enable nodejs:24 && dnf install nodejs` depuis AppStream, si vous préférez ne pas ajouter de dépôts externes (peut avoir une ou deux *minor* de retard).

### 12.2 Utilisateur dédié et code

Ne faites pas tourner Node en tant que `root`. Créez un utilisateur système sans shell de connexion :

```bash
useradd --system --create-home --home-dir /var/www/monapp-node --shell /usr/sbin/nologin nodeapp
# Envoyez/clonez votre app dans /var/www/monapp-node et compilez
cd /var/www/monapp-node
sudo -u nodeapp npm ci --omit=dev
sudo -u nodeapp npm run build   # si applicable
```

### 12.3 Service systemd (plus propre et plus sûr que PM2 en root)

Créez `/etc/systemd/system/monapp-node.service` :

```ini
[Unit]
Description=Mon App Node
After=network.target

[Service]
Type=simple
User=nodeapp
Group=nodeapp
WorkingDirectory=/var/www/monapp-node
# L'app DOIT écouter en loopback : host 127.0.0.1, port 3000
Environment=NODE_ENV=production
Environment=PORT=3000
Environment=HOST=127.0.0.1
ExecStart=/usr/bin/node dist/server.js
Restart=on-failure
RestartSec=5

# Durcissement du service
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable --now monapp-node
systemctl status monapp-node
ss -tlpn | grep 3000      # doit écouter UNIQUEMENT sur 127.0.0.1:3000
```

> Assurez-vous que votre app lit `process.env.HOST` et `process.env.PORT` et **écoute sur `127.0.0.1`**, pas sur `0.0.0.0`. Ainsi le port 3000 n'est jamais accessible depuis internet, seulement depuis Apache.

### 12.4 Autoriser le proxy dans SELinux

Pour qu'Apache puisse ouvrir une connexion réseau vers le port de Node :

```bash
setsebool -P httpd_can_network_connect on
```

### 12.5 VirtualHost reverse proxy

`/etc/httpd/conf.d/monapp-node.conf` :

```apache
<VirtualHost *:80>
    ServerName node.votre-domaine.com
    Redirect permanent / https://node.votre-domaine.com/
</VirtualHost>

<VirtualHost *:443>
    ServerName node.votre-domaine.com

    ProxyPreserveHost On
    ProxyPass        / http://127.0.0.1:3000/
    ProxyPassReverse / http://127.0.0.1:3000/

    # Support WebSocket (si votre app l'utilise : Socket.io, etc.)
    RewriteEngine On
    RewriteCond %{HTTP:Upgrade} =websocket [NC]
    RewriteRule /(.*) ws://127.0.0.1:3000/$1 [P,L]

    # (Les en-têtes de sécurité de la section 14 s'appliquent ici aussi)
    # (Certbot ajoutera les directives SSL ici)

    ErrorLog  /var/log/httpd/monapp-node-error.log
    CustomLog /var/log/httpd/monapp-node-access.log combined
</VirtualHost>
```

```bash
apachectl configtest && systemctl restart httpd
```

> **N'ouvrez pas le port 3000 dans firewalld.** Le trafic entre par le 443 (Apache, avec TLS) et est renvoyé en interne. Node reste isolé.

---

## 13. Let's Encrypt (SSL) et renouvellement automatique

```bash
dnf install -y certbot python3-certbot-apache

# Un certificat par domaine/sous-domaine
certbot --apache -d votre-domaine.com
certbot --apache -d node.votre-domaine.com
```

Certbot insère automatiquement les directives `SSLCertificateFile`, `SSLCertificateKeyFile` et `Include /etc/letsencrypt/options-ssl-apache.conf` dans vos VirtualHosts en 443.

**Renouvellement automatique.** Le paquet installe un *timer* systemd qui renouvelle sans intervention. Vérifiez-le :

```bash
systemctl list-timers | grep certbot
certbot renew --dry-run     # simulation pour confirmer que le renouvellement fonctionne
```

---

## 14. En-têtes de sécurité HTTP

Ces en-têtes corrigent les findings typiques des scanners comme web-check.xyz (HSTS, Clickjacking, MIME sniffing, XSS, CSP). Ajoutez-les dans le bloc `<VirtualHost *:443>` de chaque site.

```apache
# HSTS : impose HTTPS pendant 2 ans (éligible à la preload list)
Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"

# Anti-clickjacking
Header always set X-Frame-Options "SAMEORIGIN"

# Éviter le MIME sniffing
Header always set X-Content-Type-Options "nosniff"

# Politique de référence
Header always set Referrer-Policy "strict-origin-when-cross-origin"

# Permissions-Policy (limite les APIs du navigateur)
Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"

# Content-Security-Policy : la plus puissante contre le XSS.
# Adaptez les domaines externes que vous utilisez réellement (polices, cartes, analytics).
Header always set Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://fonts.googleapis.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self';"

# Supprimer les fuites de version
ServerSignature Off
Header unset X-Powered-By
```

> **Note sur `X-XSS-Protection` :** cet en-tête est obsolète et les navigateurs modernes l'ignorent (certains recommandent `0`). La vraie protection contre le XSS aujourd'hui est une bonne **CSP**. Si votre scanner le demande encore, vous pouvez ajouter `Header set X-XSS-Protection "1; mode=block"`, mais ce n'est pas là que réside la sécurité réelle.

> **La CSP est itérative.** Commencez avec la politique ci-dessus ; si quelque chose cesse de se charger (un script externe, une carte, Google Analytics), ajoutez ce domaine à la directive correspondante. Pour Filament, `'self' 'unsafe-inline' 'unsafe-eval'` suffit généralement.

```bash
apachectl configtest && systemctl restart httpd
```

---

## 15. Masquer les versions (fuite d'information)

Dire au monde entier « j'utilise PHP 8.5.6 et Apache 2.4.63 » revient à offrir aux attaquants la carte exacte des exploits à essayer.

**Apache** — créez `/etc/httpd/conf.d/00-security.conf` :

```apache
ServerTokens Prod
ServerSignature Off
TraceEnable Off
```

**PHP** — dans `/etc/php.ini` :

```ini
expose_php = Off
```

```bash
systemctl restart php-fpm httpd
```

Après cela, l'en-tête `Server` n'indiquera que `Apache` (sans version) et `X-Powered-By: PHP/...` disparaîtra.

---

## 16. Blocage des bots par User-Agent et chemins d'exploit

Les logs réels montrent deux types de bruit automatisé : des scanners qui s'identifient avec des User-Agents connus (`l9scan`, `zgrab`, `Nikto`, `CensysInspect`) et des bots qui demandent des chemins inexistants dans l'app (`/.env`, `/.git/config`, `/vendor/phpunit/.../eval-stdin.php`, `/wp-config.php`). Il est utile de couper les deux **au niveau du VirtualHost**, avant que la requête n'atteigne PHP.

> **Leçon apprise — n'ancrez pas le User-Agent avec `^`.** Une version précédente utilisait `RewriteCond %{HTTP_USER_AGENT} ^Nmap`, qui ne correspond que si l'UA *commence* exactement par cette chaîne. Des bots comme `l9scan` s'annoncent comme `Mozilla/5.0 (l9scan/2.0...)`, donc l'ancre les laissait passer. La règle correcte recherche la chaîne **n'importe où** dans le User-Agent.

Placez le blocage directement sous `<VirtualHost *:443>`, pas dans le `<Directory>`. Le contexte serveur est évalué en premier et indépendamment du `.htaccess` de Laravel, donc le blocage s'applique à toute requête sans dépendre de ce que Laravel traitera ensuite. Nécessite un `RewriteEngine On` explicite dans ce contexte :

```apache
RewriteEngine On

# 1) Blocage par User-Agent — SANS ancre ^, pour les attraper n'importe où
#    dans la chaîne (ex. "Mozilla/5.0 (l9scan/...)" ne passe plus)
RewriteCond %{HTTP_USER_AGENT} (l9explore|l9scan|l9tcpid|Nmap|Masscan|zgrab|Nikto|CensysInspect|leakix|libredtail|Gh0st) [NC]
RewriteRule ^ - [F,L]

# 2) User-Agent vide sur les requêtes autres que la racine (bots bruts)
RewriteCond %{HTTP_USER_AGENT} ^-?$
RewriteCond %{REQUEST_URI} !^/$
RewriteRule ^ - [F,L]

# 3) Blocage des fichiers cachés (.env, .git, etc.)
#    SAUF /.well-known (nécessaire pour le renouvellement Let's Encrypt)
RewriteRule "(^|/)\.(?!well-known)" - [F,L]

# 4) Chemins d'exploit connus (PHPUnit eval-stdin, vendor, déchets .php)
RewriteCond %{REQUEST_URI} (eval-stdin\.php|/vendor/|/phpunit|/wp-|xmlrpc\.php|/phpinfo|/\.aws|/\.ssh) [NC]
RewriteRule ^ - [F,L]
```

> **Le `/.well-known` est critique.** Si vous bloquiez tous les dotfiles sans exception, vous briseriez le défi ACME de Certbot (`/.well-known/acme-challenge/`) et votre certificat cesserait d'être renouvelé. Le `(?!well-known)` le protège.

> **Ne bloquez pas `curl` par User-Agent.** Même s'il apparaît dans les scans, c'est l'outil que vous utilisez vous-même pour les tests et les health checks. Ce comportement est mieux géré par Fail2Ban (bannit par comportement, pas par nom), voir section 17.

À partir de là, ces bots reçoivent **403 Forbidden** au lieu d'un 404. C'est une bonne chose : Fail2Ban (section suivante) bannit quiconque accumule des 403.

```bash
apachectl configtest && systemctl restart httpd
```

**Résultat mesurable.** Dans un cas réel sur ce serveur, après application du blocage, le log est passé à l'enregistrement de centaines de `403` quotidiens contre le scan de `/.env`, `/.git/config`, `/wp-config.php` et `/.aws/credentials` qui passaient auparavant en `404` inoffensifs mais atteignaient PHP. Une seule IP de scan agressive (`45.148.10.95`) a accumulé 220 blocages en un jour sans toucher à l'application.

---

## 17. Fail2Ban : défense active

Le pare-feu est un mur passif ; Fail2Ban est un gardien qui lit les logs et bannit les IPs récidivistes au niveau réseau.

```bash
dnf install -y fail2ban fail2ban-firewalld
```

**Configuration principale** — n'éditez jamais `jail.conf` ; créez `/etc/fail2ban/jail.local` :

```ini
[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 5
# Bannissement via firewalld (intégration native d'AlmaLinux 10)
banaction = firewallcmd-rich-rules
# IMPORTANT : ajoutez VOTRE IP fixe pour ne pas vous auto-bannir
ignoreip = 127.0.0.1/8 ::1 votre.ip.publique.ici

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

**Filtre personnalisé** pour détecter le scan de `.env`/`.git` et les 403 du blocage User-Agent. Créez `/etc/fail2ban/filter.d/laravel-vulnerabilities.conf` :

```ini
[Definition]
# Capte les 404 (recherche de fichiers sensibles) et 403 (blocages User-Agent / dotfiles)
failregex = ^<HOST> -.*"GET .*\.(env|git|aws|yml|yaml|json).* HTTP/.*" (404|403)
            ^<HOST> -.*"GET .*(\.git|config|credentials).* HTTP/.*" (404|403)
            ^<HOST> -.*"(GET|POST) .* HTTP/.*" 403
ignoreregex =
```

> **Sur l'abus des formulaires publics (inscription, contact).** Les IPs qui martèlent `POST /inscription` font tourner les adresses et utilisent des User-Agents de navigateurs réels, donc un filtre par 403 ne les attrape pas : au niveau HTTP ils sont indiscernables d'un humain. La bonne défense pour ça **n'est pas Fail2Ban** mais Cloudflare Turnstile + rate limiting + vérification d'email (voir section 22). Si vous voulez quand même que Fail2Ban réagisse aux plus persistants, vous pouvez ajouter un filtre qui compte les `429` (rate limit de Laravel) par IP, mais c'est une défense secondaire, pas la principale.

**Jail** utilisant ce filtre sur votre log d'accès (ajustez le chemin à votre `CustomLog`). Ajoutez à la fin de `jail.local` :

```ini
[laravel-scan]
enabled  = true
port     = http,https
filter   = laravel-vulnerabilities
logpath  = /var/log/httpd/monapp-access.log
maxretry = 2
bantime  = 48h
findtime = 1h
```

**Activer et vérifier :**

```bash
systemctl enable --now fail2ban
fail2ban-client status
fail2ban-client status laravel-scan

# Tester le filtre sur votre log actuel (compte les "Hits")
fail2ban-regex /var/log/httpd/monapp-access.log /etc/fail2ban/filter.d/laravel-vulnerabilities.conf
```

**SELinux et le log personnalisé.** Si Fail2Ban ne lit pas votre log avec un nom propre, vérifiez son contexte :

```bash
ls -Z /var/log/httpd/monapp-access.log   # doit être httpd_log_t
restorecon -v /var/log/httpd/monapp-access.log
```

> Si vous avez besoin de vous débannir : `fail2ban-client set laravel-scan unbanip 1.2.3.4`.

Avec cela vous avez une **défense en couches** : Apache identifie le bot et lui ferme la porte (403) → la tentative est enregistrée dans le log → Fail2Ban détecte l'IP récidiviste et la bloque dans firewalld.

---

## 18. security.txt et robots.txt

**security.txt** (standard pour que les chercheurs signalent les vulnérabilités de manière responsable) :

```bash
mkdir -p /var/www/monapp/public/.well-known
cat > /var/www/monapp/public/.well-known/security.txt <<'EOF'
Contact: mailto:securite@votre-domaine.com
Expires: 2027-01-01T00:00:00.000Z
Preferred-Languages: fr, en
EOF
restorecon -Rv /var/www/monapp/public/.well-known
```

**robots.txt** — pour décourager l'indexation du panneau d'administration (c'est seulement une *suggestion* pour les crawlers légitimes ; la vraie sécurité de `/admin` est le login Laravel/Filament) :

```
User-agent: *
Disallow: /admin/
Disallow: /admin
Allow: /
```

---

## 19. Flux de déploiement avec Git

**Erreur classique :** `fatal: detected dubious ownership in repository`. Se produit parce que le dossier appartient à `apache` mais vous exécutez Git comme un autre utilisateur.

```bash
git config --global --add safe.directory /var/www/monapp
```

**Le vrai problème :** après `git pull`, les nouveaux fichiers perdent le propriétaire `apache` et/ou le contexte SELinux, et Apache renvoie 403/500. Le flux correct en production :

```bash
git pull origin main
chown -R apache:apache /var/www/monapp
restorecon -Rv /var/www/monapp        # restaure les étiquettes SELinux
php /var/www/monapp/artisan optimize
```

**Automatisez avec un script de déploiement** (`/usr/local/bin/deploy-monapp`) :

```bash
#!/usr/bin/env bash
set -euo pipefail
cd /var/www/monapp
git pull origin main
composer install --no-dev --optimize-autoloader
php artisan migrate --force
php artisan config:cache && php artisan route:cache && php artisan view:cache
chown -R apache:apache /var/www/monapp
restorecon -Rv /var/www/monapp
echo "Deploy OK"
```

```bash
chmod +x /usr/local/bin/deploy-monapp
```

> **Pourquoi `restorecon` est vital :** Git attribue une étiquette temporaire aux nouveaux fichiers ; sans `restorecon`, SELinux peut bloquer leur lecture avec un 403 même si `chmod`/`chown` sont parfaits.

Pour Node, l'équivalent redémarre le service : `... && systemctl restart monapp-node`.

---

## 20. Mises à jour automatiques et maintenance

**Correctifs de sécurité automatiques :**

```bash
dnf install -y dnf-automatic
# Dans /etc/dnf/automatic.conf -> apply_updates = yes (ou seulement notifier)
systemctl enable --now dnf-automatic.timer
```

**Routine manuelle recommandée :**

```bash
dnf update --security        # correctifs de sécurité
certbot renew --dry-run      # confirmer le renouvellement SSL
fail2ban-client status       # réviser les bannissements
```

**Sauvegardes (minimum viable) :** planifiez un dump MySQL quotidien et une sauvegarde de `/var/www` et `/etc/httpd` :

```bash
mysqldump --single-transaction --routines monapp | gzip > /backups/monapp-$(date +\%F).sql.gz
```

---

## 21. Valkey (cache, sessions et files d'attente)

Pour que Laravel/Filament performent en production, déplacez le cache, les sessions et les files d'attente de la base de données vers un stockage en mémoire. **AlmaLinux 10 n'inclut plus Redis** (Redis Labs a changé de licence vers du non-FOSS en version 7.4 et la distro l'a retiré de ses dépôts) ; le remplacement officiel dans AppStream est **Valkey**, un fork sous licence FOSS. C'est un *drop-in* : phpredis et le driver `redis` de Laravel communiquent avec Valkey sans changer le moindre code applicatif.

> **Pourquoi Valkey et pas Redis via Remi.** Redis est revenu à une licence open source (AGPLv3) en 8.0 et il y a des RPMs dans `remi-modular`, mais cela lierait les mises à jour de sécurité d'un *datastore* (qui stockera des sessions) à un dépôt tiers. Valkey depuis l'AppStream officiel reçoit des correctifs selon le cycle normal de la distro, avec moins de charge de maintenance. Sauf si vous avez besoin d'une fonctionnalité très récente de Redis 8.x, Valkey est l'option recommandée.

### 21.1 Installation

```bash
dnf install -y valkey
valkey-server --version
```

### 21.2 Configuration sécurisée

Le modèle de menace classique de Redis/Valkey est « instance exposée sur internet sans mot de passe ». Comme ici Valkey vit sur le **même serveur** que Laravel, le plus sûr est de **ne pas l'exposer au réseau du tout** : socket Unix + pas de port TCP. Générez d'abord un mot de passe fort :

```bash
openssl rand -base64 48
```

Éditez `/etc/valkey/valkey.conf` (beaucoup de directives existent déjà en commentaires ; trouvez-les et ajustez) :

```conf
# --- RÉSEAU : ne pas exposer à aucune interface ---
bind 127.0.0.1 -::1
protected-mode yes
port 0                              # désactive TCP entièrement ; socket Unix uniquement

# --- SOCKET UNIX : comment Laravel se connecte ---
unixsocket /run/valkey/valkey.sock
unixsocketperm 770

# --- AUTHENTIFICATION ---
requirepass "COLLEZ_ICI_LE_MOT_DE_PASSE_GENERE"

# --- MÉMOIRE ET POLITIQUE ---
maxmemory 2gb                       # ajustez selon ce que vous lui allouez
maxmemory-policy allkeys-lru        # attention à la faute de frappe : c'est allkeys-lru (avec 'a')

# --- PERSISTANCE (pour ne pas perdre sessions/files au redémarrage) ---
appendonly yes
appendfsync everysec

# --- COMMANDES DANGEREUSES ---
rename-command FLUSHALL ""
rename-command FLUSHDB ""
rename-command KEYS ""                  # KEYS bloque le serveur en prod ; Laravel ne l'utilise pas
rename-command CONFIG "CONFIG_a8f3k2"   # renommez-le en quelque chose d'imprévisible plutôt que de le supprimer
```

> **Une faute de frappe provoque l'échec du démarrage.** Si Valkey ne démarre pas, vérifiez `systemctl status valkey` : le message `FATAL CONFIG FILE ERROR` indique le numéro de ligne exact de l'erreur. Une valeur mal orthographiée (ex. `llkeys-lru` au lieu de `allkeys-lru`) empêche le démarrage, et par conséquent le socket n'est jamais créé — d'où un `No such file or directory` en essayant de se connecter, qui est un symptôme, pas la cause.

### 21.3 Répertoire du socket, permissions et SELinux

Le répertoire du socket dans `/run` est éphémère ; créez-le de façon persistante avec tmpfiles pour qu'il survive aux redémarrages :

```bash
echo 'd /run/valkey 0750 valkey valkey -' > /etc/tmpfiles.d/valkey.conf
systemd-tmpfiles --create
```

Pour que PHP-FPM (et Netdata, si vous l'utilisez) lise le socket, ajoutez ces utilisateurs au groupe `valkey` — même logique d'appartenance aux groupes qu'avec `apache` :

```bash
usermod -aG valkey apache
usermod -aG valkey dante         # si vos pools FPM tournent en tant que dante
usermod -aG valkey netdata       # si vous monitorez avec Netdata
```

SELinux : activez le booléen de connexion web et étiquetez le répertoire du socket en cas de refus :

```bash
setsebool -P httpd_can_network_connect 1
semanage fcontext -a -t redis_var_run_t "/run/valkey(/.*)?" 2>/dev/null || true
restorecon -Rv /run/valkey

# Si Valkey échoue à cause de SELinux, examinez les refus et générez une politique ciblée :
ausearch -m avc -ts recent | grep -iE "valkey|redis"
```

### 21.4 Durcissement du service (systemd)

Renforcez l'isolation avec un drop-in plutôt qu'en éditant l'unit original :

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

### 21.5 Démarrage et vérification

```bash
systemctl enable --now valkey
systemctl status valkey --no-pager

# Connexion par socket avec authentification
valkey-cli -s /run/valkey/valkey.sock
#   AUTH "votre_mot_de_passe"
#   PING            -> doit répondre PONG
#   exit

# Confirmez qu'il n'y a PAS de port TCP en écoute (doit être vide)
ss -tlnp | grep 6379
```

### 21.6 Intégration avec Laravel

Confirmez l'extension phpredis (compilée en C, plus rapide que Predis ; pas besoin de `predis/predis` via Composer si vous utilisez celle-ci) :

```bash
php -m | grep -i redis
# si absent :
dnf install -y php-redis && systemctl reload php-fpm
```

Dans le `.env` de chaque plateforme, pointant vers le socket et **séparant** ce qui est évictable (cache, dans une DB) de ce qui ne doit pas disparaître (sessions/files, dans une autre). Avec socket Unix, `REDIS_PORT` doit être `0` :

```env
REDIS_CLIENT=phpredis
REDIS_HOST=/run/valkey/valkey.sock
REDIS_PORT=0
REDIS_PASSWORD="votre_mot_de_passe"

REDIS_DB=0          # sessions et files (ne doivent pas être évictées)
REDIS_CACHE_DB=1    # cache (évictable avec allkeys-lru)

CACHE_STORE=redis
SESSION_DRIVER=redis
QUEUE_CONNECTION=redis
```

> **Le `prefix` compte avec plusieurs plateformes.** Toutes vos apps partagent le même Valkey. Le préfixe de clés par défaut de Laravel dérive de `APP_NAME`, donc assurez-vous que chaque plateforme a un `APP_NAME` différent (ou un `REDIS_PREFIX` explicite) ou les clés de cache d'une écraseront celles de l'autre.

Comme vous avez le config en cache, **les changements au `.env` ne prennent pas effet tant que vous ne régénérez pas le cache** :

```bash
php artisan config:clear && php artisan config:cache

php artisan tinker
>>> Cache::store('redis')->put('test', 'ok', 60); Cache::store('redis')->get('test');   # -> "ok"
```

> **Les variables s'appellent toujours `REDIS_*` et le driver est `redis`** : c'est juste le nom du client. En dessous, il parle à Valkey sans le savoir ni s'en soucier.

**Inspection des clés.** Comme nous avons désactivé `KEYS`, utilisez `SCAN` (ne bloque pas le serveur). Depuis le shell, `--scan` itère seul :

```bash
export REDISCLI_AUTH="votre_mot_de_passe"     # évite d'exposer le mot de passe dans l'historique
valkey-cli -s /run/valkey/valkey.sock -n 1 --scan                       # toutes les clés de cache (DB 1)
valkey-cli -s /run/valkey/valkey.sock -n 1 --scan --pattern "monapp_*"  # filtre par préfixe d'app
valkey-cli -s /run/valkey/valkey.sock INFO keyspace                     # comptage par DB d'un coup d'œil
```

> **Ordre sécurisé :** installez et vérifiez Valkey complètement (jusqu'à ce que `PING` réponde `PONG`) **avant** de modifier les `.env`. Ainsi, si quelque chose échoue dans la connexion, vous ne laissez pas les apps sans cache ni session.

---

## 22. Protection des formulaires publics (Turnstile + rate limiting)

Les formulaires d'inscription publics sont la cible de créations massives automatisées de faux comptes. Sur ce serveur, les logs ont montré plusieurs IPs (plages de fournisseurs d'hébergement, pas d'utilisateurs réels) effectuant des `POST /inscription` avec succès de manière soutenue. Le rate limiting seul **ne suffit pas** car les bots font tourner les IPs : chacune reste en dessous du seuil. La défense efficace est en couches.

### 22.1 Cloudflare Turnstile (la pièce principale)

Turnstile est un CAPTCHA gratuit et respectueux de la vie privée. Le point critique est que la validation se produise **côté serveur**, pas seulement en rendant le widget : un bot faisant un POST direct sans passer par le navigateur doit être rejeté de la même façon.

Service de vérification (`app/Services/TurnstileService.php`) :

```php
public function verify(string $token, string $ip): bool
{
    // Garde bon marché : token vide = on n'appelle même pas Cloudflare.
    // Évite le round-trip (avec son timeout) dans le cas d'abus le plus courant (POST sans token).
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
        return false;   // fail-closed : si Cloudflare ne répond pas, personne ne s'inscrit
    }
}
```

Dans le contrôleur, vérifiez **avant** de valider ou de toucher la base de données :

```php
if (! $this->turnstile->verify((string) $request->input('cf-turnstile-response'), $request->ip())) {
    return back()->withInput()->withErrors(['captcha' => 'Nous n\'avons pas pu vérifier que vous êtes humain.']);
}
```

Deux décisions de conception à avoir en tête : le `catch` retourne `false` (**fail-closed**), correct pour freiner les abus mais implique qu'une panne réseau avec Cloudflare bloquerait les inscriptions légitimes ; et si vous avez **plusieurs routes d'inscription** (ex. hôte et client), **les deux** doivent porter la vérification, ou les bots utiliseront celle qui n'est pas protégée.

### 22.2 Rate limiting spécifique (couche secondaire)

Ne supprimez pas le rate limiter en ajoutant Turnstile ; ils sont complémentaires. Pour la route d'inscription, quelque chose de plus agressif que le défaut :

```php
RateLimiter::for('inscription', function (Request $request) {
    return [
        Limit::perMinute(3)->by($request->ip()),
        Limit::perDay(10)->by($request->ip()),
    ];
});
```

### 22.3 Vérification d'email obligatoire (confinement)

Même si un compte parvient à s'inscrire, il ne doit rien pouvoir faire tant que son email n'est pas vérifié. Utilisez `MustVerifyEmail` sur le modèle `User` et le middleware `verified` sur les routes protégées. Cela transforme tout compte indésirable qui passerait en compte inerte.

### 22.4 Comment vérifier que ça fonctionne (les logs trompent)

Le log Apache **ne distingue pas** une inscription réussie d'un rejet Turnstile : les deux produisent un `302` (le succès redirige vers `/verification.notice` ; le rejet revient au formulaire avec `back()`). Donc voir des centaines de `302` sur `/inscription` **ne signifie pas** que des comptes sont créés. Le vrai thermomètre est la base de données :

```sql
SELECT COUNT(*) FROM users WHERE created_at >= CURDATE();
```

Si ce compteur reste à vos chiffres réels attendus (ou à zéro, si vous n'attendiez pas d'inscriptions légitimes) pendant que le log continue à montrer des tentatives, Turnstile fait son travail. **Les bots ne cesseront pas d'essayer** — vous continuerez à voir les `302` et les `POST` — mais ils ne créeront pas de comptes. Ne vous alarmez pas du bruit dans le log ; surveillez le `COUNT`.

> **Défense en profondeur réelle :** Turnstile tue l'inscription automatisée, le rate limiter attrape les plus persistants, le blocage du vhost (section 16) freine le scan avant d'atteindre PHP, et Fail2Ban (section 17) bannit les récidivistes au niveau pare-feu. Chaque couche couvre les lacunes des autres.

---

## 23. Optimisation des performances

Une fois le serveur sécurisé, voici les leviers de performance pour Laravel/Filament. **Dimensionnez avec des données, pas à l'intuition :** mesurez la consommation réelle sous charge avant de fixer des valeurs, et appliquez un changement à la fois en validant qu'il a aidé.

> **Étape zéro (critique) :** confirmez que chaque app est en production. `php artisan about` doit afficher `Environment = production` et `Debug Mode = OFF`. Avec `APP_DEBUG=true` sur un serveur public, toute exception expose des identifiants et des variables d'environnement au visiteur — c'est à la fois une fuite de sécurité et un coût de performance.

### 23.1 OPcache

Le défaut (`memory_consumption=128`, `max_accelerated_files=10000`) est insuffisant pour plusieurs apps Laravel + Filament : un seul projet avec son `vendor/` tourne autour de 8–12k fichiers, donc avec deux apps OPcache évince constamment. Dans `/etc/php.d/10-opcache.ini` :

```ini
opcache.enable=1
opcache.memory_consumption=512        ; augmenter de 128
opcache.interned_strings_buffer=32    ; augmenter de 8
opcache.max_accelerated_files=65000   ; augmenter de 10000
opcache.save_comments=1               ; NE PAS désactiver : Filament/Laravel utilisent des attributs
opcache.validate_timestamps=0         ; SEULEMENT si le déploiement réinitialise OPcache (voir ci-dessous)
opcache.revalidate_freq=0
```

Et activez le JIT PCRE (accélère le moteur regex des routes/validations), généralement désactivé :

```ini
; /etc/php.d/30-pcre.ini
pcre.jit=1
```

> `validate_timestamps=0` uniquement quand votre script de déploiement (section 19) se termine par une réinitialisation d'OPcache (`cachetool opcache:reset` ou `systemctl reload php-fpm`) ; sinon les changements de code ne seraient pas reflétés après un déploiement. Le **JIT PHP** (différent de celui de PCRE) peut rester désactivé : pour une charge liée à l'I/O comme Laravel, le bénéfice est marginal.

### 23.2 PHP-FPM : un pool par plateforme

Un seul pool `www` partagé par toutes les apps est fragile : un pic sur l'une peut priver les autres de workers, et elles tournent toutes comme `apache` avec le même log. La bonne approche est **un pool par plateforme**, chacun avec son utilisateur. Dans `/etc/php-fpm.d/monapp.conf` :

```ini
[monapp]
user = dante
group = apache
listen = /run/php-fpm/monapp.sock
listen.owner = apache
listen.group = apache
listen.mode = 0660

pm = ondemand                          ; trafic faible/moyen : libère la RAM en veille
pm.max_children = 20
pm.process_idle_timeout = 30s
pm.max_requests = 500                  ; recycle les workers -> évite les fuites mémoire

php_admin_value[memory_limit] = 384M   ; par pool, PAS le 1024M global
slowlog = /var/log/php-fpm/monapp-slow.log
request_slowlog_timeout = 5s
pm.status_path = /status
```

> Un `memory_limit` global élevé (ex. 1024M) est dangereux pour le web : 50 children × 1 Go = 50 Go théoriques. Gardez-le élevé pour la CLI (migrations, exports) mais limitez-le par pool. Mesurez le poids réel par processus sous charge pour dimensionner `max_children` :
> ```bash
> ps --no-headers -o rss -C php-fpm | awk '{s+=$1;n++} END {printf "%.0f MB moy, %d procs\n", s/n/1024, n}'
> ```

### 23.3 MySQL 8.4

> **Avertissement méthodologique :** affiner en profondeur un MySQL avec peu de données est prématuré. Ce qui apporte le plus de valeur au départ est **d'activer le slow query log** pour avoir de quoi travailler à l'arrivée du vrai trafic.

Dans `/etc/my.cnf.d/optimization.cnf` :

```ini
[mysqld]
# Diagnostics (le plus important au départ)
slow_query_log = ON
long_query_time = 1
log_queries_not_using_indexes = ON     ; bruyant ; désactivez après la phase initiale

# Redo log (en 8.4 remplace innodb_log_file_size ; le défaut ~48M est petit)
innodb_redo_log_capacity = 1G          ; nécessite un redémarrage de MySQL

# Adapté au matériel (SSD SATA, pas NVMe). 10000 est irréaliste pour ces disques.
innodb_io_capacity = 2000
innodb_io_capacity_max = 4000

tmp_table_size = 64M
max_heap_table_size = 64M
```

> **Ne descendez pas `innodb_flush_log_at_trx_commit` en dessous de 1** si vous gérez des données fiscales/comptables : ne sacrifiez pas l'intégrité transactionnelle pour un microbenchmark. Augmentez `innodb_buffer_pool_size` (le défaut peut être insuffisant) seulement à mesure que les données grossissent ; vous avez de la RAM en abondance.

### 23.4 Apache MPM event et HTTP/2

Avec PHP-FPM, le MPM doit être **event** (pas prefork). Définissez des limites explicites et confirmez HTTP/2 et la compression :

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

Et mettez agressivement en cache les assets compilés par Vite (noms avec hash → immuables), dans le VirtualHost :

```apache
<LocationMatch "^/build/.*\.(js|css|woff2?|svg|png|jpe?g|webp|avif)$">
    Header set Cache-Control "public, max-age=31536000, immutable"
</LocationMatch>
```

### 23.5 Ordre d'application sécurisé

1. `APP_ENV=production` + `APP_DEBUG=false` → `artisan optimize` + `filament:optimize`.
2. Valkey pour cache/session/file (section 21).
3. OPcache (mémoire, fichiers, `pcre.jit`) → `reload php-fpm`.
4. Pools FPM par plateforme, un à la fois.
5. MySQL : slow log d'abord (sans redémarrage), puis redo log + io_capacity (avec redémarrage).
6. `opcache.validate_timestamps=0` SEULEMENT quand le déploiement réinitialise déjà OPcache.
7. Apache MPM/HTTP2/compression → `reload httpd`.

Mesurez avant/après avec `ab`/`wrk` sur un endpoint représentatif, le `pm.status_path` de FPM, et `SHOW ENGINE INNODB STATUS` après des heures d'utilisation réelle.

---

## 24. Checklist finale de vérification

| Domaine | État souhaité | Comment vérifier |
|---|---|---|
| SELinux | Enforcing (jamais permissive/disabled) | `getenforce` |
| SSH | Port 4428, sans root, clés uniquement | `ssh -p 4428`, vérifier `sshd_config.d/` |
| Pare-feu | Seulement 4428, http, https | `firewall-cmd --list-all` |
| Ports fermés | 22, 3306, 3000 NON accessibles externement | scanner externe / `ss -tlpn` |
| MySQL | Bind 127.0.0.1, utilisateur avec privilèges minimaux | `ss -tlpn \| grep 3306` |
| PHP | 8.5.x, `expose_php = Off` | `php -v`, en-têtes HTTP |
| Node | Écoute sur 127.0.0.1, tourne en tant que `nodeapp` | `ss -tlpn \| grep 3000` |
| SSL | Certificat valide, redirection 80→443 | `certbot certificates` |
| En-têtes | HSTS, CSP, X-Frame, X-Content-Type, Referrer | scanner web / `curl -I` |
| Fuites de version | Pas de version dans `Server` ni `X-Powered-By` | `curl -I https://votre-domaine.com` |
| Fail2Ban | Jails sshd + apache + laravel-scan actives | `fail2ban-client status` |
| Valkey | Socket Unix uniquement, pas de port 6379, avec auth | `ss -tlnp \| grep 6379` (vide), `valkey-cli -s ... PING` |
| Cache/session Laravel | Driver `redis` pointant vers le socket | `php artisan about`, `tinker` avec `Cache::store('redis')` |
| Turnstile | Vérification côté serveur sur TOUTES les routes d'inscription | `COUNT(*) users WHERE created_at >= CURDATE()` stable |
| OPcache | mémoire/fichiers dimensionnés pour multi-app | `php -i \| grep opcache.max_accelerated_files` |
| MySQL slow log | Actif pour diagnostic | `SHOW VARIABLES LIKE 'slow_query_log'` |
| security.txt | Présent | visiter `/.well-known/security.txt` |
| Renouvellement SSL | Timer actif | `systemctl list-timers \| grep certbot` |
| Mises à jour | dnf-automatic actif | `systemctl status dnf-automatic.timer` |

---

## 25. Annexe : DNSSEC, GeoIP et PGP

**DNSSEC / erreur « lame delegation » (RRSIG).** Cette erreur **ne se règle pas sur le serveur**, mais dans le panneau de votre registrar de domaine. Cela signifie généralement que vous avez activé DNSSEC mais que les enregistrements **DS** (Delegation Signer) ne correspondent pas aux clés de vos serveurs de noms. Action : dans le panneau du domaine, vérifiez que DNSSEC est correctement configuré chez votre fournisseur DNS ; si vous ne comptez pas l'utiliser strictement, désactivez-le pour éliminer l'erreur.

**GeoIP (optionnel).** Si un portail est réservé à un usage dans un seul pays, vous pouvez bloquer par pays au niveau du pare-feu/Apache (mod_maxminddb) pour réduire drastiquement le trafic de scan provenant de datacenters étrangers. Implémentation plus complexe ; évaluez si le cas le justifie.

**Signature PGP du security.txt (optionnel).** Signer `security.txt` avec une clé PGP évite que, si quelqu'un altérait le fichier, les signalements de vulnérabilités arrivent à un imposteur. Pour un MVP ou un portail interne **ce n'est pas urgent** ; pour des portails gouvernementaux ou financiers **c'est recommandé**. Si vous l'implémentez : générez la paire avec `gpg`, publiez la clé publique et ajoutez `Encryption: https://votre-domaine.com/pgp-key.asc` au fichier.

---
