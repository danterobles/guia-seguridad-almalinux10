# Guia de Instalação e Hardening de um Servidor AlmaLinux 10

**Objetivo:** Construir do zero um servidor de produção **altamente seguro** no **AlmaLinux 10**, capaz de hospedar tanto aplicações **Laravel (PHP 8.5 / Filament)** quanto aplicações **Node.js (LTS 24)**, atrás do Apache, com SSL do Let's Encrypt, SELinux em modo *Enforcing* e defesa ativa com Fail2Ban.

**Stack tecnológica:** AlmaLinux 10 · Apache 2.4 (MPM event + HTTP/2) · PHP 8.5 (php-fpm via Remi) · MySQL 8.4 · Valkey 8 · Node.js 24 LTS · Let's Encrypt · firewalld · SELinux · Fail2Ban · Cloudflare Turnstile

> **Como usar este documento.** Foi pensado como *runbook* (passo a passo reproduzível) e como referência de auditoria. Substitua os marcadores `seu-dominio.com`, `minhaapp`, `seu.ip.publico.aqui` e os nomes de usuário/BD pelos reais. Execute os comandos como `root` ou prefixando com `sudo`.

---

## Índice

1. [Convenções e arquitetura](#1-convenções-e-arquitetura)
2. [Preparação do sistema base](#2-preparação-do-sistema-base)
3. [Usuário administrativo e acesso SSH por chaves](#3-usuário-administrativo-e-acesso-ssh-por-chaves)
4. [SSH seguro (porta 4428 + hardening)](#4-ssh-seguro-porta-4428--hardening)
5. [Firewall (firewalld)](#5-firewall-firewalld)
6. [Fundamentos do SELinux que você precisa entender](#6-fundamentos-do-selinux-que-você-precisa-entender)
7. [Apache (servidor web / reverse proxy)](#7-apache-servidor-web--reverse-proxy)
8. [PHP 8.5 + PHP-FPM (para Laravel)](#8-php-85--php-fpm-para-laravel)
9. [MySQL 8 com privilégios mínimos](#9-mysql-8-com-privilégios-mínimos)
10. [Composer](#10-composer)
11. [Deploy de um projeto Laravel](#11-deploy-de-um-projeto-laravel)
12. [Node.js 24 LTS como serviço + reverse proxy](#12-nodejs-24-lts-como-serviço--reverse-proxy)
13. [Let's Encrypt (SSL) e renovação automática](#13-lets-encrypt-ssl-e-renovação-automática)
14. [Cabeçalhos de segurança HTTP](#14-cabeçalhos-de-segurança-http)
15. [Ocultar versões (information leakage)](#15-ocultar-versões-information-leakage)
16. [Bloqueio de bots por User-Agent e rotas de exploit](#16-bloqueio-de-bots-por-user-agent-e-rotas-de-exploit)
17. [Fail2Ban: defesa ativa](#17-fail2ban-defesa-ativa)
18. [security.txt e robots.txt](#18-securitytxt-e-robotstxt)
19. [Fluxo de deploy com Git](#19-fluxo-de-deploy-com-git)
20. [Atualizações automáticas e manutenção](#20-atualizações-automáticas-e-manutenção)
21. [Valkey (cache, sessões e filas)](#21-valkey-cache-sessões-e-filas)
22. [Proteção de formulários públicos (Turnstile + rate limiting)](#22-proteção-de-formulários-públicos-turnstile--rate-limiting)
23. [Otimização de desempenho](#23-otimização-de-desempenho)
24. [Checklist final de verificação](#24-checklist-final-de-verificação)
25. [Apêndice: DNSSEC, GeoIP e PGP](#25-apêndice-dnssec-geoip-e-pgp)

---

## 1. Convenções e arquitetura

**Estrutura de diretórios recomendada.** Tudo vive sob `/var/www`, que é o contexto que o SELinux já conhece de fábrica para o Apache:

```
/var/www/
├── minhaapp-laravel/       # projeto Laravel
│   ├── public/             # <- DocumentRoot do Apache (única pasta exposta)
│   ├── storage/            # escrita (httpd_sys_rw_content_t)
│   ├── bootstrap/cache/    # escrita (httpd_sys_rw_content_t)
│   └── .env                # NUNCA dentro de public/
└── minhaapp-node/          # projeto Node
    ├── dist/ ou build/
    └── .env
```

**Princípio orientador (regra de ouro do SELinux no AlmaLinux 10):** diante de qualquer coisa nova, lembre-se dos três pilares —
- **Porta** → `semanage port`
- **Arquivo/pasta** → `restorecon` / `semanage fcontext`
- **Permissão de ação** → `setsebool`

**Arquitetura de rede:**
- Apache escuta nas portas `80` e `443` (únicas portas web abertas para o exterior).
- PHP-FPM roda por socket Unix local (não exposto).
- MySQL escuta **somente** em `127.0.0.1:3306` (nunca exposto).
- Cada app Node roda em uma porta *loopback* (ex.: `127.0.0.1:3000`) e o Apache faz de **reverse proxy** com TLS. A porta do Node **não é aberta** no firewall.

---

## 2. Preparação do sistema base

```bash
# Garantir conectividade de rede se necessário
nmtui

# Atualizar todo o sistema
dnf update -y

# Repositórios base e utilitários
dnf install -y epel-release dnf-utils
dnf install -y vim git wget curl tar policycoreutils-python-utils setroubleshoot-server

# Fuso horário (ajuste para sua região)
timedatectl set-timezone America/Sao_Paulo

# Sincronização de hora
systemctl enable --now chronyd
```

> `policycoreutils-python-utils` fornece o `semanage`; `setroubleshoot-server` fornece o `sealert`, o tradutor de erros do SELinux. Ambos são indispensáveis para administrar o SELinux sem desativá-lo.

**Não use `net-tools` (obsoleto).** O AlmaLinux 10 já inclui `iproute2`: use `ss -tulpn` em vez de `netstat`.

**Confirme que o SELinux está ativo em modo Enforcing** (nunca o desative):

```bash
getenforce        # deve responder: Enforcing
sestatus
```

---

## 3. Usuário administrativo e acesso SSH por chaves

Trabalhar como `root` via SSH é a primeira porta que os bots atacam. Crie um usuário com `sudo` e sempre entre com ele.

**No servidor:**

```bash
adduser dante
passwd dante                 # senha forte
usermod -aG wheel dante      # 'wheel' = grupo sudo no AlmaLinux
```

**Na sua máquina local** (gere o par de chaves se não tiver):

```bash
ssh-keygen -t ed25519 -C "dante@laptop"
# Copie a chave pública para o servidor (ainda na porta 22 por enquanto)
ssh-copy-id dante@seu.ip.publico.aqui
```

Verifique que você consegue entrar **sem senha** com a chave antes de continuar. Se a chave não funcionar, **não** desabilite a autenticação por senha no próximo passo ou ficará bloqueado.

---

## 4. SSH seguro (porta 4428 + hardening)

No AlmaLinux 10 a configuração moderna do SSH é feita com arquivos *drop-in* dentro de `/etc/ssh/sshd_config.d/` (mais limpo e resistente a atualizações do que editar o arquivo principal).

```bash
cat > /etc/ssh/sshd_config.d/99-hardening.conf <<'EOF'
# Porta não padrão (reduz ruído de varreduras automatizadas)
Port 4428

# Somente IPv4/IPv6 conforme seu caso
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

> **Importante:** mudar a porta no SSH não é suficiente; o SELinux bloqueará a nova porta mesmo que o firewall a permita. É preciso rotulá-la.

```bash
# Informar ao SELinux da nova porta SSH
semanage port -a -t ssh_port_t -p tcp 4428

# Validar a sintaxe e reiniciar
sshd -t && systemctl restart sshd
```

Abra uma **segunda** sessão SSH na porta 4428 **antes** de fechar a atual, para confirmar o acesso:

```bash
ssh -p 4428 dante@seu.ip.publico.aqui
```

---

## 5. Firewall (firewalld)

Não desative o `firewalld`: no AlmaLinux 10 ele se integra perfeitamente com o SELinux e o Fail2Ban.

```bash
systemctl enable --now firewalld

# Remover o serviço SSH padrão (porta 22) e abrir a 4428
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

Resultado esperado: apenas `4428/tcp`, `http` e `https` abertos. As portas `22`, `3306` (MySQL) e as portas internas do Node **não devem aparecer**. Um scanner externo deve vê-las como fechadas/filtradas.

---

## 6. Fundamentos do SELinux que você precisa entender

O SELinux não bloqueia serviços "por capricho": ele garante que cada processo toque apenas o que tem permissão (política *deny by default*).

**O que NÃO requer configuração:**
- Servir conteúdo em `/var/www` pelas portas 80/443. Os arquivos criados lá herdam automaticamente o rótulo `httpd_sys_content_t`.

**O "porém" mais comum:** se você **mover** arquivos de `/home/usuario` para `/var/www` com `mv`, eles mantêm o rótulo de origem e o Apache retornará **403 Forbidden**. Solução universal:

```bash
restorecon -Rv /var/www/minhaapp
```

**Permissões de ação (booleanos) que você precisará:**

| Cenário | Comando |
|---|---|
| Laravel se conecta ao MySQL local | `setsebool -P httpd_can_network_connect_db on` |
| Apache faz reverse proxy para um app Node | `setsebool -P httpd_can_network_connect on` |
| Apache lê pastas fora do padrão | `setsebool -P httpd_enable_homedirs on` |

**Pastas onde Apache/Laravel precisam escrever:**

```bash
semanage fcontext -a -t httpd_sys_rw_content_t "/var/www/minhaapp/storage(/.*)?"
semanage fcontext -a -t httpd_sys_rw_content_t "/var/www/minhaapp/bootstrap/cache(/.*)?"
restorecon -Rv /var/www/minhaapp
```

> O flag `-P` no `setsebool` é **crucial**: faz a mudança persistir após reinicialização.

**Ferramentas de diagnóstico (em vez de desativar o SELinux):**

```bash
# Negações em tempo real
tail -f /var/log/audit/audit.log | grep denied

# Tradutor humano de erros
sealert -a /var/log/audit/audit.log
```

---

## 7. Apache (servidor web / reverse proxy)

```bash
dnf install -y httpd mod_ssl
systemctl enable --now httpd
```

Certifique-se de que os módulos de proxy (necessários para Node) e rewrite (para bloqueio de bots) estejam carregados:

```bash
# No AlmaLinux 10 normalmente já vêm ativos; verifique:
httpd -M | grep -E "proxy_module|proxy_http|proxy_wstunnel|rewrite|headers|ssl"
```

Se algum estiver faltando, os módulos ficam em `/etc/httpd/conf.modules.d/`. Normalmente `proxy`, `proxy_http`, `rewrite`, `headers` e `ssl` já estão habilitados; `proxy_wstunnel` pode precisar ser adicionado para WebSockets.

---

## 8. PHP 8.5 + PHP-FPM (para Laravel)

O PHP 8.5 já está disponível como módulo estável do Remi para Enterprise Linux 10.

```bash
# Repositório Remi para AlmaLinux 10
dnf install -y https://rpms.remirepo.net/enterprise/remi-release-10.rpm

# Selecionar o fluxo de módulo PHP 8.5
dnf module reset php -y
dnf module enable php:remi-8.5 -y

# Instalar PHP-FPM e extensões típicas do Laravel/Filament
dnf install -y php php-cli php-common php-fpm \
  php-mysqlnd php-pdo php-mbstring php-xml php-curl \
  php-gd php-zip php-bcmath php-intl php-opcache php-redis

systemctl enable --now php-fpm
php -v   # confirmar 8.5.x
```

**Pool do PHP-FPM sob o usuário do Apache.** Edite `/etc/php-fpm.d/www.conf` e garanta:

```ini
user = apache
group = apache
listen = /run/php-fpm/www.sock
listen.owner = apache
listen.group = apache
listen.mode = 0660
```

O pacote instala `/etc/httpd/conf.d/php.conf`, que encaminha os `.php` ao socket do PHP-FPM via `SetHandler "proxy:unix:/run/php-fpm/www.sock|fcgi://localhost"`. Não é necessário configurá-lo manualmente, salvo casos especiais.

```bash
systemctl restart php-fpm httpd
```

---

## 9. MySQL 8 com privilégios mínimos

```bash
dnf install -y mysql-server
systemctl enable --now mysqld

# Proteger a instalação (define root, remove anônimos, etc.)
mysql_secure_installation
```

**Vincule o MySQL somente ao localhost** (sem escutar na rede). Em `/etc/my.cnf.d/mysql-server.cnf`, dentro de `[mysqld]`:

```ini
bind-address = 127.0.0.1
```

```bash
systemctl restart mysqld
```

**Crie o banco de dados e um usuário com privilégios mínimos** (NÃO use `*.*` nem `WITH GRANT OPTION` para apps; esse é o padrão perigoso dos guias antigos):

```sql
CREATE DATABASE minhaapp CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE USER 'minhaapp'@'localhost' IDENTIFIED BY 'UmaSenhaLongaEAleatoria_2026!';

-- Somente privilégios sobre SEU banco de dados, nada mais
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, INDEX, DROP, REFERENCES
  ON minhaapp.* TO 'minhaapp'@'localhost';

FLUSH PRIVILEGES;
```

> O MySQL 8 usa `caching_sha2_password` por padrão, que é o recomendado. Recorra a `mysql_native_password` somente se uma biblioteca mais antiga exigir.

Se o Laravel retornar erros 500 ao conectar ao BD, quase sempre é o booleano do SELinux:

```bash
setsebool -P httpd_can_network_connect_db on
```

---

## 10. Composer

O Laravel moderno requer o Composer 2.x (não o 1.9 dos guias antigos):

```bash
php -r "copy('https://getcomposer.org/installer', 'composer-setup.php');"
php composer-setup.php --install-dir=/usr/local/bin --filename=composer
rm composer-setup.php
composer --version
```

---

## 11. Deploy de um projeto Laravel

```bash
mkdir -p /var/www/minhaapp
chown -R apache:apache /var/www/minhaapp

# Clone ou envie seu projeto para /var/www/minhaapp (veja a seção 19 para Git)
cd /var/www/minhaapp
composer install --no-dev --optimize-autoloader

# Permissões de escrita para o Laravel (Linux + SELinux)
chown -R apache:apache storage bootstrap/cache
semanage fcontext -a -t httpd_sys_rw_content_t "/var/www/minhaapp/storage(/.*)?"
semanage fcontext -a -t httpd_sys_rw_content_t "/var/www/minhaapp/bootstrap/cache(/.*)?"
restorecon -Rv /var/www/minhaapp

# Otimização do Laravel
php artisan config:cache
php artisan route:cache
php artisan view:cache
```

**VirtualHost do Laravel** em `/etc/httpd/conf.d/minhaapp.conf` (HTTP redirecionando para HTTPS; o bloco 443 será completado pelo Certbot, veja seções 13 e 14):

```apache
<VirtualHost *:80>
    ServerName seu-dominio.com
    DocumentRoot /var/www/minhaapp/public
    Redirect permanent / https://seu-dominio.com/
</VirtualHost>
```

> O `DocumentRoot` aponta para `public/`, mantendo `.env`, `vendor/` e o restante do código fora do alcance web.

**Cron do Laravel Scheduler** — deve rodar com o usuário do Apache para não quebrar permissões:

```bash
# crontab -u apache -e
* * * * * cd /var/www/minhaapp && php artisan schedule:run >> /dev/null 2>&1
```

---

## 12. Node.js 24 LTS como serviço + reverse proxy

Em maio de 2026, **Node.js 24 é a versão LTS ativa** recomendada para produção (Node 26 está na fase *Current*, ainda não é LTS).

### 12.1 Instalar o Node 24

```bash
# Repositório oficial NodeSource para o branch 24.x
curl -fsSL https://rpm.nodesource.com/setup_24.x | bash -
dnf install -y nodejs
node -v    # v24.x
npm -v
```

> Alternativa: `dnf module enable nodejs:24 && dnf install nodejs` pelo AppStream, se preferir não adicionar repositórios externos (pode estar uma ou duas *minor* atrás).

### 12.2 Usuário dedicado e código

Não rode o Node como `root`. Crie um usuário de sistema sem shell de login:

```bash
useradd --system --create-home --home-dir /var/www/minhaapp-node --shell /usr/sbin/nologin nodeapp
# Envie/clone seu app para /var/www/minhaapp-node e compile
cd /var/www/minhaapp-node
sudo -u nodeapp npm ci --omit=dev
sudo -u nodeapp npm run build   # se aplicável
```

### 12.3 Serviço systemd (mais limpo e seguro que PM2 como root)

Crie `/etc/systemd/system/minhaapp-node.service`:

```ini
[Unit]
Description=Meu App Node
After=network.target

[Service]
Type=simple
User=nodeapp
Group=nodeapp
WorkingDirectory=/var/www/minhaapp-node
# O app DEVE escutar em loopback: host 127.0.0.1, porta 3000
Environment=NODE_ENV=production
Environment=PORT=3000
Environment=HOST=127.0.0.1
ExecStart=/usr/bin/node dist/server.js
Restart=on-failure
RestartSec=5

# Hardening do serviço
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable --now minhaapp-node
systemctl status minhaapp-node
ss -tlpn | grep 3000      # deve escutar SOMENTE em 127.0.0.1:3000
```

> Certifique-se de que seu app leia `process.env.HOST` e `process.env.PORT` e **escute em `127.0.0.1`**, não em `0.0.0.0`. Assim a porta 3000 nunca será acessível pela internet, apenas pelo Apache.

### 12.4 Permitir o proxy no SELinux

Para que o Apache possa abrir uma conexão de rede para a porta do Node:

```bash
setsebool -P httpd_can_network_connect on
```

### 12.5 VirtualHost reverse proxy

`/etc/httpd/conf.d/minhaapp-node.conf`:

```apache
<VirtualHost *:80>
    ServerName node.seu-dominio.com
    Redirect permanent / https://node.seu-dominio.com/
</VirtualHost>

<VirtualHost *:443>
    ServerName node.seu-dominio.com

    ProxyPreserveHost On
    ProxyPass        / http://127.0.0.1:3000/
    ProxyPassReverse / http://127.0.0.1:3000/

    # Suporte a WebSocket (se seu app usar: Socket.io, etc.)
    RewriteEngine On
    RewriteCond %{HTTP:Upgrade} =websocket [NC]
    RewriteRule /(.*) ws://127.0.0.1:3000/$1 [P,L]

    # (Os cabeçalhos de segurança da seção 14 também se aplicam aqui)
    # (O Certbot adicionará as diretivas SSL aqui)

    ErrorLog  /var/log/httpd/minhaapp-node-error.log
    CustomLog /var/log/httpd/minhaapp-node-access.log combined
</VirtualHost>
```

```bash
apachectl configtest && systemctl restart httpd
```

> **Não abra a porta 3000 no firewalld.** O tráfego entra pela 443 (Apache, com TLS) e é encaminhado internamente. O Node permanece isolado.

---

## 13. Let's Encrypt (SSL) e renovação automática

```bash
dnf install -y certbot python3-certbot-apache

# Um certificado por domínio/subdomínio
certbot --apache -d seu-dominio.com
certbot --apache -d node.seu-dominio.com
```

O Certbot insere automaticamente as diretivas `SSLCertificateFile`, `SSLCertificateKeyFile` e `Include /etc/letsencrypt/options-ssl-apache.conf` nos seus VirtualHosts de 443.

**Renovação automática.** O pacote instala um *timer* do systemd que renova sem intervenção. Verifique:

```bash
systemctl list-timers | grep certbot
certbot renew --dry-run     # simulação para confirmar que a renovação funciona
```

---

## 14. Cabeçalhos de segurança HTTP

Esses cabeçalhos corrigem as descobertas típicas de scanners como web-check.xyz (HSTS, Clickjacking, MIME sniffing, XSS, CSP). Adicione-os dentro do bloco `<VirtualHost *:443>` de cada site.

```apache
# HSTS: impõe HTTPS por 2 anos (elegível para a preload list)
Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"

# Anti-clickjacking
Header always set X-Frame-Options "SAMEORIGIN"

# Evitar MIME sniffing
Header always set X-Content-Type-Options "nosniff"

# Política de referência
Header always set Referrer-Policy "strict-origin-when-cross-origin"

# Permissions-Policy (limita APIs do navegador)
Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"

# Content-Security-Policy: a mais poderosa contra XSS.
# Ajuste os domínios externos que você realmente usa (fontes, mapas, analytics).
Header always set Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://fonts.googleapis.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self';"

# Eliminar vazamentos de versão
ServerSignature Off
Header unset X-Powered-By
```

> **Nota sobre `X-XSS-Protection`:** esse cabeçalho está obsoleto e os navegadores modernos o ignoram (alguns recomendam `0`). A proteção real contra XSS hoje é uma boa **CSP**. Se seu scanner ainda o solicitar, você pode adicionar `Header set X-XSS-Protection "1; mode=block"`, mas não é aí que está a segurança real.

> **CSP é iterativa.** Comece com a política acima; se algo parar de carregar (um script externo, um mapa, Google Analytics), adicione esse domínio à diretiva correspondente. Para o Filament, `'self' 'unsafe-inline' 'unsafe-eval'` geralmente é suficiente.

```bash
apachectl configtest && systemctl restart httpd
```

---

## 15. Ocultar versões (information leakage)

Informar ao mundo "uso PHP 8.5.6 e Apache 2.4.63" é entregar aos atacantes o mapa exato de quais exploits tentar.

**Apache** — crie `/etc/httpd/conf.d/00-security.conf`:

```apache
ServerTokens Prod
ServerSignature Off
TraceEnable Off
```

**PHP** — em `/etc/php.ini`:

```ini
expose_php = Off
```

```bash
systemctl restart php-fpm httpd
```

Após isso, o cabeçalho `Server` dirá apenas `Apache` (sem versão) e `X-Powered-By: PHP/...` desaparecerá.

---

## 16. Bloqueio de bots por User-Agent e rotas de exploit

Os logs reais mostram dois tipos de ruído automatizado: scanners que se identificam com User-Agents conhecidos (`l9scan`, `zgrab`, `Nikto`, `CensysInspect`) e bots que requisitam caminhos que não existem na aplicação (`/.env`, `/.git/config`, `/vendor/phpunit/.../eval-stdin.php`, `/wp-config.php`). Vale a pena cortar ambos **no nível do VirtualHost**, antes que a requisição chegue ao PHP.

> **Lição aprendida — não ancore o User-Agent com `^`.** Uma versão anterior usava `RewriteCond %{HTTP_USER_AGENT} ^Nmap`, que só coincide se o UA *começar* exatamente com essa string. Bots como `l9scan` se anunciam como `Mozilla/5.0 (l9scan/2.0...)`, então a âncora os deixava passar. A regra correta busca a string em **qualquer parte** do User-Agent.

Coloque o bloqueio diretamente sob `<VirtualHost *:443>`, não dentro do `<Directory>`. O contexto de servidor é avaliado primeiro e de forma independente do `.htaccess` do Laravel, então o bloqueio se aplica a toda requisição sem depender do que o Laravel processar depois. Requer `RewriteEngine On` explícito neste contexto:

```apache
RewriteEngine On

# 1) Bloqueio por User-Agent — SEM âncora ^, para capturá-los em qualquer
#    parte da string (ex.: "Mozilla/5.0 (l9scan/...)" não passa mais)
RewriteCond %{HTTP_USER_AGENT} (l9explore|l9scan|l9tcpid|Nmap|Masscan|zgrab|Nikto|CensysInspect|leakix|libredtail|Gh0st) [NC]
RewriteRule ^ - [F,L]

# 2) User-Agent vazio em requisições que não sejam à raiz (bots crus)
RewriteCond %{HTTP_USER_AGENT} ^-?$
RewriteCond %{REQUEST_URI} !^/$
RewriteRule ^ - [F,L]

# 3) Bloqueio de arquivos ocultos (.env, .git, etc.)
#    EXCETO /.well-known (necessário para renovação do Let's Encrypt)
RewriteRule "(^|/)\.(?!well-known)" - [F,L]

# 4) Rotas de exploit conhecidas (PHPUnit eval-stdin, vendor, lixo .php)
RewriteCond %{REQUEST_URI} (eval-stdin\.php|/vendor/|/phpunit|/wp-|xmlrpc\.php|/phpinfo|/\.aws|/\.ssh) [NC]
RewriteRule ^ - [F,L]
```

> **O `/.well-known` é crítico.** Se você bloqueasse todos os dotfiles sem exceção, quebraria o desafio ACME do Certbot (`/.well-known/acme-challenge/`) e seu certificado pararia de ser renovado. O `(?!well-known)` o protege.

> **Não bloqueie `curl` por User-Agent.** Mesmo que apareça em varreduras, é a ferramenta que você mesmo usa para testes e health checks. Esse comportamento é melhor deixar para o Fail2Ban (bane por comportamento, não por nome), veja a seção 17.

A partir daqui, esses bots recebem **403 Forbidden** em vez de um 404. Isso é bom: o Fail2Ban (próxima seção) bane qualquer um que acumule 403.

```bash
apachectl configtest && systemctl restart httpd
```

**Resultado mensurável.** Em um caso real deste servidor, após aplicar o bloqueio, o log passou a registrar centenas de `403` diários contra varredura de `/.env`, `/.git/config`, `/wp-config.php` e `/.aws/credentials` que antes passavam como `404` inofensivos mas chegavam até o PHP. Um único IP de varredura agressiva (`45.148.10.95`) acumulou 220 bloqueios em um dia sem tocar na aplicação.

---

## 17. Fail2Ban: defesa ativa

O firewall é uma muralha passiva; o Fail2Ban é um guarda que lê os logs e bane IPs reincidentes no nível de rede.

```bash
dnf install -y fail2ban fail2ban-firewalld
```

**Configuração principal** — nunca edite `jail.conf`; crie `/etc/fail2ban/jail.local`:

```ini
[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 5
# Bane usando firewalld (integração nativa do AlmaLinux 10)
banaction = firewallcmd-rich-rules
# IMPORTANTE: adicione SEU IP fixo para não se auto-bloquear
ignoreip = 127.0.0.1/8 ::1 seu.ip.publico.aqui

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

**Filtro personalizado** para capturar a varredura de `.env`/`.git` e os 403 do bloqueio de User-Agent. Crie `/etc/fail2ban/filter.d/laravel-vulnerabilities.conf`:

```ini
[Definition]
# Captura 404 (busca de arquivos sensíveis) e 403 (bloqueios por User-Agent / dotfiles)
failregex = ^<HOST> -.*"GET .*\.(env|git|aws|yml|yaml|json).* HTTP/.*" (404|403)
            ^<HOST> -.*"GET .*(\.git|config|credentials).* HTTP/.*" (404|403)
            ^<HOST> -.*"(GET|POST) .* HTTP/.*" 403
ignoreregex =
```

> **Sobre o abuso de formulários públicos (registro, contato).** Os IPs que martelam `POST /registro` rotacionam endereços e usam User-Agents de navegador real, então um filtro por 403 não os captura: no nível HTTP são indistinguíveis de um humano. A defesa correta para isso **não é o Fail2Ban**, mas o Cloudflare Turnstile + rate limiting + verificação de e-mail (veja a seção 22). Se ainda assim quiser que o Fail2Ban reaja aos mais persistentes, você pode adicionar um filtro que conte os `429` (rate limit do Laravel) por IP, mas é defesa secundária, não a principal.

**Jaula** que usa esse filtro sobre seu log de acesso (ajuste o caminho ao seu `CustomLog`). Adicione ao final de `jail.local`:

```ini
[laravel-scan]
enabled  = true
port     = http,https
filter   = laravel-vulnerabilities
logpath  = /var/log/httpd/minhaapp-access.log
maxretry = 2
bantime  = 48h
findtime = 1h
```

**Ativar e verificar:**

```bash
systemctl enable --now fail2ban
fail2ban-client status
fail2ban-client status laravel-scan

# Testar o filtro contra seu log atual (conta "Hits")
fail2ban-regex /var/log/httpd/minhaapp-access.log /etc/fail2ban/filter.d/laravel-vulnerabilities.conf
```

**SELinux e o log personalizado.** Se o Fail2Ban não conseguir ler seu log com nome próprio, verifique seu contexto:

```bash
ls -Z /var/log/httpd/minhaapp-access.log   # deve ser httpd_log_t
restorecon -v /var/log/httpd/minhaapp-access.log
```

> Se precisar se desbanir: `fail2ban-client set laravel-scan unbanip 1.2.3.4`.

Com isso você tem **defesa em camadas**: o Apache identifica o bot e fecha a porta (403) → a tentativa fica no log → o Fail2Ban detecta o IP reincidente e o bloqueia no firewalld.

---

## 18. security.txt e robots.txt

**security.txt** (padrão para que pesquisadores reportem vulnerabilidades de forma responsável):

```bash
mkdir -p /var/www/minhaapp/public/.well-known
cat > /var/www/minhaapp/public/.well-known/security.txt <<'EOF'
Contact: mailto:seguranca@seu-dominio.com
Expires: 2027-01-01T00:00:00.000Z
Preferred-Languages: pt, en
EOF
restorecon -Rv /var/www/minhaapp/public/.well-known
```

**robots.txt** — para desestimular a indexação do painel administrativo (é apenas uma *sugestão* para crawlers legítimos; a segurança real do `/admin` é o login do Laravel/Filament):

```
User-agent: *
Disallow: /admin/
Disallow: /admin
Allow: /
```

---

## 19. Fluxo de deploy com Git

**Erro clássico:** `fatal: detected dubious ownership in repository`. Ocorre porque a pasta pertence ao `apache` mas você executa o Git como outro usuário.

```bash
git config --global --add safe.directory /var/www/minhaapp
```

**O problema real:** após `git pull`, os arquivos novos perdem o dono `apache` e/ou o contexto do SELinux, e o Apache retorna 403/500. O fluxo correto em produção:

```bash
git pull origin main
chown -R apache:apache /var/www/minhaapp
restorecon -Rv /var/www/minhaapp        # recupera rótulos SELinux
php /var/www/minhaapp/artisan optimize
```

**Automatize com um script de deploy** (`/usr/local/bin/deploy-minhaapp`):

```bash
#!/usr/bin/env bash
set -euo pipefail
cd /var/www/minhaapp
git pull origin main
composer install --no-dev --optimize-autoloader
php artisan migrate --force
php artisan config:cache && php artisan route:cache && php artisan view:cache
chown -R apache:apache /var/www/minhaapp
restorecon -Rv /var/www/minhaapp
echo "Deploy OK"
```

```bash
chmod +x /usr/local/bin/deploy-minhaapp
```

> **Por que o `restorecon` é vital:** o Git atribui uma etiqueta temporária aos arquivos novos; sem `restorecon`, o SELinux pode bloquear sua leitura com um 403 mesmo que `chmod`/`chown` estejam perfeitos.

Para Node, o equivalente reinicia o serviço: `... && systemctl restart minhaapp-node`.

---

## 20. Atualizações automáticas e manutenção

**Patches de segurança automáticos:**

```bash
dnf install -y dnf-automatic
# Em /etc/dnf/automatic.conf -> apply_updates = yes (ou apenas notificar)
systemctl enable --now dnf-automatic.timer
```

**Rotina manual recomendada:**

```bash
dnf update --security        # patches de segurança
certbot renew --dry-run      # confirmar renovação SSL
fail2ban-client status       # revisar banimentos
```

**Backups (mínimo viável):** programe um dump diário do MySQL e um backup de `/var/www` e `/etc/httpd`:

```bash
mysqldump --single-transaction --routines minhaapp | gzip > /backups/minhaapp-$(date +\%F).sql.gz
```

---

## 21. Valkey (cache, sessões e filas)

Para que o Laravel/Filament tenha bom desempenho em produção, mova o cache, as sessões e as filas do banco de dados para um armazenamento em memória. **O AlmaLinux 10 não inclui mais o Redis** (a Redis Labs mudou para licenças não-FOSS na versão 7.4 e a distro o removeu dos repositórios); o substituto oficial no AppStream é o **Valkey**, um fork com licença FOSS. É *drop-in*: o phpredis e o driver `redis` do Laravel falam com o Valkey sem precisar alterar nada no código da aplicação.

> **Por que Valkey e não Redis via Remi.** O Redis voltou a uma licença open source (AGPLv3) na versão 8.0 e há RPMs em `remi-modular`, mas isso vincularia as atualizações de segurança de um *datastore* (que guardará sessões) a um repositório de terceiros. O Valkey do AppStream oficial recebe patches pelo ciclo normal da distro, com menos sobrecarga de manutenção. Salvo que você precise de uma função muito nova do Redis 8.x, o Valkey é a opção recomendada.

### 21.1 Instalação

```bash
dnf install -y valkey
valkey-server --version
```

### 21.2 Configuração segura

O modelo de ameaça clássico do Redis/Valkey é "instância exposta à internet sem senha". Como aqui o Valkey vive no **mesmo servidor** que o Laravel, o mais seguro é **não expô-lo à rede de forma alguma**: socket Unix + sem porta TCP. Gere primeiro uma senha forte:

```bash
openssl rand -base64 48
```

Edite `/etc/valkey/valkey.conf` (muitas diretivas já existem comentadas; encontre-as e ajuste):

```conf
# --- REDE: não expor a nenhuma interface ---
bind 127.0.0.1 -::1
protected-mode yes
port 0                              # desativa TCP completamente; apenas socket Unix

# --- SOCKET UNIX: assim o Laravel se conecta ---
unixsocket /run/valkey/valkey.sock
unixsocketperm 770

# --- AUTENTICAÇÃO ---
requirepass "COLE_AQUI_A_SENHA_GERADA"

# --- MEMÓRIA E POLÍTICA ---
maxmemory 2gb                       # ajuste ao quanto você destinar
maxmemory-policy allkeys-lru        # cuidado com o typo: é allkeys-lru (com 'a')

# --- PERSISTÊNCIA (para não perder sessões/filas ao reiniciar) ---
appendonly yes
appendfsync everysec

# --- COMANDOS PERIGOSOS ---
rename-command FLUSHALL ""
rename-command FLUSHDB ""
rename-command KEYS ""                  # KEYS bloqueia o servidor em prod; Laravel não o usa
rename-command CONFIG "CONFIG_a8f3k2"   # renomeie para algo imprevisível em vez de apagar
```

> **Um typo aborta a inicialização.** Se o Valkey não levantar, verifique `systemctl status valkey`: a mensagem `FATAL CONFIG FILE ERROR` indica o número de linha exato do erro. Um valor com erro de digitação (ex.: `llkeys-lru` em vez de `allkeys-lru`) impede a inicialização, e como consequência o socket nunca é criado — daí um `No such file or directory` ao tentar conectar, que é sintoma, não a causa.

### 21.3 Diretório do socket, permissões e SELinux

O diretório do socket em `/run` é efêmero; crie-o de forma persistente com tmpfiles para que sobreviva a reinicializações:

```bash
echo 'd /run/valkey 0750 valkey valkey -' > /etc/tmpfiles.d/valkey.conf
systemd-tmpfiles --create
```

Para que o PHP-FPM (e o Netdata, se você o usar) leia o socket, adicione esses usuários ao grupo `valkey` — mesma lógica de associação a grupos que com `apache`:

```bash
usermod -aG valkey apache
usermod -aG valkey dante         # se seus pools FPM rodam como dante
usermod -aG valkey netdata       # se você monitora com Netdata
```

SELinux: ative o booleano de conexão web e rotule o diretório do socket se houver negações:

```bash
setsebool -P httpd_can_network_connect 1
semanage fcontext -a -t redis_var_run_t "/run/valkey(/.*)?" 2>/dev/null || true
restorecon -Rv /run/valkey

# Se o Valkey falhar por SELinux, revise as negações e gere uma política pontual:
ausearch -m avc -ts recent | grep -iE "valkey|redis"
```

### 21.4 Hardening do serviço (systemd)

Reforce o isolamento com um drop-in em vez de editar o unit original:

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

### 21.5 Inicialização e verificação

```bash
systemctl enable --now valkey
systemctl status valkey --no-pager

# Conexão por socket com autenticação
valkey-cli -s /run/valkey/valkey.sock
#   AUTH "sua_senha"
#   PING            -> deve responder PONG
#   exit

# Confirme que NÃO há porta TCP escutando (deve sair vazio)
ss -tlnp | grep 6379
```

### 21.6 Integração com Laravel

Confirme a extensão phpredis (compilada em C, mais rápida que o Predis; não precisa de `predis/predis` pelo Composer se usar esta):

```bash
php -m | grep -i redis
# se faltar:
dnf install -y php-redis && systemctl reload php-fpm
```

No `.env` de cada plataforma, apontando para o socket e **separando** o que é evictável (cache, em uma DB) do que não deve desaparecer (sessões/filas, em outra). Com socket Unix, `REDIS_PORT` deve ser `0`:

```env
REDIS_CLIENT=phpredis
REDIS_HOST=/run/valkey/valkey.sock
REDIS_PORT=0
REDIS_PASSWORD="sua_senha"

REDIS_DB=0          # sessões e filas (não devem ser desalojadas)
REDIS_CACHE_DB=1    # cache (evictável com allkeys-lru)

CACHE_STORE=redis
SESSION_DRIVER=redis
QUEUE_CONNECTION=redis
```

> **O `prefix` importa com múltiplas plataformas.** Todas as suas apps compartilham o mesmo Valkey. O prefixo de chaves padrão do Laravel deriva do `APP_NAME`, então certifique-se de que cada plataforma tenha um `APP_NAME` diferente (ou um `REDIS_PREFIX` explícito), ou as chaves de cache de uma pisarão nas da outra.

Como você tem o config em cache, **as mudanças no `.env` não terão efeito até que você regenere o cache**:

```bash
php artisan config:clear && php artisan config:cache

php artisan tinker
>>> Cache::store('redis')->put('test', 'ok', 60); Cache::store('redis')->get('test');   # -> "ok"
```

> **As variáveis ainda se chamam `REDIS_*` e o driver é `redis`**: é apenas o nome do cliente. Por baixo ele está falando com o Valkey sem saber nem se importar.

**Inspeção de chaves.** Como desativamos `KEYS`, use `SCAN` (não bloqueia o servidor). No shell, `--scan` itera sozinho:

```bash
export REDISCLI_AUTH="sua_senha"     # evita expor a senha no histórico do shell
valkey-cli -s /run/valkey/valkey.sock -n 1 --scan                       # todas as de cache (DB 1)
valkey-cli -s /run/valkey/valkey.sock -n 1 --scan --pattern "minhaapp_*"  # filtra por prefixo do app
valkey-cli -s /run/valkey/valkey.sock INFO keyspace                     # contagem por DB de uma vez
```

> **Ordem segura:** instale e verifique o Valkey completamente (até que `PING` responda `PONG`) **antes** de alterar os `.env`. Assim, se algo falhar na conexão, você não deixará os apps sem cache nem sessão.

---

## 22. Proteção de formulários públicos (Turnstile + rate limiting)

Os formulários de registro público são alvo de criação massiva e automatizada de contas falsas. Neste servidor, os logs mostraram múltiplos IPs (faixas de provedores de hospedagem, não usuários reais) fazendo `POST /registro` com sucesso de forma sustentada. O rate limiting por si só **não basta** porque os bots rotacionam IPs: cada um fica abaixo do limite. A defesa eficaz é em camadas.

### 22.1 Cloudflare Turnstile (a peça principal)

O Turnstile é um CAPTCHA gratuito e respeitoso da privacidade. O ponto crítico é que a validação ocorra **no servidor**, não apenas renderizando o widget: um bot que faça POST direto sem passar pelo navegador deve ser rejeitado igualmente.

Serviço de verificação (`app/Services/TurnstileService.php`):

```php
public function verify(string $token, string $ip): bool
{
    // Guarda barata: token vazio = nem chamamos o Cloudflare.
    // Evita o round-trip (com seu timeout) no caso de abuso mais comum (POST sem token).
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
        return false;   // fail-closed: se o Cloudflare não responder, ninguém se registra
    }
}
```

No controller, verifique **antes** de validar ou tocar no banco de dados:

```php
if (! $this->turnstile->verify((string) $request->input('cf-turnstile-response'), $request->ip())) {
    return back()->withInput()->withErrors(['captcha' => 'Não foi possível verificar que você é humano.']);
}
```

Duas decisões de design a ter consciência: o `catch` retorna `false` (**fail-closed**), correto para frear abuso mas implica que uma falha de rede com o Cloudflare bloquearia registros legítimos; e se você tiver **várias rotas de registro** (ex.: host e cliente), as **duas** devem ter a verificação, ou os bots usarão a desprotegida.

### 22.2 Rate limiting específico (camada secundária)

Não remova o rate limiter ao adicionar o Turnstile; são complementares. Para a rota de registro, algo mais agressivo que o padrão:

```php
RateLimiter::for('registro', function (Request $request) {
    return [
        Limit::perMinute(3)->by($request->ip()),
        Limit::perDay(10)->by($request->ip()),
    ];
});
```

### 22.3 Verificação de e-mail obrigatória (contenção)

Mesmo que uma conta consiga se registrar, não deve poder fazer nada até verificar seu e-mail. Use `MustVerifyEmail` no model `User` e o middleware `verified` nas rotas protegidas. Isso transforma qualquer conta lixo que passe em uma conta inerte.

### 22.4 Como verificar que está funcionando (o log engana)

O log do Apache **não distingue** um registro bem-sucedido de uma rejeição do Turnstile: ambos produzem um `302` (o sucesso redireciona para `/verification.notice`; a rejeição volta ao formulário com `back()`). Por isso, ver centenas de `302` em `/registro` **não significa** que contas estão sendo criadas. O termômetro real é o banco de dados:

```sql
SELECT COUNT(*) FROM users WHERE created_at >= CURDATE();
```

Se esse contador permanecer nos seus números reais esperados (ou em zero, se não esperava cadastros legítimos) enquanto o log continua mostrando tentativas, o Turnstile está fazendo seu trabalho. **Os bots não vão parar de tentar** — você continuará vendo os `302` e os `POST` — mas não criarão contas. Não se alarme com o ruído do log; monitore o `COUNT`.

> **Defesa em profundidade real:** o Turnstile elimina o registro automatizado, o rate limiter captura os mais insistentes, o bloqueio do vhost (seção 16) freia a varredura antes de chegar ao PHP, e o Fail2Ban (seção 17) bane reincidentes no nível de firewall. Cada camada cobre as lacunas das outras.

---

## 23. Otimização de desempenho

Uma vez que o servidor esteja protegido, estas são as alavancas de desempenho para Laravel/Filament. **Dimensione com dados, não no achismo:** meça o consumo real sob carga antes de fixar valores, e aplique uma mudança por vez validando que ela ajudou.

> **Passo zero (crítico):** confirme que cada app esteja em produção. `php artisan about` deve mostrar `Environment = production` e `Debug Mode = OFF`. Com `APP_DEBUG=true` em um servidor público, qualquer exceção expõe credenciais e variáveis de ambiente ao visitante — é ao mesmo tempo vazamento de segurança e custo de desempenho.

### 23.1 OPcache

O padrão (`memory_consumption=128`, `max_accelerated_files=10000`) fica curto para vários apps Laravel + Filament: um único projeto com seu `vendor/` tem em torno de 8–12k arquivos, então com dois apps o OPcache está constantemente desalojando. Em `/etc/php.d/10-opcache.ini`:

```ini
opcache.enable=1
opcache.memory_consumption=512        ; aumentar de 128
opcache.interned_strings_buffer=32    ; aumentar de 8
opcache.max_accelerated_files=65000   ; aumentar de 10000
opcache.save_comments=1               ; NÃO desligar: Filament/Laravel usam atributos
opcache.validate_timestamps=0         ; SOMENTE se o deploy resetar o OPcache (veja abaixo)
opcache.revalidate_freq=0
```

E habilite o JIT do PCRE (acelera o motor de regex de rotas/validação), que costuma vir desativado:

```ini
; /etc/php.d/30-pcre.ini
pcre.jit=1
```

> `validate_timestamps=0` apenas quando seu script de deploy (seção 19) terminar com um reset do OPcache (`cachetool opcache:reset` ou `systemctl reload php-fpm`); caso contrário, as mudanças de código não seriam refletidas após um deploy. O **JIT do PHP** (diferente do do PCRE) pode ficar desativado: para carga ligada a I/O como o Laravel, o benefício é marginal.

### 23.2 PHP-FPM: um pool por plataforma

Um único pool `www` compartilhado por todos os apps é frágil: um pico em um pode deixar os outros sem workers, e todos rodam como `apache` com o mesmo log. O correto é **um pool por plataforma**, cada um com seu usuário. Em `/etc/php-fpm.d/minhaapp.conf`:

```ini
[minhaapp]
user = dante
group = apache
listen = /run/php-fpm/minhaapp.sock
listen.owner = apache
listen.group = apache
listen.mode = 0660

pm = ondemand                          ; tráfego baixo/médio: libera RAM ao ficar ocioso
pm.max_children = 20
pm.process_idle_timeout = 30s
pm.max_requests = 500                  ; recicla workers -> evita vazamentos de memória

php_admin_value[memory_limit] = 384M   ; por pool, NÃO o 1024M global
slowlog = /var/log/php-fpm/minhaapp-slow.log
request_slowlog_timeout = 5s
pm.status_path = /status
```

> Um `memory_limit` global alto (ex.: 1024M) é perigoso para web: 50 children × 1 GB = 50 GB teóricos. Deixe-o alto para CLI (migrações, exports) mas limite por pool. Meça o peso real por processo sob carga para dimensionar `max_children`:
> ```bash
> ps --no-headers -o rss -C php-fpm | awk '{s+=$1;n++} END {printf "%.0f MB méd, %d procs\n", s/n/1024, n}'
> ```

### 23.3 MySQL 8.4

> **Aviso de método:** afinar profundamente um MySQL com poucos dados é prematuro. O de maior valor no início é **ativar o slow query log** para ter com o que trabalhar quando chegar tráfego real.

Em `/etc/my.cnf.d/optimization.cnf`:

```ini
[mysqld]
# Diagnóstico (o mais importante no início)
slow_query_log = ON
long_query_time = 1
log_queries_not_using_indexes = ON     ; ruidoso; desative após a fase inicial

# Redo log (no 8.4 substitui innodb_log_file_size; o padrão ~48M é pequeno)
innodb_redo_log_capacity = 1G          ; requer reinício do MySQL

# Adequado ao hardware (SSD SATA, não NVMe). 10000 é irreal para esses discos.
innodb_io_capacity = 2000
innodb_io_capacity_max = 4000

tmp_table_size = 64M
max_heap_table_size = 64M
```

> **Não baixe `innodb_flush_log_at_trx_commit` abaixo de 1** se você lida com dados fiscais/contábeis: não sacrifique integridade transacional por um microbenchmark. Aumente `innodb_buffer_pool_size` (o padrão pode ficar curto) somente conforme os dados crescerem; você tem RAM de sobra.

### 23.4 Apache MPM event e HTTP/2

Com PHP-FPM, o MPM deve ser **event** (não prefork). Defina os limites explícitos e confirme HTTP/2 e compressão:

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

E faça cache agressivo dos assets compilados pelo Vite (nomes com hash → imutáveis), dentro do VirtualHost:

```apache
<LocationMatch "^/build/.*\.(js|css|woff2?|svg|png|jpe?g|webp|avif)$">
    Header set Cache-Control "public, max-age=31536000, immutable"
</LocationMatch>
```

### 23.5 Ordem de aplicação segura

1. `APP_ENV=production` + `APP_DEBUG=false` → `artisan optimize` + `filament:optimize`.
2. Valkey para cache/sessão/fila (seção 21).
3. OPcache (memória, arquivos, `pcre.jit`) → `reload php-fpm`.
4. Pools FPM por plataforma, um de cada vez.
5. MySQL: slow log primeiro (sem reinício), depois redo log + io_capacity (com reinício).
6. `opcache.validate_timestamps=0` SOMENTE quando o deploy já resetar o OPcache.
7. Apache MPM/HTTP2/compressão → `reload httpd`.

Meça antes/depois com `ab`/`wrk` contra um endpoint representativo, o `pm.status_path` do FPM e `SHOW ENGINE INNODB STATUS` após horas de uso real.

---

## 24. Checklist final de verificação

| Área | Estado desejado | Como verificar |
|---|---|---|
| SELinux | Enforcing (nunca permissive/disabled) | `getenforce` |
| SSH | Porta 4428, sem root, apenas chaves | `ssh -p 4428`, revisar `sshd_config.d/` |
| Firewall | Apenas 4428, http, https | `firewall-cmd --list-all` |
| Portas fechadas | 22, 3306, 3000 NÃO acessíveis externamente | scanner externo / `ss -tlpn` |
| MySQL | Bind 127.0.0.1, usuário com privilégios mínimos | `ss -tlpn \| grep 3306` |
| PHP | 8.5.x, `expose_php = Off` | `php -v`, cabeçalhos HTTP |
| Node | Escuta em 127.0.0.1, roda como `nodeapp` | `ss -tlpn \| grep 3000` |
| SSL | Certificado válido, redirecionamento 80→443 | `certbot certificates` |
| Cabeçalhos | HSTS, CSP, X-Frame, X-Content-Type, Referrer | scanner web / `curl -I` |
| Vazamentos de versão | Sem versão em `Server` ou `X-Powered-By` | `curl -I https://seu-dominio.com` |
| Fail2Ban | Jails sshd + apache + laravel-scan ativos | `fail2ban-client status` |
| Valkey | Apenas socket Unix, sem porta 6379, com autenticação | `ss -tlnp \| grep 6379` (vazio), `valkey-cli -s ... PING` |
| Cache/sessão Laravel | Driver `redis` apontando para o socket | `php artisan about`, `tinker` com `Cache::store('redis')` |
| Turnstile | Verificação server-side em TODAS as rotas de registro | `COUNT(*) users WHERE created_at >= CURDATE()` estável |
| OPcache | memória/arquivos dimensionados para multi-app | `php -i \| grep opcache.max_accelerated_files` |
| MySQL slow log | Ativo para diagnóstico | `SHOW VARIABLES LIKE 'slow_query_log'` |
| security.txt | Presente | visitar `/.well-known/security.txt` |
| Renovação SSL | Timer ativo | `systemctl list-timers \| grep certbot` |
| Atualizações | dnf-automatic ativo | `systemctl status dnf-automatic.timer` |

---

## 25. Apêndice: DNSSEC, GeoIP e PGP

**DNSSEC / erro "lame delegation" (RRSIG).** Esse erro **não se resolve no servidor**, mas no painel do seu registrador de domínio. Geralmente significa que você ativou o DNSSEC mas os registros **DS** (Delegation Signer) não coincidem com as chaves dos seus servidores de nomes. Ação: no painel do domínio, verifique se o DNSSEC está corretamente configurado junto ao seu provedor DNS; se não for usá-lo estritamente, desative-o para eliminar o erro.

**GeoIP (opcional).** Se um portal é de uso exclusivo em um país, você pode bloquear por país no nível de firewall/Apache (mod_maxminddb) para reduzir drasticamente o tráfego de varredura proveniente de data centers estrangeiros. Implementação de maior esforço; avalie se o caso justifica.

**Assinatura PGP do security.txt (opcional).** Assinar o `security.txt` com uma chave PGP evita que, se alguém alterar o arquivo, os relatórios de vulnerabilidade cheguem a um impostor. Para um MVP ou portal interno **não é urgente**; para portais governamentais ou financeiros **é recomendado**. Se implementar: gere o par com `gpg`, publique a chave pública e adicione `Encryption: https://seu-dominio.com/pgp-key.asc` ao arquivo.

---
