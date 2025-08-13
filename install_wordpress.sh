#!/usr/bin/env bash
# LAMP + WordPress installer for Ubuntu
# Prompts for a single site hostname (e.g., www.example.com or dev.example.com)
# Sets DocumentRoot to /var/www/<hostname>
# Installs Apache, PHP, MariaDB, configures SSL (Let's Encrypt, custom, or self-signed),
# creates DB/user, and prepares WordPress.
# Apache vhost is minimal: no ServerAlias, no Rewrite, only Redirect for HTTP->HTTPS.

set -Eeuo pipefail

# ---------- Helpers ----------
err() { echo "Error: $*" >&2; }
info() { echo -e "\033[1;32m==>\033[0m $*"; }
warn() { echo -e "\033[1;33m!!\033[0m $*"; }
trap 'code=$?; echo "Error: Script failed (exit=$code) at line $LINENO: $BASH_COMMAND" >&2; exit $code' ERR

require_root() {
  if [[ $EUID -ne 0 ]]; then
    err "This script must be run as root. Try: sudo bash $0"
    exit 1
  fi
}

command_exists() { command -v "$1" >/dev/null 2>&1; }

tolower() { echo "$1" | tr '[:upper:]' '[:lower:]'; }

normalize_for_mysql() {
  local s="${1//[^a-zA-Z0-9]/_}"
  echo "${s:0:32}"
}

ask() {
  local prompt="$1"
  local default="${2:-}"
  local __outvar="$3"
  local reply
  if [[ -n "$default" ]]; then
    read -r -p "$prompt [$default]: " reply || true
    reply="${reply:-$default}"
  else
    read -r -p "$prompt: " reply || true
  fi
  printf -v "$__outvar" '%s' "$reply"
}

ask_hidden() {
  local prompt="$1"
  local default="${2:-}"
  local __outvar="$3"
  local reply
  if [[ -n "$default" ]]; then
    read -r -s -p "$prompt [$default]: " reply || true
    echo
    reply="${reply:-$default}"
  else
    read -r -s -p "$prompt: " reply || true
    echo
  fi
  printf -v "$__outvar" '%s' "$reply"
}

gen_password() {
  if command -v openssl >/dev/null 2>&1; then
    # URL-safe base64, trimmed to 24 chars
    openssl rand -base64 32 | tr -d '\n' | tr '+/' '-_' | cut -c1-24
  else
    # Fallback to alphanumerics only
    tr -dc 'A-Za-z0-9' </dev/urandom | head -c 24
  fi
}

is_valid_hostname() {
  local h="$1"
  [[ ${#h} -le 253 ]] || return 1
  [[ "$h" =~ ^[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)*$ ]]
}

detect_ubuntu() {
  if ! grep -qi ubuntu /etc/os-release; then
    warn "This script targets Ubuntu. Proceeding anyway."
  fi
}

require_root
detect_ubuntu

INVOKING_USER="${SUDO_USER:-root}"
INVOKING_GROUP="$(id -gn "$INVOKING_USER")"

# ---------- Prompts (simplified to a single FQDN) ----------
DEFAULT_HOST="www.example.com"
while :; do
  ask "Enter your site hostname (FQDN, e.g. www.andykemp.com or dev.andykemp.com)" "$DEFAULT_HOST" SITE_HOST
  SITE_HOST="$(tolower "$SITE_HOST")"
  if is_valid_hostname "$SITE_HOST"; then break; else warn "Invalid hostname, try again."; fi
done

# Derive an email domain from the hostname for default ServerAdmin
EMAIL_DOMAIN="${SITE_HOST#*.}"
[[ "$EMAIL_DOMAIN" == "$SITE_HOST" ]] && EMAIL_DOMAIN="$SITE_HOST"
ask "ServerAdmin email (also used for Let's Encrypt)" "admin@${EMAIL_DOMAIN}" ADMIN_EMAIL

# Web root defaults to /var/www/<hostname>
WEBROOT_DEFAULT="/var/www/${SITE_HOST}"
ask "Web root directory" "$WEBROOT_DEFAULT" WEBROOT

# Database inputs
DB_NAME_DEFAULT="db_$(normalize_for_mysql "$SITE_HOST")"
DB_USER_DEFAULT="user_$(normalize_for_mysql "$SITE_HOST")"
ask "MariaDB database name" "$DB_NAME_DEFAULT" DB_NAME
ask "MariaDB username" "$DB_USER_DEFAULT" DB_USER

TMP_PASS="$(gen_password)"
ask_hidden "MariaDB user password (leave blank to autogenerate)" "" DB_PASS_INPUT
if [[ -z "${DB_PASS_INPUT}" ]]; then
  DB_PASS="$TMP_PASS"
  AUTOGEN_DB_PASS=true
else
  DB_PASS="$DB_PASS_INPUT"
  AUTOGEN_DB_PASS=false
fi

echo
echo "SSL options:"
echo "  1) Let's Encrypt (recommended, automated renewals)"
echo "  2) Use existing certificate files (provide paths)"
echo "  3) Generate self-signed certificate (for testing)"
ask "Choose SSL option (1/2/3)" "1" SSL_OPTION

CERT_FILE=""
KEY_FILE=""
CHAIN_FILE=""
if [[ "$SSL_OPTION" == "2" ]]; then
  ask "Path to certificate file (e.g., /var/cert/${SITE_HOST}.crt)" "/var/cert/${SITE_HOST}.crt" CERT_FILE
  ask "Path to key file (e.g., /var/cert/${SITE_HOST}.key)" "/var/cert/${SITE_HOST}.key" KEY_FILE
  ask "Path to CA chain file (optional, Enter to skip)" "" CHAIN_FILE
fi

# ---------- Packages ----------
info "Updating package list and installing required packages..."
apt-get update
apt-get install -y apache2 php libsasl2-modules libapache2-mod-php php-gd mariadb-server mariadb-client php-mysql mailutils php-gmp php-mbstring php-xml php-curl wget rsync unzip tar openssl curl

# SSL helpers if LE chosen
if [[ "$SSL_OPTION" == "1" ]]; then
  apt-get install -y certbot python3-certbot-apache
fi

# ---------- Apache setup ----------
info "Enabling Apache modules..."
a2enmod ssl rewrite headers >/dev/null

info "Creating web root: $WEBROOT"
mkdir -p "$WEBROOT"
chown -R "$INVOKING_USER":"$INVOKING_GROUP" "$WEBROOT"
chmod 755 "$WEBROOT"

# ---------- Download WordPress ----------
info "Fetching latest WordPress..."
TMPDIR="$(mktemp -d)"
pushd "$TMPDIR" >/dev/null
wget -q https://wordpress.org/latest.tar.gz
tar -xzf latest.tar.gz
rsync -a wordpress/ "$WEBROOT"/
popd >/dev/null
rm -rf "$TMPDIR"

# ---------- Database setup ----------
info "Configuring MariaDB (database and user)..."
systemctl enable --now mariadb

mysql <<SQL
CREATE DATABASE IF NOT EXISTS \`${DB_NAME}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci;
CREATE USER IF NOT EXISTS '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASS}';
GRANT ALL PRIVILEGES ON \`${DB_NAME}\`.* TO '${DB_USER}'@'localhost';
FLUSH PRIVILEGES;
SQL

# ---------- WordPress config ----------
info "Creating wp-config.php..."
WP_CONFIG="$WEBROOT/wp-config.php"
if [[ -f "$WP_CONFIG" ]]; then
  warn "wp-config.php already exists, backing up to wp-config.php.bak"
  cp -a "$WP_CONFIG" "$WP_CONFIG.bak"
fi

SALTS="$(curl -fsSL https://api.wordpress.org/secret-key/1.1/salt/ || true)"
if [[ -z "$SALTS" ]]; then
  warn "Could not fetch WordPress salts, generating placeholders."
  SALTS=$(cat <<'EOS'
define('AUTH_KEY',         'put your unique phrase here');
define('SECURE_AUTH_KEY',  'put your unique phrase here');
define('LOGGED_IN_KEY',    'put your unique phrase here');
define('NONCE_KEY',        'put your unique phrase here');
define('AUTH_SALT',        'put your unique phrase here');
define('SECURE_AUTH_SALT', 'put your unique phrase here');
define('LOGGED_IN_SALT',   'put your unique phrase here');
define('NONCE_SALT',       'put your unique phrase here');
EOS
)
fi

TABLE_PREFIX="wp_"
cat > "$WP_CONFIG" <<WP
<?php
define('DB_NAME', '${DB_NAME}');
define('DB_USER', '${DB_USER}');
define('DB_PASSWORD', '${DB_PASS}');
define('DB_HOST', 'localhost');
define('DB_CHARSET', 'utf8mb4');
define('DB_COLLATE', '');

/* Authentication Unique Keys and Salts. */
$SALTS

\$table_prefix = '${TABLE_PREFIX}';

/* Recommended hardening */
define('DISALLOW_FILE_EDIT', true);
define('FS_METHOD', 'direct');

/* Optional: set site URLs now (uncomment after HTTPS is set) */
// define('WP_HOME', 'https://${SITE_HOST}');
// define('WP_SITEURL', 'https://${SITE_HOST}');

/* That's all, stop editing! Happy publishing. */
if ( ! defined( 'ABSPATH' ) ) {
  define( 'ABSPATH', __DIR__ . '/' );
}
require_once ABSPATH . 'wp-settings.php';
WP

# ---------- SSL preparation ----------
SSL_DIRECTIVES=""
SELF_SIGNED_FOR_LE=false
if [[ "$SSL_OPTION" == "2" ]]; then
  SSL_DIRECTIVES=$(cat <<EOT
    SSLEngine on
    SSLCertificateFile ${CERT_FILE}
    SSLCertificateKeyFile ${KEY_FILE}
$( [[ -n "$CHAIN_FILE" ]] && echo "    SSLCertificateChainFile ${CHAIN_FILE}" )
EOT
)
elif [[ "$SSL_OPTION" == "3" ]]; then
  mkdir -p /var/cert
  SS_CERT="/var/cert/${SITE_HOST}.crt"
  SS_KEY="/var/cert/${SITE_HOST}.key"
  info "Generating self-signed cert for ${SITE_HOST}..."
  openssl req -x509 -nodes -newkey rsa:2048 -days 365 \
    -keyout "$SS_KEY" \
    -out "$SS_CERT" \
    -subj "/C=US/ST=State/L=City/O=${EMAIL_DOMAIN}/OU=IT/CN=${SITE_HOST}" >/dev/null 2>&1
  chmod 600 "$SS_KEY"
  SSL_DIRECTIVES=$(cat <<EOT
    SSLEngine on
    SSLCertificateFile ${SS_CERT}
    SSLCertificateKeyFile ${SS_KEY}
EOT
)
elif [[ "$SSL_OPTION" == "1" ]]; then
  # Temporary self-signed so Apache can start before LE issuance
  mkdir -p /var/cert/selfsigned
  SS_CERT="/var/cert/selfsigned/${SITE_HOST}.crt"
  SS_KEY="/var/cert/selfsigned/${SITE_HOST}.key"
  info "Generating temporary self-signed cert for ${SITE_HOST} (will be replaced by Let's Encrypt)..."
  openssl req -x509 -nodes -newkey rsa:2048 -days 2 \
    -keyout "$SS_KEY" \
    -out "$SS_CERT" \
    -subj "/C=US/ST=State/L=City/O=${EMAIL_DOMAIN}/OU=IT/CN=${SITE_HOST}" >/dev/null 2>&1
  chmod 600 "$SS_KEY"
  SELF_SIGNED_FOR_LE=true
  SSL_DIRECTIVES=$(cat <<EOT
    SSLEngine on
    SSLCertificateFile ${SS_CERT}
    SSLCertificateKeyFile ${SS_KEY}
EOT
)
fi

# ---------- Apache vhost ----------
VHOST_FILE="/etc/apache2/sites-available/${SITE_HOST}.conf"
info "Creating Apache vhost: $VHOST_FILE"

cat > "$VHOST_FILE" <<APACHECONF
# Managed by install script
<VirtualHost *:80>
    ServerName ${SITE_HOST}

    # Let’s Encrypt challenge support (do NOT redirect these)
    Alias /.well-known/acme-challenge /var/www/${SITE_HOST}/.well-known/acme-challenge
    <Directory "/var/www/${SITE_HOST}/.well-known/acme-challenge">
        Options None
        AllowOverride None
        Require all granted
    </Directory>

    # Redirect everything else to HTTPS
    RedirectMatch "^/(?!\\.well-known/acme-challenge/).*" https://${SITE_HOST}/

    ErrorLog \${APACHE_LOG_DIR}/${SITE_HOST}_error.log
    CustomLog \${APACHE_LOG_DIR}/${SITE_HOST}_access.log combined
</VirtualHost>

<VirtualHost *:443>
    ServerName ${SITE_HOST}
    ServerAdmin ${ADMIN_EMAIL}
    DocumentRoot ${WEBROOT}

    <Directory ${WEBROOT}/>
        AllowOverride All
        Require all granted
    </Directory>

    # Optional security headers
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set X-XSS-Protection "1; mode=block"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    Header always set Content-Security-Policy "upgrade-insecure-requests"
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"

$( [[ -n "$SSL_DIRECTIVES" ]] && echo "$SSL_DIRECTIVES" || echo "    # SSL directives will be inserted after certificate issuance" )

    ErrorLog \${APACHE_LOG_DIR}/${SITE_HOST}_ssl_error.log
    CustomLog \${APACHE_LOG_DIR}/${SITE_HOST}_ssl_access.log combined
</VirtualHost>
APACHECONF

a2ensite "${SITE_HOST}.conf" >/dev/null

# If UFW is active, open Apache Full
if command_exists ufw && ufw status | grep -q "Status: active"; then
  ufw allow 'Apache Full' || true
fi

info "Validating Apache configuration..."
apache2ctl configtest

info "Restarting Apache..."
systemctl enable --now apache2
systemctl restart apache2

# ---------- Let's Encrypt (optional) ----------
if [[ "$SSL_OPTION" == "1" ]]; then
  info "Obtaining Let's Encrypt certificates for ${SITE_HOST}..."
  certbot certonly --webroot -w "$WEBROOT" -d "$SITE_HOST" \
    --email "$ADMIN_EMAIL" --agree-tos --no-eff-email || warn "Certbot failed. Self-signed cert remains in use."

  LE_LIVE_DIR="/etc/letsencrypt/live/${SITE_HOST}"
  if [[ -d "$LE_LIVE_DIR" ]]; then
    # Replace temporary self-signed paths with LE paths
    sed -i "s#SSLCertificateFile .*#SSLCertificateFile ${LE_LIVE_DIR}/fullchain.pem#g" "$VHOST_FILE"
    sed -i "s#SSLCertificateKeyFile .*#SSLCertificateKeyFile ${LE_LIVE_DIR}/privkey.pem#g" "$VHOST_FILE"
    info "Reloading Apache with Let's Encrypt certificate..."
    apache2ctl configtest
    systemctl reload apache2

    # Ensure auto-renew reloads Apache
    systemctl enable certbot.timer || true
    mkdir -p /etc/letsencrypt/renewal-hooks/deploy
    cat > /etc/letsencrypt/renewal-hooks/deploy/reload-apache.sh <<'HOOK'
#!/usr/bin/env bash
systemctl reload apache2
HOOK
    chmod +x /etc/letsencrypt/renewal-hooks/deploy/reload-apache.sh
  else
    warn "Let's Encrypt live directory not found; continuing with self-signed cert."
  fi
fi

# ---------- Permissions ----------
info "Setting file permissions for WordPress..."
chown -R www-data:www-data "$WEBROOT"
find "$WEBROOT" -type d -exec chmod 755 {} \;
find "$WEBROOT" -type f -exec chmod 644 {} \;

# ---------- Summary ----------
echo
echo "-------------------------------------------"
echo "Installation complete!"
echo "Site: https://${SITE_HOST}"
echo "DocumentRoot: ${WEBROOT}"
echo "Apache vhost: ${VHOST_FILE}"
echo
echo "Database name: ${DB_NAME}"
echo "Database user: ${DB_USER}"
if [[ "$AUTOGEN_DB_PASS" == "true" ]]; then
  echo "Database password (auto-generated): ${DB_PASS}"
else
  echo "Database password: (as provided)"
fi
echo
if [[ "$SSL_OPTION" == "1" ]]; then
  if [[ -d "/etc/letsencrypt/live/${SITE_HOST}" ]]; then
    echo "SSL: Let's Encrypt (auto-renew enabled)"
  else
    echo "SSL: Temporary self-signed (Let's Encrypt failed; you can retry later)"
  fi
elif [[ "$SSL_OPTION" == "2" ]]; then
  echo "SSL: Custom certs"
  echo "  Cert: ${CERT_FILE}"
  echo "  Key:  ${KEY_FILE}"
  [[ -n "$CHAIN_FILE" ]] && echo "  Chain: ${CHAIN_FILE}"
else
  echo "SSL: Self-signed (development use)"
fi
echo
echo "Next steps:"
echo "- Visit https://${SITE_HOST} to complete the WordPress setup wizard."
echo "- For pretty permalinks, go to Settings -> Permalinks in WP admin after install."
echo "-------------------------------------------"
echo
echo "Apache config file contents:"
echo "-------------------------------------------"
cat /etc/apache2/sites-available/${SITE_HOST}.conf
echo "-------------------------------------------"