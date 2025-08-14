#!/usr/bin/env bash
# SelfhostedWP Automated Installer & Backup for Ubuntu
# Interactive multi-site installer with improved backup reporting

set -Eeuo pipefail

# --- Helpers ---
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
  if command_exists openssl; then
    openssl rand -base64 32 | tr -d '\n' | tr '+/' '-_' | cut -c1-24
  else
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

install_azure_cli() {
  if command_exists az; then
    info "Azure CLI already installed."
  else
    info "Installing Azure CLI..."
    curl -sL https://aka.ms/InstallAzureCLIDeb | bash
    info "Azure CLI installed."
  fi
}

get_root_domain() {
  local host="$1"
  local two_part_tlds="co.uk|org.uk|ac.uk|gov.uk|sch.uk|me.uk|net.uk|plc.uk|ltd.uk"
  if [[ "$host" =~ ([^.]+)\.([^.]+\.(co\.uk|org\.uk|ac\.uk|gov\.uk|sch\.uk|me\.uk|net\.uk|plc\.uk|ltd\.uk))$ ]]; then
    echo "${BASH_REMATCH[2]}"
  else
    echo "${host#*.}"
  fi
}

INVOKING_USER="${SUDO_USER:-root}"
INVOKING_GROUP="$(id -gn "$INVOKING_USER")"
SITES_LIST="/etc/selfhostedwp/sites.list"
BACKUP_CONF_PATH="/etc/selfhostedwp_backup.conf"
BACKUP_SCRIPT_PATH="/usr/local/bin/backup.sh"
FIRST_RUN=false

require_root
detect_ubuntu

if [[ ! -f "$SITES_LIST" ]]; then
  FIRST_RUN=true
  mkdir -p /etc/selfhostedwp
  touch "$SITES_LIST"
  chmod 600 "$SITES_LIST"
  info "Global setup: Created $SITES_LIST for site registry."
fi

if [[ "$FIRST_RUN" == true ]]; then
  info "Installing required packages..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y apache2 php libsasl2-modules libapache2-mod-php php-gd mariadb-server mariadb-client php-mysql mailutils php-gmp php-mbstring php-xml php-curl wget rsync unzip tar openssl curl
  apt-get install -y certbot python3-certbot-apache
  install_azure_cli
  info "Requirements installed."
fi

# --- Main interactive loop for multi-site setup ---
while true; do
  # --- Site prompts ---
  DEFAULT_HOST="www.example.com"
  while :; do
    ask "Enter your site hostname (FQDN, e.g. www.andykemp.com or dev.andykemp.com)" "$DEFAULT_HOST" SITE_HOST
    SITE_HOST="$(tolower "$SITE_HOST")"
    if is_valid_hostname "$SITE_HOST"; then break; else warn "Invalid hostname, try again."; fi
  done

  EMAIL_DOMAIN="$(get_root_domain "$SITE_HOST")"
  ask "ServerAdmin email (also used for Let's Encrypt)" "admin@${EMAIL_DOMAIN}" ADMIN_EMAIL

  WEBROOT="/var/www/${SITE_HOST}"

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

  # --- Apache & WordPress setup ---
  info "Enabling Apache modules..."
  a2enmod ssl rewrite headers >/dev/null

  info "Creating web root: $WEBROOT"
  mkdir -p "$WEBROOT"
  chown -R "$INVOKING_USER":"$INVOKING_GROUP" "$WEBROOT"
  chmod 755 "$WEBROOT"

  info "Fetching latest WordPress..."
  TMPDIR="$(mktemp -d)"
  pushd "$TMPDIR" >/dev/null
  wget -q https://wordpress.org/latest.tar.gz
  tar -xzf latest.tar.gz
  rsync -a wordpress/ "$WEBROOT"/
  popd >/dev/null
  rm -rf "$TMPDIR"

  info "Configuring MariaDB (database and user)..."
  systemctl enable --now mariadb
  mysql <<SQL
CREATE DATABASE IF NOT EXISTS \`${DB_NAME}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci;
CREATE USER IF NOT EXISTS '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASS}';
GRANT ALL PRIVILEGES ON \`${DB_NAME}\`.* TO '${DB_USER}'@'localhost';
FLUSH PRIVILEGES;
SQL

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

  # --- SSL prep ---
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

  # --- Apache vhost ---
  VHOST_FILE="/etc/apache2/sites-available/${SITE_HOST}.conf"
  info "Creating Apache vhost: $VHOST_FILE"

  cat > "$VHOST_FILE" <<APACHECONF
# Managed by install script
<VirtualHost *:80>
    ServerName ${SITE_HOST}
    Alias /.well-known/acme-challenge $WEBROOT/.well-known/acme-challenge
    <Directory "$WEBROOT/.well-known/acme-challenge">
        Options None
        AllowOverride None
        Require all granted
    </Directory>
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

  if command_exists ufw && ufw status | grep -q "Status: active"; then
    ufw allow 'Apache Full' || true
  fi

  info "Validating Apache configuration..."
  apache2ctl configtest

  info "Restarting Apache..."
  systemctl enable --now apache2
  systemctl restart apache2

  # --- Let's Encrypt ---
  if [[ "$SSL_OPTION" == "1" ]]; then
    info "Obtaining Let's Encrypt certificates for ${SITE_HOST}..."
    certbot certonly --webroot -w "$WEBROOT" -d "$SITE_HOST" \
      --email "$ADMIN_EMAIL" --agree-tos --no-eff-email || warn "Certbot failed. Self-signed cert remains in use."
    LE_LIVE_DIR="/etc/letsencrypt/live/${SITE_HOST}"
    if [[ -d "$LE_LIVE_DIR" ]]; then
      sed -i "s#SSLCertificateFile .*#SSLCertificateFile ${LE_LIVE_DIR}/fullchain.pem#g" "$VHOST_FILE"
      sed -i "s#SSLCertificateKeyFile .*#SSLCertificateKeyFile ${LE_LIVE_DIR}/privkey.pem#g" "$VHOST_FILE"
      info "Reloading Apache with Let's Encrypt certificate..."
      apache2ctl configtest
      systemctl reload apache2
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

  # --- Permissions ---
  info "Setting file permissions for WordPress..."
  chown -R www-data:www-data "$WEBROOT"
  find "$WEBROOT" -type d -exec chmod 755 {} \;
  find "$WEBROOT" -type f -exec chmod 644 {} \;
  chown -R www-data:www-data /var/www
  systemctl restart apache2

  # --- Update sites.list ---
  if ! grep -q "^$SITE_HOST|" "$SITES_LIST"; then
    echo "$SITE_HOST|$DB_NAME|$DB_USER|$WEBROOT|$VHOST_FILE|$SSL_OPTION" >> "$SITES_LIST"
    info "Site $SITE_HOST added to $SITES_LIST"
  else
    info "Site $SITE_HOST already exists in $SITES_LIST"
  fi

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
  echo "-------------------------------------------"

  ask "Would you like to set up another site? (y/n)" "n" SETUP_ANOTHER
  if [[ "${SETUP_ANOTHER,,}" != "y" ]]; then
    break
  fi
done

# --- Initial backup setup (FIRST RUN ONLY) ---
if [[ "$FIRST_RUN" == true ]]; then
  read -p "Enter the backup target location (Azure Blob SAS URL): " BACKUP_TARGET
  read -p "Enter the daily backup time (24h format, e.g. 02:00): " BACKUP_TIME
  CRON_HOUR=$(echo "$BACKUP_TIME" | cut -d: -f1)
  CRON_MIN=$(echo "$BACKUP_TIME" | cut -d: -f2)
  read -p "Enter the sender email address for backup reports: " REPORT_FROM
  read -p "Enter the recipient email address for backup reports: " REPORT_TO
  read -p "Enter the SMTP server (e.g. mail.smtp2go.com): " SMTP_SERVER
  read -p "Enter the SMTP port (default 587): " SMTP_PORT
  SMTP_PORT=${SMTP_PORT:-587}
  read -p "Enter the SMTP username: " SMTP_USER
  ask_hidden "Enter the SMTP password: " "" SMTP_PASS
  MAIL_DOMAIN="$(get_root_domain "$(hostname -f)")"

  cat > "$BACKUP_CONF_PATH" <<EOF
BACKUP_TARGET="$BACKUP_TARGET"
REPORT_FROM="$REPORT_FROM"
REPORT_TO="$REPORT_TO"
SITES_LIST="$SITES_LIST"
BACKUP_TIME="$BACKUP_TIME"
EOF

  # --- Install improved backup script ---
  cat > "$BACKUP_SCRIPT_PATH" <<'EOS'
#!/usr/bin/env bash
set -Eeuo pipefail

CONFIG_FILE="/etc/selfhostedwp_backup.conf"
if [[ ! -f "$CONFIG_FILE" ]]; then
  echo "Config file $CONFIG_FILE not found!"
  exit 1
fi
set -a; source "$CONFIG_FILE"; set +a

DATE_UTC="$(date -u '+%Y-%m-%d %H:%M:%S')"
HOSTNAME="$(hostname -s)"  # Use short hostname (webserver1)
SCRIPT_VERSION="1.3.0"
BACKUP_START="$(date -u '+%Y-%m-%d %H:%M:%S')"
Today="$(date +%A)"
Temp_Backup="/tmp/selfhostedwp_backup_$Today"
mkdir -p "$Temp_Backup"

BACKUP_STATUS="SUCCESS"
ERRORS=""
SITE_RESULTS=()

trap 'BACKUP_STATUS="FAILED"; ERRORS+="Backup script exited unexpectedly at line $LINENO.\n";' ERR

add_site_result() {
  local site="$1"
  local step="$2"
  local result="$3"
  local details="$4"
  SITE_RESULTS+=("Site: $site | Step: $step | Result: $result${details:+ | $details}")
}

copy_global() {
  local src="$1"
  local dest="$2"
  if cp "$src" "$dest" 2>/dev/null; then
    add_site_result "$src" "GLOBAL CONFIG" "SUCCESS" ""
  else
    BACKUP_STATUS="FAILED"
    ERRORS+="Global config backup failed: $src\n"
    add_site_result "$src" "GLOBAL CONFIG" "FAILED" "Could not copy"
  fi
}

copy_global /etc/postfix/main.cf "$Temp_Backup/main.cf"
copy_global /etc/postfix/sasl_passwd "$Temp_Backup/sasl_passwd"
copy_global /usr/local/bin/backup.sh "$Temp_Backup/backup.sh"
copy_global /etc/selfhostedwp_backup.conf "$Temp_Backup/selfhostedwp_backup.conf"
copy_global /etc/apache2/apache2.conf "$Temp_Backup/apache2.conf"
copy_global /etc/selfhostedwp/sites.list "$Temp_Backup/sites.list"

if [[ -d /var/cert/ ]]; then
  if tar -czf "$Temp_Backup/server_cert.tar.gz" -C /var cert 2>/dev/null; then
    add_site_result "/var/cert" "GLOBAL CERTS" "SUCCESS" "Tar archive created"
  else
    BACKUP_STATUS="FAILED"
    ERRORS+="Could not archive /var/cert\n"
    add_site_result "/var/cert" "GLOBAL CERTS" "FAILED" "Tar error"
  fi
fi

if [[ -d /etc/letsencrypt/ ]]; then
  if tar -czf "$Temp_Backup/server_letsencrypt.tar.gz" -C /etc letsencrypt 2>/dev/null; then
    add_site_result "/etc/letsencrypt" "GLOBAL CERTS" "SUCCESS" "Tar archive created"
  else
    BACKUP_STATUS="FAILED"
    ERRORS+="Could not archive /etc/letsencrypt\n"
    add_site_result "/etc/letsencrypt" "GLOBAL CERTS" "FAILED" "Tar error"
  fi
fi

if [[ ! -f "$SITES_LIST" ]]; then
  BACKUP_STATUS="FAILED"
  ERRORS+="sites.list not found at $SITES_LIST\n"
else
  mapfile -t SITES < "$SITES_LIST"
  for SITE_LINE in "${SITES[@]}"; do
    IFS='|' read -r SITE_DOMAIN DB_NAME DB_USER SITE_PATH VHOST_FILE SSL_OPTION <<< "$SITE_LINE"
    SITE_LABEL="$SITE_DOMAIN"
    if tar -czf "$Temp_Backup/${SITE_DOMAIN}.tar.gz" -C "$SITE_PATH" . 2>/dev/null; then
      add_site_result "$SITE_LABEL" "FILES" "SUCCESS" "WordPress files archived"
    else
      BACKUP_STATUS="FAILED"
      ERRORS+="Failed to archive site files for $SITE_DOMAIN\n"
      add_site_result "$SITE_LABEL" "FILES" "FAILED" "Tar error"
    fi
    if mysqldump "$DB_NAME" > "$Temp_Backup/${DB_NAME}.sql" 2>/dev/null; then
      add_site_result "$SITE_LABEL" "DATABASE" "SUCCESS" "mysqldump completed"
    else
      BACKUP_STATUS="FAILED"
      ERRORS+="Failed to dump database $DB_NAME\n"
      add_site_result "$SITE_LABEL" "DATABASE" "FAILED" "mysqldump error"
    fi
    if [[ -f "$VHOST_FILE" ]]; then
      if cp "$VHOST_FILE" "$Temp_Backup/${SITE_DOMAIN}.conf" 2>/dev/null; then
        add_site_result "$SITE_LABEL" "VHOST" "SUCCESS" "Apache vhost config copied"
      else
        BACKUP_STATUS="FAILED"
        ERRORS+="Failed to backup vhost for $SITE_DOMAIN\n"
        add_site_result "$SITE_LABEL" "VHOST" "FAILED" "Copy error"
      fi
    fi
    if [[ "$SSL_OPTION" == "1" && -d "/etc/letsencrypt/live/$SITE_DOMAIN" ]]; then
      if tar -czf "$Temp_Backup/${SITE_DOMAIN}_le_certs.tar.gz" -C "/etc/letsencrypt/live/$SITE_DOMAIN" . 2>/dev/null; then
        add_site_result "$SITE_LABEL" "LE_CERTS" "SUCCESS" "Let's Encrypt certs archived"
      else
        BACKUP_STATUS="FAILED"
        ERRORS+="Failed to archive LE certs for $SITE_DOMAIN\n"
        add_site_result "$SITE_LABEL" "LE_CERTS" "FAILED" "Tar error"
      fi
    fi
    if [[ "$SSL_OPTION" == "2" || "$SSL_OPTION" == "3" ]]; then
      if [[ -f "/var/cert/${SITE_DOMAIN}.crt" && -f "/var/cert/${SITE_DOMAIN}.key" ]]; then
        if cp "/var/cert/${SITE_DOMAIN}.crt" "$Temp_Backup/${SITE_DOMAIN}.crt" && cp "/var/cert/${SITE_DOMAIN}.key" "$Temp_Backup/${SITE_DOMAIN}.key"; then
          add_site_result "$SITE_LABEL" "CUSTOM_CERTS" "SUCCESS" "Custom certs copied"
        else
          BACKUP_STATUS="FAILED"
          ERRORS+="Failed to copy custom certs for $SITE_DOMAIN\n"
          add_site_result "$SITE_LABEL" "CUSTOM_CERTS" "FAILED" "Copy error"
        fi
      fi
      if [[ -f "/var/cert/selfsigned/${SITE_DOMAIN}.crt" && -f "/var/cert/selfsigned/${SITE_DOMAIN}.key" ]]; then
        if cp "/var/cert/selfsigned/${SITE_DOMAIN}.crt" "$Temp_Backup/${SITE_DOMAIN}_selfsigned.crt" && cp "/var/cert/selfsigned/${SITE_DOMAIN}.key" "$Temp_Backup/${SITE_DOMAIN}_selfsigned.key"; then
          add_site_result "$SITE_LABEL" "SELF_SIGNED_CERTS" "SUCCESS" "Self-signed certs copied"
        else
          BACKUP_STATUS="FAILED"
          ERRORS+="Failed to copy self-signed certs for $SITE_DOMAIN\n"
          add_site_result "$SITE_LABEL" "SELF_SIGNED_CERTS" "FAILED" "Copy error"
        fi
      fi
    fi
  done
fi

AZURE_UPLOAD_STATUS="SUCCESS"
if [[ -n "$BACKUP_TARGET" ]]; then
  AZURE_BLOB_URL="$BACKUP_TARGET"
  AZURE_ACCOUNT_NAME="$(echo "$AZURE_BLOB_URL" | awk -F[/:] '{print $4}' | awk -F. '{print $1}')"
  AZURE_CONTAINER_NAME="$(echo "$AZURE_BLOB_URL" | awk -F[/:] '{print $5}' | awk -F'?' '{print $1}')"
  AZURE_SAS_TOKEN="$(echo "$AZURE_BLOB_URL" | awk -F'?' '{print $2}')"
  if command -v az >/dev/null 2>&1; then
    if az storage blob upload-batch --account-name "$AZURE_ACCOUNT_NAME" --destination "$AZURE_CONTAINER_NAME" --source "$Temp_Backup" --sas-token "$AZURE_SAS_TOKEN" --destination-path "$Today" --overwrite; then
      AZURE_UPLOAD_STATUS="SUCCESS"
    else
      BACKUP_STATUS="FAILED"
      AZURE_UPLOAD_STATUS="FAILED"
      ERRORS+="Azure blob upload failed\n"
    fi
  else
    BACKUP_STATUS="FAILED"
    AZURE_UPLOAD_STATUS="FAILED"
    ERRORS+="Azure CLI not installed\n"
  fi
else
  BACKUP_STATUS="FAILED"
  AZURE_UPLOAD_STATUS="FAILED"
  ERRORS+="Backup target not configured\n"
fi

BACKUP_END="$(date -u '+%Y-%m-%d %H:%M:%S')"
DURATION=$(( $(date -ud "$BACKUP_END" +%s) - $(date -ud "$BACKUP_START" +%s) ))

# Compose email with UTF-8 encoding and custom From header
REPORT_SUBJECT="WP Backup Report — $BACKUP_STATUS - $HOSTNAME - $BACKUP_END"
REPORT_BODY=""
REPORT_BODY+="WP Backup Report — $BACKUP_STATUS\n"
REPORT_BODY+="Host: $HOSTNAME\n"
REPORT_BODY+="Date: $BACKUP_END UTC\n"
REPORT_BODY+="Backup Target (Azure Blob): $AZURE_CONTAINER_NAME\n"
REPORT_BODY+="Script Version: $SCRIPT_VERSION\n"
REPORT_BODY+="\nSummary:\n"
REPORT_BODY+="Azure upload: $AZURE_UPLOAD_STATUS\n"
if [[ -f "$SITES_LIST" ]]; then
  REPORT_BODY+="Sites backed up: ${#SITES[@]}\n"
fi
REPORT_BODY+="Errors: ${ERRORS:-None}\n"
REPORT_BODY+="\nDetails:\n"
for r in "${SITE_RESULTS[@]}"; do
  REPORT_BODY+="$r\n"
done
REPORT_BODY+="\nTiming:\n"
REPORT_BODY+="Backup started: $BACKUP_START UTC\n"
REPORT_BODY+="Backup ended:   $BACKUP_END UTC\n"
REPORT_BODY+="Duration: ${DURATION}s\n"
REPORT_BODY+="\nNext Scheduled Backup: ${BACKUP_TIME:-Not configured}\n"
REPORT_BODY+="\nScript: /usr/local/bin/backup.sh\n"

# Use sendmail to ensure correct From and UTF-8 encoding
{
  echo "From: WP Backup System <${REPORT_FROM}>"
  echo "To: ${REPORT_TO}"
  echo "Subject: ${REPORT_SUBJECT}"
  echo "Content-Type: text/plain; charset=UTF-8"
  echo
  echo -e "$REPORT_BODY"
} | sendmail -t

rm -rf "$Temp_Backup"
EOS

  chmod +x "$BACKUP_SCRIPT_PATH"

  CRON_JOB="$CRON_MIN $CRON_HOUR * * * $BACKUP_SCRIPT_PATH"
  CRONTAB_TMP=$(mktemp)
  crontab -l 2>/dev/null | grep -v "$BACKUP_SCRIPT_PATH" > "$CRONTAB_TMP" || true
  echo "$CRON_JOB" >> "$CRONTAB_TMP"
  crontab "$CRONTAB_TMP"
  rm -f "$CRONTAB_TMP"

  info "Backup script installed at $BACKUP_SCRIPT_PATH"
  info "Daily backup scheduled at $BACKUP_TIME"
  info "Backup configuration written to $BACKUP_CONF_PATH"

  info "Configuring Postfix for SMTP relay..."
  export DEBIAN_FRONTEND=noninteractive
  debconf-set-selections <<< "postfix postfix/mailname string $MAIL_DOMAIN"
  debconf-set-selections <<< "postfix postfix/main_mailer_type string 'Internet Site'"
  apt-get install -y postfix mailutils

  postconf -e "relayhost = [$SMTP_SERVER]:$SMTP_PORT"
  postconf -e "smtp_sasl_auth_enable = yes"
  postconf -e "smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd"
  postconf -e "smtp_sasl_security_options = noanonymous"
  postconf -e "smtp_tls_security_level = may"
  postconf -e "smtp_use_tls = yes"
  postconf -e "smtp_tls_CAfile = /etc/ssl/certs/ca-certificates.crt"
  postconf -e "myhostname = $(hostname -f)"
  postconf -e "myorigin = /etc/mailname"
  postconf -e "smtputf8_enable = no"

  echo "[$SMTP_SERVER]:$SMTP_PORT $SMTP_USER:$SMTP_PASS" > /etc/postfix/sasl_passwd
  postmap /etc/postfix/sasl_passwd
  chmod 600 /etc/postfix/sasl_passwd

  systemctl restart postfix

  info "Postfix SMTP relay configured."

  # --- Install report email ---
  SITE_REPORT="/tmp/wp_install_report_$(date +%Y%m%d_%H%M%S).txt"
  {
    echo "WP Install Report"
    echo
    echo "Sites configured:"
    while IFS='|' read -r domain db user path vhost ssl; do
      echo "- $domain (DB: $db, User: $user, Path: $path, VHost: $vhost, SSL: $ssl)"
    done < "$SITES_LIST"
  } > "$SITE_REPORT"

  {
    echo "From: WP Install <${REPORT_FROM}>"
    echo "To: ${REPORT_TO}"
    echo "Subject: WP Install Report"
    echo "Content-Type: text/plain; charset=UTF-8"
    echo
    cat "$SITE_REPORT"
  } | sendmail -t

  rm -f "$SITE_REPORT"
  info "Install report sent to $REPORT_TO"
fi

# --- Offer to run backup after install ---
read -p "Would you like to run a full backup now? (y/n): " RUN_NOW
if [[ "${RUN_NOW,,}" == "y" ]]; then
  info "Running backup..."
  sudo /usr/local/bin/backup.sh
fi
