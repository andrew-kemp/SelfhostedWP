#!/usr/bin/env bash
# SelfhostedWP Automated Installer & Backup for Ubuntu
# Improved: Per-site SSL certs included in site backup archives, global configs also backed up
# Emails site setup summary to configured address after each site install

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

require_root
detect_ubuntu

INVOKING_USER="${SUDO_USER:-root}"
INVOKING_GROUP="$(id -gn "$INVOKING_USER")"

SITES_LIST="/etc/selfhostedwp/sites.list"
FIRST_RUN=false

if [[ ! -f "$SITES_LIST" ]]; then
  FIRST_RUN=true
  mkdir -p /etc/selfhostedwp
  touch "$SITES_LIST"
  chmod 600 "$SITES_LIST"
  info "Global setup: Created $SITES_LIST for site registry."
fi

# ---------- Prompts ----------
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

# ---------- Packages ----------
info "Updating package list and installing required packages..."
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y apache2 php libsasl2-modules libapache2-mod-php php-gd mariadb-server mariadb-client php-mysql mailutils php-gmp php-mbstring php-xml php-curl wget rsync unzip tar openssl curl

if [[ "$SSL_OPTION" == "1" ]]; then
  apt-get install -y certbot python3-certbot-apache
fi

install_azure_cli

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
    Alias /.well-known/acme-challenge $WEBROOT/.well-known/acme-challenge
    <Directory "$WEBROOT/.well-known/acme-challenge">
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

# ---------- Permissions ----------
info "Setting file permissions for WordPress..."
chown -R www-data:www-data "$WEBROOT"
find "$WEBROOT" -type d -exec chmod 755 {} \;
find "$WEBROOT" -type f -exec chmod 644 {} \;

info "Setting ownership for /var/www to www-data..."
chown -R www-data:www-data /var/www

info "Restarting Apache to ensure permissions are effective..."
systemctl restart apache2

# ---------- update sites.list ----------
if ! grep -q "^$SITE_HOST|" "$SITES_LIST"; then
  echo "$SITE_HOST|$DB_NAME|$DB_USER|$WEBROOT|$VHOST_FILE|$SSL_OPTION" >> "$SITES_LIST"
  info "Site $SITE_HOST added to $SITES_LIST"
else
  info "Site $SITE_HOST already exists in $SITES_LIST"
fi

# --------- Install/Update Backup Script ---------
BACKUP_SCRIPT_PATH="/usr/local/bin/backup.sh"
BACKUP_CONF_PATH="/etc/selfhostedwp_backup.conf"

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

  MAIL_DOMAIN="$EMAIL_DOMAIN"

  cat > "$BACKUP_CONF_PATH" <<EOF
BACKUP_TARGET="$BACKUP_TARGET"
REPORT_FROM="$REPORT_FROM"
REPORT_TO="$REPORT_TO"
SITES_LIST="$SITES_LIST"
EOF

  # Install embedded backup script
  cat > "$BACKUP_SCRIPT_PATH" <<'EOS'
#!/usr/bin/env bash
set -euo pipefail
CONFIG_FILE="/etc/selfhostedwp_backup.conf"
if [[ ! -f "$CONFIG_FILE" ]]; then
  echo "Config file $CONFIG_FILE not found!"
  exit 1
fi
set -a; source "$CONFIG_FILE"; set +a

Today="$(date +%A)"
Temp_Backup="/tmp/selfhostedwp_backup_$Today"
mkdir -p "$Temp_Backup"

while IFS='|' read -r SITE_HOST DB_NAME DB_USER WEBROOT VHOST_FILE SSL_OPTION; do
  # Archive site files
  tar -czf "$Temp_Backup/${SITE_HOST}.tar.gz" -C "$WEBROOT" .

  # DB dump
  mysqldump "$DB_NAME" > "$Temp_Backup/db_${DB_NAME}.sql"

  # vhost conf
  cp "$VHOST_FILE" "$Temp_Backup/${SITE_HOST}.conf"

  # --- SITE CERTS ---
  # Let's Encrypt
  if [[ "$SSL_OPTION" == "1" && -d "/etc/letsencrypt/archive/$SITE_HOST" ]]; then
    TMP_LE_CERTS="$Temp_Backup/le_certs_${SITE_HOST}"
    mkdir -p "$TMP_LE_CERTS"
    # Copy most recent versions to generic filenames
    for t in cert chain fullchain privkey; do
      SRC=$(ls -1 /etc/letsencrypt/archive/$SITE_HOST/${t}*.pem 2>/dev/null | sort | tail -n1)
      if [[ -n "$SRC" && -f "$SRC" ]]; then
        cp "$SRC" "$TMP_LE_CERTS/${t}.pem"
      fi
    done
    # Copy README if present
    if [[ -f "/etc/letsencrypt/archive/$SITE_HOST/README" ]]; then
      cp "/etc/letsencrypt/archive/$SITE_HOST/README" "$TMP_LE_CERTS/README"
    fi
    tar -czf "$Temp_Backup/${SITE_HOST}_le_certs.tar.gz" -C "$TMP_LE_CERTS" .
    rm -rf "$TMP_LE_CERTS"
  fi

  # Custom/self-signed
  if [[ "$SSL_OPTION" == "2" || "$SSL_OPTION" == "3" ]]; then
    # Find typical cert/key paths
    if [[ -f "/var/cert/$SITE_HOST.crt" ]]; then
      cp "/var/cert/$SITE_HOST.crt" "$Temp_Backup/${SITE_HOST}.crt"
    fi
    if [[ -f "/var/cert/$SITE_HOST.key" ]]; then
      cp "/var/cert/$SITE_HOST.key" "$Temp_Backup/${SITE_HOST}.key"
    fi
    if [[ -d "/var/cert/selfsigned/" ]]; then
      # If using selfsigned, back up any matching files
      if [[ -f "/var/cert/selfsigned/$SITE_HOST.crt" ]]; then
        cp "/var/cert/selfsigned/$SITE_HOST.crt" "$Temp_Backup/${SITE_HOST}_selfsigned.crt"
      fi
      if [[ -f "/var/cert/selfsigned/$SITE_HOST.key" ]]; then
        cp "/var/cert/selfsigned/$SITE_HOST.key" "$Temp_Backup/${SITE_HOST}_selfsigned.key"
      fi
    fi
  fi
done < "$SITES_LIST"

cp "$SITES_LIST" "$Temp_Backup/sites.list"

# --- GLOBAL CONFIG FILES ---
cp /etc/postfix/main.cf "$Temp_Backup/main.cf"
cp /etc/postfix/sasl_passwd "$Temp_Backup/sasl_passwd"
cp /usr/local/bin/backup.sh "$Temp_Backup/backup.sh"
cp /etc/selfhostedwp_backup.conf "$Temp_Backup/selfhostedwp_backup.conf"
cp /etc/apache2/apache2.conf "$Temp_Backup/apache2.conf"
if [[ -d /var/cert/ ]]; then
  tar -czf "$Temp_Backup/server_cert.tar.gz" -C /var cert
fi
if [[ -d /etc/letsencrypt/ ]]; then
  tar -czf "$Temp_Backup/server_letsencrypt.tar.gz" -C /etc letsencrypt
fi

if command -v az >/dev/null 2>&1; then
  Azure_Blob_Url="$BACKUP_TARGET"
  Azure_Account_Name="$(echo "$Azure_Blob_Url" | awk -F[/:] '{print $4}' | awk -F. '{print $1}')"
  Azure_Container_Name="$(echo "$Azure_Blob_Url" | awk -F[/:] '{print $5}' | awk -F'?' '{print $1}')"
  Azure_SAS_Token="$(echo "$Azure_Blob_Url" | awk -F'?' '{print $2}')"
  echo "Uploading to Azure Blob Storage container: $Azure_Container_Name/$Today"
  az storage blob upload-batch \
    --account-name "$Azure_Account_Name" \
    --destination "$Azure_Container_Name" \
    --source "$Temp_Backup" \
    --sas-token "$Azure_SAS_Token" \
    --destination-path "$Today" \
    --overwrite
else
  echo "Azure CLI (az) not found! Please install Azure CLI to upload to Azure Blob Storage."
  exit 1
fi

rm -rf "$Temp_Backup"
echo "$Today backup was successful and uploaded to Azure Blob Storage." | mail -s "$Today web server backup complete" -a "From: SelfhostedWP <$REPORT_FROM>" "$REPORT_TO"
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

  echo "[$SMTP_SERVER]:$SMTP_PORT $SMTP_USER:$SMTP_PASS" > /etc/postfix/sasl_passwd
  postmap /etc/postfix/sasl_passwd
  chmod 600 /etc/postfix/sasl_passwd

  systemctl restart postfix

  info "Postfix SMTP relay configured."
  echo "SelfhostedWP backup install completed." | mail -s "Backup install test" -a "From: SelfhostedWP <$REPORT_FROM>" "$REPORT_TO"
  info "Test email sent to $REPORT_TO from $REPORT_FROM"
fi

# --------- Install Report and Test Backup ---------
echo
INSTALL_REPORT="/tmp/install_report_$(date +%Y%m%d_%H%M%S).txt"
cat > "$INSTALL_REPORT" <<EOF
SelfhostedWP Install Report - $(date)

Site: https://${SITE_HOST}
DocumentRoot: ${WEBROOT}

Database name: ${DB_NAME}
Database user: ${DB_USER}
Database password: ${AUTOGEN_DB_PASS:+(auto-generated, see wp-config.php)${AUTOGEN_DB_PASS:-(hidden)}}

SSL: ${SSL_OPTION}
Backup location: ${BACKUP_TARGET:-configured previously}
Backup time (daily): ${BACKUP_TIME:-configured previously}

SMTP server: ${SMTP_SERVER:-configured previously}:${SMTP_PORT:-configured previously}
Report emails: From ${REPORT_FROM:-configured previously} -> To ${REPORT_TO:-configured previously}

Server hostname: $(hostname -f)
EOF

if [[ "$FIRST_RUN" == true ]]; then
  mail -s "SelfhostedWP install report: ${SITE_HOST}" -a "From: SelfhostedWP <$REPORT_FROM>" "$REPORT_TO" < "$INSTALL_REPORT"
  info "Install report emailed to $REPORT_TO from $REPORT_FROM"
  rm -f "$INSTALL_REPORT"

  echo
  read -p "Would you like to run a test backup now to verify everything is working? (y/n): " RUN_TEST_BACKUP
  if [[ "${RUN_TEST_BACKUP,,}" == "y" ]]; then
    info "Running test backup..."
    /usr/local/bin/backup.sh
    info "Test backup completed. Please check your backup destination and notification email."
  fi
fi

# --------- EMAIL SITE CONFIG TO ADMIN AFTER EVERY INSTALL ---------
if [[ -f /etc/selfhostedwp_backup.conf ]]; then
  # Use configured REPORT_FROM and REPORT_TO from backup.conf
  source /etc/selfhostedwp_backup.conf
  SITE_REPORT="/tmp/site_report_${SITE_HOST}_$(date +%Y%m%d_%H%M%S).txt"
  cat > "$SITE_REPORT" <<EOF
New WordPress Site Installed: ${SITE_HOST}

Site: https://${SITE_HOST}
DocumentRoot: ${WEBROOT}
Apache vhost: ${VHOST_FILE}

Database name: ${DB_NAME}
Database user: ${DB_USER}
Database password: ${DB_PASS}

SSL option: ${SSL_OPTION}
EOF

  mail -s "New WordPress site installed: ${SITE_HOST}" -a "From: SelfhostedWP <$REPORT_FROM>" "$REPORT_TO" < "$SITE_REPORT"
  info "Site install report emailed to $REPORT_TO from $REPORT_FROM"
  rm -f "$SITE_REPORT"
fi

# Installation summary
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
