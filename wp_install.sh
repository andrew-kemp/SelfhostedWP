#!/usr/bin/env bash
# LAMP + WordPress installer for Ubuntu
# Includes modular setup, backup script with Azure CLI, SMTP notification, scheduling, and install report

set -Eeuo pipefail

# -------------------- Global Variables --------------------
LOGFILE="/tmp/install_wordpress.log"
BACKUP_SCRIPT_PATH="/usr/local/bin/backup.sh"
BACKUP_CONF_PATH="/etc/selfhostedwp_backup.conf"
INSTALL_REPORT="/tmp/install_report_$(date +%Y%m%d_%H%M%S).txt"

# -------------------- Utility Functions --------------------
err()   { echo -e "\033[1;31mError:\033[0m $*" | tee -a "$LOGFILE" >&2; }
info()  { echo -e "\033[1;32m==>\033[0m $*" | tee -a "$LOGFILE"; }
warn()  { echo -e "\033[1;33m!!\033[0m $*" | tee -a "$LOGFILE"; }
trap 'code=$?; err "Script failed (exit=$code) at line $LINENO: $BASH_COMMAND"; exit $code' ERR

require_root() { [[ $EUID -eq 0 ]] || { err "Run as root (sudo bash $0)"; exit 1; }; }
command_exists() { command -v "$1" >/dev/null 2>&1; }
gen_password() { openssl rand -base64 32 | tr -d '\n' | tr '+/' '-_' | cut -c1-24; }

ask() {
  local prompt="$1"; local default="${2:-}"; local __outvar="$3"; local reply
  if [[ -n "$default" ]]; then
    read -r -p "$prompt [$default]: " reply || true
    reply="${reply:-$default}"
  else
    read -r -p "$prompt: " reply || true
  fi
  printf -v "$__outvar" '%s' "$reply"
}

ask_hidden() {
  local prompt="$1"; local default="${2:-}"; local __outvar="$3"; local reply
  if [[ -n "$default" ]]; then
    read -r -s -p "$prompt [$default]: " reply || true
    echo; reply="${reply:-$default}"
  else
    read -r -s -p "$prompt: " reply || true
    echo
  fi
  printf -v "$__outvar" '%s' "$reply"
}

tolower() { echo "$1" | tr '[:upper:]' '[:lower:]'; }
normalize_for_mysql() {
  local s="${1//[^a-zA-Z0-9]/_}"
  echo "${s:0:32}"
}
is_valid_hostname() {
  local h="$1"
  [[ ${#h} -le 253 ]] || return 1
  [[ "$h" =~ ^[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)*$ ]]
}

# -------------------- Modular Install Functions --------------------
install_packages() {
  info "Installing required packages..."
  apt-get update
  apt-get install -y apache2 php libsasl2-modules libapache2-mod-php php-gd mariadb-server mariadb-client php-mysql mailutils php-gmp php-mbstring php-xml php-curl wget rsync unzip tar openssl curl ufw fail2ban postfix
  info "Required packages installed."
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

setup_wordpress() {
  local WEBROOT="$1"
  info "Setting up WordPress at $WEBROOT..."
  mkdir -p "$WEBROOT"
  chown -R www-data:www-data "$WEBROOT"
  chmod 755 "$WEBROOT"
  TMPDIR="$(mktemp -d)"
  pushd "$TMPDIR" >/dev/null
  wget -q https://wordpress.org/latest.tar.gz
  tar -xzf latest.tar.gz
  rsync -a wordpress/ "$WEBROOT"/
  popd >/dev/null
  rm -rf "$TMPDIR"
  info "WordPress files placed at $WEBROOT."
}

setup_database() {
  local DB_NAME="$1"; local DB_USER="$2"; local DB_PASS="$3"
  info "Setting up MariaDB (database and user)..."
  systemctl enable --now mariadb
  mysql <<SQL
CREATE DATABASE IF NOT EXISTS \`${DB_NAME}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci;
CREATE USER IF NOT EXISTS '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASS}';
GRANT ALL PRIVILEGES ON \`${DB_NAME}\`.* TO '${DB_USER}'@'localhost';
FLUSH PRIVILEGES;
SQL
  info "Database $DB_NAME and user $DB_USER configured."
}

create_wp_config() {
  local WEBROOT="$1"; local DB_NAME="$2"; local DB_USER="$3"; local DB_PASS="$4"
  local WP_CONFIG="$WEBROOT/wp-config.php"
  info "Creating wp-config.php..."
  [[ -f "$WP_CONFIG" ]] && { warn "wp-config.php exists, backing up."; cp -a "$WP_CONFIG" "$WP_CONFIG.bak"; }
  SALTS="$(curl -fsSL https://api.wordpress.org/secret-key/1.1/salt/ || true)"
  [[ -z "$SALTS" ]] && SALTS=$(printf 'define("AUTH_KEY", "set-me");\n')
  cat > "$WP_CONFIG" <<WP
<?php
define('DB_NAME', '${DB_NAME}');
define('DB_USER', '${DB_USER}');
define('DB_PASSWORD', '${DB_PASS}');
define('DB_HOST', 'localhost');
define('DB_CHARSET', 'utf8mb4');
define('DB_COLLATE', '');
$SALTS
\$table_prefix = 'wp_';
define('DISALLOW_FILE_EDIT', true);
define('FS_METHOD', 'direct');
if ( ! defined( 'ABSPATH' ) ) define( 'ABSPATH', __DIR__ . '/' );
require_once ABSPATH . 'wp-settings.php';
WP
  info "wp-config.php created."
}

setup_postfix_smtp() {
  local SMTP_SERVER="$1" SMTP_PORT="$2" SMTP_USER="$3" SMTP_PASS="$4"
  info "Configuring Postfix SMTP relay..."
  debconf-set-selections <<< "postfix postfix/mailname string $(hostname -f)"
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
  info "Postfix configured."
}

deploy_backup_config() {
  local BACKUP_TARGET="$1" REPORT_FROM="$2" REPORT_TO="$3" WEBROOT="$4"
  cat > "$BACKUP_CONF_PATH" <<EOF
BACKUP_TARGET="$BACKUP_TARGET"
REPORT_FROM="$REPORT_FROM"
REPORT_TO="$REPORT_TO"
WEBSITE_PATH="$WEBROOT/"
WEB_CONFIG="/etc/apache2/sites-available/"
POSTFIX_CONFIG="/etc/postfix/main.cf"
SASL_PASSWD="/etc/postfix/sasl_passwd"
CERT_DIRECTORY="/var/cert"
EOF
  info "Backup config written to $BACKUP_CONF_PATH."
}

deploy_backup_script() {
  info "Deploying latest Azure CLI backup script..."
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
Temp_Backup="/tmp/temp_backup_$Today"
Backup_Archive="${Temp_Backup}/backup.tar.gz"
mkdir -p "$Temp_Backup"
tar -cpvzf "$Backup_Archive" "$WEBSITE_PATH" "$WEB_CONFIG" "$POSTFIX_CONFIG" "$SASL_PASSWD" "$CERT_DIRECTORY"
for DB in $(mysql -e "show databases" -s --skip-column-names | grep -Ev "^(information_schema|performance_schema|mysql|sys)$"); do
  mysqldump "$DB" > "$Temp_Backup/${DB}.sql"
done
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
echo "Removing the local temp files"
rm -rf "$Temp_Backup"
echo "Files removed"
echo "$Today backup was successful and uploaded to Azure Blob Storage." | mail -s "$Today web server backup complete" -r "$REPORT_FROM" "$REPORT_TO"
EOS
  chmod +x "$BACKUP_SCRIPT_PATH"
  info "Backup script installed at $BACKUP_SCRIPT_PATH."
}

schedule_backup() {
  local CRON_HOUR="$1" CRON_MIN="$2" SCRIPT_PATH="$3"
  local CRON_JOB="$CRON_MIN $CRON_HOUR * * * $SCRIPT_PATH"
  local CRONTAB_TMP=$(mktemp)
  crontab -l 2>/dev/null | grep -v "$SCRIPT_PATH" > "$CRONTAB_TMP" || true
  echo "$CRON_JOB" >> "$CRONTAB_TMP"
  crontab "$CRONTAB_TMP"
  rm -f "$CRONTAB_TMP"
  info "Backup scheduled at $CRON_HOUR:$CRON_MIN daily."
}

# -------------------- Main Script --------------------
require_root

# 1. Prompt for site/domain/database info
DEFAULT_HOST="www.example.com"
while :; do
  ask "Enter your site hostname (FQDN, e.g. www.andykemp.com or dev.andykemp.com)" "$DEFAULT_HOST" SITE_HOST
  SITE_HOST="$(tolower "$SITE_HOST")"
  if is_valid_hostname "$SITE_HOST"; then break; else warn "Invalid hostname, try again."; fi
done

EMAIL_DOMAIN="${SITE_HOST#*.}"
[[ "$EMAIL_DOMAIN" == "$SITE_HOST" ]] && EMAIL_DOMAIN="$SITE_HOST"
ask "ServerAdmin email (also used for Let's Encrypt)" "admin@${EMAIL_DOMAIN}" ADMIN_EMAIL

WEBROOT_DEFAULT="/var/www/${SITE_HOST}"
ask "Web root directory" "$WEBROOT_DEFAULT" WEBROOT

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

# SSL options (modularize as needed)
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

# 2. Install packages and Azure CLI
install_packages
install_azure_cli

# 3. Setup WordPress
setup_wordpress "$WEBROOT"

# 4. Setup Database
setup_database "$DB_NAME" "$DB_USER" "$DB_PASS"
create_wp_config "$WEBROOT" "$DB_NAME" "$DB_USER" "$DB_PASS"

# 5. Postfix SMTP relay
ask "SMTP server (e.g. mail.smtp2go.com)" "" SMTP_SERVER
ask "SMTP port" "587" SMTP_PORT
ask "SMTP username" "" SMTP_USER
ask_hidden "SMTP password" "" SMTP_PASS
setup_postfix_smtp "$SMTP_SERVER" "$SMTP_PORT" "$SMTP_USER" "$SMTP_PASS"

# 6. Backup config and script
ask "Backup target location (Azure Blob SAS URL)" "" BACKUP_TARGET
ask "Sender email for backup reports" "$ADMIN_EMAIL" REPORT_FROM
ask "Recipient email for backup reports" "$ADMIN_EMAIL" REPORT_TO
deploy_backup_config "$BACKUP_TARGET" "$REPORT_FROM" "$REPORT_TO" "$WEBROOT"
deploy_backup_script

# 7. Schedule backup
ask "Backup time (24h format, e.g. 02:00)" "02:00" BACKUP_TIME
CRON_HOUR=$(echo "$BACKUP_TIME" | cut -d: -f1)
CRON_MIN=$(echo "$BACKUP_TIME" | cut -d: -f2)
schedule_backup "$CRON_HOUR" "$CRON_MIN" "$BACKUP_SCRIPT_PATH"

# 8. Install Report
cat > "$INSTALL_REPORT" <<EOF
SelfhostedWP Install Report - $(date)

Site: https://${SITE_HOST}
DocumentRoot: ${WEBROOT}

Database name: ${DB_NAME}
Database user: ${DB_USER}
Database password: ${AUTOGEN_DB_PASS:+(auto-generated, see wp-config.php)${AUTOGEN_DB_PASS:-(hidden)}}

SSL: ${SSL_OPTION}
Backup location: ${BACKUP_TARGET}
Backup time (daily): ${BACKUP_TIME}

SMTP server: ${SMTP_SERVER}:${SMTP_PORT}
Report emails: From ${REPORT_FROM} -> To ${REPORT_TO}

Server hostname: $(hostname -f)
EOF

mail -s "SelfhostedWP install report: ${SITE_HOST}" -r "$REPORT_FROM" "$REPORT_TO" < "$INSTALL_REPORT"
info "Install report emailed to $REPORT_TO from $REPORT_FROM"
rm -f "$INSTALL_REPORT"

# 9. Test backup
echo
read -p "Would you like to run a test backup now to verify everything is working? (y/n): " RUN_TEST_BACKUP
if [[ "${RUN_TEST_BACKUP,,}" == "y" ]]; then
  info "Running test backup..."
  "$BACKUP_SCRIPT_PATH"
  info "Test backup completed. Please check your backup destination and notification email."
fi

info "Installation complete. Site: https://${SITE_HOST} DocumentRoot: ${WEBROOT}"
info "Database name: ${DB_NAME}, user: ${DB_USER}, password: ${DB_PASS}"
info "Backup scheduled at $BACKUP_TIME daily."