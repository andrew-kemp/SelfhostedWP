#!/usr/bin/env bash
# SelfhostedWP Full Restore + Backup Setup Script
# - Restores all/selected sites from Azure Blob backup
# - Resets DB/user/password and updates wp-config.php
# - Restores vhost configs and certs (real files, not symlinks)
# - Restores global config files (Postfix, Apache, backup.sh, etc.)
# - Copies sites.list to /etc/selfhostedwp/sites.list
# - Emails restore report and offers immediate backup

set -Eeuo pipefail

require_root() {
  if [[ $EUID -ne 0 ]]; then echo "Run as root." >&2; exit 1; fi
}

info() { echo -e "\033[1;32m==>\033[0m $*"; }
warn() { echo -e "\033[1;33m!!\033[0m $*"; }
gen_pw() { tr -dc A-Za-z0-9 </dev/urandom | head -c 20 ; echo ''; }
send_report() {
  local subject="$1"
  local report_file="$2"
  local from_email="$3"
  local to_email="$4"
  mail -s "$subject" -a "From: Restore <$from_email>" "$to_email" < "$report_file"
}

require_root

# --- Azure blob info ---
read -p "Azure Storage Account Name: " AZURE_ACCOUNT_NAME
read -p "Azure Blob Container Name: " AZURE_CONTAINER_NAME
read -p "Azure Blob SAS Token (after ?): " AZURE_SAS_TOKEN
echo "Backup day/folder to restore (e.g. Thursday). This is CASE SENSITIVE."
read -p "Enter backup day/folder: " DAY

LOCAL_DEST="/tmp/siterecovery"
mkdir -p "$LOCAL_DEST"

REQUIRED_COMMANDS=("az" "wget" "unzip" "tar" "rsync" "mysql")
all_tools_installed() {
  for cmd in "${REQUIRED_COMMANDS[@]}"; do
    if ! command -v "$cmd" &>/dev/null; then return 1; fi
  done
  return 0
}
if all_tools_installed; then
  info "All required modules are already installed. Skipping install step."
else
  info "Some required modules are missing. Installing prerequisites..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y azure-cli wget unzip tar rsync mariadb-client mailutils
fi

info "Listing blobs in '$DAY' folder of container '$AZURE_CONTAINER_NAME'..."
az storage blob list \
  --account-name "$AZURE_ACCOUNT_NAME" \
  --container-name "$AZURE_CONTAINER_NAME" \
  --prefix "$DAY/" \
  --sas-token "$AZURE_SAS_TOKEN" \
  --output table

info "Downloading blobs from '$DAY/' directly to '$LOCAL_DEST'..."
az storage blob download-batch \
  --account-name "$AZURE_ACCOUNT_NAME" \
  --destination "$LOCAL_DEST" \
  --source "$AZURE_CONTAINER_NAME" \
  --pattern "$DAY/*" \
  --sas-token "$AZURE_SAS_TOKEN" \
  --no-progress

if [[ -d "$LOCAL_DEST/$DAY" ]]; then
  mv "$LOCAL_DEST/$DAY"/* "$LOCAL_DEST/"
  rmdir "$LOCAL_DEST/$DAY"
  info "Moved downloaded files to '$LOCAL_DEST/' and removed '$LOCAL_DEST/$DAY' subfolder."
fi

SITES_FILE="$LOCAL_DEST/sites.list"
if [[ ! -f "$SITES_FILE" ]]; then
  warn "sites.list not found in $LOCAL_DEST! Manual restore only possible."
  exit 1
fi

BACKUP_SCRIPT_PATH="/usr/local/bin/backup.sh"
BACKUP_CONF_PATH="/etc/selfhostedwp_backup.conf"

# --- Restore global config files ---
if [[ -f "$LOCAL_DEST/main.cf" ]]; then
  sudo cp "$LOCAL_DEST/main.cf" /etc/postfix/main.cf
  info "Restored /etc/postfix/main.cf."
fi

if [[ -f "$LOCAL_DEST/sasl_passwd" ]]; then
  sudo cp "$LOCAL_DEST/sasl_passwd" /etc/postfix/sasl_passwd
  sudo chmod 600 /etc/postfix/sasl_passwd
  sudo postmap /etc/postfix/sasl_passwd
  info "Restored /etc/postfix/sasl_passwd and ran postmap."
fi

sudo systemctl restart postfix
info "Restarted Postfix after restoring configs."

if [[ -f "$LOCAL_DEST/backup.sh" ]]; then
  sudo cp "$LOCAL_DEST/backup.sh" "$BACKUP_SCRIPT_PATH"
  sudo chmod +x "$BACKUP_SCRIPT_PATH"
  info "Restored backup.sh."
else
  warn "backup.sh not found in $LOCAL_DEST!"
fi

if [[ -f "$LOCAL_DEST/selfhostedwp_backup.conf" ]]; then
  sudo cp "$LOCAL_DEST/selfhostedwp_backup.conf" "$BACKUP_CONF_PATH"
  sudo chmod 600 "$BACKUP_CONF_PATH"
  info "Restored selfhostedwp_backup.conf."
else
  warn "selfhostedwp_backup.conf not found in $LOCAL_DEST!"
fi

if [[ -f "$LOCAL_DEST/apache2.conf" ]]; then
  sudo cp "$LOCAL_DEST/apache2.conf" /etc/apache2/apache2.conf
  info "Restored /etc/apache2/apache2.conf."
fi

if [[ -f "$LOCAL_DEST/server_cert.tar.gz" ]]; then
  sudo tar -xzf "$LOCAL_DEST/server_cert.tar.gz" -C /var
  info "Restored /var/cert from server_cert.tar.gz."
fi
if [[ -f "$LOCAL_DEST/server_letsencrypt.tar.gz" ]]; then
  sudo tar -xzf "$LOCAL_DEST/server_letsencrypt.tar.gz" -C /etc
  info "Restored /etc/letsencrypt from server_letsencrypt.tar.gz."
fi

# --- Copy sites.list to /etc/selfhostedwp/sites.list ---
if [[ -f "$LOCAL_DEST/sites.list" ]]; then
  sudo mkdir -p /etc/selfhostedwp
  cp "$LOCAL_DEST/sites.list" /etc/selfhostedwp/sites.list
  chmod 600 /etc/selfhostedwp/sites.list
  info "Copied sites.list to /etc/selfhostedwp/sites.list."
else
  warn "sites.list not found in $LOCAL_DEST!"
fi

# --- Read email addresses and backup time from config file ---
if [[ -f "$BACKUP_CONF_PATH" ]]; then
  source "$BACKUP_CONF_PATH"
  REPORT_FROM="${REPORT_FROM:-}"
  REPORT_TO="${REPORT_TO:-}"
  BACKUP_TIME="${BACKUP_TIME:-}"
  BACKUP_TARGET="${BACKUP_TARGET:-}"
else
  warn "$BACKUP_CONF_PATH not found!"
  REPORT_FROM=""
  REPORT_TO=""
  BACKUP_TIME=""
  BACKUP_TARGET=""
fi

# --- If BACKUP_TIME is missing, prompt for it and update config ---
if [[ -z "$BACKUP_TIME" ]]; then
  read -p "Daily backup time (24h format, e.g. 02:00): " BACKUP_TIME
  sed -i "/^BACKUP_TIME=/d" "$BACKUP_CONF_PATH"
  echo "BACKUP_TIME=\"$BACKUP_TIME\"" >> "$BACKUP_CONF_PATH"
fi
CRON_HOUR=$(echo "$BACKUP_TIME" | cut -d: -f1)
CRON_MIN=$(echo "$BACKUP_TIME" | cut -d: -f2)

# --- Set up cron for backup.sh ---
CRON_JOB="$CRON_MIN $CRON_HOUR * * * $BACKUP_SCRIPT_PATH"
CRONTAB_TMP=$(mktemp)
crontab -l 2>/dev/null | grep -v "$BACKUP_SCRIPT_PATH" > "$CRONTAB_TMP" || true
echo "$CRON_JOB" >> "$CRONTAB_TMP"
crontab "$CRONTAB_TMP"
rm -f "$CRONTAB_TMP"
info "Scheduled backup.sh at $BACKUP_TIME daily."

# --- Interactive site selection ---
mapfile -t SITES < "$SITES_FILE"
echo "Sites available for recovery:"
for i in "${!SITES[@]}"; do
  SITE_DOMAIN="${SITES[$i]%%|*}"
  echo "$((i+1)). $SITE_DOMAIN"
done

echo ""
echo "Options:"
echo "  a. Recover ALL sites"
echo "  s. Select sites to recover (comma separated numbers)"
echo "  q. Quit"
read -p "Choose (a/s/q): " CHOICE

SELECTED_SITES=()
if [[ $CHOICE == "a" ]]; then
  SELECTED_SITES=("${SITES[@]}")
elif [[ $CHOICE == "s" ]]; then
  read -p "Enter comma-separated site numbers (e.g. 1,3): " NUMS
  IFS=',' read -ra IDS <<< "$NUMS"
  for n in "${IDS[@]}"; do
    idx=$((n-1))
    if [[ $idx -ge 0 && $idx -lt ${#SITES[@]} ]]; then
      SELECTED_SITES+=("${SITES[$idx]}")
    fi
  done
else
  echo "Quit."
  exit 0
fi

RESTORE_REPORT="/tmp/restore_report_$(date +%Y%m%d_%H%M%S).txt"
echo "Restore Report - $(date)" > "$RESTORE_REPORT"
echo "" >> "$RESTORE_REPORT"

# --- Restore each selected site ---
for SITE_LINE in "${SELECTED_SITES[@]}"; do
  IFS='|' read -r SITE_DOMAIN DB_NAME DB_USER SITE_PATH VHOST_FILE SSL_OPTION <<< "$SITE_LINE"
  info "Restoring site: $SITE_DOMAIN"

  # Restore WordPress files
  WP_ARCHIVE="$LOCAL_DEST/${SITE_DOMAIN}.tar.gz"
  if [[ -f "$WP_ARCHIVE" ]]; then
    info "Extracting WordPress files to $SITE_PATH ..."
    mkdir -p "$SITE_PATH"
    tar -xzf "$WP_ARCHIVE" -C "$SITE_PATH"
    chown -R www-data:www-data "$SITE_PATH"
  else
    warn "Site archive $WP_ARCHIVE not found for $SITE_DOMAIN."
  fi

  # Database setup: create DB, user, password, and grant privileges
  DB_BACKUP_FILE="$LOCAL_DEST/${DB_NAME}.sql"
  DB_PASS="$(gen_pw)"
  info "Creating database '$DB_NAME' and user '$DB_USER' with generated password..."
  sudo mysql -e "CREATE DATABASE IF NOT EXISTS \`${DB_NAME}\`;"
  sudo mysql -e "CREATE USER IF NOT EXISTS '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASS}';"
  sudo mysql -e "ALTER USER '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASS}';"
  sudo mysql -e "GRANT ALL PRIVILEGES ON \`${DB_NAME}\`.* TO '${DB_USER}'@'localhost';"
  sudo mysql -e "FLUSH PRIVILEGES;"

  # Restore DB
  if [[ -f "$DB_BACKUP_FILE" ]]; then
    info "Restoring database from $DB_BACKUP_FILE to $DB_NAME..."
    sudo mysql "${DB_NAME}" < "$DB_BACKUP_FILE"
    info "Database restored for $SITE_DOMAIN."
  else
    warn "Database backup $DB_BACKUP_FILE not found for $SITE_DOMAIN."
  fi

  # Update wp-config.php with new DB user and password
  WPCONFIG="${SITE_PATH}/wp-config.php"
  if [[ -f "$WPCONFIG" ]]; then
    sed -i "s/define(\s*'DB_USER',\s*'[^']*'/define('DB_USER', '${DB_USER}'/" "$WPCONFIG"
    sed -i "s/define(\s*'DB_PASSWORD',\s*'[^']*'/define('DB_PASSWORD', '${DB_PASS}'/" "$WPCONFIG"
    sed -i "s/define(\s*'DB_NAME',\s*'[^']*'/define('DB_NAME', '${DB_NAME}'/" "$WPCONFIG"
    info "Updated wp-config.php for $SITE_DOMAIN with new DB user and password."
  else
    warn "wp-config.php not found for $SITE_DOMAIN. Please update DB password manually."
  fi

  echo "Site: https://${SITE_DOMAIN}" >> "$RESTORE_REPORT"
  echo "Database name: ${DB_NAME}" >> "$RESTORE_REPORT"
  echo "Database user: ${DB_USER}" >> "$RESTORE_REPORT"
  echo "Database password: ${DB_PASS}" >> "$RESTORE_REPORT"
  echo "Webroot: ${SITE_PATH}" >> "$RESTORE_REPORT"
  echo "Apache vhost: ${VHOST_FILE}" >> "$RESTORE_REPORT"
  echo "" >> "$RESTORE_REPORT"

  # Restore vhost config
  VHOST_BACKUP="$LOCAL_DEST/${SITE_DOMAIN}.conf"
  if [[ -f "$VHOST_BACKUP" ]]; then
    info "Restoring Apache vhost config to $VHOST_FILE"
    mkdir -p "$(dirname "$VHOST_FILE")"
    cp "$VHOST_BACKUP" "$VHOST_FILE"
  else
    warn "Vhost config $VHOST_BACKUP not found for $SITE_DOMAIN."
  fi

  # Restore SSL certs if present (removes symlinks, restores real files)
  if [[ "$SSL_OPTION" == "1" && -f "$LOCAL_DEST/${SITE_DOMAIN}_le_certs.tar.gz" ]]; then
    info "Restoring Let's Encrypt certs for $SITE_DOMAIN"
    sudo mkdir -p "/etc/letsencrypt/live/$SITE_DOMAIN"
    for f in cert.pem chain.pem fullchain.pem privkey.pem; do
      if [[ -L "/etc/letsencrypt/live/$SITE_DOMAIN/$f" ]]; then
        sudo rm "/etc/letsencrypt/live/$SITE_DOMAIN/$f"
      fi
    done
    sudo tar -xzf "$LOCAL_DEST/${SITE_DOMAIN}_le_certs.tar.gz" -C "/etc/letsencrypt/live/$SITE_DOMAIN"
    sudo chown -R root:root "/etc/letsencrypt/live/$SITE_DOMAIN"
    if [[ ! -s "/etc/letsencrypt/live/$SITE_DOMAIN/fullchain.pem" || ! -s "/etc/letsencrypt/live/$SITE_DOMAIN/privkey.pem" ]]; then
      warn "Warning: Let's Encrypt certs not properly restored for $SITE_DOMAIN!"
    fi
  fi
  if [[ "$SSL_OPTION" == "2" || "$SSL_OPTION" == "3" ]]; then
    if [[ -f "$LOCAL_DEST/${SITE_DOMAIN}.crt" ]]; then
      sudo mkdir -p "/var/cert"
      sudo cp "$LOCAL_DEST/${SITE_DOMAIN}.crt" "/var/cert/${SITE_DOMAIN}.crt"
    fi
    if [[ -f "$LOCAL_DEST/${SITE_DOMAIN}.key" ]]; then
      sudo mkdir -p "/var/cert"
      sudo cp "$LOCAL_DEST/${SITE_DOMAIN}.key" "/var/cert/${SITE_DOMAIN}.key"
    fi
    if [[ -f "$LOCAL_DEST/${SITE_DOMAIN}_selfsigned.crt" ]]; then
      sudo mkdir -p "/var/cert/selfsigned"
      sudo cp "$LOCAL_DEST/${SITE_DOMAIN}_selfsigned.crt" "/var/cert/selfsigned/${SITE_DOMAIN}.crt"
    fi
    if [[ -f "$LOCAL_DEST/${SITE_DOMAIN}_selfsigned.key" ]]; then
      sudo mkdir -p "/var/cert/selfsigned"
      sudo cp "$LOCAL_DEST/${SITE_DOMAIN}_selfsigned.key" "/var/cert/selfsigned/${SITE_DOMAIN}.key"
    fi
  fi
done

# --- Enable required Apache modules ---
info "Enabling required Apache modules..."
a2enmod headers || true
a2enmod ssl || true
a2enmod rewrite || true

info "Restarting Apache..."
systemctl restart apache2

info "Selected site(s) files, databases, configs, and certs restored."

# --- Send restore report ---
if [[ -n "$REPORT_FROM" && -n "$REPORT_TO" ]]; then
  info "Emailing restore report to $REPORT_TO ..."
  send_report "Restore completed on $(hostname -f)" "$RESTORE_REPORT" "$REPORT_FROM" "$REPORT_TO"
else
  warn "Restore report not emailed: sender or recipient not set in backup config."
fi
rm -f "$RESTORE_REPORT"

echo "Review restored config files and verify SSL certs if needed."
echo "If Apache fails to start, check vhost and cert paths, and run: systemctl status apache2.service"

# --- Prompt to run backup now ---
read -p "Would you like to run a backup now to verify everything is working? (y/n): " RUN_TEST_BACKUP
if [[ "${RUN_TEST_BACKUP,,}" == "y" ]]; then
  info "Running test backup..."
  "$BACKUP_SCRIPT_PATH"
  info "Test backup completed. Please check your backup destination and notification email."
fi

info "Recovery and setup complete."
