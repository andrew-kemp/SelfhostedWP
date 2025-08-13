#!/usr/bin/env bash
# SelfhostedWP Restore Script: Recovers all or selected WordPress sites from Azure Blob backup
# Installs all prerequisites and ensures certbot auto-renew for Let's Encrypt sites

set -Eeuo pipefail

# ===== Helpers =====
require_root() {
  if [[ $EUID -ne 0 ]]; then
    echo "Run as root." >&2; exit 1
  fi
}

command_exists() { command -v "$1" >/dev/null 2>&1; }

info() { echo -e "\033[1;32m==>\033[0m $*"; }
warn() { echo -e "\033[1;33m!!\033[0m $*"; }

# ===== Main =====
require_root

# --- Prompt for SAS URL and backup day ---
read -p "Azure Blob SAS URL for backup container: " SAS_URL
read -p "Backup day to restore (e.g. Monday): " DAY
read -p "Restore all sites (a) or single site (s)? [a/s]: " MODE

TMP_RESTORE="/tmp/wp_restore_$DAY"
mkdir -p "$TMP_RESTORE"

# --- Prerequisite installs (match install script) ---
info "Updating package index and installing prerequisites..."
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y apache2 php libsasl2-modules libapache2-mod-php php-gd mariadb-server mariadb-client php-mysql mailutils php-gmp php-mbstring php-xml php-curl wget rsync unzip tar openssl curl certbot python3-certbot-apache postfix

# --- Install Azure CLI if missing ---
if ! command_exists az; then
  info "Installing Azure CLI..."
  curl -sL https://aka.ms/InstallAzureCLIDeb | bash
fi

# --- Download backup files from Azure ---
info "Downloading backup files for $DAY from Azure Blob Storage..."
AZURE_ACCOUNT_NAME="$(echo "$SAS_URL" | awk -F[/:] '{print $4}' | awk -F. '{print $1}')"
AZURE_CONTAINER_NAME="$(echo "$SAS_URL" | awk -F[/:] '{print $5}' | awk -F'?' '{print $1}')"
AZURE_SAS_TOKEN="$(echo "$SAS_URL" | awk -F'?' '{print $2}')"

az storage blob download-batch \
  --account-name "$AZURE_ACCOUNT_NAME" \
  --destination "$TMP_RESTORE" \
  --source "$AZURE_CONTAINER_NAME/$DAY" \
  --sas-token "$AZURE_SAS_TOKEN"

cd "$TMP_RESTORE"

# --- Retrieve sites.list ---
if [[ ! -f sites.list ]]; then
  warn "sites.list not found in backup. Abort."
  exit 1
fi

info "Available sites in backup:"
awk -F'|' '{print $1}' sites.list

if [[ "$MODE" == "s" ]]; then
  read -p "Enter site hostname to restore: " SITE
  if ! grep -q "^$SITE|" sites.list; then
    warn "Site $SITE not found in backup."
    exit 1
  fi
  RESTORE_SITES=("$SITE")
else
  RESTORE_SITES=( $(awk -F'|' '{print $1}' sites.list) )
fi

# --- Restore each site ---
for SITE in "${RESTORE_SITES[@]}"; do
  info "Restoring $SITE..."

  DBNAME=$(awk -F'|' -v s="$SITE" '$1==s{print $2}' sites.list)
  DBUSER=$(awk -F'|' -v s="$SITE" '$1==s{print $3}' sites.list)
  WEBROOT=$(awk -F'|' -v s="$SITE" '$1==s{print $4}' sites.list)
  VHOST_FILE="/etc/apache2/sites-available/${SITE}.conf"
  SSL_OPTION=$(awk -F'|' -v s="$SITE" '$1==s{print $6}' sites.list)

  # Restore site files
  if [[ -f "${SITE}.tar.gz" ]]; then
    mkdir -p "$WEBROOT"
    tar -xzf "${SITE}.tar.gz" -C "$WEBROOT"
    chown -R www-data:www-data "$WEBROOT"
  fi

  # Restore database
  if [[ -f "db_${DBNAME}.sql" ]]; then
    mysql -e "DROP DATABASE IF EXISTS \`${DBNAME}\`;"
    mysql -e "CREATE DATABASE \`${DBNAME}\`;"
    mysql "$DBNAME" < "db_${DBNAME}.sql"
    # Optionally, you can recreate user and set privileges here
  fi

  # Restore vhost config
  if [[ -f "${SITE}.conf" ]]; then
    cp "${SITE}.conf" "$VHOST_FILE"
    a2ensite "${SITE}.conf" >/dev/null
  fi

  # Restore SSL certs
  if [[ "$SSL_OPTION" == "1" && -f "${SITE}_le_certs.tar.gz" ]]; then
    mkdir -p "/etc/letsencrypt/live/$SITE"
    tar -xzf "${SITE}_le_certs.tar.gz" -C "/etc/letsencrypt/live/$SITE"
  fi
  if [[ -f "${SITE}.crt" ]]; then
    mkdir -p /var/cert
    cp "${SITE}.crt" "/var/cert/${SITE}.crt"
  fi
  if [[ -f "${SITE}.key" ]]; then
    mkdir -p /var/cert
    cp "${SITE}.key" "/var/cert/${SITE}.key"
  fi
  if [[ -f "${SITE}_selfsigned.crt" ]]; then
    mkdir -p "/var/cert/selfsigned"
    cp "${SITE}_selfsigned.crt" "/var/cert/selfsigned/${SITE}.crt"
  fi
  if [[ -f "${SITE}_selfsigned.key" ]]; then
    mkdir -p "/var/cert/selfsigned"
    cp "${SITE}_selfsigned.key" "/var/cert/selfsigned/${SITE}.key"
  fi

  # Permissions
  chown -R www-data:www-data "$WEBROOT"
done

# --- Restore sites.list ---
cp sites.list /etc/selfhostedwp/sites.list
chmod 600 /etc/selfhostedwp/sites.list

# --- Restore global configs ---
[[ -f server_main.cf ]] && cp server_main.cf /etc/postfix/main.cf
[[ -f server_sasl_passwd ]] && cp server_sasl_passwd /etc/postfix/sasl_passwd && postmap /etc/postfix/sasl_passwd && chmod 600 /etc/postfix/sasl_passwd
[[ -f server_selfhostedwp_backup.conf ]] && cp server_selfhostedwp_backup.conf /etc/selfhostedwp_backup.conf
[[ -f server_apache2.conf ]] && cp server_apache2.conf /etc/apache2/apache2.conf

if [[ -f server_cert.tar.gz ]]; then
  tar -xzf server_cert.tar.gz -C /
fi
if [[ -f server_letsencrypt.tar.gz ]]; then
  tar -xzf server_letsencrypt.tar.gz -C /
fi

# --- Certbot auto-renew for Let's Encrypt sites ---
if grep -q '|1$' sites.list; then
  info "Enabling certbot timer for auto-renewal..."
  systemctl enable certbot.timer
  systemctl start certbot.timer
  # Restore hook if present
  HOOK_PATH="/etc/letsencrypt/renewal-hooks/deploy/reload-apache.sh"
  if [[ ! -f "$HOOK_PATH" ]]; then
    mkdir -p "$(dirname "$HOOK_PATH")"
    cat > "$HOOK_PATH" <<'HOOK'
#!/usr/bin/env bash
systemctl reload apache2
HOOK
    chmod +x "$HOOK_PATH"
  fi
fi

# --- Restart services ---
info "Reloading Apache and Postfix..."
systemctl reload apache2
systemctl reload postfix

info "Restore complete."
echo "Sites restored: ${RESTORE_SITES[*]}"
echo "Please verify each site and adjust DNS if required."