#!/usr/bin/env bash
# Automated web server backup & notification script
# Reads config from /etc/selfhostedwp_backup.conf

set -euo pipefail

# Load config
CONFIG_PATH="/etc/selfhostedwp_backup.conf"
if [[ ! -f "$CONFIG_PATH" ]]; then
  echo "Backup config file $CONFIG_PATH not found!"
  exit 1
fi
source "$CONFIG_PATH"

# Backup variables
Today=$(date +%A)
Temp_Backup="/temp_backup"
Backup_Archive="${Temp_Backup}/${Today}/backup.tar.gz"
Website_Path="/var/www/"
Web_Config="/etc/apache2/sites-available/"
Postfix_Config="/etc/postfix/main.cf"
SASL_Passwd="/etc/postfix/sasl_passwd"
Cert_Directory="/var/cert"

# Prepare temp folder
rm -rf "$Temp_Backup"
mkdir -p "${Temp_Backup}/${Today}"

# Create archive: site files + configs + certs
tar -cpvzf "$Backup_Archive" \
  "$Website_Path" \
  "$Web_Config" \
  "$Postfix_Config" \
  "$SASL_Passwd" \
  "$Cert_Directory"

# Backup all databases
DB_DUMP_FOLDER="${Temp_Backup}/${Today}/db_dumps"
mkdir -p "$DB_DUMP_FOLDER"
for DB in $(mysql -e 'show databases' -s --skip-column-names | grep -Ev '^(information_schema|performance_schema|mysql|sys)$'); do
  mysqldump "$DB" > "${DB_DUMP_FOLDER}/${DB}.sql"
done

# Upload backup (Azure Blob)
UPLOAD_SUCCESS=0
if [[ "$BACKUP_TARGET" =~ ^https:// ]]; then
  if command -v az >/dev/null 2>&1; then
    az storage blob upload-batch --destination "$BACKUP_TARGET" --source "$Temp_Backup" --overwrite && UPLOAD_SUCCESS=1
  else
    UPLOAD_SUCCESS=2
    UPLOAD_ERROR="Azure CLI not installed!"
  fi
else
  # Local copy
  mkdir -p "$BACKUP_TARGET"
  cp -r "$Temp_Backup"/* "$BACKUP_TARGET"/ && UPLOAD_SUCCESS=1
fi

# Compose summary
if [[ $UPLOAD_SUCCESS -eq 1 ]]; then
  SUBJECT="$Today Backup Success"
  BODY="Backup completed successfully.

Files backed up:
- $Website_Path
- $Web_Config
- $Postfix_Config
- $SASL_Passwd
- $Cert_Directory
- All MySQL/MariaDB databases

Backup archive: $Backup_Archive
Database dumps: $DB_DUMP_FOLDER

Backup uploaded to: $BACKUP_TARGET

$(date)"
else
  SUBJECT="$Today Backup ERROR"
  BODY="Backup failed to upload!

Error: ${UPLOAD_ERROR:-'Unknown error'}

$(date)"
fi

# Clean up temp files
rm -rf "$Temp_Backup"

# Mail notification
echo "$BODY" | mail -s "$SUBJECT" -r "$REPORT_FROM" "$REPORT_TO"

exit 0