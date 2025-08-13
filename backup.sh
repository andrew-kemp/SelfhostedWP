#!/usr/bin/env bash
set -euo pipefail

CONFIG_FILE="/etc/selfhostedwp_backup.conf"
if [[ ! -f "$CONFIG_FILE" ]]; then
  echo "Config file $CONFIG_FILE not found!"
  exit 1
fi

set -a
source "$CONFIG_FILE"
set +a

Today="$(date +%A)"
Temp_Backup="/tmp/temp_backup_$Today"
Backup_Archive="${Temp_Backup}/backup.tar.gz"

mkdir -p "$Temp_Backup"

# Archive website files and config files
tar -cpvzf "$Backup_Archive" \
  "$WEBSITE_PATH" \
  "$WEB_CONFIG" \
  "$POSTFIX_CONFIG" \
  "$SASL_PASSWD" \
  "$CERT_DIRECTORY"

# Backup all non-system databases
for DB in $(mysql -e "show databases" -s --skip-column-names | grep -Ev "^(information_schema|performance_schema|mysql|sys)$"); do
    mysqldump "$DB" > "$Temp_Backup/${DB}.sql"
done

# Upload backup using Azure CLI, placing files in a folder named after the day
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