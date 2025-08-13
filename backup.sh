# Backup Webiste, Database and config
# Created by Andrew Kemp
# 11th May 2023
# Version 1.0

# Variables
Azure_Blob="https://andrewkemp.blob.core.windows.net/webhost?sp=rcwd&st=2024-05-20T09:55:18Z&se=2025-05-19T17:55:18Z&spr=https&sv=2022-11-02&sr=c&sig=gnBwtReondsXLGyx2EXAZpldNic%2FG%2BTY0kJTuV07OJc%3D"
Today=$(date +%A)
Web_Config="/etc/apache2/sites-available/"
# DB_Name="db_andykemp"
Postfix_Config="/etc/postfix/main.cf"
SASL_Passwd="/etc/postfix/sasl_passwd"
Temp_Backup="/temp_backup"
Website_Path="/var/www/"
Cert_Directory="/var/cert"


# Creat the temp backup folder
mkdir $Temp_Backup
mkdir $Temp_Backup"/"$Today
# Create Archive with Website data and config files
tar -cpvzf $Temp_Backup"/"$Today"/"backup".tar.gz" $Website_Path $Web_Config $Postfix_Config $SASL_Passwd $Cert_Directory

# Backup the Database
# mysqldump $DB_Name > $Temp_Backup"/"$DB_Name"-"$Today".sql"

for DB in $(mysql -e 'show databases' -s --skip-column-names); do
    mysqldump $DB > $Temp_Backup"/"$Today"/"$DB".sql";
done



# Upload the files to Azure Blob Storage
echo uploading to Azure
az storage blob upload-batch --destination $Azure_Blob --source $Temp_Backup --overwrite
# clear
# Clearing Temp Backup
echo "Removing the local temp files"
rm -r -f $Temp_Backup
echo "Files removed"
echo $Today" backup has been run" | mail -s $Today"'s web server backup has now been run" -r servers@andykemp.com andrew@kemponline.co.uk