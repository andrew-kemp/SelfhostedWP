# SelfhostedWP Automated WordPress Installer & Backup

This script automates the setup of a secure, multi-site WordPress hosting environment on Ubuntu, complete with daily backups to Azure Blob Storage and SMTP email notifications.  
It supports per-site installations in `/var/www/<site>`, robust SSL options, Apache virtual host configuration, MariaDB setup, and Postfix SMTP relay.

---

## Features

- **Multi-site WordPress:** Each site is installed in its own directory under `/var/www/<site-hostname>`.
- **Apache Virtual Hosts:** Automated creation of per-site SSL-enabled vhost configs.
- **MariaDB Database:** Secure database and user creation per site.
- **SSL Support:** Choose between Let's Encrypt (auto-renew), custom certs, or self-signed certificates.
- **SMTP Email (Postfix):** Non-interactive setup for SMTP relay (e.g., SMTP2GO), with sensible defaults for `mailname` (extracts root domain, e.g., `andykemp.com` from `dev.andykemp.com`).
- **Automated Backups:** Daily backup of `/var/www` (all sites), Apache vhost configs, SSL certs, and all MariaDB databases to Azure Blob Storage.
- **Email Reports:** Backup success/failure notifications sent via configured SMTP relay.
- **Unattended Install:** No interactive prompts during package installs.

---

## How Domain Extraction Works

When you enter a hostname (e.g., `dev3.kemponline.co.uk`, `blog.domain.com`, `mydomain.andykemp.cloud`), the script extracts the **root domain** for use in email addresses and the Postfix `mailname`.  
This means:

| Entered Hostname           | Extracted Domain for Email/Postfix |
|----------------------------|------------------------------------|
| www.kemponline.co.uk       | kemponline.co.uk                   |
| dev3.kemponline.co.uk      | kemponline.co.uk                   |
| blog.andykemp.com          | andykemp.com                       |
| mydomain.andykemp.cloud    | andykemp.cloud                     |
| www.domain.org.uk          | domain.org.uk                      |
| dev.domain.com             | domain.com                         |

If your domain uses a multi-part TLD (e.g., `.co.uk`, `.org.uk`), it is preserved.

---

## Installation Steps

1. **Run the script as root (or with sudo):**
    ```bash
    sudo bash wp_install.sh
    ```

2. **Follow the prompts:**
    - **Site Hostname:** Enter the desired FQDN (e.g., `www.mysite.com`, `dev.mysite.com`, etc.).
    - **ServerAdmin Email:** Defaults to `admin@<root-domain>`.
    - **MariaDB Details:** Database name, user, and (optional) password.
    - **SSL Choice:** Pick Let's Encrypt, custom certs, or self-signed.
    - **Backup & SMTP Details:** Provide your Azure Blob SAS URL and SMTP relay credentials.

3. **Script completes:**
    - Site installed in `/var/www/<site-hostname>`.
    - Apache vhost configured.
    - SSL issued and auto-renew (if Let's Encrypt).
    - MariaDB database and user created.
    - Postfix SMTP relay set up (with correct mailname).
    - Daily backup scheduled via cron.
    - Backup notification and install report sent via email.

---

## What Gets Backed Up?

- All site files under `/var/www`
- All Apache vhost configs (`/etc/apache2/sites-available`)
- All SSL certificates (`/var/cert`)
- All MariaDB databases
- Key Postfix config files (`/etc/postfix/main.cf`, `/etc/postfix/sasl_passwd`)

Backups are uploaded daily to your specified Azure Blob Storage SAS URL.

---

## SMTP/Email Setup

- The script configures Postfix for SMTP relay using your provided server, port, username, and password.
- The **mailname** used by Postfix is the extracted root domain from your site host (e.g., `andykemp.com` from `dev.andykemp.com`).
- All backup/report emails are sent through this relay.

---

## Example

Suppose you set up a site with hostname `dev3.kemponline.co.uk`:

- **Site files:** `/var/www/dev3.kemponline.co.uk`
- **Apache vhost:** `/etc/apache2/sites-available/dev3.kemponline.co.uk.conf`
- **MariaDB database:** e.g., `db_dev3_kemponline_co_uk`
- **ServerAdmin email:** `admin@kemponline.co.uk`
- **Postfix mailname:** `kemponline.co.uk`
- **Backups:** All sites in `/var/www`, all vhosts, all SSL certs, all databases

---

## Advanced Domain Extraction

To ensure your email and mailname are always correct, the script strips any subdomain (like `www.`, `dev.`, `blog.`, etc.) and preserves multi-part TLDs:

```bash
get_root_domain() {
  local host="$1"
  local two_part_tlds="co.uk|org.uk|ac.uk|gov.uk|sch.uk|me.uk|net.uk|plc.uk|ltd.uk"
  if [[ "$host" =~ ([^.]+)\.([^.]+\.(co\.uk|org\.uk|ac\.uk|gov\.uk|sch\.uk|me\.uk|net\.uk|plc\.uk|ltd\.uk))$ ]]; then
    echo "${BASH_REMATCH[2]}"
  else
    echo "${host#*.}"
  fi
}
```

---

## Security Notes

- Database passwords are stored in `wp-config.php` (not echoed unless you opt in).
- SSL is enforced via Apache; automated renewal is enabled for Let's Encrypt.
- Backups are encrypted in transit via Azure CLI.

---

## Requirements

- Ubuntu (recommended: 22.04 LTS or newer)
- Azure CLI (installed automatically if missing)
- Internet connectivity
- Valid SMTP relay credentials for email reports

---

## Uninstallation / Cleanup

- Remove sites from `/var/www`
- Remove vhost configs from `/etc/apache2/sites-available`
- Remove databases/users from MariaDB
- Remove backup cron job (`crontab -e`)

---

## Troubleshooting

- Check `/var/log/apache2` for Apache errors.
- Check `/var/log/mail.log` for Postfix/email issues.
- Backups are stored temporarily in `/tmp/temp_backup_<Day>` before upload.

---

## License

MIT License

---

## Credits

Script and README generated by GitHub Copilot and [andrew-kemp](https://github.com/andrew-kemp).