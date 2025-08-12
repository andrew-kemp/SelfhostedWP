# SelfHostedWP

A simple, interactive Bash script to set up a secure WordPress + LAMP stack on Ubuntu.  
Supports Let's Encrypt, custom, or self-signed SSL.  
Prompts for all key values (hostname, webroot, DB, etc) and generates a minimal production-ready Apache vhost.

---

## Features

- Installs Apache, PHP, MariaDB, and WordPress
- Prompts for all configuration (hostname, DB, SSL, etc)
- Lets you choose SSL: Let's Encrypt, custom cert, or self-signed
- Minimal, secure Apache vhost (separate logs, security headers, HTTP→HTTPS)
- Sets file permissions
- Works for dev, staging, or production

---

## Quick Start

### 1. Download and run the script

**IMPORTANT:** Run as root (use `sudo`) on Ubuntu!

```bash
curl -fsSL https://raw.githubusercontent.com/andrew-kemp/SelfHostedWP/main/install_wp.sh -o install_wp.sh
sudo bash install_wp.sh
```

### 2. Follow the prompts

- Enter your domain name, email, webroot, DB info, and choose SSL option.
- The script will set up everything and print out your credentials and vhost config at the end.

---

## Requirements

- Ubuntu (tested 20.04/22.04)
- Root/sudo access
- Fresh server recommended (but script is idempotent for most steps)

---

## What it does

- Installs Apache, PHP, MariaDB, and WordPress
- Creates a new database and user
- Downloads the latest WordPress and prepares `wp-config.php`
- Sets up a secure Apache vhost (with HTTPS redirect and security headers)
- Installs and configures SSL (Let's Encrypt, custom, or self-signed)
- Adjusts permissions for security

---

## Example output

After running, you'll see:

- Site URL
- DocumentRoot
- Apache vhost file path and contents
- Database credentials
- SSL status and info

---

## Updating or re-running

You can re-run the script safely if you want to reset or update settings.  
Be careful: the script may overwrite existing vhost and WordPress config if you use the same hostname/webroot.

---

## Troubleshooting

- If you get stuck or see an error, check the logs shown at the end of the run.
- Restart Apache if you make manual changes:  
  `sudo systemctl restart apache2`
- For DNS/SSL issues, make sure your domain resolves to the server IP.

---

## License

MIT License.  
See [LICENSE](LICENSE).

---

## Author

[andrew-kemp](https://github.com/andrew-kemp)
