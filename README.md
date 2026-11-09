# Keep Secured

A small self-hosted notepad with a tile layout and multiple vaults. Each vault is either open or encrypted with its own password. The whole site can sit behind a single master password, with no user accounts.

It is plain PHP and JavaScript with SQLite storage. There is no build step, no Composer or npm dependencies, and no external requests.

## Features

- Open vaults, listed in the navigation bar.
- Encrypted vaults (AES-256-GCM) that lock after 2 minutes of inactivity. They are hidden from navigation unless you choose to list them.
- An optional master password for the whole site, managed on the Settings page.
- A mobile-friendly layout.

## Requirements

- PHP 8.1 or newer with the `openssl`, `pdo_sqlite` and `session` extensions
- Apache 2.4 with `mod_rewrite` and `AllowOverride All`, or nginx (see below). On Windows, XAMPP includes Apache and PHP.
- HTTPS for anything other than local use, because passwords are sent to the server

IIS and PHP's built-in server (`php -S`) are not supported. Both ignore `.htaccess`, so your notes and password hash could be downloaded.

## Install

If something is missing, the site shows a plain message listing what to fix.

### Windows (XAMPP)

1. Install [XAMPP](https://www.apachefriends.org/) with PHP 8.1 or newer.

2. [Download the ZIP](https://github.com/usmanahmed/keep-secured/archive/refs/heads/main.zip) and extract it. Rename the extracted `keep-secured-main` folder to `keep-secured` and move it to `C:\xampp\htdocs\`, so that `index.php` is directly inside `C:\xampp\htdocs\keep-secured`. Make sure the `.htaccess` files are copied too, including the one in `data\`.

3. Open the XAMPP Control Panel and start Apache.

4. Go to `http://localhost/keep-secured/` straight away and set a master password. Until you make that choice, the first visitor can make it instead.

5. Open `http://localhost/keep-secured/data/system.json` and confirm that it returns 403 or 404. If you can see the file's contents, do not store anything until `.htaccess` is working.

If the site says `The data/ folder must exist and be writable`, open Command Prompt as administrator and give the account running Apache write access. If you started Apache from the XAMPP Control Panel, that is your own account:

```bat
icacls "C:\xampp\htdocs\keep-secured\data" /grant "%USERNAME%:(OI)(CI)M" /T
```

If Apache runs as a Windows service under a named account, use that account's name instead of `%USERNAME%`.

If you use plain Apache and PHP instead of XAMPP, enable `openssl` and `pdo_sqlite` in `php.ini`, and allow `.htaccess` as described under [Apache](#apache).

#### Windows limits

- **Shared computers:** Windows ignores the private file permissions the app sets on Linux. `data\` gets its permissions from its parent folder, so anyone with access to that folder can copy your files. Restrict it in the folder's **Properties > Security** tab.
- **Using it from other devices:** set up HTTPS first. Without it, passwords cross your network unencrypted.

### Linux

1. Put the files in your web root or a subfolder:

   ```sh
   git clone https://github.com/usmanahmed/keep-secured.git keep-secured
   ```

2. Let the web server write to `data/`. The user is commonly `www-data` or `apache`:

   ```sh
   sudo chown -R www-data keep-secured/data
   sudo chmod 770 keep-secured/data
   ```

3. Open the site straight away and set a master password. Until you make that choice, the first visitor can make it instead.

### Apache

The included `.htaccess` files handle clean URLs and block access to `data/`, hidden files and include-only scripts. The virtual host must allow them with `AllowOverride All`.

If you serve the app through an `Alias`, add a `RewriteBase` line with that path to `.htaccess`.

### nginx

nginx ignores `.htaccess`, so **without these rules your notes and password hash are downloadable**. Place the deny rules before your PHP location:

```nginx
location ~ /\.                                   { deny all; }
location ^~ /data/                               { deny all; }
location ~ ^/(auth|crypto)\.php$                 { deny all; }
location ~ \.(db|sqlite|json|md|sql|htpasswd)$   { deny all; }

location = /settings { rewrite ^ /settings.php last; }

location / {
    try_files $uri $uri/ @vault;
}

location @vault {
    rewrite ^/([a-zA-Z0-9_-]+)/?$ /index.php?vault=$1 last;
}
```

After setup, confirm that `/data/system.json` returns 403 or 404.

## Using it

- `/` is the default open vault.
- `/any-name` opens that vault, or offers to create it.
- `/settings` enables, changes or disables the master password, and controls whether encrypted vaults are listed in the navigation bar.

### Forgotten passwords

**Master password:** delete `data/system.json` on the server. The next visit shows the first-run screen, and no notes are affected.

**Vault password:** this cannot be recovered. The password is what decrypts the notes.

## Security model

- Vault notes are encrypted on the server with a key derived from the vault password (PBKDF2-SHA-256). The password and the key are not stored in readable form.
- Encryption and decryption happen on the server. This protects a stolen disk or backup. It does not protect against someone who controls the server while a vault is unlocked.
- Open vaults are stored as plain text. The master password controls access to the site but does not encrypt anything.
- The master password and vault passwords are independent.
- Failed password attempts are rate-limited per IP address.

## Backup and upgrade

Everything specific to your install is in `data/`. Back up that folder. To upgrade, replace the other files and keep `data/`.

## Moving from HTTP Basic Auth

If a `.htpasswd` file exists and no master password has been set, the app keeps the site locked and accepts any password from that file. The first one used becomes the master password, and `.htpasswd` can then be deleted. MD5 (`$apr1$`) and bcrypt entries are supported.

## License

[MIT](LICENSE)
