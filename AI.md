# Project Documentation: Keep Secured

## 1. Overview
A lightweight, self-hosted web notepad with a tile layout. It maintains open and encrypted vaults within one installation. The whole site can be protected by a single userless master password. See `README.md` for installation.

---

## 2. Core Architecture & Multi-Vault Model

### 2.1 Vault Routing & Discovery
- **Default Vault (`/` or `/default`)**: automatically initialized as an **ungated (open)** vault after the first-run choice.
- **Custom Vaults (`/{slug}`)**:
  - Apache `mod_rewrite` routes clean slugs to `index.php?vault={slug}`.
  - On first access to a new slug, the user chooses:
    - **Ungated (Open)**: no password, stored in plaintext, listed in navigation.
    - **Gated (Encrypted)**: protected by a vault password, stored as AES-256-GCM ciphertext, auto-locks after 2 minutes of inactivity.
  - `settings` is a reserved slug.
- **Link Visibility**: only ungated vaults appear in navigation by default. The Settings toggle (`show_gated_links` in `data/system.json`) also lists gated vaults, exposing their names but not their notes.
- **In-Place Vault Encryption**: an ungated vault can be converted to gated at any time.
- **Subfolder installs**: `app_base_path()` derives the web path from `SCRIPT_NAME`. All links go through `app_url()`, and `app.js` reads the path from the `base-path` meta tag.

---

## 3. Security & Cryptographic Model

Two independent passwords exist:

| | Master password | Vault password |
| :--- | :--- | :--- |
| Scope | Whole site | One gated vault |
| Encrypts data | No (access gate) | Yes |
| Stored | Argon2id or bcrypt hash in `data/system.json` | Not stored; verified with an encrypted canary |
| Idle timeout | 12 hours | 2 minutes |
| Forgotten | Delete `data/system.json` | Unrecoverable |

### 3.1 Master Password (`auth.php`)
- States:
  - **Unconfigured**: no `system.json` and no `.htpasswd`. Shows the first-run screen.
  - **Enabled** or **disabled**: read from `system.json`.
  - **Legacy**: no `system.json` but `.htpasswd` exists. Any password in the file unlocks the site and becomes the master password.
- An unreadable `system.json` locks the site (fails closed).
- Each save writes a new `epoch`. Sessions holding an older epoch are signed out.
- `index.php`, `settings.php` and every `api.php` action check it. Static assets are public.

### 3.2 Vault Encryption (`crypto.php`)
- **Key derivation**: PBKDF2-SHA-256 with a random 32-byte salt per vault. New vaults use 600,000 iterations, recorded as `kdf_iterations` in `config.json`. Vaults without that field use 100,000.
- **Cipher**: AES-256-GCM with a fresh 12-byte IV per encryption and a 16-byte tag. Title and body are encrypted separately.
- **Verification**: decrypts a stored canary (`NOTEPAD_SECRET_VALIDATION_TOKEN_v1`).
- **Trust boundary**: encryption runs on the server, so this is encryption at rest and not end-to-end.
- **Inactivity lock**: enforced on the server through `$_SESSION['vault_activity'][$slug]` and in the client by `app.js`.

### 3.3 Request Hardening (`auth.php`)
- Sessions: stored in `data/sessions`, strict mode, HttpOnly, SameSite=Lax, `__Host-` prefix and Secure on HTTPS. The ID is regenerated on every login.
- Derived vault keys are encrypted in the session, using a secret held only in an HttpOnly cookie.
- Every non-read API action requires POST and an `X-CSRF-Token` header.
- Failed logins are rate-limited per IP and per target: 5 free attempts, then 30 seconds doubling up to 15 minutes.
- Headers: strict CSP with no inline scripts, `X-Frame-Options`, `nosniff`, `no-referrer`, `no-store`. Do not add inline scripts or `on*=` attributes.
- API errors are logged and never returned to the client.

---

## 4. Technology Stack
- **PHP 8.1+** with `openssl`, `pdo_sqlite`, `session`.
- **SQLite** (`notes.db` per vault).
- **Apache 2.4** with `mod_rewrite`, or nginx using the rules in `README.md`.
- **Vanilla JavaScript and CSS**, no external dependencies.

---

## 5. File Structure

```text
├── README.md       # Installation and usage
├── AI.md           # This document
├── .gitignore      # Keeps data/ and .htpasswd out of git
├── .htaccess       # Rewrites and file protection
├── index.php       # Main page
├── settings.php    # Master password settings
├── api.php         # JSON API
├── auth.php        # Sessions, CSRF, master password, rate limits, shared markup
├── crypto.php      # Encryption and vault storage
├── style.css
├── app.js
└── data/           # Created at runtime except .htaccess; never committed
    ├── .htaccess   # Denies all HTTP access
    ├── system.json
    ├── ratelimit.json
    ├── sessions/
    └── vaults/{slug}/{config.json,notes.db}
```

---

## 6. API Specification (`/api.php`)

All requests accept a `vault` query parameter (default `default`). POST bodies are JSON and need the `X-CSRF-Token` header.

| Action | Method | Description |
| :--- | :--- | :--- |
| `status` | GET | Vault state and the list of open vaults. |
| `get_ungated_vaults` | GET | Open vault names and URLs. |
| `get_notes` | GET | Decrypted notes. |
| `master_login` | POST | Unlocks the site (`password`). |
| `master_logout` | POST | Clears this session, including unlocked vaults. |
| `master_enable` | POST | Sets the password while disabled or unconfigured (`password`). |
| `master_skip` | POST | First-run choice to run with no password. |
| `master_change` | POST | Changes the password (`current_password`, `password`). |
| `master_disable` | POST | Disables the password (`current_password`). |
| `set_show_gated_links` | POST | Shows or hides encrypted vault links (`show`). |
| `setup` | POST | Creates a vault (`is_gated`, optional `password`). |
| `login` | POST | Unlocks a gated vault (`password`). |
| `logout` | POST | Locks a gated vault. |
| `make_gated` | POST | Encrypts an open vault (`password`). |
| `save_note` | POST | Creates or updates a note. |
| `delete_note` | POST | Deletes a note (`id`). |
| `toggle_pin` | POST | Toggles a note's pin (`id`). |

---

## 7. Portability
The application has no hardware or machine dependencies. Everything specific to an install lives in `data/`, which can be moved between systems running PHP with the required extensions.
