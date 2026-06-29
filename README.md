# 🔐 Password Vault

A secure, lightweight desktop password manager built with Python. Credentials are encrypted using AES-128 via the Fernet standard, with your master password never stored anywhere — only used to derive the encryption key through PBKDF2-SHA256.

---

## Features

- **Master password protection** — lock screen on startup with a 5-attempt lockout
- **Strong encryption** — AES-128-CBC + HMAC-SHA256 (Fernet) with PBKDF2 key derivation (100,000 iterations)
- **No plain-text key file** — the encryption key is derived from your master password, never saved to disk
- **Add, retrieve, and delete credentials** — organised by service name
- **Show/hide toggle** — credentials are hidden by default
- **Copy to clipboard** — with automatic clipboard clear after 30 seconds
- **Dark minimal UI** — built with tkinter

---

## Requirements

- Python 3.12 (recommended — Python 3.14 has known PyInstaller compatibility issues)
- `cryptography` library

---

## Installation

**1. Clone the repository**
```bash
git clone https://github.com/AlexNCyber/password-vault.git
cd password-vault
```

**2. Install dependencies**
```bash
py -3.12 -m pip install cryptography
```

**3. Run the app**
```bash
py -3.12 password_vault.py
```

---

## Build as a standalone .exe (Windows)

**1. Install PyInstaller**
```bash
py -3.12 -m pip install pyinstaller
```

**2. Build**
```bash
py -3.12 -m PyInstaller --onefile --noconsole password_vault.py
```

The executable will be created at `dist/password_vault.exe`. No Python installation required to run it.

---

## First Run

On first launch you will be prompted to create a master password. This password is used to derive the encryption key — if you forget it, your vault data cannot be recovered.

Three files are created locally on first run:

| File | Purpose |
|------|---------|
| `vault.salt` | Random salt for key derivation |
| `vault.hash` | Salted hash of your master password for verification |
| `vault.json` | Encrypted credentials |

> ⚠️ Back these files up somewhere safe. Losing them means losing access to your vault.

---

## Security Overview

| Feature | Implementation |
|--------|---------------|
| Encryption | AES-128-CBC + HMAC-SHA256 (Fernet) |
| Key derivation | PBKDF2-SHA256, 100,000 iterations |
| Password verification | Separate PBKDF2 hash, constant-time comparison |
| Brute-force protection | 5-attempt lockout per session |
| Clipboard safety | Auto-clear after 30 seconds |

---

## License

MIT License — free to use, modify, and distribute.
