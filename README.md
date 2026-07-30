
# 🖥️ Nexus RDP

A secure, modern Remote Desktop Connection Manager for Windows. Nexus RDP lets you save, organize, and launch RDP connections with a single click — all protected behind encrypted storage and a master password.

![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?logo=windows&logoColor=white)
![License](https://img.shields.io/badge/License-GPL--3.0-blue)

[![Ko-fi](https://img.shields.io/badge/☕_Buy_Me_a_Coffee-F16061?style=for-the-badge&logo=ko-fi&logoColor=white)](https://ko-fi.com/netanelelhadad)

---

## ✨ Features (v4.2)

- Master Password Protection — Set on first run; only a salted PBKDF2 hash is stored in `config.json`.
- Encrypted Credential Storage — Connection passwords are encrypted using Fernet and stored in `secret.key`.
- One-Click RDP Connections — Credentials are injected into the Windows Credential Manager (`cmdkey`), `mstsc` is launched and credentials are removed shortly after the session starts.
- `/control` Launch — RDP sessions are launched with the `/control` flag (enables smart card/advanced security device support).
- Add / Edit / Delete Connections — Full CRUD management via dialogs.
- Duplicate Connection — Quickly duplicate an existing connection (the UI prevents duplicate names and appends `- Copy`/`(n)` as needed).
- Connection Ordering — Move connections up/down using the ▲ and ▼ buttons to arrange your list.
- Optional Credentials — Username and password are optional; if omitted, Windows will prompt during the RDP session.
- Dark & Light Themes — Switch appearance modes via the dropdown.
- Modern UI — Built with CustomTkinter for a clean, native-feeling interface.
- Portable Executable — PyInstaller spec included for building a standalone `.exe`.

---

## 🔒 Security Architecture

| Layer | Mechanism | Details |
|---|---|---|
| Master Password | PBKDF2-HMAC-SHA256 | 100,000 iterations with a random 16-byte hex salt. Only the salt and derived hash are stored in `config.json`. |
| Connection Passwords | Fernet (cryptography) | A symmetric key is generated on first run and saved to `secret.key`. All connection passwords are encrypted and decrypted with this key. |
| Credential Injection | Windows Credential Manager | `cmdkey` is used to add credentials for `TERMSRV/<host>` at connection time and deleted shortly after the session starts. |

> ⚠️ Important: Keep `secret.key` safe. If it is lost or deleted, stored connection passwords cannot be recovered.

---

## 📦 Installation

### Prerequisites

- Python 3.8+
- Windows OS (relies on `mstsc` and `cmdkey`)

### Install Dependencies

```powershell
pip install customtkinter cryptography
```

### Run the Application

```powershell
python Nexus_RDP_v4.2.py
```

On first launch you will be prompted to set a master password. This password is required on subsequent launches.

---

## 🚀 Usage

1. Login — Enter your master password to unlock the app.
2. Add a Connection — Click `+ Add` and fill in the connection name, IP/hostname, and optionally username and password.
3. Connect — Click the green `Connect` button to launch RDP. If a password is saved, it's injected into Credential Manager before launching and removed shortly after.
4. Duplicate — Click `Dup` to duplicate a connection. The dialog allows editing the new name; duplicate names are prevented.
5. Reorder — Use the ▲ / ▼ buttons to move a connection up or down in the list. Order is persisted.
6. Edit — Click `Edit` to modify connection details. When editing an existing connection, the name field is disabled to avoid accidental renames.
7. Delete — Click `X` to remove a connection (confirmation prompt shown).
8. Theme — Use the Theme dropdown at the bottom to switch between Dark and Light modes.

---

## 📁 Project Structure

```
Nexus_RDP/
├── Nexus_RDP_v4.2.py        # Main application entry point (v4.2)
├── Nexus_RDP_v4.2.spec      # PyInstaller spec for building a standalone .exe
├── config.json              # Master password salt & hash (auto-generated)
├── secret.key               # Fernet encryption key (auto-generated)
├── rdp_connections.json     # Encrypted connection data (auto-generated at runtime)
├── icon.ico                 # Application icon (used by PyInstaller)
└── README.md                # This file
```

---

## 🔨 Building a Standalone Executable

Install PyInstaller and build:

```powershell
pip install pyinstaller
pyinstaller --onefile --icon="icon.ico" --noconsole .\Nexus_RDP_v4.2.py
```

Or use the included spec:

```powershell
pyinstaller Nexus_RDP_v4.2.spec
```

The compiled executable will appear in the `dist/` folder. When distributing the `.exe`, include `secret.key` and `config.json` alongside the executable if you want to preserve saved credentials and master password data.

---

## 📌 Version History

| Version | File | Highlights |
|---|---|---|
| **v4.2** | `Nexus_RDP_v4.2.py` | Added duplicate connection, connection ordering (move up/down), improved connection dialog behavior (disable name edit when editing), UI tweaks and small layout adjustments. |
| **v4.1** | `Nexus_RDP_v4.1.py` | Stability fix — safe `stdout`/`stderr` handling for `--noconsole` mode, clean `quit()` flow for Auth window. |

---

## 👥 Authors

Created by **Netanel Elhadad**
