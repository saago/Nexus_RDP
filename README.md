
# 🖥️ Nexus RDP

A secure, modern Remote Desktop Connection Manager for Windows. Nexus RDP lets you save, organize, and launch RDP connections with a single click — all protected behind encrypted storage and a master password.

![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?logo=windows&logoColor=white)
![License](https://img.shields.io/badge/License-GPL--3.0-blue)

[![Ko-fi](https://img.shields.io/badge/☕_Buy_Me_a_Coffee-F16061?style=for-the-badge&logo=ko-fi&logoColor=white)](https://ko-fi.com/netanelelhadad)
[![Support](https://img.shields.io/badge/❤️_Support_This_Project-FF5E5B?style=for-the-badge)](https://ko-fi.com/netanelelhadad)

---

## ✨ Features

- **Master Password Protection** — The app is locked behind a master password, set on first launch and required for every subsequent session.
- **Encrypted Credential Storage** — All saved passwords are encrypted at rest using **Fernet symmetric encryption** (from the `cryptography` library).
- **One-Click RDP Connections** — Credentials are temporarily injected into the Windows Credential Manager, `mstsc` is launched, and credentials are automatically wiped after 5 seconds.
- **Smart Card Support** — Connections are launched with the `/control` flag, enabling smart card and advanced security device compatibility.
- **Add / Edit / Delete Connections** — Full CRUD management of your saved RDP connections through a clean dialog interface.
- **Optional Credentials** — Username and password are optional; connections without saved credentials will prompt via the standard Windows RDP login.
- **Dark & Light Themes** — Toggle between Dark and Light appearance modes on the fly.
- **Modern UI** — Built with [CustomTkinter](https://github.com/TomSchimansky/CustomTkinter) for a sleek, native-feeling dark-mode interface.
- **Portable Executable** — Can be compiled to a standalone `.exe` with PyInstaller (spec file included).

---

## 🔒 Security Architecture

| Layer | Mechanism | Details |
|---|---|---|
| **Master Password** | PBKDF2-HMAC-SHA256 | 100,000 iterations with a random 16-byte hex salt. Only the hash is stored in `config.json` — the plaintext password is never saved. |
| **Connection Passwords** | Fernet (AES-128-CBC) | A symmetric key is generated on first run and stored in `secret.key`. All connection passwords are encrypted/decrypted through this key. |
| **Credential Injection** | Windows Credential Manager | Passwords are injected via `cmdkey` only at connection time and are automatically deleted after 5 seconds. |

> ⚠️ **Important:** Keep `secret.key` safe. If it is lost or deleted, all saved connection passwords become unrecoverable.

---

## 📦 Installation

### Prerequisites

- **Python 3.8+**
- **Windows OS** (uses `mstsc` and `cmdkey`)

### Install Dependencies

```bash
pip install customtkinter cryptography
```

### Run the Application

```bash
python Nexus_RDP_v4.1.py
```

On first launch you will be prompted to set a **master password**. This password is required every time you open the app.

---

## 🚀 Usage

1. **Login** — Enter your master password to unlock the app.
2. **Add a Connection** — Click `+ Add` and fill in the connection name, IP address/hostname, and optionally a username and password.
3. **Connect** — Click the green `Connect` button on any saved connection to launch an RDP session.
4. **Edit** — Click the yellow `Edit` button to modify a connection's details.
5. **Delete** — Click the red `X` button to remove a connection.
6. **Theme** — Use the theme dropdown at the bottom to switch between Dark and Light modes.

---

## 📁 Project Structure

```
RDP/
├── Nexus_RDP_v4.1.py       # Latest version — main application entry point
├── Nexus_RDP_v4.1.spec      # PyInstaller spec for building a standalone .exe
├── config.json              # Master password hash & salt (auto-generated)
├── secret.key               # Fernet encryption key (auto-generated)
├── rdp_connections.json     # Encrypted connection data (auto-generated at runtime)
├── icon.ico                 # Application icon (used by PyInstaller)
└── README.md                # This file
```

---

## 🔨 Building a Standalone Executable

A PyInstaller command can be used to compile the app into a single `.exe`:

```bash
pip install pyinstaller
pyinstaller --onefile --icon="icon.ico" --noconsole .\Nexus_RDP_v4.1.py
```

Alternatively, a `.spec` file is included for building:

```bash
pyinstaller Nexus_RDP_v4.1.spec
```

The compiled executable will be placed in the `dist/` folder. It bundles all CustomTkinter assets and uses `icon.ico` as the application icon. The executable runs **without a console window** (`console=False`).

> **Note:** When distributing the `.exe`, make sure `secret.key` and `config.json` are in the same directory as the executable (they are created automatically on first run if missing).

---

## 📌 Version History

| Version | File | Highlights |
|---|---|---|
| **v4.1** | `Nexus_RDP_v4.1.py` | Stability fix — safe `stdout`/`stderr` handling for `--noconsole` mode, clean `quit()` flow for Auth window. |

---

## 👥 Authors

Created by **Meir Asulin** & **Netanel Elhadad**
