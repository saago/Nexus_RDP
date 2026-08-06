# 🖥️ Nexus RDP

A secure, modern Remote Desktop Connection Manager for Windows. Nexus RDP lets you save, organize, and launch RDP connections with a single click — all protected behind an encrypted vault and a master password.

![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?logo=windows&logoColor=white)
![License](https://img.shields.io/badge/License-GPL--3.0-blue)

[![Ko-fi](https://img.shields.io/badge/☕_Buy_Me_a_Coffee-F16061?style=for-the-badge&logo=ko-fi&logoColor=white)](https://ko-fi.com/netanelelhadad)

---

> ### ⚠️ Upgrading from v4.x? Read this first.
>
> v5.0 was a **security rewrite**. The v4.x design stored a Fernet key in `secret.key`
> *independently of your master password*, which meant anyone who copied that file could
> read every saved password without knowing the master password at all — and deleting
> `config.json` restored "first run" and let anyone set a new master password over your
> existing data.
>
> v5 fixes both. **The master password is now the encryption key itself.** The trade-off
> is absolute: **there is no recovery path.** Forget the master password and the vault is
> gone. Write it down somewhere physical.
>
> On first launch, v5 offers to import your v4 connections and then securely erase the old
> files. See [Upgrading from v4.x](#-upgrading-from-v4x).

---

## ✨ Features (v5.1)

### Connections
- **One-Click RDP** — Credentials are written directly to the Windows Credential Manager, `mstsc` launches, and the credential is removed the moment the session exits.
- **Multi-Monitor Support** *(new in v5.1)* — Each connection remembers how it should open: windowed, fullscreen, across all monitors, or spanned. See [Display Modes](#-display-modes).
- **Add / Edit / Delete / Duplicate** — Full CRUD via dialogs. Duplicate names are prevented and `- Copy` / `(n)` suffixes appended automatically.
- **Connection Ordering** — Rearrange your list with the ▲ / ▼ buttons. Order is saved.
- **Optional Credentials** — Username and password are both optional; omit them and Windows prompts you during the session.
- **Export / Import** — Share a connection list with colleagues. **Exports never contain passwords**, and imports never accept them.

### Security
- **Master Password Protection** — Set on first run. Not stored anywhere, in any form.
- **Encrypted Vault** — Your entire connection list is a single authenticated-encryption blob. Tampering is detected, not just decryption failure.
- **Idle Auto-Lock** — The app locks itself after 10 minutes of inactivity, plus a manual `Lock` button.
- **Brute-Force Throttling** — 5 failed attempts triggers a 60-second lockout that doubles with each subsequent lockout, capped at 1 hour.
- **Vault Reset** *(new in v5.1)* — Forgot your master password? Erase everything and start fresh from inside the app, behind a typed confirmation. See [Forgotten Master Password](#-forgotten-master-password).

### Interface
- **Dark & Light Themes** — Switch appearance modes via the dropdown.
- **Modern UI** — Built with CustomTkinter for a clean, native-feeling interface.
- **Portable Executable** — Builds to a standalone `.exe` with PyInstaller.

---

## 🖥️ Display Modes

Set per connection in the Add/Edit dialog. Non-default modes are shown on the connection card.

| Mode | `mstsc` flag | Behaviour |
|---|---|---|
| **Windowed (single monitor)** | *(none)* | Opens in a resizable window. The default, and what every pre-v5.1 connection uses. |
| **Fullscreen (single monitor)** | `/f` | Fills one monitor. `Ctrl+Alt+Break` toggles back. |
| **Use all my monitors** | `/multimon` | Each of your monitors appears as a **separate monitor** inside the remote session. Any layout, any resolution. |
| **Span across monitors** | `/span` | One **single** wide desktop stretched across your monitors. A maximised remote window covers all of them at once. |

> 💡 **`/multimon` vs `/span`** — these are genuinely different, not two names for one thing. `/span` is still a single-monitor session; it just makes that monitor very wide. It also has hardware requirements: your monitors must share a resolution and sit side by side in a straight line. If they don't, Windows silently falls back to a single display. `/multimon` has no such constraints and is what most people want.

---

## 🔒 Security Architecture

| Layer | Mechanism | Details |
|---|---|---|
| **Master Password** | scrypt (N=2¹⁶, r=8, p=1) | Derives a 32-byte key at unlock time, ~64 MB of memory per guess. The password is **never stored** — no hash, no verifier, no key file. The derived key lives in memory only. |
| **Vault** | Fernet (AES-128-CBC + HMAC-SHA256) | The entire document — names, hosts, usernames, passwords — is one authenticated blob in `vault.dat`. Correctness of the master password is proven by successful decryption. |
| **Key Parameters** | `vault.meta.json` | Holds the scrypt salt, cost parameters and lockout state. **Contains no password material of any kind.** |
| **Credential Injection** | `CredWriteW` (Win32 API) | Called directly via `ctypes`. Session-scoped, so Windows purges it at logoff even if the app crashes, and it is deleted when `mstsc` actually exits. |
| **Input Validation** | Allow-lists | Hosts, ports, usernames and display modes are validated against allow-lists before reaching any command line. |
| **Storage** | `%LOCALAPPDATA%\NexusRDP` | A fixed per-user location whose ACL already restricts access to your account. |

### What changed from v4.2, and why

| | v4.2 | v5.x |
|---|---|---|
| Password hashing | PBKDF2, hash stored in `config.json` | scrypt, **nothing stored** |
| Encryption key | Random key in `secret.key`, independent of your password | **Derived from your master password** |
| Copying `secret.key` | Revealed every saved password | File no longer exists |
| Deleting `config.json` | Reset to first-run — an auth bypass over your existing data | Vault refuses to be overwritten |
| Credential injection | `cmdkey /pass:<plaintext>` — password visible in the process command line to **any** process on the machine | `CredWriteW` — no command line, no child process |
| Credential cleanup | 5-second timer; closing early left it in Credential Manager permanently | Removed when `mstsc` exits, plus session-scoped and an exit-time purge |
| `mstsc` / `cmdkey` path | Bare name, resolved via PATH — a planted binary would receive your credentials | Absolute path under `%SystemRoot%` |
| Stored host string | Passed straight into the `mstsc` argv — a value like `/migrate` was read as a switch | Validated as an IP literal or DNS hostname |
| Data location | Current working directory — launching from elsewhere produced a fresh "first run" | Fixed per-user directory |

> ⚠️ **There is no recovery path, by design.** The master password *is* the encryption key. If you forget it, nobody — including the author — can recover your saved passwords. Deleting `vault.meta.json` does not reset access; it makes the vault permanently undecryptable.

---

## 📦 Installation

### Prerequisites

- Python 3.8+
- Windows (launching sessions relies on `mstsc.exe`)

### Install Dependencies

```powershell
pip install customtkinter cryptography
```

### Run the Application

```powershell
python Nexus_RDP_v5.1.py
```

On first launch you'll be asked to set a master password. It's required on every subsequent launch.

---

## 🚀 Usage

1. **Unlock** — Enter your master password.
2. **Add a Connection** — Click `+ Add`, then fill in the name, IP/hostname, and optionally port, username, password and display mode.
3. **Connect** — Click the green `Connect` button. A saved password is written to Credential Manager just before launch and removed when the session ends.
4. **Duplicate** — Click `Dup`. The dialog lets you edit the new name; duplicates are prevented.
5. **Reorder** — Use ▲ / ▼ to move a connection. Order is saved.
6. **Edit** — Click `Edit`. The name field is disabled when editing to avoid accidental renames. Saved passwords are never displayed — you can replace or delete them, not read them back.
7. **Delete** — Click `X` (confirmation shown).
8. **Export / Import** — Share your connection list. Exports contain names, hosts, ports and usernames but **never passwords**; each recipient enters their own.
9. **Lock** — Click `Lock` to return to the password prompt. Happens automatically after 10 idle minutes.
10. **Theme** — Switch between Dark and Light at the bottom.

---

## 🔑 Forgotten Master Password

There is **no way to recover your saved passwords.** The master password is the encryption key and is not stored anywhere to be recovered, cracked, or reset back into readable data. That's the point of the design.

You can, however, wipe the vault and start over with a fresh one:

**From inside the app** — click **"Forgot your master password?"** on the unlock screen, type `RESET` to confirm, and you'll be returned to first-run setup.

**Manually** — delete both of these files and relaunch:

```
%LOCALAPPDATA%\NexusRDP\vault.dat
%LOCALAPPDATA%\NexusRDP\vault.meta.json
```

> Delete **both**. Removing only `vault.meta.json` leaves the app in a "Vault Unavailable" state rather than returning it to first-run setup. (That screen also offers a reset button.)

Either way, every saved connection and password is permanently gone.

---

## 📁 Project Structure

```
Nexus_RDP/
├── Nexus_RDP_v5.1.py        # Main application entry point
├── Nexus_RDP_v5.1.spec      # PyInstaller spec for building a standalone .exe
├── icon.ico                 # Application icon (used by PyInstaller)
├── SECURITY_AUDIT.md        # Findings the v5.0 rewrite addresses
└── README.md                # This file
```

**Your data is not stored in the project folder.** It lives in a fixed per-user location:

```
%LOCALAPPDATA%\NexusRDP\
├── vault.dat                # Encrypted vault (auto-generated)
└── vault.meta.json          # scrypt salt, cost parameters, lockout state (auto-generated)
```

v4.x wrote its files to the current working directory, which meant launching the app from a different folder produced a fresh "first run" — a trivial auth bypass — and scattered secrets wherever the shortcut happened to point.

---

## 🔨 Building a Standalone Executable

```powershell
pip install pyinstaller
pyinstaller --onefile --icon="icon.ico" --noconsole .\Nexus_RDP_v5.1.py
```

Or use the included spec:

```powershell
pyinstaller Nexus_RDP_v5.1.spec
```

The executable appears in `dist/`.

> 🔐 **Distribute the `.exe` on its own.** Unlike v4.x, there are no key or config files to ship alongside it — and there is nothing you *could* usefully ship, since the vault is bound to a master password rather than to a key file. The app creates its own vault under `%LOCALAPPDATA%` on first run.
>
> To move your connections to another machine, use **Export** and re-enter the passwords there. Copying `vault.dat` and `vault.meta.json` together also works, and the same master password will open them.

---

## 🔄 Upgrading from v4.x

Run v5 from the folder containing your v4 `secret.key` and `rdp_connections.json`. On the first-run setup screen you'll see **"Import my existing v4 connections"**, ticked by default.

1. Set your new master password.
2. Your v4 connections — including their passwords — are decrypted with the old key file and re-encrypted into the new vault.
3. You'll be asked whether to overwrite and delete `secret.key`, `rdp_connections.json` and `config.json`.

**Say yes.** Those files hold your passwords in a form that doesn't need your master password at all. Leaving them behind keeps the exact weakness v5 exists to close. They're overwritten before deletion, though on SSDs and copy-on-write filesystems that's best-effort rather than a guarantee.

Imported connections default to **Windowed** display mode; change it per connection via `Edit`.

---

## 📌 Version History

| Version | File | Highlights |
|---|---|---|
| **v5.1** | `Nexus_RDP_v5.1.py` | **Multi-monitor support** — per-connection display mode (windowed / fullscreen / `/multimon` / `/span`). **In-app vault reset** for a forgotten master password, behind typed confirmation. Display mode travels in exports. |
| **v5.0** | `Nexus_RDP_v5.0.py` | **Security rewrite.** Master password is now the encryption key (scrypt); `secret.key` and the stored password hash are gone. Whole-vault authenticated encryption. `CredWriteW` replaces `cmdkey`, keeping passwords off the command line. Host/port/username validation closes argument injection. Fixed per-user data directory. Atomic writes, idle auto-lock, login throttling, password-free export/import, one-time v4 migration. |
| **v4.2** | `Nexus_RDP_v4.2.py` | Duplicate connection, connection ordering, improved dialog behaviour, UI tweaks. |
| **v4.1** | `Nexus_RDP_v4.1.py` | Safe `stdout`/`stderr` handling for `--noconsole` mode, clean `quit()` flow for the Auth window. |

> v4.x is **deprecated and insecure.** See [What changed from v4.2, and why](#what-changed-from-v42-and-why).

---

## 📄 License

GNU General Public License v3.0. See the header of the main script for full terms.

---

## 👥 Authors

Created by **Netanel Elhadad**
