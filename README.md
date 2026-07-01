<div align="center">

# 🛡️ SafeNet-Family

**System-wide adult-content filtering for Windows**

![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=flat-square&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?style=flat-square&logo=windows&logoColor=white)
![License](https://img.shields.io/badge/License-GPL--3.0-green?style=flat-square)

[![Ko-fi](https://img.shields.io/badge/☕_Buy_Me_a_Coffee-F16061?style=for-the-badge&logo=ko-fi&logoColor=white)](https://ko-fi.com/netanelelhadad)
[![Support](https://img.shields.io/badge/❤️_Support_This_Project-FF5E5B?style=for-the-badge)](https://ko-fi.com/netanelelhadad)

</div>

---

A free, browser-independent content filter for a Windows 11 home PC. It does **not** depend on any single browser — it filters at the DNS, hosts-file, OS-policy and firewall levels, so it covers Edge, Chrome, Firefox, Brave, Opera, and any future browser, plus apps.

---

## 🔒 What it does (defence in depth)

| Layer | What it blocks | Works in every browser? |
|-------|----------------|--------------------------|
| **1. Filtering DNS** — Cloudflare for Families (`1.1.1.3`) | Adult + malware sites, the whole category | Yes (system-wide) |
| **2. Forced SafeSearch** (hosts file) | Explicit results on Google / Bing / YouTube | Yes (system-wide) |
| **3. SafeSearch policies** (Edge/Chrome/Brave/Firefox) | Locks SafeSearch in the browser UI | Browser-level |
| **4. DoH lockdown** | Browsers' encrypted DNS that would bypass filtering | Yes |
| **5. Firewall anti-bypass** | Manually switching to Google/Quad9/OpenDNS etc. | Yes |
| **6. Hosts blocklist** | Top adult domains, even if DNS is tampered with | Yes (system-wide) |
| **7. Auto-reapply task** | Reverts casual tampering hourly + at startup | n/a |

---

## 🚀 How to install

> [!IMPORTANT]
> **You must download or clone the entire repository** before running the GUI or the PowerShell scripts.
> The GUI scripts (`SafeNet-GUI-heb.py` / `SafeNet-GUI-eng.py`) depend on the PowerShell scripts (`Install.ps1`, `Status.ps1`, `Uninstall.ps1`) that are located in the same folder.
>
> **Quick download:** Click the green **"Code"** button on the [repository page](https://github.com/saago/SafeNet-Family) → **"Download ZIP"**, then extract the folder to your home PC (e.g. `C:\SafeNet-Family`).

---

You can install SafeNet-Family using the **Graphical User Interface (GUI)** or via standard **PowerShell scripts**.

### 🎨 Option 1: Using the GUI (Recommended)

1. **Install Python** (version 3.8 or higher) from [python.org](https://www.python.org/downloads/) if you don't have it.
2. **Install the required package:**
   ```powershell
   pip install customtkinter
   ```
3. **Run the GUI for your preferred language:**
   - **Hebrew version:**
     ```powershell
     python .\SafeNet-GUI-heb.py
     ```
   - **English version:**
     ```powershell
     python .\SafeNet-GUI-eng.py
     ```
4. In the GUI:
   - Select your preferred YouTube restriction mode (Strict or Moderate).
   - Click the install button (**"התקנה / עדכון"** / **"Install / Update"**) and approve the Administrator (UAC) prompt.
5. You can use the GUI anytime to check the status or uninstall the filter.

> [!TIP]
> Using the source code directly avoids false positives from antivirus software that often flag PyInstaller-generated executables as malware.

### 💻 Option 2: Using PowerShell Scripts (No GUI needed)
1. Copy the entire folder somewhere on the home PC, e.g. `C:\SafeNet-Family`.
2. Right-click **`Install.ps1`** → **Run with PowerShell**. Approve the Administrator (UAC) prompt.
   - Or, for the strongest setting:
     ```powershell
     powershell -ExecutionPolicy Bypass -File .\Install.ps1 -LockDownDNS
     ```
3. Close and reopen all browsers.
4. Check it worked:
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\Status.ps1
   ```
5. Test: try visiting an adult site or searching with SafeSearch off — it should be blocked.

---

## 🗑️ To remove it

Right-click **`Uninstall.ps1`** → **Run with PowerShell**. It restores your original DNS and removes everything. *(You can also do this via the GUI!)*

---

## ⚙️ Options

- **YouTube strictness:** `-YouTubeMode Strict` (default) or `-YouTubeMode Moderate`.
- **`-LockDownDNS`:** blocks *all* DNS except the filtering resolver. Strongest, but can break unusual home networks (e.g. a local Pi-hole). Try without it first.

---

## ⚠️ Honest limitations — please read

If **everyone on the PC has Administrator rights** and the goal is to block **everyone, including yourself**, be aware:

> [!CAUTION]
> **Anything Administrator sets, Administrator can undo.** Someone with admin rights can run `Uninstall.ps1`, delete the scheduled task, or change DNS back. The hourly re-apply task reverts *casual / accidental* changes, but it is **not** a lock against a determined admin user.

- **To make this genuinely hermetic, change one thing:** create a **separate Administrator account** with a password that the protected person does **not** have, then demote the everyday account(s) to **Standard user**. Standard users cannot change DNS, edit the hosts file, alter policies, or delete the task — so the filter becomes effectively unbreakable from that account.
  - *Quick way: Settings → Accounts → Other users → Add a "Guardian" admin account with a private password; then set the daily-use account to **Standard**.*
- **Even stronger (whole-home):** set Cloudflare for Families (`1.1.1.3` / `1.0.0.3`) on your **home router** as well, so every device on the network is filtered and a single PC can't opt out. Router-level + this PC-level setup is the best free combo.

---

## 📁 Files

| File | Purpose |
|------|---------|
| `SafeNet-GUI-heb.py` | Modern **Hebrew** graphical interface to manage installation and status. |
| `SafeNet-GUI-eng.py` | Modern **English** graphical interface to manage installation and status. |
| `Install.ps1`        | Applies everything + creates the auto-reapply task. Self-elevates. |
| `Apply-Filter.ps1`   | The actual enforcement (idempotent). Run by the scheduled task. |
| `Uninstall.ps1`      | Restores the PC to its prior state. |
| `Status.ps1`         | Read-only health check of all layers. |
| `state\`             | Auto-created: DNS backup + apply log. |

---

## 💡 Notes / troubleshooting

- **SafeSearch IPs** used: Google `216.239.38.120`, YouTube `216.239.38.120` (strict) / `216.239.38.119` (moderate), Bing `150.171.28.16`. These are the official forced-SafeSearch endpoints.
- If a legitimate site is wrongly blocked, it's almost always the DNS category filter — you can switch DNS to Cloudflare's `1.1.1.2` (malware-only) by editing `$FilterDnsV4` in `Apply-Filter.ps1`, but that stops blocking adult content.
- If your home network uses a local DNS server (e.g. Pi-hole) you want to keep, install **without** `-LockDownDNS`.
- Execution policy errors? Run installs with `powershell -ExecutionPolicy Bypass -File <script>`.
- **Antivirus warnings:** If Windows Defender or another AV flags files, use the Python source code instead of compiled executables (see Option 1 above).
