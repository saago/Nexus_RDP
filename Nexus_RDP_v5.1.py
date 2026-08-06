# ============================================================================
# Nexus RDP - Secure Remote Desktop Connection Manager
# Copyright (c) 2026 Netanel Elhadad
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
# ============================================================================
#
# v5.0 - Security rewrite. See SECURITY_AUDIT.md for the findings this
#        addresses. Summary of the security model:
#
#   * The master password is the ONLY secret. It is never stored, in any
#     form - no hash, no verifier, no key file. It is fed to scrypt to
#     derive the vault key at unlock time and the derived key is held in
#     memory only.
#   * The whole vault (names, hosts, usernames, passwords) is stored as a
#     single authenticated-encryption blob. Tampering is detected, not just
#     decryption failure.
#   * Correctness of the master password is proven by successfully
#     decrypting the vault. There is nothing on disk to compare against and
#     nothing to delete that grants access.
#   * Deleting or replacing the salt file does not reset access - it makes
#     the vault permanently undecryptable, so the app refuses to overwrite
#     an existing vault. There is no recovery path by design.
#
# v5.1 - Per-connection display mode, including multi-monitor sessions.
#
#   Each connection stores a 'display_mode' token which maps to a fixed mstsc
#   switch: none (windowed), /f, /multimon or /span. The token is checked
#   against an allow-list and then discarded - the argument mstsc receives is
#   a literal constant, never the stored string. This keeps the property
#   validate_host() was written to protect: nothing out of the vault can
#   introduce a command-line switch.
#
#   Existing vaults have no such key and default to the previous windowed
#   behaviour. Choosing specific monitors is not supported, because it would
#   require writing an .rdp file and this app deliberately writes no plaintext
#   configuration to disk.
#
# ============================================================================

import sys


# 1. Create a dummy object for print outputs to prevent crashes in noconsole mode
class DummyWriter:
    def write(self, *args, **kwargs):
        pass

    def flush(self):
        pass


# 2. Redirect print streams to the empty object (Must happen before CTK import!)
if sys.stdout is None:
    sys.stdout = DummyWriter()
if sys.stderr is None:
    sys.stderr = DummyWriter()

# 3. Only now import the rest of the libraries!
import atexit
import base64
import binascii
import hmac
import ipaddress
import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox

import customtkinter as ctk
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# --- Styling Settings ---
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

APP_NAME = "NexusRDP"
IS_WINDOWS = os.name == "nt"

# --- Vault layout ---------------------------------------------------------
# vault.dat       : Fernet token. Plaintext is the full JSON document.
# vault.meta.json : scrypt salt + cost parameters + throttle state.
#                   Contains NO password material of any kind.
VAULT_FILENAME = "vault.dat"
META_FILENAME = "vault.meta.json"

VAULT_FORMAT = 2
CANARY = b"NEXUS-RDP-VAULT-V2"

# scrypt cost. n is the memory/CPU knob: 2**16 * 8 * 128 bytes ~= 64 MB and
# roughly 0.1-0.5 s on typical office hardware. Parameters are persisted per
# vault so they can be raised later without breaking existing vaults; a vault
# is re-derived with whatever parameters its own meta file records.
SCRYPT_N = 2 ** 16
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_LEN = 32
SCRYPT_MAXMEM_GUARD = 512 * 1024 * 1024  # refuse absurd params from a tampered meta file

# --- Limits (defensive: every one of these is reachable from an untrusted
# --- import file or a tampered vault, so they are enforced on read AND write)
MAX_CONNECTIONS = 2000
MAX_NAME_LEN = 96
MAX_HOST_LEN = 253
MAX_USER_LEN = 256
MAX_PASSWORD_LEN = 512
MAX_FILE_BYTES = 8 * 1024 * 1024

# --- Display mode (multi-monitor support) ---------------------------------
# Each connection stores one of these tokens. The token itself is NEVER passed
# to mstsc. It selects an entry from DISPLAY_MODE_FLAGS, whose values are
# literal constants written out below, so the stored value can only ever choose
# between a fixed set of argv shapes - it can never become one. See the comment
# on validate_display_mode() for why that indirection is not optional here.
DISPLAY_MODE_WINDOW = "window"
DISPLAY_MODE_FULLSCREEN = "fullscreen"
DISPLAY_MODE_MULTIMON = "multimon"
DISPLAY_MODE_SPAN = "span"

DEFAULT_DISPLAY_MODE = DISPLAY_MODE_WINDOW

# token -> literal mstsc arguments. An empty tuple means "add nothing", which is
# the v5.0 behaviour and therefore the default for every existing connection.
DISPLAY_MODE_FLAGS = {
    DISPLAY_MODE_WINDOW: (),
    DISPLAY_MODE_FULLSCREEN: ("/f",),
    DISPLAY_MODE_MULTIMON: ("/multimon",),
    DISPLAY_MODE_SPAN: ("/span",),
}
DISPLAY_MODES = tuple(DISPLAY_MODE_FLAGS)

DISPLAY_MODE_LABELS = {
    DISPLAY_MODE_WINDOW: "Windowed (single monitor)",
    DISPLAY_MODE_FULLSCREEN: "Fullscreen (single monitor)",
    DISPLAY_MODE_MULTIMON: "Use all my monitors",
    DISPLAY_MODE_SPAN: "Span across monitors",
}
DISPLAY_MODE_BY_LABEL = {label: mode for mode, label in DISPLAY_MODE_LABELS.items()}

# Shown under the selector. /multimon and /span are genuinely different: multimon
# gives the remote session one distinct monitor per local monitor, while span is
# still a single-monitor session stretched over a rectangle of displays, so a
# maximised remote window covers all of them at once.
DISPLAY_MODE_HINTS = {
    DISPLAY_MODE_WINDOW: "Opens in a resizable window on one monitor.",
    DISPLAY_MODE_FULLSCREEN: "Fills one monitor. Ctrl+Alt+Break toggles back.",
    DISPLAY_MODE_MULTIMON: ("Each of your monitors appears as a separate monitor in the "
                            "remote session. Any layout or resolution."),
    DISPLAY_MODE_SPAN: ("One wide desktop across your monitors. They must share a "
                        "resolution and sit side by side, or Windows falls back to one."),
}

# Compact form for the connection list.
DISPLAY_MODE_SHORT = {
    DISPLAY_MODE_WINDOW: "windowed",
    DISPLAY_MODE_FULLSCREEN: "fullscreen",
    DISPLAY_MODE_MULTIMON: "all monitors",
    DISPLAY_MODE_SPAN: "spanned",
}

# --- Auth hardening ---
MIN_MASTER_PASSWORD_LEN = 4
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_SECONDS = 60          # doubles per lockout, capped
LOCKOUT_SECONDS_MAX = 3600
IDLE_LOCK_SECONDS = 10 * 60   # auto-lock the UI after this much inactivity

# --- Legacy (v4.x) files, for one-time migration ---
LEGACY_KEY_FILE = "secret.key"
LEGACY_DATA_FILE = "rdp_connections.json"
LEGACY_CONFIG_FILE = "config.json"


# ============================================================================
# Filesystem helpers
# ============================================================================

def app_data_dir():
    """Fixed per-user location.

    v4 wrote to the current working directory, which meant launching the app
    from a different folder produced a fresh 'first run' - a trivial auth
    bypass - and left secrets wherever the shortcut happened to point.
    """
    if IS_WINDOWS:
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        path = os.path.join(base, APP_NAME)
    else:
        base = os.environ.get("XDG_DATA_HOME") or os.path.join(os.path.expanduser("~"), ".local", "share")
        path = os.path.join(base, "nexus-rdp")
    os.makedirs(path, exist_ok=True)
    return path


def _harden_path(path, is_dir=False):
    """Restrict a path to the current user, where the OS lets us do that safely.

    POSIX: chmod, which is precise and cannot fail halfway.

    Windows: deliberately a no-op. An earlier version of this function ran
    `icacls <path> /inheritance:r /grant:r <user>:(OI)(CI)F` here, which was a
    mistake in two ways. (OI)(CI) are directory inheritance flags and are
    invalid on a file, and a bare %USERNAME% does not resolve on a
    domain-joined machine without the DOMAIN\\ prefix. Either failure leaves
    icacls having already applied /inheritance:r but not the grant - an empty
    DACL, which denies access to everyone including the file's owner. The next
    os.replace() then failed with WinError 5.

    Nothing of value is lost by dropping it. %LOCALAPPDATA% already carries an
    ACL granting the user, SYSTEM and Administrators - no other interactive
    user can read it, which is the property we actually need. Stripping the
    inherited SYSTEM and Administrators entries would not stop a local admin
    anyway, since they can take ownership at will. This is the same posture
    mainstream password managers take for their local stores.
    """
    if IS_WINDOWS:
        return
    try:
        os.chmod(path, 0o700 if is_dir else 0o600)
    except OSError:
        pass


def _atomic_write_bytes(path, data):
    """Write with restrictive permissions, then atomically replace.

    Atomic replace matters here: a half-written vault after a crash used to
    mean total data loss, and there is no backup to fall back on.
    """
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".nexus-", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        _harden_path(tmp)
        os.replace(tmp, path)
        _harden_path(path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    try:
        if not IS_WINDOWS:
            dir_fd = os.open(directory, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
    except OSError:
        pass


def _sweep_stale_temp_files(directory):
    """Remove leftover write-temp files.

    Normally there are none - _atomic_write_bytes cleans up after itself. This
    clears litter from an interrupted write, and from builds prior to the
    ACL fix above, whose temp files could survive with an unusable DACL.
    """
    try:
        entries = os.listdir(directory)
    except OSError:
        return
    for entry in entries:
        if entry.startswith(".nexus-") and entry.endswith(".tmp"):
            try:
                os.unlink(os.path.join(directory, entry))
            except OSError:
                pass


def _read_bytes_limited(path, limit=MAX_FILE_BYTES):
    size = os.path.getsize(path)
    if size > limit:
        raise VaultError("File is implausibly large; refusing to load it.")
    with open(path, "rb") as fh:
        return fh.read(limit + 1)[:limit]


def _shred(path):
    """Overwrite then unlink. Best effort only - on SSDs, journalling and
    copy-on-write filesystems the old blocks may survive. Used for legacy
    key material, where 'better than a plain delete' is the goal."""
    try:
        if not os.path.isfile(path):
            return
        size = os.path.getsize(path)
        with open(path, "r+b") as fh:
            for _ in range(2):
                fh.seek(0)
                fh.write(os.urandom(size))
                fh.flush()
                os.fsync(fh.fileno())
        os.unlink(path)
    except Exception:
        try:
            os.unlink(path)
        except OSError:
            pass


# ============================================================================
# Validation - every field that reaches a subprocess or the credential store
# ============================================================================

_HOSTNAME_LABEL = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


class ValidationError(ValueError):
    pass


def validate_host(raw):
    """Accept an IPv4/IPv6 literal or a DNS hostname. Reject everything else.

    This is the fix for argument injection: v4 passed the stored 'ip' string
    straight into the mstsc/cmdkey argv. A stored value of '/migrate' or
    'host /f' is not a shell injection (no shell is used) but Windows argv
    parsing and mstsc's own option handling will happily treat it as a switch,
    and 'cmdkey /generic:TERMSRV/<attacker value>' let a tampered data file
    redirect or overwrite arbitrary stored credentials.
    """
    host = (raw or "").strip()
    if not host:
        raise ValidationError("Host is required.")
    if len(host) > MAX_HOST_LEN:
        raise ValidationError("Host is too long.")
    if _CONTROL_CHARS.search(host):
        raise ValidationError("Host contains control characters.")
    if host.startswith(("-", "/")):
        raise ValidationError("Host may not begin with '-' or '/'.")
    if any(ch in host for ch in ' \t"\'\\|&<>^%$`'):
        raise ValidationError("Host contains disallowed characters.")

    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass

    if host.endswith("."):
        host = host[:-1]
    labels = host.split(".")
    if not labels or not all(_HOSTNAME_LABEL.match(label) for label in labels):
        raise ValidationError("Not a valid IP address or hostname.")
    return host


def validate_port(raw):
    if raw is None or str(raw).strip() == "":
        return 3389
    try:
        port = int(str(raw).strip())
    except ValueError:
        raise ValidationError("Port must be a number.")
    if not 1 <= port <= 65535:
        raise ValidationError("Port must be between 1 and 65535.")
    return port


def validate_username(raw):
    user = (raw or "").strip()
    if not user:
        return ""
    if len(user) > MAX_USER_LEN:
        raise ValidationError("Username is too long.")
    if _CONTROL_CHARS.search(user):
        raise ValidationError("Username contains control characters.")
    if user.startswith(("-", "/")):
        raise ValidationError("Username may not begin with '-' or '/'.")
    if '"' in user:
        raise ValidationError("Username may not contain a double quote.")
    return user


def validate_name(raw):
    name = (raw or "").strip()
    if not name:
        raise ValidationError("Connection name is required.")
    if len(name) > MAX_NAME_LEN:
        raise ValidationError("Connection name is too long.")
    if _CONTROL_CHARS.search(name):
        raise ValidationError("Connection name contains control characters.")
    return name


def validate_password_field(raw):
    pwd = raw or ""
    if len(pwd) > MAX_PASSWORD_LEN:
        raise ValidationError("Password is too long.")
    if "\x00" in pwd:
        raise ValidationError("Password may not contain a null byte.")
    return pwd


def validate_display_mode(raw):
    """Strict allow-list check for a connection's display mode.

    This field ends up deciding part of the mstsc argv, which puts it in exactly
    the category validate_host() exists to police. The rule there applies here
    with more force: an argv contribution must come from an allow-list, never
    from a stored string.

    Note what is deliberately NOT happening: the stored value is not sanitised
    and forwarded. It is compared against a fixed set of tokens and then thrown
    away - the argument mstsc actually receives is a literal from
    DISPLAY_MODE_FLAGS. So even a vault whose plaintext is fully attacker
    controlled can only pick between four hard-coded command lines. Passing the
    stored string through, however carefully filtered, would hand back the
    ability to introduce a switch such as /admin, /shadow or /prompt.

    Empty or absent means the default, because every vault written before this
    feature existed has no such key.
    """
    if raw is None:
        return DEFAULT_DISPLAY_MODE
    if not isinstance(raw, str):
        raise ValidationError("Display mode must be text.")
    mode = raw.strip().lower()
    if not mode:
        return DEFAULT_DISPLAY_MODE
    if mode not in DISPLAY_MODE_FLAGS:
        raise ValidationError("Unknown display mode.")
    return mode


def coerce_display_mode(raw):
    """Lenient variant: never raises, falls back to the default.

    Used on every load path. _sanitize_connections() discards an entry whose
    validation fails, which is right for a host but wrong for an optional
    preference - a junk value in this one field must not delete the connection
    it belongs to, and older vaults legitimately have no value at all.
    """
    try:
        return validate_display_mode(raw)
    except ValidationError:
        return DEFAULT_DISPLAY_MODE


def display_mode_arguments(mode):
    """The literal mstsc arguments for a mode. Unknown modes contribute none."""
    return list(DISPLAY_MODE_FLAGS.get(mode, ()))


def host_for_display(host, port):
    literal = f"[{host}]" if ":" in host else host
    return literal if port == 3389 else f"{literal}:{port}"


def _character_classes(password):
    return sum([
        bool(re.search(r"[a-z]", password)),
        bool(re.search(r"[A-Z]", password)),
        bool(re.search(r"[0-9]", password)),
        bool(re.search(r"[^A-Za-z0-9]", password)),
    ])


def check_master_password_strength(password):
    """Hard floor only. Returns None if acceptable, else a reason to refuse.

    Deliberately permissive: the owner of the vault decides how much friction
    they want, and this app's realistic threat is casual access to an
    unattended desktop rather than a funded offline attack. The floor exists
    so an empty or single-character password cannot become the encryption key
    by accident.

    Enforced here rather than only in the UI, so it still applies to any
    caller of Vault.create() / change_master_password().
    """
    if len(password) < MIN_MASTER_PASSWORD_LEN:
        return f"Master password must be at least {MIN_MASTER_PASSWORD_LEN} characters."
    if len(password) > 1024:
        return "Master password is unreasonably long."
    return None


def master_password_warning(password):
    """Non-blocking advice shown next to the field. Never refuses a password.

    Since the master password IS the encryption key, its length is the entire
    cost of an offline attack on a copied vault file. scrypt at 64 MB per
    guess buys real time, but roughly 15 bits of it - it cannot rescue a
    4-character password, only slow it from seconds to hours.
    """
    if not password or len(password) < MIN_MASTER_PASSWORD_LEN:
        return None
    if len(password) >= 20:
        return None
    classes = _character_classes(password)
    if len(password) < 8 or classes < 2:
        return ("Short password. If someone copies your vault file, they could crack it "
                "offline in hours. Fine if the file stays on this machine.")
    if len(password) < 12:
        return "Moderate. 12+ characters is substantially harder to crack offline."
    return None


# ============================================================================
# Vault - key derivation, encryption, persistence
# ============================================================================

class VaultError(Exception):
    pass


class WrongPassword(VaultError):
    pass


class VaultLockedOut(VaultError):
    def __init__(self, seconds):
        super().__init__(f"Too many failed attempts. Try again in {int(seconds)} s.")
        self.seconds = seconds


class VaultUnrecoverable(VaultError):
    """Vault data present but its salt file is missing or unusable."""


STATE_NEW = "new"
STATE_READY = "ready"
STATE_ORPHANED_VAULT = "orphaned_vault"   # vault.dat without a usable meta
STATE_ORPHANED_META = "orphaned_meta"     # meta without vault.dat


def _derive_key(password, salt, n, r, p):
    if n <= 1 or (n & (n - 1)) != 0:
        raise VaultError("Vault parameters are invalid (n must be a power of two).")
    if r < 1 or p < 1 or 128 * r * n * p > SCRYPT_MAXMEM_GUARD:
        raise VaultError("Vault parameters are out of the supported range.")
    kdf = Scrypt(salt=salt, length=SCRYPT_LEN, n=n, r=r, p=p)
    raw = kdf.derive(password.encode("utf-8"))
    return base64.urlsafe_b64encode(raw)


class Vault:
    def __init__(self, directory=None):
        self.dir = directory or app_data_dir()
        # Re-apply on every start: a directory left behind by an older build
        # (or created by an installer) may have inherited loose permissions.
        _harden_path(self.dir, is_dir=True)
        _sweep_stale_temp_files(self.dir)
        self.vault_path = os.path.join(self.dir, VAULT_FILENAME)
        self.meta_path = os.path.join(self.dir, META_FILENAME)
        self._key = None
        self._doc = None
        self._session_failures = 0

    # -- state -----------------------------------------------------------
    def _read_meta(self):
        if not os.path.exists(self.meta_path):
            return None
        try:
            meta = json.loads(_read_bytes_limited(self.meta_path, 64 * 1024).decode("utf-8"))
            if not isinstance(meta, dict):
                return None
            base64.b64decode(meta["salt"], validate=True)
            int(meta["n"]), int(meta["r"]), int(meta["p"])
            return meta
        except (ValueError, KeyError, TypeError, OSError, binascii.Error, UnicodeDecodeError):
            return None

    def _write_meta(self, meta):
        _atomic_write_bytes(self.meta_path, json.dumps(meta, indent=2).encode("utf-8"))

    def state(self):
        has_vault = os.path.exists(self.vault_path)
        meta = self._read_meta()
        if has_vault and meta:
            return STATE_READY
        if has_vault and not meta:
            return STATE_ORPHANED_VAULT
        if meta and not has_vault:
            return STATE_ORPHANED_META
        return STATE_NEW

    @property
    def is_unlocked(self):
        return self._key is not None and self._doc is not None

    # -- throttling ------------------------------------------------------
    # The persisted counter is a speed bump, not a control: an attacker with
    # write access to the meta file can reset it. The real defense against
    # offline guessing is scrypt plus master-password strength. The counter
    # is here to slow down someone at the keyboard.
    def _throttle_check(self, meta):
        until = 0
        try:
            until = float(meta.get("lock_until", 0) or 0)
        except (TypeError, ValueError):
            until = 0
        remaining = until - time.time()
        if remaining > 0:
            raise VaultLockedOut(remaining)

    def _throttle_fail(self, meta):
        self._session_failures += 1
        try:
            failures = int(meta.get("failed_attempts", 0) or 0) + 1
        except (TypeError, ValueError):
            failures = 1
        meta["failed_attempts"] = failures
        if failures >= MAX_FAILED_ATTEMPTS:
            backoff = min(LOCKOUT_SECONDS * (2 ** (failures - MAX_FAILED_ATTEMPTS)), LOCKOUT_SECONDS_MAX)
            meta["lock_until"] = time.time() + backoff
        try:
            self._write_meta(meta)
        except OSError:
            pass

    def _throttle_reset(self, meta):
        if meta.get("failed_attempts") or meta.get("lock_until"):
            meta["failed_attempts"] = 0
            meta["lock_until"] = 0
            try:
                self._write_meta(meta)
            except OSError:
                pass

    # -- create / unlock -------------------------------------------------
    def create(self, password, connections=None):
        """Initialise a new vault. Refuses to run if any vault data exists.

        This is the direct fix for the reported bypass. In v4, deleting
        config.json restored 'first run' and let anyone set a new master
        password, because the password only guarded a hash comparison while
        the actual decryption key sat in secret.key. Now the key IS the
        password, so:
          - deleting the salt file does not grant access, it destroys access;
          - and we never silently create a fresh vault over existing data.
        """
        state = self.state()
        if state == STATE_ORPHANED_VAULT:
            raise VaultUnrecoverable(
                "A vault file exists but its key parameters file is missing or damaged.\n\n"
                "The vault cannot be decrypted without it. Restore the file from backup, "
                "or move the vault aside if you intend to start over."
            )
        if state != STATE_NEW:
            raise VaultError("A vault already exists in this location.")

        problem = check_master_password_strength(password)
        if problem:
            raise VaultError(problem)

        salt = os.urandom(32)
        meta = {
            "format": VAULT_FORMAT,
            "kdf": "scrypt",
            "salt": base64.b64encode(salt).decode("ascii"),
            "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P,
            "created_utc": int(time.time()),
            "failed_attempts": 0,
            "lock_until": 0,
        }
        key = _derive_key(password, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P)
        doc = {
            "canary": base64.b64encode(CANARY).decode("ascii"),
            "format": VAULT_FORMAT,
            "connections": _sanitize_connections(connections or {}),
        }
        # Write the vault first: if this fails we have not stranded a meta
        # file, and a lone meta file is harmless (STATE_ORPHANED_META).
        self._key = key
        self._doc = doc
        try:
            self._persist()
            self._write_meta(meta)
        except Exception:
            self.lock()
            raise

    def unlock(self, password):
        meta = self._read_meta()
        if not meta:
            if os.path.exists(self.vault_path):
                raise VaultUnrecoverable(
                    "The vault's key parameters file is missing or damaged, so the vault "
                    "cannot be decrypted. Restore it from backup."
                )
            raise VaultError("No vault found.")
        self._throttle_check(meta)

        key = _derive_key(password, base64.b64decode(meta["salt"]),
                          int(meta["n"]), int(meta["r"]), int(meta["p"]))
        try:
            blob = _read_bytes_limited(self.vault_path)
        except OSError as exc:
            raise VaultError(f"Cannot read the vault file: {exc.strerror or exc}")

        try:
            plaintext = Fernet(key).decrypt(blob)
        except InvalidToken:
            # Authenticated encryption: this covers a wrong password AND any
            # tampering with the ciphertext. There is no separate hash to
            # compare, so there is nothing on disk an attacker can forge.
            self._throttle_fail(meta)
            raise WrongPassword("Access denied: incorrect master password, or the vault has been altered.")

        try:
            doc = json.loads(plaintext.decode("utf-8"))
            canary = base64.b64decode(doc["canary"], validate=True)
        except (ValueError, KeyError, TypeError, binascii.Error, UnicodeDecodeError):
            raise VaultError("The vault decrypted but its contents are not readable.")
        if not hmac.compare_digest(canary, CANARY):
            raise VaultError("The vault decrypted but failed its integrity marker check.")

        self._throttle_reset(meta)
        self._session_failures = 0
        self._key = key
        self._doc = {
            "canary": doc["canary"],
            "format": doc.get("format", VAULT_FORMAT),
            "connections": _sanitize_connections(doc.get("connections", {})),
        }

    def lock(self):
        # Python strings/bytes are immutable, so this drops references rather
        # than scrubbing memory. Real scrubbing would need a mutable buffer
        # and would still not survive swap or a crash dump; the meaningful
        # mitigation is keeping the unlocked window short (see idle auto-lock).
        self._key = None
        self._doc = None

    def change_master_password(self, old_password, new_password):
        if not self.is_unlocked:
            raise VaultError("Unlock the vault first.")
        meta = self._read_meta()
        if not meta:
            raise VaultUnrecoverable("Key parameters file is missing.")
        self._throttle_check(meta)
        check_key = _derive_key(old_password, base64.b64decode(meta["salt"]),
                                int(meta["n"]), int(meta["r"]), int(meta["p"]))
        if not hmac.compare_digest(check_key, self._key):
            self._throttle_fail(meta)
            raise WrongPassword("Current master password is incorrect.")

        problem = check_master_password_strength(new_password)
        if problem:
            raise VaultError(problem)

        new_salt = os.urandom(32)
        new_key = _derive_key(new_password, new_salt, SCRYPT_N, SCRYPT_R, SCRYPT_P)
        old_key = self._key
        self._key = new_key
        try:
            self._persist()
        except Exception:
            self._key = old_key
            raise
        meta.update({
            "salt": base64.b64encode(new_salt).decode("ascii"),
            "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P,
            "rotated_utc": int(time.time()),
            "failed_attempts": 0, "lock_until": 0,
        })
        self._write_meta(meta)

    # -- data ------------------------------------------------------------
    @property
    def connections(self):
        if not self.is_unlocked:
            raise VaultError("Vault is locked.")
        return self._doc["connections"]

    def _persist(self):
        if self._key is None or self._doc is None:
            raise VaultError("Vault is locked.")
        payload = json.dumps(self._doc, separators=(",", ":")).encode("utf-8")
        _atomic_write_bytes(self.vault_path, Fernet(self._key).encrypt(payload))

    def save(self):
        if len(self._doc["connections"]) > MAX_CONNECTIONS:
            raise VaultError(f"Too many connections (limit {MAX_CONNECTIONS}).")
        self._persist()

    # -- legacy migration ------------------------------------------------
    def legacy_files_present(self, directory="."):
        key_path = os.path.join(directory, LEGACY_KEY_FILE)
        data_path = os.path.join(directory, LEGACY_DATA_FILE)
        return os.path.isfile(key_path) and os.path.isfile(data_path)

    def read_legacy_connections(self, directory="."):
        """Decrypt a v4 data file using its (password-independent) key file."""
        key = _read_bytes_limited(os.path.join(directory, LEGACY_KEY_FILE), 4096).strip()
        raw = json.loads(_read_bytes_limited(os.path.join(directory, LEGACY_DATA_FILE)).decode("utf-8"))
        if not isinstance(raw, dict):
            raise VaultError("Legacy data file has an unexpected structure.")
        cipher = Fernet(key)
        out = {}
        for name, info in list(raw.items())[:MAX_CONNECTIONS]:
            if not isinstance(info, dict):
                continue
            password = ""
            token = info.get("password") or ""
            if token:
                try:
                    password = cipher.decrypt(token.encode("utf-8")).decode("utf-8")
                except (InvalidToken, UnicodeDecodeError, ValueError):
                    password = ""
            try:
                out[validate_name(name)] = {
                    "host": validate_host(info.get("ip", "")),
                    "port": validate_port(info.get("port")),
                    "username": validate_username(info.get("username", "")),
                    "password": validate_password_field(password),
                    # v4 had no display preference; migrated entries keep the
                    # single-window behaviour they had before.
                    "display_mode": DEFAULT_DISPLAY_MODE,
                }
            except ValidationError:
                continue
        return out

    def shred_legacy_files(self, directory="."):
        for filename in (LEGACY_KEY_FILE, LEGACY_CONFIG_FILE):
            _shred(os.path.join(directory, filename))
        _shred(os.path.join(directory, LEGACY_DATA_FILE))


def _sanitize_connections(raw):
    """Normalise and validate a connections mapping from any source.

    Applied on load as well as on save, because the vault plaintext and any
    imported file are both data we should not trust to be well-formed even
    when the ciphertext authenticates.
    """
    clean = {}
    if not isinstance(raw, dict):
        return clean
    for name, info in list(raw.items())[:MAX_CONNECTIONS]:
        if not isinstance(info, dict):
            continue
        try:
            clean[validate_name(name)] = {
                "host": validate_host(info.get("host", info.get("ip", ""))),
                "port": validate_port(info.get("port")),
                "username": validate_username(info.get("username", "")),
                "password": validate_password_field(info.get("password", "")),
                # Coerced, not validated: a bad value here must not take the
                # whole connection down with it, and pre-feature vaults have
                # no such key. See coerce_display_mode().
                "display_mode": coerce_display_mode(info.get("display_mode")),
            }
        except ValidationError:
            continue
    return clean


# ============================================================================
# Password-free export / import
# ============================================================================

EXPORT_FORMAT = "nexus-rdp-export-1"


def build_export_document(connections):
    """Shareable connection list with every secret removed.

    This is the one file the app writes in the clear, so it is explicit about
    what it is. Note it still describes internal hosts and account names -
    useful to an attacker for reconnaissance - so treat it as internal.
    """
    return {
        "format": EXPORT_FORMAT,
        "_notice": "Shared configuration. Contains NO passwords. Each recipient must enter their own.",
        "contains_passwords": False,
        "exported_utc": int(time.time()),
        # display_mode is a preference, not a secret, so it travels with the
        # shared file. Adding an optional key does not need a format bump: an
        # older build ignores keys it does not know, and a newer build coerces
        # the missing key to the default (see parse_export_document).
        "connections": [
            {
                "name": name,
                "host": info["host"],
                "port": info["port"],
                "username": info.get("username", ""),
                "display_mode": info.get("display_mode", DEFAULT_DISPLAY_MODE),
            }
            for name, info in connections.items()
        ],
    }


def parse_export_document(blob):
    """Parse an untrusted export file. Returns (entries, skipped_count)."""
    try:
        doc = json.loads(blob.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise VaultError("That file is not valid JSON.")
    if not isinstance(doc, dict) or doc.get("format") != EXPORT_FORMAT:
        raise VaultError("That file is not a Nexus RDP configuration export.")
    items = doc.get("connections")
    if not isinstance(items, list):
        raise VaultError("The export file has no connection list.")

    entries, skipped = [], 0
    for item in items[:MAX_CONNECTIONS]:
        if not isinstance(item, dict):
            skipped += 1
            continue
        try:
            entries.append((
                validate_name(item.get("name", "")),
                {
                    "host": validate_host(item.get("host", item.get("ip", ""))),
                    "port": validate_port(item.get("port")),
                    "username": validate_username(item.get("username", "")),
                    "password": "",  # never accept a password from a shared file
                    # Coerced, so a hostile or simply older export cannot reject
                    # an otherwise importable entry on this field alone.
                    "display_mode": coerce_display_mode(item.get("display_mode")),
                },
            ))
        except ValidationError:
            skipped += 1
    skipped += max(0, len(items) - MAX_CONNECTIONS)
    return entries, skipped


# ============================================================================
# Windows credential handling
# ============================================================================
# v4 ran:  cmdkey /generic:TERMSRV/<ip> /user:<u> /pass:<plaintext>
# The password therefore appeared in a process command line, readable by any
# process on the machine (Task Manager details column, `wmic process get
# commandline`, WMI, Sysmon/4688 command-line auditing) for the lifetime of
# that short-lived process. Cleanup was a 5-second timer, so closing the app
# early left the credential in Credential Manager permanently.
#
# This version calls CredWriteW directly - no command line, no child process
# - writes the credential as session-scoped so Windows purges it at logoff
# even if we crash, and deletes it when mstsc actually exits.

class CredentialStoreError(Exception):
    pass


if IS_WINDOWS:
    import ctypes
    from ctypes import wintypes

    CRED_TYPE_GENERIC = 1
    CRED_PERSIST_SESSION = 1

    class _FILETIME(ctypes.Structure):
        _fields_ = [("dwLowDateTime", wintypes.DWORD), ("dwHighDateTime", wintypes.DWORD)]

    class _CREDENTIAL_ATTRIBUTEW(ctypes.Structure):
        _fields_ = [("Keyword", wintypes.LPWSTR), ("Flags", wintypes.DWORD),
                    ("ValueSize", wintypes.DWORD), ("Value", ctypes.POINTER(ctypes.c_byte))]

    class _CREDENTIALW(ctypes.Structure):
        _fields_ = [
            ("Flags", wintypes.DWORD),
            ("Type", wintypes.DWORD),
            ("TargetName", wintypes.LPWSTR),
            ("Comment", wintypes.LPWSTR),
            ("LastWritten", _FILETIME),
            ("CredentialBlobSize", wintypes.DWORD),
            ("CredentialBlob", ctypes.POINTER(ctypes.c_char)),
            ("Persist", wintypes.DWORD),
            ("AttributeCount", wintypes.DWORD),
            ("Attributes", ctypes.POINTER(_CREDENTIAL_ATTRIBUTEW)),
            ("TargetAlias", wintypes.LPWSTR),
            ("UserName", wintypes.LPWSTR),
        ]

    _advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    _advapi32.CredWriteW.argtypes = [ctypes.POINTER(_CREDENTIALW), wintypes.DWORD]
    _advapi32.CredWriteW.restype = wintypes.BOOL
    _advapi32.CredDeleteW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD]
    _advapi32.CredDeleteW.restype = wintypes.BOOL


def credential_target(host, port):
    # mstsc looks up TERMSRV/<host> (and TERMSRV/<host>:<port> for a
    # non-default port).
    return f"TERMSRV/{host_for_display(host, port)}"


def credential_write(target, username, password):
    if not IS_WINDOWS:
        raise CredentialStoreError("Credential storage is only available on Windows.")
    blob = password.encode("utf-16-le")
    buffer = ctypes.create_string_buffer(blob, len(blob))
    cred = _CREDENTIALW()
    ctypes.memset(ctypes.byref(cred), 0, ctypes.sizeof(cred))
    cred.Type = CRED_TYPE_GENERIC
    cred.TargetName = target
    cred.CredentialBlobSize = len(blob)
    cred.CredentialBlob = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_char))
    cred.Persist = CRED_PERSIST_SESSION
    cred.UserName = username or None
    try:
        if not _advapi32.CredWriteW(ctypes.byref(cred), 0):
            raise CredentialStoreError(
                f"Windows rejected the credential (error {ctypes.get_last_error()})."
            )
    finally:
        ctypes.memset(buffer, 0, len(blob))


def credential_delete(target):
    if not IS_WINDOWS:
        return
    try:
        _advapi32.CredDeleteW(target, CRED_TYPE_GENERIC, 0)
    except Exception:
        pass


class CredentialJanitor:
    """Tracks temporary credentials so none is left behind."""

    def __init__(self):
        self._pending = set()
        self._lock = threading.Lock()
        atexit.register(self.purge_all)

    def track(self, target):
        with self._lock:
            self._pending.add(target)

    def release(self, target):
        with self._lock:
            self._pending.discard(target)
        credential_delete(target)

    def purge_all(self):
        with self._lock:
            targets = list(self._pending)
            self._pending.clear()
        for target in targets:
            credential_delete(target)


JANITOR = CredentialJanitor()


def mstsc_path():
    """Absolute path, to avoid PATH/CWD binary hijacking.

    v4 used bare 'mstsc' and 'cmdkey', which Windows resolves via the
    application directory and PATH - a planted mstsc.exe next to the app
    would have received the target host, and been launched with whatever
    credential we had just cached.
    """
    system_root = os.environ.get("SystemRoot") or r"C:\Windows"
    candidate = os.path.join(system_root, "System32", "mstsc.exe")
    if os.path.isfile(candidate):
        return candidate
    found = shutil.which("mstsc.exe")
    if found:
        return found
    raise FileNotFoundError("mstsc.exe was not found on this system.")


# ============================================================================
# UI - Authentication
# ============================================================================

class AuthWindow(ctk.CTk):
    """Handles first-run setup, unlock, and legacy migration."""

    def __init__(self, vault):
        super().__init__()
        self.vault = vault
        self.unlocked = False
        self.busy = False
        self.title("Nexus RDP - Security")
        self.geometry("420x480")
        self.resizable(False, False)

        self.state_name = vault.state()
        self.setup_mode = self.state_name in (STATE_NEW, STATE_ORPHANED_META)
        self.migrate_offer = self.setup_mode and vault.legacy_files_present()

        if self.state_name == STATE_ORPHANED_VAULT:
            self._render_unrecoverable()
            return

        heading = "Set Master Password" if self.setup_mode else "Enter Master Password"
        ctk.CTkLabel(self, text=heading, font=("Arial", 20, "bold")).pack(pady=(28, 6))

        if self.setup_mode:
            ctk.CTkLabel(
                self,
                text=("This password encrypts your connections.\n"
                      "It is not stored anywhere. If you lose it,\n"
                      "the vault cannot be recovered."),
                font=("Arial", 12), text_color="#e0a800", justify="center",
            ).pack(pady=(0, 10))

        self.pass_entry = ctk.CTkEntry(self, placeholder_text="Master password", show="*", width=240)
        self.pass_entry.pack(pady=6)
        self.pass_entry.bind("<Return>", lambda _e: self.submit())

        self.confirm_entry = None
        self.warn_label = None
        if self.setup_mode:
            self.confirm_entry = ctk.CTkEntry(self, placeholder_text="Confirm password", show="*", width=240)
            self.confirm_entry.pack(pady=6)
            self.confirm_entry.bind("<Return>", lambda _e: self.submit())

            # Advisory only - it never blocks the password you chose.
            self.warn_label = ctk.CTkLabel(self, text="", font=("Arial", 11),
                                           text_color="#e0a800", wraplength=360, justify="center")
            self.warn_label.pack(pady=(6, 0))
            self.pass_entry.bind("<KeyRelease>", self._update_warning, add="+")

        if self.migrate_offer:
            self.migrate_var = tk.BooleanVar(value=True)
            ctk.CTkCheckBox(
                self, text="Import my existing v4 connections", variable=self.migrate_var,
                font=("Arial", 12),
            ).pack(pady=(10, 0))

        self.status_label = ctk.CTkLabel(self, text="", font=("Arial", 12), text_color="#dc3545",
                                         wraplength=360, justify="center")
        self.status_label.pack(pady=(10, 0))

        self.submit_btn = ctk.CTkButton(
            self, text="Create Vault" if self.setup_mode else "Unlock", command=self.submit
        )
        self.submit_btn.pack(pady=16)

        ctk.CTkLabel(self, text="Created by Netanel Elhadad", font=("Arial", 12),
                     text_color="gray").pack(side="bottom", pady=10)

        self.after(60, self.pass_entry.focus_force)

    def _render_unrecoverable(self):
        ctk.CTkLabel(self, text="Vault Unavailable", font=("Arial", 20, "bold"),
                     text_color="#dc3545").pack(pady=(40, 10))
        ctk.CTkLabel(
            self,
            text=("An encrypted vault was found, but the file holding its key\n"
                  "parameters is missing or damaged.\n\n"
                  "Without it the vault cannot be decrypted - and a new master\n"
                  "password would not help, because the password IS the key.\n\n"
                  "Restore vault.meta.json from backup, or move vault.dat aside\n"
                  "to start over (existing entries will be lost)."),
            font=("Arial", 12), justify="center",
        ).pack(pady=10, padx=20)
        ctk.CTkLabel(self, text=self.vault.dir, font=("Arial", 11), text_color="gray",
                     wraplength=380).pack(pady=6)
        ctk.CTkButton(self, text="Close", command=self.quit).pack(pady=18)

    def _update_warning(self, _event=None):
        if self.warn_label is not None:
            self.warn_label.configure(text=master_password_warning(self.pass_entry.get()) or "")

    def _set_busy(self, busy, message=""):
        self.busy = busy
        self.submit_btn.configure(state="disabled" if busy else "normal")
        self.status_label.configure(text=message, text_color="gray" if busy else "#dc3545")
        self.update_idletasks()

    def submit(self):
        if self.busy:
            return
        password = self.pass_entry.get()
        if not password:
            self.status_label.configure(text="Password cannot be empty.", text_color="#dc3545")
            return

        if self.setup_mode:
            if password != self.confirm_entry.get():
                self.status_label.configure(text="The two passwords do not match.", text_color="#dc3545")
                self.confirm_entry.delete(0, tk.END)
                return
            problem = check_master_password_strength(password)
            if problem:
                self.status_label.configure(text=problem, text_color="#dc3545")
                return
            self._create(password)
        else:
            self._unlock(password)

    def _create(self, password):
        self._set_busy(True, "Deriving key...")
        imported = None
        try:
            if self.migrate_offer and self.migrate_var.get():
                try:
                    imported = self.vault.read_legacy_connections()
                except Exception as exc:
                    self._set_busy(False)
                    messagebox.showwarning(
                        "Import failed",
                        f"Could not read the old files, so nothing was imported:\n{exc}",
                        parent=self,
                    )
                    imported = None
                    self._set_busy(True, "Deriving key...")
            self.vault.create(password, imported)
        except VaultError as exc:
            self._set_busy(False, str(exc))
            return
        except Exception as exc:
            self._set_busy(False, f"Could not create the vault: {exc}")
            return

        self._set_busy(False)
        if imported:
            count = len(imported)
            if messagebox.askyesno(
                "Remove old files?",
                f"Imported {count} connection(s) into the encrypted vault.\n\n"
                "The old files (secret.key, rdp_connections.json, config.json) still hold "
                "your passwords in a form that does not need your master password. "
                "Overwrite and delete them now?",
                parent=self,
            ):
                self.vault.shred_legacy_files()
        self.unlocked = True
        self.quit()

    def _unlock(self, password):
        self._set_busy(True, "Deriving key...")
        try:
            self.vault.unlock(password)
        except (WrongPassword, VaultLockedOut) as exc:
            self._set_busy(False, str(exc))
            self.pass_entry.delete(0, tk.END)
            return
        except VaultUnrecoverable as exc:
            self._set_busy(False)
            messagebox.showerror("Vault unavailable", str(exc), parent=self)
            return
        except VaultError as exc:
            self._set_busy(False, str(exc))
            return
        except Exception as exc:
            self._set_busy(False, f"Unlock failed: {exc}")
            return
        self._set_busy(False)
        self.unlocked = True
        self.quit()


# ============================================================================
# UI - Connection dialog
# ============================================================================

class ConnectionDialog(ctk.CTkToplevel):
    def __init__(self, parent, title, name=None, info=None, lock_name=False):
        super().__init__(parent)
        self.title(title)
        # Raised from 560 for the display selector: the layout is pack-based in a
        # non-resizable window, so a new widget falls off the bottom otherwise.
        self.geometry("380x680")
        self.resizable(False, False)
        self.result = None
        self.existing_password = (info or {}).get("password", "")
        self.transient(parent)
        self.after(10, self.focus_force)
        self.grab_set()

        ctk.CTkLabel(self, text=title, font=("Arial", 20, "bold")).pack(pady=(18, 12))

        self.name_entry = ctk.CTkEntry(self, placeholder_text="Connection Name", width=260)
        self.name_entry.pack(pady=6)
        self.host_entry = ctk.CTkEntry(self, placeholder_text="IP Address / Hostname", width=260)
        self.host_entry.pack(pady=6)
        self.port_entry = ctk.CTkEntry(self, placeholder_text="Port (default 3389)", width=260)
        self.port_entry.pack(pady=6)
        self.user_entry = ctk.CTkEntry(self, placeholder_text="Username (Optional)", width=260)
        self.user_entry.pack(pady=6)

        # Stored passwords are never written back into a widget. v4 decrypted
        # them into a CTkEntry on every edit, which put the plaintext into Tk's
        # widget state (and one 'show' toggle away from the screen) for no
        # functional benefit.
        self.replace_var = tk.BooleanVar(value=not self.existing_password)
        if self.existing_password:
            ctk.CTkLabel(self, text="A password is saved for this connection.",
                         font=("Arial", 12), text_color="gray").pack(pady=(10, 2))
            ctk.CTkCheckBox(self, text="Replace saved password", variable=self.replace_var,
                            command=self._toggle_password, font=("Arial", 12)).pack(pady=2)
        self.pass_entry = ctk.CTkEntry(self, placeholder_text="Password (Optional)", show="*", width=260)
        self.pass_entry.pack(pady=6)

        self.clear_var = tk.BooleanVar(value=False)
        if self.existing_password:
            ctk.CTkCheckBox(self, text="Delete saved password", variable=self.clear_var,
                            font=("Arial", 12)).pack(pady=2)

        # -- display mode ---------------------------------------------------
        # Stored per connection rather than globally: the same machine gets
        # docked to three screens at one desk and used on a laptop panel at
        # another, and the right answer differs per host.
        ctk.CTkLabel(self, text="Display", font=("Arial", 13, "bold")).pack(pady=(14, 2))
        initial_mode = coerce_display_mode((info or {}).get("display_mode"))
        self.display_var = tk.StringVar(value=DISPLAY_MODE_LABELS[initial_mode])
        ctk.CTkOptionMenu(
            self,
            values=[DISPLAY_MODE_LABELS[mode] for mode in DISPLAY_MODES],
            variable=self.display_var,
            command=self._update_display_hint,
            width=260,
        ).pack(pady=2)
        self.display_hint = ctk.CTkLabel(self, text="", font=("Arial", 11), text_color="gray",
                                         wraplength=300, justify="center")
        self.display_hint.pack(pady=(2, 0))

        self.error_label = ctk.CTkLabel(self, text="", font=("Arial", 12), text_color="#dc3545",
                                        wraplength=320, justify="center")
        self.error_label.pack(pady=(8, 0))

        ctk.CTkButton(self, text="Save", command=self.on_save).pack(pady=18)

        if name:
            self.name_entry.insert(0, name)
            if lock_name:
                self.name_entry.configure(state="disabled")
        if info:
            self.host_entry.insert(0, info.get("host", ""))
            self.port_entry.insert(0, str(info.get("port", 3389)))
            if info.get("username"):
                self.user_entry.insert(0, info["username"])
        self._toggle_password()
        self._update_display_hint()

    def _toggle_password(self):
        self.pass_entry.configure(state="normal" if self.replace_var.get() else "disabled")

    def _selected_display_mode(self):
        """Map the visible label back to its token, defaulting if it is unknown."""
        return DISPLAY_MODE_BY_LABEL.get(self.display_var.get(), DEFAULT_DISPLAY_MODE)

    def _update_display_hint(self, _choice=None):
        self.display_hint.configure(text=DISPLAY_MODE_HINTS.get(self._selected_display_mode(), ""))

    def on_save(self):
        try:
            name = validate_name(self.name_entry.get())
            host = validate_host(self.host_entry.get())
            port = validate_port(self.port_entry.get())
            user = validate_username(self.user_entry.get())
            display_mode = validate_display_mode(self._selected_display_mode())
            if self.clear_var.get():
                password = ""
            elif self.replace_var.get():
                password = validate_password_field(self.pass_entry.get())
            else:
                password = self.existing_password
        except ValidationError as exc:
            self.error_label.configure(text=str(exc))
            return
        self.result = (name, {"host": host, "port": port, "username": user,
                              "password": password, "display_mode": display_mode})
        self.destroy()


# ============================================================================
# UI - Main window
# ============================================================================

class RDPApp(ctk.CTk):
    def __init__(self, vault):
        super().__init__()
        self.vault = vault
        self.relock_requested = False
        self.title("Nexus RDP")
        self.geometry("600x640")
        self.protocol("WM_DELETE_WINDOW", self.on_close)

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        self.top_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.top_frame.grid(row=0, column=0, sticky="ew", padx=15, pady=15)
        self.top_frame.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(self.top_frame, text="NEXUS RDP", font=("Arial", 22, "bold")).grid(row=0, column=0, sticky="w")
        ctk.CTkButton(self.top_frame, text="+ Add", width=80,
                      command=self.add_connection).grid(row=0, column=1, sticky="e")
        ctk.CTkButton(self.top_frame, text="Lock", width=70, fg_color="#6c757d", hover_color="#5a6268",
                      command=self.lock_now).grid(row=0, column=2, sticky="e", padx=(8, 0))

        self.scrollable_frame = ctk.CTkScrollableFrame(self)
        self.scrollable_frame.grid(row=1, column=0, sticky="nsew", padx=15, pady=(0, 10))
        self.scrollable_frame.grid_columnconfigure(0, weight=1)

        self.bottom_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.bottom_frame.grid(row=2, column=0, sticky="ew", padx=15, pady=5)
        ctk.CTkButton(self.bottom_frame, text="Export (no passwords)", width=170, height=28,
                      command=self.export_config).pack(side="left")
        ctk.CTkButton(self.bottom_frame, text="Import", width=80, height=28,
                      command=self.import_config).pack(side="left", padx=8)
        ctk.CTkButton(self.bottom_frame, text="Master Password", width=140, height=28,
                      fg_color="#6c757d", hover_color="#5a6268",
                      command=self.change_master_password).pack(side="left")
        self.appearance_menu = ctk.CTkOptionMenu(
            self.bottom_frame, values=["Dark", "Light"], command=ctk.set_appearance_mode, width=90, height=28
        )
        self.appearance_menu.pack(side="right")

        self.credit_label = ctk.CTkLabel(self, text="Created by Netanel Elhadad", font=("Arial", 12),
                                         text_color="gray")
        self.credit_label.grid(row=3, column=0, pady=(0, 10))

        self.refresh_ui()

        # Idle auto-lock: bounds how long the derived key and plaintext
        # secrets stay resident on an unattended desktop.
        self._last_activity = time.monotonic()
        for sequence in ("<Any-KeyPress>", "<Any-Button>", "<Motion>", "<MouseWheel>"):
            self.bind_all(sequence, self._note_activity, add="+")
        self.after(15000, self._idle_tick)

    # -- helpers ---------------------------------------------------------
    def _note_activity(self, _event=None):
        self._last_activity = time.monotonic()

    def _idle_tick(self):
        idle = time.monotonic() - self._last_activity >= IDLE_LOCK_SECONDS
        # Never lock out from under a modal dialog: quitting the mainloop while
        # a nested wait_window is active tears down the parent mid-edit.
        if idle and self.grab_current() is None:
            self.lock_now()
            return
        self.after(15000, self._idle_tick)

    def _save(self):
        try:
            self.vault.save()
            return True
        except VaultError as exc:
            messagebox.showerror("Save failed", str(exc), parent=self)
        except OSError as exc:
            messagebox.showerror("Save failed", f"Could not write the vault: {exc.strerror or exc}", parent=self)
        return False

    def lock_now(self):
        JANITOR.purge_all()
        self.vault.lock()
        self.relock_requested = True
        self.quit()

    def on_close(self):
        JANITOR.purge_all()
        self.vault.lock()
        self.relock_requested = False
        self.quit()

    # -- rendering -------------------------------------------------------
    def refresh_ui(self):
        for widget in self.scrollable_frame.winfo_children():
            widget.destroy()

        connections = self.vault.connections
        if not connections:
            ctk.CTkLabel(self.scrollable_frame, text="No connections yet. Use '+ Add'.",
                         font=("Arial", 13), text_color="gray").pack(pady=30)
            return

        for name, info in connections.items():
            card = ctk.CTkFrame(self.scrollable_frame)
            card.pack(fill="x", pady=6, padx=2)
            card.grid_columnconfigure(0, weight=1)

            info_frame = ctk.CTkFrame(card, fg_color="transparent")
            info_frame.grid(row=0, column=0, sticky="w", padx=15, pady=10)
            ctk.CTkLabel(info_frame, text=name, font=("Arial", 15, "bold")).pack(anchor="w")
            subtitle = host_for_display(info["host"], info["port"])
            if info.get("username"):
                subtitle += f"  -  {info['username']}"
            if info.get("password"):
                subtitle += "  -  password saved"
            mode = coerce_display_mode(info.get("display_mode"))
            if mode != DEFAULT_DISPLAY_MODE:
                subtitle += f"  -  {DISPLAY_MODE_SHORT[mode]}"
            ctk.CTkLabel(info_frame, text=subtitle, font=("Arial", 12),
                         text_color="gray").pack(anchor="w", pady=(2, 0))

            btn_frame = ctk.CTkFrame(card, fg_color="transparent")
            btn_frame.grid(row=0, column=1, sticky="e", padx=10)

            order_frame = ctk.CTkFrame(btn_frame, fg_color="transparent")
            order_frame.pack(side="left", padx=(0, 10))
            ctk.CTkButton(order_frame, text="\u25b2", width=25, height=14, fg_color="#6c757d",
                          hover_color="#5a6268", command=lambda n=name: self.move(n, -1)).pack(pady=(0, 2))
            ctk.CTkButton(order_frame, text="\u25bc", width=25, height=14, fg_color="#6c757d",
                          hover_color="#5a6268", command=lambda n=name: self.move(n, 1)).pack()

            ctk.CTkButton(btn_frame, text="Connect", width=70, height=30, fg_color="#28a745",
                          hover_color="#218838", command=lambda n=name: self.connect(n)).pack(side="left", padx=3)
            ctk.CTkButton(btn_frame, text="Dup", width=45, height=30, fg_color="#17a2b8",
                          hover_color="#138496",
                          command=lambda n=name: self.duplicate_connection(n)).pack(side="left", padx=3)
            ctk.CTkButton(btn_frame, text="Edit", width=45, height=30, fg_color="#ffc107",
                          text_color="black", hover_color="#e0a800",
                          command=lambda n=name: self.edit_connection(n)).pack(side="left", padx=3)
            ctk.CTkButton(btn_frame, text="X", width=30, height=30, fg_color="#dc3545",
                          hover_color="#c82333",
                          command=lambda n=name: self.delete_connection(n)).pack(side="left", padx=3)

    # -- ordering --------------------------------------------------------
    def move(self, name, offset):
        connections = self.vault.connections
        keys = list(connections.keys())
        if name not in keys:
            return
        index = keys.index(name)
        target = index + offset
        if not 0 <= target < len(keys):
            return
        keys[index], keys[target] = keys[target], keys[index]
        reordered = {key: connections[key] for key in keys}
        connections.clear()
        connections.update(reordered)
        if self._save():
            self.refresh_ui()

    # -- CRUD ------------------------------------------------------------
    def add_connection(self):
        dialog = ConnectionDialog(self, "Add Connection")
        self.wait_window(dialog)
        if not dialog.result:
            return
        name, data = dialog.result
        if name in self.vault.connections:
            messagebox.showerror("Error", f"Connection '{name}' already exists.", parent=self)
            return
        if len(self.vault.connections) >= MAX_CONNECTIONS:
            messagebox.showerror("Error", f"Connection limit ({MAX_CONNECTIONS}) reached.", parent=self)
            return
        self.vault.connections[name] = data
        if self._save():
            self.refresh_ui()

    def edit_connection(self, name):
        info = self.vault.connections.get(name)
        if info is None:
            return
        dialog = ConnectionDialog(self, "Edit Connection", name, info, lock_name=True)
        self.wait_window(dialog)
        if not dialog.result:
            return
        _, data = dialog.result
        self.vault.connections[name] = data
        if self._save():
            self.refresh_ui()

    def duplicate_connection(self, name):
        info = self.vault.connections.get(name)
        if info is None:
            return
        new_name, counter = f"{name} - Copy", 1
        while new_name in self.vault.connections:
            counter += 1
            new_name = f"{name} - Copy ({counter})"
        dialog = ConnectionDialog(self, "Duplicate Connection", new_name[:MAX_NAME_LEN], dict(info))
        self.wait_window(dialog)
        if not dialog.result:
            return
        final_name, data = dialog.result
        if final_name in self.vault.connections:
            messagebox.showerror("Error", f"Connection '{final_name}' already exists.", parent=self)
            return
        self.vault.connections[final_name] = data
        if self._save():
            self.refresh_ui()

    def delete_connection(self, name):
        if name not in self.vault.connections:
            return
        if messagebox.askyesno("Delete", f"Are you sure you want to delete '{name}'?", parent=self):
            del self.vault.connections[name]
            if self._save():
                self.refresh_ui()

    # -- export / import -------------------------------------------------
    def export_config(self):
        connections = self.vault.connections
        if not connections:
            messagebox.showinfo("Export", "There is nothing to export yet.", parent=self)
            return
        if not messagebox.askyesno(
            "Export configuration",
            f"Export {len(connections)} connection(s) WITHOUT passwords.\n\n"
            "The file is plain text and will contain connection names, hosts, ports and "
            "usernames. No passwords are included.\n\n"
            "Continue?",
            parent=self,
        ):
            return
        path = filedialog.asksaveasfilename(
            parent=self, title="Export configuration (no passwords)",
            defaultextension=".json", initialfile="nexus-rdp-config.json",
            filetypes=[("Nexus RDP config", "*.json"), ("All files", "*.*")],
        )
        if not path:
            return
        document = build_export_document(connections)
        assert not any("password" in entry for entry in document["connections"])
        try:
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(document, fh, indent=2)
        except OSError as exc:
            messagebox.showerror("Export failed", f"Could not write the file: {exc.strerror or exc}", parent=self)
            return
        messagebox.showinfo(
            "Export complete",
            f"Wrote {len(document['connections'])} connection(s) to:\n{path}\n\n"
            "No passwords were included. Recipients will be prompted for their own.",
            parent=self,
        )

    def import_config(self):
        path = filedialog.askopenfilename(
            parent=self, title="Import configuration",
            filetypes=[("Nexus RDP config", "*.json"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            entries, skipped = parse_export_document(_read_bytes_limited(path))
        except VaultError as exc:
            messagebox.showerror("Import failed", str(exc), parent=self)
            return
        except OSError as exc:
            messagebox.showerror("Import failed", f"Could not read the file: {exc.strerror or exc}", parent=self)
            return

        connections = self.vault.connections
        added, renamed = 0, 0
        for name, data in entries:
            if len(connections) >= MAX_CONNECTIONS:
                skipped += 1
                continue
            final_name, counter = name, 1
            while final_name in connections:
                counter += 1
                suffix = f" ({counter})"
                final_name = name[:MAX_NAME_LEN - len(suffix)] + suffix
                renamed += 1
            connections[final_name] = data
            added += 1

        if added and not self._save():
            return
        self.refresh_ui()
        summary = f"Imported {added} connection(s)."
        if renamed:
            summary += f"\n{renamed} were renamed to avoid clashes."
        if skipped:
            summary += f"\n{skipped} entry(ies) were rejected as invalid."
        summary += "\n\nImported entries have no password - add yours via Edit."
        messagebox.showinfo("Import complete", summary, parent=self)

    # -- master password -------------------------------------------------
    def change_master_password(self):
        dialog = ChangePasswordDialog(self)
        self.wait_window(dialog)
        if not dialog.result:
            return
        old, new = dialog.result
        try:
            self.vault.change_master_password(old, new)
        except VaultError as exc:
            messagebox.showerror("Change failed", str(exc), parent=self)
            return
        except OSError as exc:
            messagebox.showerror("Change failed", f"Could not write the vault: {exc.strerror or exc}", parent=self)
            return
        messagebox.showinfo(
            "Master password changed",
            "The vault has been re-encrypted with the new master password.",
            parent=self,
        )

    # -- connect ---------------------------------------------------------
    def connect(self, name):
        info = self.vault.connections.get(name)
        if info is None:
            return
        if not IS_WINDOWS:
            messagebox.showerror("Unsupported", "Launching RDP sessions requires Windows.", parent=self)
            return
        try:
            host = validate_host(info["host"])
            port = validate_port(info["port"])
            user = validate_username(info.get("username", ""))
            # Re-validated here for the same reason host and port are: this is
            # the last point before the value influences an argv.
            display_mode = validate_display_mode(info.get("display_mode"))
        except ValidationError as exc:
            messagebox.showerror("Invalid connection", f"This entry cannot be used: {exc}", parent=self)
            return

        password = info.get("password", "")
        target = credential_target(host, port)
        credential_written = False

        if password:
            if not user:
                messagebox.showwarning(
                    "Username required",
                    "A saved password needs a username to go with it. Add one via Edit, "
                    "or Windows will prompt you.",
                    parent=self,
                )
            else:
                try:
                    credential_write(target, user, password)
                    JANITOR.track(target)
                    credential_written = True
                except CredentialStoreError as exc:
                    # Fail closed: never fall back to putting the password on a
                    # command line. Launch without it and let mstsc prompt.
                    messagebox.showwarning(
                        "Could not pre-fill credentials",
                        f"{exc}\n\nThe session will open and Windows will ask for the password.",
                        parent=self,
                    )
        try:
            executable = mstsc_path()
        except FileNotFoundError as exc:
            if credential_written:
                JANITOR.release(target)
            messagebox.showerror("Error", str(exc), parent=self)
            return

        # Every element here is either the absolute mstsc path, the validated
        # host, or a literal from DISPLAY_MODE_FLAGS. No stored string is ever
        # placed in argv in a position where mstsc could read it as a switch.
        command = [executable, f"/v:{host_for_display(host, port)}"]
        command.extend(display_mode_arguments(display_mode))

        try:
            process = subprocess.Popen(command, close_fds=True)
        except OSError as exc:
            if credential_written:
                JANITOR.release(target)
            messagebox.showerror("Error", f"Failed to launch the RDP client: {exc.strerror or exc}", parent=self)
            return

        if credential_written:
            # Remove the credential when mstsc actually exits, instead of after
            # a fixed 5-second guess.
            threading.Thread(
                target=self._cleanup_after, args=(process, target), daemon=True
            ).start()

    @staticmethod
    def _cleanup_after(process, target):
        try:
            process.wait()
        except Exception:
            pass
        finally:
            JANITOR.release(target)


class ChangePasswordDialog(ctk.CTkToplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Change Master Password")
        self.geometry("380x400")
        self.resizable(False, False)
        self.result = None
        self.transient(parent)
        self.after(10, self.focus_force)
        self.grab_set()

        ctk.CTkLabel(self, text="Change Master Password", font=("Arial", 18, "bold")).pack(pady=(20, 6))
        ctk.CTkLabel(self, text="The vault will be re-encrypted.\nThere is no recovery if you forget it.",
                     font=("Arial", 12), text_color="#e0a800", justify="center").pack(pady=(0, 10))

        self.old_entry = ctk.CTkEntry(self, placeholder_text="Current password", show="*", width=250)
        self.old_entry.pack(pady=6)
        self.new_entry = ctk.CTkEntry(self, placeholder_text="New password", show="*", width=250)
        self.new_entry.pack(pady=6)
        self.confirm_entry = ctk.CTkEntry(self, placeholder_text="Confirm new password", show="*", width=250)
        self.confirm_entry.pack(pady=6)
        self.warn_label = ctk.CTkLabel(self, text="", font=("Arial", 11), text_color="#e0a800",
                                       wraplength=320, justify="center")
        self.warn_label.pack(pady=(6, 0))
        self.new_entry.bind("<KeyRelease>",
                            lambda _e: self.warn_label.configure(
                                text=master_password_warning(self.new_entry.get()) or ""),
                            add="+")
        self.error_label = ctk.CTkLabel(self, text="", font=("Arial", 12), text_color="#dc3545",
                                        wraplength=320, justify="center")
        self.error_label.pack(pady=(6, 0))
        ctk.CTkButton(self, text="Change", command=self.on_submit).pack(pady=14)
        self.after(60, self.old_entry.focus_force)

    def on_submit(self):
        old, new, confirm = self.old_entry.get(), self.new_entry.get(), self.confirm_entry.get()
        if not old or not new:
            self.error_label.configure(text="All fields are required.")
            return
        if new != confirm:
            self.error_label.configure(text="The new passwords do not match.")
            return
        if new == old:
            self.error_label.configure(text="The new password must differ from the current one.")
            return
        problem = check_master_password_strength(new)
        if problem:
            self.error_label.configure(text=problem)
            return
        self.result = (old, new)
        self.destroy()


# ============================================================================
# Application Entry Point
# ============================================================================

def main():
    try:
        vault = Vault()
    except OSError as exc:
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("Nexus RDP", f"Cannot access the application data folder:\n{exc}")
        return 1

    try:
        while True:
            auth = AuthWindow(vault)
            auth.mainloop()
            unlocked = auth.unlocked
            try:
                auth.destroy()
            except tk.TclError:
                pass
            if not unlocked:
                return 0

            app = RDPApp(vault)
            app.mainloop()
            relock = app.relock_requested
            try:
                app.destroy()
            except tk.TclError:
                pass
            vault.lock()
            if not relock:
                return 0
    finally:
        JANITOR.purge_all()
        vault.lock()


if __name__ == "__main__":
    sys.exit(main())
