# ============================================================================
# Nexus RDP - Secure Remote Desktop Connection Manager
# Copyright (c) 2026 Netanel Elhadad & Meir Asulin
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

import sys

# 1. יצירת אובייקט ריק להדפסות למניעת קריסה ב-noconsole
class DummyWriter:
    def write(self, *args, **kwargs):
        pass
    def flush(self):
        pass

# 2. החלפת אפיקי ההדפסה לאובייקט הריק (חייב לקרות לפני הייבוא של CTK!)
if sys.stdout is None:
    sys.stdout = DummyWriter()
if sys.stderr is None:
    sys.stderr = DummyWriter()

# 3. רק עכשיו מייבאים את שאר הספריות!
import tkinter as tk
import customtkinter as ctk
from tkinter import messagebox
import json
import os
import subprocess
from cryptography.fernet import Fernet
import hashlib
import secrets

# --- הגדרות עיצוב ---
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

KEY_FILE = "secret.key"
DATA_FILE = "rdp_connections.json"
CONFIG_FILE = "config.json"


# --- לוגיקה של אבטחה: הצפנת נתונים (Fernet) ---
def load_or_create_key():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as key_file:
            key_file.write(key)
    with open(KEY_FILE, "rb") as key_file:
        return key_file.read()


cipher_suite = Fernet(load_or_create_key())


def encrypt_password(password):
    return cipher_suite.encrypt(password.encode()).decode()


def decrypt_password(encrypted_password):
    return cipher_suite.decrypt(encrypted_password.encode()).decode()


# --- לוגיקה של אבטחה: סיסמת מאסטר (Hash) ---
def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000)
    return salt, pwd_hash.hex()


def is_first_run():
    return not os.path.exists(CONFIG_FILE)


def save_master_password(password):
    salt, pwd_hash = hash_password(password)
    with open(CONFIG_FILE, "w") as f:
        json.dump({"salt": salt, "hash": pwd_hash}, f)


def verify_master_password(password):
    if not os.path.exists(CONFIG_FILE):
        return False
    with open(CONFIG_FILE, "r") as f:
        data = json.load(f)
    salt = data.get("salt")
    stored_hash = data.get("hash")
    _, pwd_hash = hash_password(password, salt)
    return pwd_hash == stored_hash


# --- ניהול נתונים ---
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}


def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=4)


# --- חלון אימות (Master Password) ---
class AuthWindow(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Nexus RDP - Security")
        self.geometry("350x280")
        self.eval('tk::PlaceWindow . center')
        self.authenticated = False
        self.first_run = is_first_run()

        title_text = "Set Master Password" if self.first_run else "Enter Master Password"
        ctk.CTkLabel(self, text=title_text, font=("Arial", 20, "bold")).pack(pady=30)

        self.pass_entry = ctk.CTkEntry(self, placeholder_text="Password", show="*", width=200)
        self.pass_entry.pack(pady=10)
        self.pass_entry.bind('<Return>', lambda event: self.authenticate())

        btn_text = "Save & Continue" if self.first_run else "Login"
        self.auth_btn = ctk.CTkButton(self, text=btn_text, command=self.authenticate)
        self.auth_btn.pack(pady=20)

        self.credit_label = ctk.CTkLabel(self, text="Created by Meir Asulin & Netanel Elhadad", font=("Arial", 12), text_color="gray")
        self.credit_label.pack(side="bottom", pady=10)

    def authenticate(self):
        password = self.pass_entry.get()
        if not password:
            messagebox.showerror("Error", "Password cannot be empty.")
            return

        # שימוש ב-quit כדי לא להקריס לולאות רקע
        if self.first_run:
            save_master_password(password)
            self.authenticated = True
            self.quit()
        else:
            if verify_master_password(password):
                self.authenticated = True
                self.quit()
            else:
                messagebox.showerror("Error", "Access Denied: Incorrect Password")
                self.pass_entry.delete(0, tk.END)


# --- חלון דיאלוג להוספה/עריכה ---
class ConnectionDialog(ctk.CTkToplevel):
    def __init__(self, parent, title, initial_data=None):
        super().__init__(parent)
        self.title(title)
        self.geometry("350x450")
        self.result = None
        self.after(10, self.focus_force)

        ctk.CTkLabel(self, text=title, font=("Arial", 20, "bold")).pack(pady=20)

        self.name_entry = ctk.CTkEntry(self, placeholder_text="Connection Name", width=250)
        self.name_entry.pack(pady=10)

        self.ip_entry = ctk.CTkEntry(self, placeholder_text="IP Address / Hostname", width=250)
        self.ip_entry.pack(pady=10)

        self.user_entry = ctk.CTkEntry(self, placeholder_text="Username (Optional)", width=250)
        self.user_entry.pack(pady=10)

        self.pass_entry = ctk.CTkEntry(self, placeholder_text="Password (Optional)", show="*", width=250)
        self.pass_entry.pack(pady=10)

        if initial_data:
            name, info = initial_data
            self.name_entry.insert(0, name)
            self.name_entry.configure(state="disabled")
            self.ip_entry.insert(0, info["ip"])
            if info["username"]:
                self.user_entry.insert(0, info["username"])
            if info.get("password"):
                self.pass_entry.insert(0, decrypt_password(info["password"]))

        self.save_btn = ctk.CTkButton(self, text="Save", command=self.on_save)
        self.save_btn.pack(pady=30)

    def on_save(self):
        name = self.name_entry.get().strip()
        ip = self.ip_entry.get().strip()
        user = self.user_entry.get().strip()
        password = self.pass_entry.get()

        if not name or not ip:
            messagebox.showerror("Error", "Please fill Connection Name and IP Address.")
            return

        encrypted_pass = encrypt_password(password) if password else ""

        self.result = (name, {"ip": ip, "username": user, "password": encrypted_pass})
        self.destroy()


# --- חלון ראשי - תצוגה קומפקטית ---
class RDPApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Nexus RDP")
        self.geometry("450x580")
        self.connections = load_data()

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        self.top_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.top_frame.grid(row=0, column=0, sticky="ew", padx=15, pady=15)
        self.top_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(self.top_frame, text="NEXUS RDP", font=("Arial", 22, "bold")).grid(row=0, column=0, sticky="w")
        ctk.CTkButton(self.top_frame, text="+ Add", width=80, command=self.add_connection).grid(row=0, column=1, sticky="e")

        self.scrollable_frame = ctk.CTkScrollableFrame(self)
        self.scrollable_frame.grid(row=1, column=0, sticky="nsew", padx=15, pady=(0, 10))
        self.scrollable_frame.grid_columnconfigure(0, weight=1)

        self.bottom_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.bottom_frame.grid(row=2, column=0, sticky="ew", padx=15, pady=5)

        self.appearance_menu = ctk.CTkOptionMenu(
            self.bottom_frame, values=["Dark", "Light"], command=ctk.set_appearance_mode, width=90, height=25
        )
        self.appearance_menu.pack(side="right")
        ctk.CTkLabel(self.bottom_frame, text="Theme:", font=("Arial", 12)).pack(side="right", padx=10)

        self.credit_label = ctk.CTkLabel(self, text="Created by Meir Asulin & Netanel Elhadad", font=("Arial", 12), text_color="gray")
        self.credit_label.grid(row=3, column=0, pady=(0, 10))

        self.refresh_ui()

    def refresh_ui(self):
        for widget in self.scrollable_frame.winfo_children():
            widget.destroy()

        for name, info in self.connections.items():
            card = ctk.CTkFrame(self.scrollable_frame)
            card.pack(fill="x", pady=6, padx=2)
            card.grid_columnconfigure(0, weight=1)

            info_frame = ctk.CTkFrame(card, fg_color="transparent")
            info_frame.grid(row=0, column=0, sticky="w", padx=15, pady=10)

            ctk.CTkLabel(info_frame, text=name, font=("Arial", 15, "bold")).pack(anchor="w")
            ctk.CTkLabel(info_frame, text=info["ip"], font=("Arial", 12), text_color="gray").pack(anchor="w", pady=(2, 0))

            btn_frame = ctk.CTkFrame(card, fg_color="transparent")
            btn_frame.grid(row=0, column=1, sticky="e", padx=10)

            ctk.CTkButton(btn_frame, text="Connect", width=70, height=28, fg_color="#28a745", hover_color="#218838",
                          command=lambda n=name: self.connect(n)).pack(side="left", padx=4)

            ctk.CTkButton(btn_frame, text="Edit", width=50, height=28, fg_color="#ffc107", text_color="black", hover_color="#e0a800",
                          command=lambda n=name: self.edit_connection(n)).pack(side="left", padx=4)

            ctk.CTkButton(btn_frame, text="X", width=30, height=28, fg_color="#dc3545", hover_color="#c82333",
                          command=lambda n=name: self.delete_connection(n)).pack(side="left", padx=4)

    def add_connection(self):
        dialog = ConnectionDialog(self, "Add Connection")
        self.wait_window(dialog)
        if dialog.result:
            name, data = dialog.result
            self.connections[name] = data
            save_data(self.connections)
            self.refresh_ui()

    def edit_connection(self, name):
        dialog = ConnectionDialog(self, "Edit Connection", (name, self.connections[name]))
        self.wait_window(dialog)
        if dialog.result:
            _, data = dialog.result
            self.connections[name] = data
            save_data(self.connections)
            self.refresh_ui()

    def delete_connection(self, name):
        if messagebox.askyesno("Delete", f"Are you sure you want to delete '{name}'?"):
            del self.connections[name]
            save_data(self.connections)
            self.refresh_ui()

    def connect(self, name):
        info = self.connections[name]
        ip = info["ip"]
        user = info["username"]
        encrypted_password = info.get("password", "")

        try:
            # הזרקת הסיסמה רק אם היא קיימת (חיבור רגיל)
            if encrypted_password:
                password = decrypt_password(encrypted_password)
                subprocess.run(["cmdkey", f"/generic:TERMSRV/{ip}", f"/user:{user}", f"/pass:{password}"], capture_output=True)

            # הפעלה עם /control לתמיכה בכרטיס חכם
            subprocess.Popen(["mstsc", f"/v:{ip}", "/control"])

            # מחיקה מהזיכרון רק אם הוזרקה סיסמה
            if encrypted_password:
                self.after(5000, lambda: subprocess.run(["cmdkey", f"/delete:TERMSRV/{ip}"], capture_output=True))

        except Exception as e:
            messagebox.showerror("Error", f"Failed to connect: {e}")


# --- הפעלת התוכנה ---
if __name__ == "__main__":
    auth_app = AuthWindow()
    auth_app.mainloop()

    # סגירה נקייה של חלון ה-Auth רק לאחר שהלולאה שלו הסתיימה
    if auth_app.authenticated:
        auth_app.destroy()
        app = RDPApp()
        app.mainloop()