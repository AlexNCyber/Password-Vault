import os
import sys
import json
import base64
import hashlib
import hmac
import logging
import secrets
import string
import tkinter as tk
from tkinter import messagebox, filedialog
from pathlib import Path
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# ── Logging ────────────────────────────────────────────────────────────────────

logging.basicConfig(level=logging.ERROR, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

# ── Vault directory (fixed, private location) ──────────────────────────────────

def _vault_dir() -> Path:
    """Return a fixed, private directory for vault files (never CWD)."""
    if sys.platform == "win32":
        base = Path(os.environ.get("APPDATA", Path.home()))
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    vault = base / "PasswordVault"
    vault.mkdir(parents=True, exist_ok=True)
    return vault

VAULT_DIR  = _vault_dir()
SALT_FILE  = VAULT_DIR / "vault.salt"
VAULT_FILE = VAULT_DIR / "vault.json"
HASH_FILE  = VAULT_DIR / "vault.hash"

# ── Crypto helpers ─────────────────────────────────────────────────────────────

PBKDF2_ITERATIONS = 100_000


def _derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 32-byte Fernet key from a password + salt using PBKDF2-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def _hash_password(password: str, salt: bytes) -> str:
    """One-way hash of the password for verification (separate salt stretch)."""
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt + b"verify", PBKDF2_ITERATIONS)
    return dk.hex()


def setup_vault(password: str) -> bytes:
    """First-run: create salt, hash file. Returns derived Fernet key."""
    salt = os.urandom(32)
    SALT_FILE.write_bytes(salt)
    HASH_FILE.write_text(_hash_password(password, salt))
    return _derive_key(password, salt)


def verify_and_load_key(password: str):
    """Verify master password and return derived key, or None if wrong."""
    if not SALT_FILE.exists() or not HASH_FILE.exists():
        return None
    salt = SALT_FILE.read_bytes()
    stored_hash = HASH_FILE.read_text().strip()
    candidate = _hash_password(password, salt)
    if not hmac.compare_digest(candidate, stored_hash):
        return None
    return _derive_key(password, salt)


def is_first_run() -> bool:
    return not SALT_FILE.exists()


# ── Password generator ─────────────────────────────────────────────────────────

def generate_password(length: int = 16) -> str:
    """Generate a cryptographically secure random password."""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]"
    # Ensure at least one of each character class
    pwd = [
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits),
        secrets.choice("!@#$%^&*()-_=+[]"),
    ]
    pwd += [secrets.choice(alphabet) for _ in range(length - 4)]
    secrets.SystemRandom().shuffle(pwd)
    return "".join(pwd)


# ── Vault logic ────────────────────────────────────────────────────────────────

class PasswordVault:
    def __init__(self, key: bytes):
        self.cipher = Fernet(key)
        self._cache: dict | None = None  # in-memory cache, invalidated on write

    def _load_from_disk(self) -> dict:
        if not VAULT_FILE.exists():
            return {}
        try:
            data = VAULT_FILE.read_bytes()
            if not data:
                return {}
            return json.loads(self.cipher.decrypt(data).decode())
        except InvalidToken:
            logger.error("Vault decryption failed — file may be corrupt or tampered with.")
            return {}
        except Exception as exc:
            logger.error("Unexpected error loading vault: %s", exc)
            return {}

    def _data(self) -> dict:
        if self._cache is None:
            self._cache = self._load_from_disk()
        return self._cache

    def _flush(self, data: dict):
        encrypted = self.cipher.encrypt(json.dumps(data).encode())
        VAULT_FILE.write_bytes(encrypted)
        self._cache = data  # keep cache in sync

    def add(self, service: str, username: str, password: str):
        vault = dict(self._data())
        vault[service.lower()] = {"username": username, "password": password}
        self._flush(vault)

    def get(self, service: str) -> dict | None:
        return self._data().get(service.lower())

    def update(self, service: str, username: str, password: str):
        """Alias for add — same operation, clearer intent at call site."""
        self.add(service, username, password)

    def all_services(self) -> list[str]:
        return list(self._data().keys())

    def delete(self, service: str) -> bool:
        vault = dict(self._data())
        if service.lower() in vault:
            del vault[service.lower()]
            self._flush(vault)
            return True
        return False

    def export_encrypted(self, dest_path: str):
        """Copy the encrypted vault file to a user-chosen location."""
        import shutil
        shutil.copy2(VAULT_FILE, dest_path)


# ── Design tokens ──────────────────────────────────────────────────────────────

BG       = "#0F0F0F"
SURFACE  = "#1A1A1A"
BORDER   = "#2E2E2E"
TEXT     = "#F0F0F0"
SUBTEXT  = "#888888"
ACCENT   = "#3B82F6"
ACCENT_HV = "#2563EB"
DANGER   = "#EF4444"
SUCCESS  = "#22C55E"
FONT_UI  = ("Segoe UI", 10)


# ── Reusable widgets ───────────────────────────────────────────────────────────

def card(parent, **kwargs):
    return tk.Frame(parent, bg=SURFACE, relief="flat",
                    highlightbackground=BORDER, highlightthickness=1, **kwargs)


def label(parent, text, size=10, weight="normal", color=TEXT, **kwargs):
    return tk.Label(parent, text=text, bg=parent["bg"],
                    font=("Segoe UI", size, weight), fg=color, **kwargs)


def entry_field(parent, show=None):
    return tk.Entry(parent, show=show, font=FONT_UI, bg=SURFACE, fg=TEXT,
                    relief="flat", highlightthickness=1,
                    highlightbackground=BORDER, highlightcolor=ACCENT,
                    insertbackground=TEXT)


def btn(parent, text, command, primary=True, danger=False):
    bg  = DANGER if danger else (ACCENT if primary else SURFACE)
    fg  = SURFACE if (primary or danger) else TEXT
    hv  = DANGER if danger else (ACCENT_HV if primary else BORDER)
    b   = tk.Button(parent, text=text, command=command,
                    font=("Segoe UI", 10), bg=bg, fg=fg,
                    activebackground=hv, activeforeground=fg,
                    relief="flat", cursor="hand2", padx=14, pady=7,
                    highlightthickness=0, bd=0)
    b.bind("<Enter>", lambda e: b.config(bg=hv))
    b.bind("<Leave>", lambda e: b.config(bg=bg))
    return b


def divider(parent):
    return tk.Frame(parent, bg=BORDER, height=1)


# ── Lock screen ────────────────────────────────────────────────────────────────

MAX_ATTEMPTS = 5


class LockScreen(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Password Vault")
        self.configure(bg=BG)
        self.resizable(False, False)
        self._attempts = 0
        self._first_run = is_first_run()
        self._center(380, 310 if self._first_run else 280)
        self._build()

    def _center(self, w, h):
        self.geometry(f"{w}x{h}")
        self.update_idletasks()
        x = (self.winfo_screenwidth()  - w) // 2
        y = (self.winfo_screenheight() - h) // 2
        self.geometry(f"{w}x{h}+{x}+{y}")

    def _build(self):
        outer = tk.Frame(self, bg=BG)
        outer.pack(fill="both", expand=True, padx=32, pady=32)

        label(outer, "🔐 Password Vault", size=15, weight="bold").pack(anchor="w")

        if self._first_run:
            label(outer, "Create a master password to protect your vault.",
                  color=SUBTEXT, size=9).pack(anchor="w", pady=(4, 20))

            label(outer, "Master password", size=9, color=SUBTEXT).pack(anchor="w")
            self._pwd_entry = entry_field(outer, show="●")
            self._pwd_entry.pack(fill="x", ipady=7, pady=(3, 10))

            label(outer, "Confirm password", size=9, color=SUBTEXT).pack(anchor="w")
            self._confirm_entry = entry_field(outer, show="●")
            self._confirm_entry.pack(fill="x", ipady=7, pady=(3, 10))
            self._confirm_entry.bind("<Return>", lambda e: self._unlock())

            self._status = label(outer, "", size=9, color=DANGER)
            self._status.pack(anchor="w", pady=(0, 10))
            btn(outer, "Create vault", self._unlock).pack(anchor="w")
        else:
            label(outer, "Enter your master password to continue.",
                  color=SUBTEXT, size=9).pack(anchor="w", pady=(4, 20))

            label(outer, "Master password", size=9, color=SUBTEXT).pack(anchor="w")
            self._pwd_entry = entry_field(outer, show="●")
            self._pwd_entry.pack(fill="x", ipady=7, pady=(3, 10))
            self._pwd_entry.bind("<Return>", lambda e: self._unlock())

            self._status = label(outer, "", size=9, color=DANGER)
            self._status.pack(anchor="w", pady=(0, 10))
            btn(outer, "Unlock", self._unlock).pack(anchor="w")

        self._pwd_entry.focus()

    def _unlock(self):
        pwd = self._pwd_entry.get()

        if self._first_run:
            confirm = self._confirm_entry.get()
            if not pwd:
                self._status.config(text="Password cannot be empty.")
                return
            if pwd != confirm:
                self._status.config(text="Passwords do not match.")
                self._confirm_entry.delete(0, "end")
                return
            key = setup_vault(pwd)
            self._launch(key)
            return

        if self._attempts >= MAX_ATTEMPTS:
            return

        key = verify_and_load_key(pwd)
        self._pwd_entry.delete(0, "end")

        if key is None:
            self._attempts += 1
            remaining = MAX_ATTEMPTS - self._attempts
            if remaining <= 0:
                self._status.config(text="Too many attempts. App locked.")
                self._pwd_entry.config(state="disabled")
            else:
                self._status.config(
                    text=f"Incorrect password. {remaining} attempt{'s' if remaining != 1 else ''} remaining.")
        else:
            self._launch(key)

    def _launch(self, key):
        self.destroy()
        App(key).mainloop()


# ── Main app ───────────────────────────────────────────────────────────────────

class App(tk.Tk):
    def __init__(self, key: bytes):
        super().__init__()
        self.vault = PasswordVault(key)
        self._clipboard_clear_job = None
        self._retrieve_entry: tk.Entry | None = None  # stable reference, no widget search hack

        self.title("Password Vault")
        self.configure(bg=BG)
        self.resizable(False, False)
        self._center(480, 580)
        self._build()

    def _center(self, w, h):
        self.geometry(f"{w}x{h}")
        self.update_idletasks()
        x = (self.winfo_screenwidth()  - w) // 2
        y = (self.winfo_screenheight() - h) // 2
        self.geometry(f"{w}x{h}+{x}+{y}")

    def _build(self):
        hdr = tk.Frame(self, bg=SURFACE, highlightbackground=BORDER, highlightthickness=1)
        hdr.pack(fill="x")
        inner = tk.Frame(hdr, bg=SURFACE)
        inner.pack(padx=24, pady=18)
        label(inner, "🔐 Password Vault", size=15, weight="bold").pack(anchor="w")
        label(inner, "Store and retrieve credentials securely",
              color=SUBTEXT, size=9).pack(anchor="w", pady=(2, 0))

        self.tab_var = tk.StringVar(value="add")
        tab_row = tk.Frame(self, bg=BG)
        tab_row.pack(fill="x", padx=24, pady=(16, 0))

        self._tab_btns = {}
        for key, txt in [("add", "Add / Update"), ("retrieve", "Retrieve"), ("all", "All Entries")]:
            b = tk.Button(tab_row, text=txt, font=("Segoe UI", 10),
                          relief="flat", bd=0, cursor="hand2", padx=14, pady=8,
                          command=lambda k=key: self._switch(k))
            b.pack(side="left", padx=(0, 4))
            self._tab_btns[key] = b

        self._apply_tab_styles()

        self.content = tk.Frame(self, bg=BG)
        self.content.pack(fill="both", expand=True, padx=24, pady=16)
        self._switch("add")

    def _apply_tab_styles(self):
        active = self.tab_var.get()
        for key, b in self._tab_btns.items():
            if key == active:
                b.config(bg=ACCENT,   fg=SURFACE, activebackground=ACCENT_HV, activeforeground=SURFACE)
            else:
                b.config(bg=SURFACE,  fg=TEXT,    activebackground=BORDER,    activeforeground=TEXT)

    def _switch(self, key):
        self.tab_var.set(key)
        self._apply_tab_styles()
        for w in self.content.winfo_children():
            w.destroy()
        self._retrieve_entry = None
        {"add": self._page_add, "retrieve": self._page_retrieve, "all": self._page_all}[key]()

    # ── Add page ───────────────────────────────────────────────────────────────

    def _page_add(self):
        c = card(self.content)
        c.pack(fill="x")
        f = tk.Frame(c, bg=SURFACE)
        f.pack(padx=24, pady=24, fill="x")

        label(f, "Add or update credentials", size=12, weight="bold").pack(anchor="w")
        label(f, "Existing entries for the same service will be overwritten.",
              color=SUBTEXT, size=9).pack(anchor="w", pady=(3, 16))

        fields = {}
        for lbl, key, show in [
            ("Service / Website", "service",  None),
            ("Username",          "username", None),
            ("Password",          "password", "●"),
        ]:
            label(f, lbl, size=9, color=SUBTEXT).pack(anchor="w")
            row = tk.Frame(f, bg=SURFACE)
            row.pack(fill="x", pady=(3, 12))
            e = entry_field(row, show=show)
            e.pack(side="left", fill="x", expand=True, ipady=7)
            fields[key] = e

            # Generator button next to the password field
            if key == "password":
                def fill_generated(entry=e):
                    pwd = generate_password()
                    entry.config(show="")
                    entry.delete(0, "end")
                    entry.insert(0, pwd)
                    entry.config(show="")  # show it after generating so user can see it

                gen_btn = tk.Button(
                    row, text="Generate", font=("Segoe UI", 9),
                    bg=BORDER, fg=TEXT, activebackground=ACCENT, activeforeground=SURFACE,
                    relief="flat", cursor="hand2", padx=10, pady=7,
                    highlightthickness=0, bd=0, command=fill_generated)
                gen_btn.bind("<Enter>", lambda e: gen_btn.config(bg=ACCENT, fg=SURFACE))
                gen_btn.bind("<Leave>", lambda e: gen_btn.config(bg=BORDER, fg=TEXT))
                gen_btn.pack(side="left", padx=(6, 0))

        self._status_add = label(f, "", size=9)
        self._status_add.pack(anchor="w", pady=(0, 8))

        def save():
            svc = fields["service"].get().strip()
            usr = fields["username"].get().strip()
            pwd = fields["password"].get().strip()
            if not all([svc, usr, pwd]):
                self._flash(self._status_add, "All fields are required.", DANGER)
                return
            self.vault.add(svc, usr, pwd)
            for e in fields.values():
                e.delete(0, "end")
            self._flash(self._status_add, f"✓ Saved credentials for '{svc}'.", SUCCESS)

        btn(f, "Save credentials", save).pack(anchor="w")

    # ── Retrieve page ──────────────────────────────────────────────────────────

    def _page_retrieve(self):
        c = card(self.content)
        c.pack(fill="x")
        f = tk.Frame(c, bg=SURFACE)
        f.pack(padx=24, pady=24, fill="x")

        label(f, "Retrieve credentials", size=12, weight="bold").pack(anchor="w")
        label(f, "Enter a service name to look up its stored credentials.",
              color=SUBTEXT, size=9).pack(anchor="w", pady=(3, 16))

        label(f, "Service / Website", size=9, color=SUBTEXT).pack(anchor="w")
        svc_entry = entry_field(f)
        svc_entry.pack(fill="x", ipady=7, pady=(3, 12))
        self._retrieve_entry = svc_entry  # stable reference for _jump_to

        result_card = card(f)

        def lookup():
            for w in result_card.winfo_children():
                w.destroy()

            svc = svc_entry.get().strip()
            if not svc:
                return

            creds = self.vault.get(svc)
            result_card.pack(fill="x", pady=(12, 0))
            rf = tk.Frame(result_card, bg=SURFACE)
            rf.pack(padx=16, pady=16, fill="x")

            if creds:
                label(rf, svc.capitalize(), size=11, weight="bold").pack(anchor="w")
                divider(rf).pack(fill="x", pady=8)

                # Edit-in-place fields
                edit_fields = {}
                for field, val in [("Username", creds["username"]), ("Password", creds["password"])]:
                    fkey = field.lower()
                    row = tk.Frame(rf, bg=SURFACE)
                    row.pack(fill="x", pady=4)

                    label(row, field, size=9, color=SUBTEXT).pack(side="left")

                    copy_btn = tk.Button(
                        row, text="Copy", font=("Segoe UI", 9),
                        bg=BORDER, fg=TEXT, activebackground=ACCENT,
                        activeforeground=SURFACE, relief="flat",
                        cursor="hand2", padx=10, pady=3,
                        highlightthickness=0, bd=0)

                    def make_copy(v, b):
                        def _copy():
                            self.clipboard_clear()
                            self.clipboard_append(v)
                            b.config(text="Copied!", bg=SUCCESS, fg=SURFACE)
                            self.after(1500, lambda: b.config(text="Copy", bg=BORDER, fg=TEXT))
                            if self._clipboard_clear_job:
                                self.after_cancel(self._clipboard_clear_job)
                            self._clipboard_clear_job = self.after(30_000, self._clear_clipboard)
                        return _copy

                    copy_btn.config(command=make_copy(val, copy_btn))
                    copy_btn.bind("<Enter>", lambda e, b=copy_btn: b.config(bg=ACCENT, fg=SURFACE))
                    copy_btn.bind("<Leave>", lambda e, b=copy_btn: b.config(bg=BORDER, fg=TEXT))
                    copy_btn.pack(side="right")

                    show_btn = tk.Button(
                        row, text="Show", font=("Segoe UI", 9),
                        bg=BORDER, fg=TEXT, activebackground=BORDER,
                        activeforeground=TEXT, relief="flat",
                        cursor="hand2", padx=10, pady=3,
                        highlightthickness=0, bd=0)

                    ev = tk.Entry(row, font=FONT_UI, bg=SURFACE, fg=TEXT,
                                  relief="flat", bd=0, highlightthickness=0,
                                  readonlybackground=SURFACE,
                                  disabledbackground=SURFACE,
                                  disabledforeground=TEXT)
                    ev.insert(0, "●" * len(val))
                    ev.config(state="readonly")
                    edit_fields[fkey] = (ev, val)

                    def make_toggle(entry, button, value):
                        visible = [False]
                        def _toggle():
                            entry.config(state="normal")
                            entry.delete(0, "end")
                            if visible[0]:
                                entry.insert(0, "●" * len(value))
                                button.config(text="Show")
                                visible[0] = False
                            else:
                                entry.insert(0, value)
                                button.config(text="Hide")
                                visible[0] = True
                            entry.config(state="readonly")
                        return _toggle

                    show_btn.config(command=make_toggle(ev, show_btn, val))
                    show_btn.bind("<Enter>", lambda e, b=show_btn: b.config(bg=ACCENT, fg=SURFACE))
                    show_btn.bind("<Leave>", lambda e, b=show_btn: b.config(bg=BORDER, fg=TEXT))
                    show_btn.pack(side="right", padx=(0, 4))
                    ev.pack(side="right", padx=(0, 8))

                divider(rf).pack(fill="x", pady=(12, 8))

                # ── Edit section ───────────────────────────────────────────────
                label(rf, "Edit credentials", size=10, weight="bold").pack(anchor="w", pady=(4, 8))

                edit_inputs = {}
                for lbl_txt, fkey, show_char in [
                    ("New username", "username", None),
                    ("New password", "password", "●"),
                ]:
                    label(rf, lbl_txt, size=9, color=SUBTEXT).pack(anchor="w")
                    edit_row = tk.Frame(rf, bg=SURFACE)
                    edit_row.pack(fill="x", pady=(3, 8))
                    ei = entry_field(edit_row, show=show_char)
                    ei.pack(side="left", fill="x", expand=True, ipady=6)
                    edit_inputs[fkey] = ei

                    if fkey == "password":
                        def fill_gen(entry=ei):
                            p = generate_password()
                            entry.config(show="")
                            entry.delete(0, "end")
                            entry.insert(0, p)

                        gb = tk.Button(
                            edit_row, text="Generate", font=("Segoe UI", 9),
                            bg=BORDER, fg=TEXT, activebackground=ACCENT, activeforeground=SURFACE,
                            relief="flat", cursor="hand2", padx=10, pady=6,
                            highlightthickness=0, bd=0, command=fill_gen)
                        gb.bind("<Enter>", lambda e: gb.config(bg=ACCENT, fg=SURFACE))
                        gb.bind("<Leave>", lambda e: gb.config(bg=BORDER, fg=TEXT))
                        gb.pack(side="left", padx=(6, 0))

                edit_status = label(rf, "", size=9)
                edit_status.pack(anchor="w", pady=(0, 4))

                def save_edit(s=svc):
                    new_usr = edit_inputs["username"].get().strip()
                    new_pwd = edit_inputs["password"].get().strip()
                    if not new_usr and not new_pwd:
                        self._flash(edit_status, "Enter at least one field to update.", DANGER)
                        return
                    existing = self.vault.get(s) or {}
                    self.vault.update(
                        s,
                        new_usr or existing.get("username", ""),
                        new_pwd or existing.get("password", ""),
                    )
                    for ei in edit_inputs.values():
                        ei.delete(0, "end")
                    self._flash(edit_status, f"✓ Updated '{s}'.", SUCCESS)
                    lookup()  # refresh displayed values

                btn(rf, "Save changes", save_edit).pack(anchor="w")

                divider(rf).pack(fill="x", pady=(12, 8))

                def delete_entry(s=svc):
                    if messagebox.askyesno("Delete", f"Delete credentials for '{s}'?"):
                        self.vault.delete(s)
                        result_card.pack_forget()
                        svc_entry.delete(0, "end")

                btn(rf, "Delete entry", delete_entry, danger=True).pack(anchor="w")

            else:
                label(rf, f"No entry found for '{svc}'.", color=SUBTEXT).pack(anchor="w")

        svc_entry.bind("<Return>", lambda e: lookup())
        btn(f, "Look up", lookup).pack(anchor="w")

    # ── All entries page ───────────────────────────────────────────────────────

    def _page_all(self):
        services = self.vault.all_services()

        c = card(self.content)
        c.pack(fill="both", expand=True)
        f = tk.Frame(c, bg=SURFACE)
        f.pack(padx=24, pady=24, fill="both", expand=True)

        # Header row with Export button
        hdr_row = tk.Frame(f, bg=SURFACE)
        hdr_row.pack(fill="x")
        lbl_col = tk.Frame(hdr_row, bg=SURFACE)
        lbl_col.pack(side="left")
        label(lbl_col, "All entries", size=12, weight="bold").pack(anchor="w")
        label(lbl_col, f"{len(services)} saved service{'s' if len(services) != 1 else ''}",
              color=SUBTEXT, size=9).pack(anchor="w", pady=(3, 0))

        export_status = label(f, "", size=9)

        def export_vault():
            dest = filedialog.asksaveasfilename(
                title="Export encrypted vault",
                defaultextension=".json",
                filetypes=[("Vault backup", "*.json"), ("All files", "*.*")],
                initialfile="vault_backup.json",
            )
            if dest:
                try:
                    self.vault.export_encrypted(dest)
                    self._flash(export_status, f"✓ Vault exported to {dest}", SUCCESS)
                except Exception as exc:
                    self._flash(export_status, f"Export failed: {exc}", DANGER)

        exp_btn = btn(hdr_row, "Export backup", export_vault, primary=False)
        exp_btn.pack(side="right")

        export_status.pack(anchor="w", pady=(4, 12))

        if not services:
            label(f, "No credentials stored yet. Add one to get started.",
                  color=SUBTEXT).pack(anchor="w", pady=32)
            return

        scroll_frame = tk.Frame(f, bg=SURFACE)
        scroll_frame.pack(fill="both", expand=True)

        canvas = tk.Canvas(scroll_frame, bg=SURFACE, highlightthickness=0)
        sb = tk.Scrollbar(scroll_frame, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)

        inner = tk.Frame(canvas, bg=SURFACE)
        win = canvas.create_window((0, 0), window=inner, anchor="nw")

        def on_configure(e):
            canvas.configure(scrollregion=canvas.bbox("all"))
            canvas.itemconfig(win, width=canvas.winfo_width())

        inner.bind("<Configure>", on_configure)
        canvas.bind("<Configure>", on_configure)

        for i, svc in enumerate(sorted(services)):
            if i > 0:
                divider(inner).pack(fill="x")
            row = tk.Frame(inner, bg=SURFACE)
            row.pack(fill="x", pady=2)
            label(row, svc.capitalize(), size=10).pack(side="left", pady=8)
            btn(row, "View", lambda s=svc: self._jump_to(s), primary=False).pack(side="right", pady=4)

    def _jump_to(self, service: str):
        """Switch to Retrieve tab and pre-fill the service name — no widget search needed."""
        self._switch("retrieve")
        if self._retrieve_entry is not None:
            self._retrieve_entry.delete(0, "end")
            self._retrieve_entry.insert(0, service)

    # ── Helpers ────────────────────────────────────────────────────────────────

    def _flash(self, lbl, text, color):
        lbl.config(text=text, fg=color)
        self.after(4000, lambda: lbl.config(text=""))

    def _clear_clipboard(self):
        self.clipboard_clear()
        self.clipboard_append("")
        self._clipboard_clear_job = None


if __name__ == "__main__":
    LockScreen().mainloop()
