from __future__ import annotations

import argparse
import hashlib
import json
import os
import queue
import shutil
import sys
import tempfile
import threading
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

APP_NAME = "Packwiz-Installer"
USER_AGENT = "Packwiz-Installer-Python/0.1"


def http_get(url: str, timeout: int = 30) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def safe_target(root: Path, relative: str) -> Path:
    decoded = urllib.parse.unquote(relative).replace("\\", "/")
    candidate = Path(decoded)
    if candidate.is_absolute() or any(part in ("..", "") for part in candidate.parts):
        raise ValueError(f"Unsafe path in pack index: {relative}")
    target = (root / candidate).resolve()
    base = root.resolve()
    if target != base and base not in target.parents:
        raise ValueError(f"Path escapes installation directory: {relative}")
    return target


def murmur2(data: bytes) -> str:
    # Packwiz uses the 32-bit MurmurHash2 variant for CurseForge-style hashes.
    m = 0x5BD1E995
    h = 0
    length = len(data)
    offset = 0
    remaining = length
    while remaining >= 4:
        k = int.from_bytes(data[offset:offset + 4], "little")
        k = (k * m) & 0xFFFFFFFF
        k ^= k >> 24
        k = (k * m) & 0xFFFFFFFF
        h = ((h * m) ^ k) & 0xFFFFFFFF
        offset += 4
        remaining -= 4
    if remaining == 3:
        h ^= data[offset + 2] << 16
    if remaining >= 2:
        h ^= data[offset + 1] << 8
    if remaining >= 1:
        h ^= data[offset]
        h = (h * m) & 0xFFFFFFFF
    h ^= h >> 13
    h = (h * m) & 0xFFFFFFFF
    h ^= h >> 15
    return str(h)


def calculate_hash(data: bytes, algorithm: str) -> str:
    name = algorithm.lower().replace("-", "")
    if name == "murmur2":
        return murmur2(data)
    if name not in {"sha256", "sha512", "sha1", "md5"}:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")
    return hashlib.new(name, data).hexdigest()


def verify_hash(data: bytes, algorithm: str, expected: str, label: str) -> None:
    actual = calculate_hash(data, algorithm)
    if actual.lower() != str(expected).lower():
        raise ValueError(f"Hash mismatch for {label}: expected {expected}, got {actual}")


@dataclass
class InstallFile:
    path: str
    url: str | None
    hash_format: str
    hash_value: str
    preserve: bool = False
    optional: bool = False
    default: bool = True
    side: str = "both"
    description: str = ""


class PackInstaller:
    def __init__(self, pack_url: str, install_dir: Path, side: str,
                 selected_options: set[str] | None = None, progress=None):
        self.pack_url = pack_url
        self.root = install_dir.resolve()
        self.side = side
        self.selected_options = selected_options
        self.progress = progress or (lambda *_: None)
        self.pack: dict[str, Any] = {}
        self.files: list[InstallFile] = []

    def load(self) -> None:
        pack_bytes = http_get(self.pack_url)
        self.pack = tomllib.loads(pack_bytes.decode("utf-8-sig"))
        index_info = self.pack.get("index")
        if not isinstance(index_info, dict) or not index_info.get("file"):
            raise ValueError("pack.toml has no valid [index] file entry")
        index_url = urllib.parse.urljoin(self.pack_url, index_info["file"])
        index_bytes = http_get(index_url)
        verify_hash(index_bytes, index_info.get("hash-format", "sha256"),
                    index_info.get("hash", ""), "index.toml")
        index = tomllib.loads(index_bytes.decode("utf-8-sig"))
        default_hash = index.get("hash-format", "sha256")
        entries = index.get("files", [])
        if not isinstance(entries, list):
            raise ValueError("index.toml files must be an array of tables")

        self.files.clear()
        for entry in entries:
            rel = entry.get("file")
            if not rel:
                continue
            safe_target(self.root, rel)
            hash_format = entry.get("hash-format", default_hash)
            expected = entry.get("hash", "")
            metafile = bool(entry.get("metafile", False))
            file_url = urllib.parse.urljoin(index_url, rel)
            if metafile:
                meta_bytes = http_get(file_url)
                verify_hash(meta_bytes, hash_format, expected, rel)
                meta = tomllib.loads(meta_bytes.decode("utf-8-sig"))
                download = meta.get("download", {})
                option = meta.get("option", {})
                self.files.append(InstallFile(
                    path=meta.get("filename") or Path(rel).name.removesuffix(".pw.toml"),
                    url=download.get("url"),
                    hash_format=download.get("hash-format", "sha256"),
                    hash_value=download.get("hash", ""),
                    optional=bool(option.get("optional", False)),
                    default=bool(option.get("default", True)),
                    description=str(option.get("description", "")),
                    side=str(meta.get("side", "both")).lower(),
                ))
            else:
                self.files.append(InstallFile(
                    path=rel, url=file_url, hash_format=hash_format,
                    hash_value=expected, preserve=bool(entry.get("preserve", False))
                ))

    def optional_files(self) -> list[InstallFile]:
        return [item for item in self.files if item.optional and self._side_matches(item)]

    def _side_matches(self, item: InstallFile) -> bool:
        return item.side == "both" or self.side == "both" or item.side == self.side

    def install(self) -> None:
        selected = self.selected_options
        eligible = [f for f in self.files if self._side_matches(f)]
        if selected is not None:
            eligible = [f for f in eligible if not f.optional or f.path in selected]
        else:
            eligible = [f for f in eligible if not f.optional or f.default]

        total = len(eligible)
        self.root.mkdir(parents=True, exist_ok=True)
        for number, item in enumerate(eligible, 1):
            target = safe_target(self.root, item.path)
            if item.preserve and target.exists():
                self.progress(number, total, f"Preserved: {item.path}")
                continue
            if not item.url:
                raise ValueError(f"No download URL for {item.path}")
            target.parent.mkdir(parents=True, exist_ok=True)
            self.progress(number - 1, total, f"Downloading: {item.path}")
            payload = http_get(item.url)
            verify_hash(payload, item.hash_format, item.hash_value, item.path)
            fd, temp_name = tempfile.mkstemp(prefix=".packwiz-", dir=str(target.parent))
            try:
                with os.fdopen(fd, "wb") as stream:
                    stream.write(payload)
                os.replace(temp_name, target)
            finally:
                if os.path.exists(temp_name):
                    os.unlink(temp_name)
            self.progress(number, total, f"Installed: {item.path}")


class InstallerWindow:
    BG = "#f4f6f8"
    HEADER = "#e8edf2"
    FG = "#20252b"
    MUTED = "#64717d"

    def __init__(self, installer: PackInstaller, language: str):
        import tkinter as tk
        from tkinter import ttk

        self.tk = tk
        self.ttk = ttk
        self.installer = installer
        self.language = language
        self.messages = queue.Queue()
        self.options_open = False
        self.remaining = 10
        self.started = False
        self.selected: set[str] | None = None
        self.root = tk.Tk()
        self.root.title(APP_NAME)
        self.root.overrideredirect(True)
        self.root.configure(bg=self.BG)
        self.root.geometry("620x300")
        self.root.resizable(False, False)
        self._center()
        self._build()
        self.root.after(100, self._poll)

    def tr(self, ja: str, en: str) -> str:
        return ja if self.language == "ja" else en

    def _center(self):
        self.root.update_idletasks()
        x = (self.root.winfo_screenwidth() - 620) // 2
        y = (self.root.winfo_screenheight() - 300) // 2
        self.root.geometry(f"620x300+{x}+{y}")

    def _build(self):
        tk, ttk = self.tk, self.ttk
        header = tk.Frame(self.root, bg=self.HEADER, height=64)
        header.pack(fill="x")
        header.pack_propagate(False)
        tk.Label(header, text=APP_NAME, bg=self.HEADER, fg=self.FG,
                 font=("Segoe UI", 18, "bold")).pack(side="left", padx=22)
        tk.Button(header, text="×", command=self.root.destroy, relief="flat",
                  bg=self.HEADER, fg=self.FG, font=("Segoe UI", 16),
                  activebackground="#d8e0e8").pack(side="right", padx=12)
        body = tk.Frame(self.root, bg=self.BG, padx=28, pady=22)
        body.pack(fill="both", expand=True)
        self.status = tk.Label(body, text=self.tr("準備しています...", "Preparing..."),
                               bg=self.BG, fg=self.FG, anchor="w",
                               font=("Segoe UI", 11))
        self.status.pack(fill="x", pady=(0, 14))
        self.bar = ttk.Progressbar(body, mode="determinate", maximum=100)
        self.bar.pack(fill="x", pady=(0, 12))
        self.detail = tk.Label(body, text="", bg=self.BG, fg=self.MUTED,
                               anchor="w", font=("Segoe UI", 9))
        self.detail.pack(fill="x")
        footer = tk.Frame(body, bg=self.BG)
        footer.pack(side="bottom", fill="x")
        self.language_button = tk.Button(footer, text="日本語 / English",
            command=self._toggle_language, relief="flat", bg=self.BG, fg=self.MUTED)
        self.language_button.pack(side="left")
        self.options_button = tk.Button(footer, text=self.tr("オプション...", "Options..."),
            command=self._show_options, relief="flat", bg=self.BG, fg="#1769aa")
        self.options_button.pack_forget()
        if self.installer.optional_files():
            self.options_button.pack(side="right")

    def _toggle_language(self):
        self.language = "en" if self.language == "ja" else "ja"
        self.options_button.configure(text=self.tr("オプション...", "Options..."))

    def _show_options(self):
        if self.options_open:
            return
        self.options_open = True
        import tkinter as tk
        dialog = tk.Toplevel(self.root)
        dialog.title(self.tr("オプション", "Optional mods"))
        dialog.configure(bg=self.BG)
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.geometry("500x420")
        tk.Label(dialog, text=self.tr("導入する任意 Mod を選択してください",
            "Select optional mods to install"), bg=self.BG, fg=self.FG,
            font=("Segoe UI", 11, "bold")).pack(anchor="w", padx=18, pady=14)
        vars_by_path = {}
        for item in self.installer.optional_files():
            var = tk.BooleanVar(value=item.default if self.selected is None else item.path in self.selected)
            vars_by_path[item.path] = var
            label = item.path + (f" — {item.description}" if item.description else "")
            tk.Checkbutton(dialog, text=label, variable=var, bg=self.BG,
                           anchor="w", wraplength=450).pack(fill="x", padx=20, pady=3)
        def close():
            self.selected = {path for path, var in vars_by_path.items() if var.get()}
            self.options_open = False
            dialog.destroy()
        tk.Button(dialog, text=self.tr("決定", "Apply"), command=close,
                  relief="flat", bg="#dce8f3", padx=20, pady=6).pack(side="bottom", pady=16)
        dialog.protocol("WM_DELETE_WINDOW", close)
        self.root.wait_window(dialog)

    def _poll(self):
        try:
            while True:
                kind, data = self.messages.get_nowait()
                if kind == "progress":
                    current, total, message = data
                    self.status.configure(text=self.tr("インストール中...", "Installing..."))
                    self.detail.configure(text=message)
                    self.bar["value"] = int(current * 100 / total) if total else 0
                elif kind == "done":
                    self.status.configure(text=self.tr("インストールが完了しました。", "Installation completed."))
                    self.detail.configure(text=data)
                    self.bar["value"] = 100
                elif kind == "error":
                    self.status.configure(text=self.tr("エラーが発生しました", "An error occurred"))
                    self.detail.configure(text=data)
        except queue.Empty:
            pass
        if not self.started and not self.options_open:
            if self.remaining > 0:
                self.status.configure(text=self.tr(
                    f"任意 Mod を選択できます（{self.remaining} 秒後に開始）",
                    f"Optional mods available ({self.remaining}s until start)"))
                self.remaining -= 1
                self.root.after(1000, self._poll)
                return
            self._start_install()
        elif not self.started:
            self.root.after(250, self._poll)
            return
        self.root.after(100, self._poll)

    def _start_install(self):
        self.started = True
        self.installer.selected_options = self.selected
        self.installer.progress = lambda *args: self.messages.put(("progress", args))
        def run():
            try:
                self.installer.install()
                self.messages.put(("done", str(self.installer.root)))
            except Exception as exc:
                self.messages.put(("error", str(exc)))
        threading.Thread(target=run, daemon=True).start()

    def run(self):
        self.root.mainloop()


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog=APP_NAME)
    parser.add_argument("-g", "--no-gui", action="store_true", help="disable GUI")
    parser.add_argument("-s", "--side", choices=("client", "server", "both"), default="both")
    parser.add_argument("--install-dir", type=Path, default=Path.cwd())
    parser.add_argument("pack_url", help="URL to pack.toml")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    installer = PackInstaller(args.pack_url, args.install_dir, args.side)
    try:
        installer.load()
        optional = installer.optional_files()
        if args.no_gui:
            installer.selected_options = None
            installer.install()
            print(f"Installed pack into {installer.root}")
            return 0
        language = "ja" if os.environ.get("LANG", "").lower().startswith("ja") or os.name == "nt" else "en"
        if optional:
            InstallerWindow(installer, language).run()
        else:
            window = InstallerWindow(installer, language)
            window.remaining = 0
            window.run()
        return 0
    except Exception as exc:
        print(f"Packwiz Installer error: {exc}", file=sys.stderr)
        if not args.no_gui:
            try:
                import tkinter.messagebox as messagebox
                messagebox.showerror(APP_NAME, str(exc))
            except Exception:
                pass
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
