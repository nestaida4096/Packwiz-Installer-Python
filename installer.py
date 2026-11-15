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
APP_VERSION = "1.0.3"
USER_AGENT = f"Packwiz-Installer-Python/{APP_VERSION}"


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
    BG = "#f3f6fa"
    HEADER = "#e8eef5"
    CARD = "#ffffff"
    FG = "#182230"
    MUTED = "#64748b"
    ACCENT = "#2563eb"
    BORDER = "#dce4ee"
    SUCCESS = "#15803d"
    ERROR = "#b42318"

    def __init__(self, installer: PackInstaller, language: str):
        import tkinter as tk
        from tkinter import ttk

        self.tk = tk
        self.ttk = ttk
        self.installer = installer
        self.language = language
        self.messages = queue.Queue()
        self.options_open = False
        self.remaining = 10.0
        self.last_countdown_tick = time.monotonic()
        self.started = False
        self.finished = False
        self.result_code = 0
        self.selected: set[str] | None = None
        self.optional = self.installer.optional_files()

        self.root = tk.Tk()
        self.root.title(APP_NAME)
        self.root.overrideredirect(True)
        self.root.configure(bg=self.BG)
        self.root.geometry("700x390")
        self.root.resizable(False, False)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self._center()
        self._configure_style()
        self._build()
        self.root.after(100, self._poll)

    def tr(self, ja: str, en: str) -> str:
        return ja if self.language == "ja" else en

    def _center(self):
        self.root.update_idletasks()
        width, height = 700, 390
        x = (self.root.winfo_screenwidth() - width) // 2
        y = (self.root.winfo_screenheight() - height) // 2
        self.root.geometry(f"{width}x{height}+{x}+{y}")

    def _configure_style(self):
        style = self.ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure(
            "Installer.Horizontal.TProgressbar",
            troughcolor="#e7edf4",
            background=self.ACCENT,
            bordercolor="#e7edf4",
            lightcolor=self.ACCENT,
            darkcolor=self.ACCENT,
            thickness=12,
        )

    def _label(self, parent, text="", *, size=10, weight="normal",
               color=None, bg=None, **kwargs):
        return self.tk.Label(
            parent, text=text, bg=bg or self.CARD,
            fg=color or self.FG,
            font=("Segoe UI", size, weight),
            **kwargs,
        )

    def _button(self, parent, text, command, *, primary=False):
        return self.tk.Button(
            parent,
            text=text,
            command=command,
            relief="flat",
            bd=0,
            padx=18,
            pady=9,
            cursor="hand2",
            bg=self.ACCENT if primary else "#e9eff6",
            fg="#ffffff" if primary else self.FG,
            activebackground="#1d4ed8" if primary else "#dce6f0",
            activeforeground="#ffffff" if primary else self.FG,
            disabledforeground="#94a3b8",
            font=("Segoe UI", 9, "bold"),
        )

    def _build(self):
        tk = self.tk

        header = tk.Frame(self.root, bg=self.HEADER, height=64)
        header.pack(fill="x")
        header.pack_propagate(False)

        title_area = tk.Frame(header, bg=self.HEADER)
        title_area.pack(side="left", fill="y", padx=(24, 0))
        self._label(
            title_area, APP_NAME, size=17, weight="bold", bg=self.HEADER
        ).pack(side="left", pady=15)

        self.close_button = tk.Button(
            header, text="×", command=self._on_close,
            relief="flat", bd=0, bg=self.HEADER, fg="#526174",
            activebackground="#d9e2ec", activeforeground=self.FG,
            font=("Segoe UI", 19), width=3, cursor="hand2",
        )
        self.close_button.pack(side="right", fill="y", padx=8)

        body = tk.Frame(self.root, bg=self.BG, padx=30, pady=24)
        body.pack(fill="both", expand=True)

        self.heading = self._label(
            body, self.tr("Modpack のインストール", "Installing modpack"),
            size=16, weight="bold", bg=self.BG,
        )
        self.heading.pack(anchor="w")
        self.intro = self._label(
            body,
            self.tr(
                "必要なファイルを確認し、安全にダウンロードしています。",
                "Verifying and downloading the required files.",
            ),
            size=9, color=self.MUTED, bg=self.BG,
        )
        self.intro.pack(anchor="w", pady=(5, 18))

        card = tk.Frame(
            body, bg=self.CARD, highlightthickness=1,
            highlightbackground=self.BORDER, padx=22, pady=20,
        )
        card.pack(fill="both", expand=True)

        status_row = tk.Frame(card, bg=self.CARD)
        status_row.pack(fill="x")
        self.status = self._label(
            status_row, self.tr("インストールの準備ができました", "Ready to install"),
            size=12, weight="bold",
        )
        self.status.pack(side="left", anchor="w")

        self.countdown_label = self._label(
            status_row, "", size=9, color=self.ACCENT, weight="bold"
        )
        self.countdown_label.pack(side="right")

        self.detail = self._label(
            card, self.tr("開始を待っています。", "Waiting to start."),
            size=9, color=self.MUTED, justify="left", anchor="w",
            wraplength=590,
        )
        self.detail.pack(fill="x", pady=(12, 18))

        self.bar = self.ttk.Progressbar(
            card, mode="determinate", maximum=100,
            style="Installer.Horizontal.TProgressbar",
        )
        self.bar.pack(fill="x")

        progress_row = tk.Frame(card, bg=self.CARD)
        progress_row.pack(fill="x", pady=(9, 0))
        self.progress_text = self._label(
            progress_row, self.tr("待機中", "Waiting"), size=8, color=self.MUTED
        )
        self.progress_text.pack(side="left")
        self.percent_text = self._label(
            progress_row, "0%", size=8, color=self.MUTED
        )
        self.percent_text.pack(side="right")

        footer = tk.Frame(body, bg=self.BG)
        footer.pack(fill="x", pady=(16, 0))

        self.language_button = tk.Button(
            footer, text="日本語  /  English",
            command=self._toggle_language,
            relief="flat", bd=0, bg=self.BG, fg=self.MUTED,
            activebackground=self.BG, activeforeground=self.FG,
            font=("Segoe UI", 9), cursor="hand2",
        )
        self.language_button.pack(side="left")

        self.options_button = self._button(
            footer, self.tr("オプションを選択", "Choose options"),
            self._show_options,
        )
        if self.optional:
            self.options_button.pack(side="right", padx=(8, 0))

        self.action_button = self._button(
            footer, self.tr("閉じる", "Close"), self._on_close, primary=True
        )
        self.action_button.pack(side="right")
        self.action_button.configure(state="disabled")

    def _toggle_language(self):
        self.language = "en" if self.language == "ja" else "ja"
        self.heading.configure(
            text=self.tr("Modpack のインストール", "Installing modpack")
        )
        self.intro.configure(text=self.tr(
            "必要なファイルを確認し、安全にダウンロードしています。",
            "Verifying and downloading the required files.",
        ))
        self.action_button.configure(
            text=self.tr("閉じる", "Close")
        )
        if self.optional:
            self.options_button.configure(
                text=self.tr("オプションを選択", "Choose options")
            )
        if not self.started:
            self._update_countdown_text()
        elif not self.finished:
            self.status.configure(text=self.tr(
                "ファイルをインストールしています",
                "Installing files",
            ))
        elif self.result_code == 0:
            self.status.configure(text=self.tr(
                "インストールが完了しました", "Installation completed"
            ))
            self.progress_text.configure(text=self.tr("完了", "Complete"))
        else:
            self.status.configure(text=self.tr(
                "インストールに失敗しました", "Installation failed"
            ))
            self.progress_text.configure(text=self.tr("エラー", "Error"))

    def _update_countdown_text(self):
        if not self.optional or self.started:
            self.countdown_label.configure(text="")
            return
        seconds = max(0, int(self.remaining + 0.999))
        self.status.configure(text=self.tr(
            "任意 Mod の選択が可能です",
            "Optional mods are available",
        ))
        self.countdown_label.configure(text=self.tr(
            f"自動開始まで {seconds} 秒",
            f"Starts in {seconds}s",
        ))
        self.detail.configure(text=self.tr(
            "必要に応じてオプションを変更してください。何も操作しない場合は既定の設定で開始します。",
            "Choose optional components if needed. Installation starts with the default selection when the countdown ends.",
        ))

    def _show_options(self):
        if self.options_open or self.started:
            return
        self.options_open = True
        tk = self.tk
        dialog = tk.Toplevel(self.root)
        dialog.title(self.tr("オプション", "Optional components"))
        dialog.configure(bg=self.BG)
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.resizable(True, True)
        dialog.geometry("560x500")

        outer = tk.Frame(dialog, bg=self.BG, padx=22, pady=20)
        outer.pack(fill="both", expand=True)
        self._label(
            outer, self.tr("追加コンポーネント", "Optional components"),
            size=14, weight="bold", bg=self.BG,
        ).pack(anchor="w")
        self._label(
            outer,
            self.tr(
                "インストールする項目にチェックを入れてください。",
                "Select the components you want to install.",
            ),
            size=9, color=self.MUTED, bg=self.BG,
        ).pack(anchor="w", pady=(5, 14))

        list_frame = tk.Frame(
            outer, bg=self.CARD, highlightthickness=1,
            highlightbackground=self.BORDER,
        )
        list_frame.pack(fill="both", expand=True)

        canvas = tk.Canvas(list_frame, bg=self.CARD, highlightthickness=0)
        scrollbar = self.ttk.Scrollbar(
            list_frame, orient="vertical", command=canvas.yview
        )
        content = tk.Frame(canvas, bg=self.CARD)
        content.bind(
            "<Configure>",
            lambda _event: canvas.configure(scrollregion=canvas.bbox("all")),
        )
        canvas_window = canvas.create_window(
            (0, 0), window=content, anchor="nw"
        )
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.bind(
            "<Configure>",
            lambda event: canvas.itemconfigure(canvas_window, width=event.width),
        )
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        vars_by_path = {}
        for index, item in enumerate(self.optional):
            row = tk.Frame(content, bg=self.CARD, padx=14, pady=10)
            row.pack(fill="x")
            var = tk.BooleanVar(
                value=item.default if self.selected is None
                else item.path in self.selected
            )
            vars_by_path[item.path] = var
            check = tk.Checkbutton(
                row, text=item.path, variable=var,
                bg=self.CARD, fg=self.FG, activebackground=self.CARD,
                activeforeground=self.FG, selectcolor=self.CARD,
                anchor="w", font=("Segoe UI", 9, "bold"),
                wraplength=450,
            )
            check.pack(fill="x", anchor="w")
            if item.description:
                self._label(
                    row, item.description, size=8, color=self.MUTED,
                    bg=self.CARD, justify="left", anchor="w",
                    wraplength=450,
                ).pack(fill="x", padx=(25, 0), pady=(2, 0))
            if index != len(self.optional) - 1:
                tk.Frame(content, bg="#edf1f5", height=1).pack(fill="x")

        button_row = tk.Frame(outer, bg=self.BG)
        button_row.pack(fill="x", pady=(16, 0))

        def close(apply: bool):
            if apply:
                self.selected = {
                    path for path, var in vars_by_path.items() if var.get()
                }
            self.options_open = False
            dialog.grab_release()
            dialog.destroy()
            self.last_countdown_tick = time.monotonic()
            self._update_countdown_text()

        self._button(
            button_row, self.tr("キャンセル", "Cancel"),
            lambda: close(False),
        ).pack(side="right")
        self._button(
            button_row, self.tr("選択を適用", "Apply selection"),
            lambda: close(True), primary=True,
        ).pack(side="right", padx=(0, 8))
        dialog.protocol("WM_DELETE_WINDOW", lambda: close(False))
        dialog.bind("<Escape>", lambda _event: close(False))
        dialog.wait_visibility()
        dialog.focus_set()

    def _set_progress(self, current: int, total: int):
        percent = int(current * 100 / total) if total else 0
        self.bar["value"] = percent
        self.percent_text.configure(text=f"{percent}%")
        self.progress_text.configure(text=self.tr(
            f"{current} / {total} ファイル",
            f"{current} / {total} files",
        ))

    def _poll(self):
        try:
            while True:
                kind, data = self.messages.get_nowait()
                if kind == "progress":
                    current, total, message = data
                    self.status.configure(text=self.tr(
                        "ファイルをインストールしています",
                        "Installing files",
                    ))
                    self.detail.configure(text=message)
                    self._set_progress(current, total)
                elif kind == "done":
                    self.finished = True
                    self.result_code = 0
                    self.status.configure(
                        text=self.tr("インストールが完了しました", "Installation completed"),
                        fg=self.SUCCESS,
                    )
                    self.detail.configure(text=self.tr(
                        f"保存先: {data}",
                        f"Installed to: {data}",
                    ))
                    self.bar["value"] = 100
                    self.percent_text.configure(text="100%")
                    self.progress_text.configure(text=self.tr("完了", "Complete"))
                    self.countdown_label.configure(text="")
                    self.action_button.configure(
                        state="normal",
                        text=self.tr("閉じる", "Close"),
                    )
                elif kind == "error":
                    self.finished = True
                    self.result_code = 1
                    self.status.configure(
                        text=self.tr("インストールに失敗しました", "Installation failed"),
                        fg=self.ERROR,
                    )
                    self.detail.configure(text=str(data))
                    self.progress_text.configure(text=self.tr("エラー", "Error"))
                    self.countdown_label.configure(text="")
                    self.action_button.configure(
                        state="normal",
                        text=self.tr("閉じる", "Close"),
                    )
        except queue.Empty:
            pass

        if not self.started and not self.options_open and not self.finished:
            now = time.monotonic()
            self.remaining = max(
                0.0, self.remaining - (now - self.last_countdown_tick)
            )
            self.last_countdown_tick = now
            if self.optional and self.remaining > 0:
                self._update_countdown_text()
                self.root.after(100, self._poll)
                return
            self._start_install()
        elif not self.started:
            self.last_countdown_tick = time.monotonic()

        self.root.after(100, self._poll)

    def _start_install(self):
        if self.started:
            return
        self.started = True
        self.installer.selected_options = self.selected
        self.installer.progress = lambda *args: self.messages.put(("progress", args))
        self.options_button.configure(state="disabled")
        self.status.configure(text=self.tr(
            "ダウンロードを開始しています",
            "Starting download",
        ))
        self.countdown_label.configure(text="")
        self.progress_text.configure(text=self.tr("開始中", "Starting"))
        self.detail.configure(text=self.tr(
            "ファイルの取得とハッシュ検証を行っています。",
            "Downloading files and verifying their hashes.",
        ))

        def run():
            try:
                self.installer.install()
                self.messages.put(("done", str(self.installer.root)))
            except Exception as exc:
                self.messages.put(("error", str(exc)))

        threading.Thread(target=run, daemon=True).start()

    def _on_close(self):
        if self.started and not self.finished:
            return
        self.root.destroy()

    def run(self) -> int:
        self.root.mainloop()
        return self.result_code

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
            return InstallerWindow(installer, language).run()
        else:
            window = InstallerWindow(installer, language)
            window.remaining = 0
            return window.run()
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
