from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

REPOSITORY = "nestaida4096/Packwiz-Installer-Python"
ASSET_NAME = "Packwiz-Installer.exe"
USER_AGENT = "Packwiz-Installer-Bootstrap/0.1"


def request_json(url: str) -> dict:
    request = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": USER_AGENT,
    })
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))


def download(url: str, destination: Path) -> None:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=60) as response, destination.open("wb") as output:
        while True:
            chunk = response.read(1024 * 1024)
            if not chunk:
                break
            output.write(chunk)


def main(argv: list[str] | None = None) -> int:
    forwarded_args = sys.argv[1:] if argv is None else argv
    release_url = f"https://api.github.com/repos/{REPOSITORY}/releases/latest"
    try:
        release = request_json(release_url)
        assets = release.get("assets", [])
        asset = next((item for item in assets if item.get("name") == ASSET_NAME), None)
        if asset is None:
            raise RuntimeError(
                f"Latest release ({release.get('tag_name', 'unknown')}) "
                f"does not contain {ASSET_NAME}"
            )

        cache_dir = Path(os.environ.get("LOCALAPPDATA", tempfile.gettempdir())) / "Packwiz-Installer"
        cache_dir.mkdir(parents=True, exist_ok=True)
        installer_path = cache_dir / ASSET_NAME
        download(asset["browser_download_url"], installer_path)

        # Preserve the launcher's working directory so the installer targets the
        # same Minecraft instance directory as the launcher.
        # Wait until the installer window is closed and the child process exits.
        # Returning immediately here would let launchers continue starting
        # Minecraft before the modpack update/install has finished.
        completed = subprocess.run(
            [str(installer_path), *forwarded_args],
            cwd=os.getcwd(),
            check=False,
        )
        return completed.returncode
    except (OSError, urllib.error.URLError, KeyError, StopIteration, RuntimeError) as exc:
        print(f"Packwiz Installer Bootstrap error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
