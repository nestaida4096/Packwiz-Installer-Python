# Packwiz Installer Python

Python/Tkinter implementation of a two-stage Packwiz installer for Windows.

## Architecture

- **Bootstrap** checks the latest GitHub Release and downloads the published Installer executable.
- **Installer** reads `pack.toml`, validates `index.toml` and file hashes, resolves `*.pw.toml` metadata, and installs files into the current working directory.

The bootstrap forwards the arguments it receives to the Installer. For example:

```bat
Packwiz-Installer-Bootstrap.exe -s client https://example.com/pack.toml
```

Supported options:

- `-g`, `--no-gui`: run without the graphical interface.
- `-s SIDE`, `--side SIDE`: select `client`, `server`, or `both`.
- `--install-dir PATH`: installation directory (defaults to the current working directory).
- `PACK_URL`: URL of the Packwiz `pack.toml`.

## Optional mods

When optional mods are present, the GUI displays an options button and starts a 10-second countdown. Opening the options dialog pauses the countdown. The selected options are then used for the installation.

## Development

Requires Python 3.11+ (uses the standard-library `tomllib`) and Tk support.

```powershell
python installer.py https://example.com/pack.toml
python installer.py -g -s server https://example.com/pack.toml
```

## Build Windows executables

Install PyInstaller and build each executable:

```powershell
python -m pip install -r requirements.txt
pyinstaller --onefile --noconsole --name Packwiz-Installer installer.py
pyinstaller --onefile --noconsole --name Packwiz-Installer-Bootstrap bootstrap.py
```

Publish the Installer executable as an asset named `Packwiz-Installer.exe` in a GitHub Release. The bootstrap downloads that asset from the latest release of the repository configured in `bootstrap.py`.

## Notes

This project is an independent implementation and is not affiliated with the Packwiz project. Verify your modpack source before installing it.
