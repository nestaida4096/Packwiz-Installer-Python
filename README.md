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

## Automated Windows build and release

GitHub Actions builds both Windows executables automatically when a version tag beginning with `v` is pushed.

1. Commit and push the source changes to `main`.
2. Create and push a version tag, for example:

   ```powershell
   git tag v1.0.0
   git push origin v1.0.0
   ```

3. GitHub Actions builds the EXEs on a Windows runner and creates a GitHub Release for that tag.
4. The release contains these exact assets:
   - `Packwiz-Installer.exe`
   - `Packwiz-Installer-Bootstrap.exe`

The Bootstrap downloads `Packwiz-Installer.exe` from the latest GitHub Release. Therefore, publish a new version tag after every installer update. Tags containing a hyphen (for example, `v1.1.0-rc.1`) are published as prereleases.

You can also start the workflow manually from **Actions → Build and Release Windows EXE → Run workflow**. A manual run creates downloadable workflow artifacts but does not create a GitHub Release.

## Local development and build

Requires Python 3.11+ (uses the standard-library `tomllib`) and Tk support.

```powershell
python installer.py https://example.com/pack.toml
python installer.py -g -s server https://example.com/pack.toml
```

For a local Windows build:

```powershell
build.bat
```

## Notes

This project is an independent implementation and is not affiliated with the Packwiz project. Verify your modpack source before installing it.
