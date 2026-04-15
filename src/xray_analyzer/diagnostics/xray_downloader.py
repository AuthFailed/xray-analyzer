"""Auto-download Xray core from GitHub releases."""

import platform
import shutil
import tempfile
import zipfile
from pathlib import Path

import aiohttp

from xray_analyzer.core.logger import get_logger

log = get_logger("xray_downloader")

GITHUB_API_URL = "https://api.github.com/repos/XTLS/Xray-core/releases/latest"
# Fallback: try tag-based URL if latest API fails
TAG_BASE_URL = "https://github.com/XTLS/Xray-core/releases/download/v{version}"


def _get_default_install_dir() -> Path:
    """Get the default directory for Xray installation."""
    # Prefer ~/.local/share/xray or project-local ./xray-bin
    home = Path.home()
    xray_dir = home / ".local" / "share" / "xray"
    return xray_dir


async def _get_latest_release(session: aiohttp.ClientSession) -> dict | None:
    """Fetch latest release info from GitHub API."""
    try:
        async with session.get(
            GITHUB_API_URL,
            headers={"Accept": "application/vnd.github.v3+json"},
            timeout=aiohttp.ClientTimeout(total=15),
        ) as response:
            if response.status == 200:
                return await response.json()
            log.warning(f"GitHub API returned {response.status}")
    except Exception as e:
        log.warning(f"Failed to fetch GitHub releases: {e}")
    return None


async def find_latest_xray_asset(
    session: aiohttp.ClientSession,
) -> tuple[str, str, str] | None:
    """
    Find the latest Xray download URL and filename.

    Returns (tag_version, download_url, asset_name) or None.
    """
    release = await _get_latest_release(session)
    if not release:
        return None

    tag_name = release.get("tag_name", "")
    if not tag_name:
        return None

    # Remove 'v' prefix for version
    version = tag_name.lstrip("v")

    # Determine platform
    machine = platform.machine().lower()
    is_arm = machine.startswith(("arm", "aarch"))
    asset_pattern = "Xray-linux-arm64-v8a" if is_arm else "Xray-linux-64"

    assets = release.get("assets", [])
    for asset in assets:
        if asset_pattern in asset.get("name", ""):
            return (version, asset["browser_download_url"], asset["name"])

    # Fallback: construct URL from tag
    log.warning(f"Asset '{asset_pattern}' not found in release {tag_name}, constructing download URL manually")
    url = f"{TAG_BASE_URL.format(version=version)}/{asset_pattern}.zip"
    return (version, url, f"{asset_pattern}.zip")


async def download_xray(
    install_dir: Path | None = None,
) -> str | None:
    """
    Download the latest Xray core binary from GitHub.

    Args:
        install_dir: Directory to install Xray into. Defaults to ~/.local/share/xray

    Returns:
        Path to the downloaded Xray binary, or None on failure.
    """
    if install_dir is None:
        install_dir = _get_default_install_dir()

    install_dir.mkdir(parents=True, exist_ok=True)

    log.info(f"Downloading latest Xray core to {install_dir}")

    async with aiohttp.ClientSession() as session:
        asset_info = await find_latest_xray_asset(session)
        if not asset_info:
            log.error("Could not find latest Xray release on GitHub")
            return None

        version, download_url, asset_name = asset_info
        log.info(f"Found Xray v{version}: {asset_name}")

        # Download the zip
        try:
            async with session.get(
                download_url,
                timeout=aiohttp.ClientTimeout(total=300),
            ) as response:
                if response.status != 200:
                    log.error(f"Failed to download Xray: HTTP {response.status}")
                    return None

                with tempfile.NamedTemporaryFile(suffix=".zip", delete=False, prefix="xray-") as tmp_file:
                    tmp_path = Path(tmp_file.name)
                    while True:
                        chunk = await response.content.read(8192)
                        if not chunk:
                            break
                        tmp_file.write(chunk)

            log.info(f"Downloaded {tmp_path.stat().st_size / 1024 / 1024:.1f} MB")

            # Extract binary + geoip/geosite in a single archive pass
            with zipfile.ZipFile(tmp_path) as zf:
                names = zf.namelist()

                xray_file = next(
                    (n for n in names if n == "xray" or n.endswith("/xray")),
                    None,
                )

                if not xray_file:
                    # Fallback: extract everything and search recursively
                    zf.extractall(str(install_dir))
                    xray_path = install_dir / "xray"
                    if not xray_path.exists():
                        xray_files = list(install_dir.rglob("xray"))
                        if xray_files:
                            xray_path = xray_files[0]
                        else:
                            log.error("No xray binary found in archive")
                            return None
                else:
                    xray_path = install_dir / "xray"
                    zf.extract(xray_file, str(install_dir))
                    extracted = install_dir / xray_file
                    if extracted != xray_path:
                        extracted.rename(xray_path)

                for name in names:
                    if name.endswith("geoip.dat") or name.endswith("geosite.dat"):
                        zf.extract(name, str(install_dir))
                        src = install_dir / name
                        if src.exists() and src != install_dir / Path(name).name:
                            src.rename(install_dir / Path(name).name)

            # Make executable
            xray_path.chmod(0o755)

            # Cleanup temp file
            tmp_path.unlink(missing_ok=True)

            log.info(f"Xray v{version} installed to {xray_path}")
            return str(xray_path)

        except Exception as e:
            log.error(f"Failed to download/extract Xray: {e}")
            return None


async def ensure_xray(
    binary_path: str = "xray",
    auto_download: bool = True,
) -> str | None:
    """
    Ensure Xray binary is available.

    1. Check if the specified path exists and is executable
    2. Check if 'xray' is in PATH
    3. Auto-download from GitHub if auto_download=True

    Returns the path to xray binary or None.
    """
    # 1. Check specified path
    path = Path(binary_path)
    if path.exists() and path.is_file():
        log.debug(f"Xray found at {binary_path}")
        return str(path.resolve())

    # 2. Check PATH
    xray_in_path = shutil.which("xray")
    if xray_in_path:
        log.debug(f"Xray found in PATH: {xray_in_path}")
        return xray_in_path

    # 3. Auto-download
    if auto_download:
        log.info("Xray binary not found, downloading from GitHub...")
        # Download to the parent directory of the specified binary path
        parent = Path(binary_path).parent
        install_dir = parent if parent != Path() else _get_default_install_dir()
        downloaded = await download_xray(install_dir=install_dir)
        if downloaded:
            return downloaded
        log.error("Failed to auto-download Xray")

    return None
