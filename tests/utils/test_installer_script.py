import re
from pathlib import Path


def _read_installer() -> str:
    installer = Path(__file__).resolve().parents[2] / "redaudit_install.sh"
    return installer.read_text(encoding="utf-8", errors="ignore")


def test_installer_includes_python3_pip_in_toolchain() -> None:
    content = _read_installer()
    match = re.search(r'^EXTRA_PKGS="([^"]+)"', content, re.MULTILINE)
    assert match, "Expected EXTRA_PKGS definition in installer"
    packages = match.group(1).split()
    assert "python3-pip" in packages


def test_installer_attempts_python3_impacket_apt_install() -> None:
    content = _read_installer()
    assert re.search(r"apt install -y python3-impacket", content)
