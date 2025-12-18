import importlib
import re
from pathlib import Path


def _read_pyproject_version() -> str:
    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    content = pyproject.read_text(encoding="utf-8", errors="ignore")
    match = re.search(r'(?m)^version\s*=\s*"([^"]+)"\s*$', content)
    assert match, 'Failed to find `version = "..."` in pyproject.toml'
    return match.group(1).strip()


def test_packaged_version_file_matches_pyproject() -> None:
    expected = _read_pyproject_version()
    version_file = Path(__file__).resolve().parents[1] / "redaudit" / "VERSION"
    assert version_file.is_file(), "Expected redaudit/VERSION to exist"
    assert version_file.read_text(encoding="utf-8").strip() == expected


def test_constants_version_fallback_uses_packaged_version_file(monkeypatch) -> None:
    expected = (
        (Path(__file__).resolve().parents[1] / "redaudit" / "VERSION")
        .read_text(encoding="utf-8")
        .strip()
    )

    import importlib.metadata

    def _raise_version(_: str) -> str:
        raise Exception("no metadata")

    monkeypatch.setattr(importlib.metadata, "version", _raise_version)

    import redaudit.utils.constants as constants

    importlib.reload(constants)
    assert constants.VERSION == expected
