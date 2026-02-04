[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.36/docs/releases/RELEASE_NOTES_v4.19.36_ES.md)

# RedAudit v4.19.36 - Coverage Boost Release

This release marks a significant milestone in RedAudit's engineering quality. We have achieved a comprehensive test coverage boost across all core modules, ensuring higher reliability and enterprise-grade stability.

## Summary

The primary focus of this release was eliminating testing debt and ensuring that every critical logic path is verified. Overall project coverage has reached **>98%**.

## Improved

- **Core Coverage**: Significant increase in unit and integration test coverage for all primary modules.
- **Nuclei Integration**: Reached **99.85%** coverage in `redaudit/core/nuclei.py`, ensuring robust vulnerability scanning orchestration.
- **Auditor Logic**: Enhanced coverage in `redaudit/core/auditor.py` to **97.92%**, covering complex scan resumption and reporting flows.
- **100% Coverage Club**: The following modules now maintain a perfect **100%** test coverage:
  - `redaudit/core/webhook.py`
  - `redaudit/core/osquery.py`
  - `redaudit/core/nvd.py`
- **Strategic Pragmas**: Optimized the use of `# pragma: no cover` to accurately exclude only untestable interactive UI loops and defensive safety blocks.

## Testing

- **Suite Size**: 2899 tests passed.
- **Verification**: Verified using `pytest --cov=redaudit --cov-report=term-missing`.
- **Lints**: Passed all `pre-commit` checks including `black`, `flake8`, and `bandit`.

## Upgrade

```bash
pip install --upgrade redaudit
# Or via source
git pull origin main
sudo bash redaudit_install.sh
```
