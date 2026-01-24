---
description: RedAudit Engineering Workflow
---

# RedAudit: Engineering Workflow

> [!IMPORTANT]
> **At the START of every coding task**, you MUST:
> 1. Read [AGENTS.md](../../AGENTS.md) completely - especially "Non-Negotiables" and "Versioning & Release Checklist"
> 2. Do NOT rely on conversation summaries - read the actual file
> 3. Use the repository as source of truth for behavior and workflows
> 4. Before any version bump/tag/release, follow `/release` workflow

## Key Standards Reminder

- **No Emojis**: Do not use emojis in documentation (`.md` files) or release payloads.
- **Bilingual Documentation**: Maintain parity between English and Spanish guides.
- **Version Alignment**: Every release MUST update:
  - `redaudit/VERSION`
  - `pyproject.toml`
  - README.md badge
  - ES/README_ES.md badge
  - CHANGELOG (EN/ES)
  - Release notes (EN/ES)
- **Private Artifacts**: `scan_results_private/` must never be pushed.
- **Branch Discipline**: Work on a branch. Never commit directly to `main`. Never merge or push to `main` without explicit owner approval.
- **Release Payloads**:
  - Always include the "Ver en Español" / "View in English" badge at the top.
  - Use absolute URLs for all badge links in releases.
  - Follow the standard structure: Summary, Added, Improved, Fixed, Testing, Upgrade.
- **CI Safety**: Ensure all tests and lints pass locally before pushing.
- **Parsing Fragility**: If touching `agentless_verify.py` or `scanner_versions.py`, validate against real tool outputs.
- **Search Discipline**: Prefer `rg` for searching and `rg --files` for discovery.

## Workflow Commands

- `/release` - Full release checklist with version bump
- `/pre-push` - Quality gate before any push
