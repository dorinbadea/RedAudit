---
description: RedAudit Engineering Workflow
---

# RedAudit: Engineering Workflow

> [!IMPORTANT]
> **At the START of every coding task**, you MUST:
> 1. Read [AGENTS.md](../../AGENTS.md) completely - especially "Non-Negotiables" and "Versioning & Release Checklist"
> 2. Do NOT rely on conversation summaries - read the actual file
> 3. Before any version bump/tag/release, follow `/release` workflow

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
- **Release Payloads**:
  - Always include the "Ver en Español" / "View in English" badge at the top.
  - Use absolute URLs for all badge links in releases.
  - Follow the standard structure: Summary, Added, Improved, Fixed, Testing, Upgrade.
- **CI Safety**: Ensure all tests and lints pass locally before pushing.

## Workflow Commands

- `/release` - Full release checklist with version bump
- `/pre-push` - Quality gate before any push
