<!--
NOTE: This file is for contributor best practices (agentes humanos o no humanos) when working in this repository.
Keep it aligned with the repo root `AGENTS.md` and CI/pre-commit requirements.
-->

# Agent Instructions (RedAudit)

Follow the repository workflow in `AGENTS.md` (repo root). If there is any conflict, `AGENTS.md` is canonical.

Minimum expectations before opening a PR:

- Work on a branch; never commit directly to `main`.
- Never merge or push to `main` without explicit owner approval.
- Run `pre-commit run --all-files` and commit any formatter changes as `chore(pre-commit): apply formatting fixes`.
- Run tests: `pytest tests/ -v` (or `scripts/ci_local.sh` for CI parity).
- Do not idle waiting for CI; run `scripts/ci_local.sh` and proceed with other tasks. CI can arrive after merge; if any checks fail, fix before further releases.
- Keep EN/ES documentation consistent when user-facing behavior changes.
- Do not commit private data; `scan_results_private/` must never be pushed.
- No emojis in documentation or release payloads.
- Use `rg` for search and `rg --files` for file discovery.
