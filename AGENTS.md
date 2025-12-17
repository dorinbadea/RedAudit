# RedAudit: Engineering Workflow (Agent Prompt)

This file is a reusable “initial context” for agents and humans working on RedAudit (and can be copied to other repos). The goal is a clean timeline, consistent docs, reliable releases, and zero surprises in CI.

## Non‑Negotiables

- Work on a branch (`feature/*`, `hotfix/*`, `docs/*`). Avoid committing directly to `main`.
- Fix root causes, keep changes minimal, avoid unrelated refactors.
- Keep `git status` clean before handing off.
- Keep code/docs/tests consistent (no version drift, no “docs say X but CLI does Y”).
- Do **not** retag/rewrite published tags/releases. If something was released, publish a new version.

## Branching & Commits (Clean Timeline)

- **Branch names**
  - `feature/<short-desc>`
  - `hotfix/<version>-<short-desc>`
  - `docs/<topic>`
- **Commit messages**: use conventional/semantic style:
  - `feat(scope): ...`
  - `fix(scope): ...`
  - `docs(scope): ...`
  - `test: ...`
  - `chore(release): vX.Y.Z`
  - `chore(pre-commit): apply formatting fixes`
- Group commits by intent:
  1) code fix/feature, 2) tests, 3) docs, 4) release bump/notes, 5) formatting-only (if needed).

## Local Quality Gate (Must Pass Before Merge)

### Pre-commit (Required)

Run:

```bash
pre-commit run --all-files
```

This repo’s `.pre-commit-config.yaml` includes:

- `pre-commit-hooks`
  - `trailing-whitespace`
  - `end-of-file-fixer`
  - `check-yaml`
  - `check-added-large-files --maxkb=1000`
  - `check-merge-conflict`
  - `check-json`
  - `mixed-line-ending --fix=lf`
- `black` (`--line-length=100`)
- `flake8` (excludes `tests/`, ignores `E203,W503,E501`, max line length `100`)
- `bandit` (config via `pyproject.toml`)
- `mypy` (only `redaudit/`, with `types-requests`, `--ignore-missing-imports`, `--no-strict-optional`)

If a hook modifies files (EOF fixes/formatters), commit those changes separately as:

```text
chore(pre-commit): apply formatting fixes
```

### Tests (Required)

CI runs `pytest` with coverage. Locally, run:

```bash
pytest tests/ -v
```

Optional (also supported in this repo):

```bash
python3 -m unittest discover -s tests
```

## CI (What GitHub Actions Enforces)

Workflow: `.github/workflows/tests.yml`

- **Tests job**: Python `3.9`–`3.12`, installs `nmap`, runs:
  - `pytest tests/ -v --cov=redaudit --cov-report=xml --cov-report=term-missing`
  - coverage threshold: `coverage report --fail-under=25`
- **Lint job**: runs `pre-commit` via `pre-commit/action`
- **ShellCheck job**: runs ShellCheck (currently `continue-on-error: true`)
- **update-badge** job: updates a dynamic badge via Gist (repo secrets)

Do not merge if CI is red unless the failure is understood and explicitly accepted.

## Documentation Consistency Rules

When changing behavior/UX, update the relevant docs **in both EN/ES**:

- `README.md`, `README_ES.md`
- `docs/en/USAGE.md`, `docs/es/USAGE.md`
- `docs/en/MANUAL.md`, `docs/es/MANUAL.md`
- `docs/en/DIDACTIC_GUIDE.md`, `docs/es/DIDACTIC_GUIDE.md` (if user-facing flow changed)
- `CHANGELOG.md`, `CHANGELOG_ES.md`
- `docs/ROADMAP.md`, `docs/ROADMAP_ES.md`
- release notes: `docs/releases/RELEASE_NOTES_vX.Y.Z*.md`

Make sure menu text, flags, defaults, and examples match the code.

## Versioning & Release Checklist (SemVer)

### 1) Decide bump

- `X.Y.(Z+1)` for hotfixes / behavior fixes
- `X.(Y+1).0` for new features
- `(X+1).0.0` for breaking changes

### 2) Update version sources

This repo currently keeps version in:

- `pyproject.toml`
- `redaudit/utils/constants.py`

Update tests that assert `VERSION` (e.g., `tests/test_integration.py`).

### 3) Update release documentation

- Add a new section to `CHANGELOG.md` and `CHANGELOG_ES.md`
- Add release notes:
  - `docs/releases/RELEASE_NOTES_vX.Y.Z.md`
  - `docs/releases/RELEASE_NOTES_vX.Y.Z_ES.md`

### 4) Final verification

- `pre-commit run --all-files`
- `pytest tests/ -v` (or `python3 -m unittest discover -s tests`)
- `git status` must be clean

### 5) Merge, tag, publish

From `main`:

```bash
git checkout main
git pull --ff-only origin main
git merge --no-ff <branch> -m "Merge <branch> into main"
pre-commit run --all-files
pytest tests/ -v
git tag -a vX.Y.Z -m "RedAudit vX.Y.Z"
git push origin main --tags
```

### 6) GitHub Release

Prefer `gh` (GitHub CLI):

```bash
gh release create vX.Y.Z -t "vX.Y.Z - <title>" -F docs/releases/RELEASE_NOTES_vX.Y.Z.md
```

When the release notes include an EN→ES badge/link, point it at the tagged file, e.g.:

```text
https://github.com/dorinbadea/RedAudit/blob/vX.Y.Z/docs/releases/RELEASE_NOTES_vX.Y.Z_ES.md
```

## Sudo / Paths / Ownership (Critical for UX)

RedAudit is often run with `sudo`, which can cause `~` and `$HOME` to resolve to `/root`.

Rules:

- Any “user-facing” output path (reports, defaults) should resolve to the **invoking user** when under `sudo`.
- Be careful with persisted defaults: older versions may have stored `/root/...` and must be migrated or corrected.
- Best-effort ownership (`chown`) may be required to avoid root-owned artifacts under a user’s home.
