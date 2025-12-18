# RedAudit: Engineering Workflow

This file is a reusable “initial context” for contributors working on RedAudit (and can be copied to other repos). The goal is a clean timeline, consistent docs, reliable releases, and zero surprises in CI.

## Non‑Negotiables

- Work on a branch (`feature/*`, `hotfix/*`, `docs/*`). Avoid committing directly to `main`.
- Never merge/push to `main` without explicit approval from the repo owner.
- Fix root causes, keep changes minimal, avoid unrelated refactors.
- Keep `git status` clean before handing off.
- Keep code/docs/tests consistent (no version drift, no “docs say X but CLI does Y”).
- Do **not** retag/rewrite published tags/releases. If something was released, publish a new version.
- Do not commit private data. `scan_results_private/` must never be pushed.

## Roles & Work Modes (Reusable Playbooks)

Use these modes to keep work predictable and auditable. If a task does not require code changes, do not implement “just in case”.

### 1) Diagnosis / Next‑Step Proposal (No Implementation)

**Goal:** Produce an evidence‑backed snapshot and a rational next step (impact/risk/cost).

**Strict method (in order):**

1. Start with reproducible inspection (repo structure, docs files, git status).
2. Use concrete commands as evidence (e.g., `rg`, `ls`, `sed -n`, `python -m redaudit --help`).
3. Do not invent features. If something can’t be confirmed, state it explicitly and note how to confirm.
4. Do not change designs/structure; this is analysis and recommendation only.

**Deliverable format (fixed):**

A) Current state (5–12 bullets) with evidence (file path or command)
B) Roadmap: top 5 items now (ordered) + why
C) Recommendation: next step (what/why/risks/effort OOM)
D) Alternative 1 and 2 (when to choose)
E) Operational checklist (exact sequence)

### 2) Documentation Sync (Code/CLI Is Source of Truth)

**Goal:** Update docs to reflect behavior already present in code/CLI.

**Rules:**

- Do not redesign docs. Preserve tone/structure; make minimal insertions in the right place.
- Keep EN/ES consistent: update both when behavior/UX changes.
- Examples must match real flags, defaults, paths, and menus.

**Method (in order):**

1. Extract “truth from code”: real CLI flags/defaults + recent features (with file references).
2. Audit docs vs inventory: mark missing/outdated/correct; do not touch what’s correct.
3. Apply minimal edits directly to files.
4. Run quality gate, then commit with intent (`docs(...)`).

### 3) Release Audit (Gatekeeper)

**Goal:** Detect drift between code and documentation before a release.

**Checklist (must pass):**

- Validate links/paths and remove legacy references as needed (use `rg` for evidence).
- Confirm flags/defaults match code/CLI.
- Confirm version coherence across version sources, changelog, and release notes.
- Run gates: `pre-commit run --all-files` and `pytest tests/ -v`.

If drift is found: apply minimal fixes, commit by intent, and re-run gates until green.

### 4) Release Execution (Conservative)

**Goal:** Execute merge/tag/release without surprises. Stop before tagging if anything is inconsistent.

### 5) CI Triage (CodeQL / Workflow Breakages)

**Goal:** Restore CI health with the smallest possible change, without mixing unrelated work.

**Order of operations:**

1. Confirm whether the failure is a workflow/config problem or a real finding.
2. Apply the minimum fix on the minimum branch:
   - If the team is not ready to touch `main`, apply the fix in the active feature branch so work can continue.
   - If `main` must stay green, merge a small `hotfix/*` that only fixes CI config, then port it to the feature branch (merge or cherry-pick).
3. Do not silence security findings without explicit approval; fix the code or document the accepted risk.

**CodeQL workflow quick check (typical failure mode):**

- Inspect the workflow:
  - `sed -n '1,200p' .github/workflows/codeql.yml`
- If it references an unsupported action version (example: `github/codeql-action/*@v4`), pin to a supported major (example: `@v3`) for `init` and `analyze`.
- Keep the change limited to `.github/workflows/codeql.yml`.

**Gates (always):**

- `pre-commit run --all-files`
- `pytest tests/ -v`

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
- `docs/USAGE.en.md`, `docs/USAGE.es.md`
- `docs/MANUAL.en.md`, `docs/MANUAL.es.md`
- `docs/TROUBLESHOOTING.en.md`, `docs/TROUBLESHOOTING.es.md` (if user-facing flow changed)
- `docs/DIDACTIC_GUIDE.en.md`, `docs/DIDACTIC_GUIDE.es.md` (if user-facing flow changed)
- `CHANGELOG.md`, `CHANGELOG_ES.md`
- `docs/ROADMAP.en.md`, `docs/ROADMAP.es.md`
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
- `redaudit/VERSION` (must match `pyproject.toml`)

`redaudit/utils/constants.py` resolves runtime version and must remain compatible with both package installs and script-based system installs.

Update tests that assert version behavior (e.g., `tests/test_version_resolution.py`).

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
git fetch origin
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
