# RedAudit: Engineering Workflow (Agent Prompt)

This file is reusable "initial context" for contributors working on RedAudit. The goal is a clean timeline, consistent docs, reliable releases, and no surprises in CI.

## Non-Negotiables

- Work on a branch (`feature/*`, `hotfix/*`, `docs/*`); do not commit directly to `main`.
- Never merge or push to `main` without explicit approval from the repo owner.
- Fix root causes, keep changes minimal, avoid unrelated refactors.
- Hand off with clean `git status`.
- Keep code/docs/tests consistent (no version drift, no "docs say X but CLI does Y").
- Do not retag/rewrite published tags/releases. If something was released, publish a new version.
- Do not commit private data. `scan_results_private/` must never be pushed.
- Wait for CI to be green before merging to `main` (do not force-merge with failing checks).
  Exception: documentation-only changes may merge with owner approval if checks are
  pending/skipped and there are no red failures.
- **No Emojis**: Do not use emojis in documentation (`.md` files). Maintain a professional, neutral tone.

## Contributor Workflow Guidelines

- Use `rg` for searching and `rg --files` for file discovery (fallback only if unavailable).
- Default to ASCII in edits/creates; only add non-ASCII when the file already uses it and there is clear justification.
- Prefer patch-style edits for single-file changes; avoid it for auto-generated changes or large scripted replacements.
- Avoid destructive git commands (never use `git reset --hard` or `git checkout --` unless explicitly requested).
- Do not amend commits unless explicitly requested.
- Never revert unrelated changes; if unexpected changes appear, stop and ask how to proceed.
- Keep comments minimal and only when they clarify non-obvious logic.
- Respect execution constraints; request approval only when elevated actions are required by the environment.
- **Fragility of Parsers:** This tool relies heavily on parsing `stdout` from `nmap`, `nikto`, and `nuclei`. If you modify any logic in `agentless_verify.py` or `scanner_versions.py`, you **MUST** verify the changes against actual output from modern versions of these tools. Do not rely solely on existing unit tests, as they test against "frozen" mock data.

### Planning and Scoping

- Use a short multi-step plan for complex tasks; avoid single-step plans.
- Update the plan after completing a step.
- **SIEM Changes:** "SIEM integration" in this repo means strictly **ECS-compliant JSONL output**. Do not implement direct socket/API transmission logic unless explicitly scoped as a major feature.

### Review Responses

- Prioritize bugs, risks, regressions, and missing tests.
- List findings by severity with file/line references before any summary.
- If no findings, state that explicitly and call out residual risks or testing gaps.

### Scan Result Review & Enrichment

- Review CLI output, session logs, and HTML/JSON reports for inconsistencies or weak identification.
- When a host only has vendor data and zero open ports, consider a light HTTP/HTTPS probe on common ports
  (short timeouts, opt-in config) to capture a title or server header for model identification.
- Log improvement ideas in the roadmap or issues and document behavior changes in EN/ES docs.

### Frontend/UI Work

- Preserve the existing design system when it exists.
- Otherwise, define typography, color, background, and motion deliberately; avoid generic defaults.

## Branching & Commits (Clean Timeline)

- Branch names:
  - `feature/<short-desc>`
  - `hotfix/<version>-<short-desc>`
  - `docs/<topic>`
- Commit messages: use conventional/semantic style:
  - `feat(scope): ...`
  - `fix(scope): ...`
  - `docs(scope): ...`
  - `test: ...`
  - `chore(release): vX.Y.Z`
  - `chore(pre-commit): apply formatting fixes`
- Group commits by intent:
  1) code fix/feature, 2) tests, 3) docs, 4) release bump/notes, 5) formatting-only (if needed).
- **Cleanup**: After merging to `main` and pushing, explicitly delete the local and remote feature branch (e.g., `git branch -d feature/xyz` and `git push origin --delete feature/xyz`).

## Local Quality Gate (Must Pass Before Merge)

### Pre-commit (Required)

Run:

```bash
pre-commit run --all-files
```

### Dependency Setup (Critical)

Before running tests, ensure dev dependencies are installed to avoid missing package errors:

```bash
pip install -r requirements-dev.lock && pip install -e .
```

This repo's `.pre-commit-config.yaml` includes:

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

### Local CI Parity (Multi-Python)

To avoid CI-only failures, run the local CI parity script. It runs pre-commit once and
executes pytest on each available Python version in the CI matrix.

```bash
bash scripts/ci_local.sh
```

Requirements:

- Python 3.9-3.12 available in PATH (`python3.9`, `python3.10`, `python3.11`, `python3.12`).
- Uses `requirements-dev.lock` and creates venvs under `.venv/ci` (ignored).

Optional environment variables:

- `PYTHON_VERSIONS="3.9 3.10"` to limit which versions run.
- `RUN_PRECOMMIT=0` or `RUN_TESTS=0` to skip steps.

### Test Organization (Quality over Quantity)

The test suite prioritizes maintainability over raw coverage numbers:

- **Use `conftest.py`**: Shared fixtures (`MockAuditorBase`, sample data) live in `tests/conftest.py`. Do not duplicate mock classes across files.
- **Directory structure**: Keep tests under `tests/core`, `tests/cli`, `tests/utils`, `tests/integration` to mirror the codebase.
- **Consolidate satellites**: Prefer a single `test_<module>.py` per module; fold edge/progress/extra coverage into that file instead of creating `*_edge_cases.py` or similar.
- **Semantic file names**: Test files match the module they cover (e.g., `test_entity_resolver.py` for `entity_resolver.py`). Avoid names like `batch1`, `to_90`, `aggressive`.
- **Extend existing files**: When adding tests for a module, add them to the existing test file rather than creating new fragmented files.
- **No coverage gaming**: Do not create tests solely to hit a coverage number. Each test should verify meaningful behavior.
- One mock, many tests: Define mock classes once and reuse via fixtures. A single well-designed mock beats 50 copy-pasted variants.
- **Refresh Mock Data:** When touching parsing logic, do not just update the regex to make the test pass. Verify if the tool's output format has changed and update the raw string fixtures in `conftest.py` or the test file to reflect reality.

When modifying tests:

1. Check if a test file for that module already exists.
2. If yes, add your test to that file.
3. If no, create one file per module with a clear name.
4. Import fixtures from `conftest.py` instead of defining inline mocks.

## CI (What GitHub Actions Enforces)

Workflow: `.github/workflows/tests.yml`

- Tests job: Python `3.9`-`3.12`, installs `nmap`, runs:
  - `pytest tests/ -v --cov=redaudit --cov-report=xml --cov-report=term-missing`
  - coverage threshold: `coverage report --fail-under=25`
- Lint job: runs `pre-commit` via `pre-commit/action`
- ShellCheck job: runs ShellCheck (currently `continue-on-error: true`)
- `update-badge` job: updates a dynamic badge via Gist (repo secrets)

Do not merge if CI is red unless the failure is understood and explicitly accepted.
For documentation-only changes, it is acceptable to merge with owner approval if CI is
pending/skipped and no failures are present.

## When CI Fails (Process)

Use this process when CI fails (especially tests), aligned with how RedAudit is maintained:

### Process (when CI fails)

1. Review CI logs first to locate the exact failure (job, failing test name, stacktrace, assertion).
2. Reproduce locally by running only the failing test (or the related test file).
3. Confirm whether the failure is:
   - "Expected" due to intentional new behavior (then update the test), or
   - A real bug/regression (then fix code and keep the test).
4. Adjust tests/mocks minimally to reflect real behavior (no unrelated refactors).
5. Run the full local gate (pre-commit + pytest) before pushing.

### How to identify which tests to update

- Use CI output to get the exact test name and failure.
- Re-run locally to validate the diagnosis.
- Update only the tests directly linked to the changed logic/flow.

### Test vs code: when to change each

- If the new behavior is intentional (feature/UX), update the test to match.
- If the failure shows regression or inconsistency with the intended change, fix code and keep the test.
- If the change breaks documented contracts (CLI/UX), update docs and tests together.

### How to determine new mock/input values (wizard-heavy changes)

- Walk the real flow and count each prompt in order (do not guess).
- If you introduced a new `ask_choice_with_back` or a new prompt:
  - add one input per new prompt.
- If defaults exist, include explicit ENTER inputs where defaults are accepted.
- If you added new flags/branches, add minimal cases per branch (positive/negative) only where necessary.

### Pattern to keep tests "alive"

If you touched wizard flow or heuristics, review tests that depend on:

- prompt count,
- default values,
- execution order,
- i18n messages.

Always update i18n + tests in the same commit if the real flow changed.

### Mental checklist before commit

- Flow of prompts changed? -> update wizard tests.
- Heuristic/score changed? -> update scanner mocks/fixtures.
- Output structure changed? -> update reporter/JSON/HTML tests.
- Run:
  - `pre-commit run --all-files`
  - `pytest tests/ -v`

## Scan Artifact Review (Quality Loop)

When using real scan artifacts to refine heuristics or output:

- Review HTML/TXT/JSONL for assets with vendor-only identity or `unknown` type.
- If a host exposes a web UI, do a quick HTTP/HTTPS fetch (no creds) to capture titles/headers that can improve asset naming.
- If new identity signals are added, update tests and docs in the same commit.
- Keep `scan_results_private/` local-only and never commit it.

## Documentation Consistency Rules

When changing behavior/UX, update the relevant docs in both EN/ES (flat docs structure):

- `README.md`, `ES/README_ES.md`
- `docs/INDEX.md`
- `docs/USAGE.en.md`, `docs/USAGE.es.md`
- `docs/MANUAL.en.md`, `docs/MANUAL.es.md`
- `docs/DIDACTIC_GUIDE.en.md`, `docs/DIDACTIC_GUIDE.es.md` (if user-facing flow changed)
- `docs/REPORT_SCHEMA.en.md`, `docs/REPORT_SCHEMA.es.md`
- `docs/ROADMAP.en.md`, `docs/ROADMAP.es.md`
- `docs/SECURITY.en.md`, `docs/SECURITY.es.md`
- `docs/TROUBLESHOOTING.en.md`, `docs/TROUBLESHOOTING.es.md`
- `docs/SIEM_INTEGRATION.en.md`, `docs/SIEM_INTEGRATION.es.md` (if impacted)
- `CHANGELOG.md`, `ES/CHANGELOG_ES.md`
- release notes: `docs/releases/RELEASE_NOTES_vX.Y.Z*.md`

Make sure menu text, flags, defaults, and examples match the code.
For ES docs, use Spanish (Spain) phrasing (`es-ES`) and avoid LATAM variants.

**Documentation style:**

**Documentation style:**

- Keep sentences clear and concise.
- In release notes, use absolute URLs (e.g., `https://github.com/.../blob/vX.Y.Z/...`) for language badge links. Relative links break when viewed from the GitHub release page.

## Versioning & Release Checklist (SemVer)

### 1) Decide bump

- `X.Y.(Z+1)` for hotfixes / behavior fixes
- `X.(Y+1).0` for new features
- `(X+1).0.0` for breaking changes

### 2) Update version sources

Keep version consistent across the repo. Version may be stored/used in one or more of these places (keep them in sync as applicable):

- `pyproject.toml`
- `redaudit/VERSION`
- `redaudit/utils/constants.py` (if still referenced by code/tests)

Also update any tests that assert version output (e.g., integration tests).

### 3) Update release documentation

- Add a new section to `CHANGELOG.md` and `ES/CHANGELOG_ES.md`
- Add release notes:
  - `docs/releases/RELEASE_NOTES_vX.Y.Z.md`
  - `docs/releases/RELEASE_NOTES_vX.Y.Z.md`
  - `docs/releases/RELEASE_NOTES_vX.Y.Z_ES.md`
- Create Audit Report:
  - `docs/AUDIT_REPORT_vX.Y.Z.md` (Validating the critical fixes/features)

### 4) Final verification

- `pre-commit run --all-files`
- `pytest tests/ -v` (or `python3 -m unittest discover -s tests`)
- `git status` must be clean

### Release candidate (local validation, no merge to main)

Run a local release candidate validation without merging to `main`.

```bash
git fetch origin --prune && git checkout -B release/candidate origin/release/candidate && sudo bash redaudit_install.sh && pytest tests/ -v --cov=redaudit --cov-report=xml --cov-report=term-missing
```

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

Prefer `gh` (GitHub CLI):

1. **Prepare Payload**:
   Copy the content from the English release notes (`docs/releases/RELEASE_NOTES_vX.Y.Z.md`) into a temporary file `release_payload.md`.

2. **Create Release**:

   ```bash
   gh release create vX.Y.Z -t "vX.Y.Z - <title>" -F release_payload.md
   ```

**CRITICAL**: The GitHub Release **MUST** contain the full text body (payload), not just the title.

- Copy the content from the English release notes (`docs/releases/RELEASE_NOTES_vX.Y.Z.md`).
- **Always** include the language badge at the top pointing to the Spanish version.
- **Verify** that the release page is not empty after publishing.

When the release notes include an EN->ES badge/link, point it at the tagged file, e.g.:

```text
https://github.com/dorinbadea/RedAudit/blob/vX.Y.Z/docs/releases/RELEASE_NOTES_vX.Y.Z_ES.md
```

## Sudo / Paths / Ownership (Critical for UX)

RedAudit is often run with `sudo`, which can cause `~` and `$HOME` to resolve to `/root`.

Rules:

- Any user-facing output path (reports, defaults) should resolve to the invoking user when under `sudo`.
- Be careful with persisted defaults: older versions may have stored `/root/...` and must be migrated or corrected.
- Best-effort ownership (`chown`) may be required to avoid root-owned artifacts under a user's home.

## Quick verification commands (examples)

```bash
# Show which user invoked sudo and what $HOME resolves to in this shell
whoami
echo "$HOME"
sudo -n true && echo "sudo: OK" || echo "sudo: needs password / not permitted"

# If artifacts were created as root under a user home, fix ownership (best-effort)
# Replace <user>:<group> appropriately.
sudo chown -R <user>:<group> /home/<user>/Documents/RedAuditReports 2>/dev/null || true
```
