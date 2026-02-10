# RedAudit: Engineering Workflow (Agent Prompt)

This file is the canonical operating guide for collaborators (human or non-human agents) working on RedAudit. Treat it as the single source of truth for workflow, release hygiene, and documentation integrity. The goal is a clean timeline, consistent docs, reliable releases, and no surprises in CI.

## Non-Negotiables

- Work on a branch (`feature/*`, `hotfix/*`, `docs/*`); do not commit directly to `main`.
- Never merge or push to `main` without explicit approval from the repo owner.
- Fix root causes, keep changes minimal, avoid unrelated refactors.
- Hand off with clean `git status`.
- Keep code/docs/tests consistent (no version drift, no "docs say X but CLI does Y").
- **Coverage Rule:** Any code you modify must be covered at 100% in tests. This means the specific functions or files you touched must reach full coverage for the newly changed code paths in the same change set.
- **Coverage Enforcement:** If you touch code, you must add or update tests so the exact changed code paths are fully exercised (100%) in the same change set. No exceptions.
- Do not retag/rewrite published tags/releases. If something was released, publish a new version.
- Do not commit private data. `scan_results_private/` must never be pushed.
- Before first push and before merging to `main`, satisfy the **Local Quality Gate Contract** in this document. CI can arrive after the merge; if any checks fail, treat it as a regression and fix it promptly. Do not force-merge with failing checks.
- `scripts/ci_local.sh` is the preferred local CI-parity entrypoint for code changes; a successful run is considered the local equivalent of GitHub CI for this workflow.
- **Strict Docs-only Rule:** For strict documentation-only changes (`.md` only, no behavior/contract impact), do not run `pytest` or `scripts/ci_local.sh`, and do not wait for the full GitHub test matrix. Use only the docs gate defined in the **Local Quality Gate Contract**.
- **No Emojis**: Do not use emojis in documentation (`.md` files), including release notes and release payload text. Maintain a professional, neutral tone.

**Codex exception:** When working inside Codex, the environment enforces a `codex/` branch prefix. In that case, `codex/*` is acceptable and compliant with this workflow. If preferred, the branch can be renamed to `feature/*`, `hotfix/*`, or `docs/*` before merge.

## Workflow Overview (Default Path)

1. Create a branch; never commit directly to `main`.
2. Keep scope minimal and fix root causes; avoid unrelated refactors.
3. Update code, tests, and docs together; keep EN/ES in sync when behavior changes.
4. Keep versions aligned: update version sources, README/ES README version strings and badges, changelog, roadmap, and release notes when required.
5. Execute the **Local Quality Gate Contract** once after all changes are final (docs-only shortcut applies).
6. Merge only with approval; tag and publish the release with a full payload body.
7. Clean up branches and ensure `git status` is clean.

See the **Versioning & Release Checklist** section for detailed steps and commands.

## Multi-IDE Pointer Contract

To support different IDE agent ecosystems, this repo includes helper pointer files
(`.cursorrules`, `agents/*`, `.agent/*`).

Rules for all pointer files:

- Keep them in English.
- Keep them emoji-free.
- Keep them short and pointer-oriented; do not duplicate canonical checklists.
- Avoid fragile references (for example, exact line numbers in `AGENTS.md`).
- If any pointer file conflicts with `AGENTS.md`, `AGENTS.md` is canonical.

## Contributor Workflow Guidelines

- Treat the repository as the source of truth; do not rely on conversation summaries.
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
  (short timeouts, opt-in config) to capture a title or server header for device identification.
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
- **Cleanup (CI Hygiene)**: After merging to `main` and pushing, you **MUST** explicitly delete both the local and remote feature branch (e.g., `git push origin --delete feature/xyz`). Stale branches clutter the CI dashboard and are unacceptable.

## Local Quality Gate (Must Pass Before Merge)

### Local Quality Gate Contract (Authoritative)

- **Timing rule:** Run the local quality gate exactly once after changes are final and before first push.
- **Re-run rule:** Re-run the gate only if files changed after a successful gate run.
- **Code changes path:** Run `pre-commit run --all-files` and `pytest tests/ -v` (or `bash scripts/ci_local.sh` for CI parity).
- **Docs-only path (strict):** For strict `.md`-only changes with no behavior/contract impact, run `pre-commit run --files <changed-docs>` and skip `pytest`.
- **Docs-only prohibition:** In docs-only scope, do not run `pytest tests/ -v` or `bash scripts/ci_local.sh`; this avoids redundant full-suite runs.
- **Merge condition:** `main` merge requires owner approval and no red CI checks.

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

### Dependency Management

This repo uses `pip-tools` to ensure reproducible environments.

- **Source of Truth**: `pyproject.toml` definitions.
- **Lock Files**: `requirements.lock` and `requirements-dev.lock` are autogenerated.
- **Workflow**:
  1. Edit `pyproject.toml`.
  2. Run `pip-compile --output-file=requirements.lock pyproject.toml` (for prod).
  3. Run `pip-compile --extra=dev --output-file=requirements-dev.lock pyproject.toml` (for dev).
  4. Commit changes.

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

Docs-only behavior is defined by the **Local Quality Gate Contract** above.

### Local CI Parity (Multi-Python)

To avoid CI-only failures, run the local CI parity script. It runs pre-commit once and
executes pytest on each available Python version in the CI matrix.

```bash
bash scripts/ci_local.sh
```

Requirements:

- Python 3.10-3.12 available in PATH (`python3.10`, `python3.11`, `python3.12`).
- `nmap` available in PATH for parity with the GitHub test jobs.
- Uses `requirements-dev.lock` and creates venvs under `.venv/ci` (ignored).

Optional environment variables:

- `PYTHON_VERSIONS="3.10 3.11"` to limit which versions run.
- `RUN_PRECOMMIT=0` or `RUN_TESTS=0` to skip steps.
- `COVERAGE_FAIL_UNDER=85` to override the default local coverage threshold.

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

- Tests job: Python `3.10`-`3.12`, installs `nmap`, runs:
  - `pytest tests/ -v --cov=redaudit --cov-report=xml --cov-report=term-missing`
  - coverage threshold: `coverage report --fail-under=80`
- Lint job: verifies pointer consistency via `scripts/check_agent_pointers.sh`, then runs `pre-commit` via `pre-commit/action`
- ShellCheck job: runs ShellCheck
- `update-badge` job: updates a dynamic badge via Gist (repo secrets)

Do not merge if CI is red unless the failure is understood and explicitly accepted.
For documentation-only changes, it is acceptable to merge with owner approval if CI is
pending/skipped and no failures are present. Do not block docs-only merges waiting for
the full remote matrix when the local docs-only gate has already passed.

If branch rules allow bypass for the acting role, GitHub may display a
"Bypassed rule violations" notice when pushing to `main` before required checks
finish remotely. This is expected and does not replace the requirement to run
the local quality gate first and fix any later CI regressions.

## When CI Fails (Process)

Use this process when CI fails (especially tests), aligned with how RedAudit is maintained:

### Process (when CI fails)

1. Review CI logs first to locate the exact failure (job, failing test name, stacktrace, assertion).
2. Reproduce locally by running only the failing test (or the related test file).
3. Confirm whether the failure is:
   - "Expected" due to intentional new behavior (then update the test), or
   - A real bug/regression (then fix code and keep the test).
4. Adjust tests/mocks minimally to reflect real behavior (no unrelated refactors).
5. Before pushing, execute the required path from the **Local Quality Gate Contract** once.

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
- If quality gate has not run since final edits, execute the required path once (see **Local Quality Gate Contract**).

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
Keep version strings and version badges in sync wherever they appear.
For ES docs, use Spanish (Spain) phrasing (`es-ES`) and avoid LATAM variants.

**Documentation style:**

- Keep sentences clear and concise.
- Do not use emojis in any `.md` file, including `README`, changelogs, manuals, and release notes.
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

### 3) Create Release Artifacts ("Payload")

1. **Release Notes Files**:
    - Create `docs/releases/RELEASE_NOTES_vX.Y.Z.md` (EN) and `..._ES.md` (ES).
    - **Language Badges**: MUST use the standard design:
      - EN: `[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](...)`
      - ES: `[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](...)`
    - Use **Absolute URLs** for badge links.
2. **Commit & Push Branch**:
    - Commit notes and version bumps.
    - Push branch (tagging happens in step 5 after merge).

- Add a new section to `CHANGELOG.md` and `ES/CHANGELOG_ES.md`
- Create Audit Report (PRIVATE - do NOT commit):
  - `scan_results_private/AUDIT_REPORT_vX.Y.Z.md`
  - This file contains network-specific data and must never be pushed to the repository.

### 4) Final verification

- Confirm the **Local Quality Gate Contract** has passed and is still valid (no file changes since that run).
- If not yet run, execute the required gate path once now.
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
git tag -a vX.Y.Z -m "RedAudit vX.Y.Z"
git push origin main --tags
```

Do not re-run quality gate in this step unless files changed after step 4.

> [!WARNING]
> **Pushing tags is NOT enough.** `git push --tags` creates the pointer but leaves the GitHub Release page empty. You **MUST** complete step 6.

### 6) GitHub Release

Prefer `gh` (GitHub CLI):

1. **Prepare Payload**:
   Copy the content from the English release notes (`docs/releases/RELEASE_NOTES_vX.Y.Z.md`) into a temporary file `release_payload.md`.

2. **Create Release**:

   ```bash
   gh release create vX.Y.Z -t "vX.Y.Z - <title>" -F release_payload.md
   ```

**CRITICAL**: The GitHub Release **MUST** contain the full text body (payload), not just the title.

### Release Payload Standard

- **Bilingual Badge**: Always include the "Ver en Español" / "View in English" badge at the very top.
- **Absolute URLs**: Use absolute URLs for all badge links (relative links break on the GitHub release page).
  - Example: `https://github.com/dorinbadea/RedAudit/blob/vX.Y.Z/docs/releases/RELEASE_NOTES_vX.Y.Z_ES.md`
- **Emoji-Free**: No emojis in the payload. Maintain a professional tone.
- **Structure**: Organize content into `## Summary`, `## Added`, `## Improved`, `## Fixed`, `## Testing`, and `## Upgrade`.
- **Audience-First Detail Level**: Write for end users (outcomes and impact), not for maintainers (internal validation workflow).
- **No User Validation Steps by Default**: Do not ask users to run manual checks in `Testing`/`Upgrade` unless a release truly requires migration or explicit operator action.
- **Testing Section Style**: Keep it concise and non-actionable for users (for example: `Internal validation completed.`).
- **Upgrade Section Style**: If no migration is needed, state `No action required.` Include upgrade steps only when strictly necessary.
- **Concision Rule**: Keep Added/Improved/Fixed focused on what was resolved; avoid low-level implementation details unless they are critical for safe adoption.
- **Verify**: Ensure the release body is correctly rendered and links work before finalization.

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
