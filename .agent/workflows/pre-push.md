---
description: Quality gate before pushing or merging
---

# Pre-Push Quality Gate (MANDATORY)

**Before pushing a branch or merging to `main`, run (from the repository root):**

```bash
pre-commit run --all-files
```

## Why This Matters

- CI will fail if pre-commit hooks don't pass
- Black reformats Python code (line length 100, blank lines, etc.)
- flake8 catches style issues
- Pushing without running pre-commit = broken CI = bad UX for user

## Checklist Before Push

1. [ ] `pre-commit run --all-files` passes
2. [ ] `pip install -r requirements-dev.lock && pip install -e .` (Ensure deps are synced)
3. [ ] `pytest tests/ -v` passes
4. [ ] `bash scripts/ci_local.sh` passes (Local CI parity, optional but recommended)
5. [ ] `git status` is clean

## Common Issues

- **Extra blank lines**: Black requires exactly 1 blank line before comments after code blocks
- **Line length**: Max 100 characters
- **Trailing whitespace**: Automatically fixed by pre-commit

## If Pre-Commit Modifies Files

Commit the changes separately:

```bash
git add -A
git commit -m "chore(pre-commit): apply formatting fixes"
```

Then push.
