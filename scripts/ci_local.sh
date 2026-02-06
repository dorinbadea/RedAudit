#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PYTHON_VERSIONS="${PYTHON_VERSIONS:-3.9 3.10 3.11 3.12}"
VENV_ROOT="${VENV_ROOT:-$ROOT_DIR/.venv/ci}"
RUN_PRECOMMIT="${RUN_PRECOMMIT:-1}"
RUN_TESTS="${RUN_TESTS:-1}"

found_versions=()
missing_versions=()

for ver in $PYTHON_VERSIONS; do
  py="python${ver}"
  if command -v "$py" >/dev/null 2>&1; then
    found_versions+=("$ver")
  else
    missing_versions+=("$ver")
  fi
done

if [ "${#found_versions[@]}" -eq 0 ]; then
  echo "No requested Python versions found in PATH."
  echo "Install Python 3.9-3.12 or set PYTHON_VERSIONS to match what is available."
  exit 1
fi

echo "Python versions to run: ${found_versions[*]}"
if [ "${#missing_versions[@]}" -gt 0 ]; then
  echo "Missing Python versions: ${missing_versions[*]}"
fi

first_run=1
for ver in "${found_versions[@]}"; do
  py="python${ver}"
  venv_dir="${VENV_ROOT}/py${ver}"
  echo "==> Setting up venv for Python ${ver} at ${venv_dir}"
  "${py}" -m venv "${venv_dir}"
  "${venv_dir}/bin/python" -m pip install --upgrade pip
  "${venv_dir}/bin/python" -m pip install -r requirements-dev.lock
  "${venv_dir}/bin/python" -m pip install -e .

  if [ "${RUN_PRECOMMIT}" -eq 1 ] && [ "${first_run}" -eq 1 ]; then
    "${venv_dir}/bin/pre-commit" run --all-files
  fi

  if [ "${RUN_TESTS}" -eq 1 ]; then
    "${venv_dir}/bin/pytest" tests/ -v
  fi

  first_run=0
done
