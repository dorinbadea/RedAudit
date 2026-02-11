#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PYTHON_VERSIONS="${PYTHON_VERSIONS:-3.10 3.11 3.12}"
VENV_ROOT="${VENV_ROOT:-$ROOT_DIR/.venv/ci}"
RUN_PRECOMMIT="${RUN_PRECOMMIT:-1}"
RUN_TESTS="${RUN_TESTS:-1}"
COVERAGE_FAIL_UNDER="${COVERAGE_FAIL_UNDER:-80}"
CHANGED_FILE_COVERAGE_MIN="${CHANGED_FILE_COVERAGE_MIN:-98}"
COVERAGE_BASE_REF="${COVERAGE_BASE_REF:-origin/main}"

normalize_flag() {
  local value="$1"
  local name="$2"
  local lowered
  lowered="$(printf '%s' "${value}" | tr '[:upper:]' '[:lower:]')"
  case "${lowered}" in
    1|true|yes|on) echo "1" ;;
    0|false|no|off) echo "0" ;;
    *)
      echo "Invalid value for ${name}: ${value}"
      echo "Use one of: 1,0,true,false,yes,no,on,off."
      exit 1
      ;;
  esac
}

RUN_PRECOMMIT="$(normalize_flag "${RUN_PRECOMMIT}" "RUN_PRECOMMIT")"
RUN_TESTS="$(normalize_flag "${RUN_TESTS}" "RUN_TESTS")"

if [ "${RUN_TESTS}" -eq 1 ] && ! command -v nmap >/dev/null 2>&1; then
  echo "nmap is required for CI-parity test runs."
  echo "Install nmap or run with RUN_TESTS=0 to skip tests intentionally."
  exit 1
fi

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
  echo "Install Python 3.10-3.12 or set PYTHON_VERSIONS to match what is available."
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
    "${venv_dir}/bin/pytest" tests/ -v --cov=redaudit --cov-report=xml --cov-report=term-missing --cov-report=json
    "${venv_dir}/bin/python" -m coverage report --fail-under="${COVERAGE_FAIL_UNDER}"
    "${venv_dir}/bin/python" scripts/check_changed_coverage.py \
      --coverage-file coverage.json \
      --threshold "${CHANGED_FILE_COVERAGE_MIN}" \
      --base-ref "${COVERAGE_BASE_REF}"
  fi

  first_run=0
done
