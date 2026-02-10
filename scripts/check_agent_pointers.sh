#!/usr/bin/env bash
set -euo pipefail

required_files=(
  ".cursorrules"
  "agents/AGENTS.md"
  "agents/README.md"
  ".agent/rules/workflow.md"
  ".agent/workflows/pre-push.md"
  ".agent/rules/redaudit.md"
  ".agent/workflows/release.md"
)

for file in "${required_files[@]}"; do
  if [ ! -f "$file" ]; then
    echo "Missing required pointer: $file"
    exit 1
  fi
  if ! grep -Fq "AGENTS.md" "$file"; then
    echo "Pointer missing AGENTS.md reference: $file"
    exit 1
  fi
  if ! grep -Eiq "canonical|contract" "$file"; then
    echo "Pointer missing canonical or contract note: $file"
    exit 1
  fi
done
