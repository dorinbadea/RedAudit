#!/usr/bin/env bash
set -euo pipefail

required_files=(
  ".cursorrules"
  "agents/AGENTS.md"
  ".agent/rules/workflow.md"
  ".agent/workflows/pre-push.md"
)

for file in "${required_files[@]}"; do
  if [ ! -f "$file" ]; then
    echo "Missing required pointer: $file"
    exit 1
  fi
  if ! grep -q "AGENTS.md" "$file"; then
    echo "Pointer missing AGENTS.md reference: $file"
    exit 1
  fi
  if ! grep -q "canonical" "$file"; then
    echo "Pointer missing canonical note: $file"
    exit 1
  fi
done
