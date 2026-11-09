#!/usr/bin/env bash
# Fast checks shared by contributors and the GitHub-hosted quality job.
set -euo pipefail
ci_repo=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
cd "$ci_repo"
ci_python=${CI_PYTHON:-"$ci_repo/.local/ansible-venv/bin/python"}
if [[ ! -x "$ci_python" ]]; then
  echo 'Create .local/ansible-venv and install deploy/ansible/requirements.txt first.' >&2
  exit 1
fi
mkdir -p .local
"$ci_python" scripts/check-publication.py
cmake -S . -B build/ci -DCMAKE_BUILD_TYPE=Release
cmake --build build/ci --parallel 2
"$ci_python" -m compileall -q tests scripts deploy/ansible/library
"$ci_python" tests/ansible_modules.py
"$ci_python" tests/ansible_guards.py
for ci_inventory in inventory.local.yml inventory.example.yml; do
  for ci_playbook in site.yml build.yml; do
    ./scripts/ansible.sh -i "deploy/ansible/$ci_inventory" --syntax-check "deploy/ansible/$ci_playbook"
  done
done
