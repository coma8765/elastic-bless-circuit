#!/bin/sh
set -eu
repo=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
export ANSIBLE_CONFIG="$repo/deploy/ansible/ansible.cfg"
export ANSIBLE_HOME="$repo/.local/ansible-home"
export ANSIBLE_COLLECTIONS_PATH="$repo/.local/ansible-collections"
export ANSIBLE_LOCAL_TEMP="$repo/.local/ansible-home/tmp"
export ANSIBLE_SSH_CONTROL_PATH_DIR="$repo/.local/ansible-home/cp"
if [ -x "$repo/.local/ansible-venv/bin/ansible-playbook" ]; then
  exec "$repo/.local/ansible-venv/bin/ansible-playbook" "$@"
fi
exec ansible-playbook "$@"
