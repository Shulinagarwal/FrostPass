#!/usr/bin/env sh
set -eu

project_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$project_root/solution/infra"
engine="${TERRAFORM_BIN:-terraform}"
case "${1:-}" in
  validate)
    "$engine" validate -no-color
    ;;
  apply)
    exec bash "$project_root/solution/deploy.sh"
    ;;
  output)
    "$engine" output -json manifest | python3 "$project_root/solution/publish.py" "$project_root/solution/manifest.json"
    ;;
  destroy)
    exec bash "$project_root/solution/destroy.sh"
    ;;
  *)
    echo "usage: local-terraform.sh validate|apply|output|destroy" >&2
    exit 2
    ;;
esac
