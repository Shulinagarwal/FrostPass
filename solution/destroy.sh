#!/usr/bin/env bash
set -Eeuo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
infra="$root/infra"
engine="${TERRAFORM_BIN:-terraform}"
prefix="${FROSTPASS_PREFIX:-frostpass}"
bootstrap_file="${FROSTPASS_BOOTSTRAP_TFVARS:-/workspace/config/terraform.tfvars.json}"
export FROSTPASS_PREFIX="$prefix" FROSTPASS_BOOTSTRAP_TFVARS="$bootstrap_file"
tf_vars=(-var-file="$bootstrap_file" -var "prefix=$prefix")

adopt_file="$infra/zz_adopt_generated.tf"
state_json="$(mktemp)"
rm -f "$adopt_file"
trap 'rm -f "$adopt_file" "$state_json"' EXIT

# An unreadable (torn or corrupted) state file is set aside before init,
# which would otherwise fail reading it; recovery then proceeds as for
# lost state.
for file in "$infra/terraform.tfstate" "$infra/terraform.tfstate.backup"; do
  if [[ -s "$file" ]] && ! python3 -c 'import json, sys; json.load(open(sys.argv[1]))' "$file" 2>/dev/null; then
    mv -f "$file" "$file.unreadable-$(date +%s)"
  fi
done

"$engine" -chdir="$infra" init -input=false
"$engine" -chdir="$infra" state pull > "$state_json" 2>/dev/null || true
[[ -s "$state_json" ]] || echo '{}' > "$state_json"

# Live resources missing from state (lost state, a crash) are adopted first,
# so the whole deployment is removed, never only what state remembers.
python3 "$root/adopt.py" discover "$state_json" > "$adopt_file"
if [[ -s "$adopt_file" ]]; then
  echo "Adopting $(grep -c '^import' "$adopt_file") live resources before destroying them"
  "$engine" -chdir="$infra" apply -input=false -auto-approve "${tf_vars[@]}"
fi
rm -f "$adopt_file"

# IAM refuses to delete a user that still holds keys, and Floci cannot run
# the provider's force_destroy cleanup, so retire every caller key first.
python3 "$root/adopt.py" keys-all
"$engine" -chdir="$infra" destroy -input=false -auto-approve "${tf_vars[@]}"
rm -f "$root/manifest.json"
