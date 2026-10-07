#!/usr/bin/env bash
set -Eeuo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
infra="$root/infra"
engine="${TERRAFORM_BIN:-terraform}"
prefix="${FROSTPASS_PREFIX:-frostpass}"
bootstrap_file="${FROSTPASS_BOOTSTRAP_TFVARS:-/workspace/config/terraform.tfvars.json}"
export FROSTPASS_PREFIX="$prefix" FROSTPASS_BOOTSTRAP_TFVARS="$bootstrap_file"
tf_vars=(-var-file="$bootstrap_file" -var "prefix=$prefix")

# Import blocks for live resources missing from state (after lost state or a
# crash mid-apply) are generated per run and never kept.
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
    echo "Set aside unreadable state file $(basename "$file")"
  fi
done

"$engine" -chdir="$infra" init -input=false

pull_state() {
  "$engine" -chdir="$infra" state pull > "$state_json" 2>/dev/null || true
  [[ -s "$state_json" ]] || echo '{}' > "$state_json"
}
pull_state

# A restored older state may record objects that no longer exist; drop them so
# the live replacements are adopted instead of duplicated.
for address in $(python3 "$root/adopt.py" stale "$state_json"); do
  echo "Dropping stale $address from state"
  "$engine" -chdir="$infra" state rm "$address" >/dev/null
done
pull_state

python3 "$root/adopt.py" discover "$state_json" > "$adopt_file"
if [[ -s "$adopt_file" ]]; then
  echo "Adopting $(grep -c '^import' "$adopt_file") live resources that are missing from state"
else
  rm -f "$adopt_file"
fi
python3 "$root/adopt.py" keys-pre "$state_json"

"$engine" -chdir="$infra" apply -input=false -auto-approve "${tf_vars[@]}"
rm -f "$adopt_file"

# Write the new manifest atomically, then retire any key it no longer uses.
"$engine" -chdir="$infra" output -json manifest \
  | python3 "$root/publish.py" "$root/manifest.json"
python3 "$root/adopt.py" keys-post
