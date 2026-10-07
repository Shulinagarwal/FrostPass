#!/bin/sh
set -eu

root="$(cd "$(dirname "$0")" && pwd)"
docker build --target intake \
  -t "111111111111.dkr.ecr.us-east-1.amazonaws.com/frostpass-intake:1" "$root"
docker build --target grants \
  -t "222222222222.dkr.ecr.us-east-1.amazonaws.com/frostpass-grants:1" "$root"
docker build --target broker \
  -t "222222222222.dkr.ecr.us-east-1.amazonaws.com/frostpass-broker:1" "$root"
docker build --target witness \
  -t "222222222222.dkr.ecr.us-east-1.amazonaws.com/frostpass-witness:1" "$root"
