"""Reconcile Terraform state with the live FrostPass deployment.

discover STATE_JSON       print import blocks for resources that exist but are not in state
stale STATE_JSON          print state addresses whose recorded object no longer exists
keys-pre STATE_JSON       retire caller keys that neither state nor the current manifest uses
keys-post                 retire caller keys that the new manifest does not use
keys-all                  retire every caller key (right before destroy)
"""

import json
import os
import sys
from pathlib import Path

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

ROOT = Path(__file__).resolve().parent
PREFIX = os.environ.get("FROSTPASS_PREFIX", "frostpass")
ENDPOINT = os.environ.get("AWS_ENDPOINT_URL", "http://aws:4566")
TFVARS = json.loads(Path(os.environ.get(
    "FROSTPASS_BOOTSTRAP_TFVARS", "/workspace/config/terraform.tfvars.json")).read_text())
CALLERS = {"custodian": "archive", "approver": "access", "reviewer": "access", "outsider": "access"}


def client(service, account):
    options = {
        "endpoint_url": ENDPOINT,
        "region_name": "us-east-1",
        "aws_access_key_id": TFVARS[f"{account}_admin_access_key"],
        "aws_secret_access_key": TFVARS[f"{account}_admin_secret_key"],
    }
    if service == "s3":
        options["config"] = Config(s3={"addressing_style": "path"})
    return boto3.client(service, **options)


def exists(lookup):
    try:
        return lookup() is not False
    except ClientError:
        return False


def state_resources(state_path):
    try:
        state = json.loads(Path(state_path).read_text())
    except (OSError, ValueError):
        return {}, set()
    addresses, key_ids = set(), set()
    for resource in state.get("resources", []):
        if resource.get("mode") != "managed":
            continue
        address = f"{resource['type']}.{resource['name']}"
        if resource.get("instances"):
            addresses.add(address)
        if resource["type"] == "aws_iam_access_key":
            key_ids.update(i["attributes"]["id"] for i in resource.get("instances", []))
    return addresses, key_ids


def live_mappings(lam_access):
    """This deployment's stream mappings. Everything is listed and filtered here:
    Floci ignores the list filters, and another deployment's mappings must never
    be adopted or deleted."""
    mappings, marker = [], None
    while True:
        page = lam_access.list_event_source_mappings(**({"Marker": marker} if marker else {}))
        mappings += [m for m in page.get("EventSourceMappings", [])
                     if m.get("FunctionArn", "").endswith(f":function:{PREFIX}-witness")
                     and f":table/{PREFIX}-audit/stream/" in m.get("EventSourceArn", "")]
        marker = page.get("NextMarker")
        if not marker:
            return mappings


def state_ids(state_path, resource_type):
    """IDs that state records for one resource type."""
    try:
        state = json.loads(Path(state_path).read_text())
    except (OSError, ValueError):
        return set()
    return {instance["attributes"]["id"]
            for resource in state.get("resources", []) if resource.get("type") == resource_type
            for instance in resource.get("instances", [])}


def stale(state_path):
    """Addresses whose recorded ID no longer exists (after an older state backup
    was restored). They are dropped from state so the live object is adopted."""
    manifest_ids = manifest_key_ids()
    recorded_keys = state_ids(state_path, "aws_iam_access_key")
    if recorded_keys and recorded_keys != manifest_ids:
        recorded_addresses, _ = state_resources(state_path)
        for actor in CALLERS:
            address = f"aws_iam_access_key.{actor}"
            if address in recorded_addresses:
                print(address)
    live = {m["UUID"] for m in live_mappings(client("lambda", "access"))}
    recorded = state_ids(state_path, "aws_lambda_event_source_mapping")
    if recorded and not recorded & live:
        print("aws_lambda_event_source_mapping.audit_witness")


def discover(state_path):
    managed, _ = state_resources(state_path)
    p = PREFIX
    s3, db = client("s3", "archive"), client("dynamodb", "access")
    iam = {"archive": client("iam", "archive"), "access": client("iam", "access")}
    lam = {"archive": client("lambda", "archive"), "access": client("lambda", "access")}
    scheduler, kms = client("scheduler", "access"), client("kms", "archive")

    candidates = []
    for name, bucket in (("evidence", f"{p}-evidence"), ("audit_mirror", f"{p}-audit-mirror")):
        if exists(lambda b=bucket: s3.head_bucket(Bucket=b)):
            candidates += [
                (f"aws_s3_bucket.{name}", bucket, True),
                (f"aws_s3_bucket_versioning.{name}", bucket,
                 exists(lambda b=bucket: s3.get_bucket_versioning(Bucket=b).get("Status") is not None or False)),
                (f"aws_s3_bucket_public_access_block.{name}", bucket,
                 exists(lambda b=bucket: s3.get_public_access_block(Bucket=b))),
            ]
    for name, bucket in (("broker_read", f"{p}-evidence"), ("audit_mirror", f"{p}-audit-mirror")):
        candidates.append((f"aws_s3_bucket_policy.{name}", bucket,
                           exists(lambda b=bucket: s3.get_bucket_policy(Bucket=b))))
    for name in ("grants", "audit"):
        candidates.append((f"aws_dynamodb_table.{name}", f"{p}-{name}",
                           exists(lambda n=name: db.describe_table(TableName=f"{p}-{n}"))))
    roles = {"intake": ("archive", "policy"), "grants": ("access", "policy"), "broker": ("access", "policy"),
             "archive_reader": ("archive", "policy"), "witness": ("access", "policy"),
             "audit_scheduler": ("access", "invoke")}
    for name, (account, suffix) in roles.items():
        role = f"{p}-{name.replace('_', '-')}"
        candidates.append((f"aws_iam_role.{name}", role, exists(lambda a=account, r=role: iam[a].get_role(RoleName=r))))
        policy = f"{role}-{suffix}"
        candidates.append((f"aws_iam_role_policy.{name}", f"{role}:{policy}",
                           exists(lambda a=account, r=role, n=policy: iam[a].get_role_policy(RoleName=r, PolicyName=n))))
    for name, account in CALLERS.items():
        user = f"{p}-{name}"
        candidates.append((f"aws_iam_user.{name}", user, exists(lambda a=account, u=user: iam[a].get_user(UserName=u))))
        if name != "outsider":
            policy = f"{user}-invoke"
            candidates.append((f"aws_iam_user_policy.{name}", f"{user}:{policy}",
                               exists(lambda a=account, u=user, n=policy: iam[a].get_user_policy(UserName=u, PolicyName=n))))
    for name in ("intake", "grants", "broker", "witness"):
        account = "archive" if name == "intake" else "access"
        candidates.append((f"aws_lambda_function.{name}", f"{p}-{name}",
                           exists(lambda a=account, n=name: lam[a].get_function(FunctionName=f"{p}-{n}"))))
    candidates.append(("aws_scheduler_schedule_group.audit", f"{p}-audit",
                       exists(lambda: scheduler.get_schedule_group(Name=f"{p}-audit"))))
    candidates.append(("aws_scheduler_schedule.audit_reconcile", f"{p}-audit/{p}-audit-reconcile",
                       exists(lambda: scheduler.get_schedule(GroupName=f"{p}-audit", Name=f"{p}-audit-reconcile"))))

    # The key is found through its alias, or through its description when a
    # crash happened between creating the key and its alias.
    alias = f"alias/{p}-evidence"
    key_id = None
    try:
        key_id = kms.describe_key(KeyId=alias)["KeyMetadata"]["KeyId"]
        candidates.append(("aws_kms_alias.evidence", alias, True))
    except ClientError:
        for entry in kms.list_keys()["Keys"]:
            meta = kms.describe_key(KeyId=entry["KeyId"])["KeyMetadata"]
            if meta.get("Description") == f"FrostPass evidence key {p}" and meta["KeyState"] == "Enabled":
                key_id = meta["KeyId"]
                break
    if key_id:
        candidates.append(("aws_kms_key.evidence", key_id, True))

    # Exactly one stream mapping. Keep the one state already tracks when it is
    # still live, otherwise the first live one; delete every other duplicate.
    mappings = live_mappings(lam["access"])
    tracked = state_ids(state_path, "aws_lambda_event_source_mapping")
    keeper = next((m for m in mappings if m["UUID"] in tracked), mappings[0] if mappings else None)
    for extra in mappings:
        if keeper and extra["UUID"] != keeper["UUID"]:
            lam["access"].delete_event_source_mapping(UUID=extra["UUID"])
    if keeper:
        candidates.append(("aws_lambda_event_source_mapping.audit_witness", keeper["UUID"], True))

    for address, import_id, present in candidates:
        if present and address not in managed:
            print(f'import {{\n  to = {address}\n  id = "{import_id}"\n}}\n')


def caller_keys():
    for name, account in CALLERS.items():
        iam = client("iam", account)
        try:
            keys = iam.list_access_keys(UserName=f"{PREFIX}-{name}")["AccessKeyMetadata"]
        except ClientError:
            continue
        yield iam, f"{PREFIX}-{name}", [k["AccessKeyId"] for k in keys]


def manifest_key_ids():
    try:
        callers = json.loads((ROOT / "manifest.json").read_text())["callers"]
        return {caller["access_key_id"] for caller in callers.values()}
    except (OSError, ValueError, KeyError):
        return set()


def retire_keys(keep):
    for iam, user, key_ids in caller_keys():
        for key_id in key_ids:
            if key_id not in keep:
                iam.delete_access_key(UserName=user, AccessKeyId=key_id)
                print(f"retired access key {key_id} of {user}")


if __name__ == "__main__":
    command = sys.argv[1]
    if command == "discover":
        discover(sys.argv[2])
    elif command == "stale":
        stale(sys.argv[2])
    elif command == "keys-pre":
        _, state_keys = state_resources(sys.argv[2])
        retire_keys(state_keys | manifest_key_ids())  # keep keys callers still use
    elif command == "keys-post":
        retire_keys(manifest_key_ids())
    elif command == "keys-all":
        retire_keys(set())  # before destroy: IAM refuses to delete users that hold keys
    else:
        raise SystemExit(f"unknown command {command}")
