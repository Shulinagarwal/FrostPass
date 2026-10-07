"""Create unscored local deployment identities in two Floci accounts.

The task's scored infrastructure remains entirely under the submission's
Terraform/OpenTofu configuration. This bootstrap only gives the solver
account-routable administrator credentials for initial provisioning.
"""

import json
import os
from pathlib import Path

import boto3
from botocore.exceptions import ClientError


ENDPOINT = os.environ.get("AWS_ENDPOINT_URL", "http://aws:4566")
REGION = os.environ.get("AWS_REGION", "us-east-1")
OUT = Path(os.environ.get("FROSTPASS_CONFIG_DIR", "/config"))


def ensure_admin(account_id, name):
    iam = boto3.client(
        "iam",
        endpoint_url=ENDPOINT,
        region_name=REGION,
        aws_access_key_id=account_id,
        aws_secret_access_key="local-bootstrap",
    )
    try:
        iam.get_user(UserName=name)
    except ClientError as error:
        if error.response["Error"]["Code"] != "NoSuchEntity":
            raise
        iam.create_user(UserName=name)
    iam.attach_user_policy(
        UserName=name,
        PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess",
    )
    for key in iam.list_access_keys(UserName=name)["AccessKeyMetadata"]:
        iam.delete_access_key(UserName=name, AccessKeyId=key["AccessKeyId"])
    key = iam.create_access_key(UserName=name)["AccessKey"]
    return {
        "access_key_id": key["AccessKeyId"],
        "secret_access_key": key["SecretAccessKey"],
    }


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    bootstrap = {
        "archive": ensure_admin("111111111111", "frostpass-archive-admin"),
        "access": ensure_admin("222222222222", "frostpass-access-admin"),
    }
    config_path = OUT / "bootstrap.json"
    config_path.write_text(json.dumps(bootstrap, indent=2) + "\n", encoding="utf-8")
    os.chmod(config_path, 0o644)
    tfvars = {
        "archive_admin_access_key": bootstrap["archive"]["access_key_id"],
        "archive_admin_secret_key": bootstrap["archive"]["secret_access_key"],
        "access_admin_access_key": bootstrap["access"]["access_key_id"],
        "access_admin_secret_key": bootstrap["access"]["secret_access_key"],
    }
    vars_path = OUT / "terraform.tfvars.json"
    vars_path.write_text(json.dumps(tfvars, indent=2) + "\n", encoding="utf-8")
    os.chmod(vars_path, 0o644)
    print("Created local archive and access account deployment identities")


if __name__ == "__main__":
    main()
