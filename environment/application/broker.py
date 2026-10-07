"""FrostPass gate: pin telemetry, inspect every sample, durably record before release."""
import base64
import hashlib
import json
import os
import time

from botocore.exceptions import ClientError
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from common import attr, aws_client, identifier, item_values, object_key, required_string


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _cached(item, request_hash):
    if item["request_hash"] != request_hash:
        return {"status": "denied", "reason": "request-conflict"}
    return json.loads(item["response_json"])


def _persist(db, event, fingerprint, outcome, reason, response):
    """The first conditional writer wins. All other writers read that decision."""
    try:
        db.put_item(
            TableName=os.environ["AUDIT_TABLE"],
            Item={
                "audit_id": attr(event["request_id"]),
                "grant_id": attr(event["grant_id"]),
                "outcome": attr(outcome), "reason": attr(reason),
                "at": attr(int(time.time())), "request_hash": attr(fingerprint),
                "response_json": attr(_canonical(response)),
            },
            ConditionExpression="attribute_not_exists(audit_id)",
        )
        return response
    except ClientError as error:
        if error.response["Error"]["Code"] != "ConditionalCheckFailedException":
            raise
        item = db.get_item(TableName=os.environ["AUDIT_TABLE"],
                           Key={"audit_id": attr(event["request_id"])}, ConsistentRead=True)
        winner = item_values(item.get("Item", {}))
        if not winner:
            raise RuntimeError("conditional winner is not readable") from error
        return _cached(winner, fingerprint)


def _read_report(grant):
    assumed = aws_client("sts").assume_role(
        RoleArn=os.environ["ARCHIVE_READER_ROLE"], RoleSessionName="frostpass-reader"
    )["Credentials"]
    import boto3
    from botocore.config import Config
    options = {
        "region_name": os.environ.get("AWS_REGION", "us-east-1"),
        "aws_access_key_id": assumed["AccessKeyId"],
        "aws_secret_access_key": assumed["SecretAccessKey"],
        "aws_session_token": assumed["SessionToken"],
    }
    if os.environ.get("AWS_ENDPOINT_URL"):
        options["endpoint_url"] = os.environ["AWS_ENDPOINT_URL"]
    s3 = boto3.client("s3", config=Config(s3={"addressing_style": "path"}), **options)
    kms = boto3.client("kms", **options)
    key = object_key(grant["shipment_id"], grant["sensor_id"])
    obj = s3.get_object(Bucket=os.environ["EVIDENCE_BUCKET"], Key=key,
                        VersionId=grant["version_id"])
    metadata = obj["Metadata"]
    data_key = kms.decrypt(
        CiphertextBlob=base64.b64decode(metadata["encrypted-key"], validate=True),
        EncryptionContext={"shipment": grant["shipment_id"], "sensor": grant["sensor_id"]},
    )["Plaintext"]
    content = AESGCM(data_key).decrypt(
        base64.b64decode(metadata["nonce"], validate=True), obj["Body"].read(), key.encode())
    digest = hashlib.sha256(content).hexdigest()
    return content, digest, metadata["sha256"]


def handler(event, _context):
    fields = {"operation", "request_id", "grant_id", "shipment_id", "sensor_id", "version_id"}
    if not isinstance(event, dict) or set(event) != fields or event.get("operation") != "evaluate":
        raise ValueError("evaluate requires exactly the six documented fields")
    identifier(event["request_id"], "request_id")
    object_key(event["shipment_id"], event["sensor_id"])
    for field in ("grant_id", "version_id"):
        if len(required_string(event, field)) > 128:
            raise ValueError(f"{field} is too long")
    fingerprint = hashlib.sha256(_canonical(event).encode()).hexdigest()
    db = aws_client("dynamodb")
    old = db.get_item(TableName=os.environ["AUDIT_TABLE"],
                       Key={"audit_id": attr(event["request_id"])}, ConsistentRead=True)
    if old.get("Item"):
        return _cached(item_values(old["Item"]), fingerprint)

    def denied(reason):
        return _persist(db, event, fingerprint, "denied", reason,
                        {"status": "denied", "reason": reason})

    grant = item_values(db.get_item(TableName=os.environ["GRANTS_TABLE"],
                                    Key={"grant_id": attr(event["grant_id"])},
                                    ConsistentRead=True).get("Item", {}))
    if not grant:
        return denied("unknown-grant")
    if grant["state"] != "approved":
        return denied("inactive-grant")
    if grant["expires_at"] <= int(time.time()):
        return denied("expired-grant")
    if any(event[field] != grant[field] for field in ("shipment_id", "sensor_id", "version_id")):
        return denied("scope-mismatch")
    try:
        content, digest, stored_digest = _read_report(grant)
    except (ClientError, KeyError, ValueError, InvalidTag):
        return denied("storage-error")
    if digest != stored_digest or digest != grant["expected_sha256"]:
        return denied("integrity-failure")
    try:
        report = json.loads(content)
        if not isinstance(report, dict) or set(report) != {"shipment_id", "sensor_id", "samples_mc"}:
            return denied("invalid-report")
        if any(report[field] != grant[field] for field in ("shipment_id", "sensor_id")):
            return denied("invalid-report")
        samples = report["samples_mc"]
        if not isinstance(samples, list) or not 1 <= len(samples) <= 64:
            return denied("invalid-report")
        if any(type(sample) is not int or not -100000 <= sample <= 100000 for sample in samples):
            return denied("invalid-report")
    except (ValueError, UnicodeDecodeError):
        return denied("invalid-report")
    if any(sample < 2000 or sample > 8000 for sample in samples):
        return denied("temperature-excursion")
    response = {
        "status": "released", "permit_id": event["request_id"],
        "shipment_id": grant["shipment_id"], "sensor_id": grant["sensor_id"],
        "version_id": grant["version_id"], "sha256": digest,
        "sample_count": len(samples), "min_mc": min(samples), "max_mc": max(samples),
    }
    return _persist(db, event, fingerprint, "allowed", "safe-report", response)
