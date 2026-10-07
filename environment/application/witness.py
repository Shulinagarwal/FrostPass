"""Mirror append-only access decisions into the archive account."""

import json
import os

from botocore.exceptions import ClientError

from common import aws_client


def _document(image):
    return {field: next(iter(value.values())) for field, value in image.items()}


def _copy(s3, bucket, image):
    """Write one decision copy unless it already exists; return True if written."""
    document = _document(image)
    key = f"decisions/{document['audit_id']}.json"
    try:
        s3.head_object(Bucket=bucket, Key=key)
        return False
    except ClientError as error:
        if error.response["ResponseMetadata"]["HTTPStatusCode"] != 404:
            raise
    try:
        s3.put_object(
            Bucket=bucket, Key=key,
            Body=json.dumps(document, sort_keys=True).encode(),
            ContentType="application/json", IfNoneMatch="*",
        )
    except ClientError as error:
        if error.response["ResponseMetadata"]["HTTPStatusCode"] == 412:
            return False
        raise
    return True


def _reconcile(s3, bucket):
    db = aws_client("dynamodb")
    table = os.environ["AUDIT_TABLE"]
    copied = 0
    exclusive_start_key = None
    while True:
        request = {"TableName": table}
        if exclusive_start_key:
            request["ExclusiveStartKey"] = exclusive_start_key
        page = db.scan(**request)
        for image in page.get("Items", []):
            if _copy(s3, bucket, image):
                copied += 1
        exclusive_start_key = page.get("LastEvaluatedKey")
        if not exclusive_start_key:
            break
    return {"reconciled": copied}


def handler(event, _context):
    bucket = os.environ["AUDIT_BUCKET"]
    s3 = aws_client("s3")
    if event.get("source") == "frostpass" and event.get("operation") == "reconcile":
        return _reconcile(s3, bucket)
    count = 0
    for record in event.get("Records", []):
        if record.get("eventName") != "INSERT":
            continue
        # Stream replays (e.g. a recreated mapping) must not rewrite copies.
        if _copy(s3, bucket, record["dynamodb"]["NewImage"]):
            count += 1
    return {"mirrored": count}
