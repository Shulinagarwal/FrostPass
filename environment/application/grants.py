"""Grant Manager owns the approval lifecycle in the access account."""

import os
import re
import time
import uuid

from common import attr, aws_client, item_values, object_key, required_string


def handler(event, _context):
    if not isinstance(event, dict):
        raise ValueError("event must be an object")
    operation = event.get("operation")
    table = os.environ["GRANTS_TABLE"]
    db = aws_client("dynamodb")

    if operation == "create":
        shipment_id = event.get("shipment_id")
        sensor_id = event.get("sensor_id")
        object_key(shipment_id, sensor_id)
        version_id = required_string(event, "version_id")
        expected_sha256 = required_string(event, "expected_sha256")
        if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
            raise ValueError("expected_sha256 must be a lowercase SHA-256 hex digest")
        expires_at = event.get("expires_at")
        if not isinstance(expires_at, int) or isinstance(expires_at, bool):
            raise ValueError("expires_at must be a Unix timestamp")
        if not int(time.time()) < expires_at <= int(time.time()) + 86400:
            raise ValueError("grant expiry must be within the next 24 hours")
        grant_id = str(uuid.uuid4())
        db.put_item(
            TableName=table,
            Item={
                "grant_id": attr(grant_id),
                "shipment_id": attr(shipment_id),
                "sensor_id": attr(sensor_id),
                "version_id": attr(version_id),
                "expires_at": attr(expires_at),
                "state": attr("pending"),
                "expected_sha256": attr(expected_sha256),
            },
            ConditionExpression="attribute_not_exists(grant_id)",
        )
        return {"status": "pending", "grant_id": grant_id}

    if operation in ("approve", "revoke"):
        grant_id = required_string(event, "grant_id")
        old_state, new_state = (
            ("pending", "approved") if operation == "approve" else ("approved", "revoked")
        )
        result = db.update_item(
            TableName=table,
            Key={"grant_id": attr(grant_id)},
            ConditionExpression="#state = :old",
            UpdateExpression="SET #state = :new",
            ExpressionAttributeNames={"#state": "state"},
            ExpressionAttributeValues={":old": attr(old_state), ":new": attr(new_state)},
            ReturnValues="ALL_NEW",
        )
        item = item_values(result["Attributes"])
        return {"status": new_state, "grant_id": grant_id, "expires_at": item["expires_at"]}

    raise ValueError("operation must be create, approve or revoke")
