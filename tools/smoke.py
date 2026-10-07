"""Small caller-only probe for an already deployed FrostPass instance."""
import base64
import json
import os
from pathlib import Path
import time
import uuid
import boto3
from botocore.exceptions import ClientError


def main():
    manifest = json.loads(Path(os.environ.get("FROSTPASS_MANIFEST", "/workspace/submission/manifest.json")).read_text())
    endpoint = os.environ.get("FROSTPASS_SMOKE_ENDPOINT", manifest["endpoint"])
    def invoke(actor, service, event):
        credentials = manifest["callers"][actor]
        client = boto3.client("lambda", endpoint_url=endpoint, region_name=manifest["region"],
                              aws_access_key_id=credentials["access_key_id"],
                              aws_secret_access_key=credentials["secret_access_key"])
        result = client.invoke(FunctionName=manifest["functions"][service], Payload=json.dumps(event).encode())
        response = json.loads(result["Payload"].read())
        assert "FunctionError" not in result, response
        return response
    shipment, sensor = "smoke-" + uuid.uuid4().hex[:16], "logger"
    report = json.dumps({"shipment_id": shipment, "sensor_id": sensor, "samples_mc": [2000, 5000, 8000]}).encode()
    stored = invoke("custodian", "intake", {"operation": "put", "shipment_id": shipment,
                                             "sensor_id": sensor, "content_base64": base64.b64encode(report).decode()})
    grant = invoke("approver", "grants", {"operation": "create", "shipment_id": shipment,
                                          "sensor_id": sensor, "version_id": stored["version_id"],
                                          "expected_sha256": stored["sha256"], "expires_at": int(time.time()) + 600})
    request = {"operation": "evaluate", "request_id": "r-" + uuid.uuid4().hex[:24],
               "grant_id": grant["grant_id"], "shipment_id": shipment, "sensor_id": sensor,
               "version_id": stored["version_id"]}
    assert invoke("reviewer", "broker", request) == {"status": "denied", "reason": "inactive-grant"}
    invoke("approver", "grants", {"operation": "approve", "grant_id": grant["grant_id"]})
    assert invoke("reviewer", "broker", request)["status"] == "denied", "historical denial changed"
    request["request_id"] = "r-" + uuid.uuid4().hex[:24]
    release = invoke("reviewer", "broker", request)
    assert release["status"] == "released" and release["sha256"] == stored["sha256"]
    assert invoke("reviewer", "broker", request) == release
    assert invoke("reviewer", "broker", {**request, "sensor_id": "other"}) == {
        "status": "denied", "reason": "request-conflict"}
    invoke("approver", "grants", {"operation": "revoke", "grant_id": grant["grant_id"]})
    assert invoke("reviewer", "broker", request) == release
    assert invoke("reviewer", "broker", {**request, "request_id": "r-" + uuid.uuid4().hex[:24]})["status"] == "denied"
    try:
        invoke("outsider", "broker", request)
    except ClientError as error:
        assert error.response["ResponseMetadata"]["HTTPStatusCode"] == 403
    else:
        raise AssertionError("outsider invoked Gate")
    print("PASS: safe release, durable replay, collisions, revocation and caller isolation")


if __name__ == "__main__":
    main()
