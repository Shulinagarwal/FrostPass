"""Evidence Intake owns immutable file uploads in the archive account."""

import base64
import hashlib
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from common import aws_client, decode_content, object_key


def handler(event, _context):
    if not isinstance(event, dict) or event.get("operation") != "put":
        raise ValueError("operation must be put")
    shipment_id = event.get("shipment_id")
    sensor_id = event.get("sensor_id")
    key = object_key(shipment_id, sensor_id)
    content = decode_content(event.get("content_base64"))
    digest = hashlib.sha256(content).hexdigest()
    key = object_key(shipment_id, sensor_id)
    context = {"shipment": shipment_id, "sensor": sensor_id}
    data_key = aws_client("kms").generate_data_key(
        KeyId=os.environ["EVIDENCE_KEY_ID"],
        KeySpec="AES_256",
        EncryptionContext=context,
    )
    nonce = os.urandom(12)
    ciphertext = AESGCM(data_key["Plaintext"]).encrypt(nonce, content, key.encode())
    result = aws_client("s3").put_object(
        Bucket=os.environ["EVIDENCE_BUCKET"],
        Key=key,
        Body=ciphertext,
        Metadata={
            "sha256": digest,
            "encrypted-key": base64.b64encode(data_key["CiphertextBlob"]).decode(),
            "nonce": base64.b64encode(nonce).decode(),
        },
    )
    version_id = result.get("VersionId")
    if not version_id:
        raise RuntimeError("evidence bucket must have versioning enabled")
    return {
        "status": "stored",
        "shipment_id": shipment_id,
        "sensor_id": sensor_id,
        "version_id": version_id,
        "sha256": digest,
        "size": len(content),
    }
