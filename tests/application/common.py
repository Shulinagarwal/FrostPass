"""Small shared helpers for the four fixed FrostPass Lambda images."""

import base64
import os
import re


ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")


def aws_client(service):
    import boto3

    options = {"region_name": os.environ.get("AWS_REGION", "us-east-1")}
    if os.environ.get("AWS_ENDPOINT_URL"):
        options["endpoint_url"] = os.environ["AWS_ENDPOINT_URL"]
    if service == "s3":
        from botocore.config import Config

        options["config"] = Config(s3={"addressing_style": "path"})
    return boto3.client(service, **options)


def identifier(value, field):
    if not isinstance(value, str) or not ID_PATTERN.fullmatch(value):
        raise ValueError(f"{field} must be 1-32 lowercase letters, digits or hyphens")
    return value


def object_key(shipment_id, sensor_id):
    return f"reports/{identifier(shipment_id, 'shipment_id')}/{identifier(sensor_id, 'sensor_id')}"


def required_string(event, name):
    value = event.get(name)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} is required")
    return value


def decode_content(value):
    if not isinstance(value, str):
        raise ValueError("content_base64 is required")
    try:
        data = base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error) as error:
        raise ValueError("content_base64 is invalid") from error
    if not 1 <= len(data) <= 65536:
        raise ValueError("content must contain 1-65536 bytes")
    return data


def attr(value):
    if isinstance(value, int):
        return {"N": str(value)}
    return {"S": str(value)}


def item_values(item):
    result = {}
    for key, value in item.items():
        if "S" in value:
            result[key] = value["S"]
        elif "N" in value:
            result[key] = int(value["N"])
    return result
