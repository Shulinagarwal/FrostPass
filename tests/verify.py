"""FrostPass black-box verifier. Scores observable cloud behavior and lifecycle."""
import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import time
import uuid

from infrastructure_checks import (
    InfrastructureChecks, runner, REPORT_DIR, PREFIX,
)


CHECKS = [
    ("contract and declared state", 1, "contract_and_state"),
    ("four service topology", 1, "topology"),
    ("storage and bucket policy", 1, "storage_and_policy"),
    ("two retained report versions", 2, "two_versions"),
    ("encrypted telemetry and reader trust", 3, "encryption_and_reader_boundary"),
    ("pending, expired and mismatched grants", 3, "pending_and_scope"),
    ("approved version release", 4, "approved_delivery"),
    ("temperature boundaries and every sample", 4, "temperature_cases"),
    ("malformed and identity-mismatched telemetry", 3, "malformed_cases"),
    ("reviewed digest and missing version", 3, "integrity_cases"),
    ("stable replay and request collision", 4, "replay_cases"),
    ("concurrent duplicate and conflicting requests", 4, "concurrent_cases"),
    ("historical replay versus current revocation", 3, "replay_lifecycle"),
    ("exact archive receipt contents", 2, "receipt_contents"),
    ("concurrent receipt reconciliation", 2, "concurrent_mirror"),
    ("caller isolation", 2, "caller_isolation"),
    ("direct storage denial", 2, "direct_storage_denial"),
    ("least-privilege policies", 3, "least_privilege"),
    ("attribute-level table writes", 3, "table_write_scope"),
    ("ledger failure closes release", 4, "audit_failure_is_closed"),
    ("revocation and audit", 2, "revocation_and_audit"),
    ("mirrored decisions", 1, "mirrored_audit"),
    ("immutable reports and receipts", 3, "immutable_records"),
    ("KMS key use and exact encryption context", 4, "kms_key_use"),
    ("scheduled reconciliation without stream", 3, "scheduled_reconciliation"),
    ("scheduler confused-deputy protection", 3, "scheduler_trust"),
    ("stable redeploy", 2, "stable_redeploy"),
    ("repair of deleted and altered resources", 3, "repair_drift"),
    ("recovery after state loss", 6, "recovery_after_state_loss"),
    ("recovery from restored stale state", 4, "restored_state_recovery"),
    ("recovery from corrupted state", 3, "corrupted_state_recovery"),
    ("isolated crash-consistent second deployment", 4, "second_deployment"),
    ("complete and scoped destroy", 3, "scoped_destroy"),
    ("destroy after state loss", 3, "destroy_after_state_loss"),
    ("secret handling", 2, "secret_handling"),
]
assert sum(points for _, points, _ in CHECKS) == 100


class Verification(InfrastructureChecks):
    def __init__(self):
        super().__init__()
        self.digests = {}

    def invoke(self, actor, service, event):
        event = dict(event)
        if service == "broker":
            event["operation"] = "evaluate"
            event.setdefault("request_id", "r-" + uuid.uuid4().hex[:24])
        if service == "grants" and event.get("operation") == "create":
            if "expected_sha256" not in event:
                event["expected_sha256"] = self.digests[(event["shipment_id"], event["sensor_id"], event["version_id"])]
        result = super().invoke(actor, service, event)
        if service == "intake":
            self.digests[(event["shipment_id"], event["sensor_id"], result["version_id"])] = result["sha256"]
        return result

    def upload(self, shipment, sensor, report):
        content = report if isinstance(report, bytes) else json.dumps(report, separators=(",", ":")).encode()
        stored = self.invoke("custodian", "intake", {
            "operation": "put", "shipment_id": shipment, "sensor_id": sensor,
            "content_base64": base64.b64encode(content).decode(),
        })
        assert stored["sha256"] == hashlib.sha256(content).hexdigest()
        assert stored["size"] == len(content)
        return stored, content

    def ticket(self, shipment, sensor, stored, approve=True, digest=None):
        event = {"operation": "create", "shipment_id": shipment, "sensor_id": sensor,
                 "version_id": stored["version_id"], "expires_at": int(time.time()) + 3600}
        if digest is not None:
            event["expected_sha256"] = digest
        grant = self.invoke("approver", "grants", event)
        if approve:
            self.invoke("approver", "grants", {"operation": "approve", "grant_id": grant["grant_id"]})
        return {"operation": "evaluate", "request_id": "r-" + uuid.uuid4().hex[:24],
                "grant_id": grant["grant_id"], "shipment_id": shipment, "sensor_id": sensor,
                "version_id": stored["version_id"]}

    def fixture(self, samples=(2000, 5000, 8000), report=None, approve=True):
        shipment, sensor = "ship-" + uuid.uuid4().hex[:16], "probe"
        if report is None:
            report = {"shipment_id": shipment, "sensor_id": sensor, "samples_mc": list(samples)}
        elif callable(report):
            report = report(shipment, sensor)
        stored, content = self.upload(shipment, sensor, report)
        return self.ticket(shipment, sensor, stored, approve), stored, content

    def ledger_item(self, request):
        return self.admin("dynamodb", "access").get_item(
            TableName=self.manifest["tables"]["audit"], Key={"audit_id": {"S": request["request_id"]}},
            ConsistentRead=True).get("Item")

    def fresh(self, request):
        return {**request, "request_id": "r-" + uuid.uuid4().hex[:24]}

    def assert_denied(self, request, reason):
        response = self.invoke("reviewer", "broker", request)
        assert response == {"status": "denied", "reason": reason}, response
        assert self.ledger_item(request)["outcome"]["S"] == "denied"

    def two_versions(self):
        shipment, sensor = "ship-" + uuid.uuid4().hex[:16], "report"
        first, content = self.upload(shipment, sensor, {
            "shipment_id": shipment, "sensor_id": sensor, "samples_mc": [2000, 5000, 8000]})
        second, _ = self.upload(shipment, sensor, {
            "shipment_id": shipment, "sensor_id": sensor, "samples_mc": [5000, 16000, 5000]})
        assert first["version_id"] != second["version_id"]
        self.facts.update(shipment_id=shipment, sensor_id=sensor, first=content,
                          versions=[first["version_id"], second["version_id"]])

    def temperature_cases(self):
        for samples in ([2000], [8000], [2000, 8000], [5000] * 64):
            request, stored, _ = self.fixture(samples)
            out = self.invoke("reviewer", "broker", request)
            assert out == {"status": "released", "permit_id": request["request_id"],
                           "shipment_id": request["shipment_id"], "sensor_id": request["sensor_id"],
                           "version_id": request["version_id"], "sha256": stored["sha256"],
                           "sample_count": len(samples), "min_mc": min(samples), "max_mc": max(samples)}
        for samples in ([1999], [8001], [1999, 5000, 5000], [5000, 8001, 5000], [5000] * 63 + [8001]):
            request, _, _ = self.fixture(samples)
            self.assert_denied(request, "temperature-excursion")
        # A ticket for the safe older version must not silently use latest telemetry.
        warm = {"version_id": self.facts["versions"][1]}
        req = self.ticket(self.facts["shipment_id"], self.facts["sensor_id"], warm)
        self.assert_denied(req, "temperature-excursion")

    def malformed_cases(self):
        reports = [b'not json', b'\xff\xfe', b'null', b'[]']
        for samples in ([], [True], [False], [2000.0], ["5000"], [None], [100001], [5000] * 65):
            reports.append(lambda sh, se, samples=samples: {"shipment_id": sh, "sensor_id": se, "samples_mc": samples})
        reports.extend([
            lambda sh, se: {"shipment_id": "wrong", "sensor_id": se, "samples_mc": [5000]},
            lambda sh, se: {"shipment_id": sh, "sensor_id": "wrong", "samples_mc": [5000]},
            lambda sh, se: {"shipment_id": sh, "sensor_id": se, "samples_mc": [5000], "approved": True},
        ])
        for report in reports:
            request, _, _ = self.fixture(report=report)
            self.assert_denied(request, "invalid-report")

    def integrity_cases(self):
        req, stored, _ = self.fixture()
        wrong = self.ticket(req["shipment_id"], req["sensor_id"], stored, digest="0" * 64)
        self.assert_denied(wrong, "integrity-failure")
        missing = self.ticket(req["shipment_id"], req["sensor_id"], {"version_id": "no-such-version"}, digest=stored["sha256"])
        self.assert_denied(missing, "storage-error")
        unknown = {**self.fresh(req), "grant_id": "no-such-grant"}
        self.assert_denied(unknown, "unknown-grant")

    def replay_cases(self):
        req, _, _ = self.fixture()
        original = self.invoke("reviewer", "broker", req)
        before = self.ledger_item(req)
        for _ in range(5):
            assert self.invoke("reviewer", "broker", dict(reversed(list(req.items())))) == original
        for field in ("grant_id", "shipment_id", "sensor_id", "version_id"):
            collided = {**req, field: "wrong"}
            assert self.invoke("reviewer", "broker", collided) == {"status": "denied", "reason": "request-conflict"}
        assert self.ledger_item(req) == before, "replay or conflict mutated the original decision"

    def concurrent_cases(self):
        req, _, _ = self.fixture()
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: self.invoke("reviewer", "broker", req), range(8)))
        assert all(result == results[0] and result["status"] == "released" for result in results)
        assert json.loads(self.ledger_item(req)["response_json"]["S"]) == results[0]
        other = self.ticket(req["shipment_id"], req["sensor_id"], {"version_id": req["version_id"]})
        conflict_id = "r-" + uuid.uuid4().hex[:24]
        requests = [{**(req if i % 2 else other), "request_id": conflict_id} for i in range(8)]
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda request: self.invoke("reviewer", "broker", request), requests))
        fingerprint = self.ledger_item(requests[0])["request_hash"]["S"]
        for request, result in zip(requests, results):
            wanted = hashlib.sha256(json.dumps(request, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            if wanted == fingerprint:
                assert result["status"] == "released"
            else:
                assert result == {"status": "denied", "reason": "request-conflict"}

    def replay_lifecycle(self):
        req, _, _ = self.fixture(approve=False)
        self.assert_denied(req, "inactive-grant")
        self.invoke("approver", "grants", {"operation": "approve", "grant_id": req["grant_id"]})
        self.assert_denied(req, "inactive-grant")  # immutable historical denial
        released = self.fresh(req)
        result = self.invoke("reviewer", "broker", released)
        assert result["status"] == "released"
        self.invoke("approver", "grants", {"operation": "revoke", "grant_id": req["grant_id"]})
        assert self.invoke("reviewer", "broker", released) == result
        self.assert_denied(self.fresh(req), "inactive-grant")
        # Expiry also applies to new requests, while historical decisions stay stable.
        fresh, _, _ = self.fixture()
        result = self.invoke("reviewer", "broker", fresh)
        self.admin("dynamodb", "access").update_item(
            TableName=self.manifest["tables"]["grants"], Key={"grant_id": {"S": fresh["grant_id"]}},
            UpdateExpression="SET expires_at = :past", ExpressionAttributeValues={":past": {"N": "1"}})
        assert self.invoke("reviewer", "broker", fresh) == result
        self.assert_denied(self.fresh(fresh), "expired-grant")

    def receipt_contents(self):
        request, _, _ = self.fixture()
        self.invoke("reviewer", "broker", request)
        deadline = time.monotonic() + 90
        while not self.copy_exists(request["request_id"]):
            assert time.monotonic() < deadline, "stream receipt never appeared"
            time.sleep(1)
        body = self.admin("s3", "archive").get_object(
            Bucket=self.manifest["audit_bucket"], Key=f"decisions/{request['request_id']}.json")["Body"].read()
        expected = {k: next(iter(v.values())) for k, v in self.ledger_item(request).items()}
        assert json.loads(body) == expected
        self.facts["receipt_request"] = request

    def concurrent_mirror(self):
        request = self.facts["receipt_request"]
        # Remove this fixture's receipt as archive deployer, then race workers
        # through the missing-object path instead of only checking an existing key.
        s3 = self.admin("s3", "archive")
        key = f"decisions/{request['request_id']}.json"
        existing = s3.list_object_versions(Bucket=self.manifest["audit_bucket"], Prefix=key)
        for version in existing.get("Versions", []):
            if version["Key"] == key:
                s3.delete_object(Bucket=self.manifest["audit_bucket"], Key=key, VersionId=version["VersionId"])
        lam = self.admin("lambda", "access")
        def reconcile(_):
            result = lam.invoke(FunctionName=self.manifest["functions"]["witness"],
                                Payload=b'{"source":"frostpass","operation":"reconcile"}')
            assert "FunctionError" not in result, result["Payload"].read()
            result["Payload"].read()
        with ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(reconcile, range(4)))
        versions = self.admin("s3", "archive").list_object_versions(Bucket=self.manifest["audit_bucket"], Prefix=key)
        assert sum(v["Key"] == key for v in versions.get("Versions", [])) == 1

    def audit_failure_is_closed(self):
        request, _, _ = self.fixture()
        role = self.broker_role().rsplit("/", 1)[-1]
        iam = self.admin("iam", "access")
        policy = "verifier-deny-" + uuid.uuid4().hex[:12]
        arn = f"arn:aws:dynamodb:us-east-1:222222222222:table/{self.manifest['tables']['audit']}"
        iam.put_role_policy(RoleName=role, PolicyName=policy, PolicyDocument=json.dumps({
            "Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "dynamodb:PutItem", "Resource": arn}]}))
        try:
            response = self.caller("lambda", "reviewer").invoke(
                FunctionName=self.manifest["functions"]["broker"], Payload=json.dumps(request).encode())
            raw = response["Payload"].read().decode()
            assert '"permit_id"' not in raw and '"released"' not in raw, raw
            assert self.ledger_item(request) is None
        finally:
            iam.delete_role_policy(RoleName=role, PolicyName=policy)
        assert self.invoke("reviewer", "broker", request)["status"] == "released"

    def run(self):
        try:
            self.create_decoys()
            deployed = self.run_script("deploy")
            self.script_ok(deployed, "initial deployment")
            runner("POST", "/snapshot-state")
            for name, points, method in CHECKS:
                self.score(name, points, getattr(self, method))
        except Exception as error:
            self.results.append({"name": "deployment/harness failure", "points": 0, "earned": 0,
                                 "error": f"{type(error).__name__}: {error}"[:1000]})
        finally:
            self.remove_decoys()
            self.write_report()

    def write_report(self):
        REPORT_DIR.mkdir(parents=True, exist_ok=True)
        raw = sum(item["earned"] for item in self.results)
        passed = {item["name"] for item in self.results if item["earned"] == item["points"] and item["earned"] > 0}
        cap, gates = 100, []
        if "approved version release" not in passed:
            cap = min(cap, 40)
            gates.append("no successful version-pinned release")
        if not {"caller isolation", "direct storage denial"} <= passed:
            cap = min(cap, 50)
            gates.append("identity boundary failed")
        if "ledger failure closes release" not in passed:
            cap = min(cap, 50)
            gates.append("release persistence boundary failed")
        score = min(raw, cap)
        report = {"score": score, "raw_score": raw, "cap": cap, "gates": gates, "tests": self.results}
        (REPORT_DIR / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        (REPORT_DIR / "reward.json").write_text(json.dumps({"score": score, "reward": score / 100}) + "\n")
        (REPORT_DIR / "reward.txt").write_text(f"{score / 100:.2f}\n")
        print(f"FrostPass score: {score}/100")


if __name__ == "__main__":
    Verification().run()
