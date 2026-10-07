"""Offline workload and author-harness checks; AWS/encryption integration is in verify.py.

Uses stdlib shims for SDK imports and a lock-protected conditional-write fake.
Mutant cases must be rejected by the same assertions that accept the real code.
"""
import ast
from concurrent.futures import ThreadPoolExecutor
import copy
import hashlib
import io
import importlib.util
import json
import os
from pathlib import Path
import sys
import threading
import tempfile
import types
import unittest
from unittest.mock import patch
from contextlib import redirect_stdout

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True


class ClientError(Exception):
    def __init__(self, response, operation="PutItem"):
        self.response = response
        super().__init__(response["Error"]["Code"])


def error(code, status=400):
    return ClientError({"Error": {"Code": code}, "ResponseMetadata": {"HTTPStatusCode": status}})


def load_gate(mutation=None):
    source = (ROOT / "environment/application/broker.py").read_text()
    if mutation:
        before, after = mutation
        assert before in source
        source = source.replace(before, after)
    exceptions = types.ModuleType("botocore.exceptions")
    exceptions.ClientError = ClientError
    config = types.ModuleType("botocore.config")
    config.Config = lambda **kw: kw
    crypto_exc = types.ModuleType("cryptography.exceptions")
    crypto_exc.InvalidTag = type("InvalidTag", (Exception,), {})
    crypto_aead = types.ModuleType("cryptography.hazmat.primitives.ciphers.aead")
    crypto_aead.AESGCM = object  # retrieval is explicitly replaced below
    spec = importlib.util.spec_from_file_location("common", ROOT / "environment/application/common.py")
    common = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(common)
    shims = {"common": common, "boto3": types.ModuleType("boto3"),
             "botocore.exceptions": exceptions, "botocore.config": config,
             "cryptography.exceptions": crypto_exc,
             "cryptography.hazmat.primitives.ciphers.aead": crypto_aead}
    module = types.ModuleType("gate_under_test")
    with patch.dict(sys.modules, shims):
        exec(compile(source, "broker.py", "exec"), module.__dict__)
    return module


def typed(values):
    return {key: {"N" if type(value) is int else "S": str(value)} for key, value in values.items()}


class FakeDB:
    def __init__(self, grant):
        self.grant = typed(grant)
        self.rows = {}
        self.lock = threading.Lock()
        self.writes = 0
        self.deny = False

    def get_item(self, TableName, Key, ConsistentRead):
        assert ConsistentRead is True
        with self.lock:
            item = self.grant if TableName == "grants" else self.rows.get(Key["audit_id"]["S"])
            return {"Item": copy.deepcopy(item)} if item else {}

    def put_item(self, TableName, Item, ConditionExpression=None):
        assert TableName == "audit"
        if self.deny:
            raise error("AccessDeniedException", 403)
        key = Item["audit_id"]["S"]
        with self.lock:
            if ConditionExpression == "attribute_not_exists(audit_id)" and key in self.rows:
                raise error("ConditionalCheckFailedException")
            self.rows[key] = copy.deepcopy(Item)
            self.writes += 1


def setup(samples=(2000, 5000, 8000), mutation=None, report=None):
    gate = load_gate(mutation)
    request = {"operation": "evaluate", "request_id": "request-a", "grant_id": "grant-a",
               "shipment_id": "shipment-a", "sensor_id": "sensor-a", "version_id": "version-a"}
    if report is None:
        report = {"shipment_id": "shipment-a", "sensor_id": "sensor-a", "samples_mc": list(samples)}
    content = report if isinstance(report, bytes) else json.dumps(report).encode()
    digest = hashlib.sha256(content).hexdigest()
    db = FakeDB({"grant_id": "grant-a", "shipment_id": "shipment-a", "sensor_id": "sensor-a",
                 "version_id": "version-a", "expires_at": 4000000000, "state": "approved",
                 "expected_sha256": digest})
    gate.aws_client = lambda service: db
    gate._read_report = lambda grant: (content, digest, digest)
    return gate, request, db


class QualityChecks(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(os.environ, {"AUDIT_TABLE": "audit", "GRANTS_TABLE": "grants"})
        self.env.start()
        self.addCleanup(self.env.stop)

    def test_all_python_and_scoring(self):
        for path in ROOT.rglob("*.py"):
            if not any(part.startswith('.') for part in path.relative_to(ROOT).parts):
                compile(path.read_text(), str(path), "exec")
        tree = ast.parse((ROOT / "tests/verify.py").read_text())
        checks = ast.literal_eval(next(n.value for n in tree.body if isinstance(n, ast.Assign) and n.targets[0].id == "CHECKS"))
        self.assertEqual(len(checks), 35)
        self.assertEqual(sum(points for _, points, _ in checks), 100)
        self.assertEqual(len({name for name, _, _ in checks}), 35)

    def test_independent_copies_match(self):
        for path in (ROOT / "environment/application").iterdir():
            if not path.is_file():
                continue
            self.assertEqual(path.read_bytes(), (ROOT / "tests/application" / path.name).read_bytes(), path.name)
        for path in (ROOT / "environment/workspace/contracts").iterdir():
            self.assertEqual(path.read_bytes(), (ROOT / "tests/contracts" / path.name).read_bytes(), path.name)
        self.assertEqual((ROOT / "environment/bootstrap.py").read_bytes(), (ROOT / "tests/bootstrap.py").read_bytes())

    def test_safe_boundaries(self):
        for samples in ([2000], [8000], [2000, 8000], [5000] * 64):
            gate, req, db = setup(samples)
            result = gate.handler(req, None)
            self.assertEqual(result["status"], "released")
            self.assertEqual((result["min_mc"], result["max_mc"], result["sample_count"]),
                             (min(samples), max(samples), len(samples)))
            self.assertEqual(db.writes, 1)

    def test_partial_key_state_recovery(self):
        tree = ast.parse((ROOT / "solution/adopt.py").read_text())
        selected = ast.Module(body=[node for node in tree.body if isinstance(node, ast.FunctionDef)
                                   and node.name in {"state_resources", "state_ids", "stale"}], type_ignores=[])
        names = {"Path": Path, "json": json, "CALLERS": {name: "access" for name in
                 ("custodian", "approver", "reviewer", "outsider")},
                 "manifest_key_ids": lambda: set(), "client": lambda *args: None,
                 "live_mappings": lambda *args: []}
        exec(compile(selected, "adopt.py", "exec"), names)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'partial.json'
            for recorded in ([], ["approver"], ["reviewer", "outsider"], list(names["CALLERS"])):
                path.write_text(json.dumps({"resources": [{"mode": "managed", "type": "aws_iam_access_key",
                    "name": actor, "instances": [{"attributes": {"id": actor + "-key"}}]} for actor in recorded]}))
                output = io.StringIO()
                with redirect_stdout(output):
                    names["stale"](str(path))
                self.assertEqual(set(output.getvalue().splitlines()),
                                 {f"aws_iam_access_key.{actor}" for actor in recorded})

    def assert_excursion(self, mutation=None):
        gate, req, _ = setup([5000] * 63 + [8001], mutation)
        self.assertEqual(gate.handler(req, None), {"status": "denied", "reason": "temperature-excursion"})

    def test_excursion_every_position(self):
        for samples in ([1999, 5000], [5000, 8001, 5000], [5000] * 63 + [8001]):
            gate, req, _ = setup(samples)
            self.assertEqual(gate.handler(req, None)["reason"], "temperature-excursion")

    def test_malformed(self):
        reports = [b'null', b'[]', b'invalid', b'\xff']
        for samples in ([True], [False], [2000.0], [None], [], [5000] * 65):
            reports.append({"shipment_id": "shipment-a", "sensor_id": "sensor-a", "samples_mc": samples})
        for report in reports:
            gate, req, _ = setup(report=report)
            self.assertEqual(gate.handler(req, None)["reason"], "invalid-report")

    def assert_integrity(self, mutation=None):
        gate, req, db = setup(mutation=mutation)
        db.grant["expected_sha256"] = {"S": "0" * 64}
        self.assertEqual(gate.handler(req, None)["reason"], "integrity-failure")

    def test_reviewed_digest(self):
        self.assert_integrity()

    def test_replay_conflict_and_history(self):
        gate, req, db = setup()
        first = gate.handler(req, None)
        snapshot = copy.deepcopy(db.rows)
        db.grant["state"] = {"S": "revoked"}
        self.assertEqual(gate.handler(req, None), first)
        self.assertEqual(gate.handler({**req, "sensor_id": "other"}, None)["reason"], "request-conflict")
        self.assertEqual(db.rows, snapshot)
        self.assertEqual(gate.handler({**req, "request_id": "new"}, None)["reason"], "inactive-grant")

    def assert_race(self, mutation=None):
        gate, req, db = setup(mutation=mutation)
        original_read = gate._read_report
        barrier = threading.Barrier(8)
        def read(grant):
            barrier.wait(timeout=10)
            return original_read(grant)
        gate._read_report = read
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: gate.handler(req, None), range(8)))
        self.assertTrue(all(result == results[0] for result in results))
        self.assertEqual(db.writes, 1)

    def test_conditional_race(self):
        self.assert_race()

    def assert_closed(self, mutation=None):
        gate, req, db = setup(mutation=mutation)
        db.deny = True
        with self.assertRaises(ClientError):
            gate.handler(req, None)
        self.assertEqual(db.rows, {})

    def test_fail_closed(self):
        self.assert_closed()

    def test_reject_average_only_mutant(self):
        mutation = ('any(sample < 2000 or sample > 8000 for sample in samples)',
                    'not 2000 <= sum(samples) / len(samples) <= 8000')
        with self.assertRaises(AssertionError):
            self.assert_excursion(mutation)

    def test_reject_latest_sample_only_mutant(self):
        mutation = ('any(sample < 2000 or sample > 8000 for sample in samples)',
                    'samples[-1] < 2000 or samples[-1] > 8000')
        gate, req, _ = setup([5000, 9000, 5000], mutation)
        with self.assertRaises(AssertionError):
            self.assertEqual(gate.handler(req, None)["status"], "denied")

    def test_reject_unpinned_digest_mutant(self):
        with self.assertRaises((AssertionError, KeyError)):
            self.assert_integrity(('digest != stored_digest or digest != grant["expected_sha256"]', 'digest != stored_digest'))

    def test_reject_unconditional_ledger_mutant(self):
        with self.assertRaises(AssertionError):
            self.assert_race(('ConditionExpression="attribute_not_exists(audit_id)"', 'ConditionExpression=None'))

    def test_reject_fail_open_mutant(self):
        with self.assertRaises(AssertionError):
            self.assert_closed(('            raise\n', '            return response\n'))

    def test_invalid_gate_request_no_side_effect(self):
        gate, req, db = setup()
        for change in ({"extra": True}, {"request_id": "../escape"}, {"operation": "get"}):
            with self.assertRaises(ValueError):
                gate.handler({**req, **change}, None)
        self.assertEqual(db.rows, {})


if __name__ == "__main__":
    unittest.main(verbosity=2)
