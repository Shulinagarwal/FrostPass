"""Black-box FrostPass verifier. No reference Terraform labels are used."""

import base64
import hashlib
from collections import Counter
from fnmatch import fnmatchcase
import json
import os
from pathlib import Path
import threading
import time
import traceback
import urllib.parse
import urllib.request
import uuid

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
from jsonschema import Draft202012Validator


RUNNER = os.environ.get("FROSTPASS_RUNNER", "http://runner:8088")
CONFIG = Path("/workspace/config/bootstrap.json")
SCHEMA = Path("/contracts/manifest.schema.json")
REPORT_DIR = Path("/logs/verifier")
# The verifier deliberately deploys with a prefix other than the agent's
# default, then redeploys from scratch under a minimum-length prefix.
PREFIX = os.environ.get("FROSTPASS_PREFIX", "frostpass")
FRESH_PREFIX = "srb" if PREFIX != "srb" else "src"
THIRD_PREFIX = "src" if FRESH_PREFIX != "src" else "srd"
ARCHIVE, ACCESS = "111111111111", "222222222222"
# Recovery objective for deploy.sh after lost, corrupted or restored state.
RECOVERY_SECONDS = 90


def runner(method, path, timeout=30):
    request = urllib.request.Request(RUNNER + path, method=method, data=b"" if method == "POST" else None)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.load(response)


def _as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _document(value):
    if isinstance(value, str):
        value = json.loads(urllib.parse.unquote(value))
    return value or {}


def _statements(documents):
    for document in documents:
        yield from _as_list(_document(document).get("Statement"))


def _matches(patterns, value, case_sensitive=True):
    if not case_sensitive:
        value = value.lower()
    return any(
        fnmatchcase(value, pattern if case_sensitive else pattern.lower())
        for pattern in _as_list(patterns)
    )


def _statement_covers(statement, action, resource):
    if "Action" in statement:
        action_hit = _matches(statement["Action"], action, case_sensitive=False)
    else:
        action_hit = not _matches(statement.get("NotAction"), action, case_sensitive=False)
    if "Resource" in statement:
        resource_hit = _matches(statement["Resource"], resource)
    elif "NotResource" in statement:
        resource_hit = not _matches(statement["NotResource"], resource)
    else:
        resource_hit = True
    return action_hit and resource_hit


def policy_allows(documents, action, resource):
    """Conservative identity-policy check: Allow conditions are treated as satisfied."""
    statements = list(_statements(documents))
    if any(item.get("Effect") == "Deny" and not item.get("Condition")
           and _statement_covers(item, action, resource) for item in statements):
        return False
    return any(item.get("Effect") == "Allow" and _statement_covers(item, action, resource)
               for item in statements)


def _principals(statement):
    if "NotPrincipal" in statement:
        return ["*"]
    principal = statement.get("Principal")
    if principal == "*":
        return ["*"]
    if isinstance(principal, dict):
        return list(_as_list(principal.get("AWS")))
    return []


def allowed_principals(document, action, resource):
    """AWS principals that an Allow statement in a resource policy admits."""
    principals = set()
    for statement in _statements([document]):
        if statement.get("Effect") == "Allow" and _statement_covers(statement, action, resource):
            principals.update(_principals(statement))
    return principals


_NEGATED_ARN_OPERATORS = {
    "arnnotequals": False, "stringnotequals": False,
    "arnnotlike": True, "stringnotlike": True,
}


def _deny_applies_to(statement, principal_arn):
    """Whether a Deny statement's principal scope covers principal_arn.

    Supports the contract's two exemption forms: NotPrincipal, and Principal
    "*" narrowed by a negated condition on aws:PrincipalArn. Any other
    condition makes the statement count as not applying.
    """
    if "NotPrincipal" in statement:
        exempt = _as_list((statement["NotPrincipal"] or {}).get("AWS"))
        scoped = principal_arn not in exempt
    else:
        principal = statement.get("Principal")
        listed = ["*"] if principal == "*" else _as_list((principal or {}).get("AWS"))
        scoped = "*" in listed or principal_arn in listed
    if not scoped:
        return False
    condition = statement.get("Condition")
    if not condition:
        return True
    for operator, values in condition.items():
        like = _NEGATED_ARN_OPERATORS.get(operator.lower())
        if like is None or not isinstance(values, dict):
            return False
        for key, patterns in values.items():
            if key.lower() != "aws:principalarn":
                return False
            patterns = _as_list(patterns)
            matched = any(
                fnmatchcase(principal_arn, pattern) if like else principal_arn == pattern
                for pattern in patterns
            )
            if matched:
                return False
    return True


def policy_denies(document, action, resource, principal_arn):
    """True if the resource policy explicitly denies principal_arn this request."""
    return any(
        statement.get("Effect") == "Deny"
        and _statement_covers(statement, action, resource)
        and _deny_applies_to(statement, principal_arn)
        for statement in _statements([document])
    )


# --- AWS policy evaluation with conditions -----------------------------------
# Used where Floci does not enforce a rule. Supported operators are listed in
# runtime.md; an unsupported operator makes its statement not apply.

_POSITIVE_OPERATORS = {
    "stringequals", "stringequalsignorecase", "stringlike", "arnequals", "arnlike", "bool",
}
_NEGATED_OPERATORS = {
    "stringnotequals": "stringequals", "stringnotequalsignorecase": "stringequalsignorecase",
    "stringnotlike": "stringlike", "arnnotequals": "arnequals", "arnnotlike": "arnlike",
}


def _match_one(base, value, patterns):
    value = str(value)
    if base in ("stringequals", "bool"):
        return any(value.lower() == str(p).lower() if base == "bool" else value == str(p) for p in patterns)
    if base == "stringequalsignorecase":
        return any(value.lower() == str(p).lower() for p in patterns)
    return any(fnmatchcase(value, str(p)) for p in patterns)  # *Like and Arn* operators


def _operator_holds(operator, key, patterns, context):
    """Evaluate one operator/key pair; None when the operator is unsupported."""
    name = operator.lower()
    qualifier = None
    for prefix in ("forallvalues:", "foranyvalue:"):
        if name.startswith(prefix):
            qualifier, name = prefix[:-1], name[len(prefix):]
    if_exists = name.endswith("ifexists")
    if if_exists:
        name = name[: -len("ifexists")]
    patterns = _as_list(patterns)
    request = context.get(key.lower())
    present = request is not None and request != []
    if name == "null":
        want_absent = str(patterns[0]).lower() == "true"
        return (not present) if want_absent else present
    negated = name in _NEGATED_OPERATORS
    base = _NEGATED_OPERATORS.get(name, name)
    if base not in _POSITIVE_OPERATORS:
        return None
    if not present:
        if if_exists or qualifier == "forallvalues":
            return True
        if qualifier == "foranyvalue":
            return False
        return negated  # AWS: a negated operator on a missing key is true
    values = request if isinstance(request, list) else [request]

    def single(value):
        hit = _match_one(base, value, patterns)
        return not hit if negated else hit

    if qualifier == "forallvalues":
        return all(single(v) for v in values)
    return any(single(v) for v in values)


def _conditions_hold(statement, context):
    for operator, entries in (statement.get("Condition") or {}).items():
        if not isinstance(entries, dict):
            return False
        for key, patterns in entries.items():
            if not _operator_holds(operator, key, patterns, context):
                return False
    return True


def _principal_match(statement, principal):
    """Return 'direct', 'account' (account delegation) or None for a statement."""
    kind, identity, account = principal
    if "NotPrincipal" in statement:
        listed = _as_list((statement["NotPrincipal"] or {}).get("AWS" if kind == "AWS" else "Service"))
        return None if identity in listed else "direct"
    value = statement.get("Principal")
    if value == "*":
        return "direct"
    listed = _as_list((value or {}).get("AWS" if kind == "AWS" else "Service"))
    if "*" in listed or identity in listed:
        return "direct"
    if kind == "AWS" and (f"arn:aws:iam::{account}:root" in listed or account in listed):
        return "account"
    return None


def resource_policy_decision(document, principal, action, resource, context):
    """Deny/direct-allow/account-delegation flags of a resource policy for one request."""
    decision = {"deny": False, "direct": False, "account": False}
    for statement in _statements([document]):
        if not _statement_covers(statement, action, resource):
            continue
        match = _principal_match(statement, principal)
        if match is None or not _conditions_hold(statement, context):
            continue
        if statement.get("Effect") == "Deny":
            decision["deny"] = True
        elif statement.get("Effect") == "Allow":
            decision[match] = True
    return decision


# Condition keys a caller cannot choose: who it is, and the service context a
# direct call does not carry. Every other key (encryption context, transport,
# request parameters) is one a caller can satisfy when it wants access.
_CALLER_FIXED_KEYS = {
    "aws:userid", "aws:username", "kms:calleraccount", "aws:sourceaccount", "aws:sourcearn",
    "aws:sourceowner", "aws:viaawsservice", "kms:viaservice",
}


def _caller_fixed(key):
    key = key.lower()
    return key in _CALLER_FIXED_KEYS or key.startswith(("aws:principal", "aws:calledvia"))


def _applies_to_caller(statement, context):
    """Whether a statement reaches a caller that shapes its request to get access:
    identity conditions are evaluated, request conditions are met for an Allow and
    avoided for a Deny. An unsupported operator makes the statement not apply."""
    deny = statement.get("Effect") == "Deny"
    for operator, entries in (statement.get("Condition") or {}).items():
        if not isinstance(entries, dict):
            return False
        for key, patterns in entries.items():
            if _operator_holds(operator, key, patterns, {}) is None:
                return False
            if _caller_fixed(key):
                if not _operator_holds(operator, key, patterns, context):
                    return False
            elif deny:
                return False
    return True


def resource_policy_grants(document, identity, principal_arn, action, resource, owner):
    """Whether a resource policy itself grants a principal the request, after its
    conditions and explicit denies. Delegation to the owner's account is left to IAM."""
    account = principal_arn.split(":")[4]
    context = {"aws:principalarn": principal_arn, "aws:principalaccount": account,
               "kms:calleraccount": account}
    granted = False
    for statement in _statements([document]):
        if not _statement_covers(statement, action, resource):
            continue
        match = _principal_match(statement, ("AWS", identity, account))
        if match is None or not _applies_to_caller(statement, context):
            continue
        if statement.get("Effect") == "Deny":
            return False
        if statement.get("Effect") == "Allow" and (match == "direct" or account != owner):
            granted = True
    return granted


def identity_decision(documents, action, resource, context):
    """'deny', 'allow' or None for identity policies, with conditions evaluated."""
    result = None
    for statement in _statements(documents):
        if not _statement_covers(statement, action, resource) or not _conditions_hold(statement, context):
            continue
        if statement.get("Effect") == "Deny":
            return "deny"
        if statement.get("Effect") == "Allow":
            result = "allow"
    return result


def kms_request_allowed(key_policy, identity_documents, principal, action, key_arn, context):
    """AWS KMS authorization: the key policy must allow directly, or delegate to the
    principal's own account whose IAM policy allows; any explicit Deny wins."""
    key_account = key_arn.split(":")[4]
    kp = resource_policy_decision(key_policy, principal, action, key_arn, context)
    ident = identity_decision(identity_documents, action, key_arn, context)
    if kp["deny"] or ident == "deny":
        return False
    if principal[2] == key_account:
        return kp["direct"] or (kp["account"] and ident == "allow")
    return (kp["direct"] or kp["account"]) and ident == "allow"


def kms_context(principal, encryption_context):
    context = {"aws:principalarn": principal[1], "aws:principalaccount": principal[2]}
    if encryption_context is not None:
        context["kms:encryptioncontextkeys"] = sorted(encryption_context)
        for key, value in encryption_context.items():
            context[f"kms:encryptioncontext:{key}".lower()] = value
    return context


class InfrastructureChecks:
    def __init__(self):
        self.bootstrap = json.loads(CONFIG.read_text())
        self.manifest = None
        self.facts = {}
        self.results = []
        self.script_runs = []
        self.decoys = None

    def run_script(self, name, prefix=None):
        prefix = prefix or PREFIX
        path = f"/{name}" + (f"?prefix={prefix}" if prefix else "")
        result = runner("POST", path, timeout=920)
        self.script_runs.append({"script": name, "prefix": prefix or PREFIX, **result})
        return result

    def refresh_manifest(self):
        """Reload the manifest after a deploy, even a failed or slow one, so later
        checks use the current caller credentials instead of rotated-out keys."""
        try:
            self.reload_manifest()
        except Exception:
            pass

    def reload_manifest(self):
        self.manifest = runner("GET", "/manifest")
        Draft202012Validator(json.loads(SCHEMA.read_text())).validate(self.manifest)
        return self.manifest

    def caller_user(self, actor):
        """(account, user name) behind a manifest caller, via its own credentials."""
        cache = self.facts.setdefault("caller_users", {})
        if actor not in cache:
            arn = self.caller("sts", actor).get_caller_identity()["Arn"]
            cache[actor] = (arn.split(":")[4], arn.rsplit("/", 1)[-1])
        return cache[actor]

    def user_documents(self, account, user_name):
        iam = self.admin("iam", "archive" if account == ARCHIVE else "access")
        documents = [
            iam.get_user_policy(UserName=user_name, PolicyName=name)["PolicyDocument"]
            for name in iam.list_user_policies(UserName=user_name)["PolicyNames"]
        ]
        attached = list(iam.list_attached_user_policies(UserName=user_name)["AttachedPolicies"])
        try:
            groups = iam.list_groups_for_user(UserName=user_name)["Groups"]
        except ClientError:
            groups = []
        for group in groups:
            documents += [
                iam.get_group_policy(GroupName=group["GroupName"], PolicyName=name)["PolicyDocument"]
                for name in iam.list_group_policies(GroupName=group["GroupName"])["PolicyNames"]
            ]
            attached += iam.list_attached_group_policies(GroupName=group["GroupName"])["AttachedPolicies"]
        for policy_ref in attached:
            policy = iam.get_policy(PolicyArn=policy_ref["PolicyArn"])["Policy"]
            documents.append(iam.get_policy_version(
                PolicyArn=policy_ref["PolicyArn"], VersionId=policy["DefaultVersionId"]
            )["PolicyVersion"]["Document"])
        return documents

    @staticmethod
    def gone(action, codes=("NoSuchEntity", "NoSuchBucket", "ResourceNotFoundException", "NotFound", "404")):
        """True when the lookup reports that the resource no longer exists."""
        try:
            action()
        except ClientError as error:
            code = str(error.response.get("Error", {}).get("Code"))
            return code in codes or error.response["ResponseMetadata"]["HTTPStatusCode"] == 404
        return False

    def create_decoys(self):
        """Pre-existing resources sharing the prefix that deploy/destroy must not touch."""
        name = f"{PREFIX}-preexisting-{uuid.uuid4().hex[:6]}"
        s3 = self.admin("s3", "archive")
        s3.create_bucket(Bucket=name)
        s3.put_object(Bucket=name, Key="keep.txt", Body=b"pre-existing")
        db = self.admin("dynamodb", "access")
        db.create_table(
            TableName=name, BillingMode="PAY_PER_REQUEST",
            AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
            KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
        )
        self.admin("iam", "access").create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                           "Action": "sts:AssumeRole"}],
        }))
        self.admin("iam", "archive").create_user(UserName=name)
        self.decoys = name

    def decoys_intact(self):
        name = self.decoys
        body = self.admin("s3", "archive").get_object(Bucket=name, Key="keep.txt")["Body"].read()
        assert body == b"pre-existing", "pre-existing bucket content changed"
        self.admin("dynamodb", "access").describe_table(TableName=name)
        self.admin("iam", "access").get_role(RoleName=name)
        self.admin("iam", "archive").get_user(UserName=name)
        self.admin("iam", "archive").get_user(UserName="frostpass-archive-admin")
        self.admin("iam", "access").get_user(UserName="frostpass-access-admin")

    def remove_decoys(self):
        name = self.decoys
        if not name:
            return
        s3 = self.admin("s3", "archive")
        for action in (
            lambda: s3.delete_object(Bucket=name, Key="keep.txt"),
            lambda: s3.delete_bucket(Bucket=name),
            lambda: self.admin("dynamodb", "access").delete_table(TableName=name),
            lambda: self.admin("iam", "access").delete_role(RoleName=name),
            lambda: self.admin("iam", "archive").delete_user(UserName=name),
        ):
            try:
                action()
            except ClientError:
                pass

    def evidence_read_probe_denied(self, account, bucket, key, version):
        """A principal whose identity policy allows S3 reads must not read evidence.

        The live request is tried first. Floci neither requires a bucket-policy
        Allow for cross-account reads nor evaluates conditions in bucket-policy
        Deny statements, so a read it lets through is re-judged by evaluating
        the deployed bucket policy with AWS semantics.
        """
        name, probe_key = self.temporary_user(account, {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow", "Action": ["s3:GetObject", "s3:GetObjectVersion"],
                "Resource": f"arn:aws:s3:::{bucket}/reports/*",
            }],
        })
        label = f"{account}-account principal"
        try:
            try:
                self.denied(lambda: self._client("s3", probe_key).get_object(
                    Bucket=bucket, Key=key, VersionId=version
                ))
                return
            except AssertionError:
                pass
            account_id = ARCHIVE if account == "archive" else ACCESS
            principal = f"arn:aws:iam::{account_id}:user/{name}"
            try:
                policy = self.admin("s3", "archive").get_bucket_policy(Bucket=bucket)["Policy"]
            except ClientError:
                policy = json.dumps({"Statement": []})
            resource = f"arn:aws:s3:::{bucket}/{key}"
            for action in ("s3:GetObject", "s3:GetObjectVersion"):
                if policy_denies(policy, action, resource, principal):
                    continue
                if account_id != ARCHIVE:
                    admitted = allowed_principals(policy, action, resource)
                    if not admitted & {"*", principal, f"arn:aws:iam::{account_id}:root", account_id}:
                        continue  # cross-account reads need a bucket-policy Allow
                raise AssertionError(f"{label} with an S3-read identity policy can {action} evidence")
        finally:
            self.remove_temporary_user(account, name, probe_key)

    def archive_read_probe_denied(self, bucket, key, version):
        """An archive-account principal with S3 read in its identity policy must be refused."""
        self.evidence_read_probe_denied("archive", bucket, key, version)

    def assume_probe_denied(self, reader_arn):
        """An access-account principal allowed sts:AssumeRole must be refused by the reader trust."""
        name, key = self.temporary_user("access", {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "*"}],
        })
        try:
            try:
                self.denied(lambda: self._client("sts", key).assume_role(
                    RoleArn=reader_arn, RoleSessionName="intruder"
                ))
            except AssertionError as error:
                raise AssertionError(f"reader trust admits other access-account principals: {error}") from error
        finally:
            self.remove_temporary_user("access", name, key)

    def stream_mappings(self, stream_arn):
        """Event source mappings on one stream, filtered here: Floci returns every
        mapping regardless of the EventSourceArn/FunctionName filters."""
        lam = self.admin("lambda", "access")
        found, marker = [], None
        while True:
            page = lam.list_event_source_mappings(**({"Marker": marker} if marker else {}))
            found += [m for m in page.get("EventSourceMappings", []) if m.get("EventSourceArn") == stream_arn]
            marker = page.get("NextMarker")
            if not marker:
                return found

    def copy_exists(self, audit_id):
        """Whether decisions/<audit_id>.json is present, judged by listing versions.

        Listing needs no read access to the copy, so a policy that lets only
        Witness read decisions/ is still verifiable with the deployer identity.
        """
        key = f"decisions/{audit_id}.json"
        listing = self.admin("s3", "archive").list_object_versions(
            Bucket=self.manifest["audit_bucket"], Prefix=key
        )
        present = any(v["Key"] == key for v in listing.get("Versions", []))
        hidden = any(d["Key"] == key and d.get("IsLatest") for d in listing.get("DeleteMarkers", []))
        return present and not hidden

    def approved_request(self):
        f = self.facts
        grant = self.invoke("approver", "grants", {
            "operation": "create", "shipment_id": f["shipment_id"], "sensor_id": f["sensor_id"],
            "version_id": f["versions"][0], "expires_at": int(time.time()) + 900,
        })
        self.invoke("approver", "grants", {"operation": "approve", "grant_id": grant["grant_id"]})
        return {**f["request"], "grant_id": grant["grant_id"]}

    def delivers_first_version(self, request):
        result = self.invoke("reviewer", "broker", request)
        assert result.get("status") == "released", f"broker did not deliver: {result}"
        assert result["sha256"] == hashlib.sha256(self.facts["first"]).hexdigest()

    def admin(self, service, account):
        key = self.bootstrap[account]
        return self._client(service, key)

    def caller(self, service, actor):
        return self._client(service, self.manifest["callers"][actor])

    def _client(self, service, key):
        options = {
            "endpoint_url": "http://aws:4566",
            "region_name": "us-east-1",
            "aws_access_key_id": key["access_key_id"],
            "aws_secret_access_key": key["secret_access_key"],
        }
        if service == "s3":
            options["config"] = Config(s3={"addressing_style": "path"})
        return boto3.client(service, **options)

    def invoke(self, actor, service, event):
        response = self.caller("lambda", actor).invoke(
            FunctionName=self.manifest["functions"][service],
            InvocationType="RequestResponse",
            Payload=json.dumps(event).encode(),
        )
        body = json.loads(response["Payload"].read())
        if "FunctionError" in response:
            raise AssertionError(f"{service} Lambda error: {body.get('errorMessage', body)}")
        return body

    def broker_role(self):
        return self.admin("lambda", "access").get_function(
            FunctionName=self.manifest["functions"]["broker"]
        )["Configuration"]["Role"]

    def archive_reader(self):
        role_name = self.manifest["archive_reader_role"].rsplit("/", 1)[-1]
        return self.admin("iam", "archive").get_role(RoleName=role_name)["Role"]

    def role_documents(self, account, role_arn):
        iam = self.admin("iam", account)
        role_name = role_arn.rsplit("/", 1)[-1]
        documents = [
            iam.get_role_policy(RoleName=role_name, PolicyName=name)["PolicyDocument"]
            for name in iam.list_role_policies(RoleName=role_name)["PolicyNames"]
        ]
        for attached in iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]:
            policy = iam.get_policy(PolicyArn=attached["PolicyArn"])["Policy"]
            documents.append(iam.get_policy_version(
                PolicyArn=attached["PolicyArn"], VersionId=policy["DefaultVersionId"]
            )["PolicyVersion"]["Document"])
        return documents

    def temporary_user(self, account, policy):
        """Create a probe IAM user with one inline policy; returns (name, key)."""
        iam = self.admin("iam", account)
        name = f"probe-{uuid.uuid4().hex[:10]}"
        iam.create_user(UserName=name)
        iam.put_user_policy(UserName=name, PolicyName="probe", PolicyDocument=json.dumps(policy))
        key = iam.create_access_key(UserName=name)["AccessKey"]
        return name, {"access_key_id": key["AccessKeyId"], "secret_access_key": key["SecretAccessKey"]}

    def remove_temporary_user(self, account, name, key):
        iam = self.admin("iam", account)
        for action in (
            lambda: iam.delete_access_key(UserName=name, AccessKeyId=key["access_key_id"]),
            lambda: iam.delete_user_policy(UserName=name, PolicyName="probe"),
            lambda: iam.delete_user(UserName=name),
        ):
            try:
                action()
            except ClientError:
                pass

    @staticmethod
    def script_ok(result, what):
        """Fail with a message naming the step, its exit code and its output."""
        assert result["exit_code"] == 0, (
            f"{what} failed (exit {result['exit_code']}): {result.get('output_tail') or '(no output)'}")

    @staticmethod
    def denied(action):
        try:
            action()
        except ClientError as error:
            assert error.response["ResponseMetadata"]["HTTPStatusCode"] == 403
            return
        raise AssertionError("the cloud request was unexpectedly allowed")

    def score(self, name, points, check):
        try:
            check()
            self.results.append({"name": name, "points": points, "earned": points})
            print(f"PASS {name}: {points}/{points}")
        except Exception as error:
            frames = traceback.extract_tb(error.__traceback__)
            source = next((frame for frame in reversed(frames) if Path(frame.filename).name in ("verify.py", "infrastructure_checks.py")), None)
            location = f"{Path(source.filename).name}:{source.lineno}" if source else "unknown"
            message = str(error)
            self.results.append({
                "name": name, "points": points, "earned": 0,
                # Keep the start and the end: script failures put the cause last.
                "error": f"{type(error).__name__}: {message if len(message) <= 1200 else message[:300] + ' ... ' + message[-900:]}",
                "location": location,
            })
            print(f"FAIL {name} at {location}: {type(error).__name__}: {str(error)[:160]}")

    def contract_and_state(self):
        self.manifest = runner("GET", "/manifest")
        schema = json.loads(SCHEMA.read_text())
        Draft202012Validator(schema).validate(self.manifest)
        source = Path("/runner/source/submission")
        assert (source / "deploy.sh").is_file()
        assert (source / "destroy.sh").is_file()
        assert list(source.rglob("*.tf")) or list(source.rglob("*.tofu"))
        states = runner("GET", "/state-summary")["states"]
        types = Counter(item for state in states for item in state["types"])
        assert sum(types.values()) >= 6, "cloud resources are not in Terraform/OpenTofu state"
        declared = {value for state in states for value in state.get("identifiers", [])}
        m = self.manifest
        schedule = m["reconciliation_schedule"]
        expected = [
            *m["functions"].values(), m["bucket"], m["audit_bucket"], *m["tables"].values(),
            schedule["name"],
            # The built-in "default" schedule group is not created by the deployment.
            *([schedule["group"]] if schedule["group"] != "default" else []),
            *(caller["access_key_id"] for caller in m["callers"].values()),
        ]
        missing = [value for value in expected if value not in declared]
        reader = m["archive_reader_role"]
        if reader not in declared and reader.rsplit("/", 1)[-1] not in declared:
            missing.append(reader)
        key = self.admin("kms", "archive").describe_key(KeyId=m["evidence_key"])["KeyMetadata"]
        if not {key["Arn"], key["KeyId"]} & declared:
            missing.append(m["evidence_key"])
        assert not missing, f"manifest resources are not in Terraform/OpenTofu state: {missing}"

    def topology(self):
        functions = self.manifest["functions"]
        roles = []
        for name, account, image in (
            ("intake", "111111111111", "frostpass-intake:1"),
            ("grants", "222222222222", "frostpass-grants:1"),
            ("broker", "222222222222", "frostpass-broker:1"),
            ("witness", "222222222222", "frostpass-witness:1"),
        ):
            admin = self.admin("lambda", "archive" if name == "intake" else "access")
            result = admin.get_function(FunctionName=functions[name])
            conf = result["Configuration"]
            assert f":{account}:function:" in conf["FunctionArn"]
            assert conf["PackageType"] == "Image"
            assert result["Code"]["ImageUri"].endswith(image)
            assert conf["Timeout"] >= 15 and conf["MemorySize"] >= 256
            roles.append(conf["Role"])
            variables = conf["Environment"]["Variables"]
            if name in ("intake", "broker"):
                assert variables["EVIDENCE_BUCKET"] == self.manifest["bucket"]
            if name in ("grants", "broker"):
                assert variables["GRANTS_TABLE"] == self.manifest["tables"]["grants"]
            if name == "broker":
                assert variables["AUDIT_TABLE"] == self.manifest["tables"]["audit"]
                reader = self.archive_reader()
                assert variables["ARCHIVE_READER_ROLE"] in (reader["Arn"], reader["RoleName"])
            if name == "intake":
                kms = self.admin("kms", "archive")
                configured_key = kms.describe_key(KeyId=variables["EVIDENCE_KEY_ID"])["KeyMetadata"]["Arn"]
                declared_key = kms.describe_key(KeyId=self.manifest["evidence_key"])["KeyMetadata"]["Arn"]
                assert configured_key == declared_key
            if name == "witness":
                assert variables["AUDIT_BUCKET"] == self.manifest["audit_bucket"]
                assert variables["AUDIT_TABLE"] == self.manifest["tables"]["audit"]
        assert len(set(roles)) == 4, "each service needs its own execution role"

    def storage_and_policy(self):
        archive_s3 = self.admin("s3", "archive")
        bucket = self.manifest["bucket"]
        assert archive_s3.get_bucket_versioning(Bucket=bucket)["Status"] == "Enabled"
        policy = json.loads(archive_s3.get_bucket_policy(Bucket=bucket)["Policy"])
        assert policy.get("Statement"), "evidence bucket policy is empty"
        for table in self.manifest["tables"].values():
            assert self.admin("dynamodb", "access").describe_table(TableName=table)["Table"]["TableStatus"] == "ACTIVE"
        audit_desc = self.admin("dynamodb", "access").describe_table(
            TableName=self.manifest["tables"]["audit"]
        )["Table"]
        assert audit_desc["StreamSpecification"]["StreamEnabled"]
        assert audit_desc["StreamSpecification"]["StreamViewType"] == "NEW_IMAGE"
        mirror = self.manifest["audit_bucket"]
        assert archive_s3.get_bucket_versioning(Bucket=mirror)["Status"] == "Enabled"
        mirror_policy = json.loads(archive_s3.get_bucket_policy(Bucket=mirror)["Policy"])
        assert mirror_policy.get("Statement"), "audit bucket policy is empty"
        for private_bucket in (bucket, mirror):
            blocks = archive_s3.get_public_access_block(Bucket=private_bucket)["PublicAccessBlockConfiguration"]
            assert all(blocks.get(field) is True for field in (
                "BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"))

    def encryption_and_reader_boundary(self):
        f = self.facts
        versions = self.admin("s3", "archive").list_object_versions(
            Bucket=self.manifest["bucket"],
            Prefix=f"reports/{f['shipment_id']}/{f['sensor_id']}",
        )["Versions"]
        first_version = next(v for v in versions if v["VersionId"] == f["versions"][0])
        assert first_version["Size"] == len(f["first"]) + 16, "AES-GCM tag is missing"
        key = self.admin("kms", "archive").describe_key(
            KeyId=self.manifest["evidence_key"]
        )["KeyMetadata"]
        assert key["Arn"].startswith("arn:aws:kms:us-east-1:111111111111:key/"), (
            "the evidence KMS key must belong to the archive account"
        )
        reader = self.archive_reader()
        trust = reader["AssumeRolePolicyDocument"]
        if isinstance(trust, str):
            trust = json.loads(trust)
        assert self.broker_role() in json.dumps(trust), "archive reader trust does not admit the Broker role"
        self.denied(lambda: self.caller("sts", "reviewer").assume_role(
            RoleArn=reader["Arn"], RoleSessionName="intruder"
        ))
        # An access-account principal that is allowed sts:AssumeRole must still
        # be refused by the reader trust policy.
        self.assume_probe_denied(reader["Arn"])

    def mirrored_audit(self):
        table = self.manifest["tables"]["audit"]
        db = self.admin("dynamodb", "access")
        ids = [
            item["audit_id"]["S"] for item in db.scan(TableName=table)["Items"]
            if item["grant_id"]["S"] == self.facts["request"]["grant_id"]
        ]
        assert ids
        deadline = time.time() + 30
        while not all(self.copy_exists(audit_id) for audit_id in ids):
            if time.time() > deadline:
                raise AssertionError("audit stream decisions were not mirrored to the archive bucket")
            time.sleep(1)
        for actor in ("custodian", "approver", "reviewer", "outsider"):
            self.denied(lambda actor=actor: self.caller("s3", actor).get_object(
                Bucket=self.manifest["audit_bucket"],
                Key=f"decisions/{ids[0]}.json",
            ))

    def scheduled_reconciliation(self):
        schedule_ref = self.manifest["reconciliation_schedule"]
        schedule = self.admin("scheduler", "access").get_schedule(
            GroupName=schedule_ref["group"], Name=schedule_ref["name"]
        )
        assert schedule["State"] == "ENABLED"
        assert schedule["ScheduleExpression"] == "rate(1 minute)"
        assert json.loads(schedule["Target"]["Input"]) == {
            "source": "frostpass", "operation": "reconcile"
        }
        lambda_admin = self.admin("lambda", "access")
        witness = lambda_admin.get_function(
            FunctionName=self.manifest["functions"]["witness"]
        )["Configuration"]
        function_arn = witness["FunctionArn"]
        target_arn = schedule["Target"]["Arn"]
        assert target_arn == function_arn or target_arn.startswith(function_arn + ":")

        db = self.admin("dynamodb", "access")
        audit_table = db.describe_table(TableName=self.manifest["tables"]["audit"])["Table"]
        stream_arn = audit_table["LatestStreamArn"]
        mappings = lambda_admin.list_event_source_mappings(
            FunctionName=self.manifest["functions"]["witness"]
        )["EventSourceMappings"]
        matching = [item for item in mappings if item["EventSourceArn"] == stream_arn]
        assert matching, "Witness has no mapping from the audit stream"

        s3 = self.admin("s3", "archive")
        baseline_ids = [
            item["audit_id"]["S"]
            for item in db.scan(TableName=self.manifest["tables"]["audit"])["Items"]
            if item["grant_id"]["S"] == self.facts["request"]["grant_id"]
        ]
        assert baseline_ids
        baseline_key = f"decisions/{baseline_ids[0]}.json"
        def version_count(key):
            return sum(
                version["Key"] == key
                for version in s3.list_object_versions(
                    Bucket=self.manifest["audit_bucket"], Prefix=key
                ).get("Versions", [])
            )
        baseline_versions = version_count(baseline_key)
        assert baseline_versions >= 1

        lambda_admin.delete_event_source_mapping(UUID=matching[0]["UUID"])
        try:
            deadline = time.time() + 15
            while time.time() < deadline:
                current = lambda_admin.list_event_source_mappings(
                    FunctionName=self.manifest["functions"]["witness"]
                )["EventSourceMappings"]
                if not any(item["EventSourceArn"] == stream_arn for item in current):
                    break
                time.sleep(1)
            else:
                raise AssertionError("audit stream mapping did not disappear")

            f = self.facts
            grant = self.invoke("approver", "grants", {
                "operation": "create", "shipment_id": f["shipment_id"], "sensor_id": f["sensor_id"],
                "version_id": f["versions"][0], "expires_at": int(time.time()) + 600,
            })
            self.invoke("approver", "grants", {
                "operation": "approve", "grant_id": grant["grant_id"]
            })
            result = self.invoke("reviewer", "broker", {
                **f["request"], "grant_id": grant["grant_id"]
            })
            assert result["status"] == "released"
            assert result["sha256"] == hashlib.sha256(f["first"]).hexdigest()
            ids = [
                item["audit_id"]["S"]
                for item in db.scan(TableName=self.manifest["tables"]["audit"])["Items"]
                if item["grant_id"]["S"] == grant["grant_id"]
            ]
            assert len(ids) == 1
            deadline = time.time() + 120
            while not self.copy_exists(ids[0]):
                if time.time() > deadline:
                    raise AssertionError("scheduled reconciliation missed an audit decision")
                time.sleep(2)
            current = lambda_admin.list_event_source_mappings(
                FunctionName=self.manifest["functions"]["witness"]
            )["EventSourceMappings"]
            assert not any(item["EventSourceArn"] == stream_arn for item in current), (
                "audit stream mapping reappeared before scheduled recovery completed"
            )
            assert version_count(baseline_key) == baseline_versions, (
                "reconciliation rewrote an existing audit copy"
            )
        finally:
            repaired = self.run_script("deploy")
            self.refresh_manifest()
            self.script_ok(repaired, "deploy.sh restoring the stream mapping")

        restored = lambda_admin.list_event_source_mappings(
            FunctionName=self.manifest["functions"]["witness"]
        )["EventSourceMappings"]
        assert any(item["EventSourceArn"] == stream_arn for item in restored)
        assert version_count(baseline_key) == baseline_versions


    def pending_and_scope(self):
        f = self.facts
        created = self.invoke("approver", "grants", {
            "operation": "create", "shipment_id": f["shipment_id"], "sensor_id": f["sensor_id"],
            "version_id": f["versions"][0], "expires_at": int(time.time()) + 600,
        })
        assert created["status"] == "pending"
        request = {
            "operation": "get", "grant_id": created["grant_id"],
            "shipment_id": f["shipment_id"], "sensor_id": f["sensor_id"],
            "version_id": f["versions"][0],
        }
        pending = self.invoke("reviewer", "broker", request)
        assert pending["status"] == "denied" and "permit_id" not in pending
        assert self.invoke("approver", "grants", {
            "operation": "approve", "grant_id": created["grant_id"]
        })["status"] == "approved"
        mismatched = {**request, "version_id": f["versions"][1]}
        denied = self.invoke("reviewer", "broker", mismatched)
        assert denied["status"] == "denied" and "permit_id" not in denied

        expiring = self.invoke("approver", "grants", {
            "operation": "create", "shipment_id": f["shipment_id"], "sensor_id": f["sensor_id"],
            "version_id": f["versions"][0], "expires_at": int(time.time()) + 600,
        })
        self.invoke("approver", "grants", {
            "operation": "approve", "grant_id": expiring["grant_id"]
        })
        self.admin("dynamodb", "access").update_item(
            TableName=self.manifest["tables"]["grants"],
            Key={"grant_id": {"S": expiring["grant_id"]}},
            UpdateExpression="SET expires_at = :past",
            ExpressionAttributeValues={":past": {"N": str(int(time.time()) - 1)}},
        )
        expired = self.invoke("reviewer", "broker", {
            **request, "grant_id": expiring["grant_id"]
        })
        assert expired["status"] == "denied" and "permit_id" not in expired
        self.facts["request"] = request

    def approved_delivery(self):
        f = self.facts
        result = self.invoke("reviewer", "broker", f["request"])
        assert result["status"] == "released"
        assert result["version_id"] == f["versions"][0]
        assert result["sha256"] == hashlib.sha256(f["first"]).hexdigest()

    def caller_isolation(self):
        request = self.facts["request"]
        self.denied(lambda: self.invoke("outsider", "broker", request))
        self.denied(lambda: self.invoke("reviewer", "grants", {
            "operation": "revoke", "grant_id": request["grant_id"]
        }))
        self.denied(lambda: self.invoke("approver", "broker", request))
        self.denied(lambda: self.invoke("custodian", "grants", {
            "operation": "revoke", "grant_id": request["grant_id"]
        }))

        # Each caller's only Lambda permission is invoking its own function:
        # no configuration or code access, which would expose or alter wiring.
        # Floci authorizes Lambda read APIs for any principal allowed to invoke,
        # so this part is judged from the callers' IAM policies.
        own = {"custodian": "intake", "approver": "grants", "reviewer": "broker"}
        arns = {
            service: self.admin("lambda", "archive" if service == "intake" else "access").get_function(
                FunctionName=name
            )["Configuration"]["FunctionArn"]
            for service, name in self.manifest["functions"].items()
        }
        mutating = ("lambda:UpdateFunctionCode", "lambda:UpdateFunctionConfiguration",
                    "lambda:DeleteFunction", "lambda:AddPermission", "lambda:PutFunctionConcurrency",
                    "lambda:GetFunction", "lambda:GetFunctionConfiguration")
        problems = []
        for actor in ("custodian", "approver", "reviewer", "outsider"):
            documents = self.user_documents(*self.caller_user(actor))
            for service, arn in arns.items():
                problems += [f"{actor} allowed {action} on {service}"
                             for action in mutating if policy_allows(documents, action, arn)]
                if own.get(actor) != service and policy_allows(documents, "lambda:InvokeFunction", arn):
                    problems.append(f"{actor} allowed to invoke {service}")
        assert not problems, "; ".join(problems)

    def direct_storage_denial(self):
        f = self.facts
        bucket = self.manifest["bucket"]
        key = f"reports/{f['shipment_id']}/{f['sensor_id']}"
        version = f["versions"][0]
        for actor in ("custodian", "reviewer", "outsider"):
            try:
                self.denied(lambda actor=actor: self.caller("s3", actor).get_object(
                    Bucket=bucket, Key=key, VersionId=version
                ))
            except AssertionError as error:
                raise AssertionError(f"{actor} read evidence directly: {error}") from error

        # An attacker with an identity policy that allows S3 read must still
        # fail because the archive bucket admits only the reader role.
        self.evidence_read_probe_denied("access", bucket, key, version)

        # A principal in the archive account itself needs no bucket-policy
        # allow, so only the evidence bucket policy can stop this read.
        self.archive_read_probe_denied(bucket, key, version)

    def least_privilege(self):
        m, f = self.manifest, self.facts
        evidence = f"arn:aws:s3:::{m['bucket']}/reports/{f['shipment_id']}/{f['sensor_id']}"
        outside_reports = f"arn:aws:s3:::{m['bucket']}/other/probe"
        decision = f"arn:aws:s3:::{m['audit_bucket']}/decisions/probe.json"
        table = "arn:aws:dynamodb:us-east-1:222222222222:table/{}"
        grants_table, audit_table = table.format(m["tables"]["grants"]), table.format(m["tables"]["audit"])
        functions = {
            name: self.admin("lambda", "archive" if name == "intake" else "access").get_function(
                FunctionName=m["functions"][name]
            )["Configuration"]
            for name in m["functions"]
        }
        schedule = self.admin("scheduler", "access").get_schedule(
            GroupName=m["reconciliation_schedule"]["group"], Name=m["reconciliation_schedule"]["name"]
        )
        reader = self.archive_reader()
        key_arn = self.admin("kms", "archive").describe_key(KeyId=m["evidence_key"])["KeyMetadata"]["Arn"]
        writes = ("dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem", "dynamodb:BatchWriteItem")
        forbidden = {
            ("archive", functions["intake"]["Role"], "Intake"): [
                (action, evidence) for action in
                ("s3:GetObject", "s3:GetObjectVersion", "s3:DeleteObject", "s3:DeleteObjectVersion")
            ],
            ("access", functions["grants"]["Role"], "Grant Manager"): [
                ("s3:GetObject", evidence), ("s3:GetObjectVersion", evidence),
                *((action, audit_table) for action in writes),
            ],
            ("access", functions["broker"]["Role"], "Access Broker"): [
                ("s3:PutObject", evidence), ("s3:DeleteObject", evidence),
                ("s3:DeleteObjectVersion", evidence),
                *((action, grants_table) for action in writes),
            ],
            ("access", functions["witness"]["Role"], "Audit Witness"): [
                ("s3:GetObject", evidence), ("s3:GetObjectVersion", evidence), ("kms:Decrypt", key_arn),
            ],
            ("access", schedule["Target"]["RoleArn"], "Scheduler"): [
                ("lambda:InvokeFunction", functions[name]["FunctionArn"])
                for name in ("intake", "grants", "broker")
            ],
            ("archive", reader["Arn"], "archive reader"): [
                ("s3:PutObject", evidence), ("s3:DeleteObject", evidence),
                ("s3:DeleteObjectVersion", evidence), ("s3:GetObject", outside_reports),
                ("s3:GetObject", decision),
            ],
        }
        problems = []
        for (account, role_arn, label), checks in forbidden.items():
            documents = self.role_documents(account, role_arn)
            problems += [f"{label} role allows {action} on {resource}"
                         for action, resource in checks if policy_allows(documents, action, resource)]
            for action in ("iam:CreateUser", "iam:PutRolePolicy", "iam:PassRole",
                           "lambda:UpdateFunctionCode", "s3:PutBucketPolicy", "dynamodb:DeleteTable"):
                if policy_allows(documents, action, "*"):
                    problems.append(f"{label} allows infrastructure administration: {action}")

        # Resource policies are judged by whom they actually admit after their
        # conditions and explicit denies, not by how principals are written: a
        # set of principals that must stay out, plus every principal an Allow names.
        s3 = self.admin("s3", "archive")
        reader_name = reader["Arn"].rsplit("/", 1)[-1]
        witness_name = functions["witness"]["Role"].rsplit("/", 1)[-1]
        access_roles = [functions[name]["Role"] for name in ("grants", "broker", "witness")]
        access_roles.append(schedule["Target"]["RoleArn"])
        outsiders = [f"arn:aws:iam::{ACCESS}:user/{PREFIX}-operator", "arn:aws:iam::333333333333:user/outsider"]

        def reader_principal(arn):
            # The bucket-owning account's root may manage its own bucket; the
            # archive-account probe in direct storage denial verifies that
            # this delegation does not open reads to other principals.
            return arn in (reader["Arn"], "111111111111", "arn:aws:iam::111111111111:root") or arn.startswith(
                f"arn:aws:sts::111111111111:assumed-role/{reader_name}/")

        def audit_principal(arn):
            return (
                arn == functions["witness"]["Role"]
                or arn.startswith(f"arn:aws:sts::222222222222:assumed-role/{witness_name}/")
                or arn == "111111111111"
                or (arn != "*" and ":111111111111:" in arn)
            )

        def archive_principal(arn):
            return arn == "111111111111" or (arn != "*" and ":111111111111:" in arn)

        def callers(arn):
            """(identity, aws:PrincipalArn) pairs a principal calls as: a role also as its session."""
            account, path = arn.split(":")[4], arn.split(":", 5)[-1]
            if arn.startswith("arn:aws:iam::") and path.startswith("role/"):
                session = f"arn:aws:sts::{account}:assumed-role/{path.rsplit('/', 1)[-1]}/floci-session"
                return [(arn, arn), (session, arn)]
            if arn.startswith("arn:aws:sts::") and path.startswith("assumed-role/"):
                return [(arn, f"arn:aws:iam::{account}:role/{path.split('/')[1]}")]
            return [(arn, arn)]

        def admitted(document, action, resource, probes, permitted):
            named = {p for p in allowed_principals(document, action, resource)
                     if p.startswith("arn:") and p.count(":") >= 5}
            return sorted(
                arn for arn in set(probes) | {p for p in named if not permitted(p)}
                if any(resource_policy_grants(document, identity, principal_arn, action, resource, ARCHIVE)
                       for identity, principal_arn in callers(arn)))

        evidence_policy = s3.get_bucket_policy(Bucket=m["bucket"])["Policy"]
        evidence_probes = [functions["intake"]["Role"], f"arn:aws:iam::{ARCHIVE}:user/{PREFIX}-operator",
                           *access_roles, *outsiders]
        for action in ("s3:GetObject", "s3:GetObjectVersion"):
            extra = admitted(evidence_policy, action, evidence, evidence_probes, reader_principal)
            if extra:
                problems.append(f"evidence bucket policy allows {action} to {extra}")

        audit_policy = s3.get_bucket_policy(Bucket=m["audit_bucket"])["Policy"]
        audit_probes = [role for role in access_roles if role != functions["witness"]["Role"]] + outsiders
        for action in ("s3:GetObject", "s3:PutObject", "s3:DeleteObject"):
            extra = admitted(audit_policy, action, decision, audit_probes, audit_principal)
            if extra:
                problems.append(f"audit bucket policy allows {action} to {extra}")

        key_policy = self.admin("kms", "archive").get_key_policy(KeyId=key_arn, PolicyName="default")["Policy"]
        for action in ("kms:Decrypt", "kms:GenerateDataKey"):
            outside = admitted(key_policy, action, key_arn, [*access_roles, *outsiders], archive_principal)
            if outside:
                problems.append(f"evidence key policy allows {action} to {outside}")
        assert not problems, "; ".join(problems)

    def kms_key_use(self):
        """Only Intake generates and only the reader decrypts, each with exactly {case, file}.

        Floci ignores key policies, so the key policy and the IAM policies are
        evaluated together with AWS semantics for a set of requests.
        """
        m = self.manifest
        kms = self.admin("kms", "archive")
        key_arn = kms.describe_key(KeyId=m["evidence_key"])["KeyMetadata"]["Arn"]
        key_policy = kms.get_key_policy(KeyId=key_arn, PolicyName="default")["Policy"]
        intake_role = self.admin("lambda", "archive").get_function(
            FunctionName=m["functions"]["intake"])["Configuration"]["Role"]
        broker_role = self.broker_role()
        reader_arn = self.archive_reader()["Arn"]
        deployer = self.admin("sts", "archive").get_caller_identity()["Arn"]
        everything = [{"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}]
        all_kms = [{"Statement": [{"Effect": "Allow", "Action": "kms:*", "Resource": "*"}]}]
        principals = {
            "Intake role": (("AWS", intake_role, ARCHIVE), self.role_documents("archive", intake_role)),
            "reader role": (("AWS", reader_arn, ARCHIVE), self.role_documents("archive", reader_arn)),
            "an archive principal allowed kms:*": (("AWS", f"arn:aws:iam::{ARCHIVE}:user/{PREFIX}-operator", ARCHIVE), all_kms),
            "the Broker role with kms:*": (("AWS", broker_role, ACCESS), all_kms),
            "the deployment identity": (("AWS", deployer, ARCHIVE), everything),
        }
        good = {"shipment": "case-a", "sensor": "report"}
        contexts = {
            "exact {case, file}": good,
            "no encryption context": None,
            "only {case}": {"shipment": "case-a"},
            "an extra context key": {**good, "purpose": "export"},
        }
        crypto = ("kms:GenerateDataKey", "kms:Decrypt", "kms:Encrypt", "kms:ReEncryptFrom",
                  "kms:ReEncryptTo", "kms:GenerateDataKeyWithoutPlaintext")
        expected_allow = {("Intake role", "kms:GenerateDataKey"), ("reader role", "kms:Decrypt")}
        problems = []

        def allowed(label, action, context):
            principal, documents = principals[label]
            return kms_request_allowed(key_policy, documents, principal, action, key_arn,
                                       kms_context(principal, context))

        # The deployment identity keeps key administration only; like every other
        # principal it is denied each cryptographic operation.
        for label in principals:
            for action in crypto:
                for context_label, context in contexts.items():
                    want = (label, action) in expected_allow and context is good
                    if allowed(label, action, context) != want:
                        verb = "cannot" if want else "can"
                        problems.append(f"{label} {verb} {action} with {context_label}")
        for action in ("kms:PutKeyPolicy", "kms:ScheduleKeyDeletion", "kms:DescribeKey", "kms:EnableKeyRotation"):
            if not allowed("the deployment identity", action, None):
                problems.append(f"the deployment identity cannot {action}")
        assert not problems, "; ".join(problems[:6]) + (f" (+{len(problems) - 6} more)" if len(problems) > 6 else "")

    def table_write_scope(self):
        """Writes are limited to the exact attributes the images store; audit is append-only."""
        m = self.manifest
        table = "arn:aws:dynamodb:us-east-1:222222222222:table/{}"
        grants_table, audit_table = table.format(m["tables"]["grants"]), table.format(m["tables"]["audit"])
        functions = {name: self.admin("lambda", "access").get_function(FunctionName=m["functions"][name])[
            "Configuration"]["Role"] for name in ("grants", "broker")}
        grant_attributes = ["grant_id", "shipment_id", "sensor_id", "version_id", "expires_at", "state", "expected_sha256"]
        audit_attributes = ["audit_id", "grant_id", "outcome", "reason", "at", "request_hash", "response_json"]
        problems = []
        for label, role, resource, attributes in (
            ("Grant Manager", functions["grants"], grants_table, grant_attributes),
            ("Access Broker", functions["broker"], audit_table, audit_attributes),
        ):
            documents = self.role_documents("access", role)
            if identity_decision(documents, "dynamodb:PutItem", resource,
                                 {"dynamodb:attributes": attributes}) != "allow":
                problems.append(f"{label} cannot PutItem its own attributes")
            for extra in ("approved_by", "admin"):
                if identity_decision(documents, "dynamodb:PutItem", resource,
                                     {"dynamodb:attributes": attributes + [extra]}) == "allow":
                    problems.append(f"{label} can PutItem an extra attribute '{extra}'")
                    break
        broker_documents = self.role_documents("access", functions["broker"])
        for action in ("dynamodb:UpdateItem", "dynamodb:DeleteItem", "dynamodb:BatchWriteItem"):
            if policy_allows(broker_documents, action, audit_table):
                problems.append(f"Access Broker can {action} audit items (audit must be append-only)")
        assert not problems, "; ".join(problems)

    def scheduler_trust(self):
        """The scheduler role trusts only this deployment's schedules (confused deputy).

        EventBridge Scheduler assumes the role with aws:SourceArn set to the
        schedule group's ARN, not the schedule's, so requests carry group ARNs."""
        m = self.manifest
        ref = m["reconciliation_schedule"]
        schedule = self.admin("scheduler", "access").get_schedule(GroupName=ref["group"], Name=ref["name"])
        role_name = schedule["Target"]["RoleArn"].rsplit("/", 1)[-1]
        trust = self.admin("iam", "access").get_role(RoleName=role_name)["Role"]["AssumeRolePolicyDocument"]
        role_arn = schedule["Target"]["RoleArn"]
        principal = ("Service", "scheduler.amazonaws.com", None)
        arn = "arn:aws:scheduler:us-east-1:{}:schedule-group/{}"
        requests = {
            "this deployment's schedule group": (ACCESS, arn.format(ACCESS, ref["group"]), True),
            "a schedule group in another account": ("333333333333", arn.format("333333333333", ref["group"]), False),
            "another schedule group in this account": (ACCESS, arn.format(ACCESS, f"{PREFIX}-other"), False),
            "no source context": (None, None, False),
        }
        problems = []
        for label, (account, source_arn, want) in requests.items():
            decision = resource_policy_decision(trust, principal, "sts:AssumeRole", role_arn,
                                                {"aws:sourceaccount": account, "aws:sourcearn": source_arn})
            if (decision["direct"] and not decision["deny"]) != want:
                problems.append(f"trust {'rejects' if want else 'admits'} {label}")
        assert not problems, "; ".join(problems)

    def revocation_and_audit(self):
        request = self.facts["request"]
        assert self.invoke("approver", "grants", {
            "operation": "revoke", "grant_id": request["grant_id"]
        })["status"] == "revoked"
        denied = self.invoke("reviewer", "broker", request)
        assert denied["status"] == "denied" and "permit_id" not in denied
        response = self.admin("dynamodb", "access").scan(TableName=self.manifest["tables"]["audit"])
        outcomes = [
            item["outcome"]["S"] for item in response["Items"]
            if item["grant_id"]["S"] == request["grant_id"]
        ]
        assert outcomes.count("allowed") >= 1 and outcomes.count("denied") >= 3


    def immutable_records(self):
        """Only the deployment identity may delete evidence or decision copies.

        Floci enforces bucket-policy denies for reads but not for deletes or
        versioning changes, so the policies are evaluated with AWS semantics
        (see runtime.md) against principals that must be denied and against
        the deployment identity, which must stay able to tear down.
        """
        m = self.manifest
        functions = {
            name: self.admin("lambda", "archive" if name == "intake" else "access").get_function(
                FunctionName=m["functions"][name]
            )["Configuration"]
            for name in m["functions"]
        }
        deployer = self.admin("sts", "archive").get_caller_identity()["Arn"]
        must_be_denied = {
            "an archive-account operator": f"arn:aws:iam::{ARCHIVE}:user/{PREFIX}-operator",
            "the Intake role": functions["intake"]["Role"],
            "the archive reader role": self.archive_reader()["Arn"],
            "the Witness role": functions["witness"]["Role"],
            "the access account": f"arn:aws:iam::{ACCESS}:root",
        }
        requests = {
            m["bucket"]: f"reports/{self.facts['shipment_id']}/{self.facts['sensor_id']}",
            m["audit_bucket"]: "decisions/probe.json",
        }
        problems = []
        s3 = self.admin("s3", "archive")
        for bucket, key in requests.items():
            policy = s3.get_bucket_policy(Bucket=bucket)["Policy"]
            checks = [
                ("s3:DeleteObject", f"arn:aws:s3:::{bucket}/{key}"),
                ("s3:DeleteObjectVersion", f"arn:aws:s3:::{bucket}/{key}"),
                ("s3:PutBucketVersioning", f"arn:aws:s3:::{bucket}"),
                ("s3:PutLifecycleConfiguration", f"arn:aws:s3:::{bucket}"),
            ]
            for action, resource in checks:
                problems += [f"{bucket} policy does not deny {action} to {label}"
                             for label, arn in must_be_denied.items()
                             if not policy_denies(policy, action, resource, arn)]
                if policy_denies(policy, action, resource, deployer):
                    problems.append(f"{bucket} policy denies {action} to the deployment identity")
            assert s3.get_bucket_versioning(Bucket=bucket)["Status"] == "Enabled"
        assert not problems, "; ".join(problems[:6]) + (f" (+{len(problems) - 6} more)" if len(problems) > 6 else "")

    def stable_redeploy(self):
        """A second deploy keeps every stateful resource and existing audit copies."""
        m = self.manifest
        s3, db = self.admin("s3", "archive"), self.admin("dynamodb", "access")

        def snapshot():
            buckets = {item["Name"]: item["CreationDate"] for item in s3.list_buckets()["Buckets"]}
            return {
                "evidence bucket": buckets.get(m["bucket"]),
                "audit bucket": buckets.get(m["audit_bucket"]),
                **{f"{label} table": db.describe_table(TableName=table)["Table"]["CreationDateTime"]
                   for label, table in m["tables"].items()},
                "evidence key": self.admin("kms", "archive").describe_key(
                    KeyId=m["evidence_key"])["KeyMetadata"]["KeyId"],
                "archive reader": self.archive_reader()["RoleId"],
            }

        def copy_versions():
            counts = Counter()
            for version in s3.list_object_versions(
                Bucket=m["audit_bucket"], Prefix="decisions/"
            ).get("Versions", []):
                counts[version["Key"]] += 1
            return counts

        names = ("functions", "bucket", "audit_bucket", "tables", "archive_reader_role", "reconciliation_schedule")
        request = self.approved_request()
        before, before_names = snapshot(), {key: m[key] for key in names}
        audit_before = len(db.scan(TableName=m["tables"]["audit"])["Items"])
        copies_before = copy_versions()

        result = self.run_script("deploy")
        self.refresh_manifest()
        self.script_ok(result, "repeated deploy.sh")
        after_manifest = self.reload_manifest()
        renamed = [key for key in names if after_manifest[key] != before_names[key]]
        assert not renamed, f"redeploy changed manifest resources: {renamed}"
        after = snapshot()
        replaced = [label for label in before if before[label] != after[label]]
        assert not replaced, f"redeploy replaced: {replaced}"
        assert len(db.scan(TableName=m["tables"]["audit"])["Items"]) >= audit_before
        copies_after = copy_versions()
        rewritten = [key for key, count in copies_before.items() if copies_after.get(key) != count]
        assert not rewritten, f"redeploy rewrote audit copies: {rewritten[:3]}"
        self.delivers_first_version(request)

    def repair_drift(self):
        """deploy.sh restores deleted and altered managed resources, not only Lambdas."""
        m, f = self.manifest, self.facts
        request = self.approved_request()
        reader = self.archive_reader()
        iam = self.admin("iam", "archive")
        self.admin("lambda", "access").delete_function(FunctionName=m["functions"]["broker"])
        self.admin("s3", "archive").delete_bucket_policy(Bucket=m["bucket"])
        for policy_name in iam.list_role_policies(RoleName=reader["RoleName"])["PolicyNames"]:
            iam.delete_role_policy(RoleName=reader["RoleName"], PolicyName=policy_name)
        for attached in iam.list_attached_role_policies(RoleName=reader["RoleName"])["AttachedPolicies"]:
            iam.detach_role_policy(RoleName=reader["RoleName"], PolicyArn=attached["PolicyArn"])
        iam.update_assume_role_policy(RoleName=reader["RoleName"], PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{ARCHIVE}:root"},
                           "Action": "sts:AssumeRole"}],
        }))
        schedule_ref = m["reconciliation_schedule"]
        self.admin("scheduler", "access").delete_schedule(
            GroupName=schedule_ref["group"], Name=schedule_ref["name"]
        )

        result = self.run_script("deploy")
        self.refresh_manifest()
        self.script_ok(result, "deploy.sh repairing drift")
        m = self.reload_manifest()
        self.delivers_first_version(request)
        self.archive_read_probe_denied(m["bucket"], f"reports/{f['shipment_id']}/{f['sensor_id']}", f["versions"][0])
        self.assume_probe_denied(self.archive_reader()["Arn"])
        schedule = self.admin("scheduler", "access").get_schedule(
            GroupName=m["reconciliation_schedule"]["group"], Name=m["reconciliation_schedule"]["name"]
        )
        assert schedule["State"] == "ENABLED" and schedule["ScheduleExpression"] == "rate(1 minute)"
        assert json.loads(schedule["Target"]["Input"]) == {"source": "frostpass", "operation": "reconcile"}

    def watch_rotation(self, users, old_keys):
        """Poll, in the background, when each old caller key disappears and when
        a manifest carrying only new keys first appears."""
        stop = threading.Event()
        state = {"stop": stop, "manifest_at": None, "gone_at": {actor: None for actor in old_keys}}

        def poll():
            iam = {"archive": self.admin("iam", "archive"), "access": self.admin("iam", "access")}
            while True:
                now = time.time()
                for actor, (account, user_name) in users.items():
                    if state["gone_at"][actor] is not None:
                        continue
                    try:
                        keys = iam["archive" if account == ARCHIVE else "access"].list_access_keys(
                            UserName=user_name)["AccessKeyMetadata"]
                    except ClientError:
                        continue
                    live = {k["AccessKeyId"] for k in keys if k.get("Status", "Active") == "Active"}
                    if old_keys[actor] not in live:
                        state["gone_at"][actor] = now
                if state["manifest_at"] is None:
                    try:
                        callers = runner("GET", "/manifest")["callers"]
                        if all(callers[a]["access_key_id"] != old_keys[a] for a in old_keys):
                            state["manifest_at"] = now
                    except Exception:
                        pass
                if stop.is_set():
                    return
                stop.wait(0.4)

        state["thread"] = threading.Thread(target=poll, daemon=True)
        state["thread"].start()
        return state

    def recovery_after_state_loss(self):
        """After losing local state, deploy.sh adopts the live deployment instead of duplicating it."""
        m, f = self.manifest, self.facts
        s3, db = self.admin("s3", "archive"), self.admin("dynamodb", "access")
        lambda_access = self.admin("lambda", "access")
        iam = {"archive": self.admin("iam", "archive"), "access": self.admin("iam", "access")}

        def identities():
            buckets = {item["Name"]: item["CreationDate"] for item in s3.list_buckets()["Buckets"]}
            return {
                "evidence bucket": buckets.get(m["bucket"]),
                "audit bucket": buckets.get(m["audit_bucket"]),
                **{f"{label} table": db.describe_table(TableName=table)["Table"]["CreationDateTime"]
                   for label, table in m["tables"].items()},
                "evidence key": self.admin("kms", "archive").describe_key(
                    KeyId=m["evidence_key"])["KeyMetadata"]["KeyId"],
                "archive reader": self.archive_reader()["RoleId"],
            }

        def copy_versions():
            return Counter(v["Key"] for v in s3.list_object_versions(
                Bucket=m["audit_bucket"], Prefix="decisions/").get("Versions", []))

        evidence_key = f"reports/{f['shipment_id']}/{f['sensor_id']}"

        def evidence_versions():
            return sorted(v["VersionId"] for v in s3.list_object_versions(
                Bucket=m["bucket"], Prefix=evidence_key).get("Versions", []) if v["Key"] == evidence_key)

        names = ("functions", "bucket", "audit_bucket", "tables", "archive_reader_role", "reconciliation_schedule")
        request = self.approved_request()
        users = {actor: self.caller_user(actor) for actor in m["callers"]}
        before, before_names = identities(), {key: m[key] for key in names}
        versions_before, copies_before = evidence_versions(), copy_versions()
        audit_before = len(db.scan(TableName=m["tables"]["audit"])["Items"])
        stream_arn = db.describe_table(TableName=m["tables"]["audit"])["Table"]["LatestStreamArn"]

        old_keys = {actor: caller["access_key_id"] for actor, caller in m["callers"].items()}
        runner("POST", "/snapshot-state?slot=pre")
        removed = runner("POST", "/lose-state")["removed"]
        assert removed, "no local Terraform/OpenTofu state file was found to remove"
        rotation = self.watch_rotation(users, old_keys)
        try:
            result = self.run_script("deploy")
        finally:
            rotation["stop"].set()
            rotation["thread"].join(timeout=30)
        self.refresh_manifest()
        if result["exit_code"] != 0:
            runner("POST", "/restore-state?slot=pre")  # contain the damage to this check
        self.script_ok(result, "deploy.sh after state loss")
        self.within_recovery_objective(result, "state loss")
        new_keys = {actor: caller["access_key_id"] for actor, caller in self.reload_manifest()["callers"].items()}
        unrotated = [actor for actor in old_keys if new_keys.get(actor) == old_keys[actor]]
        assert not unrotated, f"caller keys were not rotated after state loss: {unrotated}"
        published = rotation["manifest_at"]
        assert published is not None, "the new manifest was never observed during the deploy"
        early = [actor for actor, gone in rotation["gone_at"].items() if gone is not None and gone < published]
        assert not early, (
            f"old keys of {early} stopped existing before the new manifest was written "
            "(rotation must be make-before-break)")

        after_manifest = self.reload_manifest()
        renamed = [key for key in names if after_manifest[key] != before_names[key]]
        assert not renamed, f"deploy after state loss changed manifest resources: {renamed}"
        after = identities()
        replaced = [label for label in before if before[label] != after[label]]
        assert not replaced, f"deploy after state loss replaced: {replaced}"
        mappings = self.stream_mappings(stream_arn)
        assert len(mappings) == 1, f"audit stream has {len(mappings)} event source mappings"
        assert evidence_versions() == versions_before, "evidence versions changed"
        assert len(db.scan(TableName=m["tables"]["audit"])["Items"]) >= audit_before, "audit records lost"
        copies_after = copy_versions()
        rewritten = [key for key, count in copies_before.items() if copies_after.get(key) != count]
        assert not rewritten, f"audit copies rewritten: {rewritten[:3]}"

        self.facts["caller_users"] = {}
        for actor, (account, user_name) in users.items():
            assert self.caller_user(actor) == (account, user_name), f"{actor} is a different IAM user now"
            client = iam["archive" if account == ARCHIVE else "access"]
            keys = client.list_access_keys(UserName=user_name)["AccessKeyMetadata"]
            assert len(keys) == 1, f"{actor} user has {len(keys)} access keys, expected exactly 1"
        self.delivers_first_version(request)

        declared = {value for state in runner("GET", "/state-summary")["states"]
                    for value in state.get("identifiers", [])}
        untracked = [value for value in (*after_manifest["functions"].values(), after_manifest["bucket"],
                                         after_manifest["audit_bucket"], *after_manifest["tables"].values())
                     if value not in declared]
        assert not untracked, f"resources not adopted into state: {untracked}"

    def inventory(self, m):
        """Everything a live deployment created, located through its manifest."""
        lam = {"archive": self.admin("lambda", "archive"), "access": self.admin("lambda", "access")}
        functions, roles = [], []
        for service, name in m["functions"].items():
            account = "archive" if service == "intake" else "access"
            role = lam[account].get_function(FunctionName=name)["Configuration"]["Role"]
            functions.append((account, name))
            roles.append(("archive" if f":{ARCHIVE}:" in role else "access", role.rsplit("/", 1)[-1]))
        roles.append(("archive", m["archive_reader_role"].rsplit("/", 1)[-1]))
        ref = m["reconciliation_schedule"]
        scheduler_role = self.admin("scheduler", "access").get_schedule(
            GroupName=ref["group"], Name=ref["name"])["Target"]["RoleArn"]
        roles.append(("access", scheduler_role.rsplit("/", 1)[-1]))
        users = {}
        for actor, caller in m["callers"].items():
            arn = self._client("sts", caller).get_caller_identity()["Arn"]
            users[actor] = ("archive" if arn.split(":")[4] == ARCHIVE else "access", arn.rsplit("/", 1)[-1])
        db = self.admin("dynamodb", "access")
        return {
            "functions": functions, "roles": sorted(set(roles)), "users": users,
            "buckets": [m["bucket"], m["audit_bucket"]], "tables": list(m["tables"].values()),
            "schedule": ref,
            "stream": db.describe_table(TableName=m["tables"]["audit"])["Table"].get("LatestStreamArn"),
            "key": self.admin("kms", "archive").describe_key(KeyId=m["evidence_key"])["KeyMetadata"]["KeyId"],
        }

    def leftovers(self, inventory):
        """Resources from an inventory that still exist after a destroy."""
        lam = {"archive": self.admin("lambda", "archive"), "access": self.admin("lambda", "access")}
        iam = {"archive": self.admin("iam", "archive"), "access": self.admin("iam", "access")}
        s3, db = self.admin("s3", "archive"), self.admin("dynamodb", "access")
        scheduler, kms = self.admin("scheduler", "access"), self.admin("kms", "archive")
        ref = inventory["schedule"]
        checks = [
            *((f"function {n}", lambda a=a, n=n: lam[a].get_function(FunctionName=n))
              for a, n in inventory["functions"]),
            *((f"bucket {b}", lambda b=b: s3.head_bucket(Bucket=b)) for b in inventory["buckets"]),
            *((f"table {t}", lambda t=t: db.describe_table(TableName=t)) for t in inventory["tables"]),
            *((f"role {r}", lambda a=a, r=r: iam[a].get_role(RoleName=r)) for a, r in inventory["roles"]),
            *((f"user {u}", lambda a=a, u=u: iam[a].get_user(UserName=u))
              for a, u in inventory["users"].values()),
            ("schedule", lambda: scheduler.get_schedule(GroupName=ref["group"], Name=ref["name"])),
        ]
        if ref["group"] != "default":
            checks.append(("schedule group", lambda: scheduler.get_schedule_group(Name=ref["group"])))
        left = [label for label, lookup in checks if not self.gone(lookup)]
        try:
            state = kms.describe_key(KeyId=inventory["key"])["KeyMetadata"]["KeyState"]
            if state != "PendingDeletion":
                left.append(f"evidence key ({state})")
        except ClientError:
            pass
        if inventory["stream"]:
            try:
                if self.stream_mappings(inventory["stream"]):
                    left.append("audit stream mapping")
            except ClientError:
                pass
        return left

    def identities(self, m):
        """Creation-time identities that change if a resource is replaced."""
        s3, db = self.admin("s3", "archive"), self.admin("dynamodb", "access")
        buckets = {item["Name"]: item["CreationDate"] for item in s3.list_buckets()["Buckets"]}
        role = self.admin("iam", "archive").get_role(
            RoleName=m["archive_reader_role"].rsplit("/", 1)[-1])["Role"]
        return {
            "evidence bucket": buckets.get(m["bucket"]), "audit bucket": buckets.get(m["audit_bucket"]),
            **{f"{label} table": db.describe_table(TableName=t)["Table"]["CreationDateTime"]
               for label, t in m["tables"].items()},
            "evidence key": self.admin("kms", "archive").describe_key(
                KeyId=m["evidence_key"])["KeyMetadata"]["KeyId"],
            "archive reader": role["RoleId"],
        }

    def full_flow(self, m, label):
        """Upload, grant, deliver and mirror through the deployment described by m."""
        saved, self.manifest = self.manifest, m
        try:
            body = None
            shipment_id = f"flow-{uuid.uuid4().hex[:8]}"
            body = json.dumps({"shipment_id": shipment_id, "sensor_id": "report", "samples_mc": [2000, 4000, 8000]}).encode()
            stored = self.invoke("custodian", "intake", {
                "operation": "put", "shipment_id": shipment_id, "sensor_id": "report",
                "content_base64": base64.b64encode(body).decode(),
            })
            grant = self.invoke("approver", "grants", {
                "operation": "create", "shipment_id": shipment_id, "sensor_id": "report",
                "version_id": stored["version_id"], "expires_at": int(time.time()) + 600,
            })
            self.invoke("approver", "grants", {"operation": "approve", "grant_id": grant["grant_id"]})
            request = {"operation": "get", "grant_id": grant["grant_id"], "shipment_id": shipment_id,
                       "sensor_id": "report", "version_id": stored["version_id"]}
            delivered = self.invoke("reviewer", "broker", request)
            assert delivered.get("status") == "released", f"{label} did not deliver: {delivered}"
            assert delivered["sha256"] == hashlib.sha256(body).hexdigest()
            self.denied(lambda: self.invoke("outsider", "broker", request))
            ids = [item["audit_id"]["S"]
                   for item in self.admin("dynamodb", "access").scan(TableName=m["tables"]["audit"])["Items"]
                   if item["grant_id"]["S"] == grant["grant_id"]]
            assert ids, f"{label} recorded no audit decision"
            deadline = time.time() + 90
            while not self.copy_exists(ids[0]):
                if time.time() > deadline:
                    raise AssertionError(f"{label} did not mirror its audit decision")
                time.sleep(2)
        finally:
            self.manifest = saved

    def unique_live_parts(self, m, label):
        """Exactly one stream mapping, and exactly the manifest's key on every caller."""
        stream = self.admin("dynamodb", "access").describe_table(
            TableName=m["tables"]["audit"])["Table"]["LatestStreamArn"]
        mappings = self.stream_mappings(stream)
        assert len(mappings) == 1, f"{label}: audit stream has {len(mappings)} event source mappings"
        for actor, caller in m["callers"].items():
            arn = self._client("sts", caller).get_caller_identity()["Arn"]
            iam = self.admin("iam", "archive" if arn.split(":")[4] == ARCHIVE else "access")
            keys = [k["AccessKeyId"] for k in
                    iam.list_access_keys(UserName=arn.rsplit("/", 1)[-1])["AccessKeyMetadata"]]
            assert keys == [caller["access_key_id"]], (
                f"{label}: {actor} has keys {keys}, expected only its manifest key")

    def crash_deploy(self, prefix):
        """Start deploy.sh, SIGKILL it once its first IAM role exists, return what happened."""
        iam = {"archive": self.admin("iam", "archive"), "access": self.admin("iam", "access")}

        def roles():
            names = set()
            for client in iam.values():
                for page in client.get_paginator("list_roles").paginate():
                    names.update(role["RoleName"] for role in page["Roles"])
            return names

        baseline = roles()
        runner("POST", f"/deploy-start?prefix={prefix}")
        deadline = time.time() + 300
        created = set()
        while not created and time.time() < deadline:
            time.sleep(0.5)
            created = roles() - baseline
            if not created and not runner("GET", "/deploy-status")["running"]:
                break  # the deploy exited before creating any role
        killed = runner("POST", "/deploy-kill", timeout=60)
        self.script_runs.append({"script": "deploy (killed)", "prefix": prefix, **killed})
        return {"created_before_kill": sorted(created), "was_running": killed.get("was_running")}

    @staticmethod
    def within_recovery_objective(result, label):
        duration = result.get("duration")
        print(f"recovery after {label}: deploy.sh took {duration}s (objective {RECOVERY_SECONDS}s)")
        assert duration is not None and duration <= RECOVERY_SECONDS, (
            f"deploy.sh after {label} took {duration}s; the recovery objective is {RECOVERY_SECONDS}s")

    def recovery_drill(self, action, label):
        """Damage the local state, then deploy.sh must converge on the live deployment:
        nothing replaced or duplicated, data intact, keys rotated make-before-break,
        within the recovery objective."""
        m, f = self.manifest, self.facts
        s3, db = self.admin("s3", "archive"), self.admin("dynamodb", "access")
        request = self.approved_request()
        self.facts["caller_users"] = {}
        users = {actor: self.caller_user(actor) for actor in m["callers"]}
        old_keys = {actor: caller["access_key_id"] for actor, caller in m["callers"].items()}
        names = ("functions", "bucket", "audit_bucket", "tables", "archive_reader_role", "reconciliation_schedule")
        before, before_names = self.identities(m), {key: m[key] for key in names}
        evidence_key = f"reports/{f['shipment_id']}/{f['sensor_id']}"

        def evidence_versions():
            return sorted(v["VersionId"] for v in s3.list_object_versions(
                Bucket=m["bucket"], Prefix=evidence_key).get("Versions", []) if v["Key"] == evidence_key)

        def copy_versions():
            return Counter(v["Key"] for v in s3.list_object_versions(
                Bucket=m["audit_bucket"], Prefix="decisions/").get("Versions", []))

        versions_before, copies_before = evidence_versions(), copy_versions()
        audit_before = len(db.scan(TableName=m["tables"]["audit"])["Items"])

        runner("POST", "/snapshot-state?slot=pre")
        damaged = runner("POST", f"/{action}")
        assert any(damaged.values()), f"no local state file was found for {label}"
        rotation = self.watch_rotation(users, old_keys)
        try:
            result = self.run_script("deploy")
        finally:
            rotation["stop"].set()
            rotation["thread"].join(timeout=30)
        self.refresh_manifest()
        if result["exit_code"] != 0:
            runner("POST", "/restore-state?slot=pre")  # contain the damage to this check
        self.script_ok(result, f"deploy.sh after {label}")
        self.within_recovery_objective(result, label)
        if action == "corrupt-state":
            expected_damage = b'{"version": 4, "terraform_version": "1.x", "serial": 7, "resources": [{"mode": "man'
            backups = runner("GET", "/state-backups")["backups"]
            assert any(entry["sha256"] == hashlib.sha256(expected_damage).hexdigest() for entry in backups), (
                "corrupted state was discarded instead of preserving an exact copy")

        after_manifest = self.reload_manifest()
        renamed = [key for key in names if after_manifest[key] != before_names[key]]
        assert not renamed, f"deploy after {label} changed manifest resources: {renamed}"
        replaced = [key for key, value in self.identities(after_manifest).items() if before[key] != value]
        assert not replaced, f"deploy after {label} replaced: {replaced}"
        new_keys = {actor: caller["access_key_id"] for actor, caller in after_manifest["callers"].items()}
        unrotated = [actor for actor in old_keys if new_keys.get(actor) == old_keys[actor]]
        assert not unrotated, f"caller keys were not rotated after {label}: {unrotated}"
        published = rotation["manifest_at"]
        assert published is not None, "the new manifest was never observed during the deploy"
        early = [actor for actor, gone in rotation["gone_at"].items() if gone is not None and gone < published]
        assert not early, f"old keys of {early} stopped existing before the new manifest was written"
        self.unique_live_parts(after_manifest, f"after {label}")
        assert evidence_versions() == versions_before, "evidence versions changed"
        assert len(db.scan(TableName=m["tables"]["audit"])["Items"]) >= audit_before, "audit records lost"
        rewritten = [key for key, count in copies_before.items() if copy_versions().get(key) != count]
        assert not rewritten, f"audit copies rewritten: {rewritten[:3]}"
        self.facts["caller_users"] = {}
        self.delivers_first_version(request)
        declared = {value for state in runner("GET", "/state-summary")["states"]
                    for value in state.get("identifiers", [])}
        untracked = [value for value in (*after_manifest["functions"].values(), after_manifest["bucket"],
                                         after_manifest["audit_bucket"], *after_manifest["tables"].values())
                     if value not in declared]
        assert not untracked, f"resources not tracked in state after {label}: {untracked}"

    def restored_state_recovery(self):
        """An older state backup is restored: its stream mapping and caller keys no
        longer exist, and the live replacements are not in it."""
        self.recovery_drill("restore-state", "restoring an older state backup")

    def corrupted_state_recovery(self):
        """The state file is unreadable: deploy.sh sets it aside and recovers."""
        self.recovery_drill("corrupt-state", "state corruption")

    def second_deployment(self):
        """A second deployment (other prefix, own copy) is created next to the first,
        through a deploy killed mid-run and rerun, without touching the first."""
        first = self.manifest
        request = self.approved_request()
        before = self.identities(first)
        runner("POST", "/use-copy?name=b")
        crash = self.facts["crash"] = self.crash_deploy(FRESH_PREFIX)
        print(f"crash drill: deploy killed while running={crash['was_running']}, "
              f"roles created before the kill={len(crash['created_before_kill'])}")
        result = self.run_script("deploy", FRESH_PREFIX)
        try:
            self.script_ok(result, "deploy.sh of the second deployment after a killed deploy")
            second = self.facts["second_manifest"] = self.reload_manifest()
            assert second["bucket"] != first["bucket"], "both deployments use the same evidence bucket"
            self.unique_live_parts(second, "second deployment")
            self.full_flow(second, "the second deployment")
        finally:
            self.manifest = first
        changed = [label for label, value in self.identities(first).items() if before[label] != value]
        assert not changed, f"creating the second deployment replaced the first deployment's {changed}"
        self.unique_live_parts(first, "first deployment")
        self.delivers_first_version(request)

    def scoped_destroy(self):
        """destroy.sh removes its whole deployment and nothing else: not the
        pre-existing decoys, not the second deployment."""
        runner("POST", "/use-copy?name=a")
        inventory = self.inventory(self.manifest)
        result = self.run_script("destroy")
        self.script_ok(result, "destroy.sh")
        left = self.leftovers(inventory)
        assert not left, f"destroy left resources behind: {left}"
        try:
            self.decoys_intact()
        except Exception as error:
            raise AssertionError(f"destroy changed pre-existing resources: {error}") from error
        second = self.facts.get("second_manifest")
        if second:  # without one, "isolated second deployment" has already failed
            self.unique_live_parts(second, "second deployment after destroying the first")
            self.full_flow(second, "the second deployment after destroying the first")
        # Same-prefix reuse after complete destruction must also work.
        self.script_ok(self.run_script("deploy"), "redeploy after destroy")
        recreated = self.reload_manifest()
        self.full_flow(recreated, "same-prefix redeployment after destroy")
        inventory = self.inventory(recreated)
        self.script_ok(self.run_script("destroy"), "destroy recreated deployment")
        assert not self.leftovers(inventory)
        self.decoys_intact()

    def destroy_after_state_loss(self):
        """With its local state lost, destroy.sh still removes its whole deployment."""
        second = self.facts.get("second_manifest")
        prefix = FRESH_PREFIX
        if second:
            runner("POST", "/use-copy?name=b")
        else:
            # Scored on its own: the second deployment never came up, so deploy a
            # clean one from a fresh copy under another prefix, leaving that
            # failed attempt out of this check.
            prefix = THIRD_PREFIX
            runner("POST", "/use-copy?name=c")
            self.script_ok(self.run_script("deploy", prefix), "deploy.sh of a fresh deployment to destroy")
            second = self.reload_manifest()
        inventory = self.inventory(second)
        removed = runner("POST", "/lose-state")["removed"]
        assert removed, "no local state file was found to remove"
        result = self.run_script("destroy", prefix)
        self.script_ok(result, "destroy.sh after state loss")
        left = self.leftovers(inventory)
        assert not left, f"destroy after state loss left resources behind: {left}"
        self.script_ok(self.run_script("deploy", THIRD_PREFIX), "redeploy under a changed prefix")
        recreated = self.reload_manifest()
        self.full_flow(recreated, "changed-prefix redeployment after destroy")
        inventory = self.inventory(recreated)
        self.script_ok(self.run_script("destroy", THIRD_PREFIX), "destroy changed-prefix redeployment")
        assert not self.leftovers(inventory)

    def secret_handling(self):
        """The manifest is owner-only and caller secrets never appear in script output."""
        assert self.script_runs, "no deploy or destroy runs recorded"
        problems = []
        for run in self.script_runs:
            if run.get("secret_leak"):
                problems.append(f"{run['script']} ({run['prefix']}) printed a caller secret access key")
            if run["script"] == "deploy" and run.get("exit_code") == 0:
                mode = run.get("manifest_mode")
                if mode is None:
                    problems.append("deploy finished without a manifest")
                elif mode != 0o600:
                    problems.append(f"manifest.json mode is {oct(mode)}, not owner-only")
        assert not problems, "; ".join(sorted(set(problems)))

