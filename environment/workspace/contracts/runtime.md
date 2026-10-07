# FrostPass runtime contract

FrostPass models a refrigerated freight operator that needs reproducible,
auditable release decisions. Its 2–8 °C range is a synthetic benchmark rule for
this workload. The service returns certificates, never raw sensor report bytes.

## Environment and immutable application

| Item | Value |
| --- | --- |
| AWS endpoint / region | `http://aws:4566` / `us-east-1` |
| Archive account | `111111111111` |
| Operations account (manifest key `access`) | `222222222222` |
| Deployment credentials | `/workspace/config/terraform.tfvars.json` |
| Carrier Intake image | `111111111111.dkr.ecr.us-east-1.amazonaws.com/frostpass-intake:1` |
| Approval Manager image | `222222222222.dkr.ecr.us-east-1.amazonaws.com/frostpass-grants:1` |
| Release Gate image | `222222222222.dkr.ecr.us-east-1.amazonaws.com/frostpass-broker:1` |
| Receipt Witness image | `222222222222.dkr.ecr.us-east-1.amazonaws.com/frostpass-witness:1` |

Images are prebuilt by the harness; no ECR push is needed. Only offline providers
`hashicorp/aws` 6.51.0, `null` 3.2.4, `random` 3.7.2, `time` 0.13.1, `local` 2.5.3,
and `archive` 2.7.1 are available. Do not use production AWS endpoints.
Credential variables are `archive_admin_access_key`, `archive_admin_secret_key`,
`access_admin_access_key`, `access_admin_secret_key`. Scripts may use
`FROSTPASS_BOOTSTRAP_TFVARS` to override the credentials file for local author tests.

Technical aliases in the manifest and image names are deliberately stable:
`intake`, `grants`, `broker`, `witness`; callers are `custodian` (carrier),
`approver`, `reviewer` (dispatcher), and `outsider`.

## Required resources and topology

Four image Lambdas, each with its own execution role, timeout at least 15 seconds
and memory at least 256 MiB. Intake belongs to archive; the other three belong
to access. A separate archive reader role is assumed only by Gate. A sixth role
lets EventBridge Scheduler invoke Witness.

| Function | Required environment variables |
| --- | --- |
| `intake` | `EVIDENCE_BUCKET`, `EVIDENCE_KEY_ID` |
| `grants` | `GRANTS_TABLE` |
| `broker` | `EVIDENCE_BUCKET`, `GRANTS_TABLE`, `AUDIT_TABLE`, `ARCHIVE_READER_ROLE` |
| `witness` | `AUDIT_BUCKET`, `AUDIT_TABLE` |

`EVIDENCE_BUCKET` is a private versioned archive S3 bucket for encrypted reports.
`AUDIT_BUCKET` is a second private versioned archive bucket for receipts.
Both must block public ACLs and policies. `EVIDENCE_KEY_ID` identifies an archive
customer KMS key. The access account has two active on-demand DynamoDB tables:
approval table, string HASH key `grant_id`; decision ledger, string HASH key
`audit_id`, with a `NEW_IMAGE` stream. Exactly one enabled event source mapping
connects that stream to Witness. Stable identifiers appear in the manifest.

## Payloads and precise release semantics

`shipment_id`, `sensor_id`, `request_id` match `[a-z0-9][a-z0-9-]{0,31}`.
`grant_id` and `version_id` in gate requests are nonempty strings, at most
128 characters. `content_base64` decodes to 1–65536 bytes. Intake stores the
bytes as submitted; it does not validate the report's business fields.

Intake request:

```json
{"operation":"put","shipment_id":"load-42","sensor_id":"logger-a","content_base64":"<base64 report bytes>"}
```

It generates a new AES-256 data key, with exactly the KMS context keys
`shipment` and `sensor` set to the request IDs. It encrypts with AES-GCM and
associated data `reports/<shipment_id>/<sensor_id>`, then puts ciphertext at
that S3 key. Metadata is `sha256` (plaintext digest), `encrypted-key` (base64
KMS-wrapped key), and `nonce` (base64 12-byte nonce). Response has `status:
stored`, `shipment_id`, `sensor_id`, `version_id`, `sha256`, `size`. Every put
creates and retains a distinct non-null version, including repeated uploads.

Decoded report bytes must be a JSON object with exactly:

```json
{"shipment_id":"load-42","sensor_id":"logger-a","samples_mc":[2000,5000,8000]}
```

IDs must match the approval. `samples_mc` has 1–64 **integer** milli-Celsius
values in [-100000, 100000]. Booleans, floats, strings, nulls, empty or oversized
arrays, extra/missing fields, wrong IDs, invalid JSON and invalid UTF-8 produce
`invalid-report`. Every sample must be in **[2000, 8000], inclusive** to release.
An excursion anywhere, including the final sample, produces
`temperature-excursion`; neither an average nor the latest sample is enough.

Approval Manager requests:

```json
{"operation":"create","shipment_id":"load-42","sensor_id":"logger-a","version_id":"<S3 version>","expected_sha256":"<64 lowercase hex characters>","expires_at":2000000000}
{"operation":"approve","grant_id":"<returned id>"}
{"operation":"revoke","grant_id":"<returned id>"}
```

Creation returns `status: pending`, `grant_id`; expiry is an integer Unix time
strictly in the future and within 24 hours. Approval transitions only pending
to approved; revocation transitions only approved to revoked. They return the
new status, grant ID and expiry. A human can approve malformed or unsafe bytes;
the Gate must still reject them. Stored columns are exactly `grant_id`,
`shipment_id`, `sensor_id`, `version_id`, `expected_sha256`, `expires_at`, `state`.

Release Gate requires exactly six fields:

```json
{"operation":"evaluate","request_id":"try-42","grant_id":"<id>","shipment_id":"load-42","sensor_id":"logger-a","version_id":"<S3 version>"}
```

For a previously unused request ID, consistently read the approval. Deny an
unknown approval (`unknown-grant`), pending/revoked (`inactive-grant`), expiry
at or before current Unix time (`expired-grant`), or mismatch in any shipment,
sensor or version field (`scope-mismatch`). Use the pinned version, never S3's
latest version. Assume the archive reader role; retrieve and decrypt; compute
SHA-256. Both metadata and approval digest must equal that digest, else
`integrity-failure`. Retrieval, envelope, KMS or authentication-tag errors deny
as `storage-error`. Then validate report and every sample as above.

A release response has exactly `status: released`, `permit_id` equal to request
ID, shipment and sensor IDs, version ID, `sha256`, `sample_count`, `min_mc`,
`max_mc`. A denial is exactly `{"status":"denied","reason":"<reason>"}`.
Responses never include raw report bytes.

**Durable idempotency:** one request ID identifies one immutable evaluation.
Canonical request bytes are UTF-8 JSON of all six fields, keys sorted,
separators `,` and `:`, no whitespace. Persist their SHA-256 as `request_hash`.
The ledger row has exactly `audit_id` (= request ID), `grant_id`, `outcome`
(`allowed`/`denied`), `reason` (`safe-report` on release), integer Unix `at`,
`request_hash`, and `response_json` (canonical response JSON). Conditional
`PutItem` prevents overwriting the first row. Persist before returning.
When persistence is unavailable, fail the invocation or deny without any
certificate; no successful release may escape an uncommitted decision.

An identical retry returns the exact recorded response without updating its
timestamp or ledger row. Different field values with the same request ID return
`request-conflict`, leave the original row untouched and do not create another
row. Simultaneous identical requests converge to one decision and one receipt;
simultaneous conflicting requests have exactly one winning fingerprint.
This is idempotent **decision recording**, not an assertion that a physical
shipment can be moved exactly once. Historic responses remain stable after
approval/revocation/expiry. A **new request ID** checks the current approval,
so revocation or expiry takes effect on the next new evaluation. Even a pending
denial stays denied on replay after approval; a fresh request may release.
Malformed gate requests raise a validation error before touching the ledger.

## Receipts and reconciliation

Witness copies each inserted ledger row to `decisions/<audit_id>.json`. The
document preserves every ledger field: DynamoDB `S` and `N` values become their
stored strings, including numeric `at`. Stream deliveries and retries never
rewrite a receipt. Concurrent stream/schedule work must also leave exactly one
S3 version: use conditional `PutObject` with `If-None-Match: *`; a lost race
(412) is harmless. Witness treats `HeadObject` 404 as missing, other errors as
failures. It has `ListBucket` so a missing key can be reported as 404.

The access account has an enabled schedule in its own non-default group,
`rate(1 minute)`, flexible time window OFF, target Witness and input exactly
`{"source":"frostpass","operation":"reconcile"}`. Witness scans every page
of the ledger and creates only missing receipts. With the stream mapping
deleted, new decisions must be mirrored within 120 seconds **while the mapping
remains absent**. Deploy later restores exactly one mapping. Concurrent and
repeated reconciliations preserve all existing receipt versions and contents.

## IAM and resource-policy boundaries

Permissions must obey AWS semantics as well as live endpoint behavior:

1. Intake writes only `reports/` in its report bucket and performs only
   `kms:GenerateDataKey`. It cannot read or delete reports.
2. Approval Manager may only `PutItem`/`UpdateItem` in the approval table.
   `PutItem` uses `dynamodb:Attributes` to admit only the seven documented columns.
3. Gate may `GetItem` on approvals and ledger, `PutItem` on ledger limited with
   `dynamodb:Attributes` to its seven documented columns, and `sts:AssumeRole`.
   Gate cannot update/delete/batch-write ledger rows, modify approvals, directly
   read the report bucket, or decrypt without assuming the reader role.
4. Reader trust admits only Gate's execution role, including its endpoint
   session. Reader may `GetObject`/`GetObjectVersion` only under `reports/` and
   `kms:Decrypt`. Only Reader may read reports, including against same-account
   identities whose policies allow S3 reads. Enforce this with an explicit deny.
5. Callers can only `lambda:InvokeFunction` on their own function: custodian
   Intake; approver Approval Manager; reviewer Gate; outsider none. No caller
   has direct storage, KMS, STS, function configuration or function code access.
6. Witness reads the ledger stream (`DescribeStream`, `GetRecords`,
   `GetShardIterator`, `ListStreams`), scans only ledger, and reads/writes only
   `decisions/` in the receipt bucket. It lists that bucket. Only Witness gets
   these cross-account receipt permissions; it has no telemetry/key access.
   Archive deployer must retain `ListBucket`/`ListBucketVersions` for grading
   and cleanup; it can read receipts to inspect their content.
7. Both bucket policies deny `DeleteObject`, `DeleteObjectVersion`,
   `PutBucketVersioning` and `PutLifecycleConfiguration` to all principals
   except archive deployer. Use `NotPrincipal`, or `Principal: "*"` narrowed
   by negated `aws:PrincipalArn` conditions. Deployer can empty and destroy.
8. Key policy allows only Intake to `GenerateDataKey`, only Reader to
   `Decrypt`, both only with exactly `{shipment, sensor}` context keys, neither
   absent nor extra keys. No other crypto actions, including
   `GenerateDataKeyWithoutPlaintext`, `Encrypt`, `ReEncryptFrom` or
   `ReEncryptTo`, are permitted to anyone. An archive principal with `kms:*`
   and deployer still cannot use the key for cryptography. Archive deployer
   retains key policy, description, rotation and deletion administration.
9. Scheduler role may invoke only Witness. Its trust admits
   `scheduler.amazonaws.com` only when `aws:SourceAccount` is access and
   `aws:SourceArn` is **this deployment's schedule-group ARN**, not schedule
   ARN. Other groups, other accounts and absent source fields must fail.

The application does not call CloudWatch Logs APIs; broad logging or service
administrator permissions are unnecessary. No service role may administer IAM
or infrastructure. Do not grant capabilities outside these boundaries.

## Endpoint differences (Floci)

The evaluator matches `sts:AssumeRole` against `*`, KMS actions against
`arn:aws:kms:us-east-1:111111111111:key/*`. These identity-policy scopes are
accepted here; trust and key policies still identify the exact principals.
Sessions are `arn:aws:sts::<account>:assumed-role/<role-name>/floci-session`.
The endpoint ignores KMS key policies and rejects encryption-context IAM
conditions: put context rules in the key policy, keep KMS IAM allows unconditional.
It enforces `dynamodb:Attributes`. Bucket `NotPrincipal` read denies work, but
conditional denies and some mutation restrictions are not enforced; live
requests are supplemented by independent evaluation of deployed policies.
The endpoint may ignore list-event-source-mapping filters: filter returned
records by actual function and stream yourself, including during recovery.

Supported policy operators for grading are `String(Not)Equals`,
`String(Not)EqualsIgnoreCase`, `String(Not)Like`, `Arn(Not)Equals`,
`Arn(Not)Like`, `Bool`, `Null`, with `ForAllValues:`, `ForAnyValue:` and
`...IfExists`. Unsupported operators make their statement not apply.

## Deployment lifecycle (all scored)

- Names valid at prefix lengths 3 and 25; buckets globally unique.
- Fresh deployment is ready when the script returns. Normal redeploy retains
  bucket/table creation identities, key ID, reader role identity and resource
  identifiers. It keeps reports, decisions, receipts and caller users.
- Drift: restore deleted Gate, bucket policy, reader policies and schedule,
  and altered reader trust, without replacing storage. Restored Gate can
  release an old pinned report; wrong readers still cannot assume/read.
- Lost state: adopt all existing resources into local state, preserving all
  data, exactly one stream mapping and no duplicate keys/resources.
- Stale state: a first-deployment backup can be restored after mappings and
  caller keys changed. Drop stale IDs and adopt live replacements.
- Corrupted state: preserve unreadable file(s) under another name before
  recovering as from lost state. Do not silently delete the damaged evidence.
- After lost/stale/corrupt state, finish within 90 seconds. Rotate all four
  caller keys **make-before-break**: old keys active until replacement keys
  are durably published in mode-0600 manifest, then retire old keys. Each user
  ends with exactly its one manifest key. Normal redeploy need not rotate keys.
- A deploy may be SIGKILLed after its first role becomes visible. The next
  deploy adopts created resources not yet recorded in state and converges.
- Different prefixes run from separate copies, each at `/workspace/submission`,
  concurrently in the same accounts. Deploy/recover/destroy only its own copy;
  never adopt, mutate or delete another copy's mappings, keys, data or resources.
- Destroy removes functions, stream mappings, schedules/groups, roles/policies,
  caller keys/users, tables and all object versions/buckets. KMS key can remain
  pending deletion. No state is required to discover and remove owned resources.
- Preserve unrelated resources, including prefix-sharing bucket/table/role/user
  decoys and bootstrap identities. Prefix matching alone is not ownership.
- Redeploy after destroy must work under the same or a different prefix.
- Scripts must not print any caller secret. Manifest is exactly mode `0600`.

The manifest schema uses the SealRoom-compatible field names `bucket`,
`audit_bucket`, `evidence_key`, `archive_reader_role`, `tables.grants`,
`tables.audit`, and `reconciliation_schedule`. They identify telemetry,
receipts, encryption, reader, approvals, decisions and schedule respectively.
All required cloud resources are declared in `.tf` files and present in local
Terraform/OpenTofu state after deploy; labels are unrestricted.

## Scoring

35 checks total 100 points. Release failure caps score at 40; failed caller or
direct-storage isolation caps at 50; failed persist-before-release caps at 50.
Only 100 is a full pass. The author documentation enumerates weights, while
this contract specifies every scored behavior without prescribing a solution.
