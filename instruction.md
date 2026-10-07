# Deploy FrostPass

Build the cloud infrastructure for a **cold-chain shipment release gateway**.
A carrier uploads encrypted sensor reports; a quality approver reviews a specific
report version and digest; a dispatcher requests a release certificate. The gate
must quarantine out-of-range or malformed telemetry even when a human approved
it. Decisions must survive retries, concurrent requests, infrastructure drift,
and loss of the deployment's local state.

The four supplied, immutable container images implement the application. Your
task is to provision and connect their AWS resources using Terraform or OpenTofu,
with narrow IAM permissions. Do not change the images or replace the application.

Read both files in `/workspace/contracts`:

- `runtime.md`: accounts, image URIs, payloads, permission boundaries, emulator
  differences, and the complete deployment/recovery/cleanup contract.
- `manifest.schema.json`: the exact manifest format. Resource identifiers must
  be real AWS API identifiers recorded in Terraform/OpenTofu state.

The AWS endpoint is `http://aws:4566`, region `us-east-1`. Deployment credentials
are in read-only `/workspace/config/terraform.tfvars.json`. Read them on every
script invocation. Terraform, OpenTofu, AWS CLI, Python, and providers listed in
the runtime contract are installed. The workspace has no Docker CLI or socket.

Write your submission here:

```text
/workspace/submission/
├── deploy.sh
├── destroy.sh
└── infra/
    └── one or more *.tf files
```

Both scripts run from `/workspace/submission`. They must use
`FROSTPASS_PREFIX` (3–25 characters, starting with a lowercase letter, remaining
characters lowercase letters, digits or hyphens). Optional diagnostics belong
in `/workspace/evidence`.

`deploy.sh` must create a ready deployment, safely redeploy, repair deleted or
altered resources, and recover from lost, stale, corrupted, or interrupted local
state without replacing retained storage or duplicating resources. It must run
Terraform/OpenTofu from `infra/` with local `infra/terraform.tfstate`. Every
required resource must be declared in `.tf` files; AWS-CLI-only provisioning is
insufficient. Discovery, import, duplicate cleanup and access-key retirement
through AWS APIs are allowed.

After success, atomically publish `/workspace/submission/manifest.json`, mode
`0600`, at most 1 MiB. Never print caller secrets. When recovery rotates keys,
the new manifest must be published before old keys are removed. Retain a copy
of any unreadable state before recovering.

`destroy.sh` must remove the whole deployment, including non-empty versioned
buckets and caller users, even with no local state. It must preserve pre-existing
resources sharing the prefix and other deployments. A KMS key may remain pending
deletion. Deploy must work again after destroy, including under another prefix.

Deployment normally has 720 seconds; recovery from lost, stale or corrupted
state has 90 seconds. Destroy has 900 seconds. Each script may produce at most
8 MiB combined output. The verifier runs scripts in a separate runner and tests
cloud behavior, policies, persistence and lifecycle. All scored behavior is
described in the public runtime contract; implementation choices and Terraform
resource labels are yours.
