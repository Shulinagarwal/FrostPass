# FrostPass

A hard Dev Cloud infrastructure benchmark for a refrigerated freight release
gateway. It follows the SealRoom archive's `environment/`, `solution/`, `tests/`,
and `tools/` layout, with a complete public contract, immutable application
images, a Terraform reference solution, and an isolated black-box verifier.

See [validation results](tools/validation/VALIDATION.md) for the reference score,
recovery timings, mutation checks and environment verification.

The new workload adds strict sensor validation, version/digest binding,
conditional durable decision recording, concurrent request-ID collisions and
stable historical replay. Deployment recovery remains a core part of the task.

| Material | Purpose |
| --- | --- |
| `instruction.md` | Solver's task |
| `environment/workspace/contracts/` | Public runtime and manifest schema |
| `environment/application/` | Four supplied Lambda image sources |
| `environment/Dockerfile`, `docker-compose.yaml` | Solver environment and local AWS emulator |
| `solution/` | Complete author reference; never copied into solver image |
| `tests/verify.py` | 35 scored capability groups, 100 points |
| `tests/infrastructure_checks.py` | Cloud policy, state recovery and cleanup assertions |
| `tests/runtime/runner.py` | Executes submission away from verifier code |
| `reasoning.md` | Design rationale, weights and failure cases |
| `tools/` | Local smoke, harness quality checks and validation instructions |

Full author validation requires a Linux Docker engine with Compose and access
to the pinned build dependencies. All AWS operations stay inside the local
Floci stack; no production AWS account is involved.

```powershell
docker compose -p frostpass-check -f tests/docker-compose.yaml up -d --build
docker cp solution/. frostpass-check-main-1:/workspace/submission/
docker exec frostpass-check-main-1 bash /tests/test.sh
docker cp frostpass-check-main-1:/logs/verifier/report.json ./report.json
docker compose -p frostpass-check -f tests/docker-compose.yaml down -v
```

Use a fresh Compose project name for each independent trial. Successful
reference execution should score 100. `reward.json`, `reward.txt` and a detailed
report are written to `/logs/verifier`. A score of 100 is a full pass; partial
scores reveal the failed capabilities. The scripts enforce output and runtime
limits and test prefix lengths 25 and 3.

For solver runs, use `environment/docker-compose.yaml`; only the public
contracts are copied into `/workspace`. For a quick functional probe of an
already deployed system, run `tools/smoke.py` with `FROSTPASS_MANIFEST` pointing
to its mode-0600 manifest. This probe complements the full verifier.

Offline author checks need only Python 3.11 or newer:

```text
python tools/check_project.py
```

They run 16 checks, including five deliberate workload mutations; fake SDK
imports and a conditional-write database isolate pure workload behavior. The
Docker verifier tests actual encryption, AWS calls and infrastructure recovery.

`tools/crash_probe.py` runs three additional interrupted deployments from fresh
runner copies. Copy it into an existing verifier container and run it with
Python there. To recover a specific interrupted copy first, supply
`--recover-copy <name> --recover-prefix <prefix>`.

`python tools/package.py` produces `frostpass.zip` and a SHA-256 source inventory.
It excludes local state, manifests, credentials, caches and the original archive.

The archive informed the harness architecture and lifecycle fixtures. The
FrostPass business logic, its public specification, replay/concurrency tests,
and author documentation are new. Difficulty is testable; no claim that every
model must fail is made without actual model evaluations.
