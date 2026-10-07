# FrostPass validation

Validated on **6 October 2026** using a Linux Docker engine on the author host.

| Check | Result |
| --- | --- |
| Final clean reference trial | **35/35 scored groups; 100/100 points** |
| Lost-state recovery | 14.5 seconds; objective 90 seconds |
| Restored stale-state recovery | 25.9 seconds; objective 90 seconds |
| Corrupted-state recovery | 14.4 seconds; exact damaged bytes preserved |
| SIGKILL during second deployment | Passed; resources existed before kill |
| Recovery of the exact partial-state failure copy | Passed, release verified, cleanup verified |
| Three additional independent SIGKILL trials | All recovered, released and cleaned up |
| Offline quality checks | 16 passed |
| Five deliberately broken application variants | All rejected by workload assertions |
| Shipped smoke tool against real local AWS APIs | Passed; its resources removed |
| Solver, runner and verifier images | Built successfully |
| Solver image isolation | Public contracts present; tests, solution, Docker CLI/socket absent |
| Shell scripts | Bash syntax checked |
| Python, TOML and JSON | Valid; application/contract/bootstrap copies agree |
| Same-prefix and changed-prefix redeployment after destroy | Both passed |

The final black-box results are in [reference-report.json](reference-report.json).
The packaged files are fingerprinted in `source-sha256.json`.

The offline mutation cases are average-only temperature checks, checking only
the final sample, omitting the reviewed digest, unconditional ledger writes,
and allowing release after a failed ledger write. These establish that the
assertions reject common incorrect algorithms. They are not model evaluations.

The first test iteration found a 26-character verifier prefix caused by the
new project name; it was corrected to a valid 25-character prefix. Repeated
crash testing also exposed a partial-key-state recovery bug: the helper removed
addresses absent from state. The final helper removes only recorded addresses,
and the offline regression covers empty, partial and complete key states.

Reproduce the full reference trial with the README commands. Use a fresh
Compose project and clean only the stack created for your own run. The task
uses the pinned Floci AWS emulator and does not touch production AWS accounts.
Model success/failure rates have not been measured; the benchmark is intended
to be difficult and fair, without guaranteeing universal model failure.
