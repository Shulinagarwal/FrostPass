"""Author-only focused crash recovery probe; run inside the verifier container."""
import sys
import argparse
sys.path.insert(0, "/tests")
from verify import Verification
from infrastructure_checks import runner

v = Verification()
parser = argparse.ArgumentParser()
parser.add_argument("--recover-copy", help="Optional existing interrupted runner copy")
parser.add_argument("--recover-prefix", default="srb")
options = parser.parse_args()
if options.recover_copy:
    runner("POST", f"/use-copy?name={options.recover_copy}")
    v.script_ok(v.run_script("deploy", options.recover_prefix), "recover existing partial-state deployment")
    manifest = v.reload_manifest()
    v.unique_live_parts(manifest, "partial-state recovery")
    v.full_flow(manifest, "partial-state recovery")
    inventory = v.inventory(manifest)
    v.script_ok(v.run_script("destroy", options.recover_prefix), "cleanup recovered copy")
    assert not v.leftovers(inventory)
    print("PASS existing interrupted copy recovered and cleaned")

for copy, prefix in (("d", "cpd"), ("e", "cpe"), ("f", "cpf")):
    runner("POST", f"/use-copy?name={copy}")
    crash = v.crash_deploy(prefix)
    assert crash["was_running"] and crash["created_before_kill"], crash
    v.script_ok(v.run_script("deploy", prefix), "resume interrupted deploy")
    manifest = v.reload_manifest()
    v.unique_live_parts(manifest, prefix)
    v.full_flow(manifest, prefix)
    inventory = v.inventory(manifest)
    v.script_ok(v.run_script("destroy", prefix), "cleanup crash probe")
    assert not v.leftovers(inventory)
    print(f"PASS interrupted deployment {prefix} recovered, functional and cleaned")
