"""Runs an untrusted submission away from verifier code and credentials."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import threading
import time
from urllib.parse import parse_qs, urlsplit


SOURCE = Path("/runner/source/submission")
WORK = Path("/workspace/submission")
LOCK = threading.Lock()
PREPARED = False
MAX_FILES = 10000
MAX_BYTES = 256 * 1024 * 1024
MAX_OUTPUT_BYTES = 8 * 1024 * 1024
MAX_MANIFEST_BYTES = 1024 * 1024
TIMEOUTS = {"deploy.sh": 720, "destroy.sh": 900}
# Only non-secret identifying attributes are exposed from state.
IDENTIFIER_ATTRIBUTES = ("id", "arn", "name", "function_name", "bucket", "key_id", "uuid")
PREFIX_PATTERN = re.compile(r"^[a-z][a-z0-9-]{2,24}$")
# Caller secrets seen in any manifest; script output must never contain them.
KNOWN_SECRETS = set()


def remember_manifest():
    """Record caller secrets from the current manifest; return its file mode."""
    manifest = WORK / "manifest.json"
    if not manifest.is_file():
        return None
    try:
        callers = json.loads(manifest.read_text()).get("callers", {})
        KNOWN_SECRETS.update(
            caller["secret_access_key"] for caller in callers.values()
            if isinstance(caller, dict) and isinstance(caller.get("secret_access_key"), str)
            and len(caller["secret_access_key"]) >= 8
        )
    except (OSError, ValueError, AttributeError):
        pass
    return stat.S_IMODE(manifest.stat().st_mode)


def copy_submission(destination):
    """Validate the submitted files and copy them into destination."""
    if not SOURCE.is_dir():
        raise ValueError("submission artifact is missing")
    paths = list(SOURCE.rglob("*"))
    if len(paths) > MAX_FILES:
        raise ValueError("submission has too many entries")
    total_bytes = 0
    for path in paths:
        mode = path.lstat().st_mode
        if stat.S_ISLNK(mode) or not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
            raise ValueError("submission contains a symlink or special file")
        if path.is_file():
            total_bytes += path.stat().st_size
    if total_bytes > MAX_BYTES:
        raise ValueError("submission exceeds 256 MiB")
    destination.mkdir(parents=True, exist_ok=True)
    for path in paths:
        target = destination / path.relative_to(SOURCE)
        if path.is_dir():
            target.mkdir(parents=True, exist_ok=True)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)


def prepare():
    global PREPARED
    if PREPARED:
        return
    copy_submission(WORK)
    PREPARED = True


# Several deployments are operated from separate copies of the submission.
# The active copy always lives at /workspace/submission (a volume, so its
# contents are swapped rather than the directory renamed).
COPIES = Path("/workspace/.copies")
COPY_NAME = re.compile(r"^[a-z]{1,8}$")
ACTIVE = {"name": "a"}


def move_contents(source, destination):
    destination.mkdir(parents=True, exist_ok=True)
    for entry in list(source.iterdir()):
        shutil.move(str(entry), str(destination / entry.name))


def use_copy(name):
    prepare()
    if not COPY_NAME.fullmatch(name or ""):
        raise ValueError("invalid copy name")
    if BACKGROUND["process"] is not None and BACKGROUND["process"].poll() is None:
        raise ValueError("a background deploy is still running")
    if name != ACTIVE["name"]:
        stash = COPIES / ACTIVE["name"]
        if stash.exists():
            shutil.rmtree(stash)
        move_contents(WORK, stash)
        incoming = COPIES / name
        if incoming.exists():
            move_contents(incoming, WORK)
            shutil.rmtree(incoming)
        else:
            copy_submission(WORK)
        ACTIVE["name"] = name
    return {"active": ACTIVE["name"]}


def spawn(name, prefix=None):
    """Start a submission script in its own process group, so killing it also
    stops terraform/tofu children instead of leaving them on the state file."""
    prepare()
    if BACKGROUND["process"] is not None and BACKGROUND["process"].poll() is None:
        raise ValueError("a background deploy is still running")
    script = WORK / name
    if not script.is_file():
        raise ValueError(f"{name} is missing")
    environment = os.environ.copy()
    environment["FROSTPASS_BOOTSTRAP_TFVARS"] = "/workspace/config/terraform.tfvars.json"
    if prefix is not None:
        if not PREFIX_PATTERN.fullmatch(prefix):
            raise ValueError("invalid prefix")
        environment["FROSTPASS_PREFIX"] = prefix
    remember_manifest()
    return subprocess.Popen(
        ["/bin/bash", str(script)],
        cwd=WORK,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        errors="replace",
        start_new_session=True,
    )


def report(name, output, exit_code):
    if len(output.encode(errors="replace")) > MAX_OUTPUT_BYTES:
        return {"exit_code": 125, "output_tail": f"{name} produced more than 8 MiB of output"}
    mode = remember_manifest()
    leaked = any(secret in output for secret in KNOWN_SECRETS)
    tail = output[-6000:]
    for secret in KNOWN_SECRETS:
        tail = tail.replace(secret, "<redacted>")
    return {
        "exit_code": exit_code,
        "output_tail": tail,
        "secret_leak": leaked,
        "manifest_mode": mode,
    }


def execute(name, prefix=None):
    started = time.monotonic()
    process = spawn(name, prefix)
    try:
        output, _ = process.communicate(timeout=TIMEOUTS[name])
        exit_code = process.returncode
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        output, _ = process.communicate()
        exit_code = 124
        output += f"\n{name} timed out after {TIMEOUTS[name]} seconds"
    return {**report(name, output, exit_code), "duration": round(time.monotonic() - started, 1)}


SNAPSHOTS = Path("/workspace/.copies/.snapshots")


def state_files():
    return [p for p in WORK.rglob("*.tfstate*") if p.is_file()]


def snapshot_slot(slot):
    if not COPY_NAME.fullmatch(slot or ""):
        raise ValueError("invalid snapshot slot")
    return slot


def snapshot_state(slot="baseline"):
    """Keep a copy of the active copy's state files (a backup, as an operator would)."""
    prepare()
    target = SNAPSHOTS / ACTIVE["name"] / snapshot_slot(slot)
    if target.exists():
        shutil.rmtree(target)
    saved = []
    for path in state_files():
        destination = target / path.relative_to(WORK)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, destination)
        saved.append(str(path.relative_to(WORK)))
    return {"saved": sorted(saved)}


def restore_state(slot="baseline"):
    """Replace the active copy's state with the snapshot taken earlier."""
    prepare()
    source = SNAPSHOTS / ACTIVE["name"] / snapshot_slot(slot)
    if not source.is_dir():
        raise ValueError("no state snapshot for the active copy")
    for path in state_files():
        path.unlink()
    restored = []
    for path in source.rglob("*"):
        if path.is_file():
            destination = WORK / path.relative_to(source)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, destination)
            restored.append(str(path.relative_to(source)))
    return {"restored": sorted(restored)}


def corrupt_state():
    """Overwrite every state file with unreadable content (a torn write).

    .terraform/terraform.tfstate is the backend configuration, not state, so it
    is left alone."""
    prepare()
    damaged = []
    for path in state_files():
        if ".terraform" in path.relative_to(WORK).parts:
            continue
        path.write_bytes(b'{"version": 4, "terraform_version": "1.x", "serial": 7, "resources": [{"mode": "man')
        damaged.append(str(path.relative_to(WORK)))
    return {"corrupted": sorted(damaged)}


# A deploy started in the background so the verifier can kill it mid-run.
BACKGROUND = {"process": None, "chunks": [], "reader": None}


def start_background_deploy(prefix):
    process = spawn("deploy.sh", prefix)
    chunks = []

    def drain():
        for line in process.stdout:
            chunks.append(line)

    reader = threading.Thread(target=drain, daemon=True)
    reader.start()
    BACKGROUND.update(process=process, chunks=chunks, reader=reader)
    return {"started": True}


def kill_background_deploy():
    process = BACKGROUND["process"]
    if process is None:
        raise ValueError("no background deploy was started")
    was_running = process.poll() is None
    if was_running:
        os.killpg(process.pid, signal.SIGKILL)
    process.wait()
    BACKGROUND["reader"].join(timeout=10)
    result = report("deploy.sh", "".join(BACKGROUND["chunks"]), process.returncode)
    BACKGROUND.update(process=None, chunks=[], reader=None)
    return {**result, "was_running": was_running}


def lose_state():
    """Simulate losing local Terraform/OpenTofu state: delete every state file."""
    prepare()
    removed = []
    for path in WORK.rglob("*.tfstate*"):
        if path.is_file():
            path.unlink()
            removed.append(str(path.relative_to(WORK)))
    return {"removed": sorted(removed)}


def state_summary():
    prepare()
    states = []
    for path in WORK.rglob("terraform.tfstate"):
        if path.is_file():
            try:
                data = json.loads(path.read_text())
                identifiers = []
                for entry in data.get("resources", []):
                    if entry.get("mode") != "managed":
                        continue
                    for instance in entry.get("instances", []):
                        attributes = instance.get("attributes") or {}
                        identifiers.extend(
                            attributes[name] for name in IDENTIFIER_ATTRIBUTES
                            if isinstance(attributes.get(name), str) and attributes[name]
                        )
                states.append({
                    "path": str(path.relative_to(WORK)),
                    "types": [entry.get("type") for entry in data.get("resources", [])],
                    "identifiers": sorted(set(identifiers)),
                })
            except (OSError, ValueError):
                continue
    return {"states": states}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, _format, *_args):
        return

    def reply(self, status, payload):
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        try:
            if self.path == "/health":
                return self.reply(200, {"status": "ok"})
            if self.path == "/manifest":
                prepare()
                manifest = WORK / "manifest.json"
                if not manifest.is_file():
                    return self.reply(404, {"error": "manifest missing"})
                if manifest.stat().st_size > MAX_MANIFEST_BYTES:
                    return self.reply(413, {"error": "manifest exceeds 1 MiB"})
                return self.reply(200, json.loads(manifest.read_text()))
            if self.path == "/state-summary":
                return self.reply(200, state_summary())
            if self.path == "/state-backups":
                prepare()
                return self.reply(200, {"backups": [
                    {"path": str(p.relative_to(WORK)), "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}
                    for p in WORK.rglob("*.unreadable-*") if p.is_file()
                ]})
            if self.path == "/deploy-status":
                process = BACKGROUND["process"]
                return self.reply(200, {"running": process is not None and process.poll() is None})
            self.reply(404, {"error": "not found"})
        except Exception as error:
            self.reply(500, {"error": str(error)})

    def do_POST(self):
        with LOCK:
            try:
                url = urlsplit(self.path)
                prefix = parse_qs(url.query).get("prefix", [None])[0]
                if url.path == "/deploy":
                    return self.reply(200, execute("deploy.sh", prefix))
                if url.path == "/destroy":
                    return self.reply(200, execute("destroy.sh", prefix))
                if url.path == "/lose-state":
                    return self.reply(200, lose_state())
                if url.path == "/snapshot-state":
                    return self.reply(200, snapshot_state(parse_qs(url.query).get("slot", ["baseline"])[0]))
                if url.path == "/restore-state":
                    return self.reply(200, restore_state(parse_qs(url.query).get("slot", ["baseline"])[0]))
                if url.path == "/corrupt-state":
                    return self.reply(200, corrupt_state())
                if url.path == "/use-copy":
                    return self.reply(200, use_copy(parse_qs(url.query).get("name", [None])[0]))
                if url.path == "/deploy-start":
                    return self.reply(200, start_background_deploy(prefix))
                if url.path == "/deploy-kill":
                    return self.reply(200, kill_background_deploy())
                self.reply(404, {"error": "not found"})
            except Exception as error:
                self.reply(500, {"error": str(error)})


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8088), Handler).serve_forever()
