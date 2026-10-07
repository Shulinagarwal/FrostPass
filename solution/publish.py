"""Durably publish credentials before retiring the old caller access keys."""
import json
import os
from pathlib import Path
import sys

target = Path(sys.argv[1])
payload = json.load(sys.stdin)
temporary = target.with_suffix('.json.tmp')
fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
os.fchmod(fd, 0o600)
with os.fdopen(fd, 'w') as stream:
    json.dump(payload, stream, indent=2)
    stream.write('\n')
    stream.flush()
    os.fsync(stream.fileno())
os.replace(temporary, target)
directory = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(directory)
finally:
    os.close(directory)
