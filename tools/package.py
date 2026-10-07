"""Package source, contracts and sanitized validation evidence; exclude local credentials/state."""
import hashlib
import json
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parents[1]
FILES = ("README.md", "instruction.md", "reasoning.md", "task.toml",
         ".dockerignore", ".gitignore", ".gitattributes")
DIRECTORIES = ("environment", "solution", "tests", "tools")


def source_files():
    candidates = [ROOT / name for name in FILES]
    for name in DIRECTORIES:
        candidates.extend(path for path in (ROOT / name).rglob('*') if path.is_file())
    files = []
    for path in candidates:
        relative = path.relative_to(ROOT)
        if any(part in {"__pycache__", ".terraform", "local-config"} for part in relative.parts):
            continue
        if path.name.startswith('terraform.tfstate') or path.name in {
            'manifest.json', 'manifest.json.tmp', '.terraform.tfstate.lock.info', 'source-sha256.json'}:
            continue
        if path.suffix in {'.pyc', '.zip'}:
            continue
        files.append(path)
    return sorted(files)


def main():
    files = source_files()
    inventory = ROOT / 'tools/validation/source-sha256.json'
    inventory.parent.mkdir(parents=True, exist_ok=True)
    inventory.write_text(json.dumps({path.relative_to(ROOT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
                                     for path in files}, indent=2) + '\n', encoding='utf-8', newline='\n')
    files.append(inventory)
    output = ROOT / 'frostpass.zip'
    with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in files:
            entry = zipfile.ZipInfo('frostpass/' + path.relative_to(ROOT).as_posix())
            entry.create_system = 3
            entry.external_attr = (0o100755 if path.suffix == '.sh' else 0o100644) << 16
            entry.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(entry, path.read_bytes())
    with zipfile.ZipFile(output) as archive:
        assert archive.testzip() is None
        assert len(archive.namelist()) == len(set(archive.namelist()))
    print(f'Packaged {len(files)} files: {output} ({output.stat().st_size} bytes)')


if __name__ == '__main__':
    main()
