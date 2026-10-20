#!/usr/bin/env python3
"""Inspect exact runtime contents of every optional Composer adapter archive."""
import json
from pathlib import Path
import subprocess
import tempfile
import zipfile

root = Path(__file__).resolve().parents[1]
packages = {
    "psr3": "sohophp/sosecurity-psr3",
    "psr15": "sohophp/sosecurity-psr15",
    "oidc": "sohophp/sosecurity-oidc",
    "webauthn": "sohophp/sosecurity-webauthn",
}
for name, identity in packages.items():
    package = root / "integrations" / name
    manifest = json.loads((package / "composer.json").read_text(encoding="utf-8"))
    if manifest.get("name") != identity or manifest.get("license") != "MIT":
        raise RuntimeError("Invalid optional package identity or license: " + name)
    if (package / "LICENSE").read_bytes() != (root / "LICENSE").read_bytes():
        raise RuntimeError("Optional package license differs from the core license: " + name)
    validate = ["composer", "validate", "--strict", "--working-dir=" + str(package)]
    if name == "oidc":
        # This adapter intentionally pins the audited upstream 1.0.2 release.
        if manifest.get("require", {}).get("jumbojett/openid-connect-php") != "1.0.2":
            raise RuntimeError("OIDC archive verification requires the reviewed upstream pin")
        validate.append("--no-check-all")
    subprocess.run(validate,
                   check=True, capture_output=True, text=True)
    sources = {str(path.relative_to(package)) for path in (package / "src").rglob("*.php")}
    if not sources:
        raise RuntimeError("Optional package has no runtime sources: " + name)
    expected = {"composer.json", "README.md", "LICENSE"} | sources
    if name == "webauthn":
        expected |= {"schema.sqlite.sql", "schema.mysql.sql",
                     "migrations/001_generation.sqlite.sql", "migrations/001_generation.mysql.sql"}
    with tempfile.TemporaryDirectory(prefix="sosecurity-" + name + "-archive-") as directory:
        subprocess.run(["composer", "archive", "--format=zip", "--dir=" + directory,
                        "--file=adapter", "--no-interaction"],
                       cwd=package, check=True, capture_output=True, text=True)
        with zipfile.ZipFile(Path(directory, "adapter.zip")) as archive:
            names = archive.namelist()
            if len(names) != len(expected) or set(names) != expected:
                raise RuntimeError("Unexpected optional package archive contents: " + name)
            if archive.read("LICENSE") != (root / "LICENSE").read_bytes():
                raise RuntimeError("Optional package archive omitted the MIT text: " + name)
            for source in sources:
                if archive.read(source) != (package / source).read_bytes():
                    raise RuntimeError("Optional package archive changed source bytes: " + name)
    print("PASS optional archive: " + name + "; exact runtime contents and MIT license")
