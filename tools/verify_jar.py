#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fail-closed inspection of the shaded Burp extension JAR."""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import pathlib
import sys
import zipfile


REQUIRED = {
    "io/github/srmaximus/burpfm/BurpFrameworkMapperExtension.class",
    "io/github/srmaximus/burpfm/ui/MapperPanel.class",
    "mappings/correlations.json",
    "catalogs/SOURCE_MANIFEST.json",
    "schema/analysis-report.schema.json",
    "cvss/cvss_score.js",
    "cvss/bfm_wrapper.js",
    "META-INF/NOTICE-BURP-FRAMEWORK-MAPPER.txt",
    "META-INF/LICENSE-FIRST-CVSS.txt",
    "META-INF/LICENSE-RHINO-MPL-2.0.txt",
    "META-INF/THIRD-PARTY-NOTICES.md",
}
FORBIDDEN_PREFIXES = ("burp/api/montoya/", "org/junit/", "org/apache/maven/")


def verify(path: pathlib.Path) -> str:
    if not path.is_file() or path.is_symlink():
        raise ValueError("JAR must be a regular non-symlink file")
    if path.stat().st_size > 25 * 1024 * 1024:
        raise ValueError("JAR unexpectedly exceeds 25 MiB")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    with zipfile.ZipFile(path) as archive:
        bad_member = archive.testzip()
        if bad_member:
            raise ValueError(f"corrupt JAR member: {bad_member}")
        names = archive.namelist()
        missing = sorted(REQUIRED.difference(names))
        if missing:
            raise ValueError(f"missing required JAR entries: {missing}")
        forbidden = sorted(name for name in names if name.startswith(FORBIDDEN_PREFIXES))
        if forbidden:
            raise ValueError(f"provided/test/build classes leaked into JAR: {forbidden[:5]}")
        duplicates = sorted(name for name, count in Counter(names).items() if count > 1)
        if duplicates:
            raise ValueError(f"duplicate JAR entries: {duplicates[:5]}")
        manifest = archive.read("META-INF/MANIFEST.MF").decode("utf-8", "strict")
        if "Implementation-Version: 0.1.0" not in manifest:
            raise ValueError("missing or incorrect implementation version")
    return digest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("jar", type=pathlib.Path)
    arguments = parser.parse_args()
    try:
        digest = verify(arguments.jar.resolve())
    except (OSError, ValueError, zipfile.BadZipFile) as error:
        print(f"JAR validation failed: {error}", file=sys.stderr)
        return 1
    print(f"verified {arguments.jar}: sha256={digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
