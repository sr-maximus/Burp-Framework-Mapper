#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Validate curated catalogs and optionally verify pinned upstream sources."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "SOURCE_MANIFEST.json"
CATALOG = ROOT / "src/main/resources/mappings/correlations.json"
EMBEDDED_MANIFEST = ROOT / "src/main/resources/catalogs/SOURCE_MANIFEST.json"
MAX_SOURCE_BYTES = 150 * 1024 * 1024
CATALOG_VERSION = "2026.08.06-1"

REQUIRED_COLUMNS = {
    "framework", "frameworkVersion", "identifier", "title", "relationType",
    "cweIds", "surfaces", "keywords", "explanation", "officialUrl",
    "verifiedDate", "limitations",
}
RELATION_TYPES = {
    "INPUT_ASSERTED", "CURATED_CORRELATION", "CONTEXTUAL_ENABLEMENT",
    "DEFENSIVE_MITIGATION", "OFFICIAL_REFERENCE",
}
SURFACES = {"WEB", "API", "MOBILE", "AI_ML_LLM", "ENTERPRISE", "ICS_OT", "FRAUD", "GENERIC_UNKNOWN"}


def load_json(path: Path):
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def validate_local() -> tuple[dict, list[dict]]:
    manifest = load_json(MANIFEST)
    embedded_manifest = load_json(EMBEDDED_MANIFEST)
    catalog = load_json(CATALOG)
    if manifest != embedded_manifest:
        raise ValueError("root and embedded SOURCE_MANIFEST copies differ")
    if manifest.get("schemaVersion") != "1.0.0":
        raise ValueError("unsupported SOURCE_MANIFEST schemaVersion")
    if manifest.get("catalogVersion") != CATALOG_VERSION:
        raise ValueError("unsupported or missing catalogVersion")
    sources = manifest.get("sources")
    if not isinstance(sources, list) or not sources:
        raise ValueError("SOURCE_MANIFEST.sources must be a non-empty array")

    normalized_total = 0
    for source in sources:
        for field in ("name", "version", "queriedAt", "officialUrl", "termsUrl", "license", "sha256", "domain"):
            if not str(source.get(field, "")).strip():
                raise ValueError(f"manifest source field {field} is empty for {source.get('name')}")
        require_https(source["officialUrl"])
        require_https(source["termsUrl"])
        digest = source["sha256"]
        if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
            raise ValueError(f"invalid SHA-256 for {source['name']}")
        if int(source.get("sourceObjectCount", -1)) < 0:
            raise ValueError(f"invalid sourceObjectCount for {source['name']}")
        normalized_total += int(source.get("normalizedRuleCount", 0))

    if not isinstance(catalog, list) or not catalog:
        raise ValueError("correlation catalog must be a non-empty array")
    seen = set()
    for index, row in enumerate(catalog, start=1):
        columns = set(row.keys())
        if columns != REQUIRED_COLUMNS:
            raise ValueError(f"catalog row {index} schema mismatch: missing={sorted(REQUIRED_COLUMNS - columns)}, extra={sorted(columns - REQUIRED_COLUMNS)}")
        for field in ("framework", "frameworkVersion", "identifier", "title", "relationType",
                      "explanation", "officialUrl", "verifiedDate", "limitations"):
            if not str(row[field]).strip():
                raise ValueError(f"catalog row {index} has empty {field}")
        require_https(row["officialUrl"])
        if row["relationType"] not in RELATION_TYPES:
            raise ValueError(f"catalog row {index} has invalid relationType")
        if not isinstance(row["surfaces"], list) or not row["surfaces"] or not set(row["surfaces"]).issubset(SURFACES):
            raise ValueError(f"catalog row {index} has invalid surfaces")
        key = (row["framework"], row["identifier"])
        if key in seen:
            raise ValueError(f"duplicate catalog key: {key}")
        seen.add(key)
    if normalized_total != len(catalog):
        raise ValueError(
            f"manifest normalizedRuleCount total {normalized_total} does not equal catalog rows {len(catalog)}")
    return manifest, catalog


def require_https(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        raise ValueError(f"URL must use HTTPS: {url}")


def verify_upstream(manifest: dict) -> None:
    opener = urllib.request.build_opener(urllib.request.HTTPRedirectHandler())
    for source in manifest["sources"]:
        host = urlparse(source["officialUrl"]).hostname
        user_agent = "Apache-Maven/3.9.16" if host == "repo.maven.apache.org" else "Burp-Framework-Mapper-catalog-verifier/0.1.0"
        request = urllib.request.Request(source["officialUrl"], headers={"User-Agent": user_agent}, method="GET")
        digest = hashlib.sha256()
        count = 0
        with opener.open(request, timeout=45) as response:
            require_https(response.geturl())
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                count += len(chunk)
                if count > MAX_SOURCE_BYTES:
                    raise ValueError(f"source exceeds size limit: {source['name']}")
                digest.update(chunk)
        actual = digest.hexdigest()
        if actual != source["sha256"]:
            raise ValueError(
                f"upstream digest changed for {source['name']}: expected {source['sha256']}, got {actual}")
        print(f"verified {source['name']} {source['version']} ({count} bytes)")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--verify-upstream", action="store_true",
                        help="download pinned official sources and verify SHA-256")
    args = parser.parse_args()
    try:
        manifest, catalog = validate_local()
        print(f"validated {len(catalog)} normalized catalog rows and {len(manifest['sources'])} sources")
        if args.verify_upstream:
            verify_upstream(manifest)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"catalog validation failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
