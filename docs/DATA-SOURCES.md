# Data sources and reproducibility

`SOURCE_MANIFEST.json` is the machine-readable source of truth. It records 16
official inputs with name, version, release date, URL, terms URL, license,
SHA-256, source object count, normalized row count and verification date.

The current upstream snapshots are CWE 4.20; OWASP Web 2025, API 2023, Mobile
2024, MASVS 2.1.0, ASVS 5.0.0 and GenAI/LLM 2025; MITRE ATT&CK 19.1, D3FEND
1.5.0, ATLAS 2026.07, AADAPT 2025.10.31-snapshot and F3 1.1; FIRST CVSS 4.0
reference calculator; and
PortSwigger Montoya API 2026.7.

## Reproduce and verify

```bash
python3 tools/generate_curated_catalog.py
python3 tools/update_catalogs.py
python3 tools/update_catalogs.py --verify-upstream
git diff --exit-code -- src/main/resources/mappings/correlations.json
```

The first command deterministically writes the reviewed normalized rows. The
second validates local schema, uniqueness, counts, HTTPS URLs and consistency
between both manifest copies. `--verify-upstream` downloads each exact official
artifact with a size cap and verifies its SHA-256. It does not silently update a
digest: upstream drift fails closed.

## Review process for upstream drift

1. Confirm the official publisher, version and license/terms.
2. Inspect the changed artifact and release notes.
3. Review every affected identifier, title, relationship, surface and caveat.
4. Update the generator and both manifest copies in the same change.
5. Regenerate, run unit/negative tests, static analysis and packaging checks.
6. Record the change in `CHANGELOG.md`.

Never bypass a digest mismatch by copying a new hash without content review.

## MITRE AADAPT source and terms

AADAPT does not currently expose a semantic release file equivalent to the
ATT&CK STIX releases. The manifest therefore pins the official Nuxt website
state for build `1761932274`, generated on 2025-10-31, and records all 68
technique/sub-technique identifiers found in that snapshot as the upstream
object count. Only 10 reviewed identifiers and titles are normalized.

The [AADAPT Terms of Use](https://aadapt.mitre.org/resources/terms/) require the
MITRE designation and notification of use. The designation is reproduced in
the root and embedded notices. The project owner has sent the use notification
to MITRE; the correspondence and contact details are not published.
