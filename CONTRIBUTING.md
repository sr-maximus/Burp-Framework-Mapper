# Contributing

Contributions must preserve the project's defensive, local-only and
evidence-traceable scope. Do not submit exploit automation, active scanning,
credential attacks, target traffic generation, telemetry, remote data transfer,
client data or secrets.

## Development setup

Use Java 21 and the checked-in Maven Wrapper:

```bash
./mvnw clean verify spotbugs:check
python3 tools/update_catalogs.py
python3 tools/verify_jar.py target/burp-framework-mapper-0.1.0.jar
```

Before opening a pull request, also run
`python3 tools/update_catalogs.py --verify-upstream` when source metadata or the
catalog changes. Do not resolve a digest mismatch without inspecting the
official upstream content and terms.

## Catalog changes

Each new or changed mapping needs:

- exact official identifier, title, version and HTTPS source;
- a narrow applicable surface;
- one semantically accurate relation type;
- a reviewer-facing explanation and explicit limitation;
- unambiguous phrases or a supported CWE cross-reference;
- positive, ambiguous-negative and cross-surface tests;
- regenerated catalog, source-manifest updates when applicable, coverage count
  update and changelog entry.

Avoid broad keywords. ATT&CK, ATLAS and F3 mappings must never claim observed
activity. D3FEND mappings must never claim control implementation or efficacy.

## Pull requests

Keep changes focused and explain security/privacy effects. Include synthetic
examples only. All CI checks must pass, including tests, catalog validation,
SpotBugs, CodeQL, JAR inspection and SBOM generation. By contributing, you agree
that your contribution is licensed under Apache-2.0.
