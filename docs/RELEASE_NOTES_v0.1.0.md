# Draft release notes: Burp Framework Mapper v0.1.0

Draft notes for the planned initial public release of a local-only,
deterministic Burp Suite framework classifier. These notes do not indicate that
the version has been tagged or released; see `docs/BURP-VALIDATION.md`.

Highlights:

- Java 21 / Montoya 2026.7 suite tab and Audit-issue summary import;
- 86 reviewed, surface-aware correlations across CWE, OWASP, MITRE ATT&CK,
  D3FEND, ATLAS and F3;
- official FIRST CVSS 4.0 calculation;
- explainable confidence, sources and explicit limitations;
- JSON, CSV, Markdown and SARIF 2.1.0 local exports;
- catalog provenance manifest, unit/negative/security tests, static analysis,
  CodeQL and CycloneDX SBOM.

This extension does not generate traffic, exploit targets, send data externally,
prove adversary behavior or certify compliance. Review all imported text and
every correlation before use.

Requirements: Burp Suite with Montoya support and Java 21. Download the JAR and
verify it against `SHA256SUMS.txt` before loading it as a Java extension.

Manual validation evidence and current status are documented in
`docs/BURP-VALIDATION.md`.
