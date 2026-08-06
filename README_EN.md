# Burp Framework Mapper

Burp Framework Mapper is a defensive Burp Suite extension that locally and
deterministically correlates existing findings with CWE, OWASP, MITRE and CVSS
v4.0 references. It does not generate traffic, exploit targets, invoke remote
services, or present a correlation as evidence of adversary activity or
compliance.

## Authorship

**Burp Framework Mapper was conceived, created, and driven by Edwin Javier
Peñuela Camacho**, the project's creator and owner. CWE, OWASP, MITRE, FIRST,
and PortSwigger provide third-party frameworks, data, or interfaces; they do
not author, certify, approve, or sponsor this extension. See the comprehensive
[Spanish installation, configuration, and usage manual](docs/USER-MANUAL.md).

The extension supports manual input and Audit-issue context-menu import,
surface-aware mapping, explainable confidence, official source links, a
finding-by-framework correlation matrix, CVSS 4.0, and local JSON, CSV,
Markdown and SARIF 2.1.0 exports. The embedded catalog is a reviewed 86-rule
subset, not a complete mirror of any framework.

## Install

Use Burp Suite with Montoya support and Java 21. Until the
[manual Burp validation](docs/BURP-VALIDATION.md) is complete, build the JAR
from a reviewed checkout. Once a version is published, download it from
[Releases](https://github.com/sr-maximus/Burp-Framework-Mapper/releases), verify
its published SHA-256, then add it as a Java extension under **Extensions →
Installed**.

Build a reviewed checkout with:

```bash
./mvnw clean verify spotbugs:check
python3 tools/update_catalogs.py
python3 tools/verify_jar.py target/burp-framework-mapper-0.1.0.jar
```

## Privacy and interpretation

Burp import reads only the issue name, detail, remediation, base URL, severity
and confidence. It never reads HTTP request/response content or Collaborator
interactions. Imported text is redacted and bounded, but human review is still
required before export. See [privacy](docs/PRIVACY.md),
[mapping methodology](docs/MAPPING-METHODOLOGY.md),
[coverage](docs/FRAMEWORK-COVERAGE.md) and
[Burp validation](docs/BURP-VALIDATION.md).

Copyright © 2026 Edwin Javier Peñuela Camacho. Licensed under Apache-2.0.
Third-party frameworks and trademarks retain their own terms; see
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
