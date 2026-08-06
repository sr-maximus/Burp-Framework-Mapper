# Burp Framework Mapper

Burp Framework Mapper is a defensive Burp Suite extension that turns existing
Burp Audit or manually entered findings into an explainable, exportable
technical map. It correlates locally with CWE; OWASP Web, API, Mobile, MASVS,
ASVS and GenAI/LLM; MITRE ATT&CK Enterprise, Mobile and ICS; MITRE D3FEND,
ATLAS and Fight Fraud Framework (F3); and calculates CVSS 4.0 with FIRST's
official algorithm. It does not generate traffic, exploit targets, invoke
remote services, or present a correlation as evidence of adversary activity
or compliance.

## Authorship

**Burp Framework Mapper was conceived, created, and driven by Edwin Javier
Peñuela Camacho**, the project's creator and owner. CWE, OWASP, MITRE, FIRST,
and PortSwigger provide third-party frameworks, data, or interfaces; they do
not author, certify, approve, or sponsor this extension. See the comprehensive
[Spanish installation, configuration, and usage manual](docs/USER-MANUAL.md).

## What it actually provides

The curated catalog contains 86 explainable rules: CWE 4.20 (11); OWASP Web
2025 (10), API 2023 (10), Mobile 2024 (10), MASVS 2.1.0 (8), ASVS 5.0.0 (6)
and GenAI/LLM 2025 (10); ATT&CK 19.1 Enterprise (3), Mobile (2) and ICS (2);
D3FEND 1.5.0 (5); ATLAS 2026.07 (5); and F3 1.1 (4). Results preserve the
relationship type, deterministic confidence, matched signals, rationale,
official source, verification date, limitations and surface. Filters, a
finding-by-framework matrix and JSON/CSV/Markdown/SARIF exports help AppSec,
authorized testing, vulnerability management, defensive architecture and risk
teams share one traceable view without turning correlation into certification.

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
