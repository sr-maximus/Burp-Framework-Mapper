# Third-party notices

Burp Framework Mapper is licensed under Apache-2.0. The following third-party
materials and names retain their own terms. Inclusion means technical
interoperability or attribution; it does not imply sponsorship or endorsement.

## Runtime dependencies

- PortSwigger Montoya API 2026.7 is a compile-time `provided` dependency and is
  not bundled in the extension JAR. Use is governed by PortSwigger's terms.
- Jackson Databind and Jackson Java Time 2.22.1 are Apache-2.0.
- Mozilla Rhino 1.9.1 is MPL-2.0; its license is reproduced in
  [third_party/RHINO-MPL-2.0.txt](third_party/RHINO-MPL-2.0.txt).
- JUnit 5.14.4 and the build-tool dependencies are not part of the runtime JAR
  or its runtime SBOM.

## Vendored CVSS implementation

The JavaScript files under `src/main/resources/cvss/` come from the official
FIRST CVSS v4.0 reference calculator at commit
`c5b0d409ae9f57c44264c6ce5f27d89298e1d32a`. They retain the BSD-2-Clause
license reproduced in [third_party/FIRST-CVSS-LICENSE.txt](third_party/FIRST-CVSS-LICENSE.txt).
`bfm_wrapper.js` is project code under Apache-2.0.

## Framework content and marks

- OWASP Top 10, API Security, Mobile, MASVS, ASVS and GenAI/LLM identifiers and
  titles are attributed to OWASP and are used under the terms published by the
  respective official projects, generally Creative Commons Attribution-
  ShareAlike 4.0 for documentation content.
- MITRE ATT&CK is used under the ATT&CK Terms of Use. Required attribution:
  “MITRE ATT&CK®”.
- MITRE D3FEND™ content is attributed to The MITRE Corporation and is used
  under its published terms and repository license.
- MITRE ATLAS™ data is sourced from `mitre-atlas/atlas-data` under Apache-2.0.
- Fight Fraud Framework (F3) data is sourced from the Center for Threat-Informed
  Defense repository under Apache-2.0.
- CWE™ identifiers and names are sourced from MITRE's official CWE distribution
  and are used under the CWE Terms of Use.
- CVSS® is a registered trademark of FIRST.Org, Inc.

Exact source URLs, versions, verification dates and SHA-256 values are recorded
in [SOURCE_MANIFEST.json](SOURCE_MANIFEST.json).
