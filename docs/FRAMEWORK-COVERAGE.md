# Framework coverage

Catalog `2026.08.06-2`, planned for v0.1.0, contains 96 reviewed rows. These counts describe embedded
classification rules, not the total size or coverage percentage of each
framework.

| Framework | Version | Curated rows |
|---|---:|---:|
| CWE | 4.20 | 11 |
| OWASP Top 10 Web | 2025 | 10 |
| OWASP API Security Top 10 | 2023 | 10 |
| OWASP Mobile Top 10 | 2024 | 10 |
| OWASP MASVS | 2.1.0 | 8 |
| OWASP ASVS | 5.0.0 | 6 |
| OWASP GenAI/LLM Top 10 | 2025 | 10 |
| MITRE ATT&CK Enterprise | 19.1 | 3 |
| MITRE ATT&CK Mobile | 19.1 | 2 |
| MITRE ATT&CK ICS | 19.1 | 2 |
| MITRE D3FEND | 1.5.0 | 5 |
| MITRE ATLAS | 2026.07 | 5 |
| MITRE AADAPT | 2025.10.31-snapshot | 10 |
| MITRE Fight Fraud Framework (F3) | 1.1 | 4 |

The catalog prioritizes common Burp-relevant weaknesses and a small number of
carefully qualified behavioral and defensive relationships. It intentionally
does not bulk-import every ATT&CK, ATLAS, AADAPT, D3FEND, F3, ASVS or MASVS
object. The AADAPT version label identifies the pinned official website
deployment; MITRE has not presented it as a semantic framework release number.

To propose a row, provide an official source, exact version, applicable surface,
relationship type, clear explanation, limitations, positive test and at least
one negative or cross-surface test. A count change also requires updating this
document, the manifest and catalog tests.
