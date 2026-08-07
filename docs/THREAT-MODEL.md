# Threat model

## Assets

- confidentiality of Burp finding summaries and local report content;
- integrity of correlations, catalog provenance and CVSS scores;
- availability and stability of the Burp UI;
- reviewer trust in the meaning and limitations of mappings.

## Trust boundaries

Untrusted content enters through manual fields or Burp issue summaries. Vendored
catalog and CVSS resources enter through the build/release supply chain. Local
filesystem paths enter through the export chooser. Montoya is supplied by Burp
at runtime.

## Principal threats and controls

| Threat | Controls | Residual risk |
|---|---|---|
| Secret leakage from issue text | minimal-field import, regex redaction, URL query removal, length limits, no network, human warning | uncommon secret formats or sensitive context can remain |
| Active content in reports | script/style removal on import; HTML angle escaping in Markdown; JSON/SARIF serializers | downstream viewers may have their own unsafe behavior |
| CSV formula injection | prefix dangerous leading characters with an apostrophe | spreadsheet-specific import options may vary |
| Path/symlink overwrite | normalized path, existing parent, explicit overwrite, symlink refusal, atomic move | local user still chooses the destination |
| Catalog tampering or drift | SHA-256 manifest, HTTPS, source-size cap, deterministic generator, CI drift check, review | upstream publisher compromise is not eliminated |
| Arbitrary Java access through CVSS JS | bounded canonical parser, safe Rhino standard objects, class shutter denial, no dynamic script input | vulnerabilities in Rhino remain a dependency risk |
| UI freeze or resource exhaustion | bounded fields, immutable data, background analysis, finite catalog | exceptionally constrained Burp processes may still slow |
| Overclaiming/false mapping | surface isolation, exact signals, minimum threshold, relation types, explanations, caveats, no-match outcome | reviewer error remains possible |

## Explicit non-goals

The extension does not test a target, verify a Burp issue, discover an attacker,
prove ATT&CK/ATLAS/AADAPT/F3 activity, certify OWASP/ASVS/MASVS compliance or compute
complete enterprise risk.
