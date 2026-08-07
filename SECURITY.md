# Security policy

## Supported versions

The latest published release receives security fixes. Pre-release code on
`main` is not a supported release.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting feature for this repository. Do
not open a public issue containing an exploit, secret, customer finding, Burp
project data or sensitive path. Include the affected version, impact, minimal
synthetic reproduction and suggested mitigation if available.

The maintainer will acknowledge a complete report as soon as practical,
validate it, coordinate a fix and publish credit if requested and appropriate.
Do not test against systems you do not own or lack explicit authorization to
assess.

## Security properties worth preserving

- no network, telemetry or background target traffic;
- Montoya remains `provided` and absent from the shaded JAR;
- issue import never accesses HTTP messages or Collaborator interactions;
- untrusted text is bounded/redacted and exports are injection-aware;
- catalog/source changes fail closed on schema, count or digest drift;
- inferred AADAPT results remain isolated to the `Digital Assets / Web3`
  surface and are qualified as context, never evidence of adversary activity;
- CVSS input cannot access Java classes through Rhino;
- framework output is qualified, explainable and subject to human review.

See [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) for the detailed model.
