# Mapping methodology

The mapper is a constrained classifier, not a free-form inference engine. Every
possible output is a reviewed row in `mappings/correlations.json` with 12
required fields: framework, version, identifier, title, relation, CWE set,
phrases, surfaces, explanation, official URL, verification date and limitations.

## Relationship semantics

| Type | Meaning |
|---|---|
| `INPUT_ASSERTED` | The operator explicitly supplied the official identifier; the tool preserves the assertion but does not verify it. |
| `CURATED_CORRELATION` | A reviewed cross-reference based on a CWE or unambiguous concept. It is not equivalence. |
| `CONTEXTUAL_ENABLEMENT` | The weakness may enable or provide context for a behavior; it is not proof the behavior occurred. |
| `DEFENSIVE_MITIGATION` | A defensive technique can help prevent, detect or limit the condition; effectiveness is environment-dependent. |
| `OFFICIAL_REFERENCE` | The upstream framework itself embeds the referenced identifier. |

## Matching and confidence

Inputs are Unicode-normalized and compared case-insensitively with token
boundaries. Substrings such as `injection` are intentionally insufficient.
Signals add deterministic weight:

- exact normalized CWE: 0.50;
- explicit official identifier in the input: 0.45;
- first reviewed unambiguous phrase: 0.40;
- second phrase: 0.05;
- applicable surface: 0.10;
- technical context with exact CWE/identifier: 0.05.

The minimum is 0.50 and at least one strong signal is mandatory. Scores are
capped at 1.00. High confidence begins at 0.85, medium at 0.65, otherwise low.
Results are deduplicated by framework plus identifier and ordered by confidence.

Surface mismatch blocks cross-framework inference. The CWE taxonomy identity
may still be returned for an explicitly supplied CWE, and an explicitly supplied
official identifier is preserved as `INPUT_ASSERTED` even if the selected
surface differs so that the reviewer can correct the input.

## Guardrails against overclaiming

- A finding can legitimately return no mapping.
- ATT&CK, ATLAS, AADAPT and F3 results describe possible context, not observed
  tactics, techniques, digital-asset abuse, fraud activity or attribution.
- AADAPT inference is restricted to the `Digital Assets / Web3` surface. An
  explicitly supplied AADAPT identifier is preserved only as an analyst input
  assertion so an incorrect surface or identifier can be reviewed.
- D3FEND output is a defensive option, not evidence that a control exists or is
  effective.
- OWASP and verification-standard output is neither full coverage nor a
  compliance decision.
- CVSS measures technical severity under the vector assumptions; it is not
  business risk by itself.

Every result retains matched signals, explanation, limitations, framework
version, verification date and official URL to support reviewer challenge.
