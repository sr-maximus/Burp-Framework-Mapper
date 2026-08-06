# Risk interpretation

Treat the output as structured review support.

1. Validate that the underlying finding is real, in scope and reproducible under
   authorized conditions.
2. Review the selected surface, CWE and every matched signal.
3. Distinguish taxonomy, contextual behavior and defensive mitigation using the
   relationship type.
4. Validate the CVSS vector assumptions; do not inherit Burp severity as CVSS.
5. Add asset criticality, exposure, data sensitivity, exploitability evidence,
   compensating controls and business impact outside the mapper.
6. Reject or amend correlations that do not fit the system context.

`INPUT_ASSERTED` means only that a reviewer supplied an identifier.
`CONTEXTUAL_ENABLEMENT` does not mean a technique was observed.
`DEFENSIVE_MITIGATION` does not mean a control is deployed or effective.
OWASP/ASVS/MASVS correlations do not constitute compliance.

CVSS 4.0 is displayed separately from Burp severity and confidence because they
answer different questions. A technically high score can still have limited
business impact, and a lower technical score can be material on a critical
asset. Record both the vector and the business rationale.
