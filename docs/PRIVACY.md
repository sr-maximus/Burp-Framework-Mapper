# Privacy

All classification, CVSS calculation and export happens inside the Burp process.
The extension contains no HTTP client, telemetry, analytics, remote model,
automatic update or cloud integration.

## Burp issue import

The importer accesses only:

- issue name;
- issue detail;
- remediation text;
- base URL;
- Burp severity;
- Burp confidence.

It never accesses request/response objects, raw headers or bodies, cookies,
Collaborator interactions or session state. Query strings and fragments are
removed from the base URL. Common authorization/cookie/secret patterns are
redacted, active script/style blocks are removed, and each imported text field
is bounded to 4,000 characters.

Redaction is defense in depth, not a complete data-loss-prevention system.
Finding summaries can contain organization names, internal hosts, identifiers
or unusual secrets. Review every field before analysis and especially before
export. Store reports according to the assessed system's handling rules.

Exports require an explicit local file selection. Existing targets are not
overwritten without confirmation, symlink targets are rejected, and CSV cells
that could be interpreted as formulas are neutralized.
