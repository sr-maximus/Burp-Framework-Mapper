# Burp Suite validation

## Current status for v0.1.0

Automated compilation, unit tests, catalog verification, JAR inspection and
static analysis are required by CI. A real Burp Suite UI session cannot be
honestly substituted by headless unit tests. The release checklist below must
be completed on a supported Burp build before v0.1.0 is tagged. Until then,
manual Burp validation is **pending** and no document should claim otherwise.

## Manual checklist

- [ ] Add the shaded JAR as a Java extension without load errors.
- [ ] Confirm the output log reports version 0.1.0 and local-only behavior.
- [ ] Open the **Framework Mapper** suite tab in light and dark Burp themes.
- [ ] Resize the main window; verify fields, split pane, table and tabs remain usable.
- [ ] Load the synthetic example and confirm analysis finishes without freezing the UI.
- [ ] Analyze a synthetic smart-contract reentrancy finding on **Digital Assets
      / Web3**; confirm `ADT3012.005` appears as contextual enablement and its
      explanation says this is not proof of adversary activity.
- [ ] Re-run the same text on **Web**; confirm no inferred AADAPT result appears.
- [ ] Confirm result sorting, all three filters, detail view and summary.
- [ ] Validate a correct and incorrect CVSS 4.0 vector.
- [ ] From an Audit issue, send one and multiple selected issue summaries.
- [ ] Confirm no request/response, cookie, header or body content appears.
- [ ] Verify query/fragment removal, secret redaction and imported-text truncation.
- [ ] Export JSON, CSV, Markdown and SARIF; validate UTF-8 and parseability.
- [ ] Confirm existing-file overwrite prompt and symlink refusal behavior.
- [ ] Remove and re-add the extension; confirm no persisted secret state.
- [ ] Unload the extension and confirm no background activity remains.

Record Burp edition/version, operating system, Java runtime, tester, date,
result and evidence below when executed. Do not include client data.

| Field | Value |
|---|---|
| Burp version/edition | Pending |
| Operating system | Pending |
| Java runtime | Pending |
| Tester/date | Pending |
| Result | Pending |
| Evidence | Pending |

## Uninstall

Remove the extension under **Extensions → Installed**. The extension creates no
database, network account, background daemon or persistent configuration.
Delete any reports separately according to their data-handling requirements.
