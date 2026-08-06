// SPDX-License-Identifier: Apache-2.0
package io.github.srmaximus.burpfm.importer;

import burp.api.montoya.scanner.audit.issues.AuditIssue;
import io.github.srmaximus.burpfm.engine.CweParser;
import io.github.srmaximus.burpfm.engine.SensitiveDataRedactor;
import io.github.srmaximus.burpfm.model.FindingInput;
import io.github.srmaximus.burpfm.model.Surface;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Imports only the small, documented issue summary fields. HTTP messages,
 * Collaborator interactions and other potentially sensitive Burp objects are
 * deliberately never accessed.
 */
public final class BurpIssueImporter {
    public List<FindingInput> importIssues(List<AuditIssue> issues) {
        if (issues == null || issues.isEmpty()) {
            return List.of();
        }
        List<FindingInput> findings = new ArrayList<>(issues.size());
        for (AuditIssue issue : issues) {
            if (issue != null) {
                findings.add(importIssue(issue));
            }
        }
        return List.copyOf(findings);
    }

    public FindingInput importIssue(AuditIssue issue) {
        Objects.requireNonNull(issue, "issue");
        String title = SensitiveDataRedactor.redact(issue.name());
        String detail = SensitiveDataRedactor.redact(issue.detail());
        String remediation = SensitiveDataRedactor.redact(issue.remediation());
        String combined = title + "\n" + detail;
        return new FindingInput(
                null,
                title,
                detail,
                remediation.isBlank() ? "Imported from Burp issue summary." : "Burp remediation: " + remediation,
                SensitiveDataRedactor.safeAsset(issue.baseUrl()),
                inferSurface(issue.baseUrl()),
                CweParser.extractExplicit(combined),
                "",
                "",
                "",
                String.valueOf(issue.severity()),
                String.valueOf(issue.confidence()),
                List.of("burp-import"),
                "burp-audit-issue");
    }

    static Surface inferSurface(String baseUrl) {
        if (baseUrl == null || baseUrl.isBlank()) {
            return Surface.GENERIC_UNKNOWN;
        }
        String value = baseUrl.toLowerCase(java.util.Locale.ROOT);
        return value.startsWith("http://") || value.startsWith("https://")
                ? Surface.WEB
                : Surface.GENERIC_UNKNOWN;
    }
}
