// SPDX-License-Identifier: Apache-2.0
package io.github.srmaximus.burpfm.importer;

import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import io.github.srmaximus.burpfm.model.Surface;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Proxy;
import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BurpIssueImporterTest {
    @Test
    void importsOnlySummaryFieldsAndRedactsSecrets() {
        Set<String> invoked = new HashSet<>();
        AuditIssue issue = (AuditIssue) Proxy.newProxyInstance(
                AuditIssue.class.getClassLoader(), new Class<?>[]{AuditIssue.class}, (proxy, method, arguments) -> {
                    invoked.add(method.getName());
                    return switch (method.getName()) {
                        case "name" -> "SQL injection CWE-89";
                        case "detail" -> "Authorization: Bearer abcdefghijk";
                        case "remediation" -> "Use parameterized statements";
                        case "baseUrl" -> "https://example.invalid/a?session=secret";
                        case "severity" -> AuditIssueSeverity.HIGH;
                        case "confidence" -> AuditIssueConfidence.CERTAIN;
                        default -> throw new AssertionError("Unexpected sensitive method access: " + method.getName());
                    };
                });

        var finding = new BurpIssueImporter().importIssue(issue);

        assertEquals("https://example.invalid/a", finding.asset());
        assertEquals(Surface.WEB, finding.surface());
        assertEquals(java.util.List.of("CWE-89"), finding.cweIds());
        assertFalse(finding.description().contains("abcdefghijk"));
        assertFalse(invoked.contains("requestResponses"));
        assertFalse(invoked.contains("collaboratorInteractions"));
        assertTrue(invoked.containsAll(Set.of("name", "detail", "remediation", "baseUrl", "severity", "confidence")));
    }
}
