// SPDX-License-Identifier: Apache-2.0
package io.github.srmaximus.burpfm.engine;

import io.github.srmaximus.burpfm.model.AnalysisResult;
import io.github.srmaximus.burpfm.model.FindingInput;
import io.github.srmaximus.burpfm.model.RelationType;
import io.github.srmaximus.burpfm.model.Surface;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CorrelationEngineTest {
    private final AnalyzerFacade analyzer = new AnalyzerFacade();

    @Test
    void exactCweProducesTaxonomyAndSurfaceRelevantMappings() {
        AnalysisResult result = analyzer.analyze(finding("SQL injection confirmed", Surface.API, List.of("cwe:89")));

        assertTrue(has(result, "CWE", "CWE-89"));
        assertTrue(has(result, "OWASP ASVS", "v5.0.0-1.2.4"));
        assertFalse(result.correlations().stream().anyMatch(value -> value.framework().contains("Mobile")));
        assertFalse(result.correlations().stream().anyMatch(value -> value.framework().contains("ICS")));
    }

    @Test
    void exactPhraseMatchesOnlyOnApplicableSurface() {
        AnalysisResult result = analyzer.analyze(finding(
                "Broken object property level authorization in account API", Surface.API, List.of()));
        assertTrue(has(result, "OWASP API Security Top 10", "API3:2023"));
    }

    @Test
    void ambiguousGenericWordDoesNotProduceMapping() {
        AnalysisResult result = analyzer.analyze(finding("Input injection concern", Surface.WEB, List.of()));
        assertTrue(result.correlations().isEmpty());
    }

    @Test
    void positiveRateLimitLanguageDoesNotProduceApi4Mapping() {
        AnalysisResult result = analyzer.analyze(finding("A rate limit is configured", Surface.API, List.of()));
        assertFalse(has(result, "OWASP API Security Top 10", "API4:2023"));
    }

    @Test
    void missingRateLimitProducesApi4Mapping() {
        AnalysisResult result = analyzer.analyze(finding("Missing rate limit on resource-intensive API", Surface.API, List.of()));
        assertTrue(has(result, "OWASP API Security Top 10", "API4:2023"));
    }

    @Test
    void xssWebMapsToCweAndOwaspWeb() {
        AnalysisResult result = analyzer.analyze(finding("Stored cross-site scripting (XSS)", Surface.WEB, List.of()));
        assertTrue(has(result, "CWE", "CWE-79"));
        assertTrue(has(result, "OWASP Top 10 Web", "A05:2025"));
    }

    @Test
    void ssrfApiMapsToCweAndOwaspApi() {
        AnalysisResult result = analyzer.analyze(finding("Server-side request forgery (SSRF)", Surface.API, List.of()));
        assertTrue(has(result, "CWE", "CWE-918"));
        assertTrue(has(result, "OWASP API Security Top 10", "API7:2023"));
    }

    @Test
    void directAndIndirectPromptInjectionMapOnlyOnAiSurface() {
        AnalysisResult direct = analyzer.analyze(finding("Direct prompt injection", Surface.AI_ML_LLM, List.of()));
        AnalysisResult indirect = analyzer.analyze(finding("Indirect prompt injection from retrieved content", Surface.AI_ML_LLM, List.of()));
        assertTrue(has(direct, "OWASP GenAI/LLM Top 10", "LLM01:2025"));
        assertTrue(has(indirect, "MITRE ATLAS", "AML.T0051"));
        assertFalse(has(analyzer.analyze(finding("Prompt injection", Surface.WEB, List.of())),
                "OWASP GenAI/LLM Top 10", "LLM01:2025"));
    }

    @Test
    void aiDataPoisoningMapsToGenAiAndAtlas() {
        AnalysisResult result = analyzer.analyze(finding("Training data poisoning", Surface.AI_ML_LLM, List.of()));
        assertTrue(has(result, "OWASP GenAI/LLM Top 10", "LLM04:2025"));
        assertTrue(has(result, "MITRE ATLAS", "AML.T0020"));
    }

    @Test
    void insecureMobileStorageMapsToMobileAndMasvs() {
        AnalysisResult result = analyzer.analyze(finding("Sensitive data stored using insecure data storage", Surface.MOBILE, List.of()));
        assertTrue(has(result, "OWASP Mobile Top 10", "M9:2024"));
        assertTrue(has(result, "OWASP MASVS", "MASVS-STORAGE-1"));
    }

    @Test
    void softwareSupplyChainMapsToOwaspWeb() {
        AnalysisResult result = analyzer.analyze(finding("Software supply chain compromise", Surface.WEB, List.of()));
        assertTrue(has(result, "OWASP Top 10 Web", "A03:2025"));
    }

    @Test
    void securityMisconfigurationMapsToApiTaxonomy() {
        AnalysisResult result = analyzer.analyze(finding("Security misconfiguration in API gateway", Surface.API, List.of()));
        assertTrue(has(result, "CWE", "CWE-16"));
        assertTrue(has(result, "OWASP API Security Top 10", "API8:2023"));
    }

    @Test
    void surfaceIsolationPreventsMobileAndIcsLeakage() {
        AnalysisResult result = analyzer.analyze(finding("SQL injection", Surface.WEB, List.of()));
        assertFalse(result.correlations().stream().anyMatch(value ->
                value.framework().contains("MASVS") || value.framework().contains("Mobile")
                        || value.framework().contains("ICS")));
    }

    @Test
    void explicitOfficialIdentifierIsPreservedAsInputAssertion() {
        AnalysisResult result = analyzer.analyze(finding("Reviewer assigned API3:2023", Surface.WEB, List.of()));
        var match = result.correlations().stream().filter(value -> value.identifier().equals("API3:2023")).findFirst().orElseThrow();
        assertEquals(RelationType.INPUT_ASSERTED, match.relationType());
    }

    @Test
    void outputIsDeduplicatedByFrameworkAndIdentifier() {
        AnalysisResult result = analyzer.analyze(finding("SQL injection SQLi CWE-89", Surface.API, List.of("CWE-89")));
        var keys = new HashSet<String>();
        result.correlations().forEach(value -> assertTrue(keys.add(value.framework() + "\0" + value.identifier())));
    }

    @Test
    void unrelatedFindingReturnsNoMatchRatherThanGuessing() {
        AnalysisResult result = analyzer.analyze(finding("Layout text overlaps a footer", Surface.WEB, List.of()));
        assertTrue(result.correlations().isEmpty());
    }

    @Test
    void confidenceIsBoundedAndExplained() {
        AnalysisResult result = analyzer.analyze(finding("Credential stuffing", Surface.FRAUD, List.of("CWE-307")));
        assertFalse(result.correlations().isEmpty());
        result.correlations().forEach(value -> {
            assertTrue(value.confidenceScore() >= CorrelationEngine.MINIMUM_SCORE && value.confidenceScore() <= 1.0d);
            assertFalse(value.matchedSignals().isEmpty());
            assertFalse(value.explanation().isBlank());
            assertFalse(value.limitations().isBlank());
        });
    }

    private static FindingInput finding(String title, Surface surface, List<String> cwes) {
        return new FindingInput(null, title, "Controlled defensive validation.", "Synthetic evidence.",
                "https://example.invalid", surface, cwes, "", "", "", "", "", List.of(), "test");
    }

    private static boolean has(AnalysisResult result, String framework, String identifier) {
        return result.correlations().stream().anyMatch(value ->
                value.framework().equals(framework) && value.identifier().equals(identifier));
    }
}
