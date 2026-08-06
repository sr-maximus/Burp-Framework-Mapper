// SPDX-License-Identifier: Apache-2.0
package io.github.srmaximus.burpfm.export;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.srmaximus.burpfm.engine.AnalyzerFacade;
import io.github.srmaximus.burpfm.model.AnalysisReport;
import io.github.srmaximus.burpfm.model.FindingInput;
import io.github.srmaximus.burpfm.model.Surface;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ExportersTest {
    private final AnalysisReport report = AnalysisReport.of(List.of(new AnalyzerFacade().analyze(
            new FindingInput("test-1", "=CMD synthetic SQL injection", "<script>not executable</script>",
                    "Synthetic only", "https://example.invalid", Surface.API, List.of("CWE-89"),
                    "", "", "", "", "", List.of("test"), "test"))));

    @Test
    void jsonIsValidAndCarriesReviewNotice() throws Exception {
        JsonNode json = new ObjectMapper().readTree(new JsonReportExporter().export(report));
        assertEquals("1.0.0", json.path("schemaVersion").asText());
        assertTrue(json.path("reviewNotice").asText().contains("Human review"));
        assertEquals(1, json.path("findings").size());
    }

    @Test
    void csvNeutralizesSpreadsheetFormulas() {
        String csv = new CsvReportExporter().export(report);
        assertTrue(csv.contains("'=CMD synthetic SQL injection"));
        assertFalse(csv.contains(",=CMD"));
    }

    @Test
    void markdownEscapesHtmlAndTableDelimiters() {
        String markdown = new MarkdownReportExporter().export(report);
        assertTrue(markdown.contains("&lt;script&gt;"));
        assertFalse(markdown.contains("<script>"));
    }

    @Test
    void sarifIsVersionedAndParseable() throws Exception {
        JsonNode sarif = new ObjectMapper().readTree(new SarifReportExporter().export(report));
        assertEquals("2.1.0", sarif.path("version").asText());
        assertTrue(sarif.path("runs").isArray());
        assertFalse(sarif.toString().contains("artifactLocation"));
        assertTrue(sarif.toString().contains("logicalLocations"));
    }
}
