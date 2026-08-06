// SPDX-License-Identifier: Apache-2.0
package io.github.srmaximus.burpfm.export;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import io.github.srmaximus.burpfm.model.AnalysisReport;
import io.github.srmaximus.burpfm.model.AnalysisResult;
import io.github.srmaximus.burpfm.model.CorrelationResult;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class SarifReportExporter implements ReportExporter {
    private final ObjectMapper mapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

    @Override
    public String export(AnalysisReport report) {
        Map<String, Map<String, Object>> rules = new LinkedHashMap<>();
        List<Map<String, Object>> results = new ArrayList<>();
        for (AnalysisResult analysis : report.findings()) {
            for (CorrelationResult correlation : analysis.correlations()) {
                String ruleId = correlation.framework().replaceAll("[^A-Za-z0-9._-]", "-")
                        + "/" + correlation.identifier();
                rules.putIfAbsent(ruleId, Map.of(
                        "id", ruleId,
                        "name", correlation.title(),
                        "shortDescription", Map.of("text", correlation.title()),
                        "helpUri", correlation.officialUrl(),
                        "properties", Map.of(
                                "frameworkVersion", correlation.frameworkVersion(),
                                "relationship", correlation.relationType().name(),
                                "verifiedDate", correlation.verifiedDate())));
                Map<String, Object> result = new LinkedHashMap<>();
                result.put("ruleId", ruleId);
                result.put("level", sarifLevel(analysis));
                result.put("message", Map.of("text", correlation.explanation()));
                result.put("properties", Map.of(
                        "findingId", analysis.finding().id(),
                        "confidence", correlation.confidence().name(),
                        "confidenceScore", correlation.confidenceScore(),
                        "matchedSignals", correlation.matchedSignals(),
                        "limitations", correlation.limitations(),
                        "reviewRequired", true));
                if (!analysis.finding().asset().isBlank()) {
                    result.put("locations", List.of(Map.of("logicalLocations", List.of(Map.of(
                            "name", analysis.finding().asset(), "kind", "asset")))));
                }
                results.add(result);
            }
        }
        Map<String, Object> driver = new LinkedHashMap<>();
        driver.put("name", "Burp Framework Mapper");
        driver.put("version", report.productVersion());
        driver.put("informationUri", "https://github.com/sr-maximus/Burp-Framework-Mapper");
        driver.put("rules", new ArrayList<>(rules.values()));
        Map<String, Object> sarif = Map.of(
                "$schema", "https://json.schemastore.org/sarif-2.1.0.json",
                "version", "2.1.0",
                "runs", List.of(Map.of("tool", Map.of("driver", driver), "results", results)));
        try {
            return mapper.writeValueAsString(sarif) + "\n";
        } catch (JsonProcessingException exception) {
            throw new IllegalStateException("Cannot export report as SARIF", exception);
        }
    }

    private static String sarifLevel(AnalysisResult analysis) {
        if (!analysis.cvss().valid() || analysis.cvss().vector().isBlank()) {
            return "note";
        }
        return switch (analysis.cvss().severity()) {
            case "Critical", "High" -> "error";
            case "Medium" -> "warning";
            default -> "note";
        };
    }

    @Override
    public String fileExtension() {
        return ".sarif";
    }
}
