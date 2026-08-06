// SPDX-License-Identifier: Apache-2.0
package io.github.srmaximus.burpfm.export;

import io.github.srmaximus.burpfm.model.AnalysisReport;
import io.github.srmaximus.burpfm.model.AnalysisResult;
import io.github.srmaximus.burpfm.model.CorrelationResult;

import java.util.List;

public final class CsvReportExporter implements ReportExporter {
    private static final List<String> HEADER = List.of(
            "schema_version", "finding_id", "finding_title", "asset", "surface", "cwe_ids",
            "cvss_version", "cvss_vector", "cvss_score", "cvss_severity", "framework",
            "framework_version", "identifier", "title", "relation_type", "confidence",
            "confidence_score", "matched_signals", "official_url", "verified_date", "limitations");

    @Override
    public String export(AnalysisReport report) {
        StringBuilder csv = new StringBuilder(4096);
        appendRow(csv, HEADER);
        for (AnalysisResult analysis : report.findings()) {
            if (analysis.correlations().isEmpty()) {
                appendRow(csv, baseRow(report, analysis, null));
            } else {
                for (CorrelationResult result : analysis.correlations()) {
                    appendRow(csv, baseRow(report, analysis, result));
                }
            }
        }
        return csv.toString();
    }

    private static List<String> baseRow(AnalysisReport report, AnalysisResult analysis, CorrelationResult result) {
        var finding = analysis.finding();
        var cvss = analysis.cvss();
        return List.of(
                report.schemaVersion(), finding.id(), finding.title(), finding.asset(), finding.surface().label(),
                String.join(";", finding.cweIds()), cvss.version(), cvss.vector(), format(cvss.score()), cvss.severity(),
                result == null ? "" : result.framework(), result == null ? "" : result.frameworkVersion(),
                result == null ? "" : result.identifier(), result == null ? "" : result.title(),
                result == null ? "" : result.relationType().name(), result == null ? "" : result.confidence().name(),
                result == null ? "" : format(result.confidenceScore()),
                result == null ? "" : String.join(";", result.matchedSignals()),
                result == null ? "" : result.officialUrl(), result == null ? "" : result.verifiedDate(),
                result == null ? "" : result.limitations());
    }

    private static String format(double value) {
        return String.format(java.util.Locale.ROOT, "%.1f", value);
    }

    private static void appendRow(StringBuilder target, List<String> cells) {
        for (int index = 0; index < cells.size(); index++) {
            if (index > 0) {
                target.append(',');
            }
            target.append(quote(neutralizeFormula(cells.get(index))));
        }
        target.append("\r\n");
    }

    static String neutralizeFormula(String value) {
        if (value == null || value.isEmpty()) {
            return "";
        }
        char first = value.charAt(0);
        if (first == '=' || first == '+' || first == '-' || first == '@' || first == '\t' || first == '\r') {
            return "'" + value;
        }
        return value;
    }

    private static String quote(String value) {
        return '"' + value.replace("\"", "\"\"") + '"';
    }

    @Override
    public String fileExtension() {
        return ".csv";
    }
}
