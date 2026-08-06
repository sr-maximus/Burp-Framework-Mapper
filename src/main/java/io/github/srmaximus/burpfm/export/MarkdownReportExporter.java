// SPDX-License-Identifier: Apache-2.0
package io.github.srmaximus.burpfm.export;

import io.github.srmaximus.burpfm.model.AnalysisReport;
import io.github.srmaximus.burpfm.model.AnalysisResult;
import io.github.srmaximus.burpfm.model.CorrelationResult;

public final class MarkdownReportExporter implements ReportExporter {
    @Override
    public String export(AnalysisReport report) {
        StringBuilder markdown = new StringBuilder(4096);
        markdown.append("# Burp Framework Mapper report\n\n")
                .append("- Schema: `").append(escape(report.schemaVersion())).append("`\n")
                .append("- Generated: `").append(report.generatedAt()).append("`\n")
                .append("- Notice: ").append(escape(report.reviewNotice())).append("\n\n");
        for (AnalysisResult analysis : report.findings()) {
            markdown.append("## ").append(escape(analysis.finding().title())).append("\n\n")
                    .append("- Description: ").append(escape(analysis.finding().description())).append("\n")
                    .append("- Evidence: ").append(escape(analysis.finding().evidence())).append("\n")
                    .append("- Surface: ").append(escape(analysis.finding().surface().label())).append("\n")
                    .append("- Asset: ").append(escape(analysis.finding().asset())).append("\n")
                    .append("- CWE: ").append(escape(String.join(", ", analysis.finding().cweIds()))).append("\n")
                    .append("- Business context: ").append(escape(analysis.finding().businessContext())).append("\n")
                    .append("- CVSS: ").append(escape(analysis.cvss().vector())).append(" — ")
                    .append(analysis.cvss().score()).append(" ").append(escape(analysis.cvss().severity())).append("\n\n")
                    .append("| Framework | ID | Title | Relation | Confidence | Source |\n")
                    .append("|---|---|---|---|---:|---|\n");
            for (CorrelationResult result : analysis.correlations()) {
                markdown.append('|').append(cell(result.framework()))
                        .append('|').append(cell(result.identifier()))
                        .append('|').append(cell(result.title()))
                        .append('|').append(cell(result.relationType().name()))
                        .append('|').append(result.confidenceScore())
                        .append('|').append("[official source](").append(result.officialUrl()).append(")|\n");
            }
            if (analysis.correlations().isEmpty()) {
                markdown.append("| No validated correlations | | | | | |\n");
            }
            markdown.append('\n');
        }
        return markdown.toString();
    }

    private static String cell(String value) {
        return " " + escape(value) + " ";
    }

    static String escape(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("\\", "\\\\")
                .replace("|", "\\|")
                .replace("\r", " ")
                .replace("\n", " ")
                .replace("<", "&lt;")
                .replace(">", "&gt;");
    }

    @Override
    public String fileExtension() {
        return ".md";
    }
}
