// SPDX-License-Identifier: Apache-2.0
package io.github.srmaximus.burpfm.model;

import java.time.Instant;
import java.util.List;

public record AnalysisReport(
        String schemaVersion,
        Instant generatedAt,
        String productVersion,
        String catalogManifest,
        List<AnalysisResult> findings,
        String reviewNotice) {

    public AnalysisReport {
        findings = findings == null ? List.of() : List.copyOf(findings);
    }

    public static AnalysisReport of(List<AnalysisResult> results) {
        return new AnalysisReport(
                "1.0.0",
                Instant.now(),
                "0.1.0",
                "SOURCE_MANIFEST.json",
                results,
                "Human review is required. Correlations are not compliance certification or proof of adversary activity.");
    }
}
