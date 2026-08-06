// SPDX-License-Identifier: Apache-2.0
package io.github.srmaximus.burpfm.model;

import java.util.List;

public record AnalysisResult(FindingInput finding, CvssResult cvss, List<CorrelationResult> correlations) {
    public AnalysisResult {
        correlations = correlations == null ? List.of() : List.copyOf(correlations);
    }
}
