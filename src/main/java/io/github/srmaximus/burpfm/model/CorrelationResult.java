// SPDX-License-Identifier: Apache-2.0
package io.github.srmaximus.burpfm.model;

import java.util.List;

public record CorrelationResult(
        String framework,
        String frameworkVersion,
        String identifier,
        String title,
        RelationType relationType,
        double confidenceScore,
        ConfidenceLevel confidence,
        List<String> matchedSignals,
        String explanation,
        String officialUrl,
        String verifiedDate,
        String limitations,
        List<Surface> affectedSurfaces) {

    public CorrelationResult {
        matchedSignals = matchedSignals == null ? List.of() : List.copyOf(matchedSignals);
        affectedSurfaces = affectedSurfaces == null ? List.of() : List.copyOf(affectedSurfaces);
    }
}
