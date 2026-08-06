// SPDX-License-Identifier: Apache-2.0
package io.github.srmaximus.burpfm.model;

import java.util.List;
import java.util.Objects;
import java.util.UUID;

public record FindingInput(
        String id,
        String title,
        String description,
        String evidence,
        String asset,
        Surface surface,
        List<String> cweIds,
        String cve,
        String cvssVector,
        String businessContext,
        String burpSeverity,
        String burpConfidence,
        List<String> tags,
        String origin) {

    public FindingInput {
        id = blankTo(id, UUID.randomUUID().toString());
        title = blankTo(title, "Untitled finding");
        description = safe(description);
        evidence = safe(evidence);
        asset = safe(asset);
        surface = Objects.requireNonNullElse(surface, Surface.GENERIC_UNKNOWN);
        cweIds = cweIds == null ? List.of() : List.copyOf(cweIds);
        cve = safe(cve);
        cvssVector = safe(cvssVector);
        businessContext = safe(businessContext);
        burpSeverity = safe(burpSeverity);
        burpConfidence = safe(burpConfidence);
        tags = tags == null ? List.of() : List.copyOf(tags);
        origin = blankTo(origin, "manual");
    }

    private static String safe(String value) {
        return Objects.requireNonNullElse(value, "").trim();
    }

    private static String blankTo(String value, String fallback) {
        String safeValue = safe(value);
        return safeValue.isBlank() ? fallback : safeValue;
    }
}
