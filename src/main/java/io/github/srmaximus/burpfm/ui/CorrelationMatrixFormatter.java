// SPDX-License-Identifier: Apache-2.0
package io.github.srmaximus.burpfm.ui;

import io.github.srmaximus.burpfm.model.AnalysisResult;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.TreeSet;

final class CorrelationMatrixFormatter {
    private static final int MAX_LABEL_LENGTH = 60;

    private CorrelationMatrixFormatter() {
    }

    static String format(List<AnalysisResult> results) {
        Objects.requireNonNull(results, "results");
        TreeSet<String> frameworks = new TreeSet<>();
        results.stream().flatMap(result -> result.correlations().stream())
                .forEach(correlation -> frameworks.add(correlation.framework()));
        if (frameworks.isEmpty()) {
            return "No correlations to display. An empty matrix is a valid outcome.";
        }

        StringBuilder matrix = new StringBuilder("Finding");
        frameworks.forEach(framework -> matrix.append('\t').append(framework));
        matrix.append('\n');
        for (int index = 0; index < results.size(); index++) {
            AnalysisResult result = results.get(index);
            Map<String, Long> counts = new TreeMap<>();
            result.correlations().forEach(correlation -> counts.merge(correlation.framework(), 1L, Long::sum));
            matrix.append(index + 1).append(". ").append(label(result.finding().title()));
            frameworks.forEach(framework -> matrix.append('\t').append(counts.getOrDefault(framework, 0L)));
            matrix.append('\n');
        }
        return matrix.toString();
    }

    private static String label(String value) {
        String compact = value == null ? "" : value.replaceAll("[\\r\\n\\t]+", " ").trim();
        return compact.length() <= MAX_LABEL_LENGTH ? compact : compact.substring(0, MAX_LABEL_LENGTH - 1) + "…";
    }
}
