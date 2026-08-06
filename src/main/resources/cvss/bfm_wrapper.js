// Copyright 2026 Edwin Javier Peñuela Camacho
// SPDX-License-Identifier: Apache-2.0

function bfmCalculateJson(vector) {
    try {
        if (typeof vector !== "string" || vector.length === 0) {
            throw new Error("CVSS vector is empty");
        }
        var parts = vector.split("/");
        if (parts.shift() !== "CVSS:4.0") {
            throw new Error("Vector must start with CVSS:4.0");
        }

        var selected = {};
        var orderedMetrics = Object.keys(expectedMetricOrder);
        for (var i = 0; i < orderedMetrics.length; i++) {
            selected[orderedMetrics[i]] = "X";
        }

        var previousIndex = -1;
        var seen = {};
        for (var p = 0; p < parts.length; p++) {
            var pair = parts[p].split(":");
            if (pair.length !== 2 || pair[0].length === 0 || pair[1].length === 0) {
                throw new Error("Invalid metric segment: " + parts[p]);
            }
            var metric = pair[0];
            var value = pair[1];
            var metricIndex = orderedMetrics.indexOf(metric);
            if (metricIndex < 0) {
                throw new Error("Unknown CVSS metric: " + metric);
            }
            if (seen[metric]) {
                throw new Error("Duplicate CVSS metric: " + metric);
            }
            if (metricIndex <= previousIndex) {
                throw new Error("CVSS metrics are not in canonical order");
            }
            if (expectedMetricOrder[metric].indexOf(value) < 0) {
                throw new Error("Invalid value " + value + " for metric " + metric);
            }
            selected[metric] = value;
            seen[metric] = true;
            previousIndex = metricIndex;
        }

        for (var baseIndex = 0; baseIndex < 11; baseIndex++) {
            if (!seen[orderedMetrics[baseIndex]]) {
                throw new Error("Missing mandatory base metric: " + orderedMetrics[baseIndex]);
            }
        }

        var macro = macroVector(selected);
        var score = cvss_score(selected, cvssLookup_global, maxSeverity, macro);
        if (typeof score !== "number" || !isFinite(score)) {
            throw new Error("CVSS calculation did not return a finite score");
        }
        return JSON.stringify({valid: true, score: score, error: ""});
    } catch (error) {
        return JSON.stringify({valid: false, score: 0.0, error: String(error.message || error)});
    }
}
