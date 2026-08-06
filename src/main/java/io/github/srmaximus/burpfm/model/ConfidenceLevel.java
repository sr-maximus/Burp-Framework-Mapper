// SPDX-License-Identifier: Apache-2.0
package io.github.srmaximus.burpfm.model;

public enum ConfidenceLevel {
    HIGH,
    MEDIUM,
    LOW;

    public static ConfidenceLevel fromScore(double score) {
        if (score >= 0.85d) {
            return HIGH;
        }
        if (score >= 0.65d) {
            return MEDIUM;
        }
        return LOW;
    }
}
