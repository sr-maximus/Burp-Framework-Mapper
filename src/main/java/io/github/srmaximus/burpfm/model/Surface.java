// SPDX-License-Identifier: Apache-2.0
package io.github.srmaximus.burpfm.model;

import java.util.Locale;

public enum Surface {
    WEB("Web"),
    API("API"),
    MOBILE("Mobile"),
    AI_ML_LLM("AI/ML/LLM"),
    ENTERPRISE("Enterprise"),
    ICS_OT("ICS/OT"),
    FRAUD("Fraud"),
    GENERIC_UNKNOWN("Generic/Unknown");

    private final String label;

    Surface(String label) {
        this.label = label;
    }

    public String label() {
        return label;
    }

    public static Surface fromLabel(String value) {
        if (value == null || value.isBlank()) {
            return GENERIC_UNKNOWN;
        }
        String normalized = value.trim().toLowerCase(Locale.ROOT);
        for (Surface surface : values()) {
            if (surface.label.toLowerCase(Locale.ROOT).equals(normalized)
                    || surface.name().toLowerCase(Locale.ROOT).equals(normalized.replace('/', '_'))) {
                return surface;
            }
        }
        return GENERIC_UNKNOWN;
    }

    @Override
    public String toString() {
        return label;
    }
}
