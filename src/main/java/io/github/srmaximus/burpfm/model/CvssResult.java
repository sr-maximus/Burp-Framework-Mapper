// SPDX-License-Identifier: Apache-2.0
package io.github.srmaximus.burpfm.model;

public record CvssResult(String version, String vector, double score, String severity, boolean valid, String error) {
    public static CvssResult absent() {
        return new CvssResult("4.0", "", 0.0d, "Not provided", true, "");
    }

    public static CvssResult invalid(String vector, String error) {
        return new CvssResult("4.0", vector, 0.0d, "Invalid", false, error);
    }
}
