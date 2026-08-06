// SPDX-License-Identifier: Apache-2.0
package io.github.srmaximus.burpfm;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertNotNull;

class ResourcePresenceTest {
    @Test
    void requiredRuntimeResourcesArePackagedOnClasspath() {
        List.of(
                "/mappings/correlations.json",
                "/catalogs/SOURCE_MANIFEST.json",
                "/schema/analysis-report.schema.json",
                "/cvss/metrics.js",
                "/cvss/cvss_lookup.js",
                "/cvss/max_composed.js",
                "/cvss/max_severity.js",
                "/cvss/cvss_score.js",
                "/cvss/bfm_wrapper.js"
        ).forEach(resource -> assertNotNull(getClass().getResource(resource), resource));
    }
}
