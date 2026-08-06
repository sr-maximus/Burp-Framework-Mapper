// SPDX-License-Identifier: Apache-2.0
package io.github.srmaximus.burpfm.model;

import java.util.List;

public record CatalogRule(
        String framework,
        String frameworkVersion,
        String identifier,
        String title,
        RelationType relationType,
        List<String> cweIds,
        List<Surface> surfaces,
        List<String> keywords,
        String explanation,
        String officialUrl,
        String verifiedDate,
        String limitations) {

    public CatalogRule {
        cweIds = cweIds == null ? List.of() : List.copyOf(cweIds);
        surfaces = surfaces == null ? List.of() : List.copyOf(surfaces);
        keywords = keywords == null ? List.of() : List.copyOf(keywords);
    }

    public String uniqueKey() {
        return framework + "\u0000" + identifier;
    }
}
