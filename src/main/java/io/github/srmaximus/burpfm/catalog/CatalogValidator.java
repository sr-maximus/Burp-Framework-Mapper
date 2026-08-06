// SPDX-License-Identifier: Apache-2.0
package io.github.srmaximus.burpfm.catalog;

import io.github.srmaximus.burpfm.model.CatalogRule;

import java.net.URI;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public final class CatalogValidator {
    public static final int EQUIVALENT_SCHEMA_COLUMNS = 12;

    private CatalogValidator() {
    }

    public static void validate(List<CatalogRule> rules) {
        if (rules == null || rules.isEmpty()) {
            throw new IllegalArgumentException("Catalog must contain at least one rule");
        }
        Set<String> unique = new HashSet<>();
        for (CatalogRule rule : rules) {
            require(rule.framework(), "framework");
            require(rule.frameworkVersion(), "frameworkVersion");
            require(rule.identifier(), "identifier");
            require(rule.title(), "title");
            require(rule.explanation(), "explanation");
            require(rule.verifiedDate(), "verifiedDate");
            if (rule.relationType() == null) {
                throw new IllegalArgumentException("relationType is required for " + rule.identifier());
            }
            if (rule.surfaces().isEmpty()) {
                throw new IllegalArgumentException("At least one surface is required for " + rule.identifier());
            }
            URI source = URI.create(rule.officialUrl());
            if (!"https".equalsIgnoreCase(source.getScheme()) || source.getHost() == null) {
                throw new IllegalArgumentException("Official URL must use HTTPS for " + rule.identifier());
            }
            if (!unique.add(rule.uniqueKey())) {
                throw new IllegalArgumentException("Duplicate framework identifier: " + rule.uniqueKey());
            }
        }
    }

    private static void require(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
    }
}
