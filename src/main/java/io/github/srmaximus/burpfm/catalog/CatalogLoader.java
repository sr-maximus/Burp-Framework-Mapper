// SPDX-License-Identifier: Apache-2.0
package io.github.srmaximus.burpfm.catalog;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.srmaximus.burpfm.model.CatalogRule;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;

public final class CatalogLoader {
    public static final String DEFAULT_RESOURCE = "/mappings/correlations.json";
    public static final String CATALOG_VERSION = "2026.08.06-1";
    public static final int CURATED_RULE_COUNT = 86;

    private final ObjectMapper mapper;

    public CatalogLoader() {
        mapper = new ObjectMapper()
                .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
    }

    public List<CatalogRule> loadDefault() {
        try (InputStream input = CatalogLoader.class.getResourceAsStream(DEFAULT_RESOURCE)) {
            if (input == null) {
                throw new IllegalStateException("Missing catalog resource " + DEFAULT_RESOURCE);
            }
            List<CatalogRule> rules = mapper.readValue(input, new TypeReference<>() { });
            CatalogValidator.validate(rules);
            return List.copyOf(rules);
        } catch (IOException exception) {
            throw new IllegalStateException("Cannot load framework catalog", exception);
        }
    }
}
