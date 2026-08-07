// SPDX-License-Identifier: Apache-2.0
package io.github.srmaximus.burpfm.catalog;

import io.github.srmaximus.burpfm.model.CatalogRule;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CatalogValidatorTest {
    @Test
    void embeddedCatalogHasExpectedCuratedRowsAndUniqueKeys() {
        List<CatalogRule> rules = new CatalogLoader().loadDefault();
        assertEquals("2026.08.06-2", CatalogLoader.CATALOG_VERSION);
        assertEquals(CatalogLoader.CURATED_RULE_COUNT, rules.size());
        var keys = new HashSet<String>();
        rules.forEach(rule -> {
            assertTrue(keys.add(rule.uniqueKey()));
            assertTrue(rule.officialUrl().startsWith("https://"));
            assertFalse(rule.verifiedDate().isBlank());
            assertFalse(rule.limitations().isBlank());
            assertFalse(rule.surfaces().isEmpty());
        });
        assertEquals(10, rules.stream().filter(rule -> "MITRE AADAPT".equals(rule.framework())).count());
    }

    @Test
    void validatorRejectsIncompleteRule() {
        CatalogRule invalid = new CatalogRule("", "", "", "", null,
                List.of(), List.of(), List.of(), "", "", "", "");
        assertThrows(IllegalArgumentException.class, () -> CatalogValidator.validate(List.of(invalid)));
    }
}
