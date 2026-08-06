// SPDX-License-Identifier: Apache-2.0
package io.github.srmaximus.burpfm.engine;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TextNormalizerTest {
    @Test
    void normalizesUnicodeCaseControlsAndWhitespaceDeterministically() {
        String input = "  ＦＵＬＬ" + ((char) 1) + "  WIDTH\tSQL  Injection  ";
        assertEquals("full width sql injection", TextNormalizer.normalize(input));
        assertEquals("", TextNormalizer.normalize(null));
    }

    @Test
    void exactPhraseRequiresUnicodeWordBoundaries() {
        String normalized = TextNormalizer.normalize("Confirmed server-side request forgery in API");
        assertTrue(TextNormalizer.containsExactPhrase(normalized, "server-side request forgery"));
        assertFalse(TextNormalizer.containsExactPhrase(TextNormalizer.normalize("xssfilter"), "xss"));
    }
}
