// SPDX-License-Identifier: Apache-2.0
package io.github.srmaximus.burpfm.engine;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CweParserTest {
    @Test
    void normalizesManualIdentifiersAndRemovesDuplicates() {
        assertEquals(List.of("CWE-79", "CWE-89"), CweParser.parse("79, CWE:79; cwe-89"));
    }

    @Test
    void extractsOnlyExplicitCweReferencesFromProse() {
        assertEquals(List.of("CWE-79", "CWE-89"),
                CweParser.extractExplicit("CWE-79 appears here; number 123 is not a CWE; cwe: 89."));
    }

    @Test
    void ignoresZeroOversizedAndMalformedIdentifiersWithoutThrowing() {
        assertEquals(List.of(), CweParser.parse("CWE-0 CWE-999999999999999999999999999 bad"));
        assertEquals(List.of(), CweParser.extractExplicit("CWE-999999999999999999999999999"));
    }
}
