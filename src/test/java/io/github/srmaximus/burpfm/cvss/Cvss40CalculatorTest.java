// SPDX-License-Identifier: Apache-2.0
package io.github.srmaximus.burpfm.cvss;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class Cvss40CalculatorTest {
    private final Cvss40Calculator calculator = new Cvss40Calculator();

    @Test
    void calculatesMaximumBaseVectorWithOfficialFirstAlgorithm() {
        var result = calculator.calculate("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H");
        assertTrue(result.valid(), result.error());
        assertEquals(10.0d, result.score());
        assertEquals("Critical", result.severity());
    }

    @Test
    void calculatesZeroWhenAllImpactsAreNone() {
        var result = calculator.calculate("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N");
        assertTrue(result.valid(), result.error());
        assertEquals(0.0d, result.score());
        assertEquals("None", result.severity());
    }

    @Test
    void rejectsWrongVersionMissingMetricsAndDuplicates() {
        assertFalse(calculator.calculate("CVSS:3.1/AV:N").valid());
        assertFalse(calculator.calculate("CVSS:4.0/AV:N").valid());
        assertFalse(calculator.calculate("CVSS:4.0/AV:N/AV:A/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N").valid());
    }

    @Test
    void rejectsCodeLikeOrMultilineInputWithoutExecutingIt() {
        assertFalse(calculator.calculate("CVSS:4.0/AV:N\njava.lang.Runtime").valid());
        assertFalse(calculator.calculate("');Packages.java.lang.System.exit(0);//").valid());
    }
}
