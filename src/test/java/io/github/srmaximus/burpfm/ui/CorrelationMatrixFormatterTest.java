// SPDX-License-Identifier: Apache-2.0
package io.github.srmaximus.burpfm.ui;

import io.github.srmaximus.burpfm.engine.AnalyzerFacade;
import io.github.srmaximus.burpfm.model.FindingInput;
import io.github.srmaximus.burpfm.model.Surface;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CorrelationMatrixFormatterTest {
    @Test
    void formatsFindingByFrameworkCountsWithoutInjectingRows() {
        FindingInput finding = new FindingInput(null, "SQL injection\nsynthetic", "", "", "", Surface.API,
                List.of("CWE-89"), "", "", "", "", "", List.of(), "test");
        String matrix = CorrelationMatrixFormatter.format(List.of(new AnalyzerFacade().analyze(finding)));
        assertTrue(matrix.startsWith("Finding\t"));
        assertTrue(matrix.contains("1. SQL injection synthetic"));
        assertTrue(matrix.contains("CWE"));
        assertFalse(matrix.contains("SQL injection\nsynthetic"));
    }

    @Test
    void describesEmptyMatrixHonestly() {
        assertTrue(CorrelationMatrixFormatter.format(List.of()).contains("valid outcome"));
    }
}
