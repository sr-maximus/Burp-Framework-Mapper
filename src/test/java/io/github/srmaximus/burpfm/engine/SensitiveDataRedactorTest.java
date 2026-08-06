// SPDX-License-Identifier: Apache-2.0
package io.github.srmaximus.burpfm.engine;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SensitiveDataRedactorTest {
    @Test
    void redactsCommonSecretsAndRemovesActiveContent() {
        String result = SensitiveDataRedactor.redact("Authorization: Bearer abcdefghijk\npassword=hunter2\n<script>alert(1)</script>");
        assertFalse(result.contains("abcdefghijk"));
        assertFalse(result.contains("hunter2"));
        assertFalse(result.contains("alert(1)"));
        assertTrue(result.contains("[REDACTED]"));
    }

    @Test
    void stripsQueryAndFragmentFromImportedAsset() {
        assertTrue(SensitiveDataRedactor.safeAsset("https://example.invalid/a?token=secret#x")
                .equals("https://example.invalid/a"));
    }

    @Test
    void truncatesOversizedImportedText() {
        String result = SensitiveDataRedactor.redact("x".repeat(10_000_000));
        assertTrue(result.endsWith("[TRUNCATED]"));
        assertTrue(result.length() < SensitiveDataRedactor.MAX_IMPORTED_TEXT + 20);
    }
}
