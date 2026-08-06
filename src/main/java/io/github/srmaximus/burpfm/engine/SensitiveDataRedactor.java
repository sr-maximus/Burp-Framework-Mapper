// SPDX-License-Identifier: Apache-2.0
package io.github.srmaximus.burpfm.engine;

import java.util.List;
import java.util.regex.Pattern;

public final class SensitiveDataRedactor {
    public static final int MAX_IMPORTED_TEXT = 4_000;

    private static final List<Pattern> HEADER_PATTERNS = List.of(
            Pattern.compile("(?im)^(authorization|proxy-authorization|cookie|set-cookie|x-api-key)\\s*:\\s*.*$"),
            Pattern.compile("(?i)\\b(bearer|basic)\\s+[a-z0-9._~+/=-]{8,}"),
            Pattern.compile("(?i)\\b(password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token)\\s*[=:]\\s*[^\\s,;]{4,}"));

    private SensitiveDataRedactor() {
    }

    public static String redact(String value) {
        if (value == null || value.isBlank()) {
            return "";
        }
        boolean truncated = value.length() > MAX_IMPORTED_TEXT;
        String redacted = truncated ? value.substring(0, MAX_IMPORTED_TEXT) : value;
        for (Pattern pattern : HEADER_PATTERNS) {
            redacted = pattern.matcher(redacted).replaceAll("[REDACTED]");
        }
        redacted = redacted.replaceAll("(?is)<(script|style)[^>]*>.*?</\\1>", "[REMOVED ACTIVE CONTENT]");
        if (truncated) {
            redacted = redacted + "\n[TRUNCATED]";
        }
        return redacted.trim();
    }

    public static String safeAsset(String value) {
        if (value == null || value.isBlank()) {
            return "";
        }
        int query = value.indexOf('?');
        int fragment = value.indexOf('#');
        int end = value.length();
        if (query >= 0) {
            end = Math.min(end, query);
        }
        if (fragment >= 0) {
            end = Math.min(end, fragment);
        }
        return value.substring(0, end);
    }
}
