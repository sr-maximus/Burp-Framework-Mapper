// SPDX-License-Identifier: Apache-2.0
package io.github.srmaximus.burpfm.engine;

import java.text.Normalizer;
import java.util.Locale;
import java.util.regex.Pattern;

public final class TextNormalizer {
    private TextNormalizer() {
    }

    public static String normalize(String value) {
        if (value == null || value.isBlank()) {
            return "";
        }
        String normalized = Normalizer.normalize(value, Normalizer.Form.NFKC)
                .toLowerCase(Locale.ROOT)
                .replaceAll("[\\p{Cntrl}&&[^\\r\\n\\t]]", " ")
                .replaceAll("\\s+", " ")
                .trim();
        return normalized;
    }

    public static boolean containsExactPhrase(String normalizedText, String phrase) {
        String normalizedPhrase = normalize(phrase);
        if (normalizedText.isBlank() || normalizedPhrase.isBlank()) {
            return false;
        }
        String left = Character.isLetterOrDigit(normalizedPhrase.charAt(0)) ? "(?<![\\p{L}\\p{N}])" : "";
        char last = normalizedPhrase.charAt(normalizedPhrase.length() - 1);
        String right = Character.isLetterOrDigit(last) ? "(?![\\p{L}\\p{N}])" : "";
        return Pattern.compile(left + Pattern.quote(normalizedPhrase) + right, Pattern.UNICODE_CASE)
                .matcher(normalizedText)
                .find();
    }
}
