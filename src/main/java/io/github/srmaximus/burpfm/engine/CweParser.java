// SPDX-License-Identifier: Apache-2.0
package io.github.srmaximus.burpfm.engine;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class CweParser {
    private static final Pattern CWE = Pattern.compile("(?i)(?:CWE\\s*[-:]?\\s*)?(\\d{1,5})");

    private CweParser() {
    }

    public static List<String> parse(String input) {
        if (input == null || input.isBlank()) {
            return List.of();
        }
        Set<String> result = new LinkedHashSet<>();
        for (String token : input.split("[,;\\s]+")) {
            Matcher matcher = CWE.matcher(token.trim());
            if (matcher.matches()) {
                addCanonical(result, matcher.group(1));
            }
        }
        return new ArrayList<>(result);
    }

    public static List<String> normalize(List<String> input) {
        if (input == null || input.isEmpty()) {
            return List.of();
        }
        return parse(String.join(" ", input).toUpperCase(Locale.ROOT));
    }

    public static List<String> extractExplicit(String input) {
        if (input == null || input.isBlank()) {
            return List.of();
        }
        Set<String> result = new LinkedHashSet<>();
        Matcher matcher = Pattern.compile("(?i)\\bCWE\\s*[-:]?\\s*(\\d{1,5})\\b").matcher(input);
        while (matcher.find()) {
            addCanonical(result, matcher.group(1));
        }
        return new ArrayList<>(result);
    }

    private static void addCanonical(Set<String> result, String digits) {
        try {
            int number = Integer.parseInt(digits);
            if (number > 0) {
                result.add("CWE-" + number);
            }
        } catch (NumberFormatException ignored) {
            // Invalid or unexpectedly large user input is ignored rather than escaping the parser.
        }
    }
}
