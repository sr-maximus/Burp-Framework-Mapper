// SPDX-License-Identifier: Apache-2.0
package io.github.srmaximus.burpfm.engine;

import io.github.srmaximus.burpfm.model.CatalogRule;
import io.github.srmaximus.burpfm.model.ConfidenceLevel;
import io.github.srmaximus.burpfm.model.CorrelationResult;
import io.github.srmaximus.burpfm.model.FindingInput;
import io.github.srmaximus.burpfm.model.RelationType;
import io.github.srmaximus.burpfm.model.Surface;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

public final class CorrelationEngine {
    public static final double MINIMUM_SCORE = 0.50d;

    private final List<CatalogRule> rules;

    public CorrelationEngine(List<CatalogRule> rules) {
        this.rules = List.copyOf(rules);
    }

    public List<CorrelationResult> correlate(FindingInput finding) {
        String text = searchableText(finding);
        Set<String> assertedCwes = new LinkedHashSet<>(CweParser.normalize(finding.cweIds()));
        Map<String, CorrelationResult> deduplicated = new LinkedHashMap<>();

        for (CatalogRule rule : rules) {
            Match match = evaluate(rule, finding.surface(), assertedCwes, text);
            if (match.score < MINIMUM_SCORE || !match.hasStrongSignal) {
                continue;
            }
            RelationType displayedRelation = match.identifierAsserted
                    ? RelationType.INPUT_ASSERTED
                    : rule.relationType();
            double score = Math.min(1.0d, Math.round(match.score * 100.0d) / 100.0d);
            CorrelationResult result = new CorrelationResult(
                    rule.framework(), rule.frameworkVersion(), rule.identifier(), rule.title(),
                    displayedRelation, score, ConfidenceLevel.fromScore(score), match.signals,
                    rule.explanation(), rule.officialUrl(), rule.verifiedDate(), rule.limitations(), rule.surfaces());
            deduplicated.merge(rule.uniqueKey(), result,
                    (left, right) -> left.confidenceScore() >= right.confidenceScore() ? left : right);
        }

        return deduplicated.values().stream()
                .sorted(Comparator.comparingDouble(CorrelationResult::confidenceScore).reversed()
                        .thenComparing(CorrelationResult::framework)
                        .thenComparing(CorrelationResult::identifier))
                .toList();
    }

    private Match evaluate(CatalogRule rule, Surface surface, Set<String> assertedCwes, String text) {
        List<String> signals = new ArrayList<>();
        double score = 0.0d;

        List<String> matchedCwes = rule.cweIds().stream()
                .map(value -> value.toUpperCase(Locale.ROOT))
                .filter(assertedCwes::contains)
                .toList();
        boolean exactCwe = !matchedCwes.isEmpty();
        if (exactCwe) {
            score += 0.50d;
            signals.add("Exact CWE: " + String.join(", ", matchedCwes));
        }

        boolean identifier = TextNormalizer.containsExactPhrase(text, rule.identifier());
        if (identifier) {
            score += 0.45d;
            signals.add("Official identifier asserted: " + rule.identifier());
        }

        boolean surfaceMatch = rule.surfaces().contains(surface)
                || (surface == Surface.GENERIC_UNKNOWN && rule.surfaces().contains(Surface.GENERIC_UNKNOWN));
        boolean taxonomyIdentity = "CWE".equals(rule.framework());
        if (!surfaceMatch && !identifier && !taxonomyIdentity) {
            return new Match(0.0d, false, false, List.of());
        }

        List<String> phrases = rule.keywords().stream()
                .filter(keyword -> TextNormalizer.containsExactPhrase(text, keyword))
                .toList();
        boolean phrase = !phrases.isEmpty();
        if (phrase) {
            score += 0.40d;
            signals.add("Unambiguous phrase: " + phrases.getFirst());
            if (phrases.size() > 1) {
                score += 0.05d;
                signals.add("Additional phrase: " + phrases.get(1));
            }
        }

        if (surfaceMatch) {
            score += 0.10d;
            signals.add("Surface: " + surface.label());
        }

        boolean hasContext = !findingTextBlank(text);
        if ((exactCwe || identifier) && hasContext) {
            score += 0.05d;
            signals.add("Technical finding context present");
        }

        return new Match(score, exactCwe || identifier || phrase, identifier, signals);
    }

    private static boolean findingTextBlank(String text) {
        return text == null || text.isBlank();
    }

    private static String searchableText(FindingInput finding) {
        return TextNormalizer.normalize(String.join(" ",
                finding.title(), finding.description(), finding.evidence(), finding.asset(),
                finding.businessContext(), finding.cve(), String.join(" ", finding.tags())));
    }

    private record Match(double score, boolean hasStrongSignal, boolean identifierAsserted, List<String> signals) {
    }
}
