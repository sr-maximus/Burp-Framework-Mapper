// SPDX-License-Identifier: Apache-2.0
package io.github.srmaximus.burpfm.engine;

import io.github.srmaximus.burpfm.catalog.CatalogLoader;
import io.github.srmaximus.burpfm.cvss.Cvss40Calculator;
import io.github.srmaximus.burpfm.model.AnalysisResult;
import io.github.srmaximus.burpfm.model.CvssResult;
import io.github.srmaximus.burpfm.model.FindingInput;

public final class AnalyzerFacade {
    private final CorrelationEngine engine;
    private final Cvss40Calculator cvssCalculator;

    public AnalyzerFacade() {
        this(new CorrelationEngine(new CatalogLoader().loadDefault()), new Cvss40Calculator());
    }

    public AnalyzerFacade(CorrelationEngine engine, Cvss40Calculator cvssCalculator) {
        this.engine = engine;
        this.cvssCalculator = cvssCalculator;
    }

    public AnalysisResult analyze(FindingInput finding) {
        CvssResult cvss = finding.cvssVector().isBlank()
                ? CvssResult.absent()
                : cvssCalculator.calculate(finding.cvssVector());
        return new AnalysisResult(finding, cvss, engine.correlate(finding));
    }
}
