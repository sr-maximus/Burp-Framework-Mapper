// SPDX-License-Identifier: Apache-2.0
package io.github.srmaximus.burpfm.export;

import io.github.srmaximus.burpfm.model.AnalysisReport;

public interface ReportExporter {
    String export(AnalysisReport report);

    String fileExtension();
}
