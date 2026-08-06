// SPDX-License-Identifier: Apache-2.0
package io.github.srmaximus.burpfm.export;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import io.github.srmaximus.burpfm.model.AnalysisReport;

public final class JsonReportExporter implements ReportExporter {
    private final ObjectMapper mapper = new ObjectMapper()
            .registerModule(new JavaTimeModule())
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
            .enable(SerializationFeature.INDENT_OUTPUT);

    @Override
    public String export(AnalysisReport report) {
        try {
            return mapper.writeValueAsString(report) + "\n";
        } catch (JsonProcessingException exception) {
            throw new IllegalStateException("Cannot export report as JSON", exception);
        }
    }

    @Override
    public String fileExtension() {
        return ".json";
    }
}
