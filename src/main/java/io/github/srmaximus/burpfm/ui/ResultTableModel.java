// SPDX-License-Identifier: Apache-2.0
package io.github.srmaximus.burpfm.ui;

import io.github.srmaximus.burpfm.model.AnalysisResult;
import io.github.srmaximus.burpfm.model.CorrelationResult;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

final class ResultTableModel extends AbstractTableModel {
    private static final String[] COLUMNS = {
            "Framework", "Identifier", "Title", "Relationship", "Confidence", "Score", "Source"
    };
    private final List<Row> rows = new ArrayList<>();

    void setResults(List<AnalysisResult> results) {
        rows.clear();
        for (AnalysisResult analysis : results) {
            for (CorrelationResult correlation : analysis.correlations()) {
                rows.add(new Row(analysis.finding().title(), correlation));
            }
        }
        fireTableDataChanged();
    }

    Row row(int modelIndex) {
        return rows.get(modelIndex);
    }

    @Override
    public int getRowCount() {
        return rows.size();
    }

    @Override
    public int getColumnCount() {
        return COLUMNS.length;
    }

    @Override
    public String getColumnName(int column) {
        return COLUMNS[column];
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        CorrelationResult result = rows.get(rowIndex).correlation();
        return switch (columnIndex) {
            case 0 -> result.framework();
            case 1 -> result.identifier();
            case 2 -> result.title();
            case 3 -> result.relationType();
            case 4 -> result.confidence();
            case 5 -> result.confidenceScore();
            case 6 -> result.officialUrl();
            default -> "";
        };
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        return columnIndex == 5 ? Double.class : Object.class;
    }

    record Row(String findingTitle, CorrelationResult correlation) {
    }
}
