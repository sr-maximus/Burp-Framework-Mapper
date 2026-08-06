// SPDX-License-Identifier: Apache-2.0
package io.github.srmaximus.burpfm.ui;

import io.github.srmaximus.burpfm.engine.AnalyzerFacade;
import io.github.srmaximus.burpfm.engine.CweParser;
import io.github.srmaximus.burpfm.catalog.CatalogLoader;
import io.github.srmaximus.burpfm.export.CsvReportExporter;
import io.github.srmaximus.burpfm.export.JsonReportExporter;
import io.github.srmaximus.burpfm.export.MarkdownReportExporter;
import io.github.srmaximus.burpfm.export.ReportExporter;
import io.github.srmaximus.burpfm.export.SafeFileWriter;
import io.github.srmaximus.burpfm.export.SarifReportExporter;
import io.github.srmaximus.burpfm.model.AnalysisReport;
import io.github.srmaximus.burpfm.model.AnalysisResult;
import io.github.srmaximus.burpfm.model.CorrelationResult;
import io.github.srmaximus.burpfm.model.FindingInput;
import io.github.srmaximus.burpfm.model.Surface;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.RowFilter;
import javax.swing.SwingUtilities;
import javax.swing.SwingWorker;
import javax.swing.table.TableRowSorter;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Consumer;
import java.util.regex.Pattern;

public final class MapperPanel extends JPanel {
    private static final int MAX_MANUAL_TEXT = 20_000;
    private final AnalyzerFacade analyzer;
    private final Consumer<String> logger;
    private final JTextField title = new JTextField();
    private final JTextArea description = area(5);
    private final JTextArea evidence = area(4);
    private final JTextField asset = new JTextField();
    private final JComboBox<Surface> surface = new JComboBox<>(Surface.values());
    private final JTextField cwes = new JTextField();
    private final JTextField cve = new JTextField();
    private final JTextField cvss = new JTextField();
    private final JTextArea businessContext = area(3);
    private final JTextField tags = new JTextField();
    private final ResultTableModel tableModel = new ResultTableModel();
    private final JTable resultTable = new JTable(tableModel);
    private final TableRowSorter<ResultTableModel> sorter = new TableRowSorter<>(tableModel);
    private final JComboBox<String> frameworkFilter = new JComboBox<>();
    private final JComboBox<String> relationFilter = new JComboBox<>();
    private final JComboBox<String> confidenceFilter = new JComboBox<>();
    private final JTextArea detail = area(10);
    private final JTextArea summary = area(10);
    private final JTextArea matrix = area(10);
    private final JLabel status = new JLabel("Ready. Processing is local and deterministic.");
    private final JButton analyzeButton = new JButton("Analyze locally");
    private List<AnalysisResult> latestResults = List.of();

    public MapperPanel(Consumer<String> logger) {
        this(new AnalyzerFacade(), logger);
    }

    MapperPanel(AnalyzerFacade analyzer, Consumer<String> logger) {
        super(new BorderLayout(8, 8));
        this.analyzer = Objects.requireNonNull(analyzer, "analyzer");
        this.logger = logger == null ? ignored -> { } : logger;
        setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));
        add(createNotice(), BorderLayout.NORTH);
        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, createInputPanel(), createOutputPanel());
        split.setResizeWeight(0.36);
        split.setDividerLocation(430);
        add(split, BorderLayout.CENTER);
        add(status, BorderLayout.SOUTH);
        wireActions();
    }

    public void importFindings(List<FindingInput> findings) {
        Runnable action = () -> {
            if (findings == null || findings.isEmpty()) {
                return;
            }
            populate(findings.getFirst());
            analyze(findings);
        };
        if (SwingUtilities.isEventDispatchThread()) {
            action.run();
        } else {
            SwingUtilities.invokeLater(action);
        }
    }

    private Component createNotice() {
        JLabel label = new JLabel("Catalog " + CatalogLoader.CATALOG_VERSION + " · "
                + CatalogLoader.CURATED_RULE_COUNT + " rules. Local classifier only — no traffic generation or external transmission. "
                + "Human review is required; results are not compliance certification or proof of adversary activity.");
        label.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createEtchedBorder(), BorderFactory.createEmptyBorder(7, 8, 7, 8)));
        return label;
    }

    private Component createInputPanel() {
        JPanel fields = new JPanel(new GridBagLayout());
        GridBagConstraints constraints = new GridBagConstraints();
        constraints.insets = new Insets(3, 3, 3, 3);
        constraints.fill = GridBagConstraints.HORIZONTAL;
        constraints.weightx = 1;
        constraints.gridx = 0;
        constraints.gridy = 0;
        addField(fields, constraints, "Finding title *", title);
        addField(fields, constraints, "Description", new JScrollPane(description));
        addField(fields, constraints, "Evidence / remediation notes", new JScrollPane(evidence));
        addField(fields, constraints, "Asset (query strings are removed on Burp import)", asset);
        addField(fields, constraints, "Surface", surface);
        addField(fields, constraints, "CWE IDs (comma or space separated)", cwes);
        addField(fields, constraints, "CVE", cve);
        addField(fields, constraints, "CVSS 4.0 vector", cvss);
        addField(fields, constraints, "Business context", new JScrollPane(businessContext));
        addField(fields, constraints, "Tags (comma separated)", tags);
        constraints.weighty = 1;
        constraints.fill = GridBagConstraints.BOTH;
        fields.add(Box.createGlue(), constraints);

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEADING));
        buttons.add(analyzeButton);
        JButton example = new JButton("Load synthetic example");
        example.addActionListener(event -> loadSyntheticExample());
        buttons.add(example);
        JButton clear = new JButton("Clear");
        clear.addActionListener(event -> clearAll());
        buttons.add(clear);

        JPanel container = new JPanel(new BorderLayout());
        container.setBorder(BorderFactory.createTitledBorder("Finding input"));
        container.add(new JScrollPane(fields), BorderLayout.CENTER);
        container.add(buttons, BorderLayout.SOUTH);
        container.setMinimumSize(new Dimension(350, 500));
        return container;
    }

    private Component createOutputPanel() {
        resultTable.setRowSorter(sorter);
        resultTable.setAutoCreateRowSorter(false);
        resultTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        resultTable.getColumnModel().getColumn(0).setPreferredWidth(130);
        resultTable.getColumnModel().getColumn(1).setPreferredWidth(125);
        resultTable.getColumnModel().getColumn(2).setPreferredWidth(240);
        resultTable.getColumnModel().getColumn(3).setPreferredWidth(150);
        resultTable.getColumnModel().getColumn(4).setPreferredWidth(100);
        resultTable.getColumnModel().getColumn(5).setPreferredWidth(70);
        resultTable.getColumnModel().getColumn(6).setPreferredWidth(340);

        JPanel filters = new JPanel(new FlowLayout(FlowLayout.LEADING));
        initializeFilter(frameworkFilter, "All frameworks");
        initializeFilter(relationFilter, "All relationships");
        initializeFilter(confidenceFilter, "All confidence levels");
        filters.add(new JLabel("Filter:"));
        filters.add(frameworkFilter);
        filters.add(relationFilter);
        filters.add(confidenceFilter);

        detail.setEditable(false);
        summary.setEditable(false);
        matrix.setEditable(false);
        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Results", new JScrollPane(resultTable));
        tabs.addTab("Why / source", new JScrollPane(detail));
        tabs.addTab("Summary", new JScrollPane(summary));
        tabs.addTab("Correlation matrix", new JScrollPane(matrix));

        JPanel exports = new JPanel(new FlowLayout(FlowLayout.LEADING));
        Map<String, ReportExporter> exporters = new LinkedHashMap<>();
        exporters.put("Export JSON", new JsonReportExporter());
        exporters.put("Export CSV", new CsvReportExporter());
        exporters.put("Export Markdown", new MarkdownReportExporter());
        exporters.put("Export SARIF", new SarifReportExporter());
        exporters.forEach((label, exporter) -> {
            JButton button = new JButton(label);
            button.addActionListener(event -> export(exporter));
            exports.add(button);
        });

        JPanel container = new JPanel(new BorderLayout(4, 4));
        container.setBorder(BorderFactory.createTitledBorder("Framework correlations"));
        container.add(filters, BorderLayout.NORTH);
        container.add(tabs, BorderLayout.CENTER);
        container.add(exports, BorderLayout.SOUTH);
        return container;
    }

    private void wireActions() {
        analyzeButton.addActionListener(event -> {
            if (title.getText() == null || title.getText().isBlank()) {
                showError("A finding title is required.");
                return;
            }
            analyze(List.of(readForm()));
        });
        resultTable.getSelectionModel().addListSelectionListener(event -> showSelectedDetail());
        frameworkFilter.addActionListener(event -> applyFilters());
        relationFilter.addActionListener(event -> applyFilters());
        confidenceFilter.addActionListener(event -> applyFilters());
    }

    private void analyze(List<FindingInput> findings) {
        if (findings.isEmpty() || findings.stream().allMatch(finding -> finding.title().isBlank())) {
            showError("A finding title is required.");
            return;
        }
        analyzeButton.setEnabled(false);
        status.setText("Analyzing " + findings.size() + " finding(s) locally…");
        new SwingWorker<List<AnalysisResult>, Void>() {
            @Override
            protected List<AnalysisResult> doInBackground() {
                return findings.stream().map(analyzer::analyze).toList();
            }

            @Override
            protected void done() {
                try {
                    latestResults = List.copyOf(get());
                    tableModel.setResults(latestResults);
                    rebuildFilters();
                    updateSummary();
                    status.setText("Completed: " + tableModel.getRowCount() + " curated correlation(s). Review every result.");
                } catch (Exception exception) {
                    logger.accept("Analysis failed: " + exception.getMessage());
                    showError("Analysis failed safely. See the Burp extension error log for details.");
                    status.setText("Analysis failed; no partial result was exported.");
                } finally {
                    analyzeButton.setEnabled(true);
                }
            }
        }.execute();
    }

    private FindingInput readForm() {
        return new FindingInput(
                null,
                bounded(title.getText()),
                bounded(description.getText()),
                bounded(evidence.getText()),
                bounded(asset.getText()),
                (Surface) surface.getSelectedItem(),
                CweParser.parse(cwes.getText()),
                bounded(cve.getText()),
                bounded(cvss.getText()),
                bounded(businessContext.getText()),
                "",
                "",
                splitComma(tags.getText()),
                "manual");
    }

    private void populate(FindingInput finding) {
        title.setText(finding.title());
        description.setText(finding.description());
        evidence.setText(finding.evidence());
        asset.setText(finding.asset());
        surface.setSelectedItem(finding.surface());
        cwes.setText(String.join(", ", finding.cweIds()));
        cve.setText(finding.cve());
        cvss.setText(finding.cvssVector());
        businessContext.setText(finding.businessContext());
        tags.setText(String.join(", ", finding.tags()));
    }

    private void rebuildFilters() {
        setFilterValues(frameworkFilter, "All frameworks", latestResults.stream()
                .flatMap(result -> result.correlations().stream()).map(CorrelationResult::framework).distinct().sorted().toList());
        setFilterValues(relationFilter, "All relationships", latestResults.stream()
                .flatMap(result -> result.correlations().stream()).map(result -> result.relationType().toString()).distinct().sorted().toList());
        setFilterValues(confidenceFilter, "All confidence levels", latestResults.stream()
                .flatMap(result -> result.correlations().stream()).map(result -> result.confidence().toString()).distinct().sorted().toList());
        applyFilters();
    }

    private void applyFilters() {
        List<RowFilter<ResultTableModel, Integer>> filters = new ArrayList<>();
        addFilter(filters, frameworkFilter, 0);
        addFilter(filters, relationFilter, 3);
        addFilter(filters, confidenceFilter, 4);
        sorter.setRowFilter(filters.isEmpty() ? null : RowFilter.andFilter(filters));
    }

    private static void addFilter(List<RowFilter<ResultTableModel, Integer>> filters,
                                  JComboBox<String> combo, int column) {
        if (combo.getSelectedIndex() > 0 && combo.getSelectedItem() != null) {
            filters.add(RowFilter.regexFilter("^" + Pattern.quote(combo.getSelectedItem().toString()) + "$", column));
        }
    }

    private void showSelectedDetail() {
        int selected = resultTable.getSelectedRow();
        if (selected < 0) {
            return;
        }
        ResultTableModel.Row row = tableModel.row(resultTable.convertRowIndexToModel(selected));
        CorrelationResult result = row.correlation();
        detail.setText("Finding: " + row.findingTitle()
                + "\nFramework: " + result.framework() + " " + result.frameworkVersion()
                + "\nControl / technique: " + result.identifier() + " — " + result.title()
                + "\nRelationship: " + result.relationType()
                + "\nConfidence: " + result.confidence() + " (" + result.confidenceScore() + ")"
                + "\nMatched signals: " + String.join(", ", result.matchedSignals())
                + "\n\nWhy: " + result.explanation()
                + "\n\nLimitations: " + result.limitations()
                + "\n\nOfficial source: " + result.officialUrl()
                + "\nVerified: " + result.verifiedDate());
        detail.setCaretPosition(0);
    }

    private void updateSummary() {
        long invalidCvss = latestResults.stream().filter(result -> !result.cvss().valid() && !result.cvss().vector().isBlank()).count();
        Map<String, Long> counts = new java.util.TreeMap<>();
        latestResults.stream().flatMap(result -> result.correlations().stream())
                .forEach(result -> counts.merge(result.framework(), 1L, Long::sum));
        StringBuilder text = new StringBuilder()
                .append("Findings analyzed: ").append(latestResults.size()).append('\n')
                .append("Correlations shown: ").append(tableModel.getRowCount()).append('\n')
                .append("Invalid CVSS vectors: ").append(invalidCvss).append("\n\nBy framework:\n");
        counts.forEach((framework, count) -> text.append("• ").append(framework).append(": ").append(count).append('\n'));
        text.append("\nNo match is also a valid outcome. The embedded catalog is intentionally curated, versioned and finite.");
        summary.setText(text.toString());
        summary.setCaretPosition(0);
        matrix.setText(CorrelationMatrixFormatter.format(latestResults));
        matrix.setCaretPosition(0);
    }

    private void export(ReportExporter exporter) {
        if (latestResults.isEmpty()) {
            showError("Analyze at least one finding before exporting.");
            return;
        }
        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new java.io.File("burp-framework-mapper-report" + exporter.fileExtension()));
        if (chooser.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) {
            return;
        }
        Path target = chooser.getSelectedFile().toPath();
        boolean exists = java.nio.file.Files.exists(target.toAbsolutePath().normalize());
        boolean overwrite = false;
        if (exists) {
            overwrite = JOptionPane.showConfirmDialog(this,
                    "The selected file exists. Overwrite it?", "Confirm overwrite",
                    JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE) == JOptionPane.YES_OPTION;
            if (!overwrite) {
                return;
            }
        }
        try {
            Path written = SafeFileWriter.write(target, exporter.fileExtension(),
                    exporter.export(AnalysisReport.of(latestResults)), overwrite);
            status.setText("Exported locally to " + written);
        } catch (Exception exception) {
            logger.accept("Export failed: " + exception.getMessage());
            showError("Export failed safely: " + exception.getMessage());
        }
    }

    private void loadSyntheticExample() {
        populate(new FindingInput(null,
                "Synthetic SQL injection in product lookup",
                "A parameterized laboratory endpoint accepted SQL metacharacters and returned a database error.",
                "Synthetic evidence only; no live request or secret is included.",
                "https://example.invalid/api/products",
                Surface.API,
                List.of("CWE-89"),
                "",
                "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                "Training application with non-production data.",
                "High", "Certain", List.of("synthetic", "training"), "example"));
        status.setText("Synthetic example loaded. Select Analyze locally to correlate it.");
    }

    private void clearAll() {
        title.setText("");
        description.setText("");
        evidence.setText("");
        asset.setText("");
        surface.setSelectedItem(Surface.GENERIC_UNKNOWN);
        cwes.setText("");
        cve.setText("");
        cvss.setText("");
        businessContext.setText("");
        tags.setText("");
        latestResults = List.of();
        tableModel.setResults(List.of());
        detail.setText("");
        summary.setText("");
        matrix.setText("");
        status.setText("Cleared.");
    }

    private void showError(String message) {
        JOptionPane.showMessageDialog(this, message, "Burp Framework Mapper", JOptionPane.ERROR_MESSAGE);
    }

    private static void addField(JPanel panel, GridBagConstraints constraints, String label, Component component) {
        constraints.weighty = 0;
        constraints.fill = GridBagConstraints.HORIZONTAL;
        panel.add(new JLabel(label), constraints);
        constraints.gridy++;
        if (component instanceof JScrollPane) {
            constraints.fill = GridBagConstraints.BOTH;
            constraints.weighty = 0.15;
        }
        panel.add(component, constraints);
        constraints.gridy++;
    }

    private static JTextArea area(int rows) {
        JTextArea area = new JTextArea(rows, 30);
        area.setLineWrap(true);
        area.setWrapStyleWord(true);
        return area;
    }

    private static void initializeFilter(JComboBox<String> combo, String allLabel) {
        combo.addItem(allLabel);
    }

    private static void setFilterValues(JComboBox<String> combo, String allLabel, List<String> values) {
        combo.removeAllItems();
        combo.addItem(allLabel);
        values.forEach(combo::addItem);
    }

    private static List<String> splitComma(String input) {
        if (input == null || input.isBlank()) {
            return List.of();
        }
        return java.util.Arrays.stream(input.split(","))
                .map(String::trim).filter(value -> !value.isBlank()).distinct().toList();
    }

    private static String bounded(String value) {
        if (value == null) {
            return "";
        }
        String trimmed = value.trim();
        return trimmed.length() <= MAX_MANUAL_TEXT ? trimmed : trimmed.substring(0, MAX_MANUAL_TEXT);
    }
}
