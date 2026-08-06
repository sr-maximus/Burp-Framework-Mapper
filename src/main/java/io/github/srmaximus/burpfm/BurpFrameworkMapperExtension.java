// SPDX-License-Identifier: Apache-2.0
package io.github.srmaximus.burpfm;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.contextmenu.AuditIssueContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import io.github.srmaximus.burpfm.importer.BurpIssueImporter;
import io.github.srmaximus.burpfm.ui.MapperPanel;

import javax.swing.JMenuItem;
import javax.swing.SwingUtilities;
import javax.swing.SwingWorker;
import java.awt.Component;
import java.util.List;
import java.util.function.Consumer;

public final class BurpFrameworkMapperExtension implements BurpExtension {
    private static final String NAME = "Burp Framework Mapper";

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName(NAME);
        SwingUtilities.invokeLater(() -> initializeUi(api));
    }

    private void initializeUi(MontoyaApi api) {
        try {
            Consumer<String> errorLogger = message -> api.logging().logToError(message);
            MapperPanel panel = new MapperPanel(errorLogger);
            api.userInterface().applyThemeToComponent(panel);
            api.userInterface().registerSuiteTab("Framework Mapper", panel);
            api.userInterface().registerContextMenuItemsProvider(new IssueMenuProvider(panel, errorLogger));
            api.logging().logToOutput(NAME + " 0.1.0 loaded. All analysis remains local.");
        } catch (RuntimeException exception) {
            api.logging().logToError(NAME + " could not initialize", exception);
        }
    }

    private static final class IssueMenuProvider implements ContextMenuItemsProvider {
        private final MapperPanel panel;
        private final Consumer<String> errorLogger;
        private final BurpIssueImporter importer = new BurpIssueImporter();

        private IssueMenuProvider(MapperPanel panel, Consumer<String> errorLogger) {
            this.panel = panel;
            this.errorLogger = errorLogger;
        }

        @Override
        public List<Component> provideMenuItems(AuditIssueContextMenuEvent event) {
            return menuFor(event.selectedIssues());
        }

        private List<Component> menuFor(List<burp.api.montoya.scanner.audit.issues.AuditIssue> issues) {
            if (issues == null || issues.isEmpty()) {
                return List.of();
            }
            JMenuItem item = new JMenuItem("Send issue summary to Framework Mapper");
            List<burp.api.montoya.scanner.audit.issues.AuditIssue> snapshot = List.copyOf(issues);
            item.addActionListener(event -> new SwingWorker<List<io.github.srmaximus.burpfm.model.FindingInput>, Void>() {
                @Override
                protected List<io.github.srmaximus.burpfm.model.FindingInput> doInBackground() {
                    return importer.importIssues(snapshot);
                }

                @Override
                protected void done() {
                    try {
                        panel.importFindings(get());
                    } catch (Exception exception) {
                        errorLogger.accept("Burp issue import failed safely: " + exception.getMessage());
                    }
                }
            }.execute());
            return List.of(item);
        }
    }
}
