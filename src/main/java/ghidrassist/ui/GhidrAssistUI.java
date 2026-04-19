package ghidrassist.ui;

import javax.swing.*;

import ghidra.program.util.ProgramLocation;

import java.awt.*;
import ghidrassist.GhidrAssistPlugin;
import ghidrassist.ui.tabs.*;
import ghidrassist.core.TabController;
import ghidrassist.ui.common.UIConstants;

public class GhidrAssistUI extends JPanel {
    private static final long serialVersionUID = 1L;

	private final GhidrAssistPlugin plugin;
    private final TabController controller;
    private final JTabbedPane tabbedPane;
    private final ExplainTab explainTab;
    private final QueryTab queryTab;
    private final ActionsTab actionsTab;
    private final RAGManagementTab ragManagementTab;
    private final SettingsTab settingsTab;
    private final SemanticGraphTab semanticGraphTab;
    private SymGraphTab symGraphTab;

    public GhidrAssistUI(GhidrAssistPlugin plugin) {
        super(new BorderLayout());
        this.plugin = plugin;
        this.controller = new TabController(plugin);

        // Initialize components
        this.tabbedPane = new JTabbedPane();

        // Create tabs
        this.explainTab = new ExplainTab(controller);
        this.queryTab = new QueryTab(controller);
        this.actionsTab = new ActionsTab(controller);
        this.ragManagementTab = new RAGManagementTab(controller);
        this.settingsTab = new SettingsTab(controller);
        this.semanticGraphTab = new SemanticGraphTab(controller);
        this.symGraphTab = new SymGraphTab(controller);

        // Set tab references in controller
        controller.setExplainTab(explainTab);
        controller.setQueryTab(queryTab);
        controller.setActionsTab(actionsTab);
        controller.setRAGManagementTab(ragManagementTab);
        controller.setSettingsTab(settingsTab);
        controller.setSemanticGraphTab(semanticGraphTab);
        controller.setSymGraphTab(symGraphTab);

        initializeUI();
    }

    private void initializeUI() {
        setBorder(UIConstants.PANEL_BORDER);

        // Add tabs
        tabbedPane.addTab("Explain", explainTab);
        tabbedPane.addTab("Query", queryTab);
        tabbedPane.addTab("Actions", actionsTab);
        tabbedPane.addTab("Semantic Graph", semanticGraphTab);
        tabbedPane.addTab("SymGraph", symGraphTab);
        tabbedPane.addTab("RAG", ragManagementTab);
        tabbedPane.addTab("Settings", settingsTab);

        add(tabbedPane, BorderLayout.CENTER);

        // Initialize tabs that need startup data
        SwingUtilities.invokeLater(() -> {
            // Load initial context
            controller.handleContextLoad();

            // Load RAG file list
            controller.refreshRAGDocuments();
        });

        tabbedPane.addChangeListener(e -> {
            if (tabbedPane.getSelectedComponent() == settingsTab) {
                // Load current context when Settings tab is selected
                controller.handleContextLoad();
            } else if (tabbedPane.getSelectedComponent() == symGraphTab) {
                // Update binary info when SymGraph tab is selected
                controller.updateSymGraphBinaryInfo();
            }
        });
    }

    public void updateLocation(ProgramLocation loc) {
        if (loc != null && loc.getAddress() != null) {
            explainTab.updateOffset(loc.getAddress().toString());
            controller.updateAnalysis(loc);
            controller.updateSemanticGraphLocation(loc);
            controller.handleLocationUpdate(loc);  // Update line explanation display
        }
    }

    public JComponent getComponent() {
        return this;
    }

    public GhidrAssistPlugin getPlugin() {
        return plugin;
    }
}
