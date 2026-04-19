package ghidrassist.ui.tabs;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableCellRenderer;
import java.awt.*;
import java.awt.event.FocusEvent;
import java.awt.event.FocusListener;
import java.awt.image.BufferedImage;
import java.io.File;
import java.lang.reflect.Type;
import java.util.List;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import ghidra.framework.preferences.Preferences;
import ghidrassist.GhidrAssistPlugin;
import ghidrassist.apiprovider.APIProvider;
import ghidrassist.apiprovider.APIProviderConfig;
import ghidrassist.core.TabController;
import ghidrassist.ui.GhidrAssistUI;
import ghidrassist.mcp2.server.MCPServerConfig;
import ghidrassist.mcp2.server.MCPServerRegistry;
import ghidrassist.services.symgraph.SymGraphService;
import ghidrassist.apiprovider.oauth.OAuthCallbackServer;
import ghidrassist.apiprovider.oauth.OpenAIOAuthTokenManager;
import ghidrassist.apiprovider.oauth.GeminiOAuthTokenManager;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * Unified Settings tab matching BinAssist's layout.
 * Contains all settings in scrollable grouped sections:
 * - LLM Providers
 * - MCP Servers
 * - SymGraph
 * - System Prompt
 * - Database Paths
 * - Analysis Options
 */
public class SettingsTab extends JPanel {
    private static final long serialVersionUID = 1L;
    private static final String VERSION = "1.29.0";
    private static final String[] REASONING_EFFORT_OPTIONS = {"None", "Low", "Medium", "High"};

    private final TabController controller;
    private final GhidrAssistPlugin plugin;

    // LLM Providers section components
    private DefaultTableModel llmTableModel;
    private JTable llmTable;
    private JComboBox<String> activeProviderComboBox;
    private JComboBox<String> reasoningEffortCombo;
    private List<APIProviderConfig> apiProviders;
    private String selectedProviderName;

    // MCP Servers section components
    private JTable mcpServersTable;
    private MCPServersTableModel mcpTableModel;

    // SymGraph section components
    private JTextField symGraphUrlField;
    private JPasswordField symGraphKeyField;
    private JCheckBox symGraphDisableTlsCheckbox;
    private JButton showKeyButton;
    private JButton symGraphTestButton;
    private JLabel symGraphTestStatusLabel;
    private boolean keyVisible = false;

    // System Prompt section components
    private JTextArea contextArea;
    private JButton saveButton;
    private JButton revertButton;

    // Database Paths section components
    private JTextField analysisDbPathField;
    private JTextField rlhfDbPathField;
    private JTextField luceneIndexPathField;

    // Analysis Options section components
    private JSpinner maxToolCallsSpinner;

    // Test status indicators
    private JButton llmTestButton;
    private JLabel llmTestStatusLabel;
    private JButton mcpTestButton;
    private JLabel mcpTestStatusLabel;
    private ImageIcon successIcon;
    private ImageIcon failureIcon;

    // Active test workers for cancel support
    private SwingWorker<Boolean, Void> activeLlmTestWorker;
    private SwingWorker<Boolean, Void> activeMcpTestWorker;
    private SwingWorker<Boolean, Void> activeSymGraphTestWorker;

    public SettingsTab(TabController controller) {
        super(new BorderLayout());
        this.controller = controller;
        this.plugin = controller.getPlugin();

        loadApiProviders();
        initializeComponents();
        layoutComponents();
        setupListeners();
        loadSettings();
    }

    private void loadApiProviders() {
        String providersJson = Preferences.getProperty("GhidrAssist.APIProviders", "[]");
        Gson gson = new Gson();
        Type listType = new TypeToken<List<APIProviderConfig>>() {}.getType();
        apiProviders = gson.fromJson(providersJson, listType);
        if (apiProviders == null) {
            apiProviders = new java.util.ArrayList<>();
        } else {
            for (APIProviderConfig provider : apiProviders) {
                if (provider != null) {
                    provider.normalizeLegacyDefaults();
                }
            }
        }
        selectedProviderName = Preferences.getProperty("GhidrAssist.SelectedAPIProvider", "");
    }

    private void initializeComponents() {
        // Create test status icons
        successIcon = createSuccessIcon();
        failureIcon = createFailureIcon();

        // Test status labels
        llmTestStatusLabel = new JLabel();
        llmTestStatusLabel.setPreferredSize(new Dimension(20, 20));
        mcpTestStatusLabel = new JLabel();
        mcpTestStatusLabel.setPreferredSize(new Dimension(20, 20));

        // LLM Providers
        String[] llmColumnNames = {"Name", "Model", "Type", "URL"};
        llmTableModel = new DefaultTableModel(llmColumnNames, 0) {
            private static final long serialVersionUID = 1L;
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        llmTable = new JTable(llmTableModel);
        llmTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

        activeProviderComboBox = new JComboBox<>();
        reasoningEffortCombo = new JComboBox<>(REASONING_EFFORT_OPTIONS);
        reasoningEffortCombo.setToolTipText(
            "Extended thinking for complex queries\n" +
            "None: Standard response (default)\n" +
            "Low: ~2K thinking tokens\n" +
            "Medium: ~10K thinking tokens\n" +
            "High: ~25K thinking tokens"
        );

        // Populate LLM table and combo
        for (APIProviderConfig provider : apiProviders) {
            llmTableModel.addRow(new Object[] {
                provider.getName(),
                provider.getModel(),
                getProviderTypeDisplayName(provider.getType()),
                provider.getUrl()
            });
            activeProviderComboBox.addItem(provider.getName());
        }
        activeProviderComboBox.setSelectedItem(selectedProviderName);

        // MCP Servers
        mcpTableModel = new MCPServersTableModel();
        mcpServersTable = new JTable(mcpTableModel);
        mcpServersTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

        // SymGraph
        symGraphUrlField = new JTextField(30);
        symGraphKeyField = new JPasswordField(30);
        symGraphDisableTlsCheckbox = new JCheckBox("Disable TLS Verification");
        showKeyButton = new JButton("Show");
        symGraphTestButton = new JButton("Test");
        symGraphTestStatusLabel = new JLabel();
        symGraphTestStatusLabel.setPreferredSize(new Dimension(20, 20));

        // System Prompt
        contextArea = new JTextArea();
        contextArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        contextArea.setLineWrap(true);
        contextArea.setWrapStyleWord(true);
        saveButton = new JButton("Save");
        revertButton = new JButton("Revert");

        // Database Paths
        analysisDbPathField = new JTextField(30);
        rlhfDbPathField = new JTextField(30);
        luceneIndexPathField = new JTextField(30);

        // Analysis Options
        SpinnerNumberModel spinnerModel = new SpinnerNumberModel(10, 1, 500, 1);
        maxToolCallsSpinner = new JSpinner(spinnerModel);
        maxToolCallsSpinner.setPreferredSize(new Dimension(75, maxToolCallsSpinner.getPreferredSize().height));
        maxToolCallsSpinner.setToolTipText("Maximum tool calls per ReAct iteration (default: 10). Plain Query/MCP mode is unlimited.");

        autoSizeTableColumns(llmTable);
        autoSizeTableColumns(mcpServersTable);
    }

    private void layoutComponents() {
        // Create scroll area
        JPanel contentPanel = new JPanel();
        contentPanel.setLayout(new BoxLayout(contentPanel, BoxLayout.Y_AXIS));
        contentPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Add sections
        contentPanel.add(createLLMProvidersSection());
        contentPanel.add(Box.createVerticalStrut(10));
        contentPanel.add(createMCPServersSection());
        contentPanel.add(Box.createVerticalStrut(10));
        contentPanel.add(createSymGraphSection());
        contentPanel.add(Box.createVerticalStrut(10));
        contentPanel.add(createSystemPromptSection());
        contentPanel.add(Box.createVerticalStrut(10));
        contentPanel.add(createDatabasePathsSection());
        contentPanel.add(Box.createVerticalStrut(10));
        contentPanel.add(createAnalysisOptionsSection());
        contentPanel.add(Box.createVerticalGlue());

        JScrollPane scrollPane = new JScrollPane(contentPanel);
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        scrollPane.getVerticalScrollBar().setUnitIncrement(16);

        add(scrollPane, BorderLayout.CENTER);

        // Bottom panel with version
        JPanel bottomPanel = new JPanel(new BorderLayout());
        JLabel versionLabel = new JLabel("GhidrAssist v" + VERSION);
        versionLabel.setBorder(BorderFactory.createEmptyBorder(5, 10, 5, 5));
        bottomPanel.add(versionLabel, BorderLayout.WEST);
        add(bottomPanel, BorderLayout.SOUTH);
    }

    private JPanel createLLMProvidersSection() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder("LLM Providers"));

        // Table
        JScrollPane tableScrollPane = new JScrollPane(llmTable);
        tableScrollPane.setPreferredSize(new Dimension(600, 120));

        // Buttons
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton addButton = new JButton("Add");
        JButton editButton = new JButton("Edit");
        JButton duplicateButton = new JButton("Duplicate");
        JButton deleteButton = new JButton("Delete");
        llmTestButton = new JButton("Test");

        addButton.addActionListener(e -> onAddProvider());
        editButton.addActionListener(e -> onEditProvider());
        duplicateButton.addActionListener(e -> onDuplicateProvider());
        deleteButton.addActionListener(e -> onDeleteProvider());
        llmTestButton.addActionListener(e -> onTestProvider());

        buttonPanel.add(addButton);
        buttonPanel.add(editButton);
        buttonPanel.add(duplicateButton);
        buttonPanel.add(deleteButton);
        buttonPanel.add(llmTestButton);
        buttonPanel.add(llmTestStatusLabel);

        // Active provider and reasoning effort
        JPanel selectionPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        selectionPanel.add(new JLabel("Active Provider:"));
        activeProviderComboBox.setMaximumSize(new Dimension(200, activeProviderComboBox.getPreferredSize().height));
        selectionPanel.add(activeProviderComboBox);
        selectionPanel.add(Box.createHorizontalStrut(20));
        selectionPanel.add(new JLabel("Reasoning Effort:"));
        selectionPanel.add(reasoningEffortCombo);

        JPanel southPanel = new JPanel();
        southPanel.setLayout(new BoxLayout(southPanel, BoxLayout.Y_AXIS));
        southPanel.add(buttonPanel);
        southPanel.add(selectionPanel);

        panel.add(tableScrollPane, BorderLayout.CENTER);
        panel.add(southPanel, BorderLayout.SOUTH);

        return panel;
    }

    private JPanel createMCPServersSection() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder("MCP Servers"));

        JScrollPane tableScrollPane = new JScrollPane(mcpServersTable);
        tableScrollPane.setPreferredSize(new Dimension(600, 100));

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton addButton = new JButton("Add Server");
        JButton editButton = new JButton("Edit");
        JButton duplicateButton = new JButton("Duplicate");
        JButton removeButton = new JButton("Remove");
        mcpTestButton = new JButton("Test Connection");

        addButton.addActionListener(e -> showMCPAddEditDialog(null));
        editButton.addActionListener(e -> {
            int row = mcpServersTable.getSelectedRow();
            if (row >= 0) showMCPAddEditDialog(mcpTableModel.getServerAt(row));
        });
        duplicateButton.addActionListener(e -> onDuplicateMCPServer());
        removeButton.addActionListener(e -> onRemoveMCPServer());
        mcpTestButton.addActionListener(e -> onTestMCPServer());

        buttonPanel.add(addButton);
        buttonPanel.add(editButton);
        buttonPanel.add(duplicateButton);
        buttonPanel.add(removeButton);
        buttonPanel.add(mcpTestButton);
        buttonPanel.add(mcpTestStatusLabel);

        panel.add(tableScrollPane, BorderLayout.CENTER);
        panel.add(buttonPanel, BorderLayout.SOUTH);

        return panel;
    }

    private JPanel createSymGraphSection() {
        JPanel panel = new JPanel();
        panel.setBorder(BorderFactory.createTitledBorder("SymGraph"));
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));

        // API URL row
        JPanel urlRow = new JPanel(new FlowLayout(FlowLayout.LEFT));
        urlRow.add(new JLabel("API URL:"));
        symGraphUrlField.setText(Preferences.getProperty("GhidrAssist.SymGraphAPIUrl", "https://symgraph.ai"));
        symGraphUrlField.setToolTipText("SymGraph API URL (for self-hosted instances)");
        urlRow.add(symGraphUrlField);

        // API Key row
        JPanel keyRow = new JPanel(new FlowLayout(FlowLayout.LEFT));
        keyRow.add(new JLabel("API Key:"));
        symGraphKeyField.setText(Preferences.getProperty("GhidrAssist.SymGraphAPIKey", ""));
        symGraphKeyField.setToolTipText("Your SymGraph API key (required for push/pull operations)");
        keyRow.add(symGraphKeyField);
        keyRow.add(showKeyButton);
        keyRow.add(symGraphTestButton);
        keyRow.add(symGraphTestStatusLabel);

        // TLS checkbox row
        JPanel tlsRow = new JPanel(new FlowLayout(FlowLayout.LEFT));
        symGraphDisableTlsCheckbox.setSelected("true".equals(
            Preferences.getProperty("GhidrAssist.SymGraphDisableTls", "false")));
        symGraphDisableTlsCheckbox.setToolTipText("Disable TLS certificate verification for self-signed certificates");
        tlsRow.add(symGraphDisableTlsCheckbox);

        // Info label
        JLabel infoLabel = new JLabel("<html><i>SymGraph provides cloud-based symbol and graph data sharing. " +
                                      "Query operations are free; push/pull require an API key.</i></html>");
        infoLabel.setForeground(Color.GRAY);
        JPanel infoRow = new JPanel(new FlowLayout(FlowLayout.LEFT));
        infoRow.add(infoLabel);

        panel.add(urlRow);
        panel.add(keyRow);
        panel.add(tlsRow);
        panel.add(infoRow);

        return panel;
    }

    private JPanel createSystemPromptSection() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder("System Prompt"));

        JScrollPane scrollPane = new JScrollPane(contextArea);
        scrollPane.setPreferredSize(new Dimension(600, 100));

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        buttonPanel.add(revertButton);
        buttonPanel.add(saveButton);

        panel.add(scrollPane, BorderLayout.CENTER);
        panel.add(buttonPanel, BorderLayout.SOUTH);

        return panel;
    }

    private JPanel createDatabasePathsSection() {
        JPanel panel = new JPanel();
        panel.setBorder(BorderFactory.createTitledBorder("Database Paths"));
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));

        // Analysis DB
        JPanel analysisRow = new JPanel(new FlowLayout(FlowLayout.LEFT));
        analysisRow.add(new JLabel("Analysis DB:"));
        analysisDbPathField.setText(Preferences.getProperty("GhidrAssist.AnalysisDBPath", "ghidrassist_analysis.db"));
        analysisRow.add(analysisDbPathField);
        JButton analysisDbBrowse = new JButton("Browse...");
        analysisDbBrowse.addActionListener(e -> browseFile(analysisDbPathField, "Select Analysis Database", false));
        analysisRow.add(analysisDbBrowse);

        // RLHF DB
        JPanel rlhfRow = new JPanel(new FlowLayout(FlowLayout.LEFT));
        rlhfRow.add(new JLabel("RLHF DB:"));
        rlhfDbPathField.setText(Preferences.getProperty("GhidrAssist.RLHFDatabasePath", "ghidrassist_rlhf.db"));
        rlhfRow.add(rlhfDbPathField);
        JButton rlhfDbBrowse = new JButton("Browse...");
        rlhfDbBrowse.addActionListener(e -> browseFile(rlhfDbPathField, "Select RLHF Database", false));
        rlhfRow.add(rlhfDbBrowse);

        // Lucene Index
        JPanel luceneRow = new JPanel(new FlowLayout(FlowLayout.LEFT));
        luceneRow.add(new JLabel("RAG Index:"));
        luceneIndexPathField.setText(Preferences.getProperty("GhidrAssist.LuceneIndexPath", "ghidrassist_lucene"));
        luceneRow.add(luceneIndexPathField);
        JButton luceneBrowse = new JButton("Browse...");
        luceneBrowse.addActionListener(e -> browseFile(luceneIndexPathField, "Select RAG Index Directory", true));
        luceneRow.add(luceneBrowse);

        panel.add(analysisRow);
        panel.add(rlhfRow);
        panel.add(luceneRow);

        return panel;
    }

    private JPanel createAnalysisOptionsSection() {
        JPanel panel = new JPanel();
        panel.setBorder(BorderFactory.createTitledBorder("Analysis Options"));
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));

        // Max Tool Calls
        JPanel toolCallsRow = new JPanel(new FlowLayout(FlowLayout.LEFT));
        toolCallsRow.add(new JLabel("Max Tool Calls/ReAct Iteration:"));
        toolCallsRow.add(maxToolCallsSpinner);

        panel.add(toolCallsRow);

        return panel;
    }

    private void setupListeners() {
        // Active provider change
        activeProviderComboBox.addActionListener(e -> {
            String item = (String) activeProviderComboBox.getSelectedItem();
            selectedProviderName = (item != null) ? item : "";
            Preferences.setProperty("GhidrAssist.SelectedAPIProvider", selectedProviderName);
            Preferences.store();
        });

        // Reasoning effort change
        reasoningEffortCombo.addActionListener(e -> {
            String selectedEffort = (String) reasoningEffortCombo.getSelectedItem();
            controller.setReasoningEffort(selectedEffort);
        });

        // Max tool calls change
        maxToolCallsSpinner.addChangeListener(e -> {
            int maxToolCalls = (Integer) maxToolCallsSpinner.getValue();
            controller.setMaxToolCalls(maxToolCalls);
        });

        // SymGraph key visibility toggle
        showKeyButton.addActionListener(e -> {
            keyVisible = !keyVisible;
            if (keyVisible) {
                symGraphKeyField.setEchoChar((char) 0);
                showKeyButton.setText("Hide");
            } else {
                symGraphKeyField.setEchoChar('*');
                showKeyButton.setText("Show");
            }
        });

        // SymGraph TLS checkbox save on change
        symGraphDisableTlsCheckbox.addActionListener(e -> {
            Preferences.setProperty("GhidrAssist.SymGraphDisableTls",
                String.valueOf(symGraphDisableTlsCheckbox.isSelected()));
            Preferences.store();
        });

        // SymGraph URL/Key save on focus lost
        symGraphUrlField.addFocusListener(new FocusListener() {
            @Override
            public void focusGained(FocusEvent e) {}
            @Override
            public void focusLost(FocusEvent e) {
                Preferences.setProperty("GhidrAssist.SymGraphAPIUrl", symGraphUrlField.getText().trim());
                Preferences.store();
            }
        });
        symGraphKeyField.addFocusListener(new FocusListener() {
            @Override
            public void focusGained(FocusEvent e) {}
            @Override
            public void focusLost(FocusEvent e) {
                Preferences.setProperty("GhidrAssist.SymGraphAPIKey", new String(symGraphKeyField.getPassword()));
                Preferences.store();
            }
        });

        // SymGraph Test button
        symGraphTestButton.addActionListener(e -> onTestSymGraph());

        // Database paths save on focus lost
        analysisDbPathField.addFocusListener(createPathFocusListener("GhidrAssist.AnalysisDBPath"));
        rlhfDbPathField.addFocusListener(createPathFocusListener("GhidrAssist.RLHFDatabasePath"));
        luceneIndexPathField.addFocusListener(createPathFocusListener("GhidrAssist.LuceneIndexPath"));

        // System prompt buttons
        saveButton.addActionListener(e -> controller.handleContextSave(contextArea.getText()));
        revertButton.addActionListener(e -> controller.handleContextRevert());
    }

    private FocusListener createPathFocusListener(String preferenceKey) {
        return new FocusListener() {
            @Override
            public void focusGained(FocusEvent e) {}
            @Override
            public void focusLost(FocusEvent e) {
                JTextField field = (JTextField) e.getSource();
                Preferences.setProperty(preferenceKey, field.getText().trim());
                Preferences.store();
            }
        };
    }

    private void loadSettings() {
        // Load reasoning effort
        String savedEffort = controller.getReasoningEffort();
        if (savedEffort != null) {
            reasoningEffortCombo.setSelectedItem(savedEffort);
        }

        // Load max tool calls
        int savedMaxToolCalls = controller.getMaxToolCalls();
        maxToolCallsSpinner.setValue(savedMaxToolCalls);
    }

    public void setContextText(String text) {
        contextArea.setText(text);
    }

    public void loadReasoningEffort() {
        String savedEffort = controller.getReasoningEffort();
        if (savedEffort != null) {
            reasoningEffortCombo.setSelectedItem(savedEffort);
        }
    }

    public void loadMaxToolCalls() {
        int savedMaxToolCalls = controller.getMaxToolCalls();
        maxToolCallsSpinner.setValue(savedMaxToolCalls);
    }

    // ==== LLM Provider Operations ====

    private void onAddProvider() {
        APIProviderConfig newProvider = new APIProviderConfig(
            "", APIProvider.ProviderType.OPENAI_PLATFORM_API, "", 16384, "", "", false, false, 90
        );
        if (openProviderDialog(newProvider)) {
            apiProviders.add(newProvider);
            addProviderRow(newProvider);
            activeProviderComboBox.addItem(newProvider.getName());
            saveProviders();
        }
    }

    private void onEditProvider() {
        int selectedRow = llmTable.getSelectedRow();
        if (selectedRow < 0) {
            JOptionPane.showMessageDialog(this, "Please select a provider to edit.", "No Selection", JOptionPane.WARNING_MESSAGE);
            return;
        }
        APIProviderConfig provider = apiProviders.get(selectedRow);
        String previousName = provider.getName();
        APIProviderConfig editedProvider = provider.copy();
        if (openProviderDialog(editedProvider)) {
            provider.setName(editedProvider.getName());
            provider.setType(editedProvider.getType());
            provider.setModel(editedProvider.getModel());
            provider.setMaxTokens(editedProvider.getMaxTokens());
            provider.setUrl(editedProvider.getUrl());
            provider.setKey(editedProvider.getKey());
            provider.setDisableTlsVerification(editedProvider.isDisableTlsVerification());
            provider.setBypassProxy(editedProvider.isBypassProxy());
            provider.setTimeout(editedProvider.getTimeout());

            llmTableModel.setValueAt(provider.getName(), selectedRow, 0);
            llmTableModel.setValueAt(provider.getModel(), selectedRow, 1);
            llmTableModel.setValueAt(getProviderTypeDisplayName(provider.getType()), selectedRow, 2);
            llmTableModel.setValueAt(provider.getUrl(), selectedRow, 3);

            boolean wasSelectedProvider = previousName != null && previousName.equals(selectedProviderName);
            activeProviderComboBox.removeItemAt(selectedRow);
            activeProviderComboBox.insertItemAt(provider.getName(), selectedRow);
            if (wasSelectedProvider) {
                selectedProviderName = provider.getName();
                activeProviderComboBox.setSelectedItem(provider.getName());
            }
            autoSizeTableColumns(llmTable);
            saveProviders();
        }
    }

    private void onDuplicateProvider() {
        int row = llmTable.getSelectedRow();
        if (row < 0) {
            JOptionPane.showMessageDialog(this, "Please select a provider to duplicate.", "No Selection", JOptionPane.WARNING_MESSAGE);
        } else {
            APIProviderConfig provider = apiProviders.get(row).copy();
            provider.setName(provider.getName() + " - Copy");
            apiProviders.add(provider);
            addProviderRow(provider);
            activeProviderComboBox.addItem(provider.getName());
            saveProviders();
        }
    }

    private void onDeleteProvider() {
        int selectedRow = llmTable.getSelectedRow();
        if (selectedRow < 0) {
            JOptionPane.showMessageDialog(this, "Please select a provider to delete.", "No Selection", JOptionPane.WARNING_MESSAGE);
            return;
        }
        int result = JOptionPane.showConfirmDialog(this, "Are you sure you want to delete the selected provider?", "Confirm Delete", JOptionPane.YES_NO_OPTION);
        if (result == JOptionPane.YES_OPTION) {
            APIProviderConfig provider = apiProviders.get(selectedRow);
            apiProviders.remove(selectedRow);
            llmTableModel.removeRow(selectedRow);
            activeProviderComboBox.removeItemAt(selectedRow);
            if (selectedProviderName.equals(provider.getName())) {
                selectedProviderName = "";
                activeProviderComboBox.setSelectedItem(selectedProviderName);
            }
            autoSizeTableColumns(llmTable);
            saveProviders();
        }
    }

    private void onTestProvider() {
        if (activeLlmTestWorker != null && !activeLlmTestWorker.isDone()) {
            activeLlmTestWorker.cancel(true);
            llmTestButton.setText("Test");
            llmTestStatusLabel.setText("");
            llmTestStatusLabel.setIcon(failureIcon);
            llmTestStatusLabel.setToolTipText("Test cancelled by user");
            activeLlmTestWorker = null;
            return;
        }

        int selectedRow = llmTable.getSelectedRow();
        if (selectedRow < 0) {
            llmTestStatusLabel.setIcon(failureIcon);
            llmTestStatusLabel.setToolTipText("No provider selected in table");
            JOptionPane.showMessageDialog(this, "Please select a provider in the table to test.", "No Selection", JOptionPane.WARNING_MESSAGE);
            return;
        }

        final APIProviderConfig testProvider = apiProviders.get(selectedRow).copy();

        llmTestButton.setText("Cancel");
        llmTestStatusLabel.setIcon(null);
        llmTestStatusLabel.setText("...");
        llmTestStatusLabel.setToolTipText("Testing connection...");

        SwingWorker<Boolean, Void> worker = new SwingWorker<>() {
            private String errorMessage = "";

            @Override
            protected Boolean doInBackground() {
                try {
                    validateProviderForTest(testProvider);
                    testProvider.createProvider().testConnection();
                    return true;
                } catch (Exception e) {
                    errorMessage = e.getMessage();
                    return false;
                }
            }

            @Override
            protected void done() {
                llmTestButton.setText("Test");
                activeLlmTestWorker = null;
                llmTestStatusLabel.setText("");
                try {
                    if (isCancelled()) {
                        return;
                    }
                    if (get()) {
                        llmTestStatusLabel.setIcon(successIcon);
                        llmTestStatusLabel.setToolTipText("Connection successful");
                    } else {
                        llmTestStatusLabel.setIcon(failureIcon);
                        llmTestStatusLabel.setToolTipText("Connection failed: " + errorMessage);
                    }
                } catch (Exception e) {
                    llmTestStatusLabel.setIcon(failureIcon);
                    llmTestStatusLabel.setToolTipText("Test error: " + e.getMessage());
                }
            }
        };
        activeLlmTestWorker = worker;
        worker.execute();
    }

    private boolean openProviderDialog(APIProviderConfig provider) {
        JTextField nameField = new JTextField(provider.getName(), 28);
        JTextField modelField = new JTextField(provider.getModel() != null ? provider.getModel() : "", 28);
        JSpinner maxTokensSpinner = new JSpinner(new SpinnerNumberModel(
            provider.getMaxTokens() != null ? provider.getMaxTokens() : 16384, 1, 1_000_000, 1));
        JSpinner timeoutSpinner = new JSpinner(new SpinnerNumberModel(
            provider.getTimeout() != null ? provider.getTimeout() : 90, 1, 3600, 1));
        JTextField urlField = new JTextField(provider.getUrl() != null ? provider.getUrl() : "", 28);
        JTextField keyField = new JTextField(provider.getKey() != null ? provider.getKey() : "", 28);
        JComboBox<APIProvider.ProviderType> typeComboBox = new JComboBox<>(APIProvider.ProviderType.values());
        typeComboBox.setSelectedItem(provider.getType());
        JCheckBox disableTlsCheckbox = new JCheckBox("Disable TLS Verification", provider.isDisableTlsVerification());
        JCheckBox bypassProxyCheckbox = new JCheckBox("Bypass System Proxy", provider.isBypassProxy());
        JButton fetchModelsButton = new JButton("Pull");
        JButton testButton = new JButton("Test");
        JLabel testStatusLabel = new JLabel();
        testStatusLabel.setPreferredSize(new Dimension(20, 20));
        JComboBox<String> modelCombo = new JComboBox<>();
        modelCombo.setVisible(false);

        JLabel urlLabel = new JLabel("URL:");
        JLabel keyLabel = new JLabel("Key:");
        JButton authenticateButton = new JButton("Authenticate");
        JLabel oauthNoteLabel = new JLabel("<html><i>Click 'Authenticate' to sign in.</i></html>");
        oauthNoteLabel.setForeground(Color.GRAY);
        JLabel claudeCodeNoteLabel = new JLabel("<html><i>Requires 'claude' CLI installed and authenticated.<br>Install: npm install -g @anthropic-ai/claude-code</i></html>");
        claudeCodeNoteLabel.setForeground(Color.GRAY);
        JButton okButton = new JButton("OK");
        JButton cancelButton = new JButton("Cancel");
        Dimension actionButtonSize = new Dimension(110, okButton.getPreferredSize().height);
        okButton.setPreferredSize(actionButtonSize);
        cancelButton.setPreferredSize(actionButtonSize);
        testButton.setPreferredSize(actionButtonSize);
        fetchModelsButton.setPreferredSize(new Dimension(90, fetchModelsButton.getPreferredSize().height));
        authenticateButton.setPreferredSize(new Dimension(150, authenticateButton.getPreferredSize().height));

        final SwingWorker<?, ?>[] dialogTestWorker = {null};
        final SwingWorker<?, ?>[] fetchModelsWorker = {null};
        final boolean[] confirmed = {false};
        final JDialog[] dialogRef = {null};

        typeComboBox.setRenderer(new DefaultListCellRenderer() {
            private static final long serialVersionUID = 1L;

            @Override
            public Component getListCellRendererComponent(
                    JList<?> list, Object value, int index, boolean isSelected, boolean cellHasFocus) {
                Object displayValue = value instanceof APIProvider.ProviderType providerType
                    ? getProviderTypeDisplayName(providerType)
                    : value;
                return super.getListCellRendererComponent(list, displayValue, index, isSelected, cellHasFocus);
            }
        });

        modelCombo.addActionListener(e -> {
            Object selectedItem = modelCombo.getSelectedItem();
            if (selectedItem != null) {
                modelField.setText(selectedItem.toString());
            }
        });

        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(BorderFactory.createEmptyBorder(12, 12, 8, 12));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(4, 4, 4, 4);
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;

        int row = 0;

        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
        panel.add(new JLabel("Name:"), gbc);
        gbc.gridx = 1; gbc.weightx = 1; gbc.gridwidth = 2;
        panel.add(nameField, gbc);
        gbc.gridwidth = 1;
        row++;

        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
        panel.add(new JLabel("Provider Type:"), gbc);
        gbc.gridx = 1; gbc.weightx = 1; gbc.gridwidth = 2;
        panel.add(typeComboBox, gbc);
        gbc.gridwidth = 1;
        row++;

        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
        panel.add(new JLabel("Model:"), gbc);
        JPanel modelPanel = new JPanel(new BorderLayout(5, 0));
        modelPanel.add(modelField, BorderLayout.CENTER);
        modelPanel.add(fetchModelsButton, BorderLayout.EAST);
        gbc.gridx = 1; gbc.weightx = 1; gbc.gridwidth = 2;
        panel.add(modelPanel, gbc);
        gbc.gridwidth = 1;
        row++;

        gbc.gridx = 1; gbc.gridy = row; gbc.weightx = 1; gbc.gridwidth = 2;
        panel.add(modelCombo, gbc);
        gbc.gridwidth = 1;
        row++;

        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
        panel.add(urlLabel, gbc);
        gbc.gridx = 1; gbc.weightx = 1; gbc.gridwidth = 2;
        panel.add(urlField, gbc);
        gbc.gridwidth = 1;
        row++;

        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
        panel.add(new JLabel("Max Tokens:"), gbc);
        gbc.gridx = 1; gbc.weightx = 1; gbc.gridwidth = 2;
        panel.add(maxTokensSpinner, gbc);
        gbc.gridwidth = 1;
        row++;

        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
        panel.add(new JLabel("Timeout (seconds):"), gbc);
        gbc.gridx = 1; gbc.weightx = 1; gbc.gridwidth = 2;
        panel.add(timeoutSpinner, gbc);
        gbc.gridwidth = 1;
        row++;

        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
        panel.add(keyLabel, gbc);
        gbc.gridx = 1; gbc.weightx = 1;
        panel.add(keyField, gbc);
        gbc.gridx = 2; gbc.weightx = 0;
        panel.add(authenticateButton, gbc);
        row++;

        gbc.gridx = 1; gbc.gridy = row; gbc.gridwidth = 2;
        panel.add(oauthNoteLabel, gbc);
        gbc.gridwidth = 1;
        row++;

        gbc.gridx = 1; gbc.gridy = row; gbc.gridwidth = 2;
        panel.add(claudeCodeNoteLabel, gbc);
        gbc.gridwidth = 1;
        row++;

        gbc.gridx = 1; gbc.gridy = row; gbc.gridwidth = 2;
        panel.add(disableTlsCheckbox, gbc);
        gbc.gridwidth = 1;
        row++;

        gbc.gridx = 1; gbc.gridy = row; gbc.gridwidth = 2;
        panel.add(bypassProxyCheckbox, gbc);
        gbc.gridwidth = 1;
        row++;

        boolean[] isUserChange = {false};

        Runnable updateUIForProviderType = () -> {
            APIProvider.ProviderType selectedType = (APIProvider.ProviderType) typeComboBox.getSelectedItem();
            if (selectedType == null) {
                return;
            }

            boolean isOpenAIOAuth = selectedType == APIProvider.ProviderType.OPENAI_OAUTH;
            boolean isGeminiOAuth = selectedType == APIProvider.ProviderType.GEMINI_OAUTH;
            boolean isOAuth = isOpenAIOAuth || isGeminiOAuth;
            boolean isAnthropicClaudeCli = selectedType == APIProvider.ProviderType.ANTHROPIC_CLAUDE_CLI;

            authenticateButton.setVisible(isOAuth);
            oauthNoteLabel.setVisible(isOAuth);
            claudeCodeNoteLabel.setVisible(isAnthropicClaudeCli);
            fetchModelsButton.setEnabled(!isAnthropicClaudeCli);
            fetchModelsButton.setToolTipText(isAnthropicClaudeCli
                ? "Model discovery is not supported for Claude Code CLI"
                : "Fetch available models from API");

            if (isOpenAIOAuth) {
                oauthNoteLabel.setText("<html><i>Click 'Authenticate' to sign in with ChatGPT Pro/Plus subscription.</i></html>");
            } else if (isGeminiOAuth) {
                oauthNoteLabel.setText("<html><i>Click 'Authenticate' to sign in with Google Gemini CLI.</i></html>");
            }

            if (isOAuth) {
                keyLabel.setText("OAuth Token (JSON):");
                keyField.setToolTipText("OAuth credentials JSON populated by Authenticate");
            } else {
                keyLabel.setText("Key:");
                keyField.setToolTipText(null);
            }

            String defaultUrl = getDefaultProviderUrl(selectedType);
            if ((isUserChange[0] || urlField.getText().trim().isEmpty()) && defaultUrl != null) {
                urlField.setText(defaultUrl);
            }
        };

        typeComboBox.addActionListener(e -> {
            isUserChange[0] = true;
            updateUIForProviderType.run();
        });

        authenticateButton.addActionListener(e -> {
            APIProvider.ProviderType selectedType = (APIProvider.ProviderType) typeComboBox.getSelectedItem();
            if (selectedType == APIProvider.ProviderType.OPENAI_OAUTH) {
                authenticateOpenAIOAuth(panel, keyField);
            } else if (selectedType == APIProvider.ProviderType.GEMINI_OAUTH) {
                authenticateGeminiOAuth(panel, keyField);
            }
        });

        testButton.addActionListener(e -> {
            if (dialogTestWorker[0] != null && !dialogTestWorker[0].isDone()) {
                dialogTestWorker[0].cancel(true);
                testButton.setText("Test");
                testStatusLabel.setText("");
                testStatusLabel.setIcon(failureIcon);
                testStatusLabel.setToolTipText("Test cancelled by user");
                dialogTestWorker[0] = null;
                return;
            }

            APIProviderConfig testConfig;
            try {
                testConfig = buildProviderConfigFromDialog(
                    nameField, typeComboBox, modelField, maxTokensSpinner, timeoutSpinner,
                    urlField, keyField, disableTlsCheckbox, bypassProxyCheckbox, false, true);
                validateProviderForTest(testConfig);
            } catch (IllegalArgumentException ex) {
                JOptionPane.showMessageDialog(panel, ex.getMessage(), "Validation Error", JOptionPane.ERROR_MESSAGE);
                return;
            }

            testButton.setText("Cancel");
            testStatusLabel.setIcon(null);
            testStatusLabel.setText("...");
            testStatusLabel.setToolTipText("Testing connection...");

            SwingWorker<Boolean, Void> worker = new SwingWorker<>() {
                private String errorMessage = "";

                @Override
                protected Boolean doInBackground() {
                    try {
                        testConfig.createProvider().testConnection();
                        return true;
                    } catch (Exception ex) {
                        errorMessage = ex.getMessage();
                        return false;
                    }
                }

                @Override
                protected void done() {
                    testButton.setText("Test");
                    dialogTestWorker[0] = null;
                    testStatusLabel.setText("");
                    try {
                        if (isCancelled()) {
                            return;
                        }
                        if (get()) {
                            testStatusLabel.setIcon(successIcon);
                            testStatusLabel.setToolTipText("Connection successful");
                        } else {
                            testStatusLabel.setIcon(failureIcon);
                            testStatusLabel.setToolTipText("Connection failed: " + errorMessage);
                        }
                    } catch (Exception ex) {
                        testStatusLabel.setIcon(failureIcon);
                        testStatusLabel.setToolTipText("Test error: " + ex.getMessage());
                    }
                }
            };

            dialogTestWorker[0] = worker;
            worker.execute();
        });

        fetchModelsButton.addActionListener(e -> {
            if (fetchModelsWorker[0] != null && !fetchModelsWorker[0].isDone()) {
                fetchModelsWorker[0].cancel(true);
                fetchModelsButton.setText("Pull");
                fetchModelsWorker[0] = null;
                return;
            }

            APIProviderConfig fetchConfig;
            try {
                fetchConfig = buildProviderConfigFromDialog(
                    nameField, typeComboBox, modelField, maxTokensSpinner, timeoutSpinner,
                    urlField, keyField, disableTlsCheckbox, bypassProxyCheckbox, false, false);
                validateProviderForModelPull(fetchConfig);
            } catch (IllegalArgumentException ex) {
                JOptionPane.showMessageDialog(panel, ex.getMessage(), "Validation Error", JOptionPane.ERROR_MESSAGE);
                return;
            }

            fetchModelsButton.setText("Cancel");

            SwingWorker<List<String>, Void> worker = new SwingWorker<>() {
                private String errorMessage = "";

                @Override
                protected List<String> doInBackground() {
                    try {
                        APIProvider apiProvider = fetchConfig.createProvider();
                        if (!(apiProvider instanceof ghidrassist.apiprovider.capabilities.ModelListProvider listProvider) ||
                                !listProvider.supportsModelListing()) {
                            throw new IllegalArgumentException("This provider does not support live model discovery.");
                        }
                        return apiProvider.getAvailableModels();
                    } catch (Exception ex) {
                        errorMessage = ex.getMessage();
                        return null;
                    }
                }

                @Override
                protected void done() {
                    fetchModelsButton.setText("Pull");
                    fetchModelsWorker[0] = null;
                    try {
                        if (isCancelled()) {
                            return;
                        }
                        List<String> models = get();
                        if (models == null || models.isEmpty()) {
                            throw new IllegalArgumentException(errorMessage.isEmpty()
                                ? "No available models were returned."
                                : errorMessage);
                        }
                        modelCombo.removeAllItems();
                        for (String model : models) {
                            modelCombo.addItem(model);
                        }
                        modelCombo.setVisible(true);
                        String currentModel = modelField.getText().trim();
                        if (!currentModel.isEmpty()) {
                            modelCombo.setSelectedItem(currentModel);
                        } else if (modelCombo.getItemCount() > 0) {
                            modelCombo.setSelectedIndex(0);
                            Object selectedItem = modelCombo.getSelectedItem();
                            if (selectedItem != null) {
                                modelField.setText(selectedItem.toString());
                            }
                        }
                        panel.revalidate();
                        panel.repaint();
                        if (dialogRef[0] != null) {
                            dialogRef[0].pack();
                            dialogRef[0].setMinimumSize(new Dimension(560, dialogRef[0].getPreferredSize().height));
                        }
                    } catch (Exception ex) {
                        JOptionPane.showMessageDialog(panel,
                            "Failed to fetch models: " + ex.getMessage(),
                            "Model Fetch Failed",
                            JOptionPane.ERROR_MESSAGE);
                    }
                }
            };

            fetchModelsWorker[0] = worker;
            worker.execute();
        });

        updateUIForProviderType.run();

        Window owner = SwingUtilities.getWindowAncestor(this);
        String dialogTitle = (provider.getName() != null && !provider.getName().isBlank())
            ? "Edit " + provider.getName()
            : "API Provider";
        JDialog dialog = new JDialog(owner, dialogTitle, Dialog.ModalityType.APPLICATION_MODAL);
        dialogRef[0] = dialog;
        dialog.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);

        okButton.addActionListener(e -> {
            try {
                APIProviderConfig updated = buildProviderConfigFromDialog(
                    nameField, typeComboBox, modelField, maxTokensSpinner, timeoutSpinner,
                    urlField, keyField, disableTlsCheckbox, bypassProxyCheckbox, true, true);
                validateProviderForSave(updated);

                provider.setName(updated.getName());
                provider.setType(updated.getType());
                provider.setModel(updated.getModel());
                provider.setMaxTokens(updated.getMaxTokens());
                provider.setUrl(updated.getUrl());
                provider.setKey(updated.getKey());
                provider.setDisableTlsVerification(updated.isDisableTlsVerification());
                provider.setBypassProxy(updated.isBypassProxy());
                provider.setTimeout(updated.getTimeout());
                confirmed[0] = true;
                dialog.dispose();
            } catch (IllegalArgumentException ex) {
                JOptionPane.showMessageDialog(dialog, ex.getMessage(), "Validation Error", JOptionPane.ERROR_MESSAGE);
            }
        });
        cancelButton.addActionListener(e -> dialog.dispose());

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 0));
        buttonPanel.setBorder(BorderFactory.createEmptyBorder(12, 20, 20, 20));
        buttonPanel.add(okButton);
        buttonPanel.add(cancelButton);
        buttonPanel.add(testButton);
        buttonPanel.add(testStatusLabel);

        JPanel contentPanel = new JPanel(new BorderLayout());
        contentPanel.add(panel, BorderLayout.CENTER);
        contentPanel.add(buttonPanel, BorderLayout.SOUTH);

        dialog.setContentPane(contentPanel);
        dialog.getRootPane().setDefaultButton(okButton);
        dialog.addWindowListener(new java.awt.event.WindowAdapter() {
            @Override
            public void windowClosing(java.awt.event.WindowEvent e) {
                if (dialogTestWorker[0] != null && !dialogTestWorker[0].isDone()) {
                    dialogTestWorker[0].cancel(true);
                }
                if (fetchModelsWorker[0] != null && !fetchModelsWorker[0].isDone()) {
                    fetchModelsWorker[0].cancel(true);
                }
            }

            @Override
            public void windowClosed(java.awt.event.WindowEvent e) {
                if (dialogTestWorker[0] != null && !dialogTestWorker[0].isDone()) {
                    dialogTestWorker[0].cancel(true);
                }
                if (fetchModelsWorker[0] != null && !fetchModelsWorker[0].isDone()) {
                    fetchModelsWorker[0].cancel(true);
                }
            }
        });

        dialog.pack();
        dialog.setMinimumSize(new Dimension(560, dialog.getPreferredSize().height));
        dialog.setResizable(false);
        dialog.setLocationRelativeTo(this);
        dialog.setVisible(true);

        return confirmed[0];
    }

    private APIProviderConfig buildProviderConfigFromDialog(
            JTextField nameField,
            JComboBox<APIProvider.ProviderType> typeComboBox,
            JTextField modelField,
            JSpinner maxTokensSpinner,
            JSpinner timeoutSpinner,
            JTextField urlField,
            JTextField keyField,
            JCheckBox disableTlsCheckbox,
            JCheckBox bypassProxyCheckbox,
            boolean requireName,
            boolean requireModel) {
        APIProvider.ProviderType selectedType = (APIProvider.ProviderType) typeComboBox.getSelectedItem();
        if (selectedType == null) {
            throw new IllegalArgumentException("Provider type is required.");
        }

        String name = nameField.getText().trim();
        String model = modelField.getText().trim();
        String url = urlField.getText().trim();
        String key = keyField.getText().trim();
        int maxTokens = ((Number) maxTokensSpinner.getValue()).intValue();
        int timeout = ((Number) timeoutSpinner.getValue()).intValue();

        if (requireName && name.isEmpty()) {
            throw new IllegalArgumentException("Name is required.");
        }
        if (!requireName && name.isEmpty()) {
            name = "Provider Test";
        }
        if (requireModel && model.isEmpty()) {
            throw new IllegalArgumentException("Model is required.");
        }

        if (!url.isEmpty()
                && selectedType != APIProvider.ProviderType.OPENAI_OAUTH
                && selectedType != APIProvider.ProviderType.GEMINI_OAUTH
                && selectedType != APIProvider.ProviderType.ANTHROPIC_CLAUDE_CLI
                && !url.endsWith("/")) {
            url = url + "/";
        }

        return new APIProviderConfig(
            name,
            selectedType,
            model,
            maxTokens,
            url,
            key,
            disableTlsCheckbox.isSelected(),
            bypassProxyCheckbox.isSelected(),
            timeout
        );
    }

    private void validateProviderForSave(APIProviderConfig provider) {
        if (provider.getName() == null || provider.getName().isBlank()) {
            throw new IllegalArgumentException("Name is required.");
        }
        if (provider.getModel() == null || provider.getModel().isBlank()) {
            throw new IllegalArgumentException("Model is required.");
        }
        validateProviderCommon(provider);
    }

    private void validateProviderForTest(APIProviderConfig provider) {
        if (provider.getModel() == null || provider.getModel().isBlank()) {
            throw new IllegalArgumentException("Model is required.");
        }
        validateProviderCommon(provider);
    }

    private void validateProviderForModelPull(APIProviderConfig provider) {
        validateProviderCommon(provider);
        if (provider.getType() == APIProvider.ProviderType.ANTHROPIC_CLAUDE_CLI) {
            throw new IllegalArgumentException("Model discovery is not supported for Claude Code CLI.");
        }
    }

    private void validateProviderCommon(APIProviderConfig provider) {
        if (provider.getType() == APIProvider.ProviderType.OPENAI_OAUTH
                || provider.getType() == APIProvider.ProviderType.GEMINI_OAUTH) {
            if (provider.getKey() == null || provider.getKey().isBlank() || !provider.getKey().trim().startsWith("{")) {
                throw new IllegalArgumentException("OAuth token is required. Please click 'Authenticate' to sign in.");
            }
            return;
        }

        if (provider.getType() != APIProvider.ProviderType.ANTHROPIC_CLAUDE_CLI
                && (provider.getUrl() == null || provider.getUrl().isBlank())) {
            throw new IllegalArgumentException("URL is required.");
        }
    }

    private String getDefaultProviderUrl(APIProvider.ProviderType selectedType) {
        return switch (selectedType) {
            case ANTHROPIC_PLATFORM_API -> "https://api.anthropic.com/";
            case GEMINI_OAUTH -> "https://cloudcode-pa.googleapis.com/";
            case GEMINI_PLATFORM_API -> "https://generativelanguage.googleapis.com/v1beta/openai/";
            case LMSTUDIO -> "http://127.0.0.1:1234/";
            case OLLAMA -> "http://127.0.0.1:11434/";
            case OPENAI_OAUTH -> "https://chatgpt.com/backend-api/codex/responses";
            case OPENAI_PLATFORM_API -> "https://api.openai.com/v1/";
            case OPENWEBUI -> "http://127.0.0.1:3000/api/";
            case XAI_PLATFORM_API -> "https://api.x.ai/v1/";
            default -> null;
        };
    }

    private void addProviderRow(APIProviderConfig provider) {
        llmTableModel.addRow(new Object[] {
            provider.getName(),
            provider.getModel(),
            getProviderTypeDisplayName(provider.getType()),
            provider.getUrl()
        });
        autoSizeTableColumns(llmTable);
    }

    private String getProviderTypeDisplayName(APIProvider.ProviderType providerType) {
        if (providerType == null) {
            return "Unknown";
        }
        return switch (providerType) {
            case ANTHROPIC_CLAUDE_CLI -> "Anthropic Claude CLI";
            case ANTHROPIC_PLATFORM_API -> "Anthropic Platform";
            case AZURE_OPENAI -> "Azure OpenAI";
            case GEMINI_OAUTH -> "Google Gemini OAuth";
            case GEMINI_PLATFORM_API -> "Google Gemini Platform";
            case LITELLM -> "LiteLLM";
            case LMSTUDIO -> "LM Studio";
            case OLLAMA -> "Ollama";
            case OPENAI_OAUTH -> "OpenAI OAuth (ChatGPT Pro/Plus)";
            case OPENAI_PLATFORM_API -> "OpenAI Platform";
            case OPENWEBUI -> "OpenWebUI";
            case XAI_PLATFORM_API -> "xAI Platform";
        };
    }

    private void saveProviders() {
        Gson gson = new Gson();
        String providersJson = gson.toJson(apiProviders);
        Preferences.setProperty("GhidrAssist.APIProviders", providersJson);
        Preferences.setProperty("GhidrAssist.SelectedAPIProvider", selectedProviderName);
        Preferences.store();
    }
    // ==== MCP Server Operations ====

    private void showMCPAddEditDialog(MCPServerConfig existingServer) {
        MCPServerDialog dialog = new MCPServerDialog(
            SwingUtilities.getWindowAncestor(this),
            existingServer
        );
        dialog.setVisible(true);

        if (dialog.isConfirmed()) {
            MCPServerConfig config = dialog.getServerConfig();
            if (existingServer != null) {
                MCPServerRegistry.getInstance().removeServer(existingServer.getName());
            }
            MCPServerRegistry.getInstance().addServer(config);
            mcpTableModel.refresh();
            autoSizeTableColumns(mcpServersTable);
        }
    }

    private void onDuplicateMCPServer() {
        int row = mcpServersTable.getSelectedRow();
        if (row < 0) {
            JOptionPane.showMessageDialog(this, "Please select a server to duplicate.", "No Selection", JOptionPane.WARNING_MESSAGE);
        } else {
            MCPServerConfig server = mcpTableModel.getServerAt(row).copy();
            server.setName(server.getName() + "-copy");
            MCPServerRegistry.getInstance().addServer(server);
            mcpTableModel.refresh();
            autoSizeTableColumns(mcpServersTable);
        }
    }

    private void onRemoveMCPServer() {
        int selectedRow = mcpServersTable.getSelectedRow();
        if (selectedRow < 0) {
            JOptionPane.showMessageDialog(this, "Please select a server to remove.", "No Selection", JOptionPane.WARNING_MESSAGE);
            return;
        }
        MCPServerConfig server = mcpTableModel.getServerAt(selectedRow);
        int result = JOptionPane.showConfirmDialog(this, "Remove server '" + server.getName() + "'?", "Confirm Removal", JOptionPane.YES_NO_OPTION);
        if (result == JOptionPane.YES_OPTION) {
            MCPServerRegistry.getInstance().removeServer(server.getName());
            mcpTableModel.refresh();
            autoSizeTableColumns(mcpServersTable);
        }
    }

    private void onTestMCPServer() {
        // If cancel clicked during test
        if (activeMcpTestWorker != null && !activeMcpTestWorker.isDone()) {
            activeMcpTestWorker.cancel(true);
            mcpTestButton.setText("Test Connection");
            mcpTestStatusLabel.setText("");
            mcpTestStatusLabel.setIcon(failureIcon);
            mcpTestStatusLabel.setToolTipText("Test cancelled by user");
            activeMcpTestWorker = null;
            return;
        }

        int selectedRow = mcpServersTable.getSelectedRow();
        if (selectedRow < 0) {
            mcpTestStatusLabel.setIcon(failureIcon);
            mcpTestStatusLabel.setToolTipText("No server selected");
            return;
        }

        MCPServerConfig server = mcpTableModel.getServerAt(selectedRow);
        if (server.isStdioTransport() && (server.getCommand() == null || server.getCommand().isBlank())) {
            mcpTestStatusLabel.setIcon(failureIcon);
            mcpTestStatusLabel.setToolTipText("Connection failed: no stdio command configured");
            return;
        }
        if (server.isNetworkTransport() && (server.getUrl() == null || server.getUrl().isBlank())) {
            mcpTestStatusLabel.setIcon(failureIcon);
            mcpTestStatusLabel.setToolTipText("Connection failed: no URL configured");
            return;
        }

        // Show testing state with Cancel button
        mcpTestButton.setText("Cancel");
        mcpTestStatusLabel.setIcon(null);
        mcpTestStatusLabel.setText("...");
        mcpTestStatusLabel.setToolTipText("Testing connection to " + server.getName() + "...");

        SwingWorker<Boolean, Void> worker = new SwingWorker<Boolean, Void>() {
            private String errorMessage = "";

            @Override
            protected Boolean doInBackground() {
                try {
                    ghidrassist.mcp2.protocol.MCPClientAdapter client =
                        new ghidrassist.mcp2.protocol.MCPClientAdapter(server);
                    client.connect().get(15, TimeUnit.SECONDS);
                    client.disconnect();
                    return true;
                } catch (TimeoutException e) {
                    errorMessage = "Test timed out after 15 seconds";
                    return false;
                } catch (Exception e) {
                    Throwable cause = e.getCause() != null ? e.getCause() : e;
                    errorMessage = cause.getMessage();
                    return false;
                }
            }

            @Override
            protected void done() {
                mcpTestButton.setText("Test Connection");
                activeMcpTestWorker = null;
                mcpTestStatusLabel.setText("");
                try {
                    if (isCancelled()) return;
                    if (get()) {
                        mcpTestStatusLabel.setIcon(successIcon);
                        mcpTestStatusLabel.setToolTipText("Connection successful");
                    } else {
                        mcpTestStatusLabel.setIcon(failureIcon);
                        mcpTestStatusLabel.setToolTipText("Connection failed: " + errorMessage);
                    }
                } catch (Exception e) {
                    mcpTestStatusLabel.setIcon(failureIcon);
                    mcpTestStatusLabel.setToolTipText("Test error: " + e.getMessage());
                }
            }
        };
        activeMcpTestWorker = worker;
        worker.execute();
    }

    private void onTestSymGraph() {
        // If cancel clicked during test
        if (activeSymGraphTestWorker != null && !activeSymGraphTestWorker.isDone()) {
            activeSymGraphTestWorker.cancel(true);
            symGraphTestButton.setText("Test");
            symGraphTestStatusLabel.setText("");
            symGraphTestStatusLabel.setIcon(failureIcon);
            symGraphTestStatusLabel.setToolTipText("Test cancelled by user");
            activeSymGraphTestWorker = null;
            return;
        }

        // Save current field values to preferences before testing
        Preferences.setProperty("GhidrAssist.SymGraphAPIUrl", symGraphUrlField.getText().trim());
        Preferences.setProperty("GhidrAssist.SymGraphAPIKey", new String(symGraphKeyField.getPassword()));
        Preferences.setProperty("GhidrAssist.SymGraphDisableTls",
            String.valueOf(symGraphDisableTlsCheckbox.isSelected()));
        Preferences.store();

        // Show testing state with Cancel button
        symGraphTestButton.setText("Cancel");
        symGraphTestStatusLabel.setIcon(null);
        symGraphTestStatusLabel.setText("...");
        symGraphTestStatusLabel.setToolTipText("Testing SymGraph API connection...");

        SwingWorker<Boolean, Void> worker = new SwingWorker<Boolean, Void>() {
            private String errorMessage = "";
            private String successMessage = "";

            @Override
            protected Boolean doInBackground() {
                try {
                    return CompletableFuture.supplyAsync(() -> {
                        try {
                            SymGraphService service = new SymGraphService();

                            String testHash = "0000000000000000000000000000000000000000000000000000000000000000";
                            service.checkBinaryExists(testHash);

                            if (service.hasApiKey()) {
                                try {
                                    service.getSymbols(testHash);
                                    successMessage = "API reachable, authentication successful";
                                } catch (SymGraphService.SymGraphAuthException e) {
                                    errorMessage = "API reachable but authentication failed: " + e.getMessage();
                                    return false;
                                }
                            } else {
                                successMessage = "API reachable (no API key configured)";
                            }

                            return true;
                        } catch (Exception e) {
                            errorMessage = e.getMessage();
                            return false;
                        }
                    }).get(15, TimeUnit.SECONDS);
                } catch (TimeoutException e) {
                    errorMessage = "Test timed out after 15 seconds";
                    return false;
                } catch (Exception e) {
                    errorMessage = e.getMessage();
                    return false;
                }
            }

            @Override
            protected void done() {
                symGraphTestButton.setText("Test");
                activeSymGraphTestWorker = null;
                symGraphTestStatusLabel.setText("");
                try {
                    if (isCancelled()) return;
                    if (get()) {
                        symGraphTestStatusLabel.setIcon(successIcon);
                        symGraphTestStatusLabel.setToolTipText(successMessage);
                    } else {
                        symGraphTestStatusLabel.setIcon(failureIcon);
                        symGraphTestStatusLabel.setToolTipText("Connection failed: " + errorMessage);
                    }
                } catch (Exception e) {
                    symGraphTestStatusLabel.setIcon(failureIcon);
                    symGraphTestStatusLabel.setToolTipText("Test error: " + e.getMessage());
                }
            }
        };
        activeSymGraphTestWorker = worker;
        worker.execute();
    }

    // ==== Utility Methods ====

    private void browseFile(JTextField field, String title, boolean directoriesOnly) {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle(title);
        fileChooser.setFileSelectionMode(directoriesOnly ? JFileChooser.DIRECTORIES_ONLY : JFileChooser.FILES_ONLY);

        String currentPath = field.getText();
        if (!currentPath.isEmpty()) {
            File currentFile = new File(currentPath);
            fileChooser.setCurrentDirectory(currentFile.getParentFile());
            fileChooser.setSelectedFile(currentFile);
        }

        int result = fileChooser.showOpenDialog(this);
        if (result == JFileChooser.APPROVE_OPTION) {
            field.setText(fileChooser.getSelectedFile().getAbsolutePath());
        }
    }

    private void autoSizeTableColumns(JTable table) {
        for (int column = 0; column < table.getColumnCount(); column++) {
            int width = 50;

            TableCellRenderer headerRenderer = table.getTableHeader().getDefaultRenderer();
            Component headerComponent = headerRenderer.getTableCellRendererComponent(
                table, table.getColumnName(column), false, false, -1, column);
            width = Math.max(width, headerComponent.getPreferredSize().width);

            for (int row = 0; row < table.getRowCount(); row++) {
                TableCellRenderer renderer = table.getCellRenderer(row, column);
                Component component = table.prepareRenderer(renderer, row, column);
                width = Math.max(width, component.getPreferredSize().width);
            }

            table.getColumnModel().getColumn(column).setPreferredWidth(width + 16);
        }
    }

    private ImageIcon createSuccessIcon() {
        int size = 16;
        BufferedImage image = new BufferedImage(size, size, BufferedImage.TYPE_INT_ARGB);
        Graphics2D g2d = image.createGraphics();
        g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g2d.setColor(new Color(0, 180, 0));  // Green
        g2d.setStroke(new BasicStroke(2.5f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
        g2d.drawLine(3, 8, 6, 12);
        g2d.drawLine(6, 12, 13, 4);
        g2d.dispose();
        return new ImageIcon(image);
    }

    private ImageIcon createFailureIcon() {
        int size = 16;
        BufferedImage image = new BufferedImage(size, size, BufferedImage.TYPE_INT_ARGB);
        Graphics2D g2d = image.createGraphics();
        g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g2d.setColor(new Color(220, 0, 0));  // Red
        g2d.setStroke(new BasicStroke(2.5f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
        g2d.drawLine(4, 4, 12, 12);
        g2d.drawLine(4, 12, 12, 4);
        g2d.dispose();
        return new ImageIcon(image);
    }

    // ==== OAuth Authentication Methods ====
    
    /**
     * Authenticates with OpenAI OAuth using automatic callback capture.
     * Falls back to manual code entry if automatic capture fails.
     */
    private void authenticateOpenAIOAuth(JPanel parentPanel, JTextField keyField) {
        OpenAIOAuthTokenManager tokenManager = new OpenAIOAuthTokenManager();
        
        // Create progress dialog with cancel option
        JDialog progressDialog = new JDialog(SwingUtilities.getWindowAncestor(parentPanel), 
            "OpenAI OAuth Authentication", Dialog.ModalityType.APPLICATION_MODAL);
        JPanel progressPanel = new JPanel(new BorderLayout(10, 10));
        progressPanel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));
        
        JLabel statusLabel = new JLabel("Opening browser for authentication...");
        JProgressBar progressBar = new JProgressBar();
        progressBar.setIndeterminate(true);
        
        JButton cancelButton = new JButton("Cancel");
        JButton manualButton = new JButton("Use Manual Entry");
        
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 0));
        buttonPanel.add(manualButton);
        buttonPanel.add(cancelButton);
        
        progressPanel.add(statusLabel, BorderLayout.NORTH);
        progressPanel.add(progressBar, BorderLayout.CENTER);
        progressPanel.add(buttonPanel, BorderLayout.SOUTH);
        
        progressDialog.setContentPane(progressPanel);
        progressDialog.setSize(400, 150);
        progressDialog.setLocationRelativeTo(parentPanel);
        
        // Track authentication state
        final boolean[] authCompleted = {false};
        final boolean[] cancelled = {false};
        
        // Worker for automatic callback authentication
        SwingWorker<String, Void> authWorker = new SwingWorker<String, Void>() {
            private String errorMessage = null;
            private OAuthCallbackServer callbackServer = null;
            
            @Override
            protected String doInBackground() {
                try {
                    callbackServer = tokenManager.startAuthorizationFlowWithCallback();
                    publish(); // Update status
                    
                    // Wait for callback with 5 minute timeout
                    tokenManager.completeAuthorizationWithCallback(callbackServer, 5);
                    return tokenManager.toJson();
                } catch (Exception ex) {
                    if (!cancelled[0]) {
                        errorMessage = ex.getMessage();
                    }
                    return null;
                }
            }
            
            @Override
            protected void process(java.util.List<Void> chunks) {
                statusLabel.setText("Waiting for authentication in browser...");
            }
            
            @Override
            protected void done() {
                if (cancelled[0]) return;
                
                try {
                    String credentialsJson = get();
                    if (credentialsJson != null && !credentialsJson.isEmpty()) {
                        authCompleted[0] = true;
                        progressDialog.dispose();
                        keyField.setText(credentialsJson);
                        JOptionPane.showMessageDialog(parentPanel, 
                            "Successfully authenticated with ChatGPT Pro/Plus!\n\nThe OAuth token has been stored.",
                            "Authentication Successful", 
                            JOptionPane.INFORMATION_MESSAGE);
                    } else if (errorMessage != null && !cancelled[0]) {
                        progressDialog.dispose();
                        // Fall back to manual entry on error
                        authenticateOpenAIOAuthManual(parentPanel, keyField);
                    }
                } catch (Exception ex) {
                    if (!cancelled[0]) {
                        progressDialog.dispose();
                        authenticateOpenAIOAuthManual(parentPanel, keyField);
                    }
                }
            }
            
            public void cancel() {
                cancelled[0] = true;
                tokenManager.cancelAuthentication();
            }
        };
        
        // Cancel button action
        cancelButton.addActionListener(e -> {
            cancelled[0] = true;
            tokenManager.cancelAuthentication();
            authWorker.cancel(true);
            progressDialog.dispose();
        });
        
        // Manual entry button action
        manualButton.addActionListener(e -> {
            cancelled[0] = true;
            tokenManager.cancelAuthentication();
            authWorker.cancel(true);
            progressDialog.dispose();
            authenticateOpenAIOAuthManual(parentPanel, keyField);
        });
        
        // Start the worker
        authWorker.execute();
        
        // Show progress dialog (blocks until closed)
        progressDialog.setVisible(true);
    }
    
    /**
     * Manual OAuth code entry for OpenAI (fallback).
     */
    private void authenticateOpenAIOAuthManual(JPanel parentPanel, JTextField keyField) {
        OpenAIOAuthTokenManager tokenManager = new OpenAIOAuthTokenManager();
        tokenManager.startAuthorizationFlow();
        
        String code = (String) JOptionPane.showInputDialog(
            parentPanel,
            "<html>A browser window has been opened for ChatGPT Pro/Plus authentication.<br><br>" +
            "<b>Instructions:</b><br>" +
            "1. Sign in to your OpenAI/ChatGPT account in the browser<br>" +
            "2. Authorize GhidrAssist to access your account<br>" +
            "3. After authorization, you'll be redirected to localhost<br>" +
            "4. Copy the URL from the browser (or just the code value)<br>" +
            "5. Paste it below:<br><br>" +
            "<b>Paste URL or Code:</b></html>",
            "OpenAI OAuth Authentication",
            JOptionPane.PLAIN_MESSAGE,
            null,
            null,
            ""
        );
        
        if (code == null || code.trim().isEmpty()) {
            return;
        }
        
        SwingWorker<String, Void> exchangeWorker = new SwingWorker<String, Void>() {
            private String errorMessage = null;
            
            @Override
            protected String doInBackground() {
                try {
                    tokenManager.authenticateWithCode(code.trim());
                    return tokenManager.toJson();
                } catch (Exception ex) {
                    errorMessage = ex.getMessage();
                    return null;
                }
            }
            
            @Override
            protected void done() {
                try {
                    String credentialsJson = get();
                    if (credentialsJson != null && !credentialsJson.isEmpty()) {
                        keyField.setText(credentialsJson);
                        JOptionPane.showMessageDialog(parentPanel, 
                            "Successfully authenticated with ChatGPT Pro/Plus!\n\nThe OAuth token has been stored.",
                            "Authentication Successful", 
                            JOptionPane.INFORMATION_MESSAGE);
                    } else if (errorMessage != null) {
                        JOptionPane.showMessageDialog(parentPanel,
                            "Authentication failed: " + errorMessage,
                            "Authentication Error",
                            JOptionPane.ERROR_MESSAGE);
                    }
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(parentPanel,
                        "Authentication error: " + ex.getMessage(),
                        "Authentication Error",
                        JOptionPane.ERROR_MESSAGE);
                }
            }
        };
        
        exchangeWorker.execute();
    }
    
    // ==== Gemini OAuth Authentication Methods ====

    /**
     * Authenticates with Google Gemini OAuth using automatic callback capture.
     * Falls back to manual code entry if automatic capture fails.
     */
    private void authenticateGeminiOAuth(JPanel parentPanel, JTextField keyField) {
        GeminiOAuthTokenManager tokenManager = new GeminiOAuthTokenManager();

        // Create progress dialog with cancel option
        JDialog progressDialog = new JDialog(SwingUtilities.getWindowAncestor(parentPanel),
            "Gemini OAuth Authentication", Dialog.ModalityType.APPLICATION_MODAL);
        JPanel progressPanel = new JPanel(new BorderLayout(10, 10));
        progressPanel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));

        JLabel statusLabel = new JLabel("Opening browser for authentication...");
        JProgressBar progressBar = new JProgressBar();
        progressBar.setIndeterminate(true);

        JButton cancelButton = new JButton("Cancel");
        JButton manualButton = new JButton("Use Manual Entry");

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 0));
        buttonPanel.add(manualButton);
        buttonPanel.add(cancelButton);

        progressPanel.add(statusLabel, BorderLayout.NORTH);
        progressPanel.add(progressBar, BorderLayout.CENTER);
        progressPanel.add(buttonPanel, BorderLayout.SOUTH);

        progressDialog.setContentPane(progressPanel);
        progressDialog.setSize(400, 150);
        progressDialog.setLocationRelativeTo(parentPanel);

        // Track authentication state
        final boolean[] authCompleted = {false};
        final boolean[] cancelled = {false};

        // Worker for automatic callback authentication
        SwingWorker<String, Void> authWorker = new SwingWorker<String, Void>() {
            private String errorMessage = null;
            private OAuthCallbackServer callbackServer = null;

            @Override
            protected String doInBackground() {
                try {
                    callbackServer = tokenManager.startAuthorizationFlowWithCallback();
                    publish(); // Update status

                    // Wait for callback with 5 minute timeout
                    tokenManager.completeAuthorizationWithCallback(callbackServer, 5);
                    return tokenManager.toJson();
                } catch (Exception ex) {
                    if (!cancelled[0]) {
                        errorMessage = ex.getMessage();
                    }
                    return null;
                }
            }

            @Override
            protected void process(java.util.List<Void> chunks) {
                statusLabel.setText("Waiting for authentication in browser...");
            }

            @Override
            protected void done() {
                if (cancelled[0]) return;

                try {
                    String credentialsJson = get();
                    if (credentialsJson != null && !credentialsJson.isEmpty()) {
                        authCompleted[0] = true;
                        progressDialog.dispose();
                        keyField.setText(credentialsJson);
                        JOptionPane.showMessageDialog(parentPanel,
                            "Successfully authenticated with Google Gemini CLI!\n\nThe OAuth token has been stored.",
                            "Authentication Successful",
                            JOptionPane.INFORMATION_MESSAGE);
                    } else if (errorMessage != null && !cancelled[0]) {
                        progressDialog.dispose();
                        // Fall back to manual entry on error
                        authenticateGeminiOAuthManual(parentPanel, keyField);
                    }
                } catch (Exception ex) {
                    if (!cancelled[0]) {
                        progressDialog.dispose();
                        authenticateGeminiOAuthManual(parentPanel, keyField);
                    }
                }
            }

            public void cancel() {
                cancelled[0] = true;
                tokenManager.cancelAuthentication();
            }
        };

        // Cancel button action
        cancelButton.addActionListener(e -> {
            cancelled[0] = true;
            tokenManager.cancelAuthentication();
            authWorker.cancel(true);
            progressDialog.dispose();
        });

        // Manual entry button action
        manualButton.addActionListener(e -> {
            cancelled[0] = true;
            tokenManager.cancelAuthentication();
            authWorker.cancel(true);
            progressDialog.dispose();
            authenticateGeminiOAuthManual(parentPanel, keyField);
        });

        // Start the worker
        authWorker.execute();

        // Show progress dialog (blocks until closed)
        progressDialog.setVisible(true);
    }

    /**
     * Manual OAuth code entry for Google Gemini (fallback).
     * Uses headless mode with PKCE S256 and codeassist.google.com/authcode redirect.
     */
    private void authenticateGeminiOAuthManual(JPanel parentPanel, JTextField keyField) {
        GeminiOAuthTokenManager tokenManager = new GeminiOAuthTokenManager();
        tokenManager.startAuthorizationFlow();

        String code = (String) JOptionPane.showInputDialog(
            parentPanel,
            "<html>A browser window has been opened for Google Gemini authentication.<br><br>" +
            "<b>Instructions:</b><br>" +
            "1. Sign in to your Google account in the browser<br>" +
            "2. Authorize GhidrAssist to access your account<br>" +
            "3. Copy the authorization code shown on the page<br>" +
            "4. Paste it below:<br><br>" +
            "<b>Authorization Code:</b></html>",
            "Gemini OAuth Authentication",
            JOptionPane.PLAIN_MESSAGE,
            null,
            null,
            ""
        );

        if (code == null || code.trim().isEmpty()) {
            return;
        }

        SwingWorker<String, Void> exchangeWorker = new SwingWorker<String, Void>() {
            private String errorMessage = null;

            @Override
            protected String doInBackground() {
                try {
                    tokenManager.authenticateWithCode(code.trim());
                    return tokenManager.toJson();
                } catch (Exception ex) {
                    errorMessage = ex.getMessage();
                    return null;
                }
            }

            @Override
            protected void done() {
                try {
                    String credentialsJson = get();
                    if (credentialsJson != null && !credentialsJson.isEmpty()) {
                        keyField.setText(credentialsJson);
                        JOptionPane.showMessageDialog(parentPanel,
                            "Successfully authenticated with Google Gemini CLI!\n\nThe OAuth token has been stored.",
                            "Authentication Successful",
                            JOptionPane.INFORMATION_MESSAGE);
                    } else if (errorMessage != null) {
                        JOptionPane.showMessageDialog(parentPanel,
                            "Authentication failed: " + errorMessage,
                            "Authentication Error",
                            JOptionPane.ERROR_MESSAGE);
                    }
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(parentPanel,
                        "Authentication error: " + ex.getMessage(),
                        "Authentication Error",
                        JOptionPane.ERROR_MESSAGE);
                }
            }
        };

        exchangeWorker.execute();
    }

    // ==== Inner Classes ====

    private static class MCPServersTableModel extends javax.swing.table.AbstractTableModel {
        private static final long serialVersionUID = 1L;
        private static final String[] COLUMN_NAMES = {"Name", "Target", "Enabled", "Transport"};
        private List<MCPServerConfig> servers;

        public MCPServersTableModel() {
            refresh();
        }

        public void refresh() {
            servers = MCPServerRegistry.getInstance().getAllServers();
            fireTableDataChanged();
        }

        @Override
        public int getRowCount() {
            return servers.size();
        }

        @Override
        public int getColumnCount() {
            return COLUMN_NAMES.length;
        }

        @Override
        public String getColumnName(int column) {
            return COLUMN_NAMES[column];
        }

        @Override
        public Class<?> getColumnClass(int column) {
            return column == 2 ? Boolean.class : String.class;
        }

        @Override
        public Object getValueAt(int row, int column) {
            MCPServerConfig server = servers.get(row);
            switch (column) {
                case 0: return server.getName();
                case 1: return server.getDisplayTarget();
                case 2: return server.isEnabled();
                case 3: return server.getTransport().getDisplayName();
                default: return null;
            }
        }

        @Override
        public boolean isCellEditable(int row, int column) {
            return column == 2;
        }

        @Override
        public void setValueAt(Object value, int row, int column) {
            if (column == 2 && value instanceof Boolean) {
                MCPServerConfig updated = servers.get(row).copy();
                updated.setEnabled((Boolean) value);
                MCPServerRegistry.getInstance().updateServer(updated);
                fireTableCellUpdated(row, column);
            }
        }

        public MCPServerConfig getServerAt(int row) {
            return servers.get(row);
        }
    }
}
