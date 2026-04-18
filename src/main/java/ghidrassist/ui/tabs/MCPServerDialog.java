package ghidrassist.ui.tabs;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import ghidrassist.mcp2.server.MCPServerConfig;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Window;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;

public class MCPServerDialog extends JDialog {
    private static final long serialVersionUID = 1L;

    private final MCPServerConfig existingServer;

    private JTextField nameField;
    private JTextField urlField;
    private JTextField commandField;
    private JTextField argsField;
    private JTextField cwdField;
    private JTextArea envArea;
    private JScrollPane envScrollPane;
    private JLabel urlLabel;
    private JLabel commandLabel;
    private JLabel argsLabel;
    private JLabel cwdLabel;
    private JLabel envLabel;
    private JTextArea helpTextArea;
    private JComboBox<MCPServerConfig.TransportType> transportCombo;
    private JCheckBox enabledCheckBox;
    private JButton okButton;
    private JButton cancelButton;
    private boolean confirmed = false;

    public MCPServerDialog(Window parent, MCPServerConfig existingServer) {
        super(parent, existingServer == null ? "Add MCP Server" : "Edit MCP Server",
            ModalityType.APPLICATION_MODAL);

        this.existingServer = existingServer != null ? existingServer.copy() : null;

        initializeComponents();
        layoutComponents();
        setupEventHandlers();

        if (existingServer != null) {
            populateFields(existingServer);
        } else {
            setDefaults();
        }

        updateTransportFields();
        pack();
        setMinimumSize(new Dimension(560, getPreferredSize().height));
        setLocationRelativeTo(parent);
        nameField.requestFocusInWindow();
    }

    private void initializeComponents() {
        nameField = new JTextField(24);
        urlField = new JTextField(32);
        commandField = new JTextField(32);
        argsField = new JTextField(32);
        cwdField = new JTextField(32);
        envArea = new JTextArea(4, 32);
        envArea.setLineWrap(true);
        envArea.setWrapStyleWord(true);
        envScrollPane = new JScrollPane(envArea);
        envScrollPane.setPreferredSize(new Dimension(320, 90));

        transportCombo = new JComboBox<>(MCPServerConfig.TransportType.values());
        enabledCheckBox = new JCheckBox("Enabled", true);

        urlLabel = new JLabel("URL:");
        commandLabel = new JLabel("Command:");
        argsLabel = new JLabel("Arguments:");
        cwdLabel = new JLabel("Working Directory:");
        envLabel = new JLabel("Environment JSON:");

        helpTextArea = new JTextArea();
        helpTextArea.setEditable(false);
        helpTextArea.setOpaque(false);
        helpTextArea.setLineWrap(true);
        helpTextArea.setWrapStyleWord(true);
        helpTextArea.setFont(helpTextArea.getFont().deriveFont(11f));

        okButton = new JButton("OK");
        cancelButton = new JButton("Cancel");

        getRootPane().setDefaultButton(okButton);
    }

    private void layoutComponents() {
        setLayout(new BorderLayout());

        JPanel formPanel = new JPanel(new GridBagLayout());
        formPanel.setBorder(BorderFactory.createEmptyBorder(12, 12, 8, 12));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;

        int row = 0;

        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.weightx = 0;
        formPanel.add(new JLabel("Name:"), gbc);
        gbc.gridx = 1;
        gbc.weightx = 1;
        formPanel.add(nameField, gbc);
        row++;

        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.weightx = 0;
        formPanel.add(new JLabel("Transport:"), gbc);
        gbc.gridx = 1;
        gbc.weightx = 1;
        formPanel.add(transportCombo, gbc);
        row++;

        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.weightx = 0;
        formPanel.add(urlLabel, gbc);
        gbc.gridx = 1;
        gbc.weightx = 1;
        formPanel.add(urlField, gbc);
        row++;

        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.weightx = 0;
        formPanel.add(commandLabel, gbc);
        gbc.gridx = 1;
        gbc.weightx = 1;
        formPanel.add(commandField, gbc);
        row++;

        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.weightx = 0;
        formPanel.add(argsLabel, gbc);
        gbc.gridx = 1;
        gbc.weightx = 1;
        formPanel.add(argsField, gbc);
        row++;

        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.weightx = 0;
        formPanel.add(cwdLabel, gbc);
        gbc.gridx = 1;
        gbc.weightx = 1;
        formPanel.add(cwdField, gbc);
        row++;

        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.weightx = 0;
        gbc.anchor = GridBagConstraints.NORTHWEST;
        formPanel.add(envLabel, gbc);
        gbc.gridx = 1;
        gbc.weightx = 1;
        gbc.fill = GridBagConstraints.BOTH;
        formPanel.add(envScrollPane, gbc);
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.anchor = GridBagConstraints.WEST;
        row++;

        gbc.gridx = 1;
        gbc.gridy = row;
        gbc.weightx = 1;
        formPanel.add(enabledCheckBox, gbc);

        JPanel helpPanel = new JPanel(new BorderLayout());
        helpPanel.setBorder(BorderFactory.createTitledBorder("Help"));
        helpPanel.add(helpTextArea, BorderLayout.CENTER);

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        buttonPanel.add(okButton);
        buttonPanel.add(cancelButton);

        add(helpPanel, BorderLayout.NORTH);
        add(formPanel, BorderLayout.CENTER);
        add(buttonPanel, BorderLayout.SOUTH);
    }

    private void setupEventHandlers() {
        okButton.addActionListener(e -> {
            if (validateInput()) {
                confirmed = true;
                dispose();
            }
        });

        cancelButton.addActionListener(e -> {
            confirmed = false;
            dispose();
        });

        transportCombo.addActionListener(e -> updateTransportFields());
    }

    private void setDefaults() {
        transportCombo.setSelectedItem(MCPServerConfig.TransportType.SSE);
        envArea.setText("{}");
    }

    private void populateFields(MCPServerConfig server) {
        nameField.setText(server.getName());
        urlField.setText(server.getBaseUrl() != null ? server.getBaseUrl() : "");
        commandField.setText(server.getCommand() != null ? server.getCommand() : "");
        argsField.setText(formatArgs(server.getArgs()));
        cwdField.setText(server.getCwd() != null ? server.getCwd() : "");
        envArea.setText(server.getEnv().isEmpty() ? "{}" : new Gson().toJson(server.getEnv()));
        transportCombo.setSelectedItem(server.getTransport());
        enabledCheckBox.setSelected(server.isEnabled());
    }

    private void updateTransportFields() {
        MCPServerConfig.TransportType transport =
            (MCPServerConfig.TransportType) transportCombo.getSelectedItem();
        boolean isStdio = transport == MCPServerConfig.TransportType.STDIO;

        urlLabel.setVisible(!isStdio);
        urlField.setVisible(!isStdio);
        commandLabel.setVisible(isStdio);
        commandField.setVisible(isStdio);
        argsLabel.setVisible(isStdio);
        argsField.setVisible(isStdio);
        cwdLabel.setVisible(isStdio);
        cwdField.setVisible(isStdio);
        envLabel.setVisible(isStdio);
        envScrollPane.setVisible(isStdio);

        if (transport == MCPServerConfig.TransportType.SSE) {
            urlField.setToolTipText("HTTP(S) base URL for SSE transport, such as http://localhost:8080");
            helpTextArea.setText(
                "Use SSE for legacy MCP servers exposing /sse and /message endpoints.\n\n" +
                "Example:\n" +
                "  Name: GhidrAssistMCP\n" +
                "  URL: http://localhost:8080"
            );
        } else if (transport == MCPServerConfig.TransportType.STREAMABLE_HTTP) {
            urlField.setToolTipText("HTTP(S) base URL for Streamable HTTP transport; GhidrAssist will use the /mcp endpoint");
            helpTextArea.setText(
                "Use Streamable HTTP for modern remote MCP servers.\n\n" +
                "Example:\n" +
                "  Name: Remote Tools\n" +
                "  URL: http://127.0.0.1:3000"
            );
        } else {
            commandField.setToolTipText("Executable to launch, such as python, uvx, npx, or a full path");
            argsField.setToolTipText("Shell-style arguments or a JSON array of strings");
            cwdField.setToolTipText("Optional working directory for the child process");
            envArea.setToolTipText("Optional JSON object of string environment variables");
            helpTextArea.setText(
                "Use stdio for local MCP servers launched as child processes.\n\n" +
                "Examples:\n" +
                "  Command: npx\n" +
                "  Arguments: -y @modelcontextprotocol/server-filesystem /tmp\n\n" +
                "  Command: python\n" +
                "  Arguments: [\"server.py\", \"--port\", \"9000\"]\n" +
                "  Environment JSON: {\"API_KEY\":\"value\"}"
            );
        }

        revalidate();
        repaint();
        pack();
    }

    private boolean validateInput() {
        String name = nameField.getText().trim();
        MCPServerConfig.TransportType transport =
            (MCPServerConfig.TransportType) transportCombo.getSelectedItem();

        if (name.isEmpty()) {
            showError("Name cannot be empty.");
            nameField.requestFocus();
            return false;
        }

        if (!name.matches("^[a-zA-Z0-9_-]+$")) {
            showError("Name can only contain letters, numbers, underscores, and hyphens.");
            nameField.requestFocus();
            return false;
        }

        try {
            if (transport == MCPServerConfig.TransportType.STDIO) {
                if (commandField.getText().trim().isEmpty()) {
                    showError("Command cannot be empty for stdio transport.");
                    commandField.requestFocus();
                    return false;
                }
                parseArgs(argsField.getText());
                parseEnv(envArea.getText());
            } else {
                String url = urlField.getText().trim();
                if (url.isEmpty()) {
                    showError("URL cannot be empty.");
                    urlField.requestFocus();
                    return false;
                }
                if (!url.startsWith("http://") && !url.startsWith("https://")) {
                    showError("URL must start with http:// or https:// for " + transport.getDisplayName() + " transport.");
                    urlField.requestFocus();
                    return false;
                }
            }
        } catch (IllegalArgumentException e) {
            showError(e.getMessage());
            return false;
        }

        return true;
    }

    private List<String> parseArgs(String rawArgs) {
        String value = rawArgs != null ? rawArgs.trim() : "";
        if (value.isEmpty()) {
            return new ArrayList<>();
        }

        if (value.startsWith("[")) {
            JsonArray array = new Gson().fromJson(value, JsonArray.class);
            if (array == null) {
                throw new IllegalArgumentException("Arguments JSON must be an array of strings.");
            }

            List<String> args = new ArrayList<>();
            for (JsonElement element : array) {
                if (!element.isJsonPrimitive() || !element.getAsJsonPrimitive().isString()) {
                    throw new IllegalArgumentException("Arguments JSON must contain only strings.");
                }
                args.add(element.getAsString());
            }
            return args;
        }

        return splitShellArgs(value);
    }

    private Map<String, String> parseEnv(String rawEnv) {
        String value = rawEnv != null ? rawEnv.trim() : "";
        if (value.isEmpty()) {
            return new LinkedHashMap<>();
        }

        JsonObject obj = new Gson().fromJson(value, JsonObject.class);
        if (obj == null) {
            throw new IllegalArgumentException("Environment JSON must be an object of string keys and values.");
        }

        Map<String, String> env = new LinkedHashMap<>();
        for (Map.Entry<String, JsonElement> entry : obj.entrySet()) {
            if (!entry.getValue().isJsonPrimitive() || !entry.getValue().getAsJsonPrimitive().isString()) {
                throw new IllegalArgumentException("Environment JSON must contain only string values.");
            }
            env.put(entry.getKey(), entry.getValue().getAsString());
        }
        return env;
    }

    private List<String> splitShellArgs(String value) {
        List<String> args = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        boolean inSingleQuote = false;
        boolean inDoubleQuote = false;
        boolean escaping = false;

        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);

            if (escaping) {
                current.append(c);
                escaping = false;
                continue;
            }

            if (c == '\\' && !inSingleQuote) {
                escaping = true;
                continue;
            }

            if (c == '\'' && !inDoubleQuote) {
                inSingleQuote = !inSingleQuote;
                continue;
            }

            if (c == '"' && !inSingleQuote) {
                inDoubleQuote = !inDoubleQuote;
                continue;
            }

            if (Character.isWhitespace(c) && !inSingleQuote && !inDoubleQuote) {
                if (current.length() > 0) {
                    args.add(current.toString());
                    current.setLength(0);
                }
                continue;
            }

            current.append(c);
        }

        if (escaping || inSingleQuote || inDoubleQuote) {
            throw new IllegalArgumentException("Arguments contain an unterminated quote or escape sequence.");
        }

        if (current.length() > 0) {
            args.add(current.toString());
        }

        return args;
    }

    private String formatArgs(List<String> args) {
        if (args == null || args.isEmpty()) {
            return "";
        }

        List<String> formatted = new ArrayList<>();
        for (String arg : args) {
            if (arg == null) {
                continue;
            }
            if (arg.contains(" ") || arg.contains("\"")) {
                formatted.add("\"" + arg.replace("\\", "\\\\").replace("\"", "\\\"") + "\"");
            } else {
                formatted.add(arg);
            }
        }
        return String.join(" ", formatted);
    }

    private String blankToNull(String value) {
        if (value == null || value.trim().isEmpty()) {
            return null;
        }
        return value.trim();
    }

    private void showError(String message) {
        JOptionPane.showMessageDialog(this, message, "Validation Error", JOptionPane.ERROR_MESSAGE);
    }

    public boolean isConfirmed() {
        return confirmed;
    }

    public MCPServerConfig getServerConfig() {
        if (!confirmed) {
            return null;
        }

        MCPServerConfig.TransportType transport =
            (MCPServerConfig.TransportType) transportCombo.getSelectedItem();

        MCPServerConfig config = new MCPServerConfig(
            nameField.getText().trim(),
            transport == MCPServerConfig.TransportType.STDIO ? "" : urlField.getText().trim(),
            transport,
            enabledCheckBox.isSelected()
        );

        if (existingServer != null) {
            config.setConnectionTimeout(existingServer.getConnectionTimeout());
            config.setRequestTimeout(existingServer.getRequestTimeout());
            config.setDescription(existingServer.getDescription());
        }

        if (transport == MCPServerConfig.TransportType.STDIO) {
            config.setCommand(commandField.getText().trim());
            config.setArgs(parseArgs(argsField.getText()));
            config.setEnv(parseEnv(envArea.getText()));
            config.setCwd(blankToNull(cwdField.getText()));
        } else {
            config.setCommand(null);
            config.setArgs(new ArrayList<>());
            config.setEnv(new LinkedHashMap<>());
            config.setCwd(null);
        }

        return config;
    }
}
