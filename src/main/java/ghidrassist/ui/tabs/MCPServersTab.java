package ghidrassist.ui.tabs;

import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;

import ghidrassist.mcp2.server.MCPServerConfig;
import ghidrassist.mcp2.server.MCPServerRegistry;

public class MCPServersTab extends JPanel {
    private static final long serialVersionUID = 1L;
    
    private MCPServerRegistry registry;
    private JTable serversTable;
    private MCPServersTableModel tableModel;
    private JButton addButton;
    private JButton editButton;
    private JButton removeButton;
    private JButton testButton;
    private SwingWorker<Boolean, Void> activeTestWorker;
    
    public MCPServersTab() {
        this.registry = MCPServerRegistry.getInstance();
        initializeComponents();
        layoutComponents();
        setupEventHandlers();
        refreshTable();
    }
    
    private void initializeComponents() {
        tableModel = new MCPServersTableModel();
        serversTable = new JTable(tableModel);
        serversTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        serversTable.getTableHeader().setReorderingAllowed(false);
        
        // Custom renderer for enabled column
        serversTable.getColumnModel().getColumn(2).setCellRenderer(new BooleanCellRenderer());
        
        // Column widths
        serversTable.getColumnModel().getColumn(0).setPreferredWidth(150);
        serversTable.getColumnModel().getColumn(1).setPreferredWidth(300);
        serversTable.getColumnModel().getColumn(2).setPreferredWidth(80);
        serversTable.getColumnModel().getColumn(3).setPreferredWidth(120);
        
        addButton = new JButton("Add Server");
        editButton = new JButton("Edit");
        removeButton = new JButton("Remove");
        testButton = new JButton("Test Connection");
        
        // Initially disable buttons that require selection
        editButton.setEnabled(false);
        removeButton.setEnabled(false);
        testButton.setEnabled(false);
    }
    
    private void layoutComponents() {
        setLayout(new BorderLayout());
        
        // Main panel with table
        JScrollPane scrollPane = new JScrollPane(serversTable);
        scrollPane.setPreferredSize(new Dimension(600, 300));
        
        // Button panel
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        buttonPanel.add(addButton);
        buttonPanel.add(editButton);
        buttonPanel.add(removeButton);
        buttonPanel.add(Box.createHorizontalStrut(20));
        buttonPanel.add(testButton);
        
        // Info panel
        JPanel infoPanel = new JPanel(new BorderLayout());
        JTextArea infoText = new JTextArea(
            "MCP (Model Context Protocol) servers provide additional tools and context to the LLM.\n" +
            "Configure remote HTTP/SSE servers or local stdio processes here. Servers must be MCP-compliant."
        );
        infoText.setEditable(false);
        infoText.setOpaque(false);
        infoText.setFont(infoText.getFont().deriveFont(Font.ITALIC));
        infoPanel.add(infoText, BorderLayout.CENTER);
        infoPanel.setBorder(BorderFactory.createEmptyBorder(5, 10, 10, 10));
        
        add(infoPanel, BorderLayout.NORTH);
        add(scrollPane, BorderLayout.CENTER);
        add(buttonPanel, BorderLayout.SOUTH);
    }
    
    private void setupEventHandlers() {
        // Table selection listener
        serversTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                boolean hasSelection = serversTable.getSelectedRow() >= 0;
                editButton.setEnabled(hasSelection);
                removeButton.setEnabled(hasSelection);
                testButton.setEnabled(hasSelection);
            }
        });
        
        addButton.addActionListener(e -> showAddEditDialog(null));
        editButton.addActionListener(e -> {
            int selectedRow = serversTable.getSelectedRow();
            if (selectedRow >= 0) {
                MCPServerConfig server = tableModel.getServerAt(selectedRow);
                showAddEditDialog(server);
            }
        });
        
        removeButton.addActionListener(e -> {
            int selectedRow = serversTable.getSelectedRow();
            if (selectedRow >= 0) {
                MCPServerConfig server = tableModel.getServerAt(selectedRow);
                int result = JOptionPane.showConfirmDialog(
                    this,
                    "Remove server '" + server.getName() + "'?",
                    "Confirm Removal",
                    JOptionPane.YES_NO_OPTION
                );
                if (result == JOptionPane.YES_OPTION) {
                    registry.removeServer(server.getName());
                    refreshTable();
                }
            }
        });
        
        testButton.addActionListener(e -> testConnection());
    }
    
    private void showAddEditDialog(MCPServerConfig existingServer) {
        MCPServerDialog dialog = new MCPServerDialog(
            SwingUtilities.getWindowAncestor(this),
            existingServer
        );
        dialog.setVisible(true);
        
        if (dialog.isConfirmed()) {
            MCPServerConfig config = dialog.getServerConfig();
            if (existingServer != null) {
                registry.removeServer(existingServer.getName());
            }
            registry.addServer(config);
            refreshTable();
        }
    }
    
    private void testConnection() {
        // If cancel clicked during test
        if (activeTestWorker != null && !activeTestWorker.isDone()) {
            activeTestWorker.cancel(true);
            testButton.setText("Test Connection");
            activeTestWorker = null;
            return;
        }

        int selectedRow = serversTable.getSelectedRow();
        if (selectedRow < 0) return;

        MCPServerConfig server = tableModel.getServerAt(selectedRow);
        if (server.isStdioTransport() && (server.getCommand() == null || server.getCommand().isBlank())) {
            JOptionPane.showMessageDialog(
                this,
                "The selected stdio server has no command configured.",
                "Connection Test Error",
                JOptionPane.ERROR_MESSAGE
            );
            return;
        }
        if (server.isNetworkTransport() && (server.getUrl() == null || server.getUrl().isBlank())) {
            JOptionPane.showMessageDialog(
                this,
                "The selected MCP server has no URL configured.",
                "Connection Test Error",
                JOptionPane.ERROR_MESSAGE
            );
            return;
        }
        testButton.setText("Cancel");

        SwingWorker<Boolean, Void> worker = new SwingWorker<Boolean, Void>() {
            private String errorMessage = "";

            @Override
            protected Boolean doInBackground() throws Exception {
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
                testButton.setText("Test Connection");
                activeTestWorker = null;
                try {
                    if (isCancelled()) return;
                    boolean success = get();
                    String message;
                    int messageType;

                    if (success) {
                        message = "Connection successful!\n\n" +
                                 "Server is responding and supports MCP protocol.";
                        messageType = JOptionPane.INFORMATION_MESSAGE;
                    } else {
                        message = "Connection failed:\n\n" +
                            (errorMessage.isEmpty() ? "Unknown error occurred" : errorMessage);
                        messageType = JOptionPane.ERROR_MESSAGE;
                    }

                    JOptionPane.showMessageDialog(
                        MCPServersTab.this,
                        message,
                        "Connection Test Results",
                        messageType
                    );
                } catch (Exception e) {
                    JOptionPane.showMessageDialog(
                        MCPServersTab.this,
                        "Test failed: " + e.getMessage(),
                        "Connection Test Error",
                        JOptionPane.ERROR_MESSAGE
                    );
                }
            }
        };
        activeTestWorker = worker;
        worker.execute();
    }
    
    private void refreshTable() {
        tableModel.refresh();
    }
    
    private static class MCPServersTableModel extends AbstractTableModel {
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
            return column == 2; // Only enabled column is editable
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
    
    private static class BooleanCellRenderer extends DefaultTableCellRenderer {
        private JCheckBox checkBox = new JCheckBox();
        
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                boolean isSelected, boolean hasFocus, int row, int column) {
            checkBox.setSelected(value != null && (Boolean) value);
            checkBox.setHorizontalAlignment(JLabel.CENTER);
            checkBox.setOpaque(true);
            
            if (isSelected) {
                checkBox.setBackground(table.getSelectionBackground());
                checkBox.setForeground(table.getSelectionForeground());
            } else {
                checkBox.setBackground(table.getBackground());
                checkBox.setForeground(table.getForeground());
            }
            
            return checkBox;
        }
    }
}
