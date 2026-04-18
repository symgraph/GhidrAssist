package ghidrassist.mcp2.server;

import com.google.gson.Gson;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Configuration for an MCP server connection.
 * Stores all necessary information to connect to and manage an MCP server.
 */
public class MCPServerConfig {
    
    public enum TransportType {
        SSE("Server-Sent Events"),
        STREAMABLE_HTTP("Streamable HTTP"),
        STDIO("Stdio (CLI Process)");

        private final String displayName;

        TransportType(String displayName) {
            this.displayName = displayName;
        }

        public String getDisplayName() {
            return displayName;
        }

        public static TransportType fromString(String value) {
            if (value == null || value.isBlank()) {
                return null;
            }

            String normalized = value.trim()
                .toUpperCase(Locale.ROOT)
                .replace('-', '_');

            if ("HTTP".equals(normalized) || "STREAMABLEHTTP".equals(normalized)) {
                normalized = "STREAMABLE_HTTP";
            }

            try {
                return TransportType.valueOf(normalized);
            } catch (IllegalArgumentException e) {
                return null;
            }
        }
    }
    
    private String name;                    // Display name (e.g., "GhidraMCP Local")
    private String url;                     // Server URL (e.g., "http://localhost:8081")
    private TransportType transport;        // Transport mechanism
    private int connectionTimeout;          // Connection timeout in seconds
    private int requestTimeout;            // Request timeout in seconds
    private boolean enabled;               // Whether this server is active
    private String description;            // Optional description
    private String command;                // STDIO command
    private List<String> args;             // STDIO arguments
    private Map<String, String> env;       // STDIO environment variables
    private String cwd;                    // STDIO working directory
    
    // Default constructor for JSON deserialization
    public MCPServerConfig() {
        this.transport = TransportType.SSE;
        this.connectionTimeout = 15;
        this.requestTimeout = 30;
        this.enabled = true;
        this.args = new ArrayList<>();
        this.env = new LinkedHashMap<>();
    }
    
    public MCPServerConfig(String name, String url) {
        this();
        this.name = name;
        this.url = url;
    }
    
    public MCPServerConfig(String name, String url, TransportType transport) {
        this(name, url);
        this.transport = transport;
    }
    
    public MCPServerConfig(String name, String url, TransportType transport, boolean enabled) {
        this(name, url, transport);
        this.enabled = enabled;
    }
    
    // Getters and setters
    
    public String getName() {
        return name;
    }
    
    public void setName(String name) {
        this.name = name;
    }
    
    public String getUrl() {
        return url;
    }
    
    public void setUrl(String url) {
        this.url = url;
    }
    
    public TransportType getTransport() {
        return transport;
    }
    
    public void setTransport(TransportType transport) {
        this.transport = transport;
    }
    
    public int getConnectionTimeout() {
        return connectionTimeout;
    }
    
    public void setConnectionTimeout(int connectionTimeout) {
        this.connectionTimeout = connectionTimeout;
    }
    
    public int getRequestTimeout() {
        return requestTimeout;
    }
    
    public void setRequestTimeout(int requestTimeout) {
        this.requestTimeout = requestTimeout;
    }
    
    public boolean isEnabled() {
        return enabled;
    }
    
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }
    
    public String getDescription() {
        return description;
    }
    
    public void setDescription(String description) {
        this.description = description;
    }

    public String getCommand() {
        return command;
    }

    public void setCommand(String command) {
        this.command = command;
    }

    public List<String> getArgs() {
        return args != null ? new ArrayList<>(args) : new ArrayList<>();
    }

    public void setArgs(List<String> args) {
        this.args = args != null ? new ArrayList<>(args) : new ArrayList<>();
    }

    public Map<String, String> getEnv() {
        return env != null ? new LinkedHashMap<>(env) : new LinkedHashMap<>();
    }

    public void setEnv(Map<String, String> env) {
        this.env = env != null ? new LinkedHashMap<>(env) : new LinkedHashMap<>();
    }

    public String getCwd() {
        return cwd;
    }

    public void setCwd(String cwd) {
        this.cwd = cwd;
    }

    public boolean isStdioTransport() {
        return transport == TransportType.STDIO;
    }

    public boolean isNetworkTransport() {
        return transport == TransportType.SSE || transport == TransportType.STREAMABLE_HTTP;
    }
    
    /**
     * Get the base URL for HTTP connections
     */
    public String getBaseUrl() {
        if (!isNetworkTransport() || url == null || url.isBlank()) return null;
        
        // Ensure URL has protocol
        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            return "http://" + url;
        }
        return url;
    }

    /**
     * Get the user-visible target for tables/dialogs.
     */
    public String getDisplayTarget() {
        if (isStdioTransport()) {
            return command != null ? command : "";
        }
        String baseUrl = getBaseUrl();
        return baseUrl != null ? baseUrl : "";
    }
    
    /**
     * Get the host from the URL
     */
    public String getHost() {
        try {
            java.net.URI uri = java.net.URI.create(getBaseUrl());
            String host = uri.getHost();
            return host != null ? host : "localhost";
        } catch (Exception e) {
            return "localhost";
        }
    }

    /**
     * Get the port from the URL
     */
    public int getPort() {
        try {
            java.net.URI uri = java.net.URI.create(getBaseUrl());
            int port = uri.getPort();
            if (port != -1) return port;
            return "https".equals(uri.getScheme()) ? 443 : 80;
        } catch (Exception e) {
            return 8081; // Default MCP port
        }
    }
    
    /**
     * Validate configuration
     */
    public boolean isValid() {
        return name != null && !name.trim().isEmpty() &&
               transport != null &&
               connectionTimeout > 0 &&
               requestTimeout > 0 &&
               ((isNetworkTransport() && url != null && !url.trim().isEmpty()) ||
                (isStdioTransport() && command != null && !command.trim().isEmpty()));
    }
    
    /**
     * Create a copy of this configuration
     */
    public MCPServerConfig copy() {
        MCPServerConfig copy = new MCPServerConfig(name, url, transport);
        copy.setConnectionTimeout(connectionTimeout);
        copy.setRequestTimeout(requestTimeout);
        copy.setEnabled(enabled);
        copy.setDescription(description);
        copy.setCommand(command);
        copy.setArgs(getArgs());
        copy.setEnv(getEnv());
        copy.setCwd(cwd);
        return copy;
    }
    
    /**
     * Serialize to JSON
     */
    public String toJson() {
        return new Gson().toJson(this);
    }
    
    /**
     * Deserialize from JSON
     */
    public static MCPServerConfig fromJson(String json) {
        return new Gson().fromJson(json, MCPServerConfig.class);
    }
    
    @Override
    public String toString() {
        return String.format("%s (%s) - %s", name, transport.getDisplayName(), 
                           enabled ? "Enabled" : "Disabled");
    }
    
    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || getClass() != obj.getClass()) return false;
        
        MCPServerConfig that = (MCPServerConfig) obj;
        return name != null ? name.equals(that.name) : that.name == null;
    }
    
    @Override
    public int hashCode() {
        return name != null ? name.hashCode() : 0;
    }
    
    /**
     * Create default MCP configuration
     */
    public static MCPServerConfig createGhidrAssistMCPDefault() {
        MCPServerConfig config = new MCPServerConfig("GhidrAssistMCP", "http://localhost:8080");
        config.setDescription("Local GhidrAssistMCP server instance");
        config.setTransport(TransportType.SSE);
        return config;
    }
}
