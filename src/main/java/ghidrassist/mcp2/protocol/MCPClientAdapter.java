package ghidrassist.mcp2.protocol;

import com.fasterxml.jackson.databind.ObjectMapper;
import ghidrassist.mcp2.prompts.MCPPrompt;
import ghidrassist.mcp2.prompts.MCPPromptArgument;
import ghidrassist.mcp2.resources.MCPResource;
import ghidrassist.mcp2.server.MCPServerConfig;
import ghidrassist.mcp2.server.MCPServerConfig.TransportType;
import ghidrassist.mcp2.tools.MCPTool;
import ghidra.util.Msg;

import com.google.gson.JsonObject;
import com.google.gson.JsonElement;
import com.google.gson.Gson;

import io.modelcontextprotocol.client.McpClient;
import io.modelcontextprotocol.client.McpAsyncClient;
import io.modelcontextprotocol.client.transport.HttpClientSseClientTransport;
import io.modelcontextprotocol.client.transport.HttpClientStreamableHttpTransport;
import io.modelcontextprotocol.client.transport.ServerParameters;
import io.modelcontextprotocol.client.transport.StdioClientTransport;
import io.modelcontextprotocol.json.jackson.JacksonMcpJsonMapper;
import io.modelcontextprotocol.spec.McpClientTransport;
import io.modelcontextprotocol.spec.McpSchema;

import java.io.File;
import java.lang.reflect.Method;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

/**
 * Adapter that wraps the official MCP SDK client to provide compatibility
 * with our existing GhidrAssist MCP architecture.
 */
public class MCPClientAdapter {
    
    private final MCPServerConfig config;
    private volatile McpAsyncClient mcpClient;
    private MCPClientHandler handler;
    private volatile boolean initialized = false;
    private List<MCPTool> discoveredTools = new ArrayList<>();
    private List<MCPResource> discoveredResources = new ArrayList<>();
    private List<MCPPrompt> discoveredPrompts = new ArrayList<>();
    
    /**
     * Interface for handling client events (compatibility with existing code)
     */
    public interface MCPClientHandler {
        void onConnected(MCPClientAdapter client);
        void onDisconnected(MCPClientAdapter client);
        void onToolsDiscovered(MCPClientAdapter client, List<MCPTool> tools);
        void onResourcesDiscovered(MCPClientAdapter client, List<MCPResource> resources);
        void onPromptsDiscovered(MCPClientAdapter client, List<MCPPrompt> prompts);
        void onError(MCPClientAdapter client, Throwable error);
    }
    
    public MCPClientAdapter(MCPServerConfig config) {
        this.config = config;
    }
    
    /**
     * Set client event handler
     */
    public void setHandler(MCPClientHandler handler) {
        this.handler = handler;
    }
    
    /**
     * Connect and initialize the MCP client using the official SDK
     */
    public CompletableFuture<Void> connect() {
        return CompletableFuture.runAsync(() -> {
            try {
                // Create transport based on configuration
                McpClientTransport transport = createTransport();

                // Build client with our configuration
                McpSchema.ClientCapabilities capabilities = McpSchema.ClientCapabilities.builder()
                    .build();

                mcpClient = McpClient.async(transport)
                    .requestTimeout(Duration.ofSeconds(60))
                    .capabilities(capabilities)
                    .build();

                Msg.info(this, "MCP async client created with 60s timeout for: " + config.getName() +
                         " using " + config.getTransport().getDisplayName() + " transport");

                // Initialize connection (required by SDK)
                mcpClient.initialize().block();

                Msg.info(this, "Connected to MCP server using official SDK: " + config.getName());

                // Discover tools, resources, and prompts after initialization
                discoverTools().get();
                discoverResources().get();
                discoverPrompts().get();

                initialized = true;

                // Notify handler on EDT for UI updates
                if (handler != null) {
                    javax.swing.SwingUtilities.invokeLater(() -> handler.onConnected(this));
                }

            } catch (Exception e) {
                Msg.error(this, "Failed to connect to MCP server: " + e.getMessage());

                // Notify error on EDT for UI updates
                if (handler != null) {
                    javax.swing.SwingUtilities.invokeLater(() -> handler.onError(this, e));
                }

                throw new RuntimeException("MCP client connection failed", e);
            }
        });
    }

    /**
     * Create transport based on server configuration type.
     */
    private McpClientTransport createTransport() {
        switch (config.getTransport()) {
            case STREAMABLE_HTTP:
                String baseUrl = config.getBaseUrl();
                // Streamable HTTP uses /mcp endpoint
                String mcpUrl = baseUrl.endsWith("/") ? baseUrl + "mcp" : baseUrl + "/mcp";
                Msg.debug(this, "Creating Streamable HTTP transport for: " + mcpUrl);
                return HttpClientStreamableHttpTransport.builder(mcpUrl).build();
            case STDIO:
                Msg.debug(this, "Creating stdio transport for command: " + config.getCommand());
                return createStdioTransport();
            case SSE:
            default:
                baseUrl = config.getBaseUrl();
                // SSE uses base URL (endpoints at /sse and /message)
                Msg.debug(this, "Creating SSE transport for: " + baseUrl);
                return HttpClientSseClientTransport.builder(baseUrl).build();
        }
    }

    private McpClientTransport createStdioTransport() {
        var builder = ServerParameters.builder(config.getCommand());

        List<String> args = config.getArgs();
        if (!args.isEmpty()) {
            builder.args(args.toArray(new String[0]));
        }

        Map<String, String> env = config.getEnv();
        if (!env.isEmpty()) {
            invokeBuilder(builder, env, "env", Map.class);
            invokeBuilder(builder, env, "environment", Map.class);
        }

        String cwd = config.getCwd();
        if (cwd != null && !cwd.isBlank()) {
            boolean applied =
                invokeBuilder(builder, cwd, "workingDirectory", String.class) ||
                invokeBuilder(builder, Path.of(cwd), "workingDirectory", Path.class) ||
                invokeBuilder(builder, new File(cwd), "workingDirectory", File.class) ||
                invokeBuilder(builder, cwd, "cwd", String.class) ||
                invokeBuilder(builder, Path.of(cwd), "cwd", Path.class);

            if (!applied) {
                Msg.warn(this, "STDIO working directory is configured but not supported by this MCP SDK version");
            }
        }

        return new StdioClientTransport(
            builder.build(),
            new JacksonMcpJsonMapper(new ObjectMapper())
        );
    }

    private boolean invokeBuilder(Object target, Object value, String methodName, Class<?> parameterType) {
        try {
            Method method = target.getClass().getMethod(methodName, parameterType);
            method.invoke(target, value);
            return true;
        } catch (ReflectiveOperationException e) {
            return false;
        }
    }
    
    /**
     * Disconnect from the MCP server
     */
    public CompletableFuture<Void> disconnect() {
        return CompletableFuture.runAsync(() -> {
            try {
                if (mcpClient != null) {
                    mcpClient.closeGracefully().block();
                    mcpClient = null;
                }

                initialized = false;
                discoveredTools.clear();
                discoveredResources.clear();
                discoveredPrompts.clear();

                // Notify handler on EDT for UI updates
                if (handler != null) {
                    javax.swing.SwingUtilities.invokeLater(() -> handler.onDisconnected(this));
                }

            } catch (Exception e) {
                Msg.error(this, "Error during disconnect: " + e.getMessage());
            }
        });
    }
    
    /**
     * Execute a tool call using the official SDK async client
     */
    public CompletableFuture<JsonElement> executeTool(String toolName, JsonObject arguments) {
        if (!initialized || mcpClient == null) {
            return CompletableFuture.failedFuture(
                new IllegalStateException("Client not initialized"));
        }
        
        // Convert JsonObject to the format expected by the SDK
        McpSchema.CallToolRequest toolCallRequest = new McpSchema.CallToolRequest(
            toolName, 
            convertJsonObjectToMap(arguments)
        );
        
        Msg.debug(this, "Executing tool: " + toolName + " on server: " + config.getName());
        
        // Use async client and convert Mono to CompletableFuture
        return mcpClient.callTool(toolCallRequest)
            .doOnSubscribe(subscription -> Msg.debug(this, "Starting tool execution: " + toolName + " on server: " + config.getName()))
            .doOnNext(result -> Msg.debug(this, "Received tool response: " + toolName))
            .map(result -> {
                Msg.debug(this, "Tool execution completed: " + toolName);
                // Convert result back to JsonElement for compatibility
                Gson gson = new Gson();
                return gson.fromJson(gson.toJson(result.content()), JsonElement.class);
            })
            .doOnError(e -> Msg.error(this, "Tool execution failed for " + toolName + ": " + e.getMessage()))
            .doOnCancel(() -> Msg.warn(this, "Tool execution cancelled: " + toolName))
            .onErrorMap(e -> new RuntimeException("Tool execution failed: " + e.getMessage(), e))
            .toFuture();
    }
    
    /**
     * Get all discovered tools
     */
    public List<MCPTool> getDiscoveredTools() {
        return new ArrayList<>(discoveredTools);
    }
    
    /**
     * Find tool by name
     */
    public MCPTool findTool(String toolName) {
        return discoveredTools.stream()
            .filter(tool -> tool.matchesName(toolName))
            .findFirst()
            .orElse(null);
    }
    
    /**
     * Check if client is connected and initialized
     */
    public boolean isReady() {
        return initialized && mcpClient != null;
    }
    
    /**
     * Get server configuration
     */
    public MCPServerConfig getServerConfig() {
        return config;
    }
    
    /**
     * Get connection status info
     */
    public String getStatusInfo() {
        if (!initialized) {
            return "Disconnected";
        } else {
            return String.format("Connected (%d tools, %d resources, %d prompts)",
                discoveredTools.size(), discoveredResources.size(), discoveredPrompts.size());
        }
    }

    /**
     * Get all discovered resources
     */
    public List<MCPResource> getDiscoveredResources() {
        return new ArrayList<>(discoveredResources);
    }

    /**
     * Get all discovered prompts
     */
    public List<MCPPrompt> getDiscoveredPrompts() {
        return new ArrayList<>(discoveredPrompts);
    }

    /**
     * List all resources from the MCP server.
     * @return CompletableFuture containing list of MCPResource objects
     */
    public CompletableFuture<List<MCPResource>> listResources() {
        if (!initialized || mcpClient == null) {
            return CompletableFuture.completedFuture(Collections.emptyList());
        }

        return mcpClient.listResources()
            .map(result -> result.resources().stream()
                .map(r -> new MCPResource(r.uri(), r.name(), r.description(), r.mimeType()))
                .collect(Collectors.toList()))
            .onErrorResume(e -> {
                Msg.debug(this, "Resources not supported by server: " + e.getMessage());
                return reactor.core.publisher.Mono.just(Collections.emptyList());
            })
            .toFuture();
    }

    /**
     * Read the content of a specific resource by URI.
     * @param uri The resource URI to read
     * @return CompletableFuture containing the resource content as a string
     */
    public CompletableFuture<String> readResource(String uri) {
        if (!initialized || mcpClient == null) {
            return CompletableFuture.failedFuture(
                new IllegalStateException("Client not initialized"));
        }

        McpSchema.ReadResourceRequest request = new McpSchema.ReadResourceRequest(uri);

        return mcpClient.readResource(request)
            .map(result -> {
                if (result.contents() != null && !result.contents().isEmpty()) {
                    McpSchema.ResourceContents content = result.contents().get(0);
                    if (content instanceof McpSchema.TextResourceContents) {
                        return ((McpSchema.TextResourceContents) content).text();
                    } else if (content instanceof McpSchema.BlobResourceContents) {
                        return ((McpSchema.BlobResourceContents) content).blob();
                    }
                }
                return "";
            })
            .onErrorMap(e -> new RuntimeException("Failed to read resource: " + e.getMessage(), e))
            .toFuture();
    }

    /**
     * List all prompts from the MCP server.
     * @return CompletableFuture containing list of MCPPrompt objects
     */
    public CompletableFuture<List<MCPPrompt>> listPrompts() {
        if (!initialized || mcpClient == null) {
            return CompletableFuture.completedFuture(Collections.emptyList());
        }

        return mcpClient.listPrompts()
            .map(result -> result.prompts().stream()
                .map(p -> {
                    List<MCPPromptArgument> args = null;
                    if (p.arguments() != null) {
                        args = p.arguments().stream()
                            .map(a -> new MCPPromptArgument(a.name(), a.description(), a.required()))
                            .collect(Collectors.toList());
                    }
                    return new MCPPrompt(p.name(), p.description(), args);
                })
                .collect(Collectors.toList()))
            .onErrorResume(e -> {
                Msg.debug(this, "Prompts not supported by server: " + e.getMessage());
                return reactor.core.publisher.Mono.just(Collections.emptyList());
            })
            .toFuture();
    }

    /**
     * Get a specific prompt with arguments.
     * @param name The prompt name
     * @param arguments Map of argument name to value
     * @return CompletableFuture containing the prompt result
     */
    public CompletableFuture<McpSchema.GetPromptResult> getPrompt(String name, Map<String, Object> arguments) {
        if (!initialized || mcpClient == null) {
            return CompletableFuture.failedFuture(
                new IllegalStateException("Client not initialized"));
        }

        McpSchema.GetPromptRequest request = new McpSchema.GetPromptRequest(name, arguments);

        return mcpClient.getPrompt(request)
            .onErrorMap(e -> new RuntimeException("Failed to get prompt: " + e.getMessage(), e))
            .toFuture();
    }
    
    /**
     * Discover available tools using the official SDK
     */
    private CompletableFuture<Void> discoverTools() {
        return CompletableFuture.runAsync(() -> {
            try {
                McpSchema.ListToolsResult toolsResult = mcpClient.listTools().block();
                List<MCPTool> tools = new ArrayList<>();
                
                for (McpSchema.Tool tool : toolsResult.tools()) {
                    // Convert SDK tool to our MCPTool format
                    MCPTool mcpTool = new MCPTool();
                    mcpTool.setName(tool.name());
                    mcpTool.setDescription(tool.description());
                    mcpTool.setServerName(config.getName());
                    
                    // Convert input schema if present
                    if (tool.inputSchema() != null) {
                        Gson gson = new Gson();
                        JsonObject schema = gson.fromJson(gson.toJson(tool.inputSchema()), JsonObject.class);
                        mcpTool.setInputSchema(schema);
                    }
                    
                    tools.add(mcpTool);
                }
                
                discoveredTools = tools;
                Msg.info(this, String.format("Successfully discovered %d tools from %s using official SDK", 
                                            tools.size(), config.getName()));
                
                // Notify handler on EDT for UI updates
                if (handler != null) {
                    javax.swing.SwingUtilities.invokeLater(() -> 
                        handler.onToolsDiscovered(this, tools));
                }
                
            } catch (Exception e) {
                Msg.error(this, "Tool discovery failed with exception: " + e.getMessage());
                throw new RuntimeException("Tool discovery failed", e);
            }
        });
    }

    /**
     * Discover available resources using the official SDK.
     * Resources are optional - servers may not support them.
     */
    private CompletableFuture<Void> discoverResources() {
        return CompletableFuture.runAsync(() -> {
            try {
                McpSchema.ListResourcesResult resourcesResult = mcpClient.listResources().block();
                List<MCPResource> resources = new ArrayList<>();

                if (resourcesResult != null && resourcesResult.resources() != null) {
                    for (McpSchema.Resource resource : resourcesResult.resources()) {
                        MCPResource mcpResource = new MCPResource(
                            resource.uri(),
                            resource.name(),
                            resource.description(),
                            resource.mimeType()
                        );
                        resources.add(mcpResource);
                    }
                }

                discoveredResources = resources;
                Msg.info(this, String.format("Discovered %d resources from %s",
                                            resources.size(), config.getName()));

                // Notify handler on EDT for UI updates
                if (handler != null && !resources.isEmpty()) {
                    javax.swing.SwingUtilities.invokeLater(() ->
                        handler.onResourcesDiscovered(this, resources));
                }

            } catch (Exception e) {
                // Resources are optional - don't fail connection if not supported
                Msg.debug(this, "Resource discovery not supported: " + e.getMessage());
                discoveredResources = new ArrayList<>();
            }
        });
    }

    /**
     * Discover available prompts using the official SDK.
     * Prompts are optional - servers may not support them.
     */
    private CompletableFuture<Void> discoverPrompts() {
        return CompletableFuture.runAsync(() -> {
            try {
                McpSchema.ListPromptsResult promptsResult = mcpClient.listPrompts().block();
                List<MCPPrompt> prompts = new ArrayList<>();

                if (promptsResult != null && promptsResult.prompts() != null) {
                    for (McpSchema.Prompt prompt : promptsResult.prompts()) {
                        List<MCPPromptArgument> args = null;
                        if (prompt.arguments() != null) {
                            args = prompt.arguments().stream()
                                .map(a -> new MCPPromptArgument(a.name(), a.description(), a.required()))
                                .collect(Collectors.toList());
                        }
                        MCPPrompt mcpPrompt = new MCPPrompt(
                            prompt.name(),
                            prompt.description(),
                            args
                        );
                        prompts.add(mcpPrompt);
                    }
                }

                discoveredPrompts = prompts;
                Msg.info(this, String.format("Discovered %d prompts from %s",
                                            prompts.size(), config.getName()));

                // Notify handler on EDT for UI updates
                if (handler != null && !prompts.isEmpty()) {
                    javax.swing.SwingUtilities.invokeLater(() ->
                        handler.onPromptsDiscovered(this, prompts));
                }

            } catch (Exception e) {
                // Prompts are optional - don't fail connection if not supported
                Msg.debug(this, "Prompt discovery not supported: " + e.getMessage());
                discoveredPrompts = new ArrayList<>();
            }
        });
    }

    /**
     * Convert JsonObject to Map for SDK compatibility
     */
    private java.util.Map<String, Object> convertJsonObjectToMap(JsonObject jsonObject) {
        Gson gson = new Gson();
        java.lang.reflect.Type type = new com.google.gson.reflect.TypeToken<java.util.Map<String, Object>>(){}.getType();
        return gson.fromJson(jsonObject, type);
    }
}
