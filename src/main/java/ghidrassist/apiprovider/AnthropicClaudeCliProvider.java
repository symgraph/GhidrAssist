package ghidrassist.apiprovider;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.util.Msg;
import ghidrassist.LlmApi.LlmResponseHandler;
import ghidrassist.apiprovider.capabilities.FunctionCallingProvider;
import ghidrassist.apiprovider.exceptions.*;
import ghidrassist.mcp2.server.MCPServerConfig;
import ghidrassist.mcp2.server.MCPServerRegistry;
import okhttp3.OkHttpClient;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * Anthropic Claude CLI Provider - proxies API requests through the claude CLI.
 *
 * Benefits:
 * - No API key required (uses CLI's OAuth authentication)
 * - MCP integration via --mcp-config
 * - Development/testing without direct API costs
 *
 * Limitations:
 * - No true streaming (simulated by chunking complete response)
 * - Requires claude CLI installed and authenticated
 */
public class AnthropicClaudeCliProvider extends APIProvider implements FunctionCallingProvider {
    private static final Gson gson = new Gson();

    // CLI streaming simulation settings
    private int streamChunkSize = 50;
    private int streamChunkDelay = 10; // milliseconds

    // Cached CLI path
    private String cachedCliPath = null;

    public AnthropicClaudeCliProvider(String name, String model, Integer maxTokens,
                              String url, String key, boolean disableTlsVerification,
                              boolean bypassProxy, Integer timeout) {
        super(name, ProviderType.ANTHROPIC_CLAUDE_CLI, model, maxTokens,
              url != null ? url : "", key != null ? key : "",
              disableTlsVerification, bypassProxy, timeout != null ? timeout : 90);

        // Default model to "sonnet" if not specified
        if (this.model == null || this.model.isEmpty()) {
            this.model = "sonnet";
        }
    }

    @Override
    protected OkHttpClient buildClient() {
        // CLI-based provider doesn't use HTTP client, but we need to return something
        // for the base class. Build a minimal client.
        return configureClientBuilder(new OkHttpClient.Builder())
            .connectTimeout(Duration.ofSeconds(10))
            .readTimeout(super.timeout)
            .writeTimeout(super.timeout)
            .build();
    }

    /**
     * Find the claude CLI executable (cross-platform).
     * Searches common installation paths based on the operating system.
     */
    private String findClaudeCli() {
        if (cachedCliPath != null) {
            // Verify cached path still exists
            File cached = new File(cachedCliPath);
            if (cached.exists() && cached.canExecute()) {
                return cachedCliPath;
            }
            cachedCliPath = null;
        }

        String osName = System.getProperty("os.name").toLowerCase();
        String userHome = System.getProperty("user.home");
        List<String> commonPaths = new ArrayList<>();

        if (osName.contains("win")) {
            // Windows paths
            String appData = System.getenv("APPDATA");
            String localAppData = System.getenv("LOCALAPPDATA");
            String userProfile = System.getenv("USERPROFILE");

            if (appData != null) {
                commonPaths.add(appData + "\\npm\\claude.cmd");
                commonPaths.add(appData + "\\npm\\claude");
            }
            if (localAppData != null) {
                commonPaths.add(localAppData + "\\npm\\claude.cmd");
                commonPaths.add(localAppData + "\\npm\\claude");
            }
            if (userProfile != null) {
                // Scoop install location
                commonPaths.add(userProfile + "\\scoop\\shims\\claude.cmd");
                commonPaths.add(userProfile + "\\scoop\\shims\\claude");
            }
        } else if (osName.contains("mac") || osName.contains("darwin")) {
            // macOS paths
            commonPaths.add("/usr/local/bin/claude");           // Intel Macs
            commonPaths.add("/opt/homebrew/bin/claude");        // Apple Silicon (M1/M2/M3)
            commonPaths.add(userHome + "/.npm-global/bin/claude");
            commonPaths.add(userHome + "/Library/npm/bin/claude");
            commonPaths.add(userHome + "/.local/bin/claude");
        } else {
            // Linux paths
            commonPaths.add("/usr/local/bin/claude");
            commonPaths.add("/usr/bin/claude");
            commonPaths.add(userHome + "/.local/bin/claude");
            commonPaths.add(userHome + "/.npm-global/bin/claude");
            commonPaths.add("/snap/bin/claude");                // Snap install
        }

        // Check explicit paths first
        for (String path : commonPaths) {
            if (path == null) continue;
            File file = new File(path);
            if (file.exists() && file.canExecute()) {
                cachedCliPath = path;
                Msg.debug(this, "Found Claude CLI at: " + cachedCliPath);
                return cachedCliPath;
            }
        }

        // Try platform-specific PATH lookup command
        if (osName.contains("win")) {
            // Try 'where' command on Windows
            cachedCliPath = findCliUsingCommand("where", "claude");
        } else {
            // Try 'which' command on Unix-like systems
            cachedCliPath = findCliUsingCommand("which", "claude");
        }

        if (cachedCliPath != null) {
            Msg.debug(this, "Found Claude CLI via PATH lookup: " + cachedCliPath);
            return cachedCliPath;
        }

        Msg.warn(this, "Claude CLI not found. Searched paths: " + commonPaths);
        return null;
    }

    /**
     * Use a command (which/where) to find the CLI in PATH.
     */
    private String findCliUsingCommand(String... command) {
        try {
            ProcessBuilder pb = new ProcessBuilder(command);
            pb.redirectErrorStream(true);
            Process process = pb.start();

            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()))) {
                String line = reader.readLine();
                if (line != null && !line.isEmpty()) {
                    File found = new File(line.trim());
                    if (found.exists()) {
                        return found.getAbsolutePath();
                    }
                }
            }
            process.waitFor(5, TimeUnit.SECONDS);
        } catch (Exception e) {
            // Ignore - path lookup failed
        }
        return null;
    }

    /**
     * Get platform-specific error message when CLI is not found.
     */
    private String getCliNotFoundMessage() {
        String osName = System.getProperty("os.name").toLowerCase();
        StringBuilder msg = new StringBuilder();
        msg.append("Claude CLI not found.\n\n");
        msg.append("Install with: npm install -g @anthropic-ai/claude-code\n\n");

        if (osName.contains("win")) {
            msg.append("On Windows, ensure npm global bin is in your PATH:\n");
            msg.append("  %APPDATA%\\npm\n");
        } else if (osName.contains("mac") || osName.contains("darwin")) {
            msg.append("On macOS, the CLI is typically installed at:\n");
            msg.append("  /usr/local/bin/claude (Intel) or\n");
            msg.append("  /opt/homebrew/bin/claude (Apple Silicon)\n");
        } else {
            msg.append("On Linux, the CLI is typically installed at:\n");
            msg.append("  ~/.local/bin/claude or /usr/local/bin/claude\n");
        }

        msg.append("\nAfter installation, run 'claude' once to authenticate.");
        return msg.toString();
    }

    /**
     * Format chat messages into a single prompt string for the CLI.
     */
    private String formatMessagesForCli(List<ChatMessage> messages) {
        StringBuilder sb = new StringBuilder();

        for (ChatMessage msg : messages) {
            String role = msg.getRole();
            String content = msg.getContent() != null ? msg.getContent() : "";

            if (content.isEmpty()) continue;

            switch (role) {
                case ChatMessage.ChatMessageRole.SYSTEM:
                    sb.append("System: ").append(content).append("\n\n");
                    break;
                case ChatMessage.ChatMessageRole.USER:
                    sb.append("User: ").append(content).append("\n\n");
                    break;
                case ChatMessage.ChatMessageRole.ASSISTANT:
                    sb.append("Assistant: ").append(content).append("\n\n");
                    break;
                case ChatMessage.ChatMessageRole.TOOL:
                case ChatMessage.ChatMessageRole.FUNCTION:
                    sb.append("Tool Result: ").append(content).append("\n\n");
                    break;
                default:
                    sb.append(content).append("\n\n");
                    break;
            }
        }

        return sb.toString().trim();
    }

    /**
     * Create MCP config file for the Claude CLI.
     * Returns path to temporary config file, or null if no MCP servers configured.
     */
    private File createMcpConfigFile() throws IOException {
        MCPServerRegistry registry = MCPServerRegistry.getInstance();
        List<MCPServerConfig> enabledServers = registry.getEnabledServers();

        if (enabledServers.isEmpty()) {
            return null;
        }

        JsonObject config = new JsonObject();
        JsonObject mcpServers = new JsonObject();

        for (MCPServerConfig server : enabledServers) {
            JsonObject serverConfig = new JsonObject();
            String transport = server.getTransport().name().toLowerCase();
            if ("stdio".equals(transport)) {
                String command = server.getCommand();
                if (command == null || command.isBlank()) {
                    continue;
                }
                serverConfig.addProperty("command", command);
                JsonArray args = new JsonArray();
                for (String arg : server.getArgs()) {
                    args.add(arg);
                }
                JsonObject env = new JsonObject();
                for (Map.Entry<String, String> entry : server.getEnv().entrySet()) {
                    env.addProperty(entry.getKey(), entry.getValue());
                }
                serverConfig.add("args", args);
                serverConfig.add("env", env);
            } else if ("sse".equals(transport) || "streamable_http".equals(transport)) {
                String serverUrl = server.getUrl();
                if (serverUrl == null || serverUrl.isEmpty()) {
                    continue;
                }

                String cliType = "sse".equals(transport) ? "sse" : "streamable-http";
                serverConfig.addProperty("type", cliType);
                serverConfig.addProperty("url", server.getBaseUrl());
            } else {
                continue;
            }

            mcpServers.add(server.getName(), serverConfig);
        }

        if (mcpServers.size() == 0) {
            return null;
        }

        config.add("mcpServers", mcpServers);

        // Create temp file
        File tempFile = File.createTempFile("ghidrassist_mcp_", ".json");
        tempFile.deleteOnExit();

        try (FileWriter writer = new FileWriter(tempFile)) {
            gson.toJson(config, writer);
        }

        Msg.debug(this, "Created MCP config file: " + tempFile.getAbsolutePath() +
                  " with " + mcpServers.size() + " server(s)");

        return tempFile;
    }

    /**
     * Handle CLI error based on stderr output and exit code.
     */
    private void handleCliError(String stderr, int exitCode) throws APIProviderException {
        String errorLower = stderr.toLowerCase();

        if (errorLower.contains("rate limit") || errorLower.contains("429")) {
            throw new RateLimitException(
                "Claude rate limit exceeded: " + stderr,
                getName(), "runClaudeCli", 60
            );
        }

        if (errorLower.contains("auth") || errorLower.contains("login") ||
            errorLower.contains("unauthorized") || errorLower.contains("401")) {
            throw new AuthenticationException(
                "Claude CLI authentication failed. Please run 'claude' interactively to authenticate.",
                getName(), "runClaudeCli"
            );
        }

        if (errorLower.contains("not found") || errorLower.contains("no such")) {
            throw new APIProviderException(
                APIProviderException.ErrorCategory.CONFIGURATION,
                "Claude CLI error: " + stderr,
                getName(), "runClaudeCli"
            );
        }

        throw new APIProviderException(
            APIProviderException.ErrorCategory.SERVICE_ERROR,
            "Claude CLI exited with code " + exitCode + ": " +
            (stderr.isEmpty() ? "No error message" : stderr),
            getName(), "runClaudeCli"
        );
    }

    /**
     * Execute the claude CLI with the given prompt.
     *
     * @param prompt The formatted prompt string
     * @param useMcp Whether to enable MCP servers
     * @return The CLI output (Claude's response)
     */
    private String runClaudeCli(String prompt, boolean useMcp) throws APIProviderException {
        String cliPath = findClaudeCli();
        if (cliPath == null) {
            throw new APIProviderException(
                APIProviderException.ErrorCategory.CONFIGURATION,
                getCliNotFoundMessage(),
                getName(), "runClaudeCli"
            );
        }

        if (prompt == null || prompt.trim().isEmpty()) {
            throw new APIProviderException(
                APIProviderException.ErrorCategory.CONFIGURATION,
                "Cannot send empty prompt to Claude CLI",
                getName(), "runClaudeCli"
            );
        }

        List<String> command = new ArrayList<>();
        command.add(cliPath);
        command.add("--print");
        command.add("--model");
        command.add(this.model);

        File mcpConfigFile = null;
        if (useMcp) {
            try {
                mcpConfigFile = createMcpConfigFile();
                if (mcpConfigFile != null) {
                    command.add("--mcp-config");
                    command.add(mcpConfigFile.getAbsolutePath());
                    command.add("--dangerously-skip-permissions");
                }
            } catch (IOException e) {
                Msg.warn(this, "Failed to create MCP config: " + e.getMessage());
            }
        }

        Msg.debug(this, "Executing Claude CLI: " + String.join(" ", command));

        try {
            ProcessBuilder pb = new ProcessBuilder(command);
            pb.redirectErrorStream(false);

            Process process = pb.start();

            // Write prompt to stdin
            try (OutputStream stdin = process.getOutputStream()) {
                stdin.write(prompt.getBytes(StandardCharsets.UTF_8));
                stdin.flush();
            }

            // Read stdout in a separate thread to avoid deadlock
            StringBuilder stdoutBuilder = new StringBuilder();
            StringBuilder stderrBuilder = new StringBuilder();

            Thread stdoutThread = new Thread(() -> {
                try (BufferedReader reader = new BufferedReader(
                        new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        if (stdoutBuilder.length() > 0) {
                            stdoutBuilder.append("\n");
                        }
                        stdoutBuilder.append(line);
                    }
                } catch (IOException e) {
                    Msg.error(this, "Error reading stdout: " + e.getMessage());
                }
            });

            Thread stderrThread = new Thread(() -> {
                try (BufferedReader reader = new BufferedReader(
                        new InputStreamReader(process.getErrorStream(), StandardCharsets.UTF_8))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        if (stderrBuilder.length() > 0) {
                            stderrBuilder.append("\n");
                        }
                        stderrBuilder.append(line);
                    }
                } catch (IOException e) {
                    Msg.error(this, "Error reading stderr: " + e.getMessage());
                }
            });

            stdoutThread.start();
            stderrThread.start();

            // Wait for process with timeout
            long timeoutSeconds = super.timeout.getSeconds();
            boolean completed = process.waitFor(timeoutSeconds, TimeUnit.SECONDS);

            if (!completed) {
                process.destroyForcibly();
                stdoutThread.interrupt();
                stderrThread.interrupt();
                throw new APIProviderException(
                    APIProviderException.ErrorCategory.TIMEOUT,
                    "Claude CLI timed out after " + timeoutSeconds + " seconds",
                    getName(), "runClaudeCli"
                );
            }

            // Wait for reader threads to complete
            stdoutThread.join(5000);
            stderrThread.join(5000);

            int exitCode = process.exitValue();
            String stdout = stdoutBuilder.toString().trim();
            String stderr = stderrBuilder.toString().trim();

            if (exitCode != 0) {
                handleCliError(stderr, exitCode);
            }

            if (stdout.isEmpty()) {
                Msg.warn(this, "Claude CLI returned empty response");
            }

            return stdout;

        } catch (IOException e) {
            throw new NetworkException(
                getName(), "runClaudeCli",
                NetworkException.NetworkErrorType.CONNECTION_FAILED, e
            );
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new APIProviderException(
                APIProviderException.ErrorCategory.CANCELLED,
                "CLI execution interrupted",
                getName(), "runClaudeCli"
            );
        } finally {
            // Cleanup temp file
            if (mcpConfigFile != null) {
                try {
                    mcpConfigFile.delete();
                } catch (Exception e) {
                    // Ignore cleanup errors
                }
            }
        }
    }

    @Override
    public String createChatCompletion(List<ChatMessage> messages) throws APIProviderException {
        String prompt = formatMessagesForCli(messages);
        return runClaudeCli(prompt, false);
    }

    @Override
    public String createChatCompletionWithFunctions(List<ChatMessage> messages,
            List<Map<String, Object>> functions) throws APIProviderException {
        String prompt = formatMessagesForCli(messages);
        // Enable MCP when functions are provided (indicates MCP checkbox is enabled)
        boolean useMcp = functions != null && !functions.isEmpty();
        return runClaudeCli(prompt, useMcp);
    }

    @Override
    public String createChatCompletionWithFunctionsFullResponse(List<ChatMessage> messages,
            List<Map<String, Object>> functions) throws APIProviderException {
        // Get the plain text response from CLI
        String responseText = createChatCompletionWithFunctions(messages, functions);

        // Wrap in OpenAI-compatible JSON format for ConversationalToolHandler
        // Claude CLI executes MCP tools internally, so we always return finish_reason="stop"
        // (there are no tool_calls for the host to execute)
        return wrapResponseAsOpenAIFormat(responseText);
    }

    /**
     * Wrap plain text response in OpenAI-compatible JSON format.
     * This is required for ConversationalToolHandler which expects JSON with
     * choices array, finish_reason, and message object.
     *
     * Note: Claude CLI handles MCP tool execution internally, so finish_reason
     * is always "stop" - there are no tool_calls for the host application to execute.
     */
    private String wrapResponseAsOpenAIFormat(String responseText) {
        JsonObject response = new JsonObject();
        JsonArray choices = new JsonArray();
        JsonObject choice = new JsonObject();
        JsonObject message = new JsonObject();

        message.addProperty("role", "assistant");
        message.addProperty("content", responseText != null ? responseText : "");

        choice.add("message", message);
        choice.addProperty("finish_reason", "stop");
        choice.addProperty("index", 0);

        choices.add(choice);
        response.add("choices", choices);
        response.addProperty("model", this.model);
        response.addProperty("object", "chat.completion");

        return gson.toJson(response);
    }

    @Override
    public void streamChatCompletion(List<ChatMessage> messages, LlmResponseHandler handler)
            throws APIProviderException {
        handler.onStart();

        try {
            String prompt = formatMessagesForCli(messages);
            String fullResponse = runClaudeCli(prompt, false);

            if (fullResponse.isEmpty()) {
                handler.onComplete("");
                return;
            }

            // Simulate streaming by chunking the response
            StringBuilder accumulated = new StringBuilder();
            for (int i = 0; i < fullResponse.length(); i += streamChunkSize) {
                if (!handler.shouldContinue()) {
                    break;
                }

                String chunk = fullResponse.substring(i,
                    Math.min(i + streamChunkSize, fullResponse.length()));
                accumulated.append(chunk);
                handler.onUpdate(chunk);

                // Small delay for visual effect
                if (streamChunkDelay > 0 && i + streamChunkSize < fullResponse.length()) {
                    Thread.sleep(streamChunkDelay);
                }
            }

            handler.onComplete(accumulated.toString());

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            handler.onError(e);
        } catch (APIProviderException e) {
            handler.onError(e);
        } catch (Exception e) {
            handler.onError(new APIProviderException(
                APIProviderException.ErrorCategory.SERVICE_ERROR,
                e.getMessage(), getName(), "streamChatCompletion"
            ));
        }
    }

    @Override
    public List<String> getAvailableModels() throws APIProviderException {
        throw new APIProviderException(
            APIProviderException.ErrorCategory.CONFIGURATION,
            "Model discovery is not supported for Claude Code CLI",
            getName(),
            "getAvailableModels"
        );
    }

    @Override
    public void getEmbeddingsAsync(String text, EmbeddingCallback callback) {
        // Claude CLI doesn't support embeddings
        callback.onError(new APIProviderException(
            APIProviderException.ErrorCategory.CONFIGURATION,
            "Embeddings not supported by Claude Code CLI provider",
            getName(), "getEmbeddingsAsync"
        ));
    }

    /**
     * Test connection by checking if CLI is available and authenticated.
     */
    @Override
    public void testConnection() throws APIProviderException {
        String cliPath = findClaudeCli();
        if (cliPath == null) {
            throw new APIProviderException(
                APIProviderException.ErrorCategory.CONFIGURATION,
                "Claude CLI not found", getName(), "testConnection"
            );
        }

        try {
            ProcessBuilder pb = new ProcessBuilder(cliPath, "--version");
            pb.redirectErrorStream(true);
            Process process = pb.start();

            boolean completed = process.waitFor(super.timeout.getSeconds(), TimeUnit.SECONDS);

            if (completed && process.exitValue() == 0) {
                try (BufferedReader reader = new BufferedReader(
                        new InputStreamReader(process.getInputStream()))) {
                    String version = reader.readLine();
                    Msg.info(this, "Claude CLI version: " + version);
                }
                return;
            }
            throw new APIProviderException(
                APIProviderException.ErrorCategory.SERVICE_ERROR,
                "Claude CLI version check failed", getName(), "testConnection"
            );
        } catch (Exception e) {
            throw new APIProviderException(
                APIProviderException.ErrorCategory.SERVICE_ERROR,
                e.getMessage(), getName(), "testConnection"
            );
        }
    }

    /**
     * Get the path to the Claude CLI if found.
     */
    public String getCliPath() {
        return findClaudeCli();
    }

    // Token counting - CLI doesn't provide token counts, so we estimate
    @Override
    public int countTokens(List<ChatMessage> messages) {
        // Rough estimate: ~4 characters per token
        String formatted = formatMessagesForCli(messages);
        return formatted.length() / 4;
    }

    @Override
    public int countTokens(String text) {
        if (text == null) return 0;
        return text.length() / 4;
    }
}
