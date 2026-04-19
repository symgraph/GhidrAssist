package ghidrassist.apiprovider;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.stream.JsonReader;
import ghidra.util.Msg;
import ghidrassist.LlmApi.LlmResponseHandler;
import ghidrassist.apiprovider.capabilities.FunctionCallingProvider;
import ghidrassist.apiprovider.capabilities.ModelListProvider;
import ghidrassist.apiprovider.exceptions.*;
import ghidrassist.apiprovider.oauth.OpenAIOAuthTokenManager;
import okhttp3.*;
import okio.BufferedSource;

import javax.net.ssl.*;
import java.io.IOException;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * OpenAI OAuth Provider - Uses OAuth authentication for ChatGPT Pro/Plus subscriptions.
 * 
 * This provider uses the Codex Responses API endpoint, implementing the same protocol
 * as the official Codex CLI (codex-cli-rs). Routes requests through the ChatGPT backend.
 * 
 * Key Features:
 * - OAuth PKCE authentication (no API key required)
 * - Automatic token refresh
 * - OpenAI Responses API format translation
 * - Streaming (required by Codex API)
 * - Function/tool calling support
 * 
 * CRITICAL Implementation Details:
 * - originator header MUST be "codex_cli_rs" (not "opencode")
 * - OpenAI-Beta header MUST include "responses=experimental"
 * - chatgpt-account-id header must be lowercase
 * - instructions MUST match the official Codex CLI prompt
 * - stream MUST be true (API requires streaming)
 * - store MUST be false
 */
public class OpenAIOAuthProvider extends APIProvider implements FunctionCallingProvider, ModelListProvider {
    
    private static final Gson gson = new Gson();
    private static final MediaType JSON = MediaType.get("application/json");
    
    private static final String CODEX_API_BASE_URL = "https://chatgpt.com/backend-api/codex";
    private static final String CODEX_RESPONSES_ENDPOINT = "responses";
    private static final String CODEX_MODELS_ENDPOINT = "models";
    private static final String CODEX_MODELS_CLIENT_VERSION = "0.116.0";
    
    // Default model
    private static final String DEFAULT_MODEL = "gpt-5.1-codex";
    
    private final OpenAIOAuthTokenManager tokenManager;
    private volatile boolean isCancelled = false;
    
    /**
     * Creates a new OpenAI OAuth provider.
     * 
     * @param name Provider name
     * @param model Model to use (user-specified, API will validate)
     * @param maxTokens Maximum tokens
     * @param url Ignored (uses fixed Codex endpoint)
     * @param key OAuth credentials as JSON, or empty for unauthenticated
     * @param disableTlsVerification TLS verification setting
     * @param timeout Timeout in seconds
     */
    public OpenAIOAuthProvider(String name, String model, Integer maxTokens, String url,
                               String key, boolean disableTlsVerification, boolean bypassProxy, Integer timeout) {
        super(name, ProviderType.OPENAI_OAUTH, 
              model != null && !model.isEmpty() ? model : DEFAULT_MODEL,
              maxTokens, url != null && !url.isEmpty() ? url : CODEX_API_BASE_URL + "/" + CODEX_RESPONSES_ENDPOINT, key,
              disableTlsVerification, bypassProxy, timeout);
        
        // Initialize token manager with credentials from key field
        this.tokenManager = new OpenAIOAuthTokenManager(key);
        
        Msg.info(this, "OpenAI OAuth provider initialized with model: " + this.model);
    }
    
    /**
     * Gets the OAuth token manager for authentication operations.
     */
    public OpenAIOAuthTokenManager getTokenManager() {
        return tokenManager;
    }
    
    /**
     * Checks if the provider is authenticated.
     */
    public boolean isAuthenticated() {
        return tokenManager.isAuthenticated();
    }
    
    /**
     * Gets updated credentials JSON for storage.
     */
    public String getCredentialsJson() {
        return tokenManager.toJson();
    }
    
    @Override
    protected OkHttpClient buildClient() {
        try {
            OkHttpClient.Builder builder = configureClientBuilder(new OkHttpClient.Builder())
                .connectTimeout(super.timeout)
                .readTimeout(super.timeout)
                .writeTimeout(super.timeout)
                .retryOnConnectionFailure(true);
            
            if (disableTlsVerification) {
                TrustManager[] trustAllCerts = new TrustManager[]{
                    new X509TrustManager() {
                        @Override
                        public void checkClientTrusted(java.security.cert.X509Certificate[] chain, String authType) {}
                        @Override
                        public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType) {}
                        @Override
                        public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                            return new java.security.cert.X509Certificate[]{};
                        }
                    }
                };
                
                SSLContext sslContext = SSLContext.getInstance("TLS");
                sslContext.init(null, trustAllCerts, new java.security.SecureRandom());
                builder.sslSocketFactory(sslContext.getSocketFactory(), (X509TrustManager) trustAllCerts[0])
                       .hostnameVerifier((hostname, session) -> true);
            }
            
            return builder.build();
        } catch (Exception e) {
            throw new RuntimeException("Failed to build HTTP client", e);
        }
    }
    
    // =========================================================================
    // Request Headers
    // =========================================================================
    
    /**
     * Gets headers for Codex API requests.
     * CRITICAL: These headers must match what the official Codex CLI sends.
     */
    private Headers.Builder getCodexHeaders() throws IOException {
        String accessToken = tokenManager.getValidAccessToken();
        persistCredentialsIfUpdated();
        
        // Match Python client header names exactly (lowercase)
        Headers.Builder headers = new Headers.Builder()
            .add("Content-Type", "application/json")
            .add("Authorization", "Bearer " + accessToken)
            .add("originator", "codex_cli_rs")
            .add("OpenAI-Beta", "responses=experimental")
            .add("accept", "text/event-stream");  // lowercase to match Python
        
        // Add account ID header (lowercase)
        String accountId = tokenManager.getAccountId();
        if (accountId != null && !accountId.isEmpty()) {
            headers.add("chatgpt-account-id", accountId);
        }
        
        return headers;
    }

    private Headers getModelDiscoveryHeaders() throws IOException {
        String accessToken = tokenManager.getValidAccessToken();
        persistCredentialsIfUpdated();

        Headers.Builder headers = new Headers.Builder()
            .add("Authorization", "Bearer " + accessToken)
            .add("Accept", "application/json");

        String accountId = tokenManager.getAccountId();
        if (accountId != null && !accountId.isEmpty()) {
            headers.add("ChatGPT-Account-ID", accountId);
        }

        return headers.build();
    }

    private void persistCredentialsIfUpdated() {
        String credentialsJson = getCredentialsJson();
        if (credentialsJson == null || credentialsJson.isBlank() || credentialsJson.equals(this.key)) {
            return;
        }

        if (APIProviderConfigStore.updateProviderKey(this.name, credentialsJson)) {
            this.key = credentialsJson;
        }
    }

    private JsonObject parseModelDiscoveryPayload(String responseBody) throws APIProviderException {
        if (responseBody == null) {
            throw new APIProviderException(APIProviderException.ErrorCategory.SERVICE_ERROR,
                name, "getAvailableModels", "Model discovery returned an empty response.");
        }

        String trimmed = responseBody.trim();
        if (trimmed.isEmpty()) {
            throw new APIProviderException(APIProviderException.ErrorCategory.SERVICE_ERROR,
                name, "getAvailableModels", "Model discovery returned an empty response.");
        }

        // Some backends prepend non-JSON guards or whitespace before the actual payload.
        int objectStart = trimmed.indexOf('{');
        int arrayStart = trimmed.indexOf('[');
        int start = -1;
        if (objectStart >= 0 && arrayStart >= 0) {
            start = Math.min(objectStart, arrayStart);
        } else if (objectStart >= 0) {
            start = objectStart;
        } else if (arrayStart >= 0) {
            start = arrayStart;
        }
        if (start > 0) {
            trimmed = trimmed.substring(start);
        }

        try {
            JsonReader reader = new JsonReader(new StringReader(trimmed));
            reader.setLenient(true);
            JsonElement parsed = JsonParser.parseReader(reader);

            if (parsed.isJsonObject()) {
                return parsed.getAsJsonObject();
            }

            if (parsed.isJsonPrimitive() && parsed.getAsJsonPrimitive().isString()) {
                String nested = parsed.getAsString();
                JsonReader nestedReader = new JsonReader(new StringReader(nested));
                nestedReader.setLenient(true);
                JsonElement nestedParsed = JsonParser.parseReader(nestedReader);
                if (nestedParsed.isJsonObject()) {
                    return nestedParsed.getAsJsonObject();
                }
            }
        } catch (Exception e) {
            throw new APIProviderException(APIProviderException.ErrorCategory.SERVICE_ERROR,
                name, "getAvailableModels",
                "Failed to parse model discovery response: " + e.getMessage());
        }

        throw new APIProviderException(APIProviderException.ErrorCategory.SERVICE_ERROR,
            name, "getAvailableModels",
            "Model discovery returned an unexpected payload.");
    }

    private String getApiBaseUrl() {
        String configuredUrl = this.url != null ? this.url.trim() : "";
        if (configuredUrl.isEmpty()) {
            return CODEX_API_BASE_URL;
        }

        String normalized = configuredUrl.endsWith("/") ? configuredUrl.substring(0, configuredUrl.length() - 1) : configuredUrl;
        if ("https://chatgpt.com".equalsIgnoreCase(normalized)
                || "http://chatgpt.com".equalsIgnoreCase(normalized)
                || "https://www.chatgpt.com".equalsIgnoreCase(normalized)
                || "http://www.chatgpt.com".equalsIgnoreCase(normalized)) {
            return CODEX_API_BASE_URL;
        }
        if (normalized.endsWith("/" + CODEX_RESPONSES_ENDPOINT)) {
            return normalized.substring(0, normalized.length() - (CODEX_RESPONSES_ENDPOINT.length() + 1));
        }
        if (normalized.endsWith("/" + CODEX_MODELS_ENDPOINT)) {
            return normalized.substring(0, normalized.length() - (CODEX_MODELS_ENDPOINT.length() + 1));
        }
        return normalized;
    }

    private String getResponsesEndpoint() {
        return getApiBaseUrl() + "/" + CODEX_RESPONSES_ENDPOINT;
    }

    private String getModelsEndpoint() {
        return getApiBaseUrl() + "/" + CODEX_MODELS_ENDPOINT + "?client_version=" + CODEX_MODELS_CLIENT_VERSION;
    }
    
    // =========================================================================
    // Message Translation - OpenAI Responses API Format
    // =========================================================================
    
    /**
     * Translates ChatMessage list to OpenAI Responses API input format.
     * Matches the BinAssist Codex provider payload shape exactly.
     */
    private JsonArray translateMessagesToInput(List<ChatMessage> messages) {
        JsonArray inputItems = new JsonArray();

        if (messages == null) {
            return inputItems;
        }

        for (ChatMessage message : messages) {
            if (message == null || message.getRole() == null) {
                continue;
            }

            String role = message.getRole();
            String content = message.getContent();

            if (ChatMessage.ChatMessageRole.SYSTEM.equals(role)) {
                if (content == null || content.isEmpty()) {
                    continue;
                }
                JsonObject item = new JsonObject();
                item.addProperty("role", "developer");
                JsonArray contentArray = new JsonArray();
                JsonObject textContent = new JsonObject();
                textContent.addProperty("type", "input_text");
                textContent.addProperty("text", content);
                contentArray.add(textContent);
                item.add("content", contentArray);
                inputItems.add(item);
                continue;
            }

            if (ChatMessage.ChatMessageRole.USER.equals(role)) {
                if (content == null || content.isEmpty()) {
                    continue;
                }
                JsonObject item = new JsonObject();
                item.addProperty("role", "user");
                JsonArray contentArray = new JsonArray();
                JsonObject textContent = new JsonObject();
                textContent.addProperty("type", "input_text");
                textContent.addProperty("text", content);
                contentArray.add(textContent);
                item.add("content", contentArray);
                inputItems.add(item);
                continue;
            }

            if (ChatMessage.ChatMessageRole.ASSISTANT.equals(role)) {
                JsonArray toolCalls = message.getToolCalls();
                if (toolCalls != null && toolCalls.size() > 0) {
                    for (JsonElement toolCallElement : toolCalls) {
                        if (!toolCallElement.isJsonObject()) {
                            continue;
                        }
                        JsonObject toolCall = toolCallElement.getAsJsonObject();
                        JsonObject function = toolCall.has("function") && toolCall.get("function").isJsonObject()
                            ? toolCall.getAsJsonObject("function")
                            : null;

                        String callId = null;
                        if (toolCall.has("id") && !toolCall.get("id").isJsonNull()) {
                            try {
                                callId = toolCall.get("id").getAsString();
                            } catch (Exception e) {
                                // id exists but isn't a string primitive
                            }
                        }
                        if (callId == null && toolCall.has("call_id") && !toolCall.get("call_id").isJsonNull()) {
                            try {
                                callId = toolCall.get("call_id").getAsString();
                            } catch (Exception e) {
                                // call_id exists but isn't a string primitive
                            }
                        }

                        String name = null;
                        if (function != null && function.has("name")) {
                            name = function.get("name").getAsString();
                        } else if (toolCall.has("name")) {
                            name = toolCall.get("name").getAsString();
                        }

                        String arguments = null;
                        JsonElement argumentsElement = null;
                        if (function != null && function.has("arguments")) {
                            argumentsElement = function.get("arguments");
                        } else if (toolCall.has("arguments")) {
                            argumentsElement = toolCall.get("arguments");
                        }
                        if (argumentsElement != null && !argumentsElement.isJsonNull()) {
                            if (argumentsElement.isJsonPrimitive()) {
                                arguments = argumentsElement.getAsString();
                            } else {
                                arguments = gson.toJson(argumentsElement);
                            }
                        }

                        JsonObject item = new JsonObject();
                        item.addProperty("type", "function_call");
                        if (callId != null && !callId.isEmpty()) {
                            item.addProperty("call_id", callId);
                        }
                        if (name != null && !name.isEmpty()) {
                            item.addProperty("name", name);
                        }
                        if (arguments != null && !arguments.isEmpty()) {
                            item.addProperty("arguments", arguments);
                        }
                        inputItems.add(item);
                    }
                }

                if (content != null && !content.isEmpty()) {
                    JsonObject item = new JsonObject();
                    item.addProperty("role", "assistant");
                    JsonArray contentArray = new JsonArray();
                    JsonObject textContent = new JsonObject();
                    textContent.addProperty("type", "output_text");
                    textContent.addProperty("text", content);
                    contentArray.add(textContent);
                    item.add("content", contentArray);
                    inputItems.add(item);
                }
                continue;
            }

            if (ChatMessage.ChatMessageRole.TOOL.equals(role) || ChatMessage.ChatMessageRole.FUNCTION.equals(role)) {
                // Always emit tool results - dropping them creates orphaned function_call items
                // which causes API 400 errors. Use empty string if content is null.
                String outputContent = (content != null && !content.isEmpty()) ? content : "";
                JsonObject item = new JsonObject();
                item.addProperty("type", "function_call_output");
                if (message.getToolCallId() != null && !message.getToolCallId().isEmpty()) {
                    item.addProperty("call_id", message.getToolCallId());
                }
                item.addProperty("output", outputContent);
                inputItems.add(item);
            }
        }

        return inputItems;
    }
    
    /**
     * Translates tool definitions to Responses API format.
     */
    private JsonArray translateToolsToFormat(List<Map<String, Object>> tools) {
        JsonArray responsesTools = new JsonArray();
        
        if (tools == null || tools.isEmpty()) {
            return responsesTools;
        }
        
        for (Map<String, Object> tool : tools) {
            if (!"function".equals(tool.get("type"))) {
                continue;
            }
            
            @SuppressWarnings("unchecked")
            Map<String, Object> function = (Map<String, Object>) tool.get("function");
            if (function == null) continue;
            
            JsonObject responsesTool = new JsonObject();
            responsesTool.addProperty("type", "function");
            responsesTool.addProperty("name", (String) function.get("name"));
            responsesTool.addProperty("description", (String) function.get("description"));
            
            @SuppressWarnings("unchecked")
            Map<String, Object> parameters = (Map<String, Object>) function.get("parameters");
            if (parameters != null) {
                responsesTool.add("parameters", gson.toJsonTree(parameters));
            }
            
            if (function.containsKey("strict")) {
                responsesTool.addProperty("strict", (Boolean) function.get("strict"));
            }
            
            responsesTools.add(responsesTool);
        }
        
        return responsesTools;
    }
    
    // =========================================================================
    // Response Parsing
    // =========================================================================
    
    /**
     * Parses response content from Responses API format.
     * Returns a ParsedResponse containing text, tool calls, and finish reason.
     */
    private ParsedResponse parseResponseContent(JsonObject responseData) {
        StringBuilder textContent = new StringBuilder();
        JsonArray toolCalls = new JsonArray();
        String finishReason = "stop";
        
        JsonArray output = responseData.has("output") ? responseData.getAsJsonArray("output") : new JsonArray();
        
        for (JsonElement itemElement : output) {
            JsonObject item = itemElement.getAsJsonObject();
            String itemType = item.has("type") ? item.get("type").getAsString() : "";
            
            if ("message".equals(itemType)) {
                // Extract text content from message
                JsonArray content = item.has("content") ? item.getAsJsonArray("content") : new JsonArray();
                for (JsonElement partElement : content) {
                    JsonObject part = partElement.getAsJsonObject();
                    String partType = part.has("type") ? part.get("type").getAsString() : "";
                    if ("output_text".equals(partType) || "text".equals(partType)) {
                        if (part.has("text")) {
                            textContent.append(part.get("text").getAsString());
                        }
                    }
                }
            } else if ("function_call".equals(itemType)) {
                // Parse function call into OpenAI format
                JsonObject toolCall = new JsonObject();
                toolCall.addProperty("id", item.has("call_id") ? item.get("call_id").getAsString() 
                                                               : item.get("id").getAsString());
                toolCall.addProperty("type", "function");
                
                JsonObject function = new JsonObject();
                function.addProperty("name", item.get("name").getAsString());
                JsonElement arguments = item.get("arguments");
                if (arguments != null && !arguments.isJsonNull()) {
                    if (arguments.isJsonPrimitive() && arguments.getAsJsonPrimitive().isString()) {
                        function.addProperty("arguments", arguments.getAsString());
                    } else {
                        function.addProperty("arguments", gson.toJson(arguments));
                    }
                } else {
                    function.addProperty("arguments", "{}");
                }
                toolCall.add("function", function);
                
                toolCalls.add(toolCall);
                finishReason = "tool_calls";
            }
        }
        
        // Check status for finish reason
        if (responseData.has("status")) {
            String status = responseData.get("status").getAsString();
            if ("incomplete".equals(status)) {
                if (responseData.has("incomplete_details")) {
                    JsonObject details = responseData.getAsJsonObject("incomplete_details");
                    if (details.has("reason")) {
                        finishReason = details.get("reason").getAsString();
                    }
                } else {
                    finishReason = "length";
                }
            }
        }
        
        return new ParsedResponse(textContent.toString(), toolCalls, finishReason);
    }
    
    private record ParsedResponse(String textContent, JsonArray toolCalls, String finishReason) {}
    
    // =========================================================================
    // Chat Completion - Streaming Required
    // =========================================================================
    
    @Override
    public String createChatCompletion(List<ChatMessage> messages) throws APIProviderException {
        if (!isAuthenticated()) {
            throw new AuthenticationException(name, "createChatCompletion", 401, null,
                "Not authenticated. Please authenticate via Settings > Edit Provider > Authenticate.");
        }
        
        try {
            // Build payload - Codex requires stream=true, we collect the response
            JsonObject payload = buildRequestPayload(messages, null, ToolChoiceMode.AUTO);
            Headers headers = getCodexHeaders().build();
            
            Request request = new Request.Builder()
                .url(getResponsesEndpoint())
                .post(buildJsonRequestBody(payload))
                .headers(headers)
                .build();
            
            try (Response response = executeWithRetry(request, "createChatCompletion")) {
                // Collect streaming response (API requires stream=true)
                JsonObject responseData = collectStreamingResponse(response);
                ParsedResponse parsed = parseResponseContent(responseData);
                
                return parsed.textContent();
            }
        } catch (IOException e) {
            throw handleNetworkError(e, "createChatCompletion");
        }
    }
    
    @Override
    public void streamChatCompletion(List<ChatMessage> messages, LlmResponseHandler handler) 
            throws APIProviderException {
        if (!isAuthenticated()) {
            throw new AuthenticationException(name, "streamChatCompletion", 401, null,
                "Not authenticated. Please authenticate via Settings > Edit Provider > Authenticate.");
        }
        
        isCancelled = false;
        
        try {
            JsonObject payload = buildRequestPayload(messages, null, ToolChoiceMode.AUTO);
            Headers headers = getCodexHeaders().build();
            
            Request request = new Request.Builder()
                .url(getResponsesEndpoint())
                .post(buildJsonRequestBody(payload))
                .headers(headers)
                .build();
            
            client.newCall(request).enqueue(new Callback() {
                private boolean isFirst = true;
                private StringBuilder contentBuilder = new StringBuilder();
                
                @Override
                public void onFailure(Call call, IOException e) {
                    handler.onError(handleNetworkError(e, "streamChatCompletion"));
                }
                
                @Override
                public void onResponse(Call call, Response response) throws IOException {
                    try (ResponseBody responseBody = response.body()) {
                        if (response.code() == 401) {
                            handler.onError(new AuthenticationException(name, "streamChatCompletion", 
                                401, null, "Authentication failed. Please re-authenticate."));
                            return;
                        }
                        if (response.code() == 429) {
                            handler.onError(new RateLimitException(name, "streamChatCompletion", null, null));
                            return;
                        }
                        if (!response.isSuccessful()) {
                            String errorBody = responseBody != null ? responseBody.string() : "";
                            handler.onError(new APIProviderException(APIProviderException.ErrorCategory.SERVICE_ERROR,
                                name, "streamChatCompletion", 
                                "API error " + response.code() + ": " + errorBody));
                            return;
                        }
                        
                        BufferedSource source = responseBody.source();
                        while (!source.exhausted() && !isCancelled && handler.shouldContinue()) {
                            String line = source.readUtf8Line();
                            if (line == null || line.isEmpty()) continue;
                            
                            if (line.startsWith("data: ")) {
                                String data = line.substring(6).trim();
                                
                                if ("[DONE]".equals(data)) {
                                    handler.onComplete(contentBuilder.toString());
                                    return;
                                }
                                
                                try {
                                    JsonObject event = gson.fromJson(data, JsonObject.class);
                                    String eventType = event.has("type") ? event.get("type").getAsString() : "";
                                    
                                    // Handle text delta
                                    if ("response.output_text.delta".equals(eventType)) {
                                        String deltaText = event.has("delta") ? event.get("delta").getAsString() : "";
                                        if (!deltaText.isEmpty()) {
                                            if (isFirst) {
                                                handler.onStart();
                                                isFirst = false;
                                            }
                                            contentBuilder.append(deltaText);
                                            handler.onUpdate(deltaText);
                                        }
                                    }
                                    // Handle completed response
                                    else if ("response.completed".equals(eventType) || "response.done".equals(eventType)) {
                                        handler.onComplete(contentBuilder.toString());
                                        return;
                                    }
                                } catch (Exception e) {
                                    // Skip malformed events
                                    Msg.debug(OpenAIOAuthProvider.this, "Skipping malformed SSE event: " + e.getMessage());
                                }
                            }
                        }
                        
                        if (isCancelled) {
                            handler.onError(new APIProviderException(APIProviderException.ErrorCategory.CANCELLED,
                                name, "streamChatCompletion", "Request cancelled"));
                        } else {
                            handler.onComplete(contentBuilder.toString());
                        }
                    }
                }
            });
        } catch (IOException e) {
            handler.onError(handleNetworkError(e, "streamChatCompletion"));
        }
    }
    
    /**
     * Collects a streaming SSE response into a complete response object.
     * The Codex API requires stream=true, so we must parse SSE events.
     */
    private JsonObject collectStreamingResponse(Response response) throws IOException {
        JsonObject finalResponse = new JsonObject();
        JsonArray outputItems = new JsonArray();
        int outputItemCount = 0;
        
        try (ResponseBody body = response.body()) {
            if (body == null) return finalResponse;
            
            BufferedSource source = body.source();
            while (!source.exhausted()) {
                String line = source.readUtf8Line();
                if (line == null || line.isEmpty()) continue;
                
                if (line.startsWith("data: ")) {
                    String data = line.substring(6).trim();
                    
                    if ("[DONE]".equals(data)) {
                        break;
                    }
                    
                    try {
                        JsonObject event = gson.fromJson(data, JsonObject.class);
                        String eventType = event.has("type") ? event.get("type").getAsString() : "";

                        if ("response.output_item.done".equals(eventType) && event.has("item")) {
                            outputItems.add(event.get("item").deepCopy());
                            outputItemCount++;
                        } else if ("response.completed".equals(eventType) || "response.done".equals(eventType)) {
                            if (event.has("response")) {
                                finalResponse = event.getAsJsonObject("response");
                            }
                        } else if ("response.incomplete".equals(eventType) && event.has("response")) {
                            finalResponse = event.getAsJsonObject("response");
                        } else if ("response.failed".equals(eventType) && event.has("response")) {
                            finalResponse = event.getAsJsonObject("response");
                        }
                    } catch (Exception e) {
                        Msg.debug(this, "Skipping malformed SSE event while collecting response: " + e.getMessage());
                    }
                }
            }
        }

        if (!outputItems.isEmpty()) {
            finalResponse.add("output", outputItems);
        }
        if (!finalResponse.has("status")) {
            finalResponse.addProperty("status", outputItemCount > 0 ? "completed" : "unknown");
        }
        Msg.info(this, "Collected OAuth Responses SSE stream: output_items=" + outputItemCount
            + ", status=" + (finalResponse.has("status") ? finalResponse.get("status").getAsString() : "missing"));
        
        return finalResponse;
    }
    
    // =========================================================================
    // Function Calling
    // =========================================================================
    
    @Override
    public String createChatCompletionWithFunctions(List<ChatMessage> messages,
                                                    List<Map<String, Object>> functions) 
            throws APIProviderException {
        return createChatCompletionWithFunctions(messages, functions, ToolChoiceMode.AUTO);
    }

    @Override
    public String createChatCompletionWithFunctions(List<ChatMessage> messages,
                                                    List<Map<String, Object>> functions,
                                                    ToolChoiceMode toolChoiceMode)
            throws APIProviderException {
        if (!isAuthenticated()) {
            throw new AuthenticationException(name, "createChatCompletionWithFunctions", 401, null,
                "Not authenticated. Please authenticate via Settings > Edit Provider > Authenticate.");
        }
        
        try {
            JsonObject payload = buildRequestPayload(messages, functions, toolChoiceMode);
            Msg.info(this, "Submitting OAuth Responses function request: input_items="
                + payload.getAsJsonArray("input").size() + ", tools="
                + (functions != null ? functions.size() : 0) + ", model=" + this.model);
            Headers headers = getCodexHeaders().build();
            
            Request request = new Request.Builder()
                .url(getResponsesEndpoint())
                .post(buildJsonRequestBody(payload))
                .headers(headers)
                .build();
            
            try (Response response = executeWithRetry(request, "createChatCompletionWithFunctions")) {
                JsonObject responseData = collectStreamingResponse(response);
                ParsedResponse parsed = parseResponseContent(responseData);
                
                // Return tool calls in OpenAI format
                JsonObject result = new JsonObject();
                result.add("tool_calls", parsed.toolCalls());
                return gson.toJson(result);
            }
        } catch (IOException e) {
            throw handleNetworkError(e, "createChatCompletionWithFunctions");
        }
    }
    
    @Override
    public String createChatCompletionWithFunctionsFullResponse(List<ChatMessage> messages,
                                                                List<Map<String, Object>> functions)
            throws APIProviderException {
        return createChatCompletionWithFunctionsFullResponse(messages, functions, ToolChoiceMode.AUTO);
    }

    @Override
    public String createChatCompletionWithFunctionsFullResponse(List<ChatMessage> messages,
                                                                List<Map<String, Object>> functions,
                                                                ToolChoiceMode toolChoiceMode)
            throws APIProviderException {
        if (!isAuthenticated()) {
            throw new AuthenticationException(name, "createChatCompletionWithFunctionsFullResponse", 401, null,
                "Not authenticated. Please authenticate via Settings > Edit Provider > Authenticate.");
        }
        
        try {
            JsonObject payload = buildRequestPayload(messages, functions, toolChoiceMode);
            Headers headers = getCodexHeaders().build();
            
            Request request = new Request.Builder()
                .url(getResponsesEndpoint())
                .post(buildJsonRequestBody(payload))
                .headers(headers)
                .build();
            
            try (Response response = executeWithRetry(request, "createChatCompletionWithFunctionsFullResponse")) {
                JsonObject responseData = collectStreamingResponse(response);
                ParsedResponse parsed = parseResponseContent(responseData);
                ghidra.util.Msg.info(this, "OpenAI OAuth parsed function response: finish_reason="
                    + parsed.finishReason() + ", tool_calls=" + parsed.toolCalls().size()
                    + ", text_length=" + (parsed.textContent() != null ? parsed.textContent().length() : 0));
                
                // Convert to OpenAI Chat Completions format
                JsonObject fullResponse = new JsonObject();
                JsonArray choices = new JsonArray();
                JsonObject choice = new JsonObject();
                JsonObject message = new JsonObject();
                
                message.addProperty("role", "assistant");
                
                if (!parsed.toolCalls().isEmpty()) {
                    message.add("tool_calls", parsed.toolCalls());
                    message.addProperty("content", parsed.textContent().isEmpty() ? "" : parsed.textContent());
                } else {
                    message.addProperty("content", parsed.textContent());
                }
                
                choice.add("message", message);
                choice.addProperty("finish_reason", parsed.finishReason());
                choice.addProperty("index", 0);
                choices.add(choice);
                
                fullResponse.add("choices", choices);
                fullResponse.addProperty("id", "chatcmpl-codex-" + System.currentTimeMillis());
                fullResponse.addProperty("object", "chat.completion");
                fullResponse.addProperty("created", System.currentTimeMillis() / 1000);
                fullResponse.addProperty("model", this.model);
                
                return gson.toJson(fullResponse);
            }
        } catch (IOException e) {
            throw handleNetworkError(e, "createChatCompletionWithFunctionsFullResponse");
        }
    }
    
    // =========================================================================
    // Request Building
    // =========================================================================
    
    /**
     * Builds request payload in OpenAI Responses API format.
     * CRITICAL: Codex API requires store=false AND stream=true.
     */
    private JsonObject buildRequestPayload(List<ChatMessage> messages, List<Map<String, Object>> tools,
                                           ToolChoiceMode toolChoiceMode) {
        JsonObject payload = new JsonObject();
        payload.addProperty("model", this.model);
        JsonArray input = translateMessagesToInput(messages);
        sanitizeResponsesApiInput(input);
        payload.add("input", input);
        payload.addProperty("instructions", CodexInstructions.INSTRUCTIONS);
        payload.addProperty("store", false);
        payload.addProperty("stream", true);  // REQUIRED by Codex API
        
        // Add tools if present
        if (tools != null && !tools.isEmpty()) {
            payload.add("tools", translateToolsToFormat(tools));
            ToolChoiceMode resolvedMode = toolChoiceMode != null ? toolChoiceMode : ToolChoiceMode.AUTO;
            String toolChoice = resolvedMode.toOpenAIToolChoice(messages);
            payload.addProperty("tool_choice", toolChoice);
            payload.addProperty("parallel_tool_calls", true);
            Msg.info(this, "OAuth Responses tool_choice=" + toolChoice
                + " for " + tools.size() + " tools");
        }
        
        return payload;
    }

    /**
     * Sanitize the Responses API input array to prevent orphaned function_call items.
     * For each function_call, verifies a matching function_call_output exists.
     * If not, removes the function_call or inserts a placeholder output.
     */
    private void sanitizeResponsesApiInput(JsonArray inputItems) {
        // Collect all function_call items and their call_ids
        java.util.Map<String, Integer> functionCallIds = new java.util.LinkedHashMap<>();
        java.util.Set<String> functionCallOutputIds = new java.util.HashSet<>();

        for (int i = 0; i < inputItems.size(); i++) {
            JsonObject item = inputItems.get(i).getAsJsonObject();
            String type = null;
            if (item.has("type") && !item.get("type").isJsonNull()) {
                type = item.get("type").getAsString();
            }
            if ("function_call".equals(type)) {
                String callId = null;
                if (item.has("call_id") && !item.get("call_id").isJsonNull()) {
                    callId = item.get("call_id").getAsString();
                }
                if (callId != null && !callId.isEmpty()) {
                    functionCallIds.put(callId, i);
                }
            } else if ("function_call_output".equals(type)) {
                String callId = null;
                if (item.has("call_id") && !item.get("call_id").isJsonNull()) {
                    callId = item.get("call_id").getAsString();
                }
                if (callId != null) {
                    functionCallOutputIds.add(callId);
                }
            }
        }

        // Find orphaned function_calls (no matching output)
        for (java.util.Map.Entry<String, Integer> entry : functionCallIds.entrySet()) {
            if (!functionCallOutputIds.contains(entry.getKey())) {
                // Insert a placeholder function_call_output
                JsonObject placeholder = new JsonObject();
                placeholder.addProperty("type", "function_call_output");
                placeholder.addProperty("call_id", entry.getKey());
                placeholder.addProperty("output", "Error: Tool execution result was lost.");
                inputItems.add(placeholder);
                ghidra.util.Msg.warn(this, "Payload sanitization: inserted placeholder function_call_output for call_id=" + entry.getKey());
            }
        }
    }

    private RequestBody buildJsonRequestBody(JsonObject payload) {
        return RequestBody.create(gson.toJson(payload).getBytes(StandardCharsets.UTF_8), JSON);
    }
    
    
    // =========================================================================
    // Other Required Methods
    // =========================================================================
    
    @Override
    public List<String> getAvailableModels() throws APIProviderException {
        if (!isAuthenticated()) {
            throw new AuthenticationException(name, "getAvailableModels", 401, null,
                "Not authenticated. Please authenticate via Settings > Edit Provider > Authenticate.");
        }

        try {
            Headers headers = getModelDiscoveryHeaders();

            Request request = new Request.Builder()
                .url(getModelsEndpoint())
                .get()
                .headers(headers)
                .build();

            try (Response response = executeWithRetry(request, "getAvailableModels")) {
                String responseBody = response.body() != null ? response.body().string() : "{}";
                JsonObject responseObj = parseModelDiscoveryPayload(responseBody);
                JsonArray data = responseObj.has("models") && responseObj.get("models").isJsonArray()
                    ? responseObj.getAsJsonArray("models")
                    : new JsonArray();
                List<String> models = new ArrayList<>();

                for (JsonElement element : data) {
                    if (!element.isJsonObject()) {
                        continue;
                    }
                    JsonObject modelObj = element.getAsJsonObject();
                    if (modelObj.has("slug") && !modelObj.get("slug").isJsonNull()) {
                        models.add(modelObj.get("slug").getAsString());
                    }
                }

                models = models.stream().distinct().collect(Collectors.toList());
                if (models.isEmpty()) {
                    throw new APIProviderException(APIProviderException.ErrorCategory.SERVICE_ERROR,
                        name, "getAvailableModels", "No available models were returned by the API.");
                }
                return models;
            }
        } catch (IOException e) {
            throw handleNetworkError(e, "getAvailableModels");
        }
    }
    
    @Override
    public void getEmbeddingsAsync(String text, EmbeddingCallback callback) {
        callback.onError(new UnsupportedOperationException(
            "Embeddings are not supported by the OpenAI Codex OAuth API"));
    }
    
    public void cancelRequest() {
        isCancelled = true;
    }
}
