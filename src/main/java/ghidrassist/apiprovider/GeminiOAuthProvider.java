package ghidrassist.apiprovider;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import ghidra.util.Msg;
import ghidrassist.LlmApi.LlmResponseHandler;
import ghidrassist.apiprovider.capabilities.FunctionCallingProvider;
import ghidrassist.apiprovider.capabilities.ModelListProvider;
import ghidrassist.apiprovider.exceptions.*;
import ghidrassist.apiprovider.oauth.GeminiOAuthTokenManager;
import okhttp3.*;
import okio.BufferedSource;

import javax.net.ssl.*;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Google Gemini OAuth Provider - Routes requests through the Code Assist proxy.
 *
 * This provider uses OAuth authentication for Google Gemini CLI subscriptions.
 * All API requests go through cloudcode-pa.googleapis.com/v1internal:{action}.
 * Requests are wrapped in a Code Assist envelope and responses are unwrapped.
 * Uses native Gemini API format (contents/parts), NOT OpenAI-compatible.
 *
 * Key Features:
 * - OAuth authentication (no API key required)
 * - Automatic token refresh
 * - Native Gemini API format (contents[{role, parts[{text}]}])
 * - Code Assist proxy wrapping/unwrapping
 * - Streaming via ?alt=sse
 * - Function/tool calling support (Gemini format)
 */
public class GeminiOAuthProvider extends APIProvider implements FunctionCallingProvider, ModelListProvider {

    private static final Gson gson = new Gson();
    private static final MediaType JSON_MEDIA_TYPE = MediaType.get("application/json");

    // Code Assist proxy endpoint
    private static final String CODE_ASSIST_ENDPOINT = "https://cloudcode-pa.googleapis.com";
    private static final String CODE_ASSIST_API_VERSION = "v1internal";
    private static final String GEMINI_CLI_VERSION = "1.0.0";
    private static final List<String> CLI_VISIBLE_AUTO_MODELS = List.of("auto-gemini-3", "auto-gemini-2.5");
    private static final List<String> CLI_VISIBLE_PREVIEW_MODELS = List.of(
        "gemini-3.1-flash-lite-preview",
        "gemini-3.1-pro-preview",
        "gemini-3-pro-preview",
        "gemini-3-flash-preview"
    );
    private static final List<String> CLI_VISIBLE_STABLE_MODELS = List.of(
        "gemini-2.5-pro",
        "gemini-2.5-flash",
        "gemini-2.5-flash-lite"
    );

    // Default model
    private static final String DEFAULT_MODEL = "gemini-2.5-flash";

    // Synthetic thought signature used when the original is unavailable.
    // Matches the Gemini CLI's skip_thought_signature_validator behavior.
    private static final String SYNTHETIC_THOUGHT_SIGNATURE = "skip_thought_signature_validator";

    // Rate limiting: minimum interval between API requests (milliseconds)
    private static final long MIN_REQUEST_INTERVAL_MS = 2000;
    // Maximum backoff for 429 retries (milliseconds)
    private static final long MAX_RATE_LIMIT_BACKOFF_MS = 60_000;
    // Initial backoff for 429 retries (milliseconds)
    private static final long INITIAL_RATE_LIMIT_BACKOFF_MS = 5_000;

    private final GeminiOAuthTokenManager tokenManager;
    private final String sessionId;
    private volatile boolean isCancelled = false;
    private volatile long lastRequestTimeMs = 0;

    public GeminiOAuthProvider(String name, String model, Integer maxTokens, String url,
                               String key, boolean disableTlsVerification, boolean bypassProxy, Integer timeout) {
        super(name, ProviderType.GEMINI_OAUTH,
              model != null && !model.isEmpty() ? model : DEFAULT_MODEL,
              maxTokens, url != null && !url.isEmpty() ? url : CODE_ASSIST_ENDPOINT, key,
              disableTlsVerification, bypassProxy, timeout);

        this.tokenManager = new GeminiOAuthTokenManager(key);
        this.sessionId = generateSessionId();

        Msg.info(this, "Gemini OAuth provider initialized with model: " + this.model);
    }

    public GeminiOAuthTokenManager getTokenManager() {
        return tokenManager;
    }

    public boolean isAuthenticated() {
        return tokenManager.isAuthenticated();
    }

    public String getCredentialsJson() {
        return tokenManager.toJson();
    }

    @Override
    public void prepareForConcurrentRequests() throws APIProviderException {
        try {
            tokenManager.getValidAccessToken();
            persistCredentialsIfUpdated();
        } catch (IOException e) {
            throw handleNetworkError(e, "prepareForConcurrentRequests");
        }
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

    private Headers.Builder getGeminiHeaders() throws IOException {
        String accessToken = tokenManager.getValidAccessToken();
        persistCredentialsIfUpdated();

        return new Headers.Builder()
            .add("Authorization", "Bearer " + accessToken)
            .add("Content-Type", "application/json")
            .add("User-Agent", buildUserAgent());
    }

    private String buildUserAgent() {
        String os = System.getProperty("os.name", "").toLowerCase();
        String platform;
        if (os.contains("linux")) platform = "linux";
        else if (os.contains("mac") || os.contains("darwin")) platform = "darwin";
        else if (os.contains("win")) platform = "win32";
        else platform = os;

        String arch = System.getProperty("os.arch", "");
        if ("amd64".equals(arch) || "x86_64".equals(arch)) arch = "x86_64";
        else if ("aarch64".equals(arch) || "arm64".equals(arch)) arch = "arm64";

        return "GeminiCLI/" + GEMINI_CLI_VERSION + "/" + this.model + " (" + platform + "; " + arch + ")";
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

    private String getMethodUrl(String method) {
        String baseUrl = this.url != null && !this.url.isBlank() ? this.url.trim() : CODE_ASSIST_ENDPOINT;
        while (baseUrl.endsWith("/")) {
            baseUrl = baseUrl.substring(0, baseUrl.length() - 1);
        }
        if (baseUrl.endsWith("/" + CODE_ASSIST_API_VERSION)) {
            return baseUrl + ":" + method;
        }
        return baseUrl + "/" + CODE_ASSIST_API_VERSION + ":" + method;
    }

    private boolean hasPreviewAccess(JsonArray buckets) {
        for (JsonElement bucketElement : buckets) {
            if (!bucketElement.isJsonObject()) {
                continue;
            }
            JsonObject bucket = bucketElement.getAsJsonObject();
            if (!bucket.has("modelId") || bucket.get("modelId").isJsonNull()) {
                continue;
            }
            String modelId = bucket.get("modelId").getAsString().toLowerCase();
            if (modelId.contains("preview") || modelId.contains("gemini-3")) {
                return true;
            }
        }
        return false;
    }

    private List<String> buildVisibleCatalog(boolean includePreview) {
        List<String> models = new ArrayList<>(CLI_VISIBLE_AUTO_MODELS);
        models.addAll(CLI_VISIBLE_STABLE_MODELS);
        if (includePreview) {
            models.addAll(CLI_VISIBLE_PREVIEW_MODELS);
        }
        return models.stream().distinct().collect(Collectors.toList());
    }

    // =========================================================================
    // Rate Limiting
    // =========================================================================

    /**
     * Enforces minimum interval between API requests.
     * Blocks until at least MIN_REQUEST_INTERVAL_MS has elapsed since the last request.
     */
    private synchronized void enforceRateLimit() {
        long now = System.currentTimeMillis();
        long elapsed = now - lastRequestTimeMs;
        if (elapsed < MIN_REQUEST_INTERVAL_MS && lastRequestTimeMs > 0) {
            long sleepMs = MIN_REQUEST_INTERVAL_MS - elapsed;
            Msg.debug(this, "Rate limiting: waiting " + sleepMs + "ms before next request");
            try {
                Thread.sleep(sleepMs);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        lastRequestTimeMs = System.currentTimeMillis();
    }

    /**
     * Executes an HTTP request with automatic retry on 429 rate limit responses.
     * Retries indefinitely with backoff capped at MAX_RATE_LIMIT_BACKOFF_MS.
     * Returns the successful Response (caller is responsible for closing it).
     */
    private Response executeWithRateLimitRetry(Request request, String operation) throws IOException, APIProviderException {
        long backoffMs = INITIAL_RATE_LIMIT_BACKOFF_MS;
        int attempt = 0;

        while (true) {
            if (isCancelled) {
                throw new APIProviderException(APIProviderException.ErrorCategory.CANCELLED,
                    name, operation, "Request cancelled");
            }

            enforceRateLimit();
            Response response = client.newCall(request).execute();

            if (response.code() != 429) {
                return response;
            }

            // 429 - rate limited. Close this response and retry.
            response.close();
            attempt++;

            // Check for Retry-After header
            String retryAfter = response.header("Retry-After");
            long waitMs = backoffMs;
            if (retryAfter != null) {
                try {
                    waitMs = Long.parseLong(retryAfter) * 1000;
                } catch (NumberFormatException e) {
                    // ignore, use computed backoff
                }
            }
            waitMs = Math.min(waitMs, MAX_RATE_LIMIT_BACKOFF_MS);

            Msg.info(this, String.format("Rate limited (429) on %s, attempt %d. Waiting %dms...",
                operation, attempt, waitMs));

            try {
                Thread.sleep(waitMs);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException("Interrupted during rate limit backoff", e);
            }

            // Increase backoff for next time, capped
            backoffMs = Math.min(backoffMs * 2, MAX_RATE_LIMIT_BACKOFF_MS);
        }
    }

    /**
     * Enqueues a streaming HTTP request with automatic retry on 429 rate limit responses.
     * Retries indefinitely with backoff capped at MAX_RATE_LIMIT_BACKOFF_MS.
     */
    private void enqueueStreamingWithRetry(Request request, LlmResponseHandler handler) {
        enforceRateLimit();
        client.newCall(request).enqueue(new Callback() {
            private boolean isFirst = true;
            private StringBuilder contentBuilder = new StringBuilder();
            private long backoffMs = INITIAL_RATE_LIMIT_BACKOFF_MS;
            private int rateLimitAttempt = 0;

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
                        // Rate limited - retry with backoff, never give up
                        rateLimitAttempt++;
                        String retryAfter = response.header("Retry-After");
                        long waitMs = backoffMs;
                        if (retryAfter != null) {
                            try {
                                waitMs = Long.parseLong(retryAfter) * 1000;
                            } catch (NumberFormatException e) {
                                // ignore, use computed backoff
                            }
                        }
                        waitMs = Math.min(waitMs, MAX_RATE_LIMIT_BACKOFF_MS);

                        Msg.info(GeminiOAuthProvider.this, String.format(
                            "Rate limited (429) on streaming, attempt %d. Waiting %dms...",
                            rateLimitAttempt, waitMs));

                        try {
                            Thread.sleep(waitMs);
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                            handler.onError(handleNetworkError(
                                new IOException("Interrupted during rate limit backoff", e),
                                "streamChatCompletion"));
                            return;
                        }

                        backoffMs = Math.min(backoffMs * 2, MAX_RATE_LIMIT_BACKOFF_MS);

                        // Re-enqueue the request
                        if (!isCancelled) {
                            enforceRateLimit();
                            client.newCall(request).enqueue(this);
                        }
                        return;
                    }
                    if (!response.isSuccessful()) {
                        String errorBody = responseBody != null ? responseBody.string() : "";
                        handler.onError(new APIProviderException(APIProviderException.ErrorCategory.SERVICE_ERROR,
                            name, "streamChatCompletion",
                            "API error " + response.code() + ": " + errorBody));
                        return;
                    }

                    // Parse SSE: multi-line data blocks separated by empty lines
                    BufferedSource source = responseBody.source();
                    List<String> bufferedLines = new ArrayList<>();

                    while (!source.exhausted() && !isCancelled && handler.shouldContinue()) {
                        String line = source.readUtf8Line();
                        if (line == null) break;

                        if (line.startsWith("data: ")) {
                            bufferedLines.add(line.substring(6).trim());
                        } else if (line.isEmpty() && !bufferedLines.isEmpty()) {
                            // Empty line = end of SSE block, parse buffered data
                            try {
                                String jsonStr = String.join("\n", bufferedLines);
                                JsonObject event = gson.fromJson(jsonStr, JsonObject.class);
                                JsonObject unwrapped = unwrapResponse(event);

                                // Extract text from candidates
                                JsonArray candidates = unwrapped.has("candidates")
                                    ? unwrapped.getAsJsonArray("candidates") : null;

                                if (candidates != null && candidates.size() > 0) {
                                    JsonObject firstCandidate = candidates.get(0).getAsJsonObject();
                                    if (firstCandidate.has("content") && firstCandidate.get("content").isJsonObject()) {
                                        JsonArray parts = firstCandidate.getAsJsonObject("content")
                                            .has("parts") ? firstCandidate.getAsJsonObject("content").getAsJsonArray("parts") : null;

                                        if (parts != null) {
                                            for (JsonElement partEl : parts) {
                                                JsonObject part = partEl.getAsJsonObject();
                                                if (part.has("text")) {
                                                    String text = part.get("text").getAsString();
                                                    if (!text.isEmpty()) {
                                                        if (isFirst) {
                                                            handler.onStart();
                                                            isFirst = false;
                                                        }
                                                        contentBuilder.append(text);
                                                        handler.onUpdate(text);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            } catch (Exception e) {
                                Msg.debug(GeminiOAuthProvider.this, "Skipping malformed SSE event: " + e.getMessage());
                            }
                            bufferedLines.clear();
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
    }

    // =========================================================================
    // Message Translation - Gemini Native Format
    // =========================================================================

    /**
     * Translates ChatMessage list to Gemini native format.
     * Returns a JsonObject with 'contents' and optionally 'systemInstruction'.
     */
    private JsonObject translateMessages(List<ChatMessage> messages) {
        JsonObject result = new JsonObject();
        JsonArray contents = new JsonArray();

        if (messages == null) {
            result.add("contents", contents);
            return result;
        }

        for (int i = 0; i < messages.size(); i++) {
            ChatMessage message = messages.get(i);
            if (message == null || message.getRole() == null) continue;

            String role = message.getRole();
            String content = message.getContent();

            if (ChatMessage.ChatMessageRole.SYSTEM.equals(role)) {
                // System message -> systemInstruction
                if (content != null && !content.isEmpty()) {
                    JsonObject sysInstruction = new JsonObject();
                    JsonArray parts = new JsonArray();
                    JsonObject textPart = new JsonObject();
                    textPart.addProperty("text", content);
                    parts.add(textPart);
                    sysInstruction.add("parts", parts);
                    result.add("systemInstruction", sysInstruction);
                }
                continue;
            }

            if (ChatMessage.ChatMessageRole.USER.equals(role)) {
                if (content != null && !content.isEmpty()) {
                    JsonObject entry = new JsonObject();
                    entry.addProperty("role", "user");
                    JsonArray parts = new JsonArray();
                    JsonObject textPart = new JsonObject();
                    textPart.addProperty("text", content);
                    parts.add(textPart);
                    entry.add("parts", parts);
                    contents.add(entry);
                }
                continue;
            }

            if (ChatMessage.ChatMessageRole.ASSISTANT.equals(role)) {
                // Check for tool calls first
                com.google.gson.JsonArray toolCalls = message.getToolCalls();
                if (toolCalls != null && toolCalls.size() > 0) {
                    JsonObject entry = new JsonObject();
                    entry.addProperty("role", "model");
                    JsonArray parts = new JsonArray();

                    for (JsonElement toolCallElement : toolCalls) {
                        if (!toolCallElement.isJsonObject()) continue;
                        JsonObject toolCall = toolCallElement.getAsJsonObject();

                        JsonObject function = toolCall.has("function") && toolCall.get("function").isJsonObject()
                            ? toolCall.getAsJsonObject("function") : null;

                        String funcName = null;
                        if (function != null && function.has("name")) {
                            funcName = function.get("name").getAsString();
                        } else if (toolCall.has("name")) {
                            funcName = toolCall.get("name").getAsString();
                        }

                        JsonElement argsElement = null;
                        if (function != null && function.has("arguments")) {
                            argsElement = function.get("arguments");
                        } else if (toolCall.has("arguments")) {
                            argsElement = toolCall.get("arguments");
                        }

                        JsonObject args = new JsonObject();
                        if (argsElement != null && !argsElement.isJsonNull()) {
                            if (argsElement.isJsonObject()) {
                                args = argsElement.getAsJsonObject();
                            } else if (argsElement.isJsonPrimitive()) {
                                try {
                                    args = gson.fromJson(argsElement.getAsString(), JsonObject.class);
                                } catch (Exception e) {
                                    args.addProperty("input", argsElement.getAsString());
                                }
                            }
                        }

                        JsonObject functionCall = new JsonObject();
                        functionCall.addProperty("name", funcName != null ? funcName : "");
                        functionCall.add("args", args);

                        JsonObject fcPart = new JsonObject();
                        // Gemini API requires thoughtSignature on function call parts.
                        // Use synthetic signature when original is unavailable.
                        fcPart.addProperty("thoughtSignature", SYNTHETIC_THOUGHT_SIGNATURE);
                        fcPart.add("functionCall", functionCall);
                        parts.add(fcPart);
                    }

                    // Also add text content if present
                    if (content != null && !content.isEmpty()) {
                        JsonObject textPart = new JsonObject();
                        textPart.addProperty("text", content);
                        parts.add(textPart);
                    }

                    entry.add("parts", parts);
                    contents.add(entry);
                } else if (content != null && !content.isEmpty()) {
                    JsonObject entry = new JsonObject();
                    entry.addProperty("role", "model");
                    JsonArray parts = new JsonArray();
                    JsonObject textPart = new JsonObject();
                    textPart.addProperty("text", content);
                    parts.add(textPart);
                    entry.add("parts", parts);
                    contents.add(entry);
                }
                continue;
            }

            if (ChatMessage.ChatMessageRole.TOOL.equals(role) || ChatMessage.ChatMessageRole.FUNCTION.equals(role)) {
                // Batch all consecutive TOOL messages into a single user content block.
                // Gemini requires the number of functionResponse parts to match the
                // number of functionCall parts from the preceding model turn.
                JsonObject entry = new JsonObject();
                entry.addProperty("role", "user");
                JsonArray parts = new JsonArray();

                // Process this TOOL message and all consecutive ones
                for (; i < messages.size(); i++) {
                    ChatMessage toolMsg = messages.get(i);
                    if (toolMsg == null || toolMsg.getRole() == null) continue;
                    String toolRole = toolMsg.getRole();
                    if (!ChatMessage.ChatMessageRole.TOOL.equals(toolRole) &&
                        !ChatMessage.ChatMessageRole.FUNCTION.equals(toolRole)) {
                        // Not a TOOL message - back up so outer loop processes it
                        i--;
                        break;
                    }

                    // Always create a functionResponse part for every TOOL message.
                    // Gemini requires exactly one functionResponse for each functionCall.
                    // Skipping empty results would cause a count mismatch error.
                    String toolContent = toolMsg.getContent();
                    JsonObject funcResponse = new JsonObject();
                    String toolCallId = toolMsg.getToolCallId();
                    String funcName = lookupFunctionName(messages, toolCallId);
                    funcResponse.addProperty("name", funcName);
                    if (toolCallId != null) {
                        funcResponse.addProperty("id", toolCallId);
                    }

                    JsonObject responseContent = new JsonObject();
                    responseContent.addProperty("output",
                        (toolContent != null && !toolContent.isEmpty()) ? toolContent : "(no output)");
                    funcResponse.add("response", responseContent);

                    JsonObject frPart = new JsonObject();
                    frPart.add("functionResponse", funcResponse);
                    parts.add(frPart);
                }

                if (parts.size() > 0) {
                    entry.add("parts", parts);
                    contents.add(entry);
                }
            }
        }

        result.add("contents", contents);
        return result;
    }

    /**
     * Looks up the actual function name for a tool call ID by searching
     * prior assistant messages' tool_calls arrays.
     */
    private String lookupFunctionName(List<ChatMessage> messages, String toolCallId) {
        if (toolCallId == null || messages == null) return "function";

        for (ChatMessage msg : messages) {
            if (!ChatMessage.ChatMessageRole.ASSISTANT.equals(msg.getRole())) continue;
            JsonArray toolCalls = msg.getToolCalls();
            if (toolCalls == null) continue;

            for (JsonElement tcElement : toolCalls) {
                if (!tcElement.isJsonObject()) continue;
                JsonObject tc = tcElement.getAsJsonObject();

                // Check if this tool call matches the ID
                String id = tc.has("id") ? tc.get("id").getAsString() : null;
                if (!toolCallId.equals(id)) continue;

                // Extract function name from nested "function" object or direct "name"
                if (tc.has("function") && tc.get("function").isJsonObject()) {
                    JsonObject func = tc.getAsJsonObject("function");
                    if (func.has("name")) {
                        return func.get("name").getAsString();
                    }
                }
                if (tc.has("name")) {
                    return tc.get("name").getAsString();
                }
            }
        }
        return "function";
    }

    /**
     * Translates tool definitions to Gemini tools format.
     */
    private JsonArray translateToolsToGeminiFormat(List<Map<String, Object>> tools) {
        JsonArray geminiTools = new JsonArray();

        if (tools == null || tools.isEmpty()) return geminiTools;

        JsonArray functionDeclarations = new JsonArray();
        for (Map<String, Object> tool : tools) {
            if (!"function".equals(tool.get("type"))) continue;

            @SuppressWarnings("unchecked")
            Map<String, Object> function = (Map<String, Object>) tool.get("function");
            if (function == null) continue;

            JsonObject decl = new JsonObject();
            decl.addProperty("name", (String) function.get("name"));
            decl.addProperty("description", (String) function.get("description"));

            @SuppressWarnings("unchecked")
            Map<String, Object> parameters = (Map<String, Object>) function.get("parameters");
            if (parameters != null) {
                // Use parametersJsonSchema (standard JSON Schema with lowercase types)
                // instead of parameters (Gemini Schema with uppercase types like "OBJECT", "STRING")
                decl.add("parametersJsonSchema", gson.toJsonTree(parameters));
            }

            functionDeclarations.add(decl);
        }

        if (functionDeclarations.size() > 0) {
            JsonObject toolObj = new JsonObject();
            toolObj.add("functionDeclarations", functionDeclarations);
            geminiTools.add(toolObj);
        }

        return geminiTools;
    }

    // =========================================================================
    // Request Wrapping / Response Unwrapping
    // =========================================================================

    /**
     * Wraps a Gemini API request in the Code Assist envelope.
     */
    private JsonObject wrapRequest(JsonObject requestPayload) {
        requestPayload.addProperty("session_id", sessionId);

        String projectId = tokenManager.getProjectId();

        JsonObject envelope = new JsonObject();
        envelope.addProperty("model", this.model);
        envelope.addProperty("project", projectId != null ? projectId : "");
        envelope.addProperty("user_prompt_id", UUID.randomUUID().toString());
        envelope.add("request", requestPayload);

        return envelope;
    }

    /**
     * Unwraps a Code Assist response envelope.
     * The proxy returns {response: {...actual data...}, traceId: "..."}.
     */
    private JsonObject unwrapResponse(JsonObject data) {
        if (data.has("response") && data.get("response").isJsonObject()) {
            return data.getAsJsonObject("response");
        }
        return data;
    }

    // =========================================================================
    // Response Parsing
    // =========================================================================

    private ParsedResponse parseGeminiResponse(JsonObject responseData) {
        StringBuilder textContent = new StringBuilder();
        JsonArray toolCalls = new JsonArray();
        String finishReason = "stop";

        JsonArray candidates = responseData.has("candidates")
            ? responseData.getAsJsonArray("candidates") : new JsonArray();

        if (candidates.size() > 0) {
            JsonObject firstCandidate = candidates.get(0).getAsJsonObject();

            if (firstCandidate.has("content") && firstCandidate.get("content").isJsonObject()) {
                JsonObject content = firstCandidate.getAsJsonObject("content");
                JsonArray parts = content.has("parts") ? content.getAsJsonArray("parts") : new JsonArray();

                for (JsonElement partElement : parts) {
                    JsonObject part = partElement.getAsJsonObject();

                    // Text content
                    if (part.has("text")) {
                        textContent.append(part.get("text").getAsString());
                    }

                    // Function call
                    if (part.has("functionCall") && part.get("functionCall").isJsonObject()) {
                        JsonObject funcCall = part.getAsJsonObject("functionCall");

                        // Convert to OpenAI format for compatibility with ActionParser
                        JsonObject toolCall = new JsonObject();
                        toolCall.addProperty("id", "call_" + UUID.randomUUID().toString().replace("-", "").substring(0, 24));
                        toolCall.addProperty("type", "function");

                        JsonObject function = new JsonObject();
                        function.addProperty("name", funcCall.has("name") ? funcCall.get("name").getAsString() : "");
                        function.addProperty("arguments", funcCall.has("args")
                            ? gson.toJson(funcCall.get("args")) : "{}");
                        toolCall.add("function", function);

                        toolCalls.add(toolCall);
                        finishReason = "tool_calls";
                    }
                }
            }

            // Check finish reason - but don't overwrite "tool_calls" if we detected function calls,
            // because Gemini returns finishReason="STOP" even when making function calls
            if (toolCalls.isEmpty() && firstCandidate.has("finishReason")) {
                String reason = firstCandidate.get("finishReason").getAsString();
                if ("MAX_TOKENS".equals(reason)) finishReason = "length";
                else if ("STOP".equals(reason)) finishReason = "stop";
            }
        }

        return new ParsedResponse(textContent.toString(), toolCalls, finishReason);
    }

    private record ParsedResponse(String textContent, JsonArray toolCalls, String finishReason) {}

    // =========================================================================
    // Chat Completion
    // =========================================================================

    @Override
    public String createChatCompletion(List<ChatMessage> messages) throws APIProviderException {
        if (!isAuthenticated()) {
            throw new AuthenticationException(name, "createChatCompletion", 401, null,
                "Not authenticated. Please authenticate via Settings > Edit Provider > Authenticate.");
        }

        try {
            JsonObject requestPayload = buildRequestPayload(messages, null, ToolChoiceMode.AUTO);
            JsonObject wrapped = wrapRequest(requestPayload);
            Headers headers = getGeminiHeaders().build();

            String requestUrl = getMethodUrl("generateContent");

            Request request = new Request.Builder()
                .url(requestUrl)
                .post(RequestBody.create(gson.toJson(wrapped).getBytes(StandardCharsets.UTF_8), JSON_MEDIA_TYPE))
                .headers(headers)
                .build();

            try (Response response = executeWithRateLimitRetry(request, "createChatCompletion")) {
                if (response.code() == 401) {
                    throw new AuthenticationException(name, "createChatCompletion", 401,
                        response.body() != null ? response.body().string() : null,
                        "Authentication failed. Please re-authenticate.");
                }
                if (!response.isSuccessful()) {
                    String errorBody = response.body() != null ? response.body().string() : "";
                    throw new APIProviderException(APIProviderException.ErrorCategory.SERVICE_ERROR,
                        name, "createChatCompletion",
                        "API error " + response.code() + ": " + errorBody);
                }

                String responseBody = response.body() != null ? response.body().string() : "{}";
                JsonObject responseData = gson.fromJson(responseBody, JsonObject.class);
                responseData = unwrapResponse(responseData);

                ParsedResponse parsed = parseGeminiResponse(responseData);
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
            JsonObject requestPayload = buildRequestPayload(messages, null, ToolChoiceMode.AUTO);
            JsonObject wrapped = wrapRequest(requestPayload);
            Headers headers = getGeminiHeaders().build();

            // Streaming via ?alt=sse
            String requestUrl = getMethodUrl("streamGenerateContent") + "?alt=sse";

            Request request = new Request.Builder()
                .url(requestUrl)
                .post(RequestBody.create(gson.toJson(wrapped).getBytes(StandardCharsets.UTF_8), JSON_MEDIA_TYPE))
                .headers(headers)
                .build();

            enqueueStreamingWithRetry(request, handler);
        } catch (IOException e) {
            handler.onError(handleNetworkError(e, "streamChatCompletion"));
        }
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
            JsonObject requestPayload = buildRequestPayload(messages, functions, toolChoiceMode);
            JsonObject wrapped = wrapRequest(requestPayload);
            Headers headers = getGeminiHeaders().build();

            String requestUrl = getMethodUrl("generateContent");

            Request request = new Request.Builder()
                .url(requestUrl)
                .post(RequestBody.create(gson.toJson(wrapped).getBytes(StandardCharsets.UTF_8), JSON_MEDIA_TYPE))
                .headers(headers)
                .build();

            try (Response response = executeWithRateLimitRetry(request, "createChatCompletionWithFunctions")) {
                if (response.code() == 401) {
                    throw new AuthenticationException(name, "createChatCompletionWithFunctions", 401,
                        response.body() != null ? response.body().string() : null,
                        "Authentication failed. Please re-authenticate.");
                }
                if (!response.isSuccessful()) {
                    String errorBody = response.body() != null ? response.body().string() : "";
                    throw new APIProviderException(APIProviderException.ErrorCategory.SERVICE_ERROR,
                        name, "createChatCompletionWithFunctions",
                        "API error " + response.code() + ": " + errorBody);
                }

                String responseBody = response.body() != null ? response.body().string() : "{}";
                JsonObject responseData = gson.fromJson(responseBody, JsonObject.class);
                responseData = unwrapResponse(responseData);

                ParsedResponse parsed = parseGeminiResponse(responseData);

                // Return tool calls in OpenAI format for ActionParser compatibility
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
            JsonObject requestPayload = buildRequestPayload(messages, functions, toolChoiceMode);
            JsonObject wrapped = wrapRequest(requestPayload);
            Headers headers = getGeminiHeaders().build();

            String requestUrl = getMethodUrl("generateContent");

            String requestJson = gson.toJson(wrapped);
            // Debug: Log tool count and first tool name
            if (requestPayload.has("tools")) {
                JsonArray tools = requestPayload.getAsJsonArray("tools");
                int declCount = 0;
                String firstToolName = "none";
                for (JsonElement t : tools) {
                    if (t.isJsonObject() && t.getAsJsonObject().has("functionDeclarations")) {
                        JsonArray decls = t.getAsJsonObject().getAsJsonArray("functionDeclarations");
                        declCount += decls.size();
                        if (decls.size() > 0 && decls.get(0).getAsJsonObject().has("name")) {
                            firstToolName = decls.get(0).getAsJsonObject().get("name").getAsString();
                        }
                    }
                }
                Msg.info(this, "Gemini FunctionCall request: " + declCount + " tools declared, first=" + firstToolName
                    + ", hasToolConfig=" + requestPayload.has("toolConfig"));
            }

            Request request = new Request.Builder()
                .url(requestUrl)
                .post(RequestBody.create(requestJson.getBytes(StandardCharsets.UTF_8), JSON_MEDIA_TYPE))
                .headers(headers)
                .build();

            try (Response response = executeWithRateLimitRetry(request, "createChatCompletionWithFunctionsFullResponse")) {
                if (response.code() == 401) {
                    throw new AuthenticationException(name, "createChatCompletionWithFunctionsFullResponse", 401,
                        response.body() != null ? response.body().string() : null,
                        "Authentication failed. Please re-authenticate.");
                }
                if (!response.isSuccessful()) {
                    String errorBody = response.body() != null ? response.body().string() : "";
                    throw new APIProviderException(APIProviderException.ErrorCategory.SERVICE_ERROR,
                        name, "createChatCompletionWithFunctionsFullResponse",
                        "API error " + response.code() + ": " + errorBody);
                }

                String responseBody = response.body() != null ? response.body().string() : "{}";
                Msg.info(this, "Gemini raw response (first 1000 chars): " +
                    responseBody.substring(0, Math.min(1000, responseBody.length())));

                JsonObject responseData = gson.fromJson(responseBody, JsonObject.class);
                responseData = unwrapResponse(responseData);

                ParsedResponse parsed = parseGeminiResponse(responseData);
                Msg.info(this, "Gemini parsed: text=" + parsed.textContent().length() + " chars, toolCalls="
                    + parsed.toolCalls().size() + ", finishReason=" + parsed.finishReason());

                // Convert to OpenAI Chat Completions format for ActionParser compatibility
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
                fullResponse.addProperty("id", "chatcmpl-gemini-" + System.currentTimeMillis());
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
     * Builds request payload in Gemini native format.
     */
    private JsonObject buildRequestPayload(List<ChatMessage> messages, List<Map<String, Object>> tools,
                                           ToolChoiceMode toolChoiceMode) {
        JsonObject translated = translateMessages(messages);
        JsonObject payload = new JsonObject();

        // Add contents
        payload.add("contents", translated.getAsJsonArray("contents"));

        // Add systemInstruction if present
        if (translated.has("systemInstruction")) {
            payload.add("systemInstruction", translated.getAsJsonObject("systemInstruction"));
        }

        // Add tools if present
        if (tools != null && !tools.isEmpty()) {
            JsonArray geminiTools = translateToolsToGeminiFormat(tools);
            if (geminiTools.size() > 0) {
                payload.add("tools", geminiTools);

                JsonObject toolConfig = new JsonObject();
                JsonObject functionCallingConfig = new JsonObject();
                functionCallingConfig.addProperty("mode",
                    (toolChoiceMode != null ? toolChoiceMode : ToolChoiceMode.AUTO)
                        .toGeminiFunctionCallingMode(messages));
                toolConfig.add("functionCallingConfig", functionCallingConfig);
                payload.add("toolConfig", toolConfig);
            }
        }

        // Add generation config
        if (maxTokens != null && maxTokens > 0) {
            JsonObject generationConfig = new JsonObject();
            generationConfig.addProperty("maxOutputTokens", maxTokens);
            payload.add("generationConfig", generationConfig);
        }

        return payload;
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

        String projectId = tokenManager.getProjectId();
        if (projectId == null || projectId.isBlank()) {
            throw new APIProviderException(APIProviderException.ErrorCategory.CONFIGURATION,
                name, "getAvailableModels",
                "Gemini OAuth is missing a project ID. Please re-authenticate.");
        }

        try {
            Headers headers = getGeminiHeaders().build();
            JsonObject body = new JsonObject();
            body.addProperty("project", projectId);

            Request request = new Request.Builder()
                .url(getMethodUrl("retrieveUserQuota"))
                .post(RequestBody.create(gson.toJson(body).getBytes(StandardCharsets.UTF_8), JSON_MEDIA_TYPE))
                .headers(headers)
                .build();

            try (Response response = executeWithRateLimitRetry(request, "getAvailableModels")) {
                if (response.code() == 401) {
                    throw new AuthenticationException(name, "getAvailableModels", 401,
                        response.body() != null ? response.body().string() : null,
                        "Authentication failed. Please re-authenticate.");
                }
                if (!response.isSuccessful()) {
                    String errorBody = response.body() != null ? response.body().string() : "";
                    throw new APIProviderException(APIProviderException.ErrorCategory.SERVICE_ERROR,
                        name, "getAvailableModels",
                        "API error " + response.code() + ": " + errorBody);
                }

                String responseBody = response.body() != null ? response.body().string() : "{}";
                JsonObject responseObj = gson.fromJson(responseBody, JsonObject.class);
                responseObj = unwrapResponse(responseObj);
                JsonArray buckets = responseObj.has("buckets") ? responseObj.getAsJsonArray("buckets") : new JsonArray();
                if (buckets.isEmpty()) {
                    throw new APIProviderException(APIProviderException.ErrorCategory.SERVICE_ERROR,
                        name, "getAvailableModels", "No model quota data was returned by Code Assist.");
                }

                return buildVisibleCatalog(hasPreviewAccess(buckets));
            }
        } catch (IOException e) {
            throw handleNetworkError(e, "getAvailableModels");
        }
    }

    @Override
    public void getEmbeddingsAsync(String text, EmbeddingCallback callback) {
        callback.onError(new UnsupportedOperationException(
            "Embeddings are not supported by the Gemini OAuth API"));
    }

    public void cancelRequest() {
        isCancelled = true;
    }

    // =========================================================================
    // Utility
    // =========================================================================

    /**
     * Generate a session ID matching Gemini CLI format: random long int with leading dash.
     */
    private static String generateSessionId() {
        Random random = new Random();
        long id = 1_000_000_000_000_000L + (long)(random.nextDouble() * 9_000_000_000_000_000L);
        return "-" + id;
    }
}
