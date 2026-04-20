package ghidrassist.apiprovider.oauth;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import ghidra.util.Msg;
import okhttp3.*;

import java.awt.Desktop;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.concurrent.TimeUnit;

/**
 * Manages OAuth 2.0 authentication with Google Gemini CLI.
 *
 * This class handles the complete OAuth flow including:
 * - Browser-based authorization (NO PKCE, state-only CSRF protection)
 * - Headless/manual authorization (WITH PKCE S256)
 * - Token exchange (form-encoded with client_secret)
 * - Token refresh
 * - User info fetching (email)
 * - Project discovery via loadCodeAssist + onboardUser
 * - Token storage (as JSON in the provider's key field)
 *
 * Based on the official Gemini CLI authentication implementation.
 */
public class GeminiOAuthTokenManager {

    // OAuth Configuration - Official Gemini CLI Client ID (installed app - safe to embed)
    private static final String CLIENT_ID = "681255809395-oo8ft2oprdrnp9e3aqf6av3hmdib135j.apps.googleusercontent.com";
    private static final String CLIENT_SECRET = "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";
    private static final String AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth";
    private static final String TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token";
    private static final String HEADLESS_REDIRECT_URI = "https://codeassist.google.com/authcode";
    private static final String SCOPES = "https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile";
    private static final String USER_INFO_URL = "https://www.googleapis.com/oauth2/v2/userinfo";
    private static final String CODE_ASSIST_ENDPOINT = "https://cloudcode-pa.googleapis.com";
    private static final String CODE_ASSIST_API_VERSION = "v1internal";

    // Token expiry buffer (5 minutes before actual expiry)
    private static final long EXPIRY_BUFFER_MS = 5 * 60 * 1000;

    private final OkHttpClient httpClient;
    private final Gson gson;
    private final Object refreshLock = new Object();

    // Token storage
    private String accessToken;
    private String refreshToken;
    private long expiresAt; // Unix timestamp in milliseconds
    private String email;
    private String projectId;
    private String tier;
    private String tierName;

    // Auth flow state
    private String pendingCodeVerifier; // Only used in headless mode
    private String pendingState;
    private String pendingRedirectUri;
    private OAuthCallbackServer callbackServer;

    public GeminiOAuthTokenManager() {
        this.httpClient = new OkHttpClient.Builder()
            .connectTimeout(30, TimeUnit.SECONDS)
            .readTimeout(30, TimeUnit.SECONDS)
            .writeTimeout(30, TimeUnit.SECONDS)
            .build();
        this.gson = new Gson();
    }

    public GeminiOAuthTokenManager(String credentialsJson) {
        this();
        if (credentialsJson != null && !credentialsJson.isEmpty()) {
            loadFromJson(credentialsJson);
        }
    }

    public boolean isAuthenticated() {
        return accessToken != null && !accessToken.isEmpty();
    }

    public boolean isTokenExpired() {
        return System.currentTimeMillis() >= (expiresAt - EXPIRY_BUFFER_MS);
    }

    public String getEmail() { return email; }
    public String getProjectId() { return projectId; }
    public String getTier() { return tier; }
    public String getTierName() { return tierName; }
    public String getAccessToken() { return accessToken; }
    public String getRefreshToken() { return refreshToken; }
    public long getExpiresAt() { return expiresAt; }

    // =========================================================================
    // Browser Auth Flow (NO PKCE, state-only CSRF) - matches authWithWeb
    // =========================================================================

    /**
     * Starts the OAuth authorization flow with automatic callback capture.
     * Opens a local HTTP server on a dynamic port to capture the callback.
     * Browser mode: NO PKCE, just state param + access_type=offline.
     *
     * @return The OAuthCallbackServer that will receive the callback
     * @throws IOException If the callback server cannot be started
     */
    public OAuthCallbackServer startAuthorizationFlowWithCallback() throws IOException {
        pendingState = generateState();

        // Create and start callback server on dynamic port
        callbackServer = OAuthCallbackServer.forGemini(pendingState);
        callbackServer.start();

        pendingRedirectUri = callbackServer.getRedirectUri();

        // Browser mode: NO PKCE, just state + access_type=offline
        String authUrl = buildBrowserAuthUrl(pendingState, pendingRedirectUri);

        Msg.info(this, "Opening browser for Google Gemini OAuth authentication with automatic callback...");
        Msg.info(this, "Callback server listening on: " + pendingRedirectUri);

        openBrowser(authUrl);

        return callbackServer;
    }

    /**
     * Completes authentication using the callback server.
     */
    public void completeAuthorizationWithCallback(OAuthCallbackServer server, int timeoutMinutes) throws Exception {
        try {
            String code = server.waitForCode(timeoutMinutes);
            // Browser mode: no PKCE verifier
            completeAuthorization(code, pendingRedirectUri, null);
        } finally {
            server.stop();
            callbackServer = null;
        }
    }

    // =========================================================================
    // Headless Auth Flow (WITH PKCE S256) - matches authWithUserCode
    // =========================================================================

    /**
     * Starts the OAuth authorization flow for headless/manual mode.
     * Uses PKCE S256 with codeassist.google.com/authcode redirect.
     */
    public void startAuthorizationFlow() {
        pendingCodeVerifier = generateCodeVerifier();
        String codeChallenge = generateCodeChallenge(pendingCodeVerifier);
        pendingState = generateState();
        pendingRedirectUri = HEADLESS_REDIRECT_URI;

        String authUrl = buildHeadlessAuthUrl(codeChallenge, pendingState);

        Msg.info(this, "Opening browser for Google Gemini OAuth authentication (headless mode)...");
        openBrowser(authUrl);
    }

    /**
     * Performs authentication with a manually entered authorization code.
     */
    public void authenticateWithCode(String input) throws Exception {
        if (pendingCodeVerifier == null) {
            throw new IllegalStateException("Call startAuthorizationFlow() first to open the browser");
        }

        String code = extractCodeFromInput(input.trim());
        Msg.info(this, "Extracted authorization code: " + code.substring(0, Math.min(20, code.length())) + "...");

        // Headless mode: WITH PKCE verifier
        completeAuthorization(code, HEADLESS_REDIRECT_URI, pendingCodeVerifier);
    }

    // =========================================================================
    // Common Auth Completion
    // =========================================================================

    /**
     * Completes authorization by exchanging code for tokens, fetching user info,
     * and setting up the user via Code Assist.
     */
    private void completeAuthorization(String code, String redirectUri, String codeVerifier) throws IOException {
        // Exchange code for tokens
        JsonObject tokens = exchangeCodeForTokens(code, redirectUri, codeVerifier);

        this.accessToken = tokens.get("access_token").getAsString();
        this.refreshToken = tokens.has("refresh_token") && !tokens.get("refresh_token").isJsonNull()
            ? tokens.get("refresh_token").getAsString() : null;
        this.expiresAt = System.currentTimeMillis() +
            (tokens.has("expires_in") ? tokens.get("expires_in").getAsLong() * 1000L : 3600000L);

        if (this.refreshToken == null || this.refreshToken.isEmpty()) {
            throw new IOException("Missing refresh token in response");
        }

        // Fetch user info (email)
        fetchUserInfo(this.accessToken);

        // Setup user via Code Assist (project discovery)
        setupUser(this.accessToken);

        Msg.info(this, "Google Gemini OAuth authentication successful!" +
            (email != null ? " Email: " + email : "") +
            (projectId != null ? " Project: " + projectId : ""));

        // Clean up
        pendingCodeVerifier = null;
        pendingState = null;
        pendingRedirectUri = null;
    }

    // =========================================================================
    // Token Management
    // =========================================================================

    public String getValidAccessToken() throws IOException {
        if (!isAuthenticated()) {
            throw new IllegalStateException("Not authenticated. Call authenticate() first.");
        }

        if (!isTokenExpired()) {
            return accessToken;
        }

        synchronized (refreshLock) {
            if (isTokenExpired()) {
                refreshAccessTokenLocked();
            }
            return accessToken;
        }
    }

    public void refreshAccessToken() throws IOException {
        synchronized (refreshLock) {
            refreshAccessTokenLocked();
        }
    }

    private void refreshAccessTokenLocked() throws IOException {
        if (refreshToken == null || refreshToken.isEmpty()) {
            throw new IllegalStateException("No refresh token available. Re-authentication required.");
        }

        Msg.info(this, "Refreshing Google Gemini access token...");

        // Form-encoded with client_secret
        FormBody formBody = new FormBody.Builder()
            .add("grant_type", "refresh_token")
            .add("refresh_token", refreshToken)
            .add("client_id", CLIENT_ID)
            .add("client_secret", CLIENT_SECRET)
            .build();

        Request request = new Request.Builder()
            .url(TOKEN_ENDPOINT)
            .post(formBody)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .build();

        try (Response response = httpClient.newCall(request).execute()) {
            String body = response.body() != null ? response.body().string() : "";

            if (!response.isSuccessful()) {
                Msg.error(this, "Token refresh failed: " + response.code() + " - " + body);
                throw new IOException("Token refresh failed: " + response.code() + " - " + body);
            }

            JsonObject json = gson.fromJson(body, JsonObject.class);

            this.accessToken = json.get("access_token").getAsString();
            // Google refresh response may omit refresh_token - preserve original
            if (json.has("refresh_token") && !json.get("refresh_token").isJsonNull()) {
                this.refreshToken = json.get("refresh_token").getAsString();
            }
            this.expiresAt = System.currentTimeMillis() +
                (json.has("expires_in") ? json.get("expires_in").getAsLong() * 1000L : 3600000L);

            Msg.info(this, "Google Gemini access token refreshed successfully");
        }
    }

    public void cancelAuthentication() {
        if (callbackServer != null) {
            callbackServer.stop();
            callbackServer = null;
        }
        pendingCodeVerifier = null;
        pendingState = null;
        pendingRedirectUri = null;
    }

    public OAuthCallbackServer getCallbackServer() {
        return callbackServer;
    }

    public void logout() {
        accessToken = null;
        refreshToken = null;
        expiresAt = 0;
        email = null;
        projectId = null;
        tier = null;
        tierName = null;
        Msg.info(this, "Google Gemini OAuth credentials cleared");
    }

    // =========================================================================
    // Serialization
    // =========================================================================

    public String toJson() {
        JsonObject json = new JsonObject();
        json.addProperty("access_token", accessToken != null ? accessToken : "");
        json.addProperty("refresh_token", refreshToken != null ? refreshToken : "");
        json.addProperty("expires_at", expiresAt);
        json.addProperty("email", email != null ? email : "");
        json.addProperty("project_id", projectId != null ? projectId : "");
        json.addProperty("tier", tier != null ? tier : "");
        json.addProperty("tier_name", tierName != null ? tierName : "");
        return gson.toJson(json);
    }

    public void loadFromJson(String json) {
        try {
            JsonObject obj = gson.fromJson(json, JsonObject.class);

            if (obj.has("access_token") && !obj.get("access_token").isJsonNull()) {
                this.accessToken = obj.get("access_token").getAsString();
            }
            if (obj.has("refresh_token") && !obj.get("refresh_token").isJsonNull()) {
                this.refreshToken = obj.get("refresh_token").getAsString();
            }
            if (obj.has("expires_at")) {
                this.expiresAt = obj.get("expires_at").getAsLong();
            }
            if (obj.has("email") && !obj.get("email").isJsonNull()) {
                this.email = obj.get("email").getAsString();
                if (this.email.isEmpty()) this.email = null;
            }
            if (obj.has("project_id") && !obj.get("project_id").isJsonNull()) {
                this.projectId = obj.get("project_id").getAsString();
                if (this.projectId.isEmpty()) this.projectId = null;
            }
            if (obj.has("tier") && !obj.get("tier").isJsonNull()) {
                this.tier = obj.get("tier").getAsString();
                if (this.tier.isEmpty()) this.tier = null;
            }
            if (obj.has("tier_name") && !obj.get("tier_name").isJsonNull()) {
                this.tierName = obj.get("tier_name").getAsString();
                if (this.tierName.isEmpty()) this.tierName = null;
            }

            Msg.debug(this, "Loaded Google Gemini OAuth credentials from JSON");
        } catch (Exception e) {
            Msg.warn(this, "Failed to parse Google Gemini OAuth credentials: " + e.getMessage());
        }
    }

    // =========================================================================
    // Token Exchange
    // =========================================================================

    /**
     * Exchanges the authorization code for tokens.
     * Form-encoded with client_secret (unlike OpenAI/Anthropic which are public clients).
     */
    private JsonObject exchangeCodeForTokens(String code, String redirectUri, String codeVerifier) throws IOException {
        FormBody.Builder formBuilder = new FormBody.Builder()
            .add("client_id", CLIENT_ID)
            .add("client_secret", CLIENT_SECRET)
            .add("code", code)
            .add("grant_type", "authorization_code")
            .add("redirect_uri", redirectUri);

        if (codeVerifier != null) {
            formBuilder.add("code_verifier", codeVerifier);
        }

        Request request = new Request.Builder()
            .url(TOKEN_ENDPOINT)
            .post(formBuilder.build())
            .header("Content-Type", "application/x-www-form-urlencoded")
            .build();

        try (Response response = httpClient.newCall(request).execute()) {
            String body = response.body() != null ? response.body().string() : "";

            if (!response.isSuccessful()) {
                throw new IOException("Token exchange failed: " + response.code() + " - " + body);
            }

            JsonObject json = gson.fromJson(body, JsonObject.class);
            if (json.has("error")) {
                String errorDesc = json.has("error_description")
                    ? json.get("error_description").getAsString()
                    : json.get("error").getAsString();
                throw new IOException("Token exchange failed: " + errorDesc);
            }

            return json;
        }
    }

    // =========================================================================
    // User Info
    // =========================================================================

    /**
     * Fetches user info (email) from Google's userinfo v2 endpoint.
     */
    private void fetchUserInfo(String accessToken) {
        try {
            Request request = new Request.Builder()
                .url(USER_INFO_URL)
                .get()
                .header("Authorization", "Bearer " + accessToken)
                .build();

            try (Response response = httpClient.newCall(request).execute()) {
                if (response.isSuccessful() && response.body() != null) {
                    JsonObject userInfo = gson.fromJson(response.body().string(), JsonObject.class);
                    if (userInfo.has("email") && !userInfo.get("email").isJsonNull()) {
                        this.email = userInfo.get("email").getAsString();
                        Msg.info(this, "Authenticated as: " + this.email);
                    }
                }
            }
        } catch (Exception e) {
            Msg.warn(this, "Could not fetch user info: " + e.getMessage());
        }
    }

    // =========================================================================
    // Code Assist Setup (loadCodeAssist + onboardUser)
    // =========================================================================

    /**
     * Full user setup flow matching Gemini CLI setup.ts setupUser():
     * 1. loadCodeAssist to discover project and tier
     * 2. onboardUser if needed (for free tier)
     */
    private void setupUser(String accessToken) {
        try {
            Msg.info(this, "Setting up user via Code Assist...");

            // Check environment for project ID
            String envProject = System.getenv("GOOGLE_CLOUD_PROJECT");
            if (envProject == null || envProject.isEmpty()) {
                envProject = System.getenv("GOOGLE_CLOUD_PROJECT_ID");
            }

            JsonObject loadResult = loadCodeAssist(accessToken, envProject);
            if (loadResult == null || loadResult.size() == 0) {
                this.projectId = envProject;
                return;
            }

            // If user already has a current tier
            if (loadResult.has("currentTier") && !loadResult.get("currentTier").isJsonNull()) {
                JsonObject currentTier = loadResult.getAsJsonObject("currentTier");
                this.projectId = loadResult.has("cloudaicompanionProject")
                    ? loadResult.get("cloudaicompanionProject").getAsString()
                    : (envProject != null ? envProject : "");

                JsonObject effectiveTier = loadResult.has("paidTier") && !loadResult.get("paidTier").isJsonNull()
                    ? loadResult.getAsJsonObject("paidTier")
                    : currentTier;

                this.tier = effectiveTier.has("id") ? effectiveTier.get("id").getAsString() : "";
                this.tierName = effectiveTier.has("name") ? effectiveTier.get("name").getAsString() : "";

                Msg.info(this, "Code Assist project: " + this.projectId + ", tier: " + this.tier + " (" + this.tierName + ")");
                return;
            }

            // Need to onboard - find default tier from allowedTiers
            String onboardTierId = "LEGACY";
            String onboardTierName = "";

            if (loadResult.has("allowedTiers") && loadResult.get("allowedTiers").isJsonArray()) {
                JsonArray allowedTiers = loadResult.getAsJsonArray("allowedTiers");
                for (JsonElement tierElement : allowedTiers) {
                    if (tierElement.isJsonObject()) {
                        JsonObject t = tierElement.getAsJsonObject();
                        if (t.has("isDefault") && t.get("isDefault").getAsBoolean()) {
                            onboardTierId = t.has("id") ? t.get("id").getAsString() : "LEGACY";
                            onboardTierName = t.has("name") ? t.get("name").getAsString() : "";
                            break;
                        }
                    }
                }
            }

            Msg.info(this, "Onboarding user for tier: " + onboardTierId + " (" + onboardTierName + ")");
            JsonObject onboardResult = onboardUser(accessToken, onboardTierId, envProject);

            // Extract project from onboard response
            String project = "";
            if (onboardResult != null) {
                if (onboardResult.has("response") && onboardResult.get("response").isJsonObject()) {
                    JsonObject respData = onboardResult.getAsJsonObject("response");
                    if (respData.has("cloudaicompanionProject")) {
                        JsonElement cap = respData.get("cloudaicompanionProject");
                        if (cap.isJsonObject()) {
                            project = cap.getAsJsonObject().has("id")
                                ? cap.getAsJsonObject().get("id").getAsString() : "";
                        } else if (cap.isJsonPrimitive()) {
                            project = cap.getAsString();
                        }
                    }
                }
            }

            if (project.isEmpty() && envProject != null) {
                project = envProject;
            }

            this.projectId = project;
            this.tier = onboardTierId;
            this.tierName = onboardTierName;

            Msg.info(this, "Code Assist setup complete. Project: " + this.projectId + ", tier: " + this.tier);

        } catch (Exception e) {
            Msg.warn(this, "Code Assist setup failed (non-fatal): " + e.getMessage());
        }
    }

    /**
     * Load Code Assist configuration (matches loadCodeAssist from setup.ts).
     */
    private JsonObject loadCodeAssist(String accessToken, String projectId) {
        try {
            JsonObject metadata = new JsonObject();
            metadata.addProperty("ideType", "IDE_UNSPECIFIED");
            metadata.addProperty("platform", "PLATFORM_UNSPECIFIED");
            metadata.addProperty("pluginType", "GEMINI");
            if (projectId != null && !projectId.isEmpty()) {
                metadata.addProperty("duetProject", projectId);
            }

            JsonObject body = new JsonObject();
            if (projectId != null && !projectId.isEmpty()) {
                body.addProperty("cloudaicompanionProject", projectId);
            }
            body.add("metadata", metadata);

            String url = CODE_ASSIST_ENDPOINT + "/" + CODE_ASSIST_API_VERSION + ":loadCodeAssist";

            Request request = new Request.Builder()
                .url(url)
                .post(RequestBody.create(gson.toJson(body).getBytes(StandardCharsets.UTF_8),
                    MediaType.get("application/json")))
                .header("Authorization", "Bearer " + accessToken)
                .header("Content-Type", "application/json")
                .header("User-Agent", "GeminiCLI/1.0.0/gemini-2.5-flash (" + getOsPlatform() + "; " + getOsArch() + ")")
                .build();

            try (Response response = httpClient.newCall(request).execute()) {
                if (response.isSuccessful() && response.body() != null) {
                    return gson.fromJson(response.body().string(), JsonObject.class);
                }
                Msg.debug(this, "loadCodeAssist failed: " + response.code());
                return null;
            }
        } catch (Exception e) {
            Msg.debug(this, "loadCodeAssist error: " + e.getMessage());
            return null;
        }
    }

    /**
     * Onboard a user for Code Assist (matches onboardUser from setup.ts).
     */
    private JsonObject onboardUser(String accessToken, String tierId, String projectId) {
        try {
            JsonObject metadata = new JsonObject();
            metadata.addProperty("ideType", "IDE_UNSPECIFIED");
            metadata.addProperty("platform", "PLATFORM_UNSPECIFIED");
            metadata.addProperty("pluginType", "GEMINI");

            JsonObject body = new JsonObject();
            body.addProperty("tierId", tierId);

            if (!"FREE".equals(tierId) && projectId != null && !projectId.isEmpty()) {
                body.addProperty("cloudaicompanionProject", projectId);
                metadata.addProperty("duetProject", projectId);
            }
            body.add("metadata", metadata);

            String url = CODE_ASSIST_ENDPOINT + "/" + CODE_ASSIST_API_VERSION + ":onboardUser";

            Request request = new Request.Builder()
                .url(url)
                .post(RequestBody.create(gson.toJson(body).getBytes(StandardCharsets.UTF_8),
                    MediaType.get("application/json")))
                .header("Authorization", "Bearer " + accessToken)
                .header("Content-Type", "application/json")
                .header("User-Agent", "GeminiCLI/1.0.0/gemini-2.5-flash (" + getOsPlatform() + "; " + getOsArch() + ")")
                .build();

            try (Response response = httpClient.newCall(request).execute()) {
                if (response.isSuccessful() && response.body() != null) {
                    return gson.fromJson(response.body().string(), JsonObject.class);
                }
                Msg.debug(this, "onboardUser failed: " + response.code());
                return null;
            }
        } catch (Exception e) {
            Msg.debug(this, "onboardUser error: " + e.getMessage());
            return null;
        }
    }

    // =========================================================================
    // Authorization URL Builders
    // =========================================================================

    /**
     * Browser mode auth URL: NO PKCE, just state + access_type=offline.
     */
    private String buildBrowserAuthUrl(String state, String redirectUri) {
        StringBuilder url = new StringBuilder(AUTH_ENDPOINT);
        url.append("?client_id=").append(urlEncode(CLIENT_ID));
        url.append("&response_type=code");
        url.append("&redirect_uri=").append(urlEncode(redirectUri));
        url.append("&scope=").append(urlEncode(SCOPES));
        url.append("&state=").append(urlEncode(state));
        url.append("&access_type=offline");
        return url.toString();
    }

    /**
     * Headless mode auth URL: WITH PKCE S256 + access_type=offline.
     */
    private String buildHeadlessAuthUrl(String codeChallenge, String state) {
        StringBuilder url = new StringBuilder(AUTH_ENDPOINT);
        url.append("?client_id=").append(urlEncode(CLIENT_ID));
        url.append("&response_type=code");
        url.append("&redirect_uri=").append(urlEncode(HEADLESS_REDIRECT_URI));
        url.append("&scope=").append(urlEncode(SCOPES));
        url.append("&code_challenge=").append(urlEncode(codeChallenge));
        url.append("&code_challenge_method=S256");
        url.append("&state=").append(urlEncode(state));
        url.append("&access_type=offline");
        return url.toString();
    }

    // =========================================================================
    // PKCE Methods (for headless mode only)
    // =========================================================================

    private String generateCodeVerifier() {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String generateCodeChallenge(String codeVerifier) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    private String generateState() {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        // Match crypto.randomBytes(32).toString('hex') from Gemini CLI
        StringBuilder hex = new StringBuilder();
        for (byte b : bytes) {
            hex.append(String.format("%02x", b));
        }
        return hex.toString();
    }

    // =========================================================================
    // Utility Methods
    // =========================================================================

    private String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private void openBrowser(String url) {
        try {
            if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
                Desktop.getDesktop().browse(new URI(url));
            } else {
                String os = System.getProperty("os.name").toLowerCase();
                Runtime rt = Runtime.getRuntime();
                if (os.contains("mac")) {
                    rt.exec(new String[]{"open", url});
                } else if (os.contains("win")) {
                    rt.exec(new String[]{"rundll32", "url.dll,FileProtocolHandler", url});
                } else {
                    rt.exec(new String[]{"xdg-open", url});
                }
            }
        } catch (Exception e) {
            Msg.error(this, "Could not open browser: " + e.getMessage());
            Msg.info(this, "Please open this URL manually: " + url);
        }
    }

    private String extractCodeFromInput(String input) {
        // Try to parse as URL
        if (input.startsWith("http")) {
            try {
                java.net.URL url = java.net.URI.create(input).toURL();
                String query = url.getQuery();
                if (query != null) {
                    for (String param : query.split("&")) {
                        String[] pair = param.split("=", 2);
                        if (pair.length == 2 && "code".equals(pair[0])) {
                            return java.net.URLDecoder.decode(pair[1], StandardCharsets.UTF_8);
                        }
                    }
                }
            } catch (Exception e) {
                Msg.debug(this, "Failed to parse as URL, using input as-is: " + e.getMessage());
            }
        }
        return input;
    }

    private String getOsPlatform() {
        String os = System.getProperty("os.name", "").toLowerCase();
        if (os.contains("linux")) return "linux";
        if (os.contains("mac") || os.contains("darwin")) return "darwin";
        if (os.contains("win")) return "win32";
        return os;
    }

    private String getOsArch() {
        String arch = System.getProperty("os.arch", "");
        if ("amd64".equals(arch) || "x86_64".equals(arch)) return "x86_64";
        if ("aarch64".equals(arch) || "arm64".equals(arch)) return "arm64";
        return arch;
    }
}
