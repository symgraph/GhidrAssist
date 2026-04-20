package ghidrassist.apiprovider.oauth;

import com.google.gson.Gson;
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
 * Manages OAuth 2.0 authentication with Anthropic's Claude Pro/Max API.
 * 
 * This class handles the complete OAuth flow including:
 * - PKCE (Proof Key for Code Exchange) generation
 * - Browser-based authorization
 * - Token exchange
 * - Token refresh
 * - Token storage (as JSON in the provider's key field)
 */
public class OAuthTokenManager {
    
    // OAuth Configuration - Official Anthropic OAuth Client ID
    private static final String CLIENT_ID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";
    private static final String AUTH_ENDPOINT = "https://claude.ai/oauth/authorize";
    private static final String TOKEN_ENDPOINT = "https://console.anthropic.com/v1/oauth/token";
    // Default redirect URI - Anthropic's hosted callback page (for manual code entry)
    private static final String DEFAULT_REDIRECT_URI = "https://console.anthropic.com/oauth/code/callback";
    private static final String SCOPES = "user:profile user:inference user:sessions:claude_code";
    
    // Token expiry buffer (5 minutes before actual expiry)
    private static final long EXPIRY_BUFFER_MS = 5 * 60 * 1000;
    
    private final OkHttpClient httpClient;
    private final Gson gson;
    private final Object refreshLock = new Object();
    
    // Token storage
    private String accessToken;
    private String refreshToken;
    private long expiresAt; // Unix timestamp in milliseconds
    
    // PKCE state for current auth flow
    private String pendingCodeVerifier;
    private String pendingState;
    private String pendingRedirectUri;
    private OAuthCallbackServer callbackServer;
    
    /**
     * Creates a new OAuthTokenManager.
     */
    public OAuthTokenManager() {
        this.httpClient = new OkHttpClient.Builder()
            .connectTimeout(30, TimeUnit.SECONDS)
            .readTimeout(30, TimeUnit.SECONDS)
            .writeTimeout(30, TimeUnit.SECONDS)
            .build();
        this.gson = new Gson();
    }
    
    /**
     * Creates a new OAuthTokenManager with existing credentials.
     * 
     * @param credentialsJson JSON string containing access_token, refresh_token, and expires_at
     */
    public OAuthTokenManager(String credentialsJson) {
        this();
        if (credentialsJson != null && !credentialsJson.isEmpty()) {
            loadFromJson(credentialsJson);
        }
    }
    
    /**
     * Checks if valid OAuth credentials exist.
     * 
     * @return true if there is a valid access token
     */
    public boolean isAuthenticated() {
        return accessToken != null && !accessToken.isEmpty();
    }
    
    /**
     * Checks if the current token is expired or about to expire.
     * 
     * @return true if the token needs to be refreshed
     */
    public boolean isTokenExpired() {
        return System.currentTimeMillis() >= (expiresAt - EXPIRY_BUFFER_MS);
    }
    
    /**
     * Starts the OAuth authorization flow by opening the browser.
     * Returns the code verifier needed for token exchange.
     * Uses Anthropic's hosted callback page (for manual code entry).
     * 
     * @return The code verifier to use when calling completeAuthorization
     */
    public String startAuthorizationFlow() {
        return startAuthorizationFlow(DEFAULT_REDIRECT_URI);
    }
    
    /**
     * Starts the OAuth authorization flow by opening the browser with a custom redirect URI.
     * 
     * @param redirectUri The redirect URI to use
     * @return The code verifier to use when calling completeAuthorization
     */
    public String startAuthorizationFlow(String redirectUri) {
        // Generate PKCE parameters
        pendingCodeVerifier = generateCodeVerifier();
        String codeChallenge = generateCodeChallenge(pendingCodeVerifier);
        pendingRedirectUri = redirectUri;
        
        // Generate separate state for CSRF protection
        pendingState = generateState();
        
        // Build authorization URL with separate state parameter
        String authUrl = buildAuthorizationUrl(codeChallenge, pendingState, redirectUri);
        
        // Open browser
        Msg.info(this, "Opening browser for OAuth authorization...");
        openBrowser(authUrl);
        
        return pendingCodeVerifier;
    }
    
    /**
     * Starts the OAuth authorization flow with automatic callback capture.
     * Opens a local HTTP server to capture the OAuth callback automatically.
     * 
     * Note: Anthropic may not support localhost redirects, so this may fail.
     * Use startAuthorizationFlow() for manual code entry as a fallback.
     * 
     * @return The OAuthCallbackServer that will receive the callback
     * @throws IOException If the callback server cannot be started
     */
    public OAuthCallbackServer startAuthorizationFlowWithCallback() throws IOException {
        // Generate PKCE parameters
        pendingCodeVerifier = generateCodeVerifier();
        String codeChallenge = generateCodeChallenge(pendingCodeVerifier);
        
        // Generate separate state for CSRF protection
        pendingState = generateState();
        
        // Create and start callback server with state for validation
        callbackServer = OAuthCallbackServer.forAnthropic(pendingState);
        callbackServer.start();
        
        // Use the callback server's redirect URI
        pendingRedirectUri = callbackServer.getRedirectUri();
        
        // Build authorization URL with callback server's redirect URI and state
        String authUrl = buildAuthorizationUrl(codeChallenge, pendingState, pendingRedirectUri);
        
        Msg.info(this, "Opening browser for Anthropic OAuth authentication with automatic callback...");
        Msg.info(this, "Callback server listening on: " + pendingRedirectUri);
        
        openBrowser(authUrl);
        
        return callbackServer;
    }
    
    /**
     * Completes authentication using the callback server.
     * Waits for the authorization code from the callback server.
     * 
     * @param server The callback server from startAuthorizationFlowWithCallback
     * @param timeoutMinutes Timeout in minutes
     * @throws Exception If authentication fails or times out
     */
    public void completeAuthorizationWithCallback(OAuthCallbackServer server, int timeoutMinutes) throws Exception {
        try {
            String code = server.waitForCode(timeoutMinutes);
            // Exchange code for tokens with separate state parameter
            TokenResponse tokens = exchangeCodeForTokens(code, pendingState, pendingCodeVerifier);
            
            this.accessToken = tokens.accessToken;
            this.refreshToken = tokens.refreshToken;
            this.expiresAt = System.currentTimeMillis() + (tokens.expiresIn * 1000L);
            
            Msg.info(this, "OAuth authentication successful!");
        } finally {
            server.stop();
            callbackServer = null;
            pendingCodeVerifier = null;
            pendingState = null;
        }
    }
    
    /**
     * Cancels the current authentication flow and stops the callback server.
     */
    public void cancelAuthentication() {
        if (callbackServer != null) {
            callbackServer.stop();
            callbackServer = null;
        }
        pendingCodeVerifier = null;
        pendingState = null;
        pendingRedirectUri = null;
    }
    
    /**
     * Gets the current callback server (if any).
     * 
     * @return The callback server, or null if not using automatic callback
     */
    public OAuthCallbackServer getCallbackServer() {
        return callbackServer;
    }
    
    /**
     * Completes the OAuth authorization by exchanging the code for tokens.
     * Used for manual flow where user copies code from Anthropic's hosted callback page.
     * 
     * @param authorizationCode The authorization code from the browser (format: "code#state" or just "code")
     * @param codeVerifier The code verifier from startAuthorizationFlow
     * @throws IOException If the token exchange fails
     */
    public void completeAuthorization(String authorizationCode, String codeVerifier) throws IOException {
        // Parse code#state format (from Anthropic's hosted callback page)
        String[] parts = authorizationCode.split("#");
        String code = parts[0];
        // For manual flow, use pendingState if available, otherwise try to extract from code#state format
        String state = pendingState != null ? pendingState : (parts.length > 1 ? parts[1] : "");
        
        TokenResponse tokens = exchangeCodeForTokens(code, state, codeVerifier);
        
        this.accessToken = tokens.accessToken;
        this.refreshToken = tokens.refreshToken;
        this.expiresAt = System.currentTimeMillis() + (tokens.expiresIn * 1000L);
        
        Msg.info(this, "OAuth authentication successful!");
        
        // Clean up
        pendingCodeVerifier = null;
        pendingState = null;
    }
    
    /**
     * Performs the complete authentication flow with user interaction.
     * Opens browser and prompts user to paste the authorization code.
     * 
     * @param timeoutMinutes Timeout (not used in manual flow, kept for API compatibility)
     * @throws Exception If authentication fails
     */
    @SuppressWarnings("unused")  // verifier preserved for future interactive auth flow
    public void authenticate(int timeoutMinutes) throws Exception {
        // Start the flow and get verifier
        String verifier = startAuthorizationFlow();

        // Prompt user for the code (this will be handled by SettingsTab UI)
        // For now, throw an exception indicating manual code entry is needed
        throw new UnsupportedOperationException(
            "Use authenticateWithCode(String code) after user provides the authorization code from browser"
        );
    }
    
    /**
     * Performs authentication with a manually entered authorization code.
     * 
     * @param authorizationCode The code copied from the browser (format: "code#state" or just "code")
     * @throws Exception If authentication fails
     */
    public void authenticateWithCode(String authorizationCode) throws Exception {
        if (pendingCodeVerifier == null) {
            throw new IllegalStateException("Call startAuthorizationFlow() first to open the browser");
        }
        
        completeAuthorization(authorizationCode, pendingCodeVerifier);
    }
    
    /**
     * Gets a valid access token, refreshing if necessary.
     * 
     * @return A valid access token
     * @throws IOException If token refresh fails
     */
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
    
    /**
     * Refreshes the access token using the refresh token.
     * 
     * @throws IOException If refresh fails
     */
    public void refreshAccessToken() throws IOException {
        synchronized (refreshLock) {
            refreshAccessTokenLocked();
        }
    }

    private void refreshAccessTokenLocked() throws IOException {
        if (refreshToken == null || refreshToken.isEmpty()) {
            throw new IllegalStateException("No refresh token available. Re-authentication required.");
        }
        
        Msg.info(this, "Refreshing OAuth access token...");
        
        // Build JSON request body (Anthropic requires JSON, not form-encoded)
        JsonObject requestJson = new JsonObject();
        requestJson.addProperty("grant_type", "refresh_token");
        requestJson.addProperty("refresh_token", refreshToken);
        requestJson.addProperty("client_id", CLIENT_ID);
        
        RequestBody jsonBody = RequestBody.create(
            gson.toJson(requestJson),
            MediaType.parse("application/json")
        );
        
        Request request = new Request.Builder()
            .url(TOKEN_ENDPOINT)
            .post(jsonBody)
            .header("Content-Type", "application/json")
            .build();
        
        try (Response response = httpClient.newCall(request).execute()) {
            String body = response.body() != null ? response.body().string() : "";
            
            if (!response.isSuccessful()) {
                if (isTerminalRefreshTokenFailure(response.code(), body)) {
                    clearCredentialsAfterRefreshFailure();
                }
                Msg.error(this, "Token refresh failed: " + response.code() + " - " + body);
                throw new IOException("Token refresh failed: " + response.code() + " - " + body);
            }
            
            JsonObject json = gson.fromJson(body, JsonObject.class);
            
            this.accessToken = json.get("access_token").getAsString();
            if (json.has("refresh_token")) {
                this.refreshToken = json.get("refresh_token").getAsString();
            }
            this.expiresAt = System.currentTimeMillis() + (json.get("expires_in").getAsInt() * 1000L);
            
            Msg.info(this, "OAuth access token refreshed successfully");
        }
    }

    private boolean isTerminalRefreshTokenFailure(int statusCode, String body) {
        if (statusCode != 400 && statusCode != 401) {
            return false;
        }
        String lowerBody = body != null ? body.toLowerCase() : "";
        return lowerBody.contains("refresh_token_reused") ||
            lowerBody.contains("refresh token has already been used") ||
            lowerBody.contains("refresh_token_expired") ||
            lowerBody.contains("refresh token has expired") ||
            lowerBody.contains("expired refresh token") ||
            lowerBody.contains("refresh_token_revoked") ||
            lowerBody.contains("refresh token has been revoked") ||
            lowerBody.contains("refresh token revoked") ||
            lowerBody.contains("refresh_token_invalid") ||
            lowerBody.contains("invalid refresh token") ||
            lowerBody.contains("refresh token is invalid") ||
            lowerBody.contains("invalid_grant");
    }

    private void clearCredentialsAfterRefreshFailure() {
        accessToken = null;
        refreshToken = null;
        expiresAt = 0;
    }
    
    /**
     * Clears all stored credentials.
     */
    public void logout() {
        accessToken = null;
        refreshToken = null;
        expiresAt = 0;
        Msg.info(this, "OAuth credentials cleared");
    }
    
    /**
     * Exports credentials to JSON for storage in the provider's key field.
     * 
     * @return JSON string containing credentials
     */
    public String toJson() {
        JsonObject json = new JsonObject();
        json.addProperty("access_token", accessToken != null ? accessToken : "");
        json.addProperty("refresh_token", refreshToken != null ? refreshToken : "");
        json.addProperty("expires_at", expiresAt);
        return gson.toJson(json);
    }
    
    /**
     * Loads credentials from JSON.
     * 
     * @param json JSON string containing credentials
     */
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
            
            Msg.debug(this, "Loaded OAuth credentials from JSON");
            
        } catch (Exception e) {
            Msg.warn(this, "Failed to parse OAuth credentials: " + e.getMessage());
        }
    }
    
    // =========================================================================
    // PKCE Methods
    // =========================================================================
    
    /**
     * Generates a cryptographically random code verifier for PKCE.
     */
    private String generateCodeVerifier() {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
    
    /**
     * Generates the code challenge from the verifier using SHA-256.
     */
    private String generateCodeChallenge(String codeVerifier) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }
    
    /**
     * Generates a cryptographically random state parameter for CSRF protection.
     * This is separate from the PKCE code verifier.
     */
    private String generateState() {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
    
    // =========================================================================
    // Authorization URL
    // =========================================================================
    
    /**
     * Builds the OAuth authorization URL with all required parameters.
     * 
     * @param codeChallenge PKCE code challenge
     * @param state Random state parameter for CSRF protection (separate from verifier)
     */
    private String buildAuthorizationUrl(String codeChallenge, String state) {
        return buildAuthorizationUrl(codeChallenge, state, DEFAULT_REDIRECT_URI);
    }
    
    /**
     * Builds the OAuth authorization URL with all required parameters and custom redirect URI.
     * 
     * @param codeChallenge PKCE code challenge
     * @param state Random state parameter for CSRF protection (separate from verifier)
     * @param redirectUri The redirect URI to use
     */
    private String buildAuthorizationUrl(String codeChallenge, String state, String redirectUri) {
        try {
            // State is a separate random token for CSRF protection (not the PKCE verifier)
            return AUTH_ENDPOINT + "?" +
                "code=true" +  // Request code display in browser
                "&client_id=" + URLEncoder.encode(CLIENT_ID, StandardCharsets.UTF_8) +
                "&response_type=code" +
                "&redirect_uri=" + URLEncoder.encode(redirectUri, StandardCharsets.UTF_8) +
                "&scope=" + URLEncoder.encode(SCOPES, StandardCharsets.UTF_8) +
                "&code_challenge=" + URLEncoder.encode(codeChallenge, StandardCharsets.UTF_8) +
                "&code_challenge_method=S256" +
                "&state=" + URLEncoder.encode(state, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException("Failed to build authorization URL", e);
        }
    }
    
    /**
     * Opens the system default browser to the specified URL.
     */
    private void openBrowser(String url) {
        try {
            if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
                Desktop.getDesktop().browse(new URI(url));
            } else {
                // Fallback for headless environments
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
    
    // =========================================================================
    // Token Exchange
    // =========================================================================
    
    /**
     * Exchanges the authorization code for access and refresh tokens.
     */
    private TokenResponse exchangeCodeForTokens(String code, String state, String codeVerifier) 
            throws IOException {
        
        // Use the redirect URI from the auth flow, or default
        String redirectUri = pendingRedirectUri != null ? pendingRedirectUri : DEFAULT_REDIRECT_URI;
        
        // Build JSON request body (Anthropic requires JSON, not form-encoded)
        JsonObject requestJson = new JsonObject();
        requestJson.addProperty("code", code);
        requestJson.addProperty("state", state);
        requestJson.addProperty("grant_type", "authorization_code");
        requestJson.addProperty("client_id", CLIENT_ID);
        requestJson.addProperty("redirect_uri", redirectUri);
        requestJson.addProperty("code_verifier", codeVerifier);
        
        RequestBody jsonBody = RequestBody.create(
            gson.toJson(requestJson),
            MediaType.parse("application/json")
        );
        
        Request request = new Request.Builder()
            .url(TOKEN_ENDPOINT)
            .post(jsonBody)
            .header("Content-Type", "application/json")
            .build();
        
        try (Response response = httpClient.newCall(request).execute()) {
            String body = response.body() != null ? response.body().string() : "";
            
            if (!response.isSuccessful()) {
                throw new IOException("Token exchange failed: " + response.code() + " - " + body);
            }
            
            JsonObject json = gson.fromJson(body, JsonObject.class);
            
            return new TokenResponse(
                json.get("access_token").getAsString(),
                json.has("refresh_token") ? json.get("refresh_token").getAsString() : null,
                json.get("expires_in").getAsInt()
            );
        }
    }
    
    /**
     * Token response from the OAuth server.
     */
    private record TokenResponse(String accessToken, String refreshToken, int expiresIn) {}
    
    // =========================================================================
    // Getters for testing/debugging
    // =========================================================================
    
    public String getAccessToken() {
        return accessToken;
    }
    
    public String getRefreshToken() {
        return refreshToken;
    }
    
    public long getExpiresAt() {
        return expiresAt;
    }
}
