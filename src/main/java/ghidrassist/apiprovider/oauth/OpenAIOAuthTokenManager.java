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
 * Manages OAuth 2.0 authentication with OpenAI's Codex API (ChatGPT Pro/Plus).
 * 
 * This class handles the complete OAuth flow including:
 * - PKCE (Proof Key for Code Exchange) generation
 * - Browser-based authorization
 * - Token exchange (form-encoded, not JSON)
 * - Token refresh
 * - Account ID extraction from JWT
 * - Token storage (as JSON in the provider's key field)
 * 
 * Based on the official Codex CLI (codex-cli-rs) authentication implementation.
 */
public class OpenAIOAuthTokenManager {
    
    // OAuth Configuration - Official OpenAI/Codex CLI Client ID
    private static final String CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann";
    private static final String AUTH_ENDPOINT = "https://auth.openai.com/oauth/authorize";
    private static final String TOKEN_ENDPOINT = "https://auth.openai.com/oauth/token";
    // Default redirect URI - can be overridden when using callback server
    private static final String DEFAULT_REDIRECT_URI = "http://localhost:1455/auth/callback";
    private static final String SCOPES = "openid profile email offline_access";
    
    // Token expiry buffer (5 minutes before actual expiry)
    private static final long EXPIRY_BUFFER_MS = 5 * 60 * 1000;
    
    private final OkHttpClient httpClient;
    private final Gson gson;
    private final Object refreshLock = new Object();
    
    // Token storage
    private String accessToken;
    private String refreshToken;
    private long expiresAt; // Unix timestamp in milliseconds
    private String accountId; // ChatGPT account ID for org subscriptions
    
    // PKCE state for current auth flow
    private String pendingCodeVerifier;
    private String pendingState;
    private String pendingRedirectUri;
    private OAuthCallbackServer callbackServer;
    
    /**
     * Creates a new OpenAIOAuthTokenManager.
     */
    public OpenAIOAuthTokenManager() {
        this.httpClient = new OkHttpClient.Builder()
            .connectTimeout(30, TimeUnit.SECONDS)
            .readTimeout(30, TimeUnit.SECONDS)
            .writeTimeout(30, TimeUnit.SECONDS)
            .build();
        this.gson = new Gson();
    }
    
    /**
     * Creates a new OpenAIOAuthTokenManager with existing credentials.
     * 
     * @param credentialsJson JSON string containing access_token, refresh_token, expires_at, account_id
     */
    public OpenAIOAuthTokenManager(String credentialsJson) {
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
     * Gets the ChatGPT account ID (for organization subscriptions).
     * 
     * @return The account ID, or null if not available
     */
    public String getAccountId() {
        return accountId;
    }
    
    /**
     * Starts the OAuth authorization flow by opening the browser.
     * Returns the code verifier needed for token exchange.
     * Uses the default redirect URI (manual code entry).
     * 
     * @return The code verifier to use when calling completeAuthorization
     */
    public String startAuthorizationFlow() {
        return startAuthorizationFlow(DEFAULT_REDIRECT_URI);
    }
    
    /**
     * Starts the OAuth authorization flow by opening the browser with a custom redirect URI.
     * 
     * @param redirectUri The redirect URI to use (for callback server)
     * @return The code verifier to use when calling completeAuthorization
     */
    public String startAuthorizationFlow(String redirectUri) {
        // Generate PKCE parameters
        pendingCodeVerifier = generateCodeVerifier();
        String codeChallenge = generateCodeChallenge(pendingCodeVerifier);
        pendingState = generateState();
        pendingRedirectUri = redirectUri;
        
        // Build authorization URL
        String authUrl = buildAuthorizationUrl(codeChallenge, pendingState, redirectUri);
        
        // Debug: Log the auth URL (redact sensitive parts)
        Msg.info(this, "Opening browser for OpenAI Codex OAuth authentication...");
        Msg.debug(this, "Auth URL (code_challenge redacted): " + 
            authUrl.replaceAll("code_challenge=[^&]+", "code_challenge=REDACTED"));
        
        openBrowser(authUrl);
        
        return pendingCodeVerifier;
    }
    
    /**
     * Starts the OAuth authorization flow with automatic callback capture.
     * Opens a local HTTP server to capture the OAuth callback automatically.
     * 
     * @return The OAuthCallbackServer that will receive the callback
     * @throws IOException If the callback server cannot be started
     */
    public OAuthCallbackServer startAuthorizationFlowWithCallback() throws IOException {
        // Generate PKCE parameters
        pendingCodeVerifier = generateCodeVerifier();
        String codeChallenge = generateCodeChallenge(pendingCodeVerifier);
        pendingState = generateState();
        
        // Create and start callback server
        callbackServer = OAuthCallbackServer.forOpenAI(pendingState);
        callbackServer.start();
        
        // Use the callback server's redirect URI
        pendingRedirectUri = callbackServer.getRedirectUri();
        
        // Build authorization URL with callback server's redirect URI
        String authUrl = buildAuthorizationUrl(codeChallenge, pendingState, pendingRedirectUri);
        
        Msg.info(this, "Opening browser for OpenAI Codex OAuth authentication with automatic callback...");
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
            completeAuthorization(code, pendingCodeVerifier);
        } finally {
            server.stop();
            callbackServer = null;
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
     * 
     * @param authorizationCode The authorization code from the browser URL
     * @param codeVerifier The code verifier from startAuthorizationFlow
     * @throws IOException If the token exchange fails
     */
    public void completeAuthorization(String authorizationCode, String codeVerifier) throws IOException {
        TokenResponse tokens = exchangeCodeForTokens(authorizationCode, codeVerifier);
        
        this.accessToken = tokens.accessToken;
        this.refreshToken = tokens.refreshToken;
        this.expiresAt = System.currentTimeMillis() + (tokens.expiresIn * 1000L);
        
        // Extract account ID from tokens
        this.accountId = extractAccountId(tokens.idToken, tokens.accessToken);
        
        Msg.info(this, "OpenAI Codex OAuth authentication successful!" + 
            (accountId != null ? " Account ID: " + accountId : ""));
        
        // Clean up
        pendingCodeVerifier = null;
        pendingState = null;
    }
    
    /**
     * Performs authentication with a manually entered authorization code or URL.
     * Accepts either:
     * - The full redirect URL (http://localhost:1455/auth/callback?code=XXX&state=YYY)
     * - Just the code value
     * 
     * @param input The code or URL copied from the browser
     * @throws Exception If authentication fails
     */
    public void authenticateWithCode(String input) throws Exception {
        if (pendingCodeVerifier == null) {
            throw new IllegalStateException("Call startAuthorizationFlow() first to open the browser");
        }
        
        String code = extractCodeFromInput(input.trim());
        Msg.info(this, "Extracted authorization code: " + code.substring(0, Math.min(20, code.length())) + "...");
        
        completeAuthorization(code, pendingCodeVerifier);
    }
    
    /**
     * Extracts the authorization code from user input.
     * Handles full URL, code#state format, or just the code.
     */
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
                            Msg.info(this, "Extracted code from URL");
                            return java.net.URLDecoder.decode(pair[1], StandardCharsets.UTF_8);
                        }
                    }
                }
            } catch (Exception e) {
                Msg.debug(this, "Failed to parse as URL, using input as-is: " + e.getMessage());
            }
        }
        
        // Try code#state format
        if (input.contains("#")) {
            return input.split("#")[0];
        }
        
        // Return as-is
        return input;
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
        
        Msg.info(this, "Refreshing OpenAI Codex access token...");
        
        // OpenAI uses form-encoded body for token refresh
        FormBody formBody = new FormBody.Builder()
            .add("grant_type", "refresh_token")
            .add("refresh_token", refreshToken)
            .add("client_id", CLIENT_ID)
            .build();
        
        Request request = new Request.Builder()
            .url(TOKEN_ENDPOINT)
            .post(formBody)
            .header("Content-Type", "application/x-www-form-urlencoded")
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
            if (json.has("refresh_token") && !json.get("refresh_token").isJsonNull()) {
                this.refreshToken = json.get("refresh_token").getAsString();
            }
            this.expiresAt = System.currentTimeMillis() + (json.get("expires_in").getAsInt() * 1000L);
            
            // Update account ID if present in new tokens
            if (json.has("id_token") && !json.get("id_token").isJsonNull()) {
                String newAccountId = extractAccountIdFromToken(json.get("id_token").getAsString());
                if (newAccountId != null) {
                    this.accountId = newAccountId;
                }
            }
            
            Msg.info(this, "OpenAI Codex access token refreshed successfully");
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
        accountId = null;
    }
    
    /**
     * Clears all stored credentials.
     */
    public void logout() {
        accessToken = null;
        refreshToken = null;
        expiresAt = 0;
        accountId = null;
        Msg.info(this, "OpenAI OAuth credentials cleared");
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
        json.addProperty("account_id", accountId != null ? accountId : "");
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
            if (obj.has("account_id") && !obj.get("account_id").isJsonNull()) {
                this.accountId = obj.get("account_id").getAsString();
                if (this.accountId.isEmpty()) {
                    this.accountId = null;
                }
            }
            
            Msg.debug(this, "Loaded OpenAI OAuth credentials from JSON");
            
        } catch (Exception e) {
            Msg.warn(this, "Failed to parse OpenAI OAuth credentials: " + e.getMessage());
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
     * Generates a random state parameter for CSRF protection.
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
     * Includes Codex-specific parameters required by the API.
     * 
     * Based on codex-cli-rs OAuth implementation.
     */
    private String buildAuthorizationUrl(String codeChallenge, String state) {
        return buildAuthorizationUrl(codeChallenge, state, DEFAULT_REDIRECT_URI);
    }
    
    /**
     * Builds the OAuth authorization URL with all required parameters and custom redirect URI.
     * Includes Codex-specific parameters required by the API.
     * 
     * Based on codex-cli-rs OAuth implementation.
     */
    private String buildAuthorizationUrl(String codeChallenge, String state, String redirectUri) {
        try {
            // Build URL with all required parameters matching codex-cli-rs exactly
            StringBuilder url = new StringBuilder(AUTH_ENDPOINT);
            url.append("?response_type=code");
            url.append("&client_id=").append(urlEncode(CLIENT_ID));
            url.append("&redirect_uri=").append(urlEncode(redirectUri));
            url.append("&scope=").append(urlEncode(SCOPES));
            url.append("&code_challenge=").append(urlEncode(codeChallenge));
            url.append("&code_challenge_method=S256");
            url.append("&state=").append(urlEncode(state));
            // Codex-specific parameters (from codex-cli-rs)
            url.append("&id_token_add_organizations=true");
            url.append("&codex_cli_simplified_flow=true");
            url.append("&originator=codex_cli_rs");
            
            String finalUrl = url.toString();
            Msg.info(this, "Generated OAuth URL: " + finalUrl);
            return finalUrl;
        } catch (Exception e) {
            throw new RuntimeException("Failed to build authorization URL", e);
        }
    }
    
    /**
     * URL-encodes a string using application/x-www-form-urlencoded format.
     */
    private String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
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
     * OpenAI uses form-encoded body (not JSON like Anthropic).
     */
    private TokenResponse exchangeCodeForTokens(String code, String codeVerifier) throws IOException {
        // Use the redirect URI from the auth flow, or default
        String redirectUri = pendingRedirectUri != null ? pendingRedirectUri : DEFAULT_REDIRECT_URI;
        
        // OpenAI uses form-encoded body
        FormBody formBody = new FormBody.Builder()
            .add("grant_type", "authorization_code")
            .add("code", code)
            .add("redirect_uri", redirectUri)
            .add("client_id", CLIENT_ID)
            .add("code_verifier", codeVerifier)
            .build();
        
        Request request = new Request.Builder()
            .url(TOKEN_ENDPOINT)
            .post(formBody)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .build();
        
        try (Response response = httpClient.newCall(request).execute()) {
            String body = response.body() != null ? response.body().string() : "";
            
            if (!response.isSuccessful()) {
                throw new IOException("Token exchange failed: " + response.code() + " - " + body);
            }
            
            JsonObject json = gson.fromJson(body, JsonObject.class);
            
            return new TokenResponse(
                json.get("access_token").getAsString(),
                json.has("refresh_token") && !json.get("refresh_token").isJsonNull() 
                    ? json.get("refresh_token").getAsString() : null,
                json.get("expires_in").getAsInt(),
                json.has("id_token") && !json.get("id_token").isJsonNull()
                    ? json.get("id_token").getAsString() : null
            );
        }
    }
    
    /**
     * Token response from the OAuth server.
     */
    private record TokenResponse(String accessToken, String refreshToken, int expiresIn, String idToken) {}
    
    // =========================================================================
    // Account ID Extraction
    // =========================================================================
    
    /**
     * Extracts the ChatGPT account ID from OAuth tokens.
     * The account ID is needed for organization subscriptions and is
     * sent in the chatgpt-account-id header.
     */
    private String extractAccountId(String idToken, String accessToken) {
        // Try id_token first
        if (idToken != null) {
            String accountId = extractAccountIdFromToken(idToken);
            if (accountId != null) {
                return accountId;
            }
        }
        
        // Fall back to access_token
        if (accessToken != null) {
            return extractAccountIdFromToken(accessToken);
        }
        
        return null;
    }
    
    /**
     * Extracts account ID from a JWT token.
     */
    private String extractAccountIdFromToken(String token) {
        try {
            JsonObject claims = parseJwtClaims(token);
            if (claims == null) {
                return null;
            }
            
            // Direct claim
            if (claims.has("chatgpt_account_id") && !claims.get("chatgpt_account_id").isJsonNull()) {
                return claims.get("chatgpt_account_id").getAsString();
            }
            
            // Nested in auth namespace
            if (claims.has("https://api.openai.com/auth")) {
                JsonElement authElement = claims.get("https://api.openai.com/auth");
                if (authElement.isJsonObject()) {
                    JsonObject authNamespace = authElement.getAsJsonObject();
                    if (authNamespace.has("chatgpt_account_id") && !authNamespace.get("chatgpt_account_id").isJsonNull()) {
                        return authNamespace.get("chatgpt_account_id").getAsString();
                    }
                }
            }
            
            // From organizations array
            if (claims.has("organizations")) {
                JsonElement orgsElement = claims.get("organizations");
                if (orgsElement.isJsonArray()) {
                    JsonArray orgs = orgsElement.getAsJsonArray();
                    if (!orgs.isEmpty()) {
                        JsonElement firstOrg = orgs.get(0);
                        if (firstOrg.isJsonObject()) {
                            JsonObject org = firstOrg.getAsJsonObject();
                            if (org.has("id") && !org.get("id").isJsonNull()) {
                                return org.get("id").getAsString();
                            }
                        }
                    }
                }
            }
            
        } catch (Exception e) {
            Msg.debug(this, "Failed to extract account ID from token: " + e.getMessage());
        }
        
        return null;
    }
    
    /**
     * Parses claims from a JWT token (without verification).
     */
    private JsonObject parseJwtClaims(String token) {
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            return null;
        }
        
        try {
            // Add padding if needed
            String payload = parts[1];
            int padding = 4 - payload.length() % 4;
            if (padding != 4) {
                payload += "=".repeat(padding);
            }
            
            byte[] decoded = Base64.getUrlDecoder().decode(payload);
            return gson.fromJson(new String(decoded, StandardCharsets.UTF_8), JsonObject.class);
        } catch (Exception e) {
            return null;
        }
    }
    
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
