# Spring Security OAuth 2.0 - Complete API Flow & Architecture

## Understanding the Architecture First

Before diving into code, understand this: Spring Security implements OAuth 2.0 through several interconnected components that work together in a specific sequence. The flow follows this pattern:

1. **HTTP Request arrives** → Security Filter Chain intercepts it
2. **OAuth2LoginAuthenticationFilter** decides if it's an OAuth-related request
3. **Authentication Manager** coordinates the authentication process
4. **Authentication Providers** perform the actual OAuth logic
5. **Client Registration Repository** provides OAuth provider configuration
6. **Access Token Response Client** exchanges authorization code for tokens
7. **User Info Endpoint** fetches user details
8. **Security Context** stores the authenticated principal

This is the dance between filters, managers, providers, and repositories. Let's understand each piece.

---

## Part 1: Entry Point - Security Filter Chain

The security filter chain is where everything starts. It's a series of filters that Spring Security runs for every HTTP request.

### Understanding the Filter Chain

```java
/**
 * Spring Security's DelegatingFilterProxy acts as the entry point.
 * It's registered with the servlet container and intercepts ALL requests.
 * 
 * When a request comes in:
 * 1. Servlet container calls DelegatingFilterProxy
 * 2. DelegatingFilterProxy delegates to FilterChainProxy (the real filter chain)
 * 3. FilterChainProxy runs a series of security filters in order
 * 
 * Important: The order of filters matters!
 * Filters run in this order (simplified):
 * - SecurityContextPersistenceFilter (loads authentication from session)
 * - LogoutFilter (handles /logout requests)
 * - OAuth2LoginAuthenticationFilter (handles OAuth login)
 * - UsernamePasswordAuthenticationFilter (handles form login)
 * - ExceptionTranslationFilter (catches authentication exceptions)
 * - FilterSecurityInterceptor (checks if user has permission)
 * 
 * Each filter checks if it should handle the request.
 * If yes, it processes it. If no, it passes to the next filter.
 */
```

### The OAuth2LoginAuthenticationFilter

This is the filter that specifically handles OAuth 2.0 login. This is where the OAuth flow actually begins.

```java
package org.springframework.security.oauth2.client.web;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.web.util.UriComponentsBuilder;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * This filter is the entry point for OAuth 2.0 Authorization Code Flow.
 * It intercepts TWO types of requests:
 * 1. Authorization requests: /oauth2/authorization/{registrationId}
 * 2. Callback requests: /oauth2/callback/{registrationId}
 */
public class CustomOAuth2LoginAuthenticationFilter extends OncePerRequestFilter {
    
    // These repositories and clients are injected by Spring
    private final ClientRegistrationRepository clientRegistrationRepository;
    private final OAuth2AuthorizedClientRepository authorizedClientRepository;
    private final OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> 
        accessTokenResponseClient;
    private final OAuth2UserService<OAuth2UserRequest, OAuth2User> 
        userInfoEndpointClient;
    
    /**
     * This method is called for EVERY HTTP request.
     * The filter decides: "Is this MY request to handle?"
     */
    @Override
    protected void doFilterInternal(
            HttpServletRequest request, 
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {
        
        // ========================================================
        // STEP 1: Identify if this is an OAuth request
        // ========================================================
        
        // Check if this is an authorization initiation request
        // Example: GET /oauth2/authorization/google
        if (isAuthorizationRequest(request)) {
            // This is when user clicks "Sign in with Google"
            // We need to redirect user to Google's authorization server
            
            /*
             * ACTION: Build the authorization request
             * This involves:
             * 1. Getting the ClientRegistration for the provider
             * 2. Creating a state parameter for CSRF protection
             * 3. Building the redirect URL
             * 4. Redirecting browser to OAuth provider
             */
            
            handleAuthorizationRequest(request, response);
            return; // Don't continue filter chain
        }
        
        // Check if this is an authorization callback
        // Example: GET /oauth2/callback/google?code=XXX&state=YYY
        if (isAuthorizationResponse(request)) {
            // OAuth provider redirected user back with authorization code
            // Now we need to exchange code for access token
            
            /*
             * ACTION: Attempt to authenticate using the authorization code
             * This is where the REAL OAuth protocol happens:
             * 1. Extract authorization code and state from request
             * 2. Validate state parameter
             * 3. Create OAuth2LoginAuthenticationToken with the code
             * 4. Pass to AuthenticationManager for processing
             * 5. AuthenticationManager will call AuthenticationProviders
             * 
             * We'll explain AuthenticationManager next
             */
            
            Authentication authenticationRequest = 
                this.authenticationConverter.convert(request);
            
            // This is the key line - we're asking the AuthenticationManager
            // to authenticate using OAuth 2.0
            Authentication authenticationResult;
            try {
                authenticationResult = this.authenticationManager
                    .authenticate(authenticationRequest);
            } catch (AuthenticationException failed) {
                // If OAuth authentication fails, handle the error
                this.authenticationFailureHandler.onAuthenticationFailure(
                    request, response, failed);
                return;
            }
            
            // Authentication succeeded!
            // Store the result and continue
            this.authenticationSuccessHandler.onAuthenticationSuccess(
                request, response, authenticationResult);
            return;
        }
        
        // Not an OAuth request, continue to next filter
        filterChain.doFilter(request, response);
    }
    
    /**
     * Helper method to detect authorization initiation requests
     */
    private boolean isAuthorizationRequest(HttpServletRequest request) {
        String path = request.getRequestURI();
        // Pattern: /oauth2/authorization/{registrationId}
        return path.matches("/oauth2/authorization/.*") && 
               request.getMethod().equals("GET");
    }
    
    /**
     * Helper method to detect OAuth provider callback requests
     */
    private boolean isAuthorizationResponse(HttpServletRequest request) {
        String path = request.getRequestURI();
        String code = request.getParameter("code");
        // Pattern: /oauth2/callback/{registrationId}?code=...
        return path.matches("/oauth2/callback/.*") && 
               code != null && 
               request.getMethod().equals("GET");
    }
}
```

**Key Insight**: The filter doesn't do the actual OAuth logic itself. It's a router. It recognizes OAuth requests and passes them to the AuthenticationManager for processing. This separation of concerns is important.

---

## Part 2: Authentication Manager - The Orchestrator

The AuthenticationManager is the central coordinator. When the filter calls `authenticationManager.authenticate(authenticationRequest)`, the manager decides which AuthenticationProvider should handle this request.

### The AuthenticationManager Interface

```java
package org.springframework.security.authentication;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

/**
 * The AuthenticationManager is like a router for authentication requests.
 * It receives an Authentication object (which contains credentials or tokens)
 * and returns an authenticated Authentication object.
 * 
 * The key principle: AuthenticationManager doesn't know HOW to authenticate.
 * It delegates to AuthenticationProviders.
 */
public interface AuthenticationManager {
    /**
     * This is the main method.
     * Input: An Authentication with unauthenticated credentials
     * Output: An Authentication with authenticated principal (user details)
     * 
     * The manager iterates through providers and asks:
     * "Can you handle this authentication type?"
     * When a provider says "yes", it delegates the authentication to it.
     */
    Authentication authenticate(Authentication authentication) 
        throws AuthenticationException;
}

/**
 * The default implementation
 */
public class ProviderManager implements AuthenticationManager {
    
    private List<AuthenticationProvider> providers;
    
    @Override
    public Authentication authenticate(Authentication authentication) 
            throws AuthenticationException {
        
        AuthenticationException lastException = null;
        
        // Iterate through each authentication provider
        for (AuthenticationProvider provider : this.providers) {
            // Step 1: Check if this provider supports this authentication type
            if (!provider.supports(authentication.getClass())) {
                // This provider doesn't handle this type, skip to next
                continue;
            }
            
            // Step 2: This provider supports it, let it authenticate
            try {
                // The provider does the actual authentication work
                Authentication result = provider.authenticate(authentication);
                
                // Step 3: If successful, return the authenticated token
                if (result != null) {
                    return result;
                }
            } catch (AuthenticationException e) {
                lastException = e;
                // Try next provider
            }
        }
        
        // No provider succeeded
        throw lastException;
    }
}
```

**Understanding the Flow**: When the OAuth2LoginAuthenticationFilter calls `authenticationManager.authenticate(oauthToken)`, the ProviderManager loops through registered providers asking "Who can handle this OAuth2LoginAuthenticationToken?" The OAuth2AuthenticationProvider says "I can!" and takes over.

---

## Part 3: Authentication Provider - The Actual Work

This is where the OAuth 2.0 protocol actually happens. The provider exchanges the authorization code for tokens and fetches user information.

### The AuthenticationProvider Interface

```java
package org.springframework.security.authentication;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

/**
 * An AuthenticationProvider knows HOW to authenticate for a specific mechanism.
 * Think of it as a specialist. UsernamePasswordAuthenticationProvider handles
 * username/password, OAuth2AuthenticationProvider handles OAuth 2.0, etc.
 */
public interface AuthenticationProvider {
    /**
     * Actually perform the authentication.
     * This receives the unauthenticated Authentication object
     * and returns the authenticated one.
     */
    Authentication authenticate(Authentication authentication) 
        throws AuthenticationException;
    
    /**
     * Does this provider support this authentication type?
     * For OAuth2, it would return true for OAuth2LoginAuthenticationToken
     */
    boolean supports(Class<?> authentication);
}
```

### The OAuth2 Authentication Provider

```java
package org.springframework.security.oauth2.client.authentication;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.user.OAuth2User;

/**
 * This is the OAuth 2.0 specific provider.
 * It handles the entire Authorization Code Flow.
 * 
 * Reminder of what happens:
 * Input: OAuth2LoginAuthenticationToken with authorization code
 * Output: OAuth2AuthenticationToken with OAuth2User (authenticated principal)
 */
public class CustomOAuth2AuthenticationProvider implements AuthenticationProvider {
    
    // These are the key OAuth 2.0 components
    private final ClientRegistrationRepository clientRegistrationRepository;
    private final OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> 
        accessTokenResponseClient;
    private final OAuth2UserService<OAuth2UserRequest, OAuth2User> 
        oauth2UserService;
    
    /**
     * This is the main authentication method.
     * It performs the OAuth 2.0 Authorization Code Flow:
     * 1. Exchange authorization code for access token
     * 2. Fetch user information using access token
     * 3. Create authenticated Authentication object
     */
    @Override
    public Authentication authenticate(Authentication authentication) 
            throws AuthenticationException {
        
        // Cast to OAuth authentication token
        // This token contains the authorization code and provider information
        OAuth2LoginAuthenticationToken authorizationCodeToken = 
            (OAuth2LoginAuthenticationToken) authentication;
        
        // ========================================================
        // STEP 1: Get the OAuth Provider Configuration
        // ========================================================
        
        /**
         * We need to know:
         * - What is the provider's authorization URI?
         * - What is the token URI?
         * - What are our client credentials?
         * 
         * All this information comes from ClientRegistration,
         * which we retrieve from ClientRegistrationRepository.
         * 
         * The repository is typically configured in application.properties,
         * but you can implement it yourself.
         */
        
        String registrationId = authorizationCodeToken.getClientRegistrationId();
        
        ClientRegistration clientRegistration = 
            this.clientRegistrationRepository.findByRegistrationId(registrationId);
        
        if (clientRegistration == null) {
            throw new OAuth2AuthenticationException(
                "Unknown client registration: " + registrationId);
        }
        
        // ========================================================
        // STEP 2: Exchange Authorization Code for Access Token
        // ========================================================
        
        /**
         * This is the crucial step - we're doing the backend-to-backend
         * exchange that makes OAuth 2.0 secure.
         * 
         * We send:
         * - Authorization code (from the request)
         * - Client ID and Client Secret (from ClientRegistration)
         * - Grant type: "authorization_code"
         * - Redirect URI
         * 
         * The OAuth provider responds with:
         * - Access Token
         * - Refresh Token
         * - Token Type and Expiration
         */
        
        // Create the authorization code grant request
        OAuth2AuthorizationCodeGrantRequest codeGrantRequest = 
            new OAuth2AuthorizationCodeGrantRequest(
                clientRegistration,
                authorizationCodeToken.getAuthorizationCode(),
                authorizationCodeToken.getRedirectUri(),
                authorizationCodeToken.getState()
            );
        
        // Exchange the code for tokens
        // This is where accessTokenResponseClient does its work
        OAuth2AccessTokenResponse accessTokenResponse;
        try {
            accessTokenResponse = this.accessTokenResponseClient
                .getTokenResponse(codeGrantRequest);
        } catch (OAuth2AuthorizationException e) {
            // If token exchange fails, the OAuth provider returned an error
            throw new OAuth2AuthenticationException(e.getError(), e);
        }
        
        // Extract the access token from the response
        OAuth2AccessToken accessToken = accessTokenResponse.getAccessToken();
        
        /**
         * At this point, we have a valid access token from the OAuth provider.
         * The access token proves that the user authenticated with the provider.
         * Now we need to fetch the user's details using this token.
         */
        
        // ========================================================
        // STEP 3: Fetch User Information from OAuth Provider
        // ========================================================
        
        /**
         * We send the access token to the OAuth provider's user info endpoint.
         * The provider returns the user's profile information
         * (name, email, picture, etc.)
         * 
         * This is where OAuth2UserService comes in.
         */
        
        // Create a user request that contains the access token
        OAuth2UserRequest userRequest = new OAuth2UserRequest(
            clientRegistration,
            accessToken
        );
        
        // Fetch user info using the access token
        // oauth2UserService makes an HTTP call to the provider's user info endpoint
        OAuth2User oAuth2User;
        try {
            oAuth2User = this.oauth2UserService.loadUser(userRequest);
        } catch (OAuth2AuthenticationException e) {
            // If user info fetch fails
            throw new OAuth2AuthenticationException(e.getError(), e);
        }
        
        /**
         * Now we have:
         * - Access Token (proof we can call provider APIs)
         * - OAuth2User (the authenticated user's information)
         * 
         * We can now create a fully authenticated Authentication object.
         */
        
        // ========================================================
        // STEP 4: Create Authenticated Authentication Object
        // ========================================================
        
        /**
         * The OAuth2AuthenticationToken represents a fully authenticated user.
         * It contains:
         * - The OAuth2User (principal)
         * - The authorities/roles
         * - The client registration ID
         * 
         * When this is returned, Spring Security knows the user is authenticated.
         */
        
        OAuth2AuthenticationToken authenticationToken = new OAuth2AuthenticationToken(
            oAuth2User,
            oAuth2User.getAuthorities(),
            clientRegistration.getRegistrationId()
        );
        
        // Mark as authenticated
        authenticationToken.setAuthenticated(true);
        
        return authenticationToken;
    }
    
    /**
     * Does this provider handle OAuth 2.0 login tokens?
     */
    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2LoginAuthenticationToken.class
            .isAssignableFrom(authentication);
    }
}
```

**Key Insight**: The OAuth2AuthenticationProvider is where all the actual OAuth work happens. It orchestrates three sub-components:
1. ClientRegistrationRepository - knows the OAuth provider configuration
2. OAuth2AccessTokenResponseClient - exchanges code for tokens
3. OAuth2UserService - fetches user information

Each of these is replaceable, allowing customization at different levels.

---

## Part 4: Client Registration Repository - OAuth Provider Configuration

The repository is how Spring Security knows about your OAuth providers (Google, GitHub, etc.). It stores their configuration.

### Understanding ClientRegistration

```java
package org.springframework.security.oauth2.client.registration;

/**
 * ClientRegistration represents the configuration for a single OAuth provider.
 * It contains all the information needed to authenticate with that provider.
 */
public class ClientRegistration {
    
    // Your application's credentials
    private String clientId;              // Identifies your app to the provider
    private String clientSecret;          // Secret to prove your app's identity
    
    // OAuth provider endpoints
    private String authorizationUri;      // Where to redirect user for login
    private String tokenUri;              // Where to exchange code for token
    private String userInfoUri;           // Where to fetch user details
    
    // Scopes - what permissions we're requesting
    private Set<String> scopes;
    
    // How to identify the user in the response
    private String userNameAttributeName;
    
    // Misc
    private String registrationId;        // Unique identifier (e.g., "google", "github")
    private String redirectUri;           // Where provider redirects user back to
    private AuthorizationGrantType authorizationGrantType;
}

/**
 * Example: Google's ClientRegistration would look like:
 * - registrationId: "google"
 * - clientId: "123456.apps.googleusercontent.com"
 * - clientSecret: "secret_value"
 * - authorizationUri: "https://accounts.google.com/o/oauth2/v2/auth"
 * - tokenUri: "https://oauth2.googleapis.com/token"
 * - userInfoUri: "https://www.googleapis.com/oauth2/v2/userinfo"
 * - userNameAttributeName: "id"
 * - redirectUri: "http://localhost:8080/oauth2/callback/{registrationId}"
 */
```

### ClientRegistrationRepository Interface

```java
package org.springframework.security.oauth2.client.registration;

/**
 * The repository is how your application accesses ClientRegistration objects.
 * 
 * Think of it like a database query. When you need to know about Google's
 * OAuth configuration, you ask the repository.
 */
public interface ClientRegistrationRepository {
    /**
     * Find a ClientRegistration by registration ID
     * For example: findByRegistrationId("google") returns Google's config
     */
    ClientRegistration findByRegistrationId(String registrationId);
    
    // Can also have iterator method to get all registrations
    Iterator<ClientRegistration> iterator();
}

/**
 * In-memory implementation - useful for understanding
 */
public class InMemoryClientRegistrationRepository implements ClientRegistrationRepository {
    
    private final Map<String, ClientRegistration> registrations = new HashMap<>();
    
    public InMemoryClientRegistrationRepository(ClientRegistration... registrations) {
        for (ClientRegistration reg : registrations) {
            this.registrations.put(reg.getRegistrationId(), reg);
        }
    }
    
    @Override
    public ClientRegistration findByRegistrationId(String registrationId) {
        return this.registrations.get(registrationId);
    }
    
    @Override
    public Iterator<ClientRegistration> iterator() {
        return this.registrations.values().iterator();
    }
}

/**
 * Real implementation - loaded from application.properties
 * Spring Security provides InMemoryClientRegistrationRepository by default
 * when you configure OAuth in application.properties
 */
public class PropertiesClientRegistrationRepository 
        implements ClientRegistrationRepository {
    
    /**
     * This is how Spring loads your OAuth configuration:
     * spring.security.oauth2.client.registration.google.client-id=...
     * spring.security.oauth2.client.registration.google.client-secret=...
     * 
     * It creates ClientRegistration objects from these properties
     * and stores them in a map.
     */
    
    private Map<String, ClientRegistration> registrations;
    
    public PropertiesClientRegistrationRepository(
            OAuth2ClientProperties properties) {
        
        // Convert OAuth2ClientProperties to ClientRegistration objects
        // This happens automatically when Spring sees oauth2.client properties
        this.registrations = loadFromProperties(properties);
    }
    
    @Override
    public ClientRegistration findByRegistrationId(String registrationId) {
        return registrations.get(registrationId);
    }
}
```

**Why This Matters**: The ClientRegistrationRepository is the source of truth for OAuth configuration. By implementing it yourself, you can load OAuth configurations from a database, environment variables, or any other source instead of just properties files.

---

## Part 5: Access Token Response Client - Code to Token Exchange

This is the component that actually makes the HTTP request to the OAuth provider to exchange the authorization code for an access token.

### OAuth2AccessTokenResponseClient Interface

```java
package org.springframework.security.oauth2.client.endpoint;

import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.web.client.RestOperations;

/**
 * This client is responsible for exchanging authorization code for access token.
 * 
 * Remember from the OAuth flow:
 * 1. User gets authorization code from provider
 * 2. Client backend exchanges code + client_secret for access token
 * 3. This component does step 2
 * 
 * Generic type parameter indicates what kind of grant request it handles
 */
public interface OAuth2AccessTokenResponseClient<T extends OAuth2AuthorizationGrantRequest> {
    /**
     * Exchange the authorization code for access token
     * 
     * Input: Grant request containing code, client credentials, token endpoint
     * Output: OAuth2AccessTokenResponse containing access token, refresh token, etc.
     */
    OAuth2AccessTokenResponse getTokenResponse(T request) 
        throws OAuth2AuthorizationException;
}

/**
 * Specific implementation for Authorization Code Flow
 */
public interface OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest>
        extends OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> {
    
    // Inherited from parent
}

/**
 * Default implementation provided by Spring
 */
public class DefaultAuthorizationCodeTokenResponseClient 
        implements OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> {
    
    // Uses RestTemplate to make HTTP requests
    private RestOperations restOperations;
    
    @Override
    public OAuth2AccessTokenResponse getTokenResponse(
            OAuth2AuthorizationCodeGrantRequest authorizationCodeGrantRequest) 
            throws OAuth2AuthorizationException {
        
        ClientRegistration clientRegistration = 
            authorizationCodeGrantRequest.getClientRegistration();
        
        /**
         * Construct the token request that will be sent to the OAuth provider.
         * This is the backend-to-backend call.
         */
        
        RequestEntity<MultiValueMap<String, String>> request = 
            this.requestEntityConverter.convert(authorizationCodeGrantRequest);
        
        /**
         * The request will look like:
         * 
         * POST https://oauth2.googleapis.com/token
         * Content-Type: application/x-www-form-urlencoded
         * 
         * grant_type=authorization_code
         * code=authorization_code_value
         * redirect_uri=http://localhost:8080/oauth2/callback/google
         * client_id=YOUR_CLIENT_ID.apps.googleusercontent.com
         * client_secret=YOUR_CLIENT_SECRET
         * 
         * The "code" and "client_secret" are the crucial parts.
         * The provider will verify the code was issued to this client.
         */
        
        ResponseEntity<Map<String, Object>> response;
        try {
            // Make the HTTP request to the token endpoint
            response = this.restOperations.exchange(request, 
                new ParameterizedTypeReference<Map<String, Object>>() {});
        } catch (Exception e) {
            throw new OAuth2AuthorizationException(
                "Token endpoint error", e);
        }
        
        /**
         * Parse the response from the OAuth provider.
         * The response should contain:
         * {
         *   "access_token": "ya29.a0AfH6SMB...",
         *   "expires_in": 3600,
         *   "refresh_token": "1//0gF...",
         *   "scope": "openid profile email",
         *   "token_type": "Bearer"
         * }
         */
        
        Map<String, Object> tokenResponseParameters = response.getBody();
        
        // Convert the response to OAuth2AccessTokenResponse object
        OAuth2AccessTokenResponse accessTokenResponse = 
            this.responseConverter.convert(tokenResponseParameters);
        
        return accessTokenResponse;
    }
}

/**
 * Custom implementation example - for demonstrating how to customize
 */
public class CustomAuthorizationCodeTokenResponseClient 
        implements OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> {
    
    private RestOperations restOperations;
    
    @Override
    public OAuth2AccessTokenResponse getTokenResponse(
            OAuth2AuthorizationCodeGrantRequest authorizationCodeGrantRequest) 
            throws OAuth2AuthorizationException {
        
        ClientRegistration clientReg = 
            authorizationCodeGrantRequest.getClientRegistration();
        
        String authorizationCode = 
            authorizationCodeGrantRequest.getAuthorizationCode();
        
        String redirectUri = 
            authorizationCodeGrantRequest.getRedirectUri();
        
        /**
         * Here's where you can customize:
         * - Add custom headers
         * - Modify request parameters
         * - Handle provider-specific response formats
         * - Add logging/auditing
         * - Implement retry logic
         * 
         * For example, some OAuth providers have slightly different
         * response formats or require additional parameters.
         */
        
        // Build request parameters
        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
        parameters.add("grant_type", "authorization_code");
        parameters.add("code", authorizationCode);
        parameters.add("redirect_uri", redirectUri);
        parameters.add("client_id", clientReg.getClientId());
        parameters.add("client_secret", clientReg.getClientSecret());
        
        /**
         * Add custom parameters if needed
         * Some providers require additional parameters
         */
        // parameters.add("custom_param", "custom_value");
        
        // Create the request
        RequestEntity<MultiValueMap<String, String>> request = 
            RequestEntity.post(
                URI.create(clientReg.getProviderDetails().getTokenUri()))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(parameters);
        
        // Send the request
        ResponseEntity<Map<String, Object>> response = 
            restOperations.exchange(request, 
                new ParameterizedTypeReference<Map<String, Object>>() {});
        
        // Parse response and return
        return OAuth2AccessTokenResponse.withToken(
            (String) response.getBody().get("access_token"))
            .expiresIn(((Number) response.getBody()
                .get("expires_in")).longValue())
            .refreshToken((String) response.getBody()
                .get("refresh_token"))
            .build();
    }
}
```

**Understanding the Exchange**: The `getTokenResponse` method is doing the crucial OAuth step. It's making a backend-to-backend call, sending the authorization code AND the client secret to the OAuth provider. The provider verifies that the code was issued to this client and returns the access token.

---

## Part 6: OAuth2UserService - Fetching User Information

Once we have the access token, we use it to fetch the user's profile information from the OAuth provider.

### OAuth2UserService Interface

```java
package org.springframework.security.oauth2.client.userinfo;

import org.springframework.security.oauth2.core.user.OAuth2User;

/**
 * This service fetches user information from the OAuth provider
 * using the access token we just received.
 * 
 * Generic type: What type of request it handles
 * For Authorization Code Flow, it's OAuth2UserRequest
 */
public interface OAuth2UserService<R extends OAuth2UserRequest, U extends OAuth2User> {
    /**
     * Load user information from the OAuth provider
     * 
     * Input: OAuth2UserRequest containing access token and provider info
     * Output: OAuth2User containing the authenticated user's information
     * 
     * This makes an HTTP call to the provider's user info endpoint
     * using the access token as authorization.
     */
    U loadUser(R userRequest) throws OAuth2AuthenticationException;
}

/**
 * Default implementation for standard OAuth 2.0 providers
 */
public class DefaultOAuth2UserService 
        implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {
    
    private RestOperations restOperations;
    
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) 
            throws OAuth2AuthenticationException {
        
        ClientRegistration clientRegistration = 
            userRequest.getClientRegistration();
        
        /**
         * The userRequest contains:
         * - ClientRegistration (knows where user info endpoint is)
         * - OAuth2AccessToken (the token we just received)
         * 
         * We'll use this token to make an authenticated request to the
         * user info endpoint.
         */
        
        // Get the user info endpoint URL
        String userInfoEndpointUri = clientRegistration
            .getProviderDetails()
            .getUserInfoEndpoint()
            .getUri();
        
        // Create request with Authorization header
        // The access token goes here
        RequestEntity<?> request = RequestEntity
            .get(URI.create(userInfoEndpointUri))
            .header("Authorization", 
                "Bearer " + userRequest.getAccessToken().getTokenValue())
            .build();
        
        /**
         * The request looks like:
         * GET https://www.googleapis.com/oauth2/v2/userinfo
         * Authorization: Bearer ya29.a0AfH6SMB...
         * 
         * The OAuth provider verifies the token and returns user info
         */
        
        ResponseEntity<Map<String, Object>> response;
        try {
            // Make the HTTP call to user info endpoint
            response = this.restOperations.exchange(request,
                new ParameterizedTypeReference<Map<String, Object>>() {});
        } catch (Exception e) {
            throw new OAuth2AuthenticationException(
                "Failed to fetch user information", e);
        }
        
        /**
         * The provider responds with user information:
         * {
         *   "id": "1234567890",
         *   "email": "user@gmail.com",
         *   "name": "John Doe",
         *   "picture": "https://lh3.googleusercontent.com/...",
         *   "verified_email": true
         * }
         */
        
        Map<String, Object> userAttributes = response.getBody();
        
        // Create OAuth2User from the response
        // This object will be the authenticated principal
        OAuth2User oAuth2User = new DefaultOAuth2User(
            // Authorities - what roles does the user have
            // In OAuth, this is usually just "ROLE_USER"
            Collections.singletonList(
                new SimpleGrantedAuthority("ROLE_USER")),
            // The user attributes from the provider
            userAttributes,
            // The attribute name that uniquely identifies the user
            // For Google, this is "id"
            clientRegistration
                .getProviderDetails()
                .getUserInfoEndpoint()
                .getUserNameAttributeName()
        );
        
        return oAuth2User;
    }
}

/**
 * Custom implementation example
 * This is useful when:
 * - You need to map OAuth attributes to your own user object
 * - You want to sync OAuth user with your database
 * - You need to assign custom roles/authorities
 * - You want to add additional user processing
 */
public class CustomOAuth2UserService 
        implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {
    
    private OAuth2UserService<OAuth2UserRequest, OAuth2User> delegate = 
        new DefaultOAuth2UserService();
    
    private UserRepository userRepository; // Your database
    
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) 
            throws OAuth2AuthenticationException {
        
        // First, use the default service to fetch user info
        OAuth2User oAuth2User = delegate.loadUser(userRequest);
        
        /**
         * Now you can customize:
         * - Save/update user in your database
         * - Fetch additional data
         * - Assign custom roles based on attributes
         * - Perform business logic
         */
        
        // Extract user information
        String email = oAuth2User.getAttribute("email");
        String name = oAuth2User.getAttribute("name");
        String providerId = oAuth2User.getAttribute("id");
        
        String registrationId = 
            userRequest.getClientRegistration().getRegistrationId();
        
        // Check if user already exists in your database
        User user = userRepository
            .findByEmailAndProvider(email, registrationId)
            .orElse(null);
        
        if (user == null) {
            // First time this user is logging in via this provider
            // Create new user in your database
            user = new User();
            user.setEmail(email);
            user.setName(name);
            user.setProvider(registrationId);
            user.setProviderId(providerId);
            user = userRepository.save(user);
        } else {
            // User exists, update their information
            user.setName(name);
            user.setLastLogin(Instant.now());
            userRepository.save(user);
        }
        
        // Return the OAuth2User (can wrap it with custom attributes)
        return oAuth2User;
    }
}
```

**Key Point**: The OAuth2UserService is where you can customize how user data from the OAuth provider is handled. By implementing this interface, you can:
- Save OAuth users to your database
- Map OAuth attributes to your application's user model
- Assign custom roles
- Integrate OAuth login with your existing user system

---

## Part 7: Authentication Objects - The Token Flow

Now let's understand the Authentication objects themselves - they represent different stages of authentication.

### Understanding Authentication Token Flow

```java
/**
 * The Authentication interface represents a security principal in Spring Security.
 * It goes through stages:
 * 1. UNAUTHENTICATED: Created from incoming request (has credentials but not verified)
 * 2. AUTHENTICATED: After provider verifies it (has verified principal)
 * 
 * Different implementations for different auth mechanisms:
 * - UsernamePasswordAuthenticationToken: For username/password
 * - OAuth2AuthenticationToken: For OAuth 2.0
 * - JWT/JwtAuthenticationToken: For JWT
 */

/**
 * STAGE 1: Unauthenticated OAuth2LoginAuthenticationToken
 * Created by OAuth2LoginAuthenticationFilter when it receives callback from OAuth provider
 */
public class OAuth2LoginAuthenticationToken extends AbstractAuthenticationToken {
    
    // Contains the authorization code from the provider
    private String authorizationCode;
    
    // Contains the state parameter (for CSRF validation)
    private String state;
    
    // Which OAuth provider (google, github, etc.)
    private String clientRegistrationId;
    
    // The original request URI (redirect_uri)
    private String redirectUri;
    
    /**
     * Constructor for unauthenticated token
     * This is created by the filter before passing to AuthenticationManager
     */
    public OAuth2LoginAuthenticationToken(
            String authorizationCode,
            String state,
            String clientRegistrationId,
            String redirectUri) {
        // Not authenticated yet
        super(null);  // No authorities yet
        
        this.authorizationCode = authorizationCode;
        this.state = state;
        this.clientRegistrationId = clientRegistrationId;
        this.redirectUri = redirectUri;
        
        // Mark as unauthenticated
        this.setAuthenticated(false);
    }
    
    // Getters...
    
    @Override
    public Object getCredentials() {
        // The authorization code is the credential
        return this.authorizationCode;
    }
    
    @Override
    public Object getPrincipal() {
        // Not yet available in unauthenticated token
        return null;
    }
}

/**
 * STAGE 2: Authenticated OAuth2AuthenticationToken
 * Created by OAuth2AuthenticationProvider after successful authentication
 */
public class OAuth2AuthenticationToken extends AbstractAuthenticationToken {
    
    // The authenticated user (contains name, email, picture, etc.)
    private OAuth2User principal;
    
    // Which provider authenticated this user
    private String authorizedClientRegistrationId;
    
    /**
     * Constructor for authenticated token
     * This is created by the provider and returned to filter
     */
    public OAuth2AuthenticationToken(
            OAuth2User principal,
            Collection<? extends GrantedAuthority> authorities,
            String authorizedClientRegistrationId) {
        super(authorities);
        
        this.principal = principal;
        this.authorizedClientRegistrationId = authorizedClientRegistrationId;
        
        // Mark as authenticated - Spring Security now trusts this
        this.setAuthenticated(true);
    }
    
    @Override
    public Object getCredentials() {
        // For OAuth, credentials are not needed anymore
        // Token is already authenticated
        return null;
    }
    
    @Override
    public Object getPrincipal() {
        // The authenticated OAuth2User
        return this.principal;
    }
    
    @Override
    public String getName() {
        return this.principal.getName();
    }
}

/**
 * The OAuth2User interface represents the authenticated user
 * It contains the user's information from the OAuth provider
 */
public interface OAuth2User extends AuthenticatedPrincipal {
    
    // Get all attributes returned by the OAuth provider
    Map<String, Object> getAttributes();
    
    // Get user authorities
    Collection<? extends GrantedAuthority> getAuthorities();
    
    // Get the user's name
    String getName();
}

/**
 * Default implementation
 */
public class DefaultOAuth2User implements OAuth2User {
    
    private Collection<? extends GrantedAuthority> authorities;
    private Map<String, Object> attributes;
    private String nameAttributeKey;
    
    public DefaultOAuth2User(
            Collection<? extends GrantedAuthority> authorities,
            Map<String, Object> attributes,
            String nameAttributeKey) {
        this.authorities = authorities;
        this.attributes = attributes;
        this.nameAttributeKey = nameAttributeKey;
    }
    
    @Override
    public String getName() {
        // Return the value of the name attribute
        // For Google: attributes.get("id")
        // For GitHub: attributes.get("id")
        return (String) this.attributes.get(this.nameAttributeKey);
    }
    
    @Override
    public Map<String, Object> getAttributes() {
        return this.attributes;
    }
    
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.authorities;
    }
}
```

**The Token Evolution**: Notice how the token starts unauthenticated (with just the authorization code) and becomes authenticated (with user information). This mirrors the OAuth flow - we start with a code, exchange it for a token, fetch user info, and finally have a complete authenticated user.

---

## Part 8: Complete Flow Sequence Diagram

Now let's see how all these pieces work together:

```
1. USER INITIATES LOGIN
   User clicks "Sign in with Google" button
        ↓
   Browser: GET /oauth2/authorization/google
        ↓
   
2. FILTER RECEIVES REQUEST
   OAuth2LoginAuthenticationFilter.doFilterInternal() is called
        ↓
   Filter detects: isAuthorizationRequest() = true
        ↓
   Action: Build redirect to Google's authorization endpoint
   Redirect includes: client_id, redirect_uri, scope, state
        ↓
   Browser is redirected to Google
        ↓
   
3. USER AUTHENTICATES WITH PROVIDER
   User logs in with Google credentials
   User grants permission ("Allow")
        ↓
   
4. PROVIDER REDIRECTS BACK
   Google redirects browser back to your app
   Browser: GET /oauth2/callback/google?code=AUTH_CODE&state=STATE
        ↓
   
5. FILTER RECEIVES CALLBACK
   OAuth2LoginAuthenticationFilter.doFilterInternal() is called again
        ↓
   Filter detects: isAuthorizationResponse() = true
        ↓
   Filter extracts: authorization code, state, registrationId from request
        ↓
   
6. CREATE UNAUTHENTICATED TOKEN
   Filter creates: OAuth2LoginAuthenticationToken
   This token contains: authorization code, state, registrationId
   Token is marked: NOT AUTHENTICATED
        ↓
   
7. PASS TO AUTHENTICATION MANAGER
   Filter calls: authenticationManager.authenticate(unauthenticatedToken)
        ↓
   
8. MANAGER FINDS PROVIDER
   ProviderManager loops through providers
   It asks each provider: "Can you authenticate this?"
   OAuth2AuthenticationProvider.supports() returns true
        ↓
   
9. PROVIDER PROCESSES AUTHENTICATION
   OAuth2AuthenticationProvider.authenticate() is called
        ↓
   
   9a. GET CLIENT REGISTRATION
       ClientRegistrationRepository.findByRegistrationId("google")
       Returns: Google's OAuth configuration (client_id, client_secret, endpoints)
        ↓
   
   9b. EXCHANGE CODE FOR TOKEN
       Creates: OAuth2AuthorizationCodeGrantRequest
       Calls: OAuth2AccessTokenResponseClient.getTokenResponse()
            └─> Makes HTTP POST to: https://oauth2.googleapis.com/token
            └─> Sends: authorization code + client_secret + other params
            └─> Receives: access_token, refresh_token, expires_in
        ↓
   
   9c. FETCH USER INFORMATION
       Creates: OAuth2UserRequest with access token
       Calls: OAuth2UserService.loadUser()
            └─> Makes HTTP GET to: https://www.googleapis.com/oauth2/v2/userinfo
            └─> Sends: Authorization: Bearer {access_token}
            └─> Receives: user attributes (id, email, name, picture)
        ↓
   
   9d. CREATE AUTHENTICATED TOKEN
       Creates: OAuth2AuthenticationToken
       This token contains: OAuth2User (principal), authorities
       Token is marked: AUTHENTICATED
        ↓
   
10. RETURN AUTHENTICATED TOKEN
    Provider returns: OAuth2AuthenticationToken (authenticated)
         ↓
    Manager returns it to filter
         ↓
    
11. FILTER STORES AUTHENTICATION
    Filter stores the authenticated token in: SecurityContext
    SecurityContext is stored in: Session/ThreadLocal
         ↓
    
12. FILTER STORES IN SESSION
    Filter calls: AuthenticationSuccessHandler
    Handler stores SecurityContext in session
    Handler redirects browser to: /dashboard (or other success URL)
         ↓
    
13. USER IS NOW AUTHENTICATED
    Browser has session cookie
    Session contains: SecurityContext with OAuth2AuthenticationToken
    
14. ACCESSING PROTECTED RESOURCES
    User requests: GET /dashboard
         ↓
    Security filter chain runs again
         ↓
    SecurityContextPersistenceFilter loads SecurityContext from session
         ↓
    Authentication is available in thread local storage
         ↓
    Controller can access via: Authentication parameter or SecurityContextHolder
         ↓
    Authorization checks pass (user has required authorities)
         ↓
    Controller returns: /dashboard view with user information
```

---

## Part 9: Configuration with Custom Components

Now let's see how you would wire up all these custom components:

```java
package com.example.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.user.OAuth2User;

/**
 * This configuration shows how to build custom OAuth 2.0 components
 * and wire them together.
 */
@Configuration
public class CustomOAuth2Config {
    
    /**
     * Step 1: Provide ClientRegistrationRepository
     * This could load from properties, database, or any source
     */
    @Bean
    public ClientRegistrationRepository clientRegistrationRepository() {
        return new CustomClientRegistrationRepository();
        // Or: return new InMemoryClientRegistrationRepository(
        //   googleClientRegistration(),
        //   githubClientRegistration()
        // );
    }
    
    /**
     * Step 2: Provide AccessTokenResponseClient
     * This exchanges authorization code for access token
     */
    @Bean
    public OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest>
            accessTokenResponseClient() {
        
        return new DefaultAuthorizationCodeTokenResponseClient();
        // Or: return new CustomAuthorizationCodeTokenResponseClient();
    }
    
    /**
     * Step 3: Provide OAuth2UserService
     * This fetches user information using access token
     */
    @Bean
    public OAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService() {
        return new DefaultOAuth2UserService();
        // Or: return new CustomOAuth2UserService();
    }
    
    /**
     * Step 4: Create the OAuth2 AuthenticationProvider
     * This coordinates the entire OAuth flow
     */
    @Bean
    public OAuth2AuthenticationProvider oauth2AuthenticationProvider(
            ClientRegistrationRepository clientRegistrationRepository,
            OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest>
                    accessTokenResponseClient,
            OAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService) {
        
        OAuth2AuthenticationProvider provider = 
            new OAuth2AuthenticationProvider(
                clientRegistrationRepository,
                accessTokenResponseClient,
                oauth2UserService
            );
        
        return provider;
    }
    
    /**
     * Step 5: Create AuthenticationManager with the OAuth provider
     * This is what the filter will call
     */
    @Bean
    public AuthenticationManager authenticationManager(
            OAuth2AuthenticationProvider oauth2AuthenticationProvider) {
        
        return new ProviderManager(
            Arrays.asList(
                oauth2AuthenticationProvider,
                // You can add other providers too
                // new UsernamePasswordAuthenticationProvider()
            )
        );
    }
    
    /**
     * Step 6: Register the OAuth2LoginAuthenticationFilter
     * This is where the whole process starts
     */
    @Bean
    public OAuth2LoginAuthenticationFilter oauth2LoginAuthenticationFilter(
            AuthenticationManager authenticationManager,
            ClientRegistrationRepository clientRegistrationRepository,
            OAuth2AuthorizedClientRepository authorizedClientRepository) {
        
        OAuth2LoginAuthenticationFilter filter = 
            new OAuth2LoginAuthenticationFilter(
                clientRegistrationRepository,
                authorizedClientRepository
            );
        
        // Set the authentication manager
        filter.setAuthenticationManager(authenticationManager);
        
        // Set success/failure handlers
        filter.setAuthenticationSuccessHandler(
            (request, response, authentication) -> {
                // Redirect to dashboard on success
                response.sendRedirect("/dashboard");
            }
        );
        
        filter.setAuthenticationFailureHandler(
            (request, response, exception) -> {
                // Redirect to login page on failure
                response.sendRedirect("/login?error");
            }
        );
        
        return filter;
    }
}
```

---

## Key Takeaways

1. **Filter**: Entry point, routes requests to AuthenticationManager
2. **AuthenticationManager**: Coordinator, finds appropriate provider
3. **AuthenticationProvider**: Does the actual OAuth work
4. **ClientRegistrationRepository**: Stores OAuth provider configurations
5. **AccessTokenResponseClient**: Exchanges code for access token
6. **OAuth2UserService**: Fetches user information
7. **Authentication Tokens**: Represent authentication state (unauthenticated → authenticated)
8. **SecurityContext**: Stores the authenticated token

Each component is replaceable, allowing you to customize the OAuth 2.0 flow at any level.
