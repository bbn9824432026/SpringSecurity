# PHASE 2: CALLBACK HANDLING & TOKEN EXCHANGE - DEEP DEVELOPER GUIDE
## User Returns from Provider, Exchange Code for Token

---

## WHAT HAPPENS IN PHASE 2

After user authenticates on provider (Google/GitHub/Okta):
1. Provider redirects user back to your app with authorization code
2. Your app exchanges code for access token
3. Token is stored for future API calls

---

## ENTRY POINT: Provider Redirects Back

```
Google's servers → User clicks "Allow" → Browser redirected

HTTP Request sent to your app:
GET /authorized/google?code=4%2F0Acd-J...&state=abc123xyz HTTP/1.1
Host: localhost:8080
Cookie: JSESSIONID=ABC123
```

The request contains:
- `code`: Authorization code from provider
- `state`: CSRF token sent in Phase 1 (must match)
- Other provider-specific params

---

## 1. OAuth2LoginAuthenticationFilter

### What It Is
A **Servlet Filter** that intercepts callback requests (`/authorized/{registrationId}`)

### What It Does to Request/Response

**REQUEST TRANSFORMATION:**
```
Incoming Request:
GET /authorized/google?code=4%2F0Acd-J...&state=abc123xyz HTTP/1.1
Cookie: JSESSIONID=ABC123

↓ Filter processes ↓

Extracts:
- registrationId: "google"
- code: "4/0Acd-J..."
- state: "abc123xyz"
- session: JSESSIONID=ABC123
```

**RESPONSE TRANSFORMATION:**
```
If successful:
- Creates OAuth2AuthenticationToken (authenticated=true)
- Sets in SecurityContext
- Redirects to home page (HTTP 302)
- Session contains: authenticated user info

If failed:
- Creates OAuth2AuthenticationException
- Passes to OAuth2AuthenticationFailureHandler
- Returns error page or error response
```

### Internal Flow

```java
public class OAuth2LoginAuthenticationFilter extends AbstractAuthenticationProcessingFilter {
    
    private OAuth2AuthorizationCodeTokenResponseClient accessTokenResponseClient;
    // Makes HTTP request to token endpoint
    
    private OAuth2UserService<OAuth2UserRequest, OAuth2User> userService;
    // Fetches user info from userinfo endpoint
    
    private OAuth2AuthorizationRequestRepository authorizationRequestRepository;
    // Retrieves stored authorization request from session
    
    @Override
    public Authentication attemptAuthentication(
            HttpServletRequest request,
            HttpServletResponse response) throws AuthenticationException {
        
        // STEP 1: Extract callback parameters from request
        String code = request.getParameter("code");          // Auth code
        String state = request.getParameter("state");         // CSRF token
        String registrationId = extractRegistrationId(request);  // "google"
        
        if (code == null || state == null) {
            // Check for error from provider
            String error = request.getParameter("error");
            if (error != null) {
                throw new OAuth2AuthenticationException(error);
            }
            return null;
        }
        
        // STEP 2: Retrieve stored authorization request from session
        OAuth2AuthorizationRequest authorizationRequest = 
            authorizationRequestRepository.loadAuthorizationRequest(request);
        
        if (authorizationRequest == null) {
            throw new OAuth2AuthenticationException(
                "Session timed out or invalid request"
            );
        }
        
        // STEP 3: Validate state parameter (CSRF protection)
        if (!state.equals(authorizationRequest.getState())) {
            throw new OAuth2AuthenticationException("State mismatch - CSRF attack?");
        }
        
        // STEP 4: Create OAuth2AuthenticationToken (not yet authenticated)
        OAuth2AuthenticationToken authenticationToken = 
            new OAuth2AuthenticationToken(
                null,  // principal will be set after user info fetch
                null,  // authorities will be set after user info fetch
                registrationId
            );
        
        // STEP 5: Attempt authentication
        // This delegates to OAuth2LoginAuthenticationProvider
        return this.getAuthenticationManager().authenticate(authenticationToken);
    }
    
    private String extractRegistrationId(HttpServletRequest request) {
        // From URL: /authorized/{registrationId}
        String path = request.getRequestURI();
        return path.substring(path.lastIndexOf('/') + 1);
    }
}
```

### Data Held by Filter

```java
private OAuth2AuthorizationCodeTokenResponseClient accessTokenResponseClient;
// Makes POST request to provider's token endpoint
// Input: OAuth2AuthorizationCodeGrantRequest
// Output: OAuth2AccessTokenResponse

private OAuth2UserService<OAuth2UserRequest, OAuth2User> userService;
// Fetches user info from provider's userinfo endpoint
// Input: OAuth2UserRequest
// Output: OAuth2User

private OAuth2AuthorizationRequestRepository authorizationRequestRepository;
// Retrieves request stored in Phase 1
// Input: HttpRequest
// Output: OAuth2AuthorizationRequest

private String authorizationResponseBaseUri = "/authorized";
// Base path for callback URL
```

### How to Use - Customize Filter Path

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        
        http.oauth2Login(oauth2 ->
            oauth2.redirectionEndpoint(endpoint ->
                // Change default /authorized/{registrationId} path
                endpoint.baseUri("/callback/{registrationId}")
            )
        );
        
        return http.build();
    }
}

// Now provider redirects to: /callback/google?code=...&state=...
```

### How to Use - Add Custom Success/Failure Handlers

```java
@Component
public class CustomOAuth2AuthenticationSuccessHandler 
        implements AuthenticationSuccessHandler {
    
    private final UserService userService;
    
    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication) throws IOException, ServletException {
        
        // STEP 1: Get authenticated user
        OAuth2AuthenticationToken token = (OAuth2AuthenticationToken) authentication;
        OAuth2User principal = (OAuth2User) token.getPrincipal();
        
        // STEP 2: Extract user details
        String email = principal.getAttribute("email");
        String name = principal.getAttribute("name");
        String registrationId = token.getAuthorizedClientRegistrationId();
        
        // STEP 3: Save user to database
        userService.saveOrUpdateUser(
            email,
            name,
            registrationId,
            principal.getAttributes()
        );
        
        // STEP 4: Set session attribute
        request.getSession().setAttribute("user", email);
        
        // STEP 5: Redirect to home page
        response.sendRedirect("/home");
    }
}

@Component
public class CustomOAuth2AuthenticationFailureHandler 
        implements AuthenticationFailureHandler {
    
    @Override
    public void onAuthenticationFailure(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException exception) throws IOException, ServletException {
        
        // STEP 1: Log the error
        String error = exception.getMessage();
        System.out.println("OAuth2 Auth Failed: " + error);
        
        // STEP 2: Redirect to error page with message
        response.sendRedirect("/login?error=" + URLEncoder.encode(error, "UTF-8"));
    }
}

@Configuration
public class OAuth2HandlerConfig {
    
    @Bean
    public SecurityFilterChain filterChain(
            HttpSecurity http,
            CustomOAuth2AuthenticationSuccessHandler successHandler,
            CustomOAuth2AuthenticationFailureHandler failureHandler) throws Exception {
        
        http.oauth2Login(oauth2 ->
            oauth2
                .successHandler(successHandler)
                .failureHandler(failureHandler)
        );
        
        return http.build();
    }
}
```

---

## 2. OAuth2AuthorizationResponse Class

### What It Is
A **Data Transfer Object (DTO)** representing the callback response from provider.

### Data Structure

```java
public class OAuth2AuthorizationResponse {
    
    // Authorization code from provider
    private String code;
    // Example: "4/0Acd-J6wqxxxxxx"
    // This is exchanged for access token
    
    // CSRF protection token (must match state from Phase 1)
    private String state;
    // Example: "abc123xyz"
    
    // If provider returns error instead of code
    private String error;
    // Example: "access_denied", "server_error"
    
    private String errorDescription;
    // Example: "The user denied access"
    
    private String errorUri;
    // URL with error details
    
    // Additional provider-specific parameters
    private Map<String, String> additionalParameters;
}
```

### What It Represents

This object is created from the callback query string:
```
Callback URL:
/authorized/google?code=4%2F0Acd-J...&state=abc123xyz

Parsed to:
OAuth2AuthorizationResponse {
    code: "4/0Acd-J...",
    state: "abc123xyz",
    error: null,
    errorDescription: null
}
```

### What It Does With Data

1. **code** - Extracted and used to build `OAuth2AuthorizationCodeGrantRequest`
2. **state** - Validated against stored state from Phase 1 (CSRF protection)
3. **error** - Checked to determine if authorization failed
4. **additionalParameters** - May contain provider-specific info

### How to Use - Parse Callback Response

```java
public class CallbackResponseParser {
    
    public static OAuth2AuthorizationResponse parseCallback(
            HttpServletRequest request) {
        
        // STEP 1: Extract parameters from request
        String code = request.getParameter("code");
        String state = request.getParameter("state");
        String error = request.getParameter("error");
        String errorDescription = request.getParameter("error_description");
        String errorUri = request.getParameter("error_uri");
        
        // STEP 2: Build response object
        OAuth2AuthorizationResponse.Builder builder = 
            OAuth2AuthorizationResponse.builder();
        
        if (error != null) {
            // Error scenario
            builder
                .error(error)
                .errorDescription(errorDescription)
                .errorUri(errorUri);
        } else {
            // Success scenario
            builder
                .code(code)
                .state(state);
        }
        
        // STEP 3: Build and return
        return builder.build();
    }
}
```

---

## 3. OAuth2AuthorizationCodeGrantRequest Class

### What It Is
A **Data Transfer Object (DTO)** prepared for token exchange.

### Data Structure

```java
public class OAuth2AuthorizationCodeGrantRequest {
    
    // The client registration (provider config)
    private ClientRegistration clientRegistration;
    // Contains: clientId, clientSecret, tokenUri, etc.
    
    // Authorization request from Phase 1
    private OAuth2AuthorizationRequest authorizationRequest;
    // Contains: redirectUri, scopes, state, etc.
    
    // Authorization response from callback
    private OAuth2AuthorizationResponse authorizationResponse;
    // Contains: code, state
}
```

### What It Represents

Bundle of data needed to exchange code for token:
```
Authorization Code Grant Request = {
    Client Config + Original Request + Callback Response
}
```

### What It Does With Data

This object is passed to `OAuth2AccessTokenResponseClient` to make POST request to token endpoint.

### How to Use - Build Manually

```java
public class TokenExchangePreparation {
    
    public static OAuth2AuthorizationCodeGrantRequest prepareTokenExchange(
            ClientRegistration clientRegistration,
            OAuth2AuthorizationRequest authRequest,
            OAuth2AuthorizationResponse authResponse) {
        
        return new OAuth2AuthorizationCodeGrantRequest(
            clientRegistration,
            authRequest,
            authResponse
        );
    }
}
```

---

## 4. OAuth2AccessTokenResponseClient Interface

### What It Is
An **Interface** that defines a CONTRACT for exchanging authorization code for access token.

### Contract Definition

```java
public interface OAuth2AccessTokenResponseClient<T extends AbstractOAuth2AuthorizationGrantRequest> {
    
    // Exchange authorization code for access token
    // Input: OAuth2AuthorizationCodeGrantRequest
    // Output: OAuth2AccessTokenResponse (contains access_token, refresh_token, etc.)
    // Throws: OAuth2AuthorizationException if exchange fails
    OAuth2AccessTokenResponse getTokenResponse(T grantRequest) 
        throws OAuth2AuthorizationException;
}
```

### What Data Flows Through

```
Input:
└─ OAuth2AuthorizationCodeGrantRequest {
    clientId: "123456789...",
    clientSecret: "secret",
    code: "4/0Acd-J...",
    redirectUri: "http://localhost:8080/authorized/google",
    tokenUri: "https://www.googleapis.com/oauth2/v4/token"
}

Processing:
├─ Build POST request body with code, client_id, client_secret, etc.
├─ Send to provider's token endpoint
└─ Parse response

Output:
└─ OAuth2AccessTokenResponse {
    access_token: "ya29.a0xxx...",
    refresh_token: "1//0gxxx...",
    expires_in: 3599,
    scope: "email profile",
    token_type: "Bearer"
}
```

---

## 5. RestClientAuthorizationCodeTokenResponseClient

### What It Is
A **Concrete Class** implementing `OAuth2AccessTokenResponseClient` using `RestTemplate`.

### Data It Holds

```java
public class RestClientAuthorizationCodeTokenResponseClient 
        implements OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> {
    
    private RestOperations restOperations;
    // Spring's RestTemplate for making HTTP requests
    
    private OAuth2AuthorizationCodeRequestEntityConverter requestEntityConverter;
    // Converts OAuth2AuthorizationCodeGrantRequest to HTTP request entity
    
    private OAuth2AccessTokenResponseHttpMessageConverter responseConverter;
    // Converts HTTP response to OAuth2AccessTokenResponse
    
    private OAuth2ErrorHttpMessageConverter errorConverter;
    // Converts error response to OAuth2Error
}
```

### What It Does - Internal Logic

```java
@Override
public OAuth2AccessTokenResponse getTokenResponse(
        OAuth2AuthorizationCodeGrantRequest authorizationGrantRequest) 
        throws OAuth2AuthorizationException {
    
    // STEP 1: Build HTTP request entity from grant request
    RequestEntity<?> request = 
        requestEntityConverter.convert(authorizationGrantRequest);
    
    // STEP 2: Make POST request to token endpoint
    // POST https://www.googleapis.com/oauth2/v4/token
    // Body: code=4%2F0Acd-J...&client_id=123456789...&client_secret=secret&redirect_uri=...&grant_type=authorization_code
    ResponseEntity<OAuth2AccessTokenResponse> response;
    try {
        response = restOperations.exchange(
            request,
            OAuth2AccessTokenResponse.class
        );
    } catch (RestClientException ex) {
        throw new OAuth2AuthorizationException(
            new OAuth2Error("connection_error"),
            ex
        );
    }
    
    // STEP 3: Check if response status is 200 OK
    if (!response.getStatusCode().is2xxSuccessful()) {
        throw new OAuth2AuthorizationException(
            "Token endpoint returned error: " + response.getStatusCode()
        );
    }
    
    // STEP 4: Return access token response
    // Response contains: access_token, refresh_token, expires_in, etc.
    return response.getBody();
}
```

### How to Use - Default Implementation

```java
// Spring auto-configures this, no code needed!
// OAuth2LoginAuthenticationProvider uses it automatically
```

### How to Use - Custom Implementation with Logging

```java
@Component
public class LoggingTokenResponseClient 
        implements OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> {
    
    private final RestClientAuthorizationCodeTokenResponseClient delegate;
    
    public LoggingTokenResponseClient(RestTemplate restTemplate) {
        this.delegate = new RestClientAuthorizationCodeTokenResponseClient();
    }
    
    @Override
    public OAuth2AccessTokenResponse getTokenResponse(
            OAuth2AuthorizationCodeGrantRequest authorizationGrantRequest) 
            throws OAuth2AuthorizationException {
        
        // STEP 1: Log before exchange
        String clientId = authorizationGrantRequest
            .getClientRegistration()
            .getClientId();
        String code = authorizationGrantRequest
            .getAuthorizationResponse()
            .getCode();
        
        System.out.println("Exchanging code for token:");
        System.out.println("  Client ID: " + clientId);
        System.out.println("  Code: " + code.substring(0, 10) + "...");
        
        // STEP 2: Call delegate to perform exchange
        OAuth2AccessTokenResponse response;
        try {
            response = delegate.getTokenResponse(authorizationGrantRequest);
        } catch (OAuth2AuthorizationException ex) {
            System.out.println("Token exchange failed: " + ex.getMessage());
            throw ex;
        }
        
        // STEP 3: Log success
        System.out.println("Token exchange successful!");
        System.out.println("  Access Token: " + 
            response.getAccessToken().getTokenValue().substring(0, 20) + "...");
        System.out.println("  Expires In: " + 
            response.getAccessToken().getExpiresAt());
        
        return response;
    }
}
```

### Register Custom Implementation

```java
@Configuration
public class CustomTokenClientConfig {
    
    @Bean
    public OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> 
            accessTokenResponseClient() {
        return new LoggingTokenResponseClient(new RestTemplate());
    }
}
```

---

## 6. OAuth2AccessTokenResponse Class

### What It Is
A **Data Transfer Object (DTO)** holding the token response from provider.

### Data Structure

```java
public class OAuth2AccessTokenResponse {
    
    // Access token for calling APIs
    private OAuth2AccessToken accessToken;
    // Contains: tokenValue, tokenType ("Bearer"), expiresAt
    
    // Refresh token for getting new access token
    private OAuth2RefreshToken refreshToken;
    // Contains: tokenValue
    
    // Additional scopes granted (may differ from requested)
    private Set<String> scopes;
    
    // Provider-specific parameters
    private Map<String, Object> additionalParameters;
    // Example: {"id_token": "jwt-string", "custom_param": "value"}
}
```

### What It Represents

This is the response from provider's token endpoint:
```
Token Endpoint Response (JSON):
{
    "access_token": "ya29.a0Arenxxxxxx",
    "expires_in": 3599,
    "refresh_token": "1//0gxxxx",
    "scope": "email profile",
    "token_type": "Bearer",
    "id_token": "eyJhbGciOiJSUzI1NiIs..."
}

Parsed to:
OAuth2AccessTokenResponse {
    accessToken: OAuth2AccessToken {
        tokenValue: "ya29.a0Arenxxxxxx",
        tokenType: "Bearer",
        expiresAt: 2024-01-01T12:30:00Z
    },
    refreshToken: OAuth2RefreshToken {
        tokenValue: "1//0gxxxx"
    },
    scopes: ["email", "profile"],
    additionalParameters: {
        "id_token": "eyJhbGciOiJSUzI1NiIs..."
    }
}
```

### What It Does With Data

1. **accessToken** - Used to call provider's APIs
2. **refreshToken** - Used later to get new access token when expired
3. **scopes** - What permissions were actually granted
4. **additionalParameters** - Provider-specific data (e.g., ID token for OIDC)

### How to Use - Extract Tokens

```java
public class TokenExtractor {
    
    public static void extractAndUseTokens(
            OAuth2AccessTokenResponse response) {
        
        // STEP 1: Get access token
        OAuth2AccessToken accessToken = response.getAccessToken();
        String tokenValue = accessToken.getTokenValue();
        // Use this in Authorization header: "Authorization: Bearer " + tokenValue
        
        // STEP 2: Check expiry
        Instant expiresAt = accessToken.getExpiresAt();
        if (Instant.now().isAfter(expiresAt)) {
            // Token expired, need to refresh
        }
        
        // STEP 3: Get refresh token
        OAuth2RefreshToken refreshToken = response.getRefreshToken();
        if (refreshToken != null) {
            String refreshValue = refreshToken.getTokenValue();
            // Store for later use
        }
        
        // STEP 4: Check scopes
        Set<String> grantedScopes = response.getScopes();
        System.out.println("Granted scopes: " + grantedScopes);
    }
}
```

---

## PHASE 2 SUMMARY TABLE

| Component | Type | Purpose | Input → Output |
|-----------|------|---------|-----------------|
| **OAuth2LoginAuthenticationFilter** | Filter | Callback handler, validates code/state, initiates token exchange | Request with code → OAuth2AuthenticationToken |
| **OAuth2AuthorizationResponse** | Class | Callback response data (code, state, error) | Query string → Response object |
| **OAuth2AuthorizationCodeGrantRequest** | Class | Request to exchange code for token | Client + Auth + Response → Grant request |
| **OAuth2AccessTokenResponseClient** | Interface | Contract for token exchange | Grant request → Token response |
| **RestClientAuthorizationCodeTokenResponseClient** | Class | Makes POST to token endpoint | Grant request → Token response |
| **OAuth2AccessTokenResponse** | Class | Token endpoint response | JSON → Token objects |

---

## PHASE 2 COMPLETE

**Phase 2 Outcome:**
- Provider redirects back with authorization code
- Filter validates code & state (CSRF protection)
- Code exchanged for access token via POST
- Access token stored for future API calls
- Session ready with authenticated user

**Next: Phase 3 - User Info Fetch & Session Storage**
Ready?