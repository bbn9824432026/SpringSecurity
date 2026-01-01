# PHASE 1: INITIAL LOGIN REQUEST - DETAILED DEVELOPER GUIDE
## Understand Every Contract, Every Data Transformation

---

## ENTRY POINT: User Clicks Login Button

```
HTML Page: <a href="/oauth2/authorization/google">Login with Google</a>
         ↓
HTTP Request: GET /oauth2/authorization/google
         ↓
Spring Security Filter Chain
```

---

## 1. OAuth2AuthorizationRequestRedirectFilter

### What It Is
A **Servlet Filter** that intercepts HTTP requests before they reach your application code.

### What It Does to Request/Response

**REQUEST TRANSFORMATION:**
```
Incoming Request:
GET /oauth2/authorization/google HTTP/1.1
Host: localhost:8080
Cookie: JSESSIONID=ABC123

↓ Filter processes this ↓

Extracts:
- Request path: /oauth2/authorization/google
- registrationId: "google"
- Session: JSESSIONID=ABC123
```

**RESPONSE TRANSFORMATION:**
```
Filter creates HTTP 302 Response:
HTTP/1.1 302 Found
Location: https://accounts.google.com/o/oauth2/v2/auth?
  client_id=123456789&
  redirect_uri=http://localhost:8080/authorized/google&
  response_type=code&
  scope=email+profile&
  state=xyz123

Set-Cookie: JSESSIONID=ABC123; Path=/; HttpOnly; SameSite=Strict
```

### Internal Flow

```java
public class OAuth2AuthorizationRequestRedirectFilter extends OncePerRequestFilter {
    
    private OAuth2AuthorizationRequestResolver authorizationRequestResolver;
    private OAuth2AuthorizationRequestRepository authorizationRequestRepository;
    private String redirectUri = "/oauth2/authorization/{registrationId}";
    
    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {
        
        // STEP 1: Check if this request matches the OAuth2 authorization pattern
        // Pattern: /oauth2/authorization/{registrationId}
        String registrationId = extractRegistrationId(request);
        if (registrationId == null) {
            // Not an OAuth2 authorization request, pass to next filter
            filterChain.doFilter(request, response);
            return;
        }
        
        // STEP 2: Call the resolver to build authorization request
        // This will query ClientRegistrationRepository for "google" configuration
        OAuth2AuthorizationRequest authorizationRequest = 
            authorizationRequestResolver.resolve(request, registrationId);
        
        if (authorizationRequest == null) {
            // Registration not found, pass to next filter
            filterChain.doFilter(request, response);
            return;
        }
        
        // STEP 3: Save authorization request in session
        // This is stored for later validation when callback comes
        // CSRF protection: state parameter will be validated
        authorizationRequestRepository.saveAuthorizationRequest(
            authorizationRequest,
            request,
            response
        );
        
        // STEP 4: Redirect user to Authorization Server
        // User's browser will load this URL
        String authorizationUri = authorizationRequest.getAuthorizationRequestUri();
        // authorizationUri = "https://accounts.google.com/o/oauth2/v2/auth?..."
        response.sendRedirect(authorizationUri);
        
        // Flow stops here - response sent to client
    }
    
    private String extractRegistrationId(HttpServletRequest request) {
        // From URL: /oauth2/authorization/{registrationId}
        // Extract the registrationId part
        String path = request.getRequestURI();
        // Returns: "google"
        return path.replace("/oauth2/authorization/", "");
    }
}
```

### Data Held by Filter
```java
// These are stored as bean properties in the filter instance:

private OAuth2AuthorizationRequestResolver authorizationRequestResolver;
// Responsible for building OAuth2AuthorizationRequest from ClientRegistration

private OAuth2AuthorizationRequestRepository authorizationRequestRepository;
// Responsible for storing request in session (CSRF token validation)

private String authorizationRequestUri = "/oauth2/authorization/{registrationId}";
// The URL pattern this filter listens to
```

### How to Use - Customize the Filter Path

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    
    @Bean
    public SecurityFilterChain filterChain(
            HttpSecurity http,
            OAuth2AuthorizationRequestResolver authResolver) throws Exception {
        
        http.oauth2Login(oauth2 -> 
            // Change the default /oauth2/authorization/{registrationId} path
            oauth2.authorizationEndpoint(endpoint ->
                endpoint
                    // Use custom path like /auth/login/{registrationId}
                    .baseUri("/auth/login/{registrationId}")
                    // Provide custom resolver (we'll explain next)
                    .authorizationRequestResolver(authResolver)
            )
        );
        
        return http.build();
    }
}

// Now users click: <a href="/auth/login/google">Login</a>
// Instead of: <a href="/oauth2/authorization/google">Login</a>
```

### How to Use - Add Logging/Auditing

```java
@Component
public class AuditingOAuth2AuthorizationFilter extends OncePerRequestFilter {
    
    private final OAuth2AuthorizationRequestRedirectFilter delegate;
    private final AuditLogger auditLogger;
    
    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {
        
        String registrationId = extractRegistrationId(request);
        
        if (registrationId != null) {
            // Log before redirect
            auditLogger.logOAuth2LoginAttempt(
                registrationId,
                request.getRemoteAddr(),
                request.getHeader("User-Agent")
            );
        }
        
        // Call delegate filter
        delegate.doFilterInternal(request, response, filterChain);
    }
    
    private String extractRegistrationId(HttpServletRequest request) {
        String path = request.getRequestURI();
        String[] parts = path.split("/");
        return parts.length > 0 ? parts[parts.length - 1] : null;
    }
}
```

---

## 2. OAuth2AuthorizationRequestResolver Interface

### What It Is
An **Interface** that defines a CONTRACT for resolving authorization requests.

### Contract Definition

```java
public interface OAuth2AuthorizationRequestResolver {
    
    // PRIMARY METHOD
    // Input: HTTP request + registrationId (e.g., "google")
    // Output: OAuth2AuthorizationRequest (or null if registration not found)
    // Purpose: Build authorization request from client registration config
    OAuth2AuthorizationRequest resolve(
        HttpServletRequest request, 
        String registrationId
    );
    
    // ALTERNATIVE METHOD
    // Input: HTTP request (registrationId extracted from path)
    // Output: OAuth2AuthorizationRequest (or null)
    // Purpose: Same as above but registrationId extracted from request
    OAuth2AuthorizationRequest resolve(HttpServletRequest request);
}
```

### What Data Flows Through This Interface

```
Input Data:
├─ HttpServletRequest
│  ├─ URI path: /oauth2/authorization/google
│  ├─ Query params: ?custom=value
│  ├─ Session: JSESSIONID
│  └─ Headers: User-Agent, Accept, etc.
└─ String registrationId: "google"

Processing:
├─ Lookup ClientRegistration("google")
├─ Get OAuth2 provider URLs and config
├─ Validate registration exists
├─ Build authorization request with:
│  ├─ clientId from ClientRegistration
│  ├─ authorizationUri from provider config
│  ├─ redirectUri (where to callback)
│  ├─ scopes (permissions requested)
│  └─ state (CSRF token - random)

Output:
└─ OAuth2AuthorizationRequest object
   ├─ authorizationUri with all query params
   ├─ clientId
   ├─ scopes
   ├─ redirectUri
   ├─ state (CSRF token)
   └─ additionalParameters
```

### How to Implement - Custom Resolver

```java
public class CustomOAuth2AuthorizationRequestResolver 
        implements OAuth2AuthorizationRequestResolver {
    
    private final ClientRegistrationRepository clientRegistrationRepository;
    private final DefaultOAuth2AuthorizationRequestResolver defaultResolver;
    
    public CustomOAuth2AuthorizationRequestResolver(
            ClientRegistrationRepository clientRegistrationRepository) {
        this.clientRegistrationRepository = clientRegistrationRepository;
        this.defaultResolver = new DefaultOAuth2AuthorizationRequestResolver(
            clientRegistrationRepository,
            "/oauth2/authorization/{registrationId}"
        );
    }
    
    @Override
    public OAuth2AuthorizationRequest resolve(
            HttpServletRequest request, 
            String registrationId) {
        
        // STEP 1: Get default authorization request from DefaultResolver
        // This performs lookup in ClientRegistrationRepository
        OAuth2AuthorizationRequest authRequest = 
            defaultResolver.resolve(request, registrationId);
        
        // Return null if registration not found
        // (DefaultResolver will throw exception if not found)
        if (authRequest == null) {
            return null;
        }
        
        // STEP 2: Customize based on registrationId
        // Different providers may need different parameters
        if ("google".equals(registrationId)) {
            authRequest = addGoogleSpecificParams(authRequest);
        } else if ("github".equals(registrationId)) {
            authRequest = addGithubSpecificParams(authRequest);
        }
        
        // STEP 3: Return modified authorization request
        return authRequest;
    }
    
    private OAuth2AuthorizationRequest addGoogleSpecificParams(
            OAuth2AuthorizationRequest request) {
        
        // Google-specific parameters
        // Build a new request based on existing one
        return OAuth2AuthorizationRequest
            .from(request)  // Copy all existing values
            .additionalParameters(params -> {
                // Force Google to show consent screen every time (for testing)
                params.put("prompt", "consent");
                // Request offline access (to get refresh token)
                params.put("access_type", "offline");
                // Incremental authorization
                params.put("include_granted_scopes", "true");
            })
            .build();  // Create new request with modifications
    }
    
    private OAuth2AuthorizationRequest addGithubSpecificParams(
            OAuth2AuthorizationRequest request) {
        
        // GitHub-specific parameters
        return OAuth2AuthorizationRequest
            .from(request)
            .additionalParameters(params -> {
                // Don't allow signup, only existing accounts
                params.put("allow_signup", "false");
            })
            .build();
    }
    
    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
        // Alternative method: extract registrationId from request path
        String path = request.getRequestURI();
        String registrationId = path.substring(path.lastIndexOf('/') + 1);
        return resolve(request, registrationId);
    }
}
```

### How to Use - Register Custom Implementation

```java
@Configuration
public class OAuth2SecurityConfig {
    
    @Bean
    public OAuth2AuthorizationRequestResolver customAuthorizationResolver(
            ClientRegistrationRepository clientRegistrationRepository) {
        
        return new CustomOAuth2AuthorizationRequestResolver(
            clientRegistrationRepository
        );
    }
    
    @Bean
    public SecurityFilterChain filterChain(
            HttpSecurity http,
            OAuth2AuthorizationRequestResolver customResolver) throws Exception {
        
        http.oauth2Login(oauth2 ->
            oauth2.authorizationEndpoint(endpoint ->
                endpoint.authorizationRequestResolver(customResolver)
            )
        );
        
        return http.build();
    }
}
```

---

## 3. DefaultOAuth2AuthorizationRequestResolver

### What It Is
A **Concrete Class** implementing `OAuth2AuthorizationRequestResolver` interface.

### Data It Holds
```java
public class DefaultOAuth2AuthorizationRequestResolver 
        implements OAuth2AuthorizationRequestResolver {
    
    private final ClientRegistrationRepository clientRegistrationRepository;
    // Holds reference to repository for looking up ClientRegistration
    
    private final String authorizationRequestUri;
    // The URL pattern: "/oauth2/authorization/{registrationId}"
    
    private OAuth2AuthorizationRequestCustomizer authorizationRequestCustomizer;
    // Optional customizer to modify request before returning
}
```

### What It Does - Internal Logic

```java
public OAuth2AuthorizationRequest resolve(
        HttpServletRequest request, 
        String registrationId) {
    
    // STEP 1: Look up ClientRegistration from repository
    ClientRegistration clientRegistration = 
        clientRegistrationRepository.findByRegistrationId(registrationId);
    
    if (clientRegistration == null) {
        throw new IllegalArgumentException(
            "Unknown registration id: " + registrationId
        );
    }
    
    // STEP 2: Extract redirect URI with variable substitution
    // Supports: {baseUrl}, {baseScheme}, {baseHost}, {basePort}, {basePath}, {registrationId}
    String redirectUri = substituteVariables(
        clientRegistration.getRedirectUri(),
        request,
        registrationId
    );
    // Input: "{baseUrl}/authorized/{registrationId}"
    // Output: "http://localhost:8080/authorized/google"
    
    // STEP 3: Build authorization request using ClientRegistration
    OAuth2AuthorizationRequest.Builder builder = 
        OAuth2AuthorizationRequest
            .authorizationCode()
            // Response type for Authorization Code flow
            .clientId(clientRegistration.getClientId())
            // From ClientRegistration
            .authorizationUri(clientRegistration.getAuthorizationUri())
            // From ClientRegistration
            .redirectUri(redirectUri)
            // Computed from template
            .scopes(clientRegistration.getScopes())
            // From ClientRegistration
            .state(generateRandomState());
            // Generated for CSRF protection
    
    // STEP 4: Apply customizer if provided
    // Allows adding extra parameters
    if (authorizationRequestCustomizer != null) {
        authorizationRequestCustomizer.customize(builder);
    }
    
    // STEP 5: Build and return final request
    return builder.build();
}

private String generateRandomState() {
    // Generate random 20-character string for CSRF protection
    // Example: "xyzabc123..."
    byte[] bytes = new byte[20];
    secureRandom.nextBytes(bytes);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
}

private String substituteVariables(
        String redirectUri, 
        HttpServletRequest request,
        String registrationId) {
    
    // Replaces template variables with actual values
    String result = redirectUri
        .replace("{baseUrl}", getBaseUrl(request))
        .replace("{baseScheme}", request.getScheme())
        .replace("{baseHost}", request.getServerName())
        .replace("{basePort}", getPort(request))
        .replace("{basePath}", request.getContextPath())
        .replace("{registrationId}", registrationId);
    
    // Example:
    // Input: "{baseUrl}/authorized/{registrationId}"
    // Output: "http://localhost:8080/authorized/google"
    return result;
}
```

### How to Use - Simple Customization

```java
@Configuration
public class SimpleOAuth2Config {
    
    @Bean
    public OAuth2AuthorizationRequestResolver authorizationResolver(
            ClientRegistrationRepository clientRegRepository) {
        
        DefaultOAuth2AuthorizationRequestResolver resolver = 
            new DefaultOAuth2AuthorizationRequestResolver(
                clientRegRepository,
                "/oauth2/authorization/{registrationId}"
            );
        
        // Add customizer to modify request
        resolver.setAuthorizationRequestCustomizer(customizer ->
            customizer
                // Add extra parameters to the authorization URL
                .additionalParameters(params -> {
                    params.put("prompt", "login");
                    params.put("custom_param", "value");
                })
        );
        
        return resolver;
    }
}
```

---

## 4. ClientRegistrationRepository Interface

### What It Is
An **Interface** that defines a CONTRACT for storing and retrieving OAuth2 client configurations.

### Contract Definition

```java
public interface ClientRegistrationRepository 
        extends Iterable<ClientRegistration> {
    
    // PRIMARY METHOD
    // Input: registrationId (e.g., "google")
    // Output: ClientRegistration object or throws exception
    // Purpose: Find client config by unique identifier
    ClientRegistration findByRegistrationId(String registrationId);
    
    // INHERITED FROM ITERABLE
    // Input: none
    // Output: Iterator over all ClientRegistration objects
    // Purpose: Iterate all configured clients
    Iterator<ClientRegistration> iterator();
}
```

### What Data Flows Through This Interface

```
Input:
└─ String registrationId: "google"

Repository Processing:
├─ Search in memory, database, external service, etc.
└─ Find matching ClientRegistration

Output:
└─ ClientRegistration object containing:
   ├─ clientId: "123456789.apps.googleusercontent.com"
   ├─ clientSecret: "secret-key"
   ├─ authorizationUri: "https://accounts.google.com/o/oauth2/v2/auth"
   ├─ tokenUri: "https://www.googleapis.com/oauth2/v4/token"
   ├─ userInfoUri: "https://www.googleapis.com/oauth2/v1/userinfo"
   ├─ scopes: ["email", "profile"]
   └─ ... other config
```

### Built-in Implementations

**1. InMemoryClientRegistrationRepository**
```java
// Spring creates this automatically from application.yml

ClientRegistrationRepository repository = 
    new InMemoryClientRegistrationRepository(
        googleClientRegistration,
        githubClientRegistration,
        oktaClientRegistration
    );

// Stores registrations in a Map internally
private final Map<String, ClientRegistration> registrations;

// When you call findByRegistrationId("google"):
ClientRegistration result = registrations.get("google");
return result;
```

### How to Use - Property-Based (Auto-Configured)

```yaml
# application.yml
spring:
  security:
    oauth2:
      client:
        registration:
          google:
            client-id: 123456789.apps.googleusercontent.com
            client-secret: your-secret
            scope: email,profile
          github:
            client-id: your-github-id
            client-secret: your-github-secret
            scope: user:email,read:user
        provider:
          google:
            authorization-uri: https://accounts.google.com/o/oauth2/v2/auth
            token-uri: https://www.googleapis.com/oauth2/v4/token
            user-info-uri: https://www.googleapis.com/oauth2/v1/userinfo
          github:
            authorization-uri: https://github.com/login/oauth/authorize
            token-uri: https://github.com/login/oauth/access_token
            user-info-uri: https://api.github.com/user

# Spring automatically creates InMemoryClientRegistrationRepository
# and populates it with these registrations
```

### How to Use - Custom Database Implementation

```java
@Component
public class DatabaseClientRegistrationRepository 
        implements ClientRegistrationRepository {
    
    private final ClientRegistrationDAO dao;
    private final Map<String, ClientRegistration> cache;
    
    public DatabaseClientRegistrationRepository(ClientRegistrationDAO dao) {
        this.dao = dao;
        this.cache = new ConcurrentHashMap<>();
        // Load all registrations on startup
        loadAllRegistrations();
    }
    
    private void loadAllRegistrations() {
        // Load from database at startup
        dao.findAll().forEach(entity -> {
            ClientRegistration registration = entityToRegistration(entity);
            cache.put(registration.getRegistrationId(), registration);
        });
    }
    
    @Override
    public ClientRegistration findByRegistrationId(String registrationId) {
        // STEP 1: Check cache first (fast lookup)
        ClientRegistration cached = cache.get(registrationId);
        if (cached != null) {
            return cached;
        }
        
        // STEP 2: If not cached, load from database
        ClientRegistrationEntity entity = dao.findByRegistrationId(registrationId);
        if (entity == null) {
            return null;
        }
        
        // STEP 3: Convert entity to ClientRegistration
        ClientRegistration registration = entityToRegistration(entity);
        
        // STEP 4: Cache for future lookups
        cache.put(registrationId, registration);
        
        return registration;
    }
    
    private ClientRegistration entityToRegistration(ClientRegistrationEntity entity) {
        return ClientRegistration
            .withRegistrationId(entity.getRegistrationId())
            .clientId(entity.getClientId())
            .clientSecret(entity.getClientSecret())
            .clientAuthenticationMethod(
                ClientAuthenticationMethod.valueOf(entity.getAuthMethod())
            )
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri(entity.getRedirectUri())
            .authorizationUri(entity.getAuthorizationUri())
            .tokenUri(entity.getTokenUri())
            .userInfoUri(entity.getUserInfoUri())
            .userNameAttributeName(entity.getUserNameAttribute())
            .scope(entity.getScopes().split(","))
            .build();
    }
    
    @Override
    public Iterator<ClientRegistration> iterator() {
        return cache.values().iterator();
    }
    
    // Method to refresh cache (call when DB is updated)
    public void refresh() {
        cache.clear();
        loadAllRegistrations();
    }
}
```

### How to Use - Register Custom Implementation

```java
@Configuration
public class RepositoryConfig {
    
    @Bean
    public ClientRegistrationRepository clientRegistrationRepository(
            ClientRegistrationDAO dao) {
        
        // Use custom database-backed repository instead of property-based
        return new DatabaseClientRegistrationRepository(dao);
    }
}
```

---

## 5. ClientRegistration Class

### What It Is
A **Data Transfer Object (DTO)** that holds OAuth2 provider configuration.

### Data Structure

```java
public class ClientRegistration {
    
    // Unique identifier for this provider
    private String registrationId;  // "google", "github", "okta"
    
    // OAuth2 Credentials
    private String clientId;        // "123456789.apps.googleusercontent.com"
    private String clientSecret;    // "secret-key-from-provider"
    
    // Client Authentication Method
    private ClientAuthenticationMethod clientAuthenticationMethod;
    // Options:
    // - CLIENT_SECRET_BASIC: Sends as HTTP Basic Auth header
    // - CLIENT_SECRET_POST: Sends as form parameter
    // - NONE: No authentication (public clients)
    
    // OAuth2 Grant Type
    private AuthorizationGrantType authorizationGrantType;
    // For this phase: AuthorizationGrantType.AUTHORIZATION_CODE
    
    // Where provider redirects back to your app
    private String redirectUri;     // "http://localhost:8080/authorized/google"
    
    // Provider's OAuth2 Endpoints
    private String authorizationUri; // "https://accounts.google.com/o/oauth2/v2/auth"
    private String tokenUri;        // "https://www.googleapis.com/oauth2/v4/token"
    private String userInfoUri;     // "https://www.googleapis.com/oauth2/v1/userinfo"
    private String jwkSetUri;       // For JWT validation (OIDC)
    private String issuerUri;       // OIDC issuer
    
    // User identification
    private String userNameAttributeName;
    // Which claim identifies user uniquely:
    // - "sub" (OIDC standard)
    // - "email"
    // - "login" (GitHub)
    // - "id" (custom)
    
    // Requested permissions
    private Set<String> scopes;     // ["email", "profile"]
    
    // Additional configuration
    private ClientSettings clientSettings;
}
```

### What It Represents
ClientRegistration holds **all information needed to authenticate with one OAuth2 provider**.

It's like a blueprint that says:
> "To authenticate with Google, use this client-id, send requests to this URL, ask for these permissions, and identify users by this claim."

### What It Does With Data
1. **Stores** the configuration
2. **Used by DefaultOAuth2AuthorizationRequestResolver** to build authorization requests
3. **Used by token exchange** to authenticate to provider
4. **Used by user info fetch** to call userinfo endpoint

### How to Use - Create Manually

```java
ClientRegistration googleRegistration = ClientRegistration
    // Unique identifier
    .withRegistrationId("google")
    
    // OAuth2 Credentials from Google Console
    .clientId("123456789.apps.googleusercontent.com")
    .clientSecret("your-client-secret-from-google-console")
    
    // How to send credentials to token endpoint
    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
    // Options:
    // - CLIENT_SECRET_BASIC: Authorization: Basic base64(id:secret)
    // - CLIENT_SECRET_POST: client_id=xxx&client_secret=xxx in body
    // - NONE: public client, no credentials
    
    // OAuth2 flow type
    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
    
    // Where Google redirects back after user authorizes
    .redirectUri("http://localhost:8080/authorized/google")
    // Template variables supported:
    // {baseUrl}, {baseScheme}, {baseHost}, {basePort}, {basePath}, {registrationId}
    
    // Google's OAuth2 endpoints
    .authorizationUri("https://accounts.google.com/o/oauth2/v2/auth")
    .tokenUri("https://www.googleapis.com/oauth2/v4/token")
    .userInfoUri("https://www.googleapis.com/oauth2/v1/userinfo")
    .jwkSetUri("https://www.googleapis.com/oauth2/v3/certs")
    
    // Which claim uniquely identifies user
    .userNameAttributeName("sub")
    
    // Scopes (permissions) to request
    .scope("email", "profile")
    
    // Additional settings
    .clientSettings(ClientSettings.builder()
        .requireProofKey(true)  // Enable PKCE for security
        .build()
    )
    
    .build();
```

### How to Use - Multiple Providers

```java
@Configuration
public class MultiProviderConfig {
    
    @Bean
    public ClientRegistrationRepository clientRegistrationRepository() {
        return new InMemoryClientRegistrationRepository(
            googleRegistration(),
            githubRegistration(),
            oktaRegistration()
        );
    }
    
    private ClientRegistration googleRegistration() {
        return ClientRegistration
            .withRegistrationId("google")
            .clientId("${GOOGLE_CLIENT_ID}")
            .clientSecret("${GOOGLE_CLIENT_SECRET}")
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri("{baseUrl}/authorized/google")
            .authorizationUri("https://accounts.google.com/o/oauth2/v2/auth")
            .tokenUri("https://www.googleapis.com/oauth2/v4/token")
            .userInfoUri("https://www.googleapis.com/oauth2/v1/userinfo")
            .userNameAttributeName("sub")
            .scope("email", "profile")
            .build();
    }
    
    private ClientRegistration githubRegistration() {
        return ClientRegistration
            .withRegistrationId("github")
            .clientId("${GITHUB_CLIENT_ID}")
            .clientSecret("${GITHUB_CLIENT_SECRET}")
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri("{baseUrl}/authorized/github")
            .authorizationUri("https://github.com/login/oauth/authorize")
            .tokenUri("https://github.com/login/oauth/access_token")
            .userInfoUri("https://api.github.com/user")
            .userNameAttributeName("login")  // GitHub uses "login" not "sub"
            .scope("user:email", "read:user")
            .build();
    }
    
    private ClientRegistration oktaRegistration() {
        return ClientRegistration
            .withRegistrationId("okta")
            .clientId("${OKTA_CLIENT_ID}")
            .clientSecret("${OKTA_CLIENT_SECRET}")
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri("{baseUrl}/authorized/okta")
            .authorizationUri("${OKTA_DOMAIN}/oauth2/v1/authorize")
            .tokenUri("${OKTA_DOMAIN}/oauth2/v1/token")
            .userInfoUri("${OKTA_DOMAIN}/oauth2/v1/userinfo")
            .userNameAttributeName("sub")
            .scope("openid", "profile", "email")
            .build();
    }
}
```

---

## 6. OAuth2AuthorizationRequest Class

### What It Is
A **Data Transfer Object (DTO)** that represents the authorization request sent to the OAuth2 provider.

### Data Structure

```java
public class OAuth2AuthorizationRequest {
    
    // OAuth2 Authorization Endpoint URL
    private String authorizationUri;
    // Example: "https://accounts.google.com/o/oauth2/v2/auth"
    
    // Client identifier
    private String clientId;
    // Example: "123456789.apps.googleusercontent.com"
    
    // Where provider redirects after authorization
    private String redirectUri;
    // Example: "http://localhost:8080/authorized/google"
    
    // Requested scopes (permissions)
    private Set<String> scopes;
    // Example: ["email", "profile"]
    
    // OAuth2 response type
    private String responseType;
    // For Authorization Code flow: "code"
    
    // CSRF protection token
    private String state;
    // Random value generated for security
    // Example: "abc123xyz"
    
    // Additional parameters specific to provider
    private Map<String, Object> additionalParameters;
    // Example: {"prompt": "consent", "access_type": "offline"}
    
    // PKCE (Proof Key for Code Exchange) parameters
    private String codeChallenge;
    // Example: "xyz123..."
    private String codeChallengeMethod;
    // Example: "S256" or "plain"
}
```

### What It Represents

This object is **transformed into a URL query string** that gets sent to the provider:

```java
// This object:
OAuth2AuthorizationRequest request = OAuth2AuthorizationRequest
    .authorizationCode()
    .clientId("123456789.apps.googleusercontent.com")
    .authorizationUri("https://accounts.google.com/o/oauth2/v2/auth")
    .redirectUri("http://localhost:8080/authorized/google")
    .scopes("email", "profile")
    .state("abc123xyz")
    .additionalParameters(Map.of("prompt", "consent"))
    .build();

// Becomes this URL sent to browser:
// https://accounts.google.com/o/oauth2/v2/auth?
//   client_id=123456789.apps.googleusercontent.com&
//   redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fauthorized%2Fgoogle&
//   response_type=code&
//   scope=email+profile&
//   state=abc123xyz&
//   prompt=consent
```

### What It Does With Data

1. **Built** by `DefaultOAuth2AuthorizationRequestResolver`
2. **Stored** in `OAuth2AuthorizationRequestRepository` (session) for CSRF validation
3. **Converted** to authorization URI by calling `.getAuthorizationRequestUri()`
4. **Retrieved** later when callback comes in to validate state parameter

### How to Use - Build Manually

```java
OAuth2AuthorizationRequest request = OAuth2AuthorizationRequest
    .authorizationCode()  // Response type = "code"
    .clientId("123456789.apps.googleusercontent.com")
    .authorizationUri("https://accounts.google.com/o/oauth2/v2/auth")
    .redirectUri("http://localhost:8080/authorized/google")
    .scopes("email", "profile")
    .state("random-state-xyz")
    .additionalParameters(
        Map.of(
            "prompt", "consent",           // Google-specific
            "access_type", "offline"       // Google-specific
        )
    )
    .build();

// Get the full URL that browser will visit
String authorizationUrl = request.getAuthorizationRequestUri();
// Returns: https://accounts.google.com/o/oauth2/v2/auth?...

// Access individual fields
String clientId = request.getClientId();        // "123456789..."
Set<String> scopes = request.getScopes();       // ["email", "profile"]
String state = request.getState();              // "abc123xyz"
```

### How to Use - Customize Using OAuth2AuthorizationRequestCustomizer

```java
@Configuration
public class CustomizerConfig {
    
    @Bean
    public OAuth2AuthorizationRequestResolver authResolver(
            ClientRegistrationRepository clientRegRepository) {
        
        DefaultOAuth2AuthorizationRequestResolver resolver = 
            new DefaultOAuth2AuthorizationRequestResolver(
                clientRegRepository,
                "/oauth2/authorization/{registrationId}"
            );
        
        // Set customizer to modify the request before it's used
        resolver.setAuthorizationRequestCustomizer(customizer ->
            customizer
                // Modify the authorization URI (add query params)
                .authorizationRequestUri(uriBuilder ->
                    uriBuilder
                        .queryParam("prompt", "login")
                        .queryParam("max_age", "3600")
                        .build()
                )
                // Or add parameters to the request object
                .additionalParameters(params -> {
                    params.put("custom_param", "custom_value");
                    params.put("login_hint", getUserEmail());
                })
        );
        
        return resolver;
    }
    
    private String getUserEmail() {
        Authentication auth = SecurityContextHolder.getContext()
            .getAuthentication();
        return auth != null ? auth.getName() : "";
    }
}
```

---

## 7. OAuth2AuthorizationRequestRepository Interface

### What It Is
An **Interface** that defines a CONTRACT for storing/retrieving authorization requests.

### Contract Definition

```java
public interface OAuth2AuthorizationRequestRepository {
    
    // Load authorization request from storage
    // Input: HTTP request (contains session ID)
    // Output: OAuth2AuthorizationRequest (or null if not found)
    // Purpose: Retrieve request that was stored in saveAuthorizationRequest()
    OAuth2AuthorizationRequest loadAuthorizationRequest(HttpServletRequest request);
    
    // Save authorization request to storage
    // Input: OAuth2AuthorizationRequest + HTTP request/response
    // Output: none (side effect: stores in session)
    // Purpose: Store request for later retrieval during callback
    void saveAuthorizationRequest(
        OAuth2AuthorizationRequest authorizationRequest,
        HttpServletRequest request,
        HttpServletResponse response
    );
    
    // Remove authorization request from storage
    // Input: HTTP request/response
    // Output: OAuth2AuthorizationRequest that was stored (or null)
    // Purpose: Clean up after use, prevent replay attacks
    OAuth2AuthorizationRequest removeAuthorizationRequest(
        HttpServletRequest request,
        HttpServletResponse response
    );
}
```

### What Data Flows Through This Interface

```
SAVE Operation:
Input:
├─ OAuth2AuthorizationRequest
│  ├─ clientId: "123456789..."
│  ├─ scopes: ["email", "profile"]
│  ├─ state: "abc123xyz"
│  └─ ...other fields...
├─ HttpServletRequest (contains session)
└─ HttpServletResponse

Processing:
└─ Serialize OAuth2AuthorizationRequest
└─ Store in session under key:
   "SPRING_SECURITY_OAUTH2_AUTHORIZATION_REQUEST_ATTR"

LOAD Operation:
Input:
└─ HttpServletRequest (contains JSESSIONID cookie)

Processing:
├─ Get session by JSESSIONID
├─ Retrieve value from session using the key
└─ Deserialize to OAuth2AuthorizationRequest

Output:
└─ OAuth2AuthorizationRequest (or null if not in session)
```

### Built-in Implementation

```java
public class HttpSessionOAuth2AuthorizationRequestRepository 
        implements OAuth2AuthorizationRequestRepository {
    
    private static final String ATTR_NAME = 
        "SPRING_SECURITY_OAUTH2_AUTHORIZATION_REQUEST_ATTR";
    
    @Override
    public void saveAuthorizationRequest(
            OAuth2AuthorizationRequest authorizationRequest,
            HttpServletRequest request,
            HttpServletResponse response) {
        
        // STEP 1: Get or create session
        HttpSession session = request.getSession();
        
        // STEP 2: Store the request in session
        // Session is persisted as cookie (JSESSIONID)
        session.setAttribute(ATTR_NAME, authorizationRequest);
        
        // STEP 3: Session is automatically serialized and sent in response
        // Response contains: Set-Cookie: JSESSIONID=ABC123; ...
    }
    
    @Override
    public OAuth2AuthorizationRequest loadAuthorizationRequest(
            HttpServletRequest request) {
        
        // STEP 1: Get session (creates new if doesn't exist)
        HttpSession session = request.getSession(false);
        
        // STEP 2: If no session exists, return null
        if (session == null) {
            return null;
        }
        
        // STEP 3: Retrieve request from session
        Object attr = session.getAttribute(ATTR_NAME);
        
        // STEP 4: Deserialize and return
        return (OAuth2AuthorizationRequest) attr;
    }
    
    @Override
    public OAuth2AuthorizationRequest removeAuthorizationRequest(
            HttpServletRequest request,
            HttpServletResponse response) {
        
        // STEP 1: Get session
        HttpSession session = request.getSession(false);
        
        if (session == null) {
            return null;
        }
        
        // STEP 2: Retrieve request
        OAuth2AuthorizationRequest authRequest = 
            (OAuth2AuthorizationRequest) session.getAttribute(ATTR_NAME);
        
        // STEP 3: Remove from session (cleanup)
        session.removeAttribute(ATTR_NAME);
        
        // STEP 4: Return for validation
        return authRequest;
    }
}
```

### How to Use - Default (Session-Based)

```java
// Spring auto-configures this, no code needed!
// It's already registered and used by OAuth2AuthorizationRequestRedirectFilter
```

### How to Use - Custom Redis-Based Storage

```java
@Component
public class RedisOAuth2AuthorizationRequestRepository 
        implements OAuth2AuthorizationRequestRepository {
    
    private final RedisTemplate<String, OAuth2AuthorizationRequest> redis;
    private static final String KEY_PREFIX = "oauth2:authreq:";
    private static final long TIMEOUT_MINUTES = 10;
    
    public RedisOAuth2AuthorizationRequestRepository(
            RedisTemplate<String, OAuth2AuthorizationRequest> redis) {
        this.redis = redis;
    }
    
    @Override
    public void saveAuthorizationRequest(
            OAuth2AuthorizationRequest authorizationRequest,
            HttpServletRequest request,
            HttpServletResponse response) {
        
        // STEP 1: Use state parameter as key
        String state = authorizationRequest.getState();
        String key = KEY_PREFIX + state;
        
        // STEP 2: Store in Redis with 10-minute expiry
        redis.opsForValue().set(
            key,
            authorizationRequest,
            TIMEOUT_MINUTES,
            TimeUnit.MINUTES
        );
        
        // STEP 3: Store state in session as backup
        // (in case Redis goes down)
        HttpSession session = request.getSession();
        session.setAttribute("oauth2_state", state);
    }
    
    @Override
    public OAuth2AuthorizationRequest loadAuthorizationRequest(
            HttpServletRequest request) {
        
        // STEP 1: Get state from request parameter
        String state = request.getParameter("state");
        
        if (state == null) {
            return null;
        }
        
        // STEP 2: Look up in Redis
        String key = KEY_PREFIX + state;
        OAuth2AuthorizationRequest authRequest = 
            redis.opsForValue().get(key);
        
        // STEP 3: Return (null if not found or expired)
        return authRequest;
    }
    
    @Override
    public OAuth2AuthorizationRequest removeAuthorizationRequest(
            HttpServletRequest request,
            HttpServletResponse response) {
        
        // STEP 1: Get state parameter
        String state = request.getParameter("state");
        
        if (state == null) {
            return null;
        }
        
        // STEP 2: Retrieve from Redis
        String key = KEY_PREFIX + state;
        OAuth2AuthorizationRequest authRequest = 
            redis.opsForValue().get(key);
        
        // STEP 3: Delete from Redis (cleanup)
        redis.delete(key);
        
        // STEP 4: Return for validation
        return authRequest;
    }
}
```

### Register Custom Repository

```java
@Configuration
public class RedisOAuth2Config {
    
    @Bean
    public OAuth2AuthorizationRequestRepository authorizationRequestRepository(
            RedisTemplate<String, OAuth2AuthorizationRequest> redisTemplate) {
        
        return new RedisOAuth2AuthorizationRequestRepository(redisTemplate);
    }
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.oauth2Login(oauth2 ->
            oauth2.authorizationEndpoint(endpoint ->
                endpoint.authorizationRequestRepository(
                    authorizationRequestRepository(null)  // Will be injected
                )
            )
        );
        return http.build();
    }
}
```

---

## PHASE 1 SUMMARY TABLE

| Component | Type | Purpose | Input → Output |
|-----------|------|---------|-----------------|
| **OAuth2AuthorizationRequestRedirectFilter** | Filter | Entry point that intercepts `/oauth2/authorization/{regId}` | Request → HTTP 302 Redirect |
| **OAuth2AuthorizationRequestResolver** | Interface | Contract for building authorization request | (Request, RegId) → OAuth2AuthorizationRequest |
| **DefaultOAuth2AuthorizationRequestResolver** | Class | Default implementation, builds request from ClientRegistration | (Request, RegId) → OAuth2AuthorizationRequest |
| **ClientRegistrationRepository** | Interface | Contract for storing/retrieving client configs | RegId → ClientRegistration |
| **HttpSessionOAuth2AuthorizationRequestRepository** | Class | Stores requests in HTTP session | Request → Session storage/retrieval |
| **ClientRegistration** | Class | Configuration for one OAuth2 provider | Data holder with clientId, URIs, scopes, etc. |
| **OAuth2AuthorizationRequest** | Class | Request to be sent to provider | Data holder with state, scopes, clientId, etc. |

---

## PHASE 1 COMPLETE - Ready for Phase 2?

**Phase 1 Outcome:**
- User clicks login button
- Filter intercepts request
- ClientRegistrationRepository provides provider config
- Authorization request is built
- Request is stored in session for CSRF validation
- User is redirected to provider's authorization URL

**Next: Phase 2 - Callback Handling**
Ready?