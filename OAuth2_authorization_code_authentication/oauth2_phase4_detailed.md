# PHASE 4: SESSION STORAGE & SUBSEQUENT API REQUESTS - DEEP DEVELOPER GUIDE
## Store Authorized Client, Make Future API Calls, Handle Token Refresh

---

## WHAT HAPPENS IN PHASE 4

After Phase 3 authentication completes:
1. OAuth2AuthorizedClient is created from tokens
2. Stored in repository (session, database, cache, etc.)
3. User makes requests to protected resources
4. App retrieves stored client for API calls
5. Token refreshed automatically if expired
6. User remains authenticated for session duration

---

## ENTRY POINT: After Phase 3 Authentication Complete

```
Flow from Phase 3:
OAuth2AuthenticationToken created
    ↓
OAuth2AuthenticationSuccessHandler called
    ↓
OAuth2AuthorizedClient created
    ↓
Stored in OAuth2AuthorizedClientRepository
    ↓
User redirected to home page (authenticated!)
    ↓
Future requests use stored client & token
```

---

## 1. OAuth2AuthorizedClientRepository Interface

### What It Is
An **Interface** defining CONTRACT for storing/retrieving authorized clients.

### Contract Definition

```java
public interface OAuth2AuthorizedClientRepository {
    
    // Save authorized client to persistent storage
    // Input: client to save + authentication + request/response
    // Output: none (side effect: persists client)
    // Purpose: Store client for future use
    void saveAuthorizedClient(
        OAuth2AuthorizedClient authorizedClient,
        Authentication principal,
        HttpServletRequest request,
        HttpServletResponse response
    );
    
    // Load authorized client from persistent storage
    // Input: registrationId + authentication + request
    // Output: OAuth2AuthorizedClient (or null if not found)
    // Purpose: Retrieve previously stored client
    OAuth2AuthorizedClient loadAuthorizedClient(
        String clientRegistrationId,
        Authentication principal,
        HttpServletRequest request
    );
    
    // Remove authorized client from persistent storage
    // Input: registrationId + authentication + request/response
    // Output: none (side effect: deletes client)
    // Purpose: Logout or revoke authorization
    void removeAuthorizedClient(
        String clientRegistrationId,
        Authentication principal,
        HttpServletRequest request,
        HttpServletResponse response
    );
}
```

### What Data Flows Through

```
SAVE Operation:
Input:
├─ OAuth2AuthorizedClient {
│  ├─ clientRegistration: {...},
│  ├─ principalName: "user@example.com",
│  ├─ accessToken: "ya29.a0Arenxxxxxx",
│  └─ refreshToken: "1//0gxxxx"
├─ Authentication (authenticated user)
└─ HttpRequest/Response (contains session)

Processing:
└─ Serialize OAuth2AuthorizedClient
└─ Store with key: registrationId + principalName

LOAD Operation:
Input:
├─ String clientRegistrationId: "google"
├─ Authentication principal
└─ HttpRequest

Processing:
├─ Retrieve from storage using: registrationId + principalName
└─ Deserialize to OAuth2AuthorizedClient

Output:
└─ OAuth2AuthorizedClient (or null if not found)
```

---

## 2. HttpSessionOAuth2AuthorizedClientRepository

### What It Is
A **Concrete Class** implementing `OAuth2AuthorizedClientRepository` using HTTP session.

### Data It Holds

```java
public class HttpSessionOAuth2AuthorizedClientRepository 
        implements OAuth2AuthorizedClientRepository {
    
    private static final String SESSION_ATTR_PREFIX = 
        "SPRING_SECURITY_OAUTH2_AUTHORIZED_CLIENT_";
    // Session keys like: SPRING_SECURITY_OAUTH2_AUTHORIZED_CLIENT_GOOGLE
}
```

### What It Does - Internal Logic

```java
@Override
public void saveAuthorizedClient(
        OAuth2AuthorizedClient authorizedClient,
        Authentication principal,
        HttpServletRequest request,
        HttpServletResponse response) {
    
    // STEP 1: Get or create HTTP session
    HttpSession session = request.getSession();
    
    // STEP 2: Build storage key using registrationId
    String registrationId = authorizedClient.getClientRegistration()
        .getRegistrationId();
    String sessionAttrName = SESSION_ATTR_PREFIX + registrationId;
    
    // STEP 3: Store client in session
    session.setAttribute(sessionAttrName, authorizedClient);
    
    // Session is automatically persisted as cookie (JSESSIONID)
    // Response contains: Set-Cookie: JSESSIONID=ABC123; ...
}

@Override
public OAuth2AuthorizedClient loadAuthorizedClient(
        String clientRegistrationId,
        Authentication principal,
        HttpServletRequest request) {
    
    // STEP 1: Get session (create new if doesn't exist)
    HttpSession session = request.getSession(false);
    
    // STEP 2: If no session, return null
    if (session == null) {
        return null;
    }
    
    // STEP 3: Build session key
    String sessionAttrName = SESSION_ATTR_PREFIX + clientRegistrationId;
    
    // STEP 4: Retrieve from session
    Object attr = session.getAttribute(sessionAttrName);
    
    // STEP 5: Cast and return
    return (OAuth2AuthorizedClient) attr;
}

@Override
public void removeAuthorizedClient(
        String clientRegistrationId,
        Authentication principal,
        HttpServletRequest request,
        HttpServletResponse response) {
    
    // STEP 1: Get session
    HttpSession session = request.getSession(false);
    
    if (session == null) {
        return;
    }
    
    // STEP 2: Build session key
    String sessionAttrName = SESSION_ATTR_PREFIX + clientRegistrationId;
    
    // STEP 3: Remove from session (logout)
    session.removeAttribute(sessionAttrName);
}
```

### How to Use - Default (Session-Based)

```java
// Spring auto-configures this, no code needed!
// It's already registered when you configure OAuth2

@Configuration
public class SecurityConfig {
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.oauth2Login();  // Uses HttpSessionOAuth2AuthorizedClientRepository by default
        return http.build();
    }
}
```

### How to Use - Custom Database Storage

```java
@Component
public class DatabaseOAuth2AuthorizedClientRepository 
        implements OAuth2AuthorizedClientRepository {
    
    private final OAuth2ClientDAO dao;
    
    public DatabaseOAuth2AuthorizedClientRepository(OAuth2ClientDAO dao) {
        this.dao = dao;
    }
    
    @Override
    public void saveAuthorizedClient(
            OAuth2AuthorizedClient authorizedClient,
            Authentication principal,
            HttpServletRequest request,
            HttpServletResponse response) {
        
        // STEP 1: Extract data from authorized client
        String registrationId = authorizedClient.getClientRegistration()
            .getRegistrationId();
        String principalName = authorizedClient.getPrincipalName();
        String accessTokenValue = authorizedClient.getAccessToken()
            .getTokenValue();
        Instant accessTokenExpiresAt = authorizedClient.getAccessToken()
            .getExpiresAt();
        
        String refreshTokenValue = null;
        if (authorizedClient.getRefreshToken() != null) {
            refreshTokenValue = authorizedClient.getRefreshToken()
                .getTokenValue();
        }
        
        // STEP 2: Create entity
        OAuth2ClientEntity entity = new OAuth2ClientEntity();
        entity.setRegistrationId(registrationId);
        entity.setPrincipalName(principalName);
        entity.setAccessTokenValue(accessTokenValue);
        entity.setAccessTokenExpiresAt(accessTokenExpiresAt);
        entity.setRefreshTokenValue(refreshTokenValue);
        entity.setClientRegistrationId(registrationId);
        entity.setUpdatedAt(Instant.now());
        
        // STEP 3: Save to database
        dao.save(entity);
    }
    
    @Override
    public OAuth2AuthorizedClient loadAuthorizedClient(
            String clientRegistrationId,
            Authentication principal,
            HttpServletRequest request) {
        
        // STEP 1: Get principal name
        String principalName = principal.getName();
        
        // STEP 2: Load from database
        OAuth2ClientEntity entity = dao.findByRegistrationIdAndPrincipalName(
            clientRegistrationId,
            principalName
        );
        
        if (entity == null) {
            return null;
        }
        
        // STEP 3: Get client registration
        ClientRegistration clientRegistration = 
            clientRegistrationRepository.findByRegistrationId(
                clientRegistrationId
            );
        
        if (clientRegistration == null) {
            return null;
        }
        
        // STEP 4: Reconstruct OAuth2AccessToken
        OAuth2AccessToken accessToken = new OAuth2AccessToken(
            OAuth2AccessToken.TokenType.BEARER,
            entity.getAccessTokenValue(),
            Instant.now(),
            entity.getAccessTokenExpiresAt()
        );
        
        // STEP 5: Reconstruct OAuth2RefreshToken (if exists)
        OAuth2RefreshToken refreshToken = null;
        if (entity.getRefreshTokenValue() != null) {
            refreshToken = new OAuth2RefreshToken(
                entity.getRefreshTokenValue(),
                Instant.now()
            );
        }
        
        // STEP 6: Create and return OAuth2AuthorizedClient
        return new OAuth2AuthorizedClient(
            clientRegistration,
            entity.getPrincipalName(),
            accessToken,
            refreshToken
        );
    }
    
    @Override
    public void removeAuthorizedClient(
            String clientRegistrationId,
            Authentication principal,
            HttpServletRequest request,
            HttpServletResponse response) {
        
        // STEP 1: Get principal name
        String principalName = principal.getName();
        
        // STEP 2: Delete from database
        dao.deleteByRegistrationIdAndPrincipalName(
            clientRegistrationId,
            principalName
        );
    }
}

// DAO interface
@Repository
public interface OAuth2ClientDAO extends JpaRepository<OAuth2ClientEntity, Long> {
    OAuth2ClientEntity findByRegistrationIdAndPrincipalName(
        String registrationId,
        String principalName
    );
    void deleteByRegistrationIdAndPrincipalName(
        String registrationId,
        String principalName
    );
}

// Entity class
@Entity
@Table(name = "oauth2_authorized_clients")
public class OAuth2ClientEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(nullable = false)
    private String registrationId;
    
    @Column(nullable = false)
    private String principalName;
    
    @Column(nullable = false, columnDefinition = "LONGTEXT")
    private String accessTokenValue;
    
    @Column
    private Instant accessTokenExpiresAt;
    
    @Column(columnDefinition = "LONGTEXT")
    private String refreshTokenValue;
    
    @Column
    private Instant updatedAt;
    
    // Getters and setters...
}
```

### Register Custom Repository

```java
@Configuration
public class RepositoryConfig {
    
    @Bean
    public OAuth2AuthorizedClientRepository authorizedClientRepository(
            OAuth2ClientDAO dao) {
        return new DatabaseOAuth2AuthorizedClientRepository(dao);
    }
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.oauth2Login();
        return http.build();
    }
}
```

---

## 3. OAuth2AuthorizedClientManager Interface

### What It Is
An **Interface** managing authorized client lifecycle (retrieval + refresh).

### Contract Definition

```java
public interface OAuth2AuthorizedClientManager {
    
    // Get authorized client, refreshing if needed
    // Input: OAuth2AuthorizeRequest (contains registrationId, authentication)
    // Output: OAuth2AuthorizedClient (or null if cannot authorize)
    // Purpose: Get valid client with non-expired token
    OAuth2AuthorizedClient authorize(OAuth2AuthorizeRequest authorizeRequest);
}
```

### What Data Flows Through

```
Input:
└─ OAuth2AuthorizeRequest {
    clientRegistrationId: "google",
    principal: Authentication,
    request: HttpServletRequest,
    response: HttpServletResponse
}

Processing:
├─ Load OAuth2AuthorizedClient from repository
├─ Check if access token expired
├─ If expired, refresh using refresh token
└─ Return valid (non-expired) client

Output:
└─ OAuth2AuthorizedClient {
    accessToken: (fresh if was expired),
    refreshToken: (unchanged),
    ...
}
```

---

## 4. DefaultOAuth2AuthorizedClientManager

### What It Is
A **Concrete Class** implementing `OAuth2AuthorizedClientManager`.

### Data It Holds

```java
public class DefaultOAuth2AuthorizedClientManager 
        implements OAuth2AuthorizedClientManager {
    
    private final ClientRegistrationRepository clientRegistrationRepository;
    // Look up client config
    
    private final OAuth2AuthorizedClientRepository authorizedClientRepository;
    // Load/save authorized client
    
    private OAuth2AuthorizedClientProvider authorizedClientProvider;
    // Providers for handling different grant types (auth code, refresh)
}
```

### What It Does - Internal Logic

```java
@Override
public OAuth2AuthorizedClient authorize(OAuth2AuthorizeRequest authorizeRequest) {
    
    String clientRegistrationId = authorizeRequest.getClientRegistrationId();
    
    // STEP 1: Load authorized client from storage
    OAuth2AuthorizedClient authorizedClient = 
        authorizedClientRepository.loadAuthorizedClient(
            clientRegistrationId,
            authorizeRequest.getPrincipal(),
            authorizeRequest.getRequest()
        );
    
    // STEP 2: If client already exists
    if (authorizedClient != null) {
        
        // Check if access token expired
        if (!authorizedClient.getAccessToken().isExpired()) {
            // Token still valid, return as-is
            return authorizedClient;
        }
        
        // Token expired, try to refresh
        // Delegates to OAuth2AuthorizedClientProvider
        OAuth2AuthorizedClient refreshedClient = 
            authorizedClientProvider.authorize(authorizeRequest);
        
        if (refreshedClient != null) {
            // Refresh successful, save updated client
            authorizedClientRepository.saveAuthorizedClient(
                refreshedClient,
                authorizeRequest.getPrincipal(),
                authorizeRequest.getRequest(),
                authorizeRequest.getResponse()
            );
            
            return refreshedClient;
        }
    }
    
    // STEP 3: If no client exists, try to authorize from scratch
    OAuth2AuthorizedClient newClient = 
        authorizedClientProvider.authorize(authorizeRequest);
    
    if (newClient != null) {
        authorizedClientRepository.saveAuthorizedClient(
            newClient,
            authorizeRequest.getPrincipal(),
            authorizeRequest.getRequest(),
            authorizeRequest.getResponse()
        );
    }
    
    return newClient;
}
```

### How to Use - Configure with Token Refresh

```java
@Configuration
public class ClientManagerConfig {
    
    @Bean
    public OAuth2AuthorizedClientManager authorizedClientManager(
            ClientRegistrationRepository clientRegistrationRepository,
            OAuth2AuthorizedClientRepository authorizedClientRepository) {
        
        // STEP 1: Create manager
        DefaultOAuth2AuthorizedClientManager manager = 
            new DefaultOAuth2AuthorizedClientManager(
                clientRegistrationRepository,
                authorizedClientRepository
            );
        
        // STEP 2: Create provider for authorization code grant
        AuthorizationCodeOAuth2AuthorizedClientProvider authCodeProvider = 
            new AuthorizationCodeOAuth2AuthorizedClientProvider();
        
        // STEP 3: Create provider for refresh token grant
        RefreshTokenOAuth2AuthorizedClientProvider refreshProvider = 
            new RefreshTokenOAuth2AuthorizedClientProvider();
        
        // STEP 4: Create delegating provider (try each in order)
        DelegatingOAuth2AuthorizedClientProvider delegatingProvider = 
            new DelegatingOAuth2AuthorizedClientProvider(
                authCodeProvider,
                refreshProvider
            );
        
        // STEP 5: Set provider on manager
        manager.setAuthorizedClientProvider(delegatingProvider);
        
        return manager;
    }
}
```

---

## 5. OAuth2AuthorizeRequest Class

### What It Is
A **Data Transfer Object (DTO)** for requesting authorized client.

### Data Structure

```java
public class OAuth2AuthorizeRequest {
    
    // Which OAuth2 provider
    private String clientRegistrationId;
    // Example: "google"
    
    // Authenticated user
    private Authentication principal;
    // Contains authenticated user info
    
    // HTTP request/response
    private HttpServletRequest request;
    private HttpServletResponse response;
    // For repository operations
    
    // Additional attributes (optional)
    private Map<String, Object> attributes;
}
```

### How to Use - Build Request

```java
@RestController
public class ApiController {
    
    private final OAuth2AuthorizedClientManager clientManager;
    private final RestTemplate restTemplate;
    
    @GetMapping("/fetch-user-data")
    public ResponseEntity<Map<String, Object>> fetchUserData(
            HttpServletRequest request,
            HttpServletResponse response) throws IOException {
        
        // STEP 1: Get authenticated user
        Authentication authentication = 
            SecurityContextHolder.getContext().getAuthentication();
        
        if (authentication == null || !authentication.isAuthenticated()) {
            return ResponseEntity.status(401).body(null);
        }
        
        // STEP 2: Build OAuth2AuthorizeRequest
        OAuth2AuthorizeRequest authorizeRequest = 
            OAuth2AuthorizeRequest
                .withClientRegistrationId("google")
                .principal(authentication)
                .request(request)
                .response(response)
                .build();
        
        // STEP 3: Get authorized client (with refresh if needed)
        OAuth2AuthorizedClient authorizedClient = 
            clientManager.authorize(authorizeRequest);
        
        if (authorizedClient == null) {
            return ResponseEntity.status(401).body(null);
        }
        
        // STEP 4: Get access token
        String accessToken = authorizedClient.getAccessToken()
            .getTokenValue();
        
        // STEP 5: Make API call with token
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);
        
        HttpEntity<String> entity = new HttpEntity<>("", headers);
        
        ResponseEntity<Map<String, Object>> apiResponse = 
            restTemplate.exchange(
                "https://www.googleapis.com/drive/v3/files",
                HttpMethod.GET,
                entity,
                new ParameterizedTypeReference<Map<String, Object>>() {}
            );
        
        return apiResponse;
    }
}
```

---

## 6. RefreshTokenOAuth2AuthorizedClientProvider

### What It Is
A **Concrete Class** handling token refresh when access token expires.

### Data It Holds

```java
public class RefreshTokenOAuth2AuthorizedClientProvider 
        implements OAuth2AuthorizedClientProvider {
    
    private OAuth2AccessTokenResponseClient<OAuth2RefreshTokenGrantRequest> 
        accessTokenResponseClient;
    // Makes POST to token endpoint with refresh token
    
    private Clock clock;
    // For checking token expiry
}
```

### What It Does - Internal Logic

```java
@Override
public OAuth2AuthorizedClient authorize(OAuth2AuthorizeRequest authorizeRequest) {
    
    // STEP 1: Get authorized client
    OAuth2AuthorizedClient authorizedClient = 
        authorizeRequest.getAuthorizedClient();
    
    if (authorizedClient == null) {
        return null;
    }
    
    // STEP 2: Get refresh token
    OAuth2RefreshToken refreshToken = authorizedClient.getRefreshToken();
    
    if (refreshToken == null) {
        // No refresh token available
        return null;
    }
    
    // STEP 3: Check if access token expired
    OAuth2AccessToken accessToken = authorizedClient.getAccessToken();
    
    if (accessToken != null && !isTokenExpired(accessToken)) {
        // Token still valid
        return authorizedClient;
    }
    
    // STEP 4: Prepare refresh request
    OAuth2RefreshTokenGrantRequest refreshRequest = 
        new OAuth2RefreshTokenGrantRequest(
            authorizedClient.getClientRegistration(),
            accessToken,
            refreshToken
        );
    
    // STEP 5: Call token endpoint to get new access token
    // POST https://www.googleapis.com/oauth2/v4/token
    // Body: grant_type=refresh_token&refresh_token=1%2F0gxxxx&client_id=xxx&client_secret=xxx
    OAuth2AccessTokenResponse tokenResponse;
    try {
        tokenResponse = accessTokenResponseClient.getTokenResponse(refreshRequest);
    } catch (OAuth2AuthorizationException ex) {
        return null;  // Refresh failed
    }
    
    // STEP 6: Create new authorized client with fresh token
    OAuth2AuthorizedClient refreshedClient = new OAuth2AuthorizedClient(
        authorizedClient.getClientRegistration(),
        authorizedClient.getPrincipalName(),
        tokenResponse.getAccessToken(),
        tokenResponse.getRefreshToken() != null ? 
            tokenResponse.getRefreshToken() : 
            refreshToken  // Keep old refresh token if new one not provided
    );
    
    return refreshedClient;
}

private boolean isTokenExpired(OAuth2AccessToken token) {
    Instant expiresAt = token.getExpiresAt();
    if (expiresAt == null) {
        return false;  // No expiry info
    }
    
    // Check if expired (with small buffer, e.g., 1 minute)
    return expiresAt.isBefore(Instant.now().plus(Duration.ofMinutes(1)));
}
```

### How to Use - Automatic Token Refresh

```java
@RestController
public class AutoRefreshApiController {
    
    private final OAuth2AuthorizedClientManager clientManager;
    private final RestTemplate restTemplate;
    
    @GetMapping("/api/protected-resource")
    public ResponseEntity<String> callProtectedAPI(
            HttpServletRequest request,
            HttpServletResponse response) throws IOException {
        
        // STEP 1: Get authenticated user
        Authentication authentication = 
            SecurityContextHolder.getContext().getAuthentication();
        
        // STEP 2: Build authorize request
        OAuth2AuthorizeRequest authorizeRequest = 
            OAuth2AuthorizeRequest
                .withClientRegistrationId("google")
                .principal(authentication)
                .request(request)
                .response(response)
                .build();
        
        // STEP 3: Get authorized client
        // If token expired, RefreshTokenOAuth2AuthorizedClientProvider
        // will automatically refresh it!
        OAuth2AuthorizedClient authorizedClient = 
            clientManager.authorize(authorizeRequest);
        
        if (authorizedClient == null) {
            return ResponseEntity.status(401).body("Not authorized");
        }
        
        // STEP 4: Token is guaranteed to be fresh here
        String accessToken = authorizedClient.getAccessToken()
            .getTokenValue();
        
        // STEP 5: Call API with fresh token
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);
        headers.setContentType(MediaType.APPLICATION_JSON);
        
        HttpEntity<String> entity = new HttpEntity<>("", headers);
        
        ResponseEntity<String> apiResponse = restTemplate.exchange(
            "https://www.googleapis.com/calendar/v3/calendars/primary/events",
            HttpMethod.GET,
            entity,
            String.class
        );
        
        return apiResponse;
    }
}
```

---

## 7. DelegatingOAuth2AuthorizedClientProvider

### What It Is
A **Concrete Class** that delegates to multiple providers in sequence.

### What It Does

```java
public class DelegatingOAuth2AuthorizedClientProvider 
        implements OAuth2AuthorizedClientProvider {
    
    private final List<OAuth2AuthorizedClientProvider> providers;
    // List of providers to try in order
    
    @Override
    public OAuth2AuthorizedClient authorize(OAuth2AuthorizeRequest authorizeRequest) {
        
        // STEP 1: Try each provider in order
        for (OAuth2AuthorizedClientProvider provider : providers) {
            
            // STEP 2: Call provider
            OAuth2AuthorizedClient authorizedClient = 
                provider.authorize(authorizeRequest);
            
            // STEP 3: If provider returns client, use it
            if (authorizedClient != null) {
                return authorizedClient;
            }
        }
        
        // STEP 4: If no provider succeeded, return null
        return null;
    }
}
```

### How to Use - Chain Multiple Providers

```java
@Configuration
public class DelegatingProviderConfig {
    
    @Bean
    public OAuth2AuthorizedClientProvider authorizedClientProvider() {
        
        // STEP 1: Create individual providers
        AuthorizationCodeOAuth2AuthorizedClientProvider authCodeProvider = 
            new AuthorizationCodeOAuth2AuthorizedClientProvider();
        
        RefreshTokenOAuth2AuthorizedClientProvider refreshProvider = 
            new RefreshTokenOAuth2AuthorizedClientProvider();
        
        // STEP 2: Create delegating provider
        return new DelegatingOAuth2AuthorizedClientProvider(
            authCodeProvider,      // Try this first
            refreshProvider        // Try this second
        );
        
        // Usage:
        // - If client exists and token fresh: authCodeProvider returns it
        // - If client exists but token expired: refreshProvider refreshes it
        // - If no client exists: both return null
    }
}
```

---

## PHASE 4 SUMMARY TABLE

| Component | Type | Purpose | Input → Output |
|-----------|------|---------|-----------------|
| **OAuth2AuthorizedClientRepository** | Interface | Contract for storing/retrieving authorized clients | Client → Storage/Retrieval |
| **HttpSessionOAuth2AuthorizedClientRepository** | Class | Session-based storage (default) | Client → Session attribute |
| **DatabaseOAuth2AuthorizedClientRepository** | Class | Database-backed storage | Client → Database record |
| **OAuth2AuthorizedClientManager** | Interface | Manages client lifecycle + refresh | AuthorizeRequest → Valid Client |
| **DefaultOAuth2AuthorizedClientManager** | Class | Default manager with refresh handling | Request → Client (refreshed if needed) |
| **OAuth2AuthorizeRequest** | Class | Request for authorized client | Request data → Request object |
| **RefreshTokenOAuth2AuthorizedClientProvider** | Class | Handles token refresh when expired | Expired token → Fresh token |
| **DelegatingOAuth2AuthorizedClientProvider** | Class | Chains multiple providers | Request → Result from first matching provider |

---

## PHASE 4 COMPLETE

**Phase 4 Outcome:**
- OAuth2AuthorizedClient stored in session/database
- Manager loads and checks token expiry
- Token automatically refreshed if expired
- Fresh token used for API calls
- User remains authenticated until logout

**Phases 1-4 Summary:**
- **Phase 1:** User login → Authorization request → Redirect to provider
- **Phase 2:** Provider callback → Code → Token exchange
- **Phase 3:** Token → User info fetch → Authenticated token
- **Phase 4:** Authorized client stored → Token refresh → API calls

---

**OAuth2 Authorization Code Grant Flow Complete! 🎉**

All 4 phases covered with detailed contracts, data flows, and practical usage examples.