# PHASE 3: USER INFO FETCH & COMPLETE AUTHENTICATION - DEEP DEVELOPER GUIDE
## Exchange Token for User Info, Create Authenticated Session

---

## WHAT HAPPENS IN PHASE 3

After access token is obtained in Phase 2:
1. Your app calls provider's UserInfo endpoint with access token
2. Provider returns user details (email, name, picture, etc.)
3. User object is created and authenticated
4. Authenticated token is set in SecurityContext
5. User session is established

---

## ENTRY POINT: After Phase 2 Token Exchange

```
Flow from Phase 2:
OAuth2AccessTokenResponse received
    ↓
OAuth2LoginAuthenticationProvider processes it
    ↓
Calls OAuth2UserService to fetch user info
    ↓
Creates OAuth2User
    ↓
Creates authenticated OAuth2AuthenticationToken
    ↓
User is logged in!
```

---

## 1. OAuth2LoginAuthenticationProvider

### What It Is
A **Spring Security Provider** that authenticates OAuth2 users (implements `AuthenticationProvider`).

### Contract It Implements

```java
public interface AuthenticationProvider {
    
    // Authenticate the given authentication object
    // Input: Authentication (with incomplete data)
    // Output: Authentication (fully authenticated with principal & authorities)
    // Throws: AuthenticationException if auth fails
    Authentication authenticate(Authentication authentication) 
        throws AuthenticationException;
    
    // Check if this provider supports given authentication type
    // Input: Authentication class
    // Output: boolean (true if this provider handles it)
    boolean supports(Class<?> authentication);
}
```

### Data It Holds

```java
public class OAuth2LoginAuthenticationProvider implements AuthenticationProvider {
    
    private final OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> 
        accessTokenResponseClient;
    // Makes POST to token endpoint to exchange code for token
    
    private final OAuth2UserService<OAuth2UserRequest, OAuth2User> userService;
    // Fetches user info from provider's userinfo endpoint
    
    private final GrantedAuthoritiesMapper authoritiesMapper;
    // Maps provider roles/scopes to Spring authorities
}
```

### What It Does - Internal Logic

```java
@Override
public Authentication authenticate(Authentication authentication) 
        throws AuthenticationException {
    
    OAuth2AuthenticationToken token = (OAuth2AuthenticationToken) authentication;
    String registrationId = token.getAuthorizedClientRegistrationId();
    
    // STEP 1: Get client registration
    ClientRegistration clientRegistration = 
        clientRegistrationRepository.findByRegistrationId(registrationId);
    
    if (clientRegistration == null) {
        throw new OAuth2AuthenticationException(
            "Unknown registration id: " + registrationId
        );
    }
    
    // STEP 2: Get authorization code and response from token
    // (These were set by OAuth2LoginAuthenticationFilter)
    OAuth2AuthorizationCodeGrantRequest grantRequest = 
        buildGrantRequest(token, clientRegistration);
    
    // STEP 3: Exchange authorization code for access token
    // Makes POST request to provider's token endpoint
    OAuth2AccessTokenResponse accessTokenResponse;
    try {
        accessTokenResponse = accessTokenResponseClient.getTokenResponse(grantRequest);
    } catch (OAuth2AuthorizationException ex) {
        throw new OAuth2AuthenticationException(
            "Failed to exchange code for access token: " + ex.getMessage()
        );
    }
    
    // STEP 4: Create OAuth2UserRequest (for fetching user info)
    OAuth2UserRequest userRequest = new OAuth2UserRequest(
        clientRegistration,
        accessTokenResponse.getAccessToken()
    );
    // This contains: client config + access token
    
    // STEP 5: Fetch user info from provider
    // Makes GET request to provider's userinfo endpoint
    // Authorization: Bearer <access_token>
    OAuth2User oAuth2User;
    try {
        oAuth2User = userService.loadUser(userRequest);
    } catch (Exception ex) {
        throw new OAuth2AuthenticationException(
            "Failed to fetch user info: " + ex.getMessage()
        );
    }
    
    // STEP 6: Get user authorities/roles
    Collection<GrantedAuthority> authorities = 
        authoritiesMapper.mapAuthorities(oAuth2User.getAuthorities());
    
    // STEP 7: Create authenticated OAuth2AuthenticationToken
    OAuth2AuthenticationToken authenticatedToken = 
        new OAuth2AuthenticationToken(
            oAuth2User,              // principal (user with attributes)
            authorities,             // authorities/roles
            registrationId
        );
    authenticatedToken.setAuthenticated(true);
    
    // STEP 8: Return authenticated token
    return authenticatedToken;
}

@Override
public boolean supports(Class<?> authentication) {
    return OAuth2AuthenticationToken.class.isAssignableFrom(authentication);
}
```

### How to Use - Customize Authorities Mapping

```java
@Configuration
public class CustomAuthoritiesConfig {
    
    @Bean
    public GrantedAuthoritiesMapper authoritiesMapper() {
        return authorities -> {
            // STEP 1: Get original authorities from user attributes
            Set<GrantedAuthority> mappedAuthorities = new HashSet<>(authorities);
            
            // STEP 2: Add custom authorities based on scopes
            for (GrantedAuthority authority : authorities) {
                String authName = authority.getAuthority();
                
                if ("email".equals(authName)) {
                    mappedAuthorities.add(
                        new SimpleGrantedAuthority("ROLE_EMAIL_USER")
                    );
                }
                
                if ("profile".equals(authName)) {
                    mappedAuthorities.add(
                        new SimpleGrantedAuthority("ROLE_PROFILE_AVAILABLE")
                    );
                }
            }
            
            // STEP 3: Return mapped authorities
            return mappedAuthorities;
        };
    }
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.oauth2Login(oauth2 ->
            oauth2.userInfoEndpoint(endpoint ->
                endpoint.userAuthoritiesMapper(authoritiesMapper())
            )
        );
        return http.build();
    }
}
```

---

## 2. OAuth2UserService Interface

### What It Is
An **Interface** defining CONTRACT for loading user information from provider.

### Contract Definition

```java
public interface OAuth2UserService<R extends AbstractOAuth2UserRequest, U extends OAuth2User> {
    
    // Fetch user info from provider's userinfo endpoint
    // Input: OAuth2UserRequest (contains client config + access token)
    // Output: OAuth2User (user with attributes and authorities)
    // Throws: OAuth2AuthenticationException if fetch fails
    U loadUser(R userRequest) throws OAuth2AuthenticationException;
}
```

### What Data Flows Through

```
Input:
└─ OAuth2UserRequest {
    clientRegistration: {...},
    accessToken: {
        tokenValue: "ya29.a0Arenxxxxxx",
        ...
    }
}

Processing:
├─ Build GET request to userinfo endpoint
├─ Add Authorization header: "Bearer ya29.a0Arenxxxxxx"
├─ Send request: GET https://www.googleapis.com/oauth2/v1/userinfo
└─ Parse response JSON

Output:
└─ OAuth2User {
    name: "user@example.com",
    attributes: {
        "sub": "107936220804",
        "email": "user@example.com",
        "name": "John Doe",
        "picture": "https://..."
    },
    authorities: [...]
}
```

---

## 3. DefaultOAuth2UserService

### What It Is
A **Concrete Class** implementing `OAuth2UserService` using RestTemplate.

### Data It Holds

```java
public class DefaultOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {
    
    private RestOperations restOperations;
    // Spring's RestTemplate for making HTTP requests
    
    private OAuth2UserRequestEntityConverter requestEntityConverter;
    // Converts OAuth2UserRequest to GET request to userinfo endpoint
    
    private OAuth2UserResponseConverter userResponseConverter;
    // Converts JSON response to Map of user attributes
}
```

### What It Does - Internal Logic

```java
@Override
public OAuth2User loadUser(OAuth2UserRequest userRequest) 
        throws OAuth2AuthenticationException {
    
    ClientRegistration clientRegistration = userRequest.getClientRegistration();
    String userInfoUri = clientRegistration.getProviderDetails()
        .getUserInfoEndpoint().getUri();
    
    // STEP 1: Build HTTP GET request with access token
    // Authorization: Bearer <access_token>
    RequestEntity<?> request = 
        requestEntityConverter.convert(userRequest);
    
    // STEP 2: Make GET request to userinfo endpoint
    // GET https://www.googleapis.com/oauth2/v1/userinfo
    ResponseEntity<Map<String, Object>> response;
    try {
        response = restOperations.exchange(
            request,
            new ParameterizedTypeReference<Map<String, Object>>() {}
        );
    } catch (RestClientException ex) {
        throw new OAuth2AuthenticationException(
            "Failed to get user info: " + ex.getMessage()
        );
    }
    
    // STEP 3: Check response is 200 OK
    if (!response.getStatusCode().is2xxSuccessful()) {
        throw new OAuth2AuthenticationException(
            "Userinfo endpoint returned error: " + response.getStatusCode()
        );
    }
    
    // STEP 4: Get user attributes from response body
    Map<String, Object> userAttributes = response.getBody();
    
    // STEP 5: Get the unique user identifier attribute name
    String userNameAttributeName = clientRegistration
        .getProviderDetails()
        .getUserInfoEndpoint()
        .getUserNameAttributeName();
    
    if (userNameAttributeName == null) {
        throw new OAuth2AuthenticationException(
            "Missing userNameAttributeName in client registration"
        );
    }
    
    // STEP 6: Create DefaultOAuth2User with attributes
    DefaultOAuth2User user = new DefaultOAuth2User(
        AuthorityUtils.createAuthorityList("ROLE_USER"),
        userAttributes,
        userNameAttributeName
    );
    
    // STEP 7: Return user
    return user;
}
```

### How to Use - Custom User Service with Database Lookup

```java
@Component
public class CustomOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {
    
    private final DefaultOAuth2UserService delegate;
    private final UserRepository userRepository;
    private final UserMapper userMapper;
    
    public CustomOAuth2UserService(
            DefaultOAuth2UserService delegate,
            UserRepository userRepository,
            UserMapper userMapper) {
        this.delegate = delegate;
        this.userRepository = userRepository;
        this.userMapper = userMapper;
    }
    
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) 
            throws OAuth2AuthenticationException {
        
        // STEP 1: Call default service to fetch from provider
        OAuth2User oAuth2User = delegate.loadUser(userRequest);
        
        // STEP 2: Extract user identifier
        String userId = oAuth2User.getName();
        String email = oAuth2User.getAttribute("email");
        String registrationId = userRequest.getClientRegistration()
            .getRegistrationId();
        
        // STEP 3: Look up user in database
        UserEntity existingUser = userRepository
            .findByEmailAndProvider(email, registrationId);
        
        // STEP 4: Save or update user
        if (existingUser == null) {
            // New user - create entry
            UserEntity newUser = new UserEntity();
            newUser.setEmail(email);
            newUser.setName(oAuth2User.getAttribute("name"));
            newUser.setProvider(registrationId);
            newUser.setProviderUserId(userId);
            newUser.setProfilePicture(oAuth2User.getAttribute("picture"));
            newUser.setCreatedAt(Instant.now());
            
            userRepository.save(newUser);
        } else {
            // Existing user - update last login
            existingUser.setLastLoginAt(Instant.now());
            userRepository.save(existingUser);
        }
        
        // STEP 5: Return user (can wrap in custom class)
        return oAuth2User;
    }
}

@Configuration
public class CustomUserServiceConfig {
    
    @Bean
    public OAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService(
            UserRepository userRepository,
            UserMapper userMapper) {
        return new CustomOAuth2UserService(
            new DefaultOAuth2UserService(),
            userRepository,
            userMapper
        );
    }
}
```

---

## 4. OAuth2UserRequest Class

### What It Is
A **Data Transfer Object (DTO)** containing request data for fetching user info.

### Data Structure

```java
public class OAuth2UserRequest {
    
    // OAuth2 provider configuration
    private ClientRegistration clientRegistration;
    // Contains: userInfoUri, userNameAttributeName, etc.
    
    // Access token to authenticate to userinfo endpoint
    private OAuth2AccessToken accessToken;
    // Contains: tokenValue ("Bearer ya29.a0Arenxxxxxx"), expiresAt
}
```

### What It Represents

Bundle of data needed to fetch user info:
```
User Info Request = {
    Client Config (where to fetch) + Access Token (authentication)
}
```

### How to Use - Build Manually

```java
public class UserInfoRequestBuilder {
    
    public static OAuth2UserRequest buildRequest(
            ClientRegistration clientRegistration,
            OAuth2AccessToken accessToken) {
        
        return new OAuth2UserRequest(
            clientRegistration,
            accessToken
        );
    }
}
```

---

## 5. OAuth2User Interface

### What It Is
An **Interface** representing authenticated OAuth2 user with attributes.

### Contract Definition

```java
public interface OAuth2User extends AuthenticatedPrincipal {
    
    // Get map of user attributes from provider
    // Returns: email, name, picture, sub, etc.
    Map<String, Object> getAttributes();
    
    // Get user's authorities/roles
    Collection<? extends GrantedAuthority> getAuthorities();
    
    // Get user's name/identifier
    String getName();
}
```

### What Data Flows Through

```
Input from Provider:
{
    "sub": "107936220804",
    "email": "user@example.com",
    "email_verified": true,
    "name": "John Doe",
    "picture": "https://lh3.googleusercontent.com/...",
    "given_name": "John",
    "family_name": "Doe",
    "locale": "en"
}

Wrapped in:
OAuth2User {
    attributes: {
        "sub": "107936220804",
        "email": "user@example.com",
        "name": "John Doe",
        ...
    },
    authorities: [ROLE_USER],
    name: "user@example.com" (or "107936220804" depending on config)
}
```

---

## 6. DefaultOAuth2User Class

### What It Is
A **Concrete Class** implementing `OAuth2User` interface.

### Data Structure

```java
public class DefaultOAuth2User implements OAuth2User {
    
    // User's granted authorities/roles
    private Collection<? extends GrantedAuthority> authorities;
    // Example: [ROLE_USER, ROLE_PROFILE]
    
    // All user attributes from provider
    private Map<String, Object> attributes;
    // Example: {"sub": "107936220804", "email": "user@example.com", ...}
    
    // Which attribute uniquely identifies user
    private String nameAttributeKey;
    // Example: "sub" or "email" or "login"
}
```

### What It Does With Data

1. **authorities** - Converted to Spring roles/permissions
2. **attributes** - Accessed via `getAttribute(name)` method
3. **nameAttributeKey** - Used to get user's identifier via `getName()`

### How to Use - Access User Attributes

```java
@RestController
public class UserController {
    
    @GetMapping("/user-info")
    public ResponseEntity<Map<String, Object>> getUserInfo(
            @AuthenticationPrincipal OAuth2User oAuth2User) {
        
        // STEP 1: Get all attributes
        Map<String, Object> attributes = oAuth2User.getAttributes();
        
        // STEP 2: Access specific attributes
        String email = (String) attributes.get("email");
        String name = (String) attributes.get("name");
        String picture = (String) attributes.get("picture");
        String sub = (String) attributes.get("sub");
        
        // STEP 3: Get authorities
        Collection<? extends GrantedAuthority> authorities = 
            oAuth2User.getAuthorities();
        
        // STEP 4: Get name/identifier
        String userId = oAuth2User.getName();
        
        // STEP 5: Return as JSON
        Map<String, Object> response = new HashMap<>();
        response.put("email", email);
        response.put("name", name);
        response.put("picture", picture);
        response.put("authorities", authorities);
        response.put("userId", userId);
        
        return ResponseEntity.ok(response);
    }
    
    @GetMapping("/protected")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<String> protectedResource(
            @AuthenticationPrincipal OAuth2User oAuth2User) {
        
        String userEmail = (String) oAuth2User.getAttributes().get("email");
        return ResponseEntity.ok("Hello " + userEmail);
    }
}
```

### How to Use - Create Manually

```java
public class OAuth2UserCreator {
    
    public static OAuth2User createUser(
            Map<String, Object> attributes,
            String nameAttributeKey) {
        
        return new DefaultOAuth2User(
            AuthorityUtils.createAuthorityList("ROLE_USER", "ROLE_PREMIUM"),
            attributes,
            nameAttributeKey
        );
    }
}
```

---

## 7. OAuth2AuthenticationToken Class

### What It Is
A **Spring Security Authentication Token** representing fully authenticated OAuth2 user.

### Data Structure

```java
public class OAuth2AuthenticationToken extends AbstractAuthenticationToken {
    
    // The authenticated principal (OAuth2User)
    private OAuth2User principal;
    // Contains all user attributes and authorities
    
    // User's granted authorities/roles
    private Collection<? extends GrantedAuthority> authorities;
    // Example: [ROLE_USER, ROLE_PROFILE]
    
    // Registration ID of provider
    private String authorizedClientRegistrationId;
    // Example: "google", "github"
    
    // Whether user is fully authenticated
    private boolean authenticated;
    // Set to true after authentication succeeds
}
```

### What It Represents

This is the **final authenticated token** stored in SecurityContext:
```
OAuth2AuthenticationToken = {
    Principal (OAuth2User with attributes) +
    Authorities (roles/permissions) +
    Provider Info +
    Authenticated Flag
}
```

### How to Use - Access in Controllers

```java
@RestController
public class SecureController {
    
    @GetMapping("/my-info")
    public ResponseEntity<Map<String, String>> getMyInfo(
            Authentication authentication) {
        
        // STEP 1: Get the OAuth2AuthenticationToken
        OAuth2AuthenticationToken token = 
            (OAuth2AuthenticationToken) authentication;
        
        // STEP 2: Get the authenticated user
        OAuth2User user = token.getPrincipal();
        
        // STEP 3: Get provider info
        String provider = token.getAuthorizedClientRegistrationId();
        
        // STEP 4: Get user attributes
        String email = (String) user.getAttribute("email");
        String name = (String) user.getAttribute("name");
        
        // STEP 5: Return response
        Map<String, String> response = Map.of(
            "email", email,
            "name", name,
            "provider", provider,
            "userId", user.getName()
        );
        
        return ResponseEntity.ok(response);
    }
    
    @GetMapping("/authorities")
    public ResponseEntity<List<String>> getAuthorities(
            Authentication authentication) {
        
        // Get roles/authorities
        List<String> authorities = authentication.getAuthorities()
            .stream()
            .map(GrantedAuthority::getAuthority)
            .toList();
        
        return ResponseEntity.ok(authorities);
    }
}
```

### How to Use - Check Authentication Status

```java
@Component
public class AuthenticationChecker {
    
    public void checkAuth() {
        // STEP 1: Get security context
        SecurityContext context = SecurityContextHolder.getContext();
        
        // STEP 2: Get authentication
        Authentication authentication = context.getAuthentication();
        
        if (authentication == null) {
            System.out.println("Not authenticated");
            return;
        }
        
        // STEP 3: Check if authenticated
        if (!authentication.isAuthenticated()) {
            System.out.println("Not authenticated");
            return;
        }
        
        // STEP 4: Get principal
        Object principal = authentication.getPrincipal();
        
        // STEP 5: Check type
        if (principal instanceof OAuth2User) {
            OAuth2User oAuth2User = (OAuth2User) principal;
            System.out.println("Authenticated as: " + oAuth2User.getName());
            System.out.println("Email: " + 
                oAuth2User.getAttribute("email"));
        }
    }
}
```

---

## 8. OAuth2AuthorizedClient Class

### What It Is
A **Data Transfer Object (DTO)** storing relationship between client and authenticated user.

### Data Structure

```java
public class OAuth2AuthorizedClient {
    
    // The registered client (provider config)
    private ClientRegistration clientRegistration;
    // Contains: clientId, tokenUri, userInfoUri, etc.
    
    // Principal name (user identifier)
    private String principalName;
    // Example: "user@example.com" or user ID
    
    // Access token for calling APIs
    private OAuth2AccessToken accessToken;
    // Contains: tokenValue, expiresAt, scope
    
    // Refresh token for getting new access token
    private OAuth2RefreshToken refreshToken;
    // Contains: tokenValue (optional)
}
```

### What It Represents

Represents **who** (user) has been authorized by **which** provider (client):
```
OAuth2AuthorizedClient = {
    User + Provider + Access Token + Refresh Token
}
```

Used later for:
- Making API calls on behalf of user
- Refreshing token when expired
- Storing authorization in session

### How to Use - Store in Session

```java
@Component
public class AuthorizedClientStorage {
    
    private final OAuth2AuthorizedClientRepository repository;
    
    public void storeAuthorizedClient(
            OAuth2AuthorizedClient authorizedClient,
            HttpServletRequest request,
            HttpServletResponse response) {
        
        // Store in session/database
        repository.saveAuthorizedClient(
            authorizedClient,
            // Extract authentication from SecurityContext
            SecurityContextHolder.getContext().getAuthentication(),
            request,
            response
        );
    }
}
```

### How to Use - Retrieve Later

```java
@RestController
public class ApiCallerController {
    
    private final OAuth2AuthorizedClientRepository clientRepository;
    private final RestTemplate restTemplate;
    
    @GetMapping("/call-api")
    public ResponseEntity<String> callAPI(
            HttpServletRequest request,
            Authentication authentication) {
        
        // STEP 1: Get authorized client from storage
        OAuth2AuthorizedClient authorizedClient = 
            clientRepository.loadAuthorizedClient(
                "google",  // registrationId
                authentication,
                request
            );
        
        if (authorizedClient == null) {
            return ResponseEntity.status(401).body("Not authorized");
        }
        
        // STEP 2: Get access token
        String accessToken = authorizedClient
            .getAccessToken()
            .getTokenValue();
        
        // STEP 3: Make API call with token
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);
        
        HttpEntity<String> entity = new HttpEntity<>("", headers);
        
        ResponseEntity<String> response = restTemplate.exchange(
            "https://www.googleapis.com/oauth2/v1/userinfo",
            HttpMethod.GET,
            entity,
            String.class
        );
        
        return response;
    }
}
```

---

## PHASE 3 SUMMARY TABLE

| Component | Type | Purpose | Input → Output |
|-----------|------|---------|-----------------|
| **OAuth2LoginAuthenticationProvider** | Provider | Orchestrates token exchange & user fetch | Incomplete Token → Authenticated Token |
| **OAuth2UserService** | Interface | Contract for fetching user info | OAuth2UserRequest → OAuth2User |
| **DefaultOAuth2UserService** | Class | Makes GET to userinfo endpoint | OAuth2UserRequest → OAuth2User |
| **OAuth2UserRequest** | Class | Request to fetch user info | Client + Token → Request object |
| **OAuth2User** | Interface | User with attributes & authorities | Data → Authenticated principal |
| **DefaultOAuth2User** | Class | User implementation with attributes | Attributes → User object |
| **OAuth2AuthenticationToken** | Class | Final authenticated token | User + Authorities → Security token |
| **OAuth2AuthorizedClient** | Class | Store user-client relationship | User + Token → Storage object |

---

## PHASE 3 COMPLETE

**Phase 3 Outcome:**
- Access token used to fetch user info
- User attributes retrieved from provider
- OAuth2User created with authorities
- OAuth2AuthenticationToken created and authenticated
- Stored in SecurityContext
- Session established with authorized client info

**Next: Phase 4 - Session Management & Subsequent Requests**
Ready?