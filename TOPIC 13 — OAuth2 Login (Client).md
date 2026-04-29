# TOPIC 13 — OAuth2 Login (Client)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

---

## 1️⃣ Conceptual Explanation

---

### 13.1 OAuth2 Login Architecture — The Big Picture

Spring Security's OAuth2 Login feature implements the **Authorization Code Grant** (with optional PKCE) on the **client side**. It handles the complete dance between your application, the user's browser, and the Authorization Server.

**The two dedicated filters:**

```
OAuth2 Login involves exactly TWO filters working in sequence:

Filter 1: OAuth2AuthorizationRequestRedirectFilter
     Purpose: Intercepts login initiation requests
     Triggers: GET /oauth2/authorization/{registrationId}
     Action:   Builds authorization URL, redirects browser to Auth Server
     Position: Before UsernamePasswordAuthenticationFilter

Filter 2: OAuth2LoginAuthenticationFilter
     Purpose: Handles the callback from Auth Server
     Triggers: GET /login/oauth2/code/{registrationId}
     Action:   Exchanges authorization code for tokens, authenticates user
     Position: Same position as UsernamePasswordAuthenticationFilter (extends it)
     Base class: AbstractAuthenticationProcessingFilter
```

**Complete request lifecycle overview:**

```
User clicks "Login with Google"
     │
     ▼
GET /oauth2/authorization/google
     │
     ▼
OAuth2AuthorizationRequestRedirectFilter
     └── Builds Google auth URL
     └── Stores OAuth2AuthorizationRequest in session
     └── Redirects browser to Google
     │
     ▼ (browser at Google)
User authenticates + consents at Google
     │
     ▼
Google redirects back:
GET /login/oauth2/code/google?code=AUTH_CODE&state=STATE
     │
     ▼
OAuth2LoginAuthenticationFilter
     └── Validates state
     └── Exchanges code for tokens
     └── Loads user info
     └── Creates OAuth2AuthenticationToken
     └── Stores in SecurityContext
     └── Redirects to dashboard
```

---

### 13.2 OAuth2AuthorizationRequestRedirectFilter — Deep Internals

This filter's job is to **initiate the OAuth2 flow** — build the correct authorization URL and redirect the browser.

```java
public class OAuth2AuthorizationRequestRedirectFilter
        extends OncePerRequestFilter {

    // Default base URI — triggers this filter
    public static final String DEFAULT_AUTHORIZATION_REQUEST_BASE_URI =
        "/oauth2/authorization";

    private final OAuth2AuthorizationRequestResolver authorizationRequestResolver;
    private AuthorizationRequestRepository<OAuth2AuthorizationRequest>
        authorizationRequestRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
            HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        // Step 1: Resolve authorization request
        // Only activates for /oauth2/authorization/{registrationId}
        OAuth2AuthorizationRequest authorizationRequest =
            this.authorizationRequestResolver.resolve(request);

        if (authorizationRequest == null) {
            // Not an authorization request URL → pass through
            filterChain.doFilter(request, response);
            return;
        }

        // Step 2: Save authorization request
        // Stores: state, code_verifier (PKCE), original request URI
        this.authorizationRequestRepository.saveAuthorizationRequest(
            authorizationRequest, request, response);

        // Step 3: Build redirect URL
        // authorizationRequest.getAuthorizationRequestUri()
        // = "https://accounts.google.com/o/oauth2/v2/auth
        //    ?client_id=...&redirect_uri=...&scope=...
        //    &state=RANDOM_STATE&response_type=code"

        // Step 4: Redirect browser to Authorization Server
        this.authorizationRedirectStrategy.sendRedirect(
            request, response,
            authorizationRequest.getAuthorizationRequestUri());
    }
}
```

**`DefaultOAuth2AuthorizationRequestResolver` — what it builds:**

```java
// Internal resolver creates OAuth2AuthorizationRequest:
OAuth2AuthorizationRequest.authorizationCode()
    .authorizationUri(provider.getAuthorizationUri())
    .clientId(registration.getClientId())
    .redirectUri(expandRedirectUri(request, registration))
    .scope(registration.getScopes())
    .state(DEFAULT_STATE_GENERATOR.generateKey())  // SecureKeyGenerator (Base64URL)
    .additionalParameters(params -> {
        // Add PKCE if public client
        if (isPkceRequired(registration)) {
            String codeVerifier = generateCodeVerifier();
            params.put("code_challenge",
                computeCodeChallenge(codeVerifier));
            params.put("code_challenge_method", "S256");
            // Store verifier for later use in token exchange
        }
    })
    .build();
```

**The `state` parameter — CSRF protection built in:**

```
state = BASE64URL(32 random bytes)
      = "bWVzc2FnZXdvcmxkYmVzdA"

Stored in session via authorizationRequestRepository:
     HttpSession.setAttribute(
         "SPRING_SECURITY_OAUTH2_AUTHORIZATIONREQUEST",
         OAuth2AuthorizationRequest{state=..., codeVerifier=..., ...})

When callback arrives:
     Returned state == session state? → valid
     State mismatch → invalid (possible CSRF) → reject
```

---

### 13.3 AuthorizationRequestRepository — Storage Strategies

```java
// Default: HttpSessionOAuth2AuthorizationRequestRepository
// Stores in HTTP session
HttpSessionOAuth2AuthorizationRequestRepository

// Alternative: CookieOAuth2AuthorizationRequestRepository
// Stores in cookie (for stateless or SPA scenarios)
// Part of Spring Security 6.x

// What gets stored:
public class OAuth2AuthorizationRequest implements Serializable {
    String authorizationUri;   // where we sent user
    AuthorizationGrantType grantType; // authorization_code
    String responseType;       // code
    String clientId;
    URI redirectUri;
    Set<String> scopes;
    String state;              // the CSRF protection value
    Map<String, Object> additionalParameters; // includes code_verifier (PKCE)
    String authorizationRequestUri; // the full URL we redirected to
    Map<String, Object> attributes; // extra data (e.g., nonce for OIDC)
}
```

---

### 13.4 OAuth2LoginAuthenticationFilter — Complete Internal Architecture

This filter handles the **callback** from the Authorization Server — the most complex part of the OAuth2 login flow.

```java
public class OAuth2LoginAuthenticationFilter
        extends AbstractAuthenticationProcessingFilter {

    // Default callback URL pattern
    public static final String DEFAULT_FILTER_PROCESSES_URI =
        "/login/oauth2/code/*";

    @Override
    public Authentication attemptAuthentication(
            HttpServletRequest request,
            HttpServletResponse response) throws AuthenticationException {

        // Step 1: Check for OAuth2 error in callback
        // (e.g., user denied consent: error=access_denied)
        MultiValueMap<String, String> params =
            OAuth2AuthorizationResponseUtils.toMultiMap(
                request.getParameterMap());

        if (!OAuth2AuthorizationResponseUtils.isAuthorizationResponse(params)) {
            OAuth2Error error = new OAuth2Error(
                OAuth2ErrorCodes.INVALID_REQUEST);
            throw new OAuth2AuthenticationException(error);
        }

        // Step 2: Load stored authorization request from session
        OAuth2AuthorizationRequest authorizationRequest =
            this.authorizationRequestRepository.removeAuthorizationRequest(
                request, response);
        // REMOVE (not just load) — single use!

        if (authorizationRequest == null) {
            // No matching authorization request in session
            // Possible: session expired, CSRF attack, direct URL access
            OAuth2Error error = new OAuth2Error(
                OAuth2ErrorCodes.INVALID_REQUEST,
                "No authorization request found for state: "
                + request.getParameter("state"), null);
            throw new OAuth2AuthenticationException(error);
        }

        // Step 3: Find matching client registration
        String registrationId = authorizationRequest
            .getAttribute(OAuth2ParameterNames.REGISTRATION_ID);
        ClientRegistration clientRegistration =
            this.clientRegistrationRepository
                .findByRegistrationId(registrationId);

        // Step 4: Build authorization response
        // (wraps code + state + redirectUri from callback URL)
        String redirectUri = UriComponentsBuilder
            .fromHttpUrl(UrlUtils.buildFullRequestUrl(request))
            .build().toUriString();

        OAuth2AuthorizationResponse authorizationResponse =
            OAuth2AuthorizationResponseUtils.convert(params, redirectUri);

        // Step 5: Build authentication token for processing
        OAuth2LoginAuthenticationToken authenticationRequest =
            new OAuth2LoginAuthenticationToken(
                clientRegistration,
                new OAuth2AuthorizationExchange(
                    authorizationRequest,
                    authorizationResponse));

        // Step 6: Authenticate (delegate to AuthenticationManager)
        // This triggers OAuth2LoginAuthenticationProvider
        OAuth2LoginAuthenticationToken authenticationResult =
            (OAuth2LoginAuthenticationToken)
            this.getAuthenticationManager().authenticate(
                authenticationRequest);

        // Step 7: Build final OAuth2AuthenticationToken
        OAuth2AuthenticationToken oauth2Authentication =
            this.authenticationResultConverter
                .convert(authenticationResult);

        // Step 8: Save authorized client for future API calls
        OAuth2AuthorizedClient authorizedClient =
            new OAuth2AuthorizedClient(
                authenticationResult.getClientRegistration(),
                oauth2Authentication.getName(),
                authenticationResult.getAccessToken(),
                authenticationResult.getRefreshToken());

        this.authorizedClientRepository.saveAuthorizedClient(
            authorizedClient, oauth2Authentication, request, response);

        return oauth2Authentication;
    }
}
```

---

### 13.5 OAuth2LoginAuthenticationProvider — The Code Exchange Engine

After `OAuth2LoginAuthenticationFilter` builds the token, `OAuth2LoginAuthenticationProvider` (or `OidcAuthorizationCodeAuthenticationProvider` for OIDC) does the actual work:

```java
public class OAuth2LoginAuthenticationProvider
        implements AuthenticationProvider {

    private final OAuth2AccessTokenResponseClient
        OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient;
    private final OAuth2UserService<OAuth2UserRequest, OAuth2User> userService;

    @Override
    public Authentication authenticate(Authentication authentication) {
        OAuth2LoginAuthenticationToken loginAuthenticationToken =
            (OAuth2LoginAuthenticationToken) authentication;

        // Step 1: Validate state (CSRF check)
        OAuth2AuthorizationExchange exchange =
            loginAuthenticationToken.getAuthorizationExchange();

        if (!exchange.getAuthorizationRequest().getState()
                .equals(exchange.getAuthorizationResponse().getState())) {
            OAuth2Error error = new OAuth2Error(
                OAuth2ErrorCodes.INVALID_STATE_PARAMETER);
            throw new OAuth2AuthenticationException(error);
        }

        // Step 2: Exchange authorization code for access token
        // POST to token endpoint with code + client credentials
        OAuth2AccessTokenResponse accessTokenResponse =
            this.accessTokenResponseClient.getTokenResponse(
                new OAuth2AuthorizationCodeGrantRequest(
                    loginAuthenticationToken.getClientRegistration(),
                    exchange));
        // accessTokenResponse contains:
        //   access_token, token_type, expires_in, refresh_token, scope

        // Step 3: Load user info
        // GET userinfo endpoint with access_token
        OAuth2User oauth2User = this.userService.loadUser(
            new OAuth2UserRequest(
                loginAuthenticationToken.getClientRegistration(),
                accessTokenResponse.getAccessToken(),
                accessTokenResponse.getAdditionalParameters()));

        // Step 4: Validate scopes
        Collection<? extends GrantedAuthority> mappedAuthorities =
            this.authoritiesMapper.mapAuthorities(
                oauth2User.getAuthorities());

        // Step 5: Return authenticated token
        return new OAuth2LoginAuthenticationToken(
            loginAuthenticationToken.getClientRegistration(),
            exchange,
            oauth2User,
            mappedAuthorities,
            accessTokenResponse.getAccessToken(),
            accessTokenResponse.getRefreshToken());
    }
}
```

---

### 13.6 OIDC Authentication Provider — The OpenID Connect Path

When `scope` includes `openid`, Spring Security routes through `OidcAuthorizationCodeAuthenticationProvider`:

```
OAuth2LoginAuthenticationFilter detects OIDC request:
     scope contains "openid" → use OidcAuthorizationCodeAuthenticationProvider

OidcAuthorizationCodeAuthenticationProvider:
     Step 1: Exchange code for token response
          → Same as above via accessTokenResponseClient
          → Response includes: access_token, id_token, refresh_token

     Step 2: Validate id_token (JWT)
          OidcIdTokenDecoderFactory → creates JwtDecoder for this provider
          Validates: signature, issuer, audience, expiry, nonce
          nonce check: stored nonce == id_token nonce claim
               (prevents replay attacks on id_token)

     Step 3: Get user info
          Option A: Parse claims from id_token (no extra HTTP call)
          Option B: Call userinfo endpoint with access_token
          (Spring: calls userinfo if scopes like 'profile', 'email' requested)

     Step 4: Create OidcUser (combines id_token + userinfo claims)
          OidcUser.getIdToken()     → IdToken JWT
          OidcUser.getUserInfo()    → UserInfo claims
          OidcUser.getClaims()      → merged (id_token + userinfo)
          OidcUser.getSubject()     → "sub" claim
```

---

### 13.7 DefaultOAuth2UserService — Loading User Attributes

```java
public class DefaultOAuth2UserService
        implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest)
            throws OAuth2AuthenticationException {

        // Step 1: Determine user name attribute
        // (configured as userNameAttributeName in provider config)
        // e.g., for Google: "sub", for GitHub: "id", for Facebook: "id"
        String userNameAttributeName = userRequest.getClientRegistration()
            .getProviderDetails()
            .getUserInfoEndpoint()
            .getUserNameAttributeName();

        // Step 2: Call userinfo endpoint
        // GET {userInfoUri}
        // Authorization: Bearer {access_token}
        RequestEntity<?> request = this.requestEntityConverter
            .convert(userRequest);

        ResponseEntity<Map<String, Object>> response =
            this.restOperations.exchange(request, PARAMETERIZED_RESPONSE_TYPE);

        // Step 3: Extract attributes
        Map<String, Object> attributes = response.getBody();

        // Step 4: Build GrantedAuthority from OAuth2 user
        Set<GrantedAuthority> authorities = new LinkedHashSet<>();
        authorities.add(new OAuth2UserAuthority(attributes));
        // Adds: "OAUTH2_USER" authority (or "OIDC_USER" for OIDC)

        // Add scopes as authorities
        OAuth2AccessToken token = userRequest.getAccessToken();
        for (String scope : token.getScopes()) {
            authorities.add(new SimpleGrantedAuthority("SCOPE_" + scope));
        }

        return new DefaultOAuth2User(authorities,
            attributes, userNameAttributeName);
    }
}
```

**Default authorities for OAuth2 users:**

```
After loadUser():
     Principal has authorities:
          [OAUTH2_USER, SCOPE_openid, SCOPE_profile, SCOPE_email]
                 ↑              ↑
          OAuth2UserAuthority  Scopes from access token

For OIDC:
     [OIDC_USER, SCOPE_openid, SCOPE_profile, SCOPE_email]
```

---

### 13.8 OidcUserService — OIDC-Specific User Loading

```java
public class OidcUserService
        implements OAuth2UserService<OidcUserRequest, OidcUser> {

    private OAuth2UserService<OAuth2UserRequest, OAuth2User>
        oauth2UserService = new DefaultOAuth2UserService();

    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) {

        // Step 1: Always have id_token (OIDC requirement)
        OidcIdToken idToken = userRequest.getIdToken();

        // Step 2: Should we also call userinfo endpoint?
        // YES if additional scopes requested (profile, email, etc.)
        Set<String> accessibleScopes = getAccessibleScopes(userRequest);

        OidcUserInfo userInfo = null;
        if (!accessibleScopes.isEmpty()) {
            // Call userinfo endpoint → get additional claims
            OAuth2User oauth2User =
                this.oauth2UserService.loadUser(userRequest);
            userInfo = new OidcUserInfo(oauth2User.getAttributes());
        }

        // Step 3: Build OidcUser combining id_token + userinfo
        Set<GrantedAuthority> authorities =
            new LinkedHashSet<>();
        authorities.add(new OidcUserAuthority(idToken, userInfo));
        // "OIDC_USER" authority

        // Add scopes
        for (String scope : userRequest.getAccessToken().getScopes()) {
            authorities.add(new SimpleGrantedAuthority("SCOPE_" + scope));
        }

        // Step 4: Determine username attribute
        // For OIDC: default is "sub" (unless configured otherwise)
        return new DefaultOidcUser(authorities, idToken, userInfo);
    }
}
```

---

### 13.9 OAuth2AuthorizedClient — Token Storage

`OAuth2AuthorizedClient` is the container that holds the authorized client's tokens for future API calls:

```java
public class OAuth2AuthorizedClient implements Serializable {
    private final ClientRegistration clientRegistration;  // config (clientId, etc.)
    private final String principalName;      // who authorized this client
    private final OAuth2AccessToken accessToken;
    private final OAuth2RefreshToken refreshToken;       // null if not provided
}
```

**Storage backends via `OAuth2AuthorizedClientRepository`:**

```
HttpSessionOAuth2AuthorizedClientRepository (default for web)
     → Stores in HTTP session
     → Suitable for single-node stateful apps

InMemoryOAuth2AuthorizedClientService
     → In-memory map (principal → client)
     → Used in non-web contexts (CLI, tests)
     → NOT suitable for clustered deployments

JdbcOAuth2AuthorizedClientService
     → Stored in database
     → Suitable for clustered/stateless deployments
     → Requires oauth2_authorized_client table

Custom:
     → Redis, Hazelcast, etc. for distributed token storage
```

**Accessing the authorized client in controller:**

```java
@GetMapping("/user-data")
public String getUserData(
        // @RegisteredOAuth2AuthorizedClient auto-loads the client
        @RegisteredOAuth2AuthorizedClient("google")
        OAuth2AuthorizedClient authorizedClient) {

    String accessToken = authorizedClient
        .getAccessToken().getTokenValue();

    // Use access token to call Google API
    return googleApiClient.getUserData(accessToken);
}
```

---

### 13.10 OAuth2AuthorizedClientManager — Token Lifecycle Management

`OAuth2AuthorizedClientManager` is the high-level API for managing authorized clients, including automatic token refresh:

```
OAuth2AuthorizedClientManager (interface)
     │
     └── DefaultOAuth2AuthorizedClientManager (for web/servlet context)
     └── AuthorizedClientServiceOAuth2AuthorizedClientManager (non-web)

DefaultOAuth2AuthorizedClientManager:
     ├── authorize(OAuth2AuthorizeRequest request)
     │       └── Checks if token exists and is valid
     │       └── If expired → uses RefreshTokenOAuth2AuthorizedClientProvider
     │               → POST /token with refresh_token
     │               → Returns new access_token
     │       └── If no token → runs authorization flow
     │
     └── Backed by OAuth2AuthorizedClientProvider chain:
               AuthorizationCodeOAuth2AuthorizedClientProvider
               RefreshTokenOAuth2AuthorizedClientProvider
               ClientCredentialsOAuth2AuthorizedClientProvider
               PasswordOAuth2AuthorizedClientProvider (deprecated)
```

---

### 13.11 ClientRegistration — The Configuration Model

```java
// Built from application.yml or programmatically:
ClientRegistration googleRegistration = ClientRegistration
    .withRegistrationId("google")          // unique ID for this registration
    .clientId("google-client-id")
    .clientSecret("google-client-secret")
    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
    .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
    .scope("openid", "profile", "email")
    .authorizationUri("https://accounts.google.com/o/oauth2/v2/auth")
    .tokenUri("https://www.googleapis.com/oauth2/v4/token")
    .userInfoUri("https://www.googleapis.com/oauth2/v3/userinfo")
    .userNameAttributeName(IdTokenClaimNames.SUB)  // "sub"
    .jwkSetUri("https://www.googleapis.com/oauth2/v3/certs")
    .clientName("Google")
    .build();
```

**Spring Boot auto-configures well-known providers:**

```java
// CommonOAuth2Provider — built-in configurations:
public enum CommonOAuth2Provider {
    GOOGLE {
        // All Google endpoints pre-configured
        // Just provide client-id and client-secret
    },
    GITHUB { ... },
    FACEBOOK { ... },
    OKTA { ... }
}

// In application.yml:
spring:
  security:
    oauth2:
      client:
        registration:
          google:
            client-id: YOUR_ID      # just these two needed
            client-secret: YOUR_SECRET
            # Everything else auto-configured by CommonOAuth2Provider.GOOGLE
```

---

### 13.12 Custom OAuth2 Login Page

```java
// Default login page: /login
// Shows links like: "Login with Google", "Login with GitHub"
// Each link: /oauth2/authorization/{registrationId}

// Custom login page:
http.oauth2Login(oauth2 -> oauth2
    .loginPage("/custom-login")  // your controller renders this
);

// Custom login page controller:
@GetMapping("/custom-login")
public String loginPage(Model model,
        @Autowired ClientRegistrationRepository registrations) {
    // Provide OAuth2 provider links to template
    Map<String, String> providers = new HashMap<>();
    registrations.forEach(registration ->
        providers.put(
            registration.getRegistrationId(),
            "/oauth2/authorization/" + registration.getRegistrationId()
        )
    );
    model.addAttribute("providers", providers);
    return "custom-login";
}
```

---

### 13.13 OAuth2 Login Success/Failure Handlers

```java
http.oauth2Login(oauth2 -> oauth2
    .successHandler((request, response, authentication) -> {
        OAuth2AuthenticationToken token =
            (OAuth2AuthenticationToken) authentication;
        OAuth2User user = token.getPrincipal();

        // Provision user in local DB on first login
        String email = user.getAttribute("email");
        String sub = user.getAttribute("sub");
        userService.provisionIfAbsent(sub, email);

        // Redirect based on role
        String redirectUrl = determineRedirectUrl(authentication);
        response.sendRedirect(redirectUrl);
    })
    .failureHandler((request, response, exception) -> {
        log.error("OAuth2 login failed: {}", exception.getMessage());
        response.sendRedirect("/login?oauth2Error=" +
            URLEncoder.encode(exception.getMessage(),
                StandardCharsets.UTF_8));
    })
);
```

---

## 2️⃣ Code Examples

---

### Example 1 — Multi-Provider OAuth2 Login (Google + GitHub)

```yaml
spring:
  security:
    oauth2:
      client:
        registration:
          # ── Google (OIDC) ─────────────────────────────────────────
          google:
            client-id: ${GOOGLE_CLIENT_ID}
            client-secret: ${GOOGLE_CLIENT_SECRET}
            scope: openid, profile, email

          # ── GitHub (OAuth2, no OIDC) ──────────────────────────────
          github:
            client-id: ${GITHUB_CLIENT_ID}
            client-secret: ${GITHUB_CLIENT_SECRET}
            scope: user:email, read:user

          # ── Custom OIDC provider ──────────────────────────────────
          keycloak:
            client-id: my-app
            client-secret: ${KEYCLOAK_SECRET}
            scope: openid, profile, email, roles
            authorization-grant-type: authorization_code
            redirect-uri: "{baseUrl}/login/oauth2/code/{registrationId}"

        provider:
          keycloak:
            issuer-uri: https://auth.example.com/realms/my-realm
            # Spring auto-discovers all endpoints from issuer-uri
            # via /.well-known/openid-configuration
```

```java
@Configuration
@EnableWebSecurity
public class MultiProviderOAuth2Config {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/", "/login/**", "/oauth2/**", "/error")
                    .permitAll()
                .anyRequest().authenticated()
            )
            .oauth2Login(oauth2 -> oauth2
                .loginPage("/login")
                .userInfoEndpoint(userInfo -> userInfo
                    .userService(oAuth2UserService())
                    .oidcUserService(oidcUserService())
                )
                .successHandler(oAuth2SuccessHandler())
            );

        return http.build();
    }

    @Bean
    public OAuth2UserService<OAuth2UserRequest, OAuth2User>
            oAuth2UserService() {
        DefaultOAuth2UserService delegate = new DefaultOAuth2UserService();
        return request -> {
            OAuth2User oauth2User = delegate.loadUser(request);

            // Map provider-specific attributes to unified format
            String registrationId = request.getClientRegistration()
                .getRegistrationId();

            String email = switch (registrationId) {
                case "google"  -> oauth2User.getAttribute("email");
                case "github"  -> oauth2User.getAttribute("email");
                default -> null;
            };

            // Provision user in local DB
            appUserService.findOrCreate(
                oauth2User.getName(), email, registrationId);

            return oauth2User;
        };
    }

    @Bean
    public OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService() {
        OidcUserService delegate = new OidcUserService();
        return request -> {
            OidcUser oidcUser = delegate.loadUser(request);

            // Extract additional claims from Keycloak JWT
            Map<String, Object> claims = oidcUser.getClaims();
            // Keycloak may include realm_access.roles in id_token

            return oidcUser;
        };
    }
}
```

---

### Example 2 — Custom User Authority Mapping

```java
// Map OAuth2 provider groups/roles to Spring Security authorities
@Bean
public OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService() {
    OidcUserService delegate = new OidcUserService();

    return request -> {
        OidcUser oidcUser = delegate.loadUser(request);

        // Extract roles from Keycloak token
        // Keycloak JWT: "realm_access": {"roles": ["admin", "user"]}
        Map<String, Object> realmAccess =
            oidcUser.getClaimAsMap("realm_access");

        Set<GrantedAuthority> mappedAuthorities =
            new HashSet<>(oidcUser.getAuthorities());

        if (realmAccess != null && realmAccess.containsKey("roles")) {
            @SuppressWarnings("unchecked")
            List<String> roles = (List<String>) realmAccess.get("roles");
            roles.stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role.toUpperCase()))
                .forEach(mappedAuthorities::add);
        }

        // Create new OidcUser with extended authorities
        return new DefaultOidcUser(
            mappedAuthorities,
            oidcUser.getIdToken(),
            oidcUser.getUserInfo()
        );
    };
}
```

---

### Example 3 — Persisting OAuth2 Authorized Clients to Database

```java
@Configuration
public class OAuth2ClientPersistenceConfig {

    @Bean
    public OAuth2AuthorizedClientService authorizedClientService(
            JdbcTemplate jdbcTemplate,
            ClientRegistrationRepository registrationRepository) {
        return new JdbcOAuth2AuthorizedClientService(
            jdbcTemplate, registrationRepository);
    }

    @Bean
    public OAuth2AuthorizedClientRepository authorizedClientRepository(
            OAuth2AuthorizedClientService authorizedClientService) {
        return new AuthenticatedPrincipalOAuth2AuthorizedClientRepository(
            authorizedClientService);
    }
}
```

```sql
-- Required database table (Spring Security provides schema):
CREATE TABLE oauth2_authorized_client (
    client_registration_id  VARCHAR(100) NOT NULL,
    principal_name          VARCHAR(200) NOT NULL,
    access_token_type       VARCHAR(100) NOT NULL,
    access_token_value      BLOB         NOT NULL,
    access_token_issued_at  TIMESTAMP    NOT NULL,
    access_token_expires_at TIMESTAMP    NOT NULL,
    access_token_scopes     VARCHAR(1000) DEFAULT NULL,
    refresh_token_value     BLOB         DEFAULT NULL,
    refresh_token_issued_at TIMESTAMP    DEFAULT NULL,
    created_at              TIMESTAMP    DEFAULT CURRENT_TIMESTAMP NOT NULL,
    PRIMARY KEY (client_registration_id, principal_name)
);
```

---

### Example 4 — Calling Downstream API with OAuth2 Token

```java
@Service
public class GoogleCalendarService {

    private final WebClient webClient;

    public GoogleCalendarService(
            OAuth2AuthorizedClientManager clientManager) {

        // Configure WebClient with OAuth2 token support
        ServletOAuth2AuthorizedClientExchangeFilterFunction oauth2 =
            new ServletOAuth2AuthorizedClientExchangeFilterFunction(clientManager);

        this.webClient = WebClient.builder()
            .apply(oauth2.oauth2Configuration())
            .baseUrl("https://www.googleapis.com/calendar/v3")
            .build();
    }

    public List<CalendarEvent> getEvents(
            OAuth2AuthenticationToken authentication) {

        return webClient
            .get()
            .uri("/calendars/primary/events")
            // Specify which authorized client to use for this request
            .attributes(oauth2AuthorizedClient(
                loadAuthorizedClient(authentication)))
            .retrieve()
            .bodyToFlux(CalendarEvent.class)
            .collectList()
            .block();
    }

    // Or simpler: use @RegisteredOAuth2AuthorizedClient in controller:
}

@RestController
public class CalendarController {

    @GetMapping("/calendar")
    public List<CalendarEvent> getCalendar(
            @RegisteredOAuth2AuthorizedClient("google")
            OAuth2AuthorizedClient googleClient) {

        String token = googleClient.getAccessToken().getTokenValue();
        return calendarService.getEventsWithToken(token);
    }
}
```

---

### Example 5 — Custom OAuth2 Authorization Request (Adding Parameters)

```java
// Customizing the authorization request before redirecting
// Use case: Add custom parameters, nonce, login_hint, etc.

@Bean
public OAuth2AuthorizationRequestResolver authorizationRequestResolver(
        ClientRegistrationRepository registrations) {

    DefaultOAuth2AuthorizationRequestResolver resolver =
        new DefaultOAuth2AuthorizationRequestResolver(
            registrations,
            OAuth2AuthorizationRequestRedirectFilter
                .DEFAULT_AUTHORIZATION_REQUEST_BASE_URI);

    // Customize the authorization request
    resolver.setAuthorizationRequestCustomizer(
        customizer -> customizer
            // Force account selection at Google
            .additionalParameters(params -> params.put(
                "prompt", "select_account"))

            // Or: Pass login hint
            .additionalParameters(params -> {
                String loginHint = extractLoginHint();
                if (loginHint != null) {
                    params.put("login_hint", loginHint);
                }
            })
    );

    return resolver;
}

// Register in SecurityFilterChain:
http.oauth2Login(oauth2 -> oauth2
    .authorizationEndpoint(endpoint -> endpoint
        .authorizationRequestResolver(authorizationRequestResolver(
            clientRegistrationRepository))
    )
);
```

---

### Example 6 — Incorrect OAuth2 Login Configurations

```java
// ❌ WRONG 1 — Not permitting oauth2 redirect URIs
http.authorizeHttpRequests(auth -> auth
    .anyRequest().authenticated()
    // Missing: .requestMatchers("/login/oauth2/code/**").permitAll()
);
// OAuth2 callback URL requires no authentication
// Without permitAll(), callback URL is protected → infinite redirect!

// Spring Security handles this automatically when you use oauth2Login()
// but important to understand if configuring manually

// ❌ WRONG 2 — Registering callback URL that doesn't match config
// application.yml: redirect-uri: "{baseUrl}/login/oauth2/code/{registrationId}"
// Google Console: https://app.com/oauth/callback  ← DIFFERENT!
// Result: Google rejects the redirect_uri with "redirect_uri_mismatch"
// Spring Security callback filter never receives the code
// ALWAYS: redirect_uri in app config MUST exactly match Auth Server registration

// ❌ WRONG 3 — Custom login page without permitting it
http.oauth2Login(oauth2 -> oauth2
    .loginPage("/custom-login")
)
.authorizeHttpRequests(auth -> auth
    .anyRequest().authenticated()
    // Missing: .requestMatchers("/custom-login").permitAll()
    // Result: /custom-login requires auth → redirect to /custom-login → loop!
);

// ✓ CORRECT:
http.authorizeHttpRequests(auth -> auth
    .requestMatchers("/custom-login", "/oauth2/**",
                     "/login/oauth2/code/**").permitAll()
    .anyRequest().authenticated()
)
.oauth2Login(oauth2 -> oauth2
    .loginPage("/custom-login")
);

// ❌ WRONG 4 — Using same client ID for multiple environments
// Dev and prod use same Google client ID
// Google registered callback: https://prod.example.com/login/oauth2/code/google
// Dev callback: http://localhost:8080/login/oauth2/code/google
// Result: Google rejects localhost callback (not registered)
// ALWAYS: Register separate OAuth2 apps for dev/staging/prod
```

---

## 3️⃣ Exam-Style Questions

---

**Q1 (MCQ):** Which filter initiates the OAuth2 Authorization Code flow when a user navigates to `/oauth2/authorization/google`?

A. `OAuth2LoginAuthenticationFilter`
B. `OAuth2AuthorizationRequestRedirectFilter`
C. `AbstractAuthenticationProcessingFilter`
D. `BearerTokenAuthenticationFilter`

**Answer: B — `OAuth2AuthorizationRequestRedirectFilter`**
`OAuth2AuthorizationRequestRedirectFilter` intercepts `/oauth2/authorization/{registrationId}` requests, builds the authorization URL with state/PKCE, stores the authorization request in session, and redirects the browser to the Authorization Server.

---

**Q2 (MCQ):** What does Spring Security store in the HTTP session during the OAuth2 authorization request phase?

A. The user's access token
B. The complete `OAuth2AuthorizationRequest` object (including state and code verifier)
C. Only the `state` parameter
D. The authorization code received from the server

**Answer: B**
`HttpSessionOAuth2AuthorizationRequestRepository` stores the complete `OAuth2AuthorizationRequest` object in session. This includes `state` (for CSRF validation), `codeVerifier` (for PKCE), `clientId`, `redirectUri`, `scopes`, and other parameters needed for the callback validation.

---

**Q3 (Select All That Apply):** Which are true about `OAuth2LoginAuthenticationFilter`?

A. It extends `AbstractAuthenticationProcessingFilter`
B. It handles `GET /oauth2/authorization/{registrationId}`
C. It validates the `state` parameter from the callback
D. It removes (not just reads) the authorization request from session after use
E. It stores the `OAuth2AuthorizedClient` in `OAuth2AuthorizedClientRepository`

**Answer: A, C, D, E**
B is false — `OAuth2AuthorizationRequestRedirectFilter` handles `/oauth2/authorization/**`. The login filter handles `/login/oauth2/code/**` (the callback).

---

**Q4 (Flow Prediction):**

A user visits `/oauth2/authorization/github`. Trace the complete Spring Security filter execution through to successful authentication.

**Answer:**
```
1. GET /oauth2/authorization/github
2. OAuth2AuthorizationRequestRedirectFilter activates
3. DefaultOAuth2AuthorizationRequestResolver builds:
   - state = random UUID
   - scopes = [user:email, read:user]
   - authorizationUri = https://github.com/login/oauth2/authorize
4. HttpSessionOAuth2AuthorizationRequestRepository saves OAuth2AuthorizationRequest
5. 302 redirect to GitHub with state + client_id + scope + redirect_uri

--- User authenticates at GitHub ---

6. GET /login/oauth2/code/github?code=CODE&state=STATE
7. OAuth2LoginAuthenticationFilter activates
8. Loads OAuth2AuthorizationRequest from session (removes it)
9. Validates: returned state == stored state ✓
10. Builds OAuth2LoginAuthenticationToken
11. AuthenticationManager → OAuth2LoginAuthenticationProvider
12. DefaultAuthorizationCodeTokenResponseClient:
    POST https://github.com/login/oauth2/access_token
    code=CODE&client_id=...&client_secret=...
    → Returns access_token (no id_token — GitHub doesn't support OIDC)
13. DefaultOAuth2UserService:
    GET https://api.github.com/user
    Authorization: Bearer access_token
    → Returns user attributes {login, id, email, ...}
14. Creates OAuth2AuthenticationToken with:
    principal=DefaultOAuth2User{name="github-id", ...}
    authorities=[OAUTH2_USER, SCOPE_user:email, SCOPE_read:user]
15. Stores OAuth2AuthorizedClient in HttpSessionOAuth2AuthorizedClientRepository
16. SecurityContextHolder.setAuthentication(oauth2Token)
17. Saves SecurityContext to session
18. SavedRequestAwareAuthenticationSuccessHandler:
    → Redirect to savedRequest or defaultSuccessUrl
```

---

**Q5 (Code Prediction):**

```java
http.oauth2Login(oauth2 -> oauth2
    .loginPage("/login")
)
.authorizeHttpRequests(auth -> auth
    .anyRequest().authenticated()
);
```

A user directly requests `GET /login/oauth2/code/google?code=CODE&state=WRONG_STATE`. What happens?

**Answer:** `OAuth2AuthenticationException` is thrown.

1. `OAuth2LoginAuthenticationFilter` activates (URL matches `/login/oauth2/code/*`)
2. Filter attempts to load `OAuth2AuthorizationRequest` from session
3. Session may not have matching request (state doesn't match), OR:
4. If request found: state validation fails (`WRONG_STATE != stored state`)
5. Provider throws `OAuth2AuthenticationException` with `invalid_state_parameter`
6. `AbstractAuthenticationProcessingFilter.unsuccessfulAuthentication()` called
7. `AuthenticationFailureHandler` redirects to `/login?error`

The state mismatch is treated as an authentication failure, not an authorization failure. The user sees the login page with an error parameter.

---

**Q6 (Provider Difference):**

You configure both Google (OIDC) and GitHub (OAuth2 only) providers. A user logs in with each. What `Authentication` type is created for each, and what authorities do they have?

**Answer:**

**Google (OIDC — scope includes `openid`):**
- Authentication type: `OAuth2AuthenticationToken` with `OidcUser` principal
- Provider: `OidcAuthorizationCodeAuthenticationProvider`
- User service: `OidcUserService`
- Principal type: `DefaultOidcUser` (has `getIdToken()`, `getUserInfo()`)
- Authorities: `[OIDC_USER, SCOPE_openid, SCOPE_profile, SCOPE_email]`
- Extra: id_token validated (signature, nonce, issuer, audience)

**GitHub (OAuth2 — no `openid` scope):**
- Authentication type: `OAuth2AuthenticationToken` with `OAuth2User` principal
- Provider: `OAuth2LoginAuthenticationProvider`
- User service: `DefaultOAuth2UserService`
- Principal type: `DefaultOAuth2User` (attributes from userinfo endpoint)
- Authorities: `[OAUTH2_USER, SCOPE_user:email, SCOPE_read:user]`
- No id_token — just API response from `https://api.github.com/user`

---

**Q7 (Authorized Client Storage):**

In a clustered deployment (3 nodes), `HttpSessionOAuth2AuthorizedClientRepository` is used. User authenticates on Node 1. Their next request goes to Node 2. What happens to their OAuth2 tokens?

**Answer:** The tokens are **lost** on Node 2.

`HttpSessionOAuth2AuthorizedClientRepository` stores tokens in the HTTP session. Without session replication or sticky sessions:
- Session (with tokens) is on Node 1 only
- Node 2 has no knowledge of the user's tokens
- When Node 2 code tries to access `@RegisteredOAuth2AuthorizedClient`, it returns null
- Token refresh fails (no existing token to refresh)
- User must re-authenticate

**Fix:** Use `JdbcOAuth2AuthorizedClientService` (database-backed) or implement a Redis-backed service for distributed token storage. All nodes share the same database/Redis, so tokens are accessible from any node.

---

**Q8 (Customization Scenario):**

You need to provision a user in your local database on their first OAuth2 login, capturing their email and provider. Where is the correct place to do this?

**Answer:** In a custom `OAuth2UserService` (or `OidcUserService`) implementation:

```java
@Bean
public OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService() {
    OidcUserService delegate = new OidcUserService();
    return request -> {
        OidcUser oidcUser = delegate.loadUser(request);

        // Provision here — called once per authentication
        String sub = oidcUser.getSubject();
        String email = oidcUser.getEmail();
        String provider = request.getClientRegistration().getRegistrationId();

        appUserRepository.findByProviderAndSub(provider, sub)
            .orElseGet(() -> appUserRepository.save(
                new AppUser(sub, email, provider)));

        return oidcUser;
    };
}
```

This is the correct place because:
1. Called after successful token exchange — tokens are valid
2. User claims are fully populated
3. Called before `successHandler` — provisioning happens before any redirect
4. `sub` is stable (unlike email) — use as unique identifier

---

## 4️⃣ Trick Analysis

---

**Trick 1 — `/oauth2/authorization/**` vs `/login/oauth2/code/**` Confusion**

```
/oauth2/authorization/{registrationId}
     Purpose: STARTS the OAuth2 flow
     Handler: OAuth2AuthorizationRequestRedirectFilter
     Produces: 302 redirect to Auth Server
     This is what "Login with Google" links point to

/login/oauth2/code/{registrationId}
     Purpose: HANDLES the Auth Server callback
     Handler: OAuth2LoginAuthenticationFilter
     Receives: code + state from Auth Server
     Produces: authenticated session

EXAM TRAP: "Which URL handles the authorization code callback?"
Answer: /login/oauth2/code/{registrationId} — NOT /oauth2/authorization/
```

---

**Trick 2 — `OidcUser` vs `OAuth2User` Principal Types**

```
scope includes 'openid':
     Provider: OidcAuthorizationCodeAuthenticationProvider
     Principal: OidcUser (extends OAuth2User)
     Has: getIdToken(), getUserInfo(), getSubject(), getEmail()
     Authority: OIDC_USER

scope does NOT include 'openid':
     Provider: OAuth2LoginAuthenticationProvider
     Principal: OAuth2User
     Has: getAttributes() (raw map from userinfo endpoint)
     Authority: OAUTH2_USER

TRAP: Casting to OidcUser when provider doesn't support OIDC:
     Authentication auth = ...;
     OidcUser user = (OidcUser) auth.getPrincipal(); // ClassCastException for GitHub!
     
CORRECT:
     if (auth.getPrincipal() instanceof OidcUser oidcUser) {
         // OIDC provider (Google, Keycloak)
     } else if (auth.getPrincipal() instanceof OAuth2User oauth2User) {
         // Plain OAuth2 provider (GitHub, custom)
     }
```

---

**Trick 3 — The `userNameAttributeName` Determines `getName()`**

```java
// For Google: userNameAttributeName = "sub"
// OAuth2User.getName() = attributes.get("sub") = "104567891234..."
// (numeric Google user ID — stable, not email)

// For GitHub: userNameAttributeName = "id"  
// OAuth2User.getName() = attributes.get("id") = "12345678"
// (numeric GitHub user ID)

// For custom provider: configurable
// user-name-attribute: email → getName() returns email

// Consequence for @AuthenticationPrincipal:
@GetMapping("/profile")
public String profile(@AuthenticationPrincipal OAuth2User user) {
    user.getName();  // returns the userNameAttributeName value
    // NOT necessarily email or username!
    // Could be "104567891234" for Google
}

// To get email specifically:
user.getAttribute("email");  // explicit attribute access
```

---

**Trick 4 — Authorization Request Removal on Callback (Single Use)**

```java
// In OAuth2LoginAuthenticationFilter:
OAuth2AuthorizationRequest authorizationRequest =
    this.authorizationRequestRepository.removeAuthorizationRequest(
        request, response);
//                      ↑ REMOVE not just load

// Why remove?
// 1. Single-use: authorization code is one-time, state is one-time
// 2. Prevents replay attacks (same callback URL used twice)
// 3. Cleans up session storage

// Consequence:
// If callback fails (network error to token endpoint):
//    Authorization request is already removed from session!
//    Second attempt to /login/oauth2/code/google?code=SAME_CODE...
//    → No authorization request in session → failure!
//    User must restart flow from /oauth2/authorization/google
```

---

**Trick 5 — Redirect URI Must Match Exactly**

```
Registered in Google Console: https://app.com/login/oauth2/code/google
Configured in application.yml: {baseUrl}/login/oauth2/code/{registrationId}

At runtime {baseUrl} = https://app.com, {registrationId} = google
Expanded: https://app.com/login/oauth2/code/google ✓ MATCHES

Common mistakes:
     Trailing slash: https://app.com/login/oauth2/code/google/
     HTTP vs HTTPS: http://app.com/login/oauth2/code/google
     Wrong port: https://app.com:443/login/oauth2/code/google
     (443 is default, including it may or may not match depending on provider)

Google is STRICT: exact match required
GitHub: slightly more lenient
Keycloak: configurable
```

---

**Trick 6 — Token Refresh in OAuth2 Login Context**

```
After OAuth2 login:
     Access token stored in OAuth2AuthorizedClient
     Typically expires in 3600 seconds (1 hour)

Spring Security does NOT automatically refresh access tokens
for OAuth2 Login sessions!

Why: OAuth2 Login authenticates the user (session-based)
     The session's Authentication doesn't expire with the access token
     User is still "authenticated" to your app even if Google access token expired

When does refresh matter?
     When your app calls downstream APIs using the access token
     → Token expired → API returns 401
     → Need to refresh via OAuth2AuthorizedClientManager

// Automatic refresh in WebClient:
// OAuth2AuthorizedClientManager with RefreshTokenOAuth2AuthorizedClientProvider
// handles this automatically when using the WebClient filter function
```

---

**Trick 7 — `@RegisteredOAuth2AuthorizedClient` Only Works in Web Context**

```java
// Works in @Controller/@RestController with web request:
@GetMapping("/api")
public String api(
        @RegisteredOAuth2AuthorizedClient("google")
        OAuth2AuthorizedClient client) { ... }

// FAILS in @Service (no HttpServletRequest):
@Service
public class MyService {
    public void process(
            @RegisteredOAuth2AuthorizedClient("google")  // ← FAILS
            OAuth2AuthorizedClient client) { ... }
}

// Correct for service layer:
@Service
public class MyService {
    @Autowired
    OAuth2AuthorizedClientService clientService;

    public void process(Authentication auth) {
        OAuth2AuthorizedClient client = clientService.loadAuthorizedClient(
            "google", auth.getName());
    }
}
```

---

## 5️⃣ Summary Sheet

---

### OAuth2 Login Filter Architecture

```
GET /oauth2/authorization/google
     │
     ▼
OAuth2AuthorizationRequestRedirectFilter
     ├── Resolve ClientRegistration for "google"
     ├── Generate state (+ PKCE code_verifier if public client)
     ├── Build authorization URL
     ├── Save OAuth2AuthorizationRequest to session
     └── 302 Redirect → https://accounts.google.com/o/oauth2/v2/auth?...

     [User authenticates at Google]

GET /login/oauth2/code/google?code=CODE&state=STATE
     │
     ▼
OAuth2LoginAuthenticationFilter
     ├── Load + REMOVE OAuth2AuthorizationRequest from session
     ├── Validate: state matches ✓
     ├── Build OAuth2LoginAuthenticationToken
     │
     ▼
AuthenticationManager → Provider selection:
     scope has 'openid'?
          YES → OidcAuthorizationCodeAuthenticationProvider
          NO  → OAuth2LoginAuthenticationProvider
     │
     ├── POST /token endpoint (code exchange)
     ├── Validate id_token if OIDC
     ├── GET /userinfo endpoint
     ├── Build OAuth2User or OidcUser
     │
     ▼
OAuth2AuthenticationToken created
OAuth2AuthorizedClient saved to repository
SecurityContext updated → session saved
SuccessHandler → redirect to /dashboard
```

---

### OAuth2 User Service Selection

| Condition | Provider Class | User Service | Principal Type |
|-----------|---------------|-------------|---------------|
| `scope` includes `openid` | `OidcAuthorizationCodeAuthenticationProvider` | `OidcUserService` | `OidcUser` (has `id_token`) |
| `scope` does NOT include `openid` | `OAuth2LoginAuthenticationProvider` | `DefaultOAuth2UserService` | `OAuth2User` (attributes only) |

---

### Key URLs Reference

| URL Pattern | Filter | Purpose |
|-------------|--------|---------|
| `/oauth2/authorization/{id}` | `OAuth2AuthorizationRequestRedirectFilter` | Starts OAuth2 flow |
| `/login/oauth2/code/{id}` | `OAuth2LoginAuthenticationFilter` | Handles callback |
| `/login` | `LoginUrlAuthenticationEntryPoint` | Custom login page |

---

### OAuth2AuthorizedClientRepository Comparison

| Implementation | Storage | Clustered | Use Case |
|---------------|---------|-----------|----------|
| `HttpSessionOAuth2AuthorizedClientRepository` | HTTP Session | ❌ No | Single-node web app |
| `InMemoryOAuth2AuthorizedClientService` | JVM Memory | ❌ No | Tests, CLI |
| `JdbcOAuth2AuthorizedClientService` | Database | ✅ Yes | Production multi-node |
| Custom Redis | Redis | ✅ Yes | High-performance distributed |

---

### Common Interview One-Liners

- **`/oauth2/authorization/{id}`** starts the flow; **`/login/oauth2/code/{id}`** handles the callback
- **`OAuth2AuthorizationRequest` is removed** (not just read) from session on callback — single-use
- **`state` validation** is built-in CSRF protection for OAuth2 callback
- **OIDC flow** (scope=openid) validates `id_token` and uses `OidcUserService`; plain OAuth2 uses `DefaultOAuth2UserService`
- **`OidcUser`** has `getIdToken()` and `getUserInfo()`; **`OAuth2User`** only has `getAttributes()`
- **`userNameAttributeName`** determines `OAuth2User.getName()` — not necessarily email
- **`JdbcOAuth2AuthorizedClientService`** required for clustered deployments — session-based storage fails
- **`@RegisteredOAuth2AuthorizedClient`** only works in controller layer (needs `HttpServletRequest`)
- **Token refresh** for downstream APIs requires `OAuth2AuthorizedClientManager` with `RefreshTokenProvider`
- **`redirect_uri` must exactly match** what's registered with the Auth Server — any deviation causes rejection

---
