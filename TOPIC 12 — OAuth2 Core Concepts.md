# TOPIC 12 — OAuth2 Core Concepts

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

---

## 1️⃣ Conceptual Explanation

---

### 12.1 Why OAuth2 Exists — The Delegation Problem

Before OAuth2, the only way to let a third-party application access your resources was to give it your username and password. This was catastrophically dangerous:

```
Pre-OAuth2 world:
     User wants: "Let my photo editor access my Google Photos"
     Solution:   Give photo editor your Google password
     Problems:
          ├── Photo editor has full Google account access (not just photos)
          ├── User cannot revoke access without changing password
          ├── Every app stores your password → massive breach surface
          ├── No scope limitation (app can read email, delete files, etc.)
          └── No time limitation (access forever)

OAuth2 solution:
     User authorizes photo editor → receives limited-scope access token
          ├── Scope: read:photos only (not email, not calendar)
          ├── Expiry: token expires in 1 hour
          ├── Revocable: user can revoke without changing password
          ├── Password never shared with third-party app
          └── Audit trail: authorization server tracks what was authorized
```

**OAuth2 is a delegation framework, not an authentication protocol.** This is the most fundamental concept. OAuth2 answers "what can this application do on behalf of this user?" — not "who is this user?"

---

### 12.2 OAuth2 Roles — The Four Actors

```
┌─────────────────────────────────────────────────────────────────────┐
│                     OAuth2 Roles                                    │
│                                                                     │
│  Resource Owner     = The USER who owns the protected resources     │
│  (Human being or system that can grant access)                      │
│                                                                     │
│  Client             = The APPLICATION requesting access             │
│  (Web app, mobile app, SPA, backend service)                        │
│                                                                     │
│  Authorization Server = Issues tokens after authenticating user     │
│  (Google, Okta, Keycloak, Spring Authorization Server)              │
│                                                                     │
│  Resource Server    = Holds the protected resources                 │
│  (Your Spring Boot API, Google Photos API, GitHub API)              │
└─────────────────────────────────────────────────────────────────────┘
```

**Concrete example — "Login with Google" in a Spring Boot app:**

```
Resource Owner:     Alice (the user)
Client:             YourApp.com (your Spring Boot web app)
Authorization Server: Google's OAuth2/OIDC service (accounts.google.com)
Resource Server:    Google's APIs (Gmail API, Photos API)
                    OR your own Spring Boot API (secured with JWT)
```

**The separation of Authorization Server and Resource Server:**

```
Common misunderstanding: They must be the same server
Reality: They are often different services

Example 1 (same organization, different services):
     Auth Server: auth.company.com (issues JWTs)
     Resource Server: api.company.com (validates JWTs)

Example 2 (third-party auth):
     Auth Server: accounts.google.com
     Resource Server: your-app-api.com
     (Your API validates JWTs issued by Google)

Example 3 (self-contained — monolith):
     Auth Server + Resource Server: same Spring Boot app
     (Spring Authorization Server embedded in your app)
```

---

### 12.3 OAuth2 Grant Types — The Complete Taxonomy

Grant types define **how** a client obtains an access token. Different scenarios need different flows.

```
OAuth2 Grant Types:
     │
     ├── Authorization Code Grant
     │       For: Web apps with server-side rendering (most secure)
     │
     ├── Authorization Code + PKCE
     │       For: SPAs, mobile apps (public clients without client secret)
     │
     ├── Client Credentials Grant
     │       For: Machine-to-machine (no user involved)
     │
     ├── Refresh Token Grant
     │       For: Obtaining new access tokens without re-authentication
     │
     ├── Device Authorization Grant (RFC 8628)
     │       For: Devices without browsers (TV, CLI tools)
     │
     └── [DEPRECATED - RFC 6749, removed in OAuth 2.1]
               ├── Resource Owner Password Credentials (ROPC)
               └── Implicit Grant
```

---

### 12.4 Authorization Code Grant — The Most Important Flow

This is the most secure and most widely used grant type. Spring Security's `OAuth2LoginConfigurer` implements this flow.

**Complete flow — every HTTP request:**

```
┌──────────┐     ┌──────────────┐     ┌──────────────────────┐
│  Browser  │     │  Your App    │     │  Authorization Server │
│  (Alice)  │     │  (Client)    │     │  (Google/Okta/etc.)   │
└────┬──────┘     └──────┬───────┘     └──────────┬───────────┘
     │                   │                         │
     │ GET /dashboard    │                         │
     │──────────────────►│                         │
     │                   │ Not authenticated        │
     │                   │ Generate state=random1   │
     │                   │ Save state in session    │
     │                   │                         │
     │ 302 redirect       │                         │
     │◄──────────────────│                         │
     │ Location:          │                         │
     │ https://google.com/o/oauth2/auth             │
     │ ?client_id=YOUR_ID                           │
     │ &redirect_uri=https://app.com/callback       │
     │ &response_type=code                          │
     │ &scope=openid email profile                  │
     │ &state=random1                               │
     │                   │                         │
     │ GET /o/oauth2/auth?...                       │
     │────────────────────────────────────────────►│
     │                   │          Alice logs in   │
     │                   │         Consent screen   │
     │                   │         Alice approves   │
     │                   │                         │
     │ 302 redirect       │                         │
     │◄────────────────────────────────────────────│
     │ Location:          │                         │
     │ https://app.com/callback                     │
     │ ?code=AUTH_CODE_XYZ                          │
     │ &state=random1                               │
     │                   │                         │
     │ GET /callback      │                         │
     │ ?code=AUTH_CODE    │                         │
     │ &state=random1     │                         │
     │──────────────────►│                         │
     │                   │ Validate state==random1  │
     │                   │ (CSRF protection!)       │
     │                   │                         │
     │                   │ POST /token              │
     │                   │─────────────────────────►
     │                   │ grant_type=authorization_code
     │                   │ code=AUTH_CODE_XYZ       │
     │                   │ redirect_uri=...         │
     │                   │ client_id=...            │
     │                   │ client_secret=...        │
     │                   │                         │
     │                   │◄────────────────────────│
     │                   │ {                        │
     │                   │   "access_token": "...", │
     │                   │   "token_type": "Bearer",│
     │                   │   "expires_in": 3600,    │
     │                   │   "refresh_token": "...",│
     │                   │   "id_token": "..." (OIDC)
     │                   │ }                        │
     │                   │                         │
     │ 302 to /dashboard  │                         │
     │◄──────────────────│                         │
```

**Why the authorization code is not the access token:**

```
Code exchange happens server-side:
     Authorization code: short-lived (seconds to minutes), single-use
          → Travels through browser (potentially exposed in URL, logs)
          → Attacker intercepting code cannot use it without client_secret

     Access token: longer-lived (minutes to hours)
          → NEVER travels through browser URL
          → Exchanged server-to-server (POST to token endpoint)
          → Client secret required for exchange
          → Intercepted code is useless without secret

     Defense in depth: even if code is intercepted, it cannot be used
```

**The `state` parameter — built-in CSRF protection:**

```
State parameter flow:
     1. App generates: state = UUID.randomUUID()
     2. App saves state in session
     3. App includes state in authorization URL
     4. Auth server returns state in redirect callback
     5. App validates: returned state == session state

     If attacker forges callback:
          Forged: https://app.com/callback?code=EVIL_CODE&state=WRONG
          App checks: WRONG != random1 → rejects → CSRF attack prevented

     Spring Security OAuth2 handles this automatically!
```

---

### 12.5 Authorization Code + PKCE — Public Clients

PKCE (Proof Key for Code Exchange, pronounced "pixy") solves the problem of public clients (SPAs, mobile apps) that cannot securely store a `client_secret`.

**The problem PKCE solves:**

```
SPA (JavaScript app):
     Must have client_id to make auth requests
     CANNOT have client_secret (it's in JavaScript → visible to anyone)
     Without client_secret: code interception attack possible!

     Attacker intercepts authorization code
     → Makes token request with just client_id (no secret needed)
     → Gets access token!

PKCE solution: replace client_secret with a cryptographic proof
```

**PKCE flow:**

```
Step 1: Client generates code verifier
     code_verifier = random string, 43-128 chars
     (high entropy: cryptographically random)

Step 2: Client computes code challenge
     code_challenge = BASE64URL(SHA256(code_verifier))
     (one-way hash — verifier cannot be derived from challenge)

Step 3: Authorization request includes challenge
     GET /authorize
     ?code_challenge=BASE64URL_HASH
     &code_challenge_method=S256

Step 4: Auth server stores code_challenge with code
     (links the challenge to the issued authorization code)

Step 5: Token request includes verifier (NOT challenge)
     POST /token
     code=AUTH_CODE
     code_verifier=ORIGINAL_RANDOM_STRING
     (no client_secret needed)

Step 6: Auth server validates
     Recomputes: BASE64URL(SHA256(received_verifier))
     Compares with stored code_challenge
     Match → issues token
     No match → rejects

Why it prevents interception:
     Attacker intercepts code_challenge (in URL) AND authorization code
     Attacker cannot reverse SHA256 to get code_verifier
     Without code_verifier → cannot exchange code for token
```

---

### 12.6 Client Credentials Grant — Machine-to-Machine

No user involved. The client authenticates itself to get a token for its own operations.

**Use cases:**

```
Service A (Order Service) → Service B (Inventory Service)
Scheduled batch job → API
CI/CD pipeline → Deployment API
```

**Complete flow:**

```
Client (Service A)                 Authorization Server
     │                                      │
     │ POST /token                          │
     │ grant_type=client_credentials        │
     │ client_id=service-a                  │
     │ client_secret=secret123              │
     │ scope=inventory:read inventory:write │
     │─────────────────────────────────────►│
     │                                      │
     │◄─────────────────────────────────────│
     │ {                                    │
     │   "access_token": "...",             │
     │   "token_type": "Bearer",            │
     │   "expires_in": 3600,                │
     │   "scope": "inventory:read ..."      │
     │ }                                    │
     │                                      │
     │ GET /api/inventory                   │
     │ Authorization: Bearer ACCESS_TOKEN   │
     │─────────────────────────────────────►│
     │                               Resource Server
```

**Key characteristics:**
- No `refresh_token` issued (client can always re-authenticate)
- No user context — `sub` claim is the client ID, not a user ID
- Scope represents what the **client** can do (not a user's permissions)

---

### 12.7 Refresh Token Grant — Token Lifecycle Management

Access tokens are intentionally short-lived (minutes to hours). Refresh tokens allow obtaining new access tokens without re-authenticating the user.

**Token lifecycle:**

```
Login (Authorization Code flow):
     → access_token (expires: 1 hour)
     → refresh_token (expires: 30 days or until revoked)
     → id_token (OIDC — contains user identity)

60 minutes later:
     access_token expired
     API returns 401

Client uses refresh token:
     POST /token
     grant_type=refresh_token
     refresh_token=LONG_LIVED_TOKEN
     client_id=...
     client_secret=...  (for confidential clients)

     Response:
     → new access_token (1 hour)
     → new refresh_token (rotation — old token invalidated)
     → (optional) new id_token
```

**Refresh token rotation:**

```
Without rotation:
     Refresh token: same value forever (until expiry)
     Stolen refresh token: valid until expiry → long-term compromise

With rotation (recommended):
     Every refresh operation: new refresh token issued, old one invalidated
     Stolen token used by attacker:
          Server: "Old token already used (rotated)"
          → Detect potential theft → invalidate ALL tokens for this session
          → User must re-authenticate
```

**Spring Security's `OAuth2AuthorizedClientService`** manages token storage and refresh:

```java
// Automatic token refresh with Spring Security client:
@Service
public class ApiService {

    @Autowired
    private OAuth2AuthorizedClientService clientService;

    public String callApi(OAuth2AuthenticationToken authentication) {
        OAuth2AuthorizedClient client = clientService.loadAuthorizedClient(
            authentication.getAuthorizedClientRegistrationId(),
            authentication.getName()
        );

        // Token automatically refreshed if expired (if refresh token available)
        String accessToken = client.getAccessToken().getTokenValue();
        // Make API call with access token...
    }
}
```

---

### 12.8 OAuth2 vs OIDC — The Critical Distinction

**OAuth2 = Authorization Framework**
**OIDC = Authentication Protocol built on top of OAuth2**

```
OAuth2:
     Purpose: AUTHORIZATION (delegation)
     Question: "Can this app access these resources?"
     Token: access_token (opaque or JWT)
     No standard for user identity
     No standard UserInfo format

OpenID Connect (OIDC):
     Purpose: AUTHENTICATION (identity)
     Question: "Who is this user? Verify their identity."
     Adds to OAuth2:
          ├── id_token (JWT with user claims)
          ├── userinfo endpoint (standardized user profile)
          ├── Standard claims: sub, name, email, picture, etc.
          ├── nonce parameter (replay attack prevention)
          └── Standard scopes: openid, profile, email, address, phone
```

**OIDC scopes and claims:**

```
scope=openid → mandatory for OIDC, returns id_token
               id_token claims: sub, iss, aud, exp, iat, nonce

scope=profile → name, family_name, given_name, nickname,
                preferred_username, profile, picture, website,
                gender, birthdate, zoneinfo, locale, updated_at

scope=email   → email, email_verified

scope=address → address (JSON object with street, city, country, etc.)

scope=phone   → phone_number, phone_number_verified
```

**The `sub` claim — the stable user identifier:**

```
sub (subject) = unique, stable identifier for the user within the Auth Server
     → Does NOT change (unlike email, username)
     → Scoped to the issuer (same person may have different sub on different IdPs)
     → Should be used as the primary user identifier in your database

Example:
     Google issues: sub = "104567891234567890"
     Okta issues:   sub = "00u1a2b3c4d5e6f7g8h9"
     Both represent the same person but have different sub values
```

---

### 12.9 Token Types — Access Token, ID Token, Refresh Token

**Access Token:**

```
Purpose: Authorize access to protected resources
Contains: scope, expiry, subject (user or client), issuer
Format: Opaque string OR JWT
Lifetime: Short (minutes to hours)
Who validates it: Resource Server

Opaque access token:
     "a1b2c3d4e5f6..." (random string)
     Resource Server must call Auth Server's introspection endpoint
     to validate and get claims

JWT access token:
     Base64(header).Base64(payload).signature
     Resource Server validates locally (no Auth Server call needed)
     payload contains: sub, iss, aud, exp, iat, scope
```

**ID Token (OIDC only):**

```
Purpose: Authenticate the user (prove identity)
Contains: User identity claims (sub, email, name, etc.)
Format: ALWAYS JWT (required by OIDC spec)
Lifetime: Short (typically same as access token)
Who validates it: CLIENT (your application)
                  NOT the Resource Server!

Critical: ID token is for the CLIENT to know who the user is
          Access token is for the RESOURCE SERVER to authorize the request
          They are NOT interchangeable!
```

**Refresh Token:**

```
Purpose: Obtain new access tokens without re-authentication
Contains: Usually opaque (no JWT format required)
Lifetime: Long (days to months)
Who uses it: CLIENT (when access token expires)
Storage: Must be stored securely (equivalent value to user credentials)
```

---

### 12.10 JWT Structure — Deep Internals

JWTs used as access tokens or ID tokens have three Base64URL-encoded parts:

```
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.
eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFsaWNlIiwiaWF0IjoxNTE2MjM5MDIyfQ.
SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
│                                                │                           │
│              Header                            │        Payload            │  Signature
└────────────────────────────────────────────────┘───────────────────────────┘──────────┘

Header (decoded):
{
  "alg": "RS256",   // RSA SHA256 — asymmetric (private key signs, public key verifies)
  "typ": "JWT"
}

Payload (decoded):
{
  "sub": "alice@example.com",  // subject (user identifier)
  "iss": "https://auth.example.com",  // issuer
  "aud": ["https://api.example.com"], // audience (who this token is for)
  "exp": 1699999999,  // expiry (Unix timestamp)
  "iat": 1699996399,  // issued at
  "nbf": 1699996399,  // not before
  "jti": "unique-token-id",  // JWT ID (for revocation/replay detection)
  "scope": "read:orders write:orders",
  "roles": ["ROLE_USER"],
  "email": "alice@example.com"
}

Signature:
RSASHA256(
  base64url(header) + "." + base64url(payload),
  privateKey  // only Authorization Server has this
)
```

**Signature algorithms:**

```
Symmetric (HMAC):
     HS256, HS384, HS512
     Same secret for signing AND verification
     Auth Server and Resource Server share the secret
     → Problem: Resource Server must know the secret → can forge tokens!
     Use only when Auth Server = Resource Server (monolith)

Asymmetric (RSA, ECDSA):
     RS256, RS384, RS512 (RSA)
     ES256, ES384, ES512 (ECDSA)
     Private key: Auth Server signs (kept secret)
     Public key: Resource Server verifies (publicly available)
     → Resource Server CANNOT forge tokens (no private key)
     → Recommended for distributed systems
     → Keys published at: {issuer}/.well-known/jwks.json (JWKS endpoint)
```

---

### 12.11 OAuth2 Endpoints — Standard URLs

```
Authorization Endpoint:
     GET {issuer}/oauth2/authorize
     Purpose: User authenticates and grants consent
     Used in: Authorization Code, PKCE, Implicit (deprecated)

Token Endpoint:
     POST {issuer}/oauth2/token
     Purpose: Exchange code/credentials for tokens
     Used in: All grant types

UserInfo Endpoint (OIDC):
     GET {issuer}/userinfo
     Authorization: Bearer {access_token}
     Purpose: Get current user's claims
     Returns: JSON with standard OIDC claims

JWKS Endpoint:
     GET {issuer}/.well-known/jwks.json
     Purpose: Publish public keys for JWT verification
     Cached by Resource Servers

Introspection Endpoint:
     POST {issuer}/oauth2/introspect
     Purpose: Validate opaque tokens, get associated claims
     Used by: Resource Servers with opaque tokens

Revocation Endpoint:
     POST {issuer}/oauth2/revoke
     Purpose: Invalidate access/refresh tokens
     Used by: Clients on logout

Discovery Endpoint (OIDC):
     GET {issuer}/.well-known/openid-configuration
     Purpose: Auto-discover all other endpoints and capabilities
     Used by: Spring Security for auto-configuration
```

---

### 12.12 OAuth 2.1 — The Modernization

OAuth 2.1 (draft RFC) consolidates best practices from the past decade:

```
OAuth 2.1 changes from 2.0:
     ✓ PKCE REQUIRED for all authorization code flows
       (even confidential clients — defense in depth)

     ✓ Redirect URIs MUST be exact match
       (no wildcard, no partial matching)

     ✗ Implicit Grant REMOVED
       (access token in URL fragment — insecure)

     ✗ Resource Owner Password Credentials REMOVED
       (password sharing defeats OAuth2 purpose)

     ✓ Refresh token MUST be sender-constrained OR rotated
       (prevents token theft)

     ✓ Bearer token usage in query parameters PROHIBITED
       (tokens must only be in Authorization header or request body)
```

---

## 2️⃣ Code Examples

---

### Example 1 — Spring Security OAuth2 Client Setup (Authorization Code + OIDC)

```yaml
# application.yml — Google OAuth2 login
spring:
  security:
    oauth2:
      client:
        registration:
          google:
            client-id: YOUR_GOOGLE_CLIENT_ID
            client-secret: YOUR_GOOGLE_CLIENT_SECRET
            scope:
              - openid
              - profile
              - email
            redirect-uri: "{baseUrl}/login/oauth2/code/{registrationId}"
            authorization-grant-type: authorization_code
            client-authentication-method: client_secret_basic

        provider:
          google:
            # Spring Boot auto-configures this for Google, GitHub, Okta, etc.
            # For custom provider:
            authorization-uri: https://accounts.google.com/o/oauth2/v2/auth
            token-uri: https://oauth2.googleapis.com/token
            user-info-uri: https://www.googleapis.com/oauth2/v3/userinfo
            jwk-set-uri: https://www.googleapis.com/oauth2/v3/certs
            user-name-attribute: sub
```

```java
@Configuration
@EnableWebSecurity
public class OAuth2LoginConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/", "/login/**", "/error").permitAll()
                .anyRequest().authenticated()
            )
            .oauth2Login(oauth2 -> oauth2
                .loginPage("/login")
                .defaultSuccessUrl("/dashboard", true)
                .failureUrl("/login?error")
                .userInfoEndpoint(userInfo -> userInfo
                    .userService(customOAuth2UserService())
                    .oidcUserService(customOidcUserService())
                )
            );

        return http.build();
    }

    @Bean
    public OAuth2UserService<OAuth2UserRequest, OAuth2User>
            customOAuth2UserService() {
        DefaultOAuth2UserService delegate = new DefaultOAuth2UserService();

        return request -> {
            OAuth2User user = delegate.loadUser(request);

            // Extract additional info and create custom principal
            Map<String, Object> attributes = user.getAttributes();
            String email = (String) attributes.get("email");

            // Optionally: provision user in local database
            // userRepository.findByEmail(email)
            //     .orElseGet(() -> userRepository.save(new User(email)));

            return user;
        };
    }
}
```

---

### Example 2 — PKCE Configuration for Public Client

```yaml
# application.yml — SPA with PKCE (no client secret)
spring:
  security:
    oauth2:
      client:
        registration:
          my-spa:
            client-id: spa-public-client
            # NO client-secret — public client!
            scope: openid, profile, email, read:orders
            redirect-uri: "https://app.example.com/callback"
            authorization-grant-type: authorization_code
            client-authentication-method: none  # public client
        provider:
          my-spa:
            authorization-uri: https://auth.example.com/oauth2/authorize
            token-uri: https://auth.example.com/oauth2/token
            jwk-set-uri: https://auth.example.com/oauth2/jwks
```

```java
// Spring Security 6.x PKCE is enabled automatically for public clients
// (client-authentication-method: none)
// No additional configuration needed — PKCE challenge is generated and verified

// What Spring Security does automatically:
// 1. Generates code_verifier = random 43-128 char string
// 2. Computes code_challenge = BASE64URL(SHA256(code_verifier))
// 3. Includes challenge in authorization request
// 4. Stores verifier in session
// 5. Includes verifier in token exchange request
```

---

### Example 3 — Client Credentials Grant (Service-to-Service)

```yaml
spring:
  security:
    oauth2:
      client:
        registration:
          inventory-service:
            client-id: order-service
            client-secret: order-service-secret
            authorization-grant-type: client_credentials
            scope: inventory:read inventory:write
        provider:
          inventory-service:
            token-uri: https://auth.example.com/oauth2/token
```

```java
@Service
public class InventoryClient {

    private final WebClient webClient;

    public InventoryClient(
            OAuth2AuthorizedClientManager authorizedClientManager) {

        // Configure WebClient with automatic token management
        ServletOAuth2AuthorizedClientExchangeFilterFunction oauth2 =
            new ServletOAuth2AuthorizedClientExchangeFilterFunction(
                authorizedClientManager);

        oauth2.setDefaultClientRegistrationId("inventory-service");

        this.webClient = WebClient.builder()
            .apply(oauth2.oauth2Configuration())
            .baseUrl("https://api.inventory.com")
            .build();
    }

    public Inventory getInventory(String productId) {
        return webClient
            .get()
            .uri("/inventory/{id}", productId)
            .retrieve()
            .bodyToMono(Inventory.class)
            .block();
        // WebClient automatically:
        // 1. Gets/caches client_credentials token
        // 2. Adds Authorization: Bearer header
        // 3. Refreshes token when expired
    }
}

@Bean
public OAuth2AuthorizedClientManager authorizedClientManager(
        ClientRegistrationRepository registrations,
        OAuth2AuthorizedClientRepository clientRepository) {

    // Client credentials provider
    OAuth2AuthorizedClientProvider provider =
        OAuth2AuthorizedClientProviderBuilder.builder()
            .clientCredentials()
            .refreshToken()  // for other grant types
            .build();

    DefaultOAuth2AuthorizedClientManager manager =
        new DefaultOAuth2AuthorizedClientManager(
            registrations, clientRepository);
    manager.setAuthorizedClientProvider(provider);
    return manager;
}
```

---

### Example 4 — Custom Claims Extraction from JWT

```java
@Configuration
public class JwtClaimsConfig {

    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter authoritiesConverter =
            new JwtGrantedAuthoritiesConverter();

        // Claim name where roles are stored in JWT
        authoritiesConverter.setAuthoritiesClaimName("roles");

        // Prefix to add to each role value
        authoritiesConverter.setAuthorityPrefix("ROLE_");
        // JWT: "roles": ["ADMIN", "USER"]
        // Spring: [ROLE_ADMIN, ROLE_USER]

        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(authoritiesConverter);

        // Custom principal name extraction
        converter.setPrincipalClaimName("email");
        // Instead of "sub", use "email" as the principal name

        return converter;
    }
}
```

---

### Example 5 — Accessing OAuth2 User Info in Controller

```java
@RestController
public class UserController {

    // Standard Spring Security Authentication
    @GetMapping("/me")
    public Map<String, Object> getCurrentUser(Authentication authentication) {

        if (authentication instanceof OAuth2AuthenticationToken oauth2Token) {
            // OAuth2 Login (Authorization Code flow)
            OAuth2User user = oauth2Token.getPrincipal();
            return Map.of(
                "name",     user.getAttribute("name"),
                "email",    user.getAttribute("email"),
                "provider", oauth2Token.getAuthorizedClientRegistrationId()
            );

        } else if (authentication instanceof JwtAuthenticationToken jwtToken) {
            // Resource Server JWT
            Jwt jwt = jwtToken.getToken();
            return Map.of(
                "sub",    jwt.getSubject(),
                "email",  jwt.getClaimAsString("email"),
                "scopes", jwt.getClaimAsStringList("scope"),
                "expiry", jwt.getExpiresAt()
            );
        }

        return Map.of("user", authentication.getName());
    }

    // Access raw OAuth2 token details
    @GetMapping("/token-info")
    public Map<String, Object> getTokenInfo(
            @RegisteredOAuth2AuthorizedClient("google")
            OAuth2AuthorizedClient authorizedClient) {

        OAuth2AccessToken accessToken = authorizedClient.getAccessToken();
        return Map.of(
            "tokenValue", accessToken.getTokenValue(),
            "issuedAt",   accessToken.getIssuedAt(),
            "expiresAt",  accessToken.getExpiresAt(),
            "scopes",     accessToken.getScopes()
        );
    }
}
```

---

### Example 6 — JWT Validation Configuration (Resource Server)

```java
@Configuration
@EnableWebSecurity
public class ResourceServerConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/public/**").permitAll()
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                .anyRequest().hasAuthority("SCOPE_read")
            )
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt
                    .decoder(jwtDecoder())
                    .jwtAuthenticationConverter(jwtAuthConverter())
                )
            )
            .sessionManagement(s -> s
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .csrf(AbstractHttpConfigurer::disable);

        return http.build();
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        // Option A: JWK Set URI (auto-downloads public keys, caches them)
        return NimbusJwtDecoder
            .withJwkSetUri("https://auth.example.com/.well-known/jwks.json")
            .build();

        // Option B: Public key file (static key)
        // return NimbusJwtDecoder
        //     .withPublicKey(loadPublicKey())
        //     .build();

        // Option C: Issuer URI (auto-discovers all endpoints via OIDC discovery)
        // return JwtDecoders.fromIssuerLocation("https://auth.example.com");
    }

    @Bean
    public JwtAuthenticationConverter jwtAuthConverter() {
        JwtGrantedAuthoritiesConverter converter =
            new JwtGrantedAuthoritiesConverter();
        converter.setAuthoritiesClaimName("roles");
        converter.setAuthorityPrefix("ROLE_");

        JwtAuthenticationConverter jwtConverter = new JwtAuthenticationConverter();
        jwtConverter.setJwtGrantedAuthoritiesConverter(
            token -> {
                // Combine roles AND scopes into authorities
                Collection<GrantedAuthority> roleAuthorities =
                    converter.convert(token);

                Collection<GrantedAuthority> scopeAuthorities =
                    new JwtGrantedAuthoritiesConverter().convert(token);

                List<GrantedAuthority> all = new ArrayList<>();
                all.addAll(roleAuthorities);
                all.addAll(scopeAuthorities);
                return all;
            }
        );
        return jwtConverter;
    }
}
```

---

### Example 7 — Common OAuth2 Misconfigurations

```java
// ❌ WRONG 1 — Using ID token as access token
// ID token is for CLIENT to verify user identity
// Resource Server should validate ACCESS token, not ID token
http.oauth2ResourceServer(oauth2 -> oauth2
    .jwt(jwt -> jwt
        // DO NOT use the id_token endpoint as your jwk-set-uri
        // ID tokens are for the client, not resource servers
        .decoder(NimbusJwtDecoder
            .withJwkSetUri("https://auth.example.com/id-token-jwks")
            .build())
    )
);
```

```java
// ❌ WRONG 2 — Not validating audience (aud) claim
// Without audience validation, tokens issued for OTHER services work here!
@Bean
public JwtDecoder jwtDecoder() {
    NimbusJwtDecoder decoder = NimbusJwtDecoder
        .withJwkSetUri("https://auth.example.com/.well-known/jwks.json")
        .build();

    // Missing: audience validator
    // Token for audience "other-service" accepted by your service!

    // ✓ CORRECT — validate audience:
    OAuth2TokenValidator<Jwt> audienceValidator = token -> {
        if (token.getAudience().contains("your-service-identifier")) {
            return OAuth2TokenValidatorResult.success();
        }
        return OAuth2TokenValidatorResult.failure(
            new OAuth2Error("invalid_token", "Invalid audience", null));
    };

    OAuth2TokenValidator<Jwt> withAudience =
        new DelegatingOAuth2TokenValidator<>(
            JwtValidators.createDefault(),
            audienceValidator
        );
    decoder.setJwtValidator(withAudience);
    return decoder;
}
```

```java
// ❌ WRONG 3 — ROPC Grant in production (deprecated/removed in OAuth 2.1)
// Defeats the purpose of OAuth2 — user gives password to client
// Never use for third-party integrations
spring:
  security:
    oauth2:
      client:
        registration:
          my-app:
            authorization-grant-type: password  # WRONG!
```

---

## 3️⃣ Exam-Style Questions

---

**Q1 (MCQ):** In the OAuth2 Authorization Code flow, what prevents an attacker from exchanging a stolen authorization code for an access token?

A. The authorization code is encrypted
B. The authorization code expires in seconds
C. The token exchange requires the `client_secret` known only to the client
D. The authorization code is one-time-use

**Answer: C (primary protection), with D as secondary**
The authorization code is exchanged server-side using `client_secret`. An attacker who intercepts the code (from browser URL/history/logs) cannot exchange it without the `client_secret` (which never travels through the browser). D is also correct (codes are single-use) but the primary protection for confidential clients is C.

---

**Q2 (MCQ):** What is the primary purpose of the `state` parameter in the Authorization Code flow?

A. It carries the user's identity across the redirect
B. It prevents CSRF attacks on the OAuth2 callback endpoint
C. It encodes the requested scopes
D. It identifies the Authorization Server

**Answer: B**
The `state` parameter is a random value generated by the client, stored in session, and included in the authorization URL. When the Auth Server redirects back with the code, the client validates that the returned `state` matches the session-stored value. This prevents CSRF attacks where an attacker tricks the application into processing an attacker-controlled authorization response.

---

**Q3 (Select All That Apply):** Which are true about PKCE?

A. PKCE requires the client to have a `client_secret`
B. `code_verifier` is a high-entropy random string generated by the client
C. `code_challenge = BASE64URL(SHA256(code_verifier))` with `S256` method
D. PKCE protects against authorization code interception attacks
E. PKCE is mandatory in OAuth 2.1 for all authorization code flows

**Answer: B, C, D, E**
A is false — PKCE was specifically designed for PUBLIC clients that CANNOT have a `client_secret`. The cryptographic proof (verifier/challenge) replaces the client secret.

---

**Q4 (Scenario):**

```yaml
spring:
  security:
    oauth2:
      client:
        registration:
          my-api:
            authorization-grant-type: client_credentials
            scope: read:data
```

A user tries to log in via this configuration. What happens?

**Answer:** Nothing user-facing happens — client credentials grant has NO user authentication flow. There is no authorization code redirect, no login page, no consent screen. The application authenticates itself (as a service) to obtain tokens. If the intent was to provide user login, this is a misconfiguration — `authorization_code` grant type should be used instead.

---

**Q5 (OAuth2 vs OIDC):**

A developer says: "I'm using OAuth2 to authenticate users — I check the access token to know who logged in." What is wrong with this approach?

**Answer:** OAuth2 is an **authorization** framework, not an authentication protocol. The access token does NOT reliably identify the user:
1. Access token format is not standardized — it may be opaque (no readable claims)
2. Access token is for the **Resource Server**, not for the Client to inspect
3. No standard claims for user identity in plain OAuth2

**Correct approach:** Use **OIDC** (OpenID Connect). Request `scope=openid` to get an `id_token` (always a JWT with standard identity claims like `sub`, `email`, `name`). The `id_token` is designed for the **Client** to verify user identity. Spring Security's `OAuth2LoginConfigurer` handles this automatically when `openid` scope is included.

---

**Q6 (Token Validation):**

A Resource Server receives:
```
Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhbGljZSIsImF1ZCI6WyJvdGhlci1zZXJ2aWNlIl0sImV4cCI6OTk5OTk5OTk5OX0.SIGNATURE
```

The JWT is valid (signature checks out, not expired). The `aud` claim is `["other-service"]`. Your service is `"my-service"`. What should happen?

**Answer:** The JWT should be **rejected** with `401 Unauthorized`. Even though the JWT is cryptographically valid and not expired, it was issued for `"other-service"`, not `"my-service"`. Without audience validation, tokens intended for one service can be used on any other service sharing the same Auth Server — a serious security vulnerability. Spring Security's `NimbusJwtDecoder` with proper audience validator catches this.

---

**Q7 (Grant Type Selection):**

Match each scenario to the correct grant type:

| Scenario | Grant Type |
|----------|-----------|
| A. User logs into web app via "Login with Google" | ? |
| B. React SPA user logs in (no backend secret) | ? |
| C. Nightly batch job accesses reporting API | ? |
| D. Access token expired, get new one silently | ? |

**Answers:**
- A → Authorization Code Grant (confidential client with `client_secret`)
- B → Authorization Code + PKCE (public client, no `client_secret`)
- C → Client Credentials Grant (no user, service authenticates itself)
- D → Refresh Token Grant (exchange refresh token for new access token)

---

**Q8 (JWT Claims):**

A JWT payload contains:
```json
{
  "sub": "alice",
  "iss": "https://auth.example.com",
  "aud": ["api.example.com"],
  "exp": 1699996399,
  "iat": 1699992799,
  "scope": "read write",
  "roles": ["USER"]
}
```

Spring Security JwtAuthenticationConverter is configured with:
```java
converter.setAuthoritiesClaimName("roles");
converter.setAuthorityPrefix("ROLE_");
```

What authorities does the resulting `Authentication` object have?

**Answer:** `[ROLE_USER, SCOPE_read, SCOPE_write]`

The custom `JwtGrantedAuthoritiesConverter` with `authoritiesClaimName="roles"` and `authorityPrefix="ROLE_"` produces `ROLE_USER` from the `roles` claim.

Additionally, the **default** `JwtGrantedAuthoritiesConverter` (which processes the `scope` claim) produces `SCOPE_read` and `SCOPE_write` from the `scope` claim.

BUT — this depends on whether both converters are applied. If only the custom converter is set (replacing the default), then only `ROLE_USER` is produced. If both are composed (as in Example 6), all three are present. The exam answer depends on the exact configuration — know both scenarios.

---

## 4️⃣ Trick Analysis

---

**Trick 1 — OAuth2 Is NOT Authentication — The Identity Confusion**

```
OAuth2 access token tells you: "This bearer can do X"
OAuth2 access token does NOT tell you: "This is Alice"

Developers commonly:
     GET /userinfo with access_token → get user info → "I authenticated Alice!"
     
This works PRACTICALLY but is NOT OAuth2.
This is actually OIDC (the userinfo endpoint is an OIDC endpoint).

Correct mental model:
     OAuth2 = delegation (can do X)
     OIDC   = identity (is Alice, certified by Auth Server)
     
Spring Security's oauth2Login() uses OIDC automatically
when scope includes 'openid' → gets id_token → proper authentication
```

---

**Trick 2 — `aud` Claim Validation Is Critical (Often Missed)**

```
Without audience validation:
     Token issued for "service-a" → works on "service-b"
     All services share same Auth Server → same signing key
     Compromised service-a credentials → attacker uses token on service-b
     → Cross-service token abuse

With audience validation:
     JwtDecoder checks: aud claim contains "service-b"?
     No → Reject (even if signature is valid)

Default NimbusJwtDecoder behavior:
     Spring Boot: If issuer-uri configured → auto-validates aud
     If jwk-set-uri only → NO auto aud validation!
     Must add custom OAuth2TokenValidator<Jwt>
```

---

**Trick 3 — Implicit Grant Removal**

```
OAuth 2.0 Implicit Grant:
     access_token returned directly in URL fragment:
     https://app.com/callback#access_token=TOKEN&...
     
Problems:
     Token in URL → browser history
     Token in URL → server logs
     Token in URL → Referer header leakage
     No refresh token support
     
OAuth 2.1: Implicit grant REMOVED
Spring Security: Still supports it for backward compatibility
                 but actively discourages it
                 
"I need Implicit grant for my SPA" → Use Authorization Code + PKCE instead
                 
EXAM TRAP: "What replaced Implicit Grant for SPAs?"
Answer: Authorization Code + PKCE
```

---

**Trick 4 — Resource Owner Password Credentials (ROPC) Trap**

```
ROPC Grant:
     Client collects username + password directly
     Sends to token endpoint: grant_type=password&username=alice&password=secret
     
Why it defeats OAuth2:
     Client sees raw credentials (OAuth2 was designed to PREVENT this!)
     No SSO (user must enter password in every app)
     No MFA support
     No consent screen
     
When teams use it:
     "Our own app, so it's fine to use ROPC"
     
Why it's still wrong:
     Migrating to SSO/federation becomes impossible
     If client is compromised, passwords are exposed
     
OAuth 2.1: ROPC REMOVED
Spring Security: Still configurable but deprecated
Correct: Use Authorization Code for user-facing apps
         Use Client Credentials for machine-to-machine
```

---

**Trick 5 — `scope` vs `roles` — Two Different Authorization Models**

```
Scopes (OAuth2 standard):
     Define what the CLIENT can do on behalf of the user
     Granted by the user during consent
     Format: "read:orders write:orders profile"
     Examples: SCOPE_read, SCOPE_write
     Spring default: JwtGrantedAuthoritiesConverter adds SCOPE_ prefix

Roles (application-specific):
     Define what the USER can do
     Assigned to user by the application
     Format: "ROLE_ADMIN", "ROLE_USER"
     Not an OAuth2 standard — application convention

In JWT resource server:
     scope claim → hasAuthority("SCOPE_read")
     roles claim → hasRole("ADMIN") (if converter adds ROLE_ prefix)

EXAM TRAP:
     "hasRole('read')" checks for "ROLE_read" — won't match "SCOPE_read"!
     "hasAuthority('SCOPE_read')" is the correct check for scope claims
```

---

**Trick 6 — JWK Set Caching and Key Rotation**

```
Spring Security caches JWKS (public keys) from:
     https://auth.example.com/.well-known/jwks.json

Default behavior:
     Keys cached indefinitely (with background refresh)
     If Auth Server rotates keys (new kid in JWT header):
          NimbusJwtDecoder tries cached keys → verification fails
          → Triggers fresh JWKS fetch
          → Verifies with new key

Misconfiguration trap:
     Using static public key file instead of JWKS URI:
          .withPublicKey(loadStaticKey())
     When Auth Server rotates keys → all new tokens fail verification!
     → Use withJwkSetUri() or fromIssuerLocation() for production
```

---

**Trick 7 — The Difference Between `client-authentication-method`**

```
client_secret_basic:
     Credentials in Authorization header:
     Authorization: Basic Base64(client_id:client_secret)
     RFC 6749 recommended method

client_secret_post:
     Credentials in request body:
     POST /token
     client_id=...&client_secret=...
     Less preferred (body can be logged)

client_secret_jwt:
     Client signs assertion JWT with shared secret
     High security for confidential clients

private_key_jwt:
     Client signs assertion JWT with private key
     Server verifies with client's registered public key
     Highest security — private key never transmitted

none:
     No authentication (public client)
     Used with PKCE
     Must configure PKCE on auth server too
```

---

## 5️⃣ Summary Sheet

---

### OAuth2 Roles and Token Flow

```
Resource Owner (User Alice)
     │ Grants permission
     ▼
Authorization Server (Google/Okta/Spring Auth Server)
     │ Issues tokens
     ├──► access_token  → Resource Server (API authorization)
     ├──► id_token      → Client (user identity, OIDC only)
     └──► refresh_token → Client (get new access_token)
                              │
                              ▼
                    Client (Your Spring Boot App)
                         │ Uses access_token
                         ▼
                    Resource Server (Your API / Google APIs)
```

---

### Grant Type Decision Tree

```
Is a USER involved?
     NO  → Client Credentials Grant (machine-to-machine)
     YES → Continue

Is the client a PUBLIC client (SPA, mobile — no secret)?
     YES → Authorization Code + PKCE
     NO  → Continue (confidential client)

Does the client have a server-side component?
     YES → Authorization Code Grant (standard)
     NO  → Authorization Code + PKCE (even for confidential SPAs)

Need new access token without re-login?
     → Refresh Token Grant
```

---

### JWT Claims Reference

| Claim | Name | Purpose |
|-------|------|---------|
| `sub` | Subject | Unique user identifier (stable) |
| `iss` | Issuer | Who issued the token |
| `aud` | Audience | Intended recipient(s) |
| `exp` | Expiration | Token expiry (Unix timestamp) |
| `iat` | Issued At | When token was issued |
| `nbf` | Not Before | Token not valid before this time |
| `jti` | JWT ID | Unique token ID (replay prevention) |
| `scope` | Scope | OAuth2 scopes granted |
| `nonce` | Nonce | OIDC replay attack prevention |

---

### OAuth2 vs OIDC Comparison

| Aspect | OAuth2 | OIDC |
|--------|--------|------|
| Purpose | Authorization (delegation) | Authentication (identity) |
| Question | "Can app do X?" | "Who is the user?" |
| Token | access_token | id_token (+ access_token) |
| Token format | Any | id_token is always JWT |
| User info | Not standardized | Standardized claims (sub, email) |
| Trigger | Any scope | Must include `openid` scope |
| Discovery | Not standard | `/.well-known/openid-configuration` |

---

### Common Interview One-Liners

- **OAuth2 is authorization, not authentication** — use OIDC (`scope=openid`) for identity
- **Authorization code is NOT the access token** — it's a short-lived, single-use code exchanged server-side
- **PKCE replaces `client_secret`** for public clients via cryptographic proof (SHA256 hash challenge)
- **`state` parameter** prevents CSRF on the OAuth2 callback endpoint
- **Client Credentials** = no user, service authenticates itself (machine-to-machine)
- **`aud` claim validation is critical** — without it, tokens for service-A work on service-B
- **`sub` claim** = stable user identifier — use as database key, not `email` (email can change)
- **Implicit grant is removed in OAuth 2.1** — replaced by Authorization Code + PKCE for SPAs
- **Refresh token rotation** detects theft — reuse of rotated token triggers session invalidation
- **`scope` → `SCOPE_` prefix** in Spring Security; `roles` → `ROLE_` prefix (different claims, different checks)

---
