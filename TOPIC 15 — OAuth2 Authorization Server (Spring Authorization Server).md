# TOPIC 15 — OAuth2 Authorization Server (Spring Authorization Server)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

---

## 1️⃣ Conceptual Explanation

---

### 15.1 What Is Spring Authorization Server — Design Philosophy

Spring Authorization Server (SAS) is a **separate project** from Spring Security that implements the **OAuth 2.1** and **OpenID Connect 1.0** specifications. It provides a complete, production-ready Authorization Server that issues and manages tokens.

**Relationship to Spring Security:**

```
Spring Security:
     ├── Authentication (form login, Basic, OAuth2 client, Resource Server)
     ├── Authorization (filter chain, method security)
     └── Infrastructure (filters, context, sessions)

Spring Authorization Server (builds ON TOP of Spring Security):
     ├── Authorization endpoint (/oauth2/authorize)
     ├── Token endpoint (/oauth2/token)
     ├── JWK Set endpoint (/.well-known/jwks.json)
     ├── Token introspection endpoint (/oauth2/introspect)
     ├── Token revocation endpoint (/oauth2/revoke)
     ├── OpenID Connect userinfo endpoint (/userinfo)
     └── OIDC discovery endpoint (/.well-known/openid-configuration)
```

**Key design decisions:**

```
1. Separation from Spring Security core:
     Independent release cycle
     OAuth2 spec evolves independently
     Cleaner separation of concerns

2. Extensible by design:
     Every component can be replaced or extended
     Token customizers, grant type handlers, etc.
     Not "convention over configuration" — explicit wiring

3. OAuth 2.1 compliance:
     PKCE required for authorization code (even confidential clients)
     Refresh token rotation by default
     No implicit grant
     No ROPC grant
```

---

### 15.2 Spring Authorization Server Architecture — Component Map

```
Spring Authorization Server Components:
     │
     ├── AuthorizationServerSettings
     │       Configuration: issuer URI, endpoint URLs
     │
     ├── RegisteredClientRepository
     │       Stores OAuth2 client registrations
     │       InMemory or JDBC backed
     │
     ├── OAuth2AuthorizationService
     │       Stores active authorizations (codes, tokens)
     │       InMemory or JDBC backed
     │
     ├── OAuth2AuthorizationConsentService
     │       Stores user consent decisions
     │       InMemory or JDBC backed
     │
     ├── JWKSource<SecurityContext>
     │       Provides JWK Set (public keys for JWT signing)
     │       Used by: /.well-known/jwks.json endpoint
     │
     ├── OAuth2TokenGenerator<T>
     │       Generates access tokens, refresh tokens, auth codes
     │       Pluggable: JWT, opaque, custom formats
     │
     ├── TokenSettings
     │       Per-client token configuration
     │       access token TTL, refresh token TTL, rotation policy
     │
     └── ClientSettings
             Per-client security settings
             PKCE requirement, consent requirement, auth methods
```

---

### 15.3 RegisteredClient — The Client Model

`RegisteredClient` is the Spring Authorization Server's model for an OAuth2 client registration. It is the server-side equivalent of Spring Security's `ClientRegistration`.

```java
RegisteredClient client = RegisteredClient
    .withId(UUID.randomUUID().toString())  // internal ID

    // ── Client Identity ─────────────────────────────────────────
    .clientId("my-client")
    .clientSecret(passwordEncoder.encode("my-secret"))
    // Encoded with PasswordEncoder — never store plaintext!

    // ── Authentication Methods ────────────────────────────────────
    .clientAuthenticationMethod(
        ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
    // How client authenticates to token endpoint:
    // CLIENT_SECRET_BASIC → Authorization: Basic header
    // CLIENT_SECRET_POST  → client_id/secret in POST body
    // CLIENT_SECRET_JWT   → client signs JWT with shared secret
    // PRIVATE_KEY_JWT     → client signs JWT with private key
    // NONE                → public client (no authentication)

    // ── Grant Types ───────────────────────────────────────────────
    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
    .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)

    // ── Redirect URIs ─────────────────────────────────────────────
    .redirectUri("https://app.example.com/login/oauth2/code/my-provider")
    .redirectUri("https://app.example.com/authorized")
    // EXACT match required — no wildcards, no partial matches
    // OAuth 2.1 requirement

    // ── Post-Logout Redirect URIs (OIDC) ──────────────────────────
    .postLogoutRedirectUri("https://app.example.com/logged-out")

    // ── Scopes ────────────────────────────────────────────────────
    .scope(OidcScopes.OPENID)     // "openid" — enables OIDC
    .scope(OidcScopes.PROFILE)    // "profile"
    .scope(OidcScopes.EMAIL)      // "email"
    .scope("read:orders")         // custom scope
    .scope("write:orders")

    // ── Client Settings ───────────────────────────────────────────
    .clientSettings(ClientSettings.builder()
        .requireAuthorizationConsent(true)
        // Show consent screen to user

        .requireProofKey(false)
        // true = REQUIRE PKCE (recommended for all clients in OAuth 2.1)
        // false = PKCE optional

        .jwkSetUrl("https://client.example.com/.well-known/jwks.json")
        // For PRIVATE_KEY_JWT client auth — client's public key location

        .tokenEndpointAuthenticationSigningAlgorithm(
            SignatureAlgorithm.RS256)
        .build())

    // ── Token Settings ────────────────────────────────────────────
    .tokenSettings(TokenSettings.builder()
        .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
        // SELF_CONTAINED = JWT (default)
        // REFERENCE = opaque token

        .accessTokenTimeToLive(Duration.ofMinutes(30))

        .refreshTokenTimeToLive(Duration.ofDays(7))

        .reuseRefreshTokens(false)
        // false = rotate refresh token on every use (recommended)
        // true = same refresh token until expiry (less secure)

        .idTokenSignatureAlgorithm(SignatureAlgorithm.RS256)

        .authorizationCodeTimeToLive(Duration.ofMinutes(5))
        .build())

    .build();
```

---

### 15.4 Authorization Server Endpoints — Deep Architecture

**The Protocol Endpoint Filters:**

Spring Authorization Server registers a set of `SecurityFilterChain` beans, each handling specific OAuth2 protocol endpoints:

```
Spring Authorization Server adds these filter chains:

Filter Chain 1: OAuth2 Authorization Endpoint
     URL: /oauth2/authorize (GET + POST)
     Filter: OAuth2AuthorizationEndpointFilter
     Handles: Authorization Code initiation + consent

Filter Chain 2: OAuth2 Token Endpoint
     URL: /oauth2/token (POST)
     Filter: OAuth2TokenEndpointFilter
     Handles: All grant type token issuance

Filter Chain 3: OAuth2 Token Introspection
     URL: /oauth2/introspect (POST)
     Filter: OAuth2TokenIntrospectionEndpointFilter

Filter Chain 4: OAuth2 Token Revocation
     URL: /oauth2/revoke (POST)
     Filter: OAuth2TokenRevocationEndpointFilter

Filter Chain 5: JWK Set
     URL: /.well-known/jwks.json (GET)
     Filter: NimbusJwkSetEndpointFilter

Filter Chain 6: OIDC Provider Configuration
     URL: /.well-known/openid-configuration (GET)
     Filter: OidcProviderConfigurationEndpointFilter

Filter Chain 7: OIDC UserInfo
     URL: /userinfo (GET + POST)
     Filter: OidcUserInfoEndpointFilter

Filter Chain 8: OIDC Client Registration (optional)
     URL: /connect/register (POST)
     Filter: OidcClientRegistrationEndpointFilter
```

---

### 15.5 Authorization Endpoint — The User-Facing Flow

The authorization endpoint is where the **user** interacts — authenticating and granting consent.

**Complete authorization endpoint flow:**

```
Step 1: Client initiates authorization
GET /oauth2/authorize
?response_type=code
&client_id=my-client
&redirect_uri=https://app.example.com/callback
&scope=openid profile read:orders
&state=random-state
&code_challenge=BASE64URL(SHA256(verifier))  [PKCE]
&code_challenge_method=S256

     ▼
OAuth2AuthorizationEndpointFilter
     │
     ├── Validate client_id → load RegisteredClient
     ├── Validate redirect_uri (exact match)
     ├── Validate scopes (all requested scopes registered?)
     ├── Validate PKCE parameters (if required)
     ├── Check: Is user authenticated?
     │         NO  → Save authorization request
     │               Redirect to login page
     │               (Spring Security form login handles this)
     │         YES → Continue
     │
     ├── Check: Is consent required AND not previously given?
     │         YES → Store authorization request in session
     │               Redirect to consent page (/oauth2/consent)
     │               User approves/denies scopes
     │         NO  → Continue
     │
     ├── Generate authorization code
     │       code = 32 random bytes (URL-safe Base64)
     │       Store: OAuth2Authorization{
     │           registeredClientId, principalName,
     │           authorizationGrantType, attributes,
     │           authorizationCode{tokenValue, issuedAt, expiresAt},
     │           authorizedScopes, state
     │       }
     │       Saved via OAuth2AuthorizationService
     │
     └── Redirect to redirect_uri:
           https://app.example.com/callback
           ?code=AUTH_CODE_XYZ
           &state=random-state
```

---

### 15.6 Token Endpoint — The Machine-Facing Flow

The token endpoint is a **machine-to-machine** endpoint — clients authenticate here and exchange codes/credentials for tokens.

**Token endpoint internal flow:**

```
POST /oauth2/token
Content-Type: application/x-www-form-urlencoded
Authorization: Basic Base64(client_id:client_secret)
Body: grant_type=authorization_code
      &code=AUTH_CODE_XYZ
      &redirect_uri=https://app.example.com/callback
      &code_verifier=PKCE_VERIFIER  [if PKCE used]

     ▼
OAuth2TokenEndpointFilter
     │
     ├── Client Authentication:
     │       ClientSecretBasicAuthenticationConverter
     │       → Extract client credentials from Authorization header
     │       → Build OAuth2ClientAuthenticationToken
     │       → ClientSecretAuthenticationProvider validates
     │           → Load RegisteredClient by clientId
     │           → passwordEncoder.matches(secret, storedSecret)
     │           → Store authenticated client in SecurityContext
     │
     ├── Route to grant type handler:
     │       grant_type=authorization_code
     │           → OAuth2AuthorizationCodeAuthenticationProvider
     │       grant_type=client_credentials
     │           → OAuth2ClientCredentialsAuthenticationProvider
     │       grant_type=refresh_token
     │           → OAuth2RefreshTokenAuthenticationProvider
     │       grant_type=urn:ietf:params:oauth:grant-type:device_code
     │           → OAuth2DeviceCodeAuthenticationProvider
     │
     └── For authorization_code:
               ├── Load OAuth2Authorization by code
               ├── Validate code not expired
               ├── Validate redirect_uri matches
               ├── Validate PKCE: SHA256(verifier) == stored challenge
               ├── Generate tokens via OAuth2TokenGenerator:
               │       access_token  (JWT or opaque)
               │       refresh_token (opaque, if granted)
               │       id_token      (JWT, if openid scope)
               ├── Invalidate authorization code (single-use)
               ├── Save new OAuth2Authorization with tokens
               └── Return token response:
                     {
                       "access_token": "...",
                       "token_type": "Bearer",
                       "expires_in": 1800,
                       "scope": "openid profile read:orders",
                       "refresh_token": "...",
                       "id_token": "..."  [OIDC only]
                     }
```

---

### 15.7 OAuth2TokenGenerator — Token Generation Architecture

```java
// OAuth2TokenGenerator interface:
@FunctionalInterface
public interface OAuth2TokenGenerator<T extends OAuth2Token> {
    @Nullable
    T generate(OAuth2TokenContext context);
}

// Default implementation: DelegatingOAuth2TokenGenerator
// Delegates to registered generators in order:

DelegatingOAuth2TokenGenerator
     │
     ├── JwtGenerator
     │       Generates JWT access tokens and id_tokens
     │       Uses JWKSource to sign with RS256/ES256
     │       Customizable via OAuth2TokenCustomizer<JwtEncodingContext>
     │
     ├── OAuth2AccessTokenGenerator
     │       Generates opaque access tokens
     │       UUID-based random values
     │       Customizable via OAuth2TokenCustomizer<OAuth2TokenClaimsContext>
     │
     └── OAuth2RefreshTokenGenerator
             Generates opaque refresh tokens
             UUID-based random values
```

**`OAuth2TokenCustomizer` — adding custom claims to JWT:**

```java
@Bean
public OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
    return context -> {
        if (context.getTokenType() == OAuth2TokenType.ACCESS_TOKEN) {
            // Add custom claims to access token JWT
            Authentication principal = context.getPrincipal();

            // Add user roles
            Set<String> roles = principal.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .filter(auth -> auth.startsWith("ROLE_"))
                .map(role -> role.substring(5))  // remove ROLE_ prefix
                .collect(Collectors.toSet());

            context.getClaims().claim("roles", roles);

            // Add tenant ID from user details
            if (principal.getPrincipal() instanceof CustomUserDetails ud) {
                context.getClaims().claim("tenant", ud.getTenantId());
            }

            // Add client metadata
            context.getClaims().claim("client_id",
                context.getRegisteredClient().getClientId());
        }

        if (context.getTokenType().getValue().equals(
                OidcParameterNames.ID_TOKEN)) {
            // Add custom claims to ID token
            context.getClaims().claim("custom_claim", "custom_value");
        }
    };
}
```

**`JwtEncodingContext` — what's available for customization:**

```java
// Context provides access to:
context.getTokenType()          // ACCESS_TOKEN, REFRESH_TOKEN, ID_TOKEN
context.getPrincipal()          // Authentication of the resource owner
context.getRegisteredClient()   // The OAuth2 client
context.getAuthorizedScopes()   // Approved scopes
context.getAuthorizationGrant() // The authorization grant token
context.getAuthorizationGrantType() // authorization_code, client_credentials, etc.
context.getClaims()             // JwtClaimsSet.Builder — modify claims here
context.getJwsHeader()          // JwsHeader.Builder — modify header here
```

---

### 15.8 JWKSource — Key Management

The `JWKSource<SecurityContext>` provides the cryptographic keys for signing JWTs:

```java
@Bean
public JWKSource<SecurityContext> jwkSource() {
    // Generate RSA key pair at startup
    KeyPairGenerator keyPairGenerator =
        KeyPairGenerator.getInstance("RSA");
    keyPairGenerator.initialize(2048);
    KeyPair keyPair = keyPairGenerator.generateKeyPair();

    RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
    RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

    RSAKey rsaKey = new RSAKey.Builder(publicKey)
        .privateKey(privateKey)
        .keyID(UUID.randomUUID().toString())  // kid
        .keyUse(KeyUse.SIGNATURE)
        .keyOperations(Set.of(KeyOperation.SIGN, KeyOperation.VERIFY))
        .algorithm(JWSAlgorithm.RS256)
        .build();

    JWKSet jwkSet = new JWKSet(rsaKey);
    return new ImmutableJWKSet<>(jwkSet);
}
```

**Production key management concerns:**

```
Problem with in-memory keys:
     Keys generated at startup → different on each restart
     → All existing JWTs become invalid after restart
     → Different cluster nodes have different keys
     → Tokens from Node 1 cannot be verified by Node 2!

Production solutions:
     Option A: External key store (AWS KMS, HashiCorp Vault)
     Option B: Database-backed JWK store (persist key pair in DB)
     Option C: Kubernetes secrets / environment variables

// Persistent key example (from environment/vault):
@Bean
public JWKSource<SecurityContext> jwkSource(
        @Value("${auth.rsa.private-key}") RSAPrivateKey privateKey,
        @Value("${auth.rsa.public-key}") RSAPublicKey publicKey,
        @Value("${auth.rsa.key-id}") String keyId) {

    RSAKey rsaKey = new RSAKey.Builder(publicKey)
        .privateKey(privateKey)
        .keyID(keyId)  // stable key ID
        .build();

    return new ImmutableJWKSet<>(new JWKSet(rsaKey));
}
```

**Key rotation:**

```java
// For zero-downtime key rotation:
// 1. Add NEW key to JWK set (keep OLD key too)
// 2. Start signing with NEW key
// 3. Old tokens (signed with OLD key) still verifiable
// 4. Wait until all old tokens expire
// 5. Remove OLD key from JWK set

@Bean
public JWKSource<SecurityContext> jwkSource(KeyRotationService keyRotation) {
    return (selector, securityContext) -> {
        // Provide both old and new keys
        List<JWK> keys = new ArrayList<>();
        keys.add(keyRotation.getCurrentSigningKey());
        keys.addAll(keyRotation.getVerificationOnlyKeys());
        return selector.select(new JWKSet(keys));
    };
}
```

---

### 15.9 OAuth2AuthorizationService — Authorization Storage

`OAuth2AuthorizationService` stores and retrieves `OAuth2Authorization` objects — the record of what was authorized.

```java
// OAuth2Authorization represents an active authorization:
OAuth2Authorization {
    String id                          // internal ID
    String registeredClientId          // which client
    String principalName               // which user (or client for CC)
    AuthorizationGrantType             // how it was obtained
    Set<String> authorizedScopes       // approved scopes
    Map<Class<? extends OAuth2Token>, Token> tokens {
        OAuth2AuthorizationCode:   {value, issuedAt, expiresAt, invalidated}
        OAuth2AccessToken:         {value, issuedAt, expiresAt, tokenType, scopes}
        OAuth2RefreshToken:        {value, issuedAt, expiresAt}
        OidcIdToken:               {value, issuedAt, expiresAt, claims}
    }
    Map<String, Object> attributes     // state, code_challenge, nonce, etc.
}
```

**Storage implementations:**

```java
// InMemoryOAuth2AuthorizationService (development/testing)
@Bean
public OAuth2AuthorizationService authorizationService() {
    return new InMemoryOAuth2AuthorizationService();
}
// WARNING: Not suitable for production!
// All authorizations lost on restart
// No clustering support
// Unbounded memory growth (no cleanup of expired tokens)

// JdbcOAuth2AuthorizationService (production)
@Bean
public OAuth2AuthorizationService authorizationService(
        JdbcTemplate jdbcTemplate,
        RegisteredClientRepository registeredClientRepository) {
    return new JdbcOAuth2AuthorizationService(
        jdbcTemplate, registeredClientRepository);
}
// Requires oauth2_authorization table in database
// Survives restarts
// Works in clustered environments
```

---

### 15.10 Consent Management

When `requireAuthorizationConsent(true)` is set on a client, users must explicitly approve scopes on first authorization:

```java
// Default consent page: /oauth2/consent
// Custom consent page:
http.apply(authorizationServerConfigurer)
    .authorizationEndpoint(authz -> authz
        .consentPage("/custom-consent")
    );

// Custom consent controller:
@Controller
public class ConsentController {

    @GetMapping("/custom-consent")
    public String consentForm(
            Model model,
            @RequestParam String client_id,
            @RequestParam String scope,
            @RequestParam String state,
            @RegisteredOAuth2AuthorizedClient(...)
            // Load client details for display
            ) {
        // Display which scopes are being requested
        // User approves or denies
        return "consent";
    }
}
```

**Consent storage:**

```java
// OAuth2AuthorizationConsentService stores previous consent decisions
// So users don't have to approve the same scopes every time

InMemoryOAuth2AuthorizationConsentService  // dev
JdbcOAuth2AuthorizationConsentService       // production
```

---

### 15.11 PKCE Implementation in Spring Authorization Server

Spring Authorization Server implements PKCE as required by OAuth 2.1:

```
Authorization Code Request (with PKCE):
     code_challenge = BASE64URL(SHA256("random-verifier-string"))
     code_challenge_method = S256

     Stored in OAuth2Authorization.attributes:
          "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
          "code_challenge_method": "S256"

Token Request (with PKCE verification):
     code_verifier = "random-verifier-string"

     Spring Authorization Server validates:
          BASE64URL(SHA256(code_verifier)) == stored code_challenge?
          YES → issue token
          NO  → OAuth2AuthenticationException("pkce_required")

Configuring PKCE requirement per client:
     ClientSettings.builder()
          .requireProofKey(true)   // ALL authorization code requests must use PKCE
          .build()

     // If false: PKCE optional but recommended
     // If true: requests without PKCE are rejected
```

---

### 15.12 Complete Spring Authorization Server Setup

```java
// Minimum viable Authorization Server configuration:

@Configuration
@EnableWebSecurity
public class AuthorizationServerConfig {

    // Chain 1: Authorization Server protocol endpoints
    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerFilterChain(
            HttpSecurity http) throws Exception {

        // Apply default authorization server configuration
        OAuth2AuthorizationServerConfiguration
            .applyDefaultSecurity(http);

        // Enable OIDC
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
            .oidc(Customizer.withDefaults());

        // Custom authentication for unauthenticated requests:
        http.exceptionHandling(exceptions -> exceptions
            .defaultAuthenticationEntryPointFor(
                new LoginUrlAuthenticationEntryPoint("/login"),
                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
            )
        )
        // For Resource Server: validate access tokens for /userinfo
        .oauth2ResourceServer(oauth2 -> oauth2
            .jwt(Customizer.withDefaults())
        );

        return http.build();
    }

    // Chain 2: Default security for other endpoints (login form, etc.)
    @Bean
    @Order(2)
    public SecurityFilterChain defaultFilterChain(
            HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .anyRequest().authenticated()
            )
            .formLogin(Customizer.withDefaults());
        return http.build();
    }

    // Client registrations (in-memory for dev)
    @Bean
    public RegisteredClientRepository registeredClientRepository(
            PasswordEncoder passwordEncoder) {

        RegisteredClient webClient = RegisteredClient
            .withId(UUID.randomUUID().toString())
            .clientId("web-client")
            .clientSecret(passwordEncoder.encode("secret"))
            .clientAuthenticationMethod(
                ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(
                AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizationGrantType(
                AuthorizationGrantType.REFRESH_TOKEN)
            .redirectUri(
                "http://localhost:8080/login/oauth2/code/my-auth-server")
            .scope(OidcScopes.OPENID)
            .scope(OidcScopes.PROFILE)
            .scope(OidcScopes.EMAIL)
            .scope("read:orders")
            .clientSettings(ClientSettings.builder()
                .requireAuthorizationConsent(true)
                .requireProofKey(true)  // mandate PKCE
                .build())
            .tokenSettings(TokenSettings.builder()
                .accessTokenTimeToLive(Duration.ofMinutes(30))
                .refreshTokenTimeToLive(Duration.ofDays(7))
                .reuseRefreshTokens(false)
                .build())
            .build();

        return new InMemoryRegisteredClientRepository(webClient);
    }

    // JWK source for token signing
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = generateRsaKey();
        RSAKey rsaKey = new RSAKey.Builder(
                (RSAPublicKey) keyPair.getPublic())
            .privateKey((RSAPrivateKey) keyPair.getPrivate())
            .keyID(UUID.randomUUID().toString())
            .build();
        return new ImmutableJWKSet<>(new JWKSet(rsaKey));
    }

    private KeyPair generateRsaKey() {
        try {
            KeyPairGenerator gen =
                KeyPairGenerator.getInstance("RSA");
            gen.initialize(2048);
            return gen.generateKeyPair();
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException(ex);
        }
    }

    // JWT decoder for /userinfo endpoint validation
    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration
            .jwtDecoder(jwkSource);
    }

    // Authorization server settings (issuer URI)
    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
            .issuer("https://auth.example.com")
            .build();
    }

    // In-memory authorization service (dev only)
    @Bean
    public OAuth2AuthorizationService authorizationService() {
        return new InMemoryOAuth2AuthorizationService();
    }

    // In-memory consent service (dev only)
    @Bean
    public OAuth2AuthorizationConsentService consentService() {
        return new InMemoryOAuth2AuthorizationConsentService();
    }
}
```

---

## 2️⃣ Code Examples

---

### Example 1 — JDBC-Backed Authorization Server (Production)

```java
@Configuration
public class JdbcAuthorizationServerConfig {

    @Bean
    public RegisteredClientRepository registeredClientRepository(
            JdbcTemplate jdbcTemplate) {
        // Clients stored in oauth2_registered_client table
        JdbcRegisteredClientRepository repository =
            new JdbcRegisteredClientRepository(jdbcTemplate);

        // On first startup: register default clients
        if (repository.findByClientId("web-app") == null) {
            repository.save(buildWebAppClient());
            repository.save(buildApiClient());
        }

        return repository;
    }

    @Bean
    public OAuth2AuthorizationService authorizationService(
            JdbcTemplate jdbcTemplate,
            RegisteredClientRepository clients) {
        return new JdbcOAuth2AuthorizationService(
            jdbcTemplate, clients);
    }

    @Bean
    public OAuth2AuthorizationConsentService consentService(
            JdbcTemplate jdbcTemplate,
            RegisteredClientRepository clients) {
        return new JdbcOAuth2AuthorizationConsentService(
            jdbcTemplate, clients);
    }
}
```

```sql
-- Required tables (provided by Spring Authorization Server):
-- oauth2_registered_client
-- oauth2_authorization
-- oauth2_authorization_consent

-- Run schema from:
-- spring-authorization-server/oauth2-authorization-server/
--    src/main/resources/org/springframework/security/
--    oauth2/server/authorization/client/
--    oauth2-registered-client-schema.sql
```

---

### Example 2 — Custom Token Claims

```java
@Bean
public OAuth2TokenCustomizer<JwtEncodingContext> accessTokenCustomizer(
        UserRepository userRepository) {
    return context -> {
        // Only customize access tokens
        if (!OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
            return;
        }

        Authentication principal = context.getPrincipal();
        String username = principal.getName();

        // Load additional user data from DB
        User user = userRepository.findByUsername(username)
            .orElse(null);

        if (user != null) {
            // Add tenant to token
            context.getClaims()
                .claim("tenant_id", user.getTenantId());

            // Add user's roles (not the Spring authorities)
            context.getClaims()
                .claim("roles", user.getRoles());

            // Add user's department
            context.getClaims()
                .claim("department", user.getDepartment());
        }

        // Add grant type to token
        context.getClaims()
            .claim("grant_type",
                context.getAuthorizationGrantType().getValue());

        // Add client ID (for audit)
        context.getClaims()
            .claim("client_id",
                context.getRegisteredClient().getClientId());

        // Add requested scopes
        context.getClaims()
            .claim("approved_scopes",
                context.getAuthorizedScopes());
    };
}

@Bean
public OAuth2TokenCustomizer<JwtEncodingContext> idTokenCustomizer(
        UserRepository userRepository) {
    return context -> {
        // Only customize ID tokens (OIDC)
        if (!OidcParameterNames.ID_TOKEN.equals(
                context.getTokenType().getValue())) {
            return;
        }

        User user = userRepository.findByUsername(
            context.getPrincipal().getName()).orElse(null);

        if (user != null) {
            // Add OIDC standard claims
            context.getClaims()
                .claim(StandardClaimNames.EMAIL, user.getEmail())
                .claim(StandardClaimNames.EMAIL_VERIFIED, user.isEmailVerified())
                .claim(StandardClaimNames.GIVEN_NAME, user.getFirstName())
                .claim(StandardClaimNames.FAMILY_NAME, user.getLastName())
                .claim(StandardClaimNames.PICTURE, user.getAvatarUrl());
        }
    };
}
```

---

### Example 3 — Multiple Clients with Different Settings

```java
@Bean
public RegisteredClientRepository registeredClientRepository(
        PasswordEncoder encoder) {

    // ── Web Application (Authorization Code + PKCE) ──────────────
    RegisteredClient webApp = RegisteredClient
        .withId("web-app-id")
        .clientId("web-app")
        .clientSecret(encoder.encode("web-secret"))
        .clientAuthenticationMethod(
            ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
        .authorizationGrantType(
            AuthorizationGrantType.AUTHORIZATION_CODE)
        .authorizationGrantType(
            AuthorizationGrantType.REFRESH_TOKEN)
        .redirectUri("https://app.example.com/login/oauth2/code/my-auth")
        .scope(OidcScopes.OPENID).scope(OidcScopes.PROFILE)
        .scope(OidcScopes.EMAIL).scope("read:orders")
        .clientSettings(ClientSettings.builder()
            .requireProofKey(true)
            .requireAuthorizationConsent(true)
            .build())
        .tokenSettings(TokenSettings.builder()
            .accessTokenTimeToLive(Duration.ofMinutes(15))
            .refreshTokenTimeToLive(Duration.ofDays(30))
            .reuseRefreshTokens(false)
            .build())
        .build();

    // ── Public SPA (no secret, PKCE required) ────────────────────
    RegisteredClient spa = RegisteredClient
        .withId("spa-id")
        .clientId("spa-client")
        // NO clientSecret — public client
        .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
        .authorizationGrantType(
            AuthorizationGrantType.AUTHORIZATION_CODE)
        .redirectUri("https://spa.example.com/callback")
        .scope(OidcScopes.OPENID).scope(OidcScopes.PROFILE)
        .scope("read:data")
        .clientSettings(ClientSettings.builder()
            .requireProofKey(true)   // MANDATORY for public clients
            .requireAuthorizationConsent(false)
            .build())
        .tokenSettings(TokenSettings.builder()
            .accessTokenTimeToLive(Duration.ofMinutes(5))
            // No refresh token for public SPA (security consideration)
            .build())
        .build();

    // ── Backend Service (Client Credentials) ─────────────────────
    RegisteredClient serviceClient = RegisteredClient
        .withId("service-id")
        .clientId("order-service")
        .clientSecret(encoder.encode("service-secret"))
        .clientAuthenticationMethod(
            ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
        .authorizationGrantType(
            AuthorizationGrantType.CLIENT_CREDENTIALS)
        .scope("inventory:read")
        .scope("inventory:write")
        .tokenSettings(TokenSettings.builder()
            .accessTokenTimeToLive(Duration.ofHours(1))
            // No refresh token for CC (just re-authenticate)
            .build())
        .build();

    return new InMemoryRegisteredClientRepository(
        webApp, spa, serviceClient);
}
```

---

### Example 4 — Custom Grant Type (Token Exchange RFC 8693)

```java
// Extending Spring Authorization Server with a custom grant type
// Example: Token Exchange (RFC 8693)

@Component
public class TokenExchangeAuthenticationConverter
        implements AuthenticationConverter {

    @Override
    public Authentication convert(HttpServletRequest request) {
        String grantType = request.getParameter(
            OAuth2ParameterNames.GRANT_TYPE);
        if (!"urn:ietf:params:oauth:grant-type:token-exchange".equals(
                grantType)) {
            return null;
        }

        // Extract token exchange parameters
        String subjectToken = request.getParameter("subject_token");
        String subjectTokenType = request.getParameter("subject_token_type");
        String audience = request.getParameter("audience");

        // Build custom authentication token
        return new TokenExchangeAuthenticationToken(
            subjectToken, subjectTokenType, audience,
            extractClientAuthentication(request));
    }
}

@Component
public class TokenExchangeAuthenticationProvider
        implements AuthenticationProvider {

    @Override
    public Authentication authenticate(Authentication authentication) {
        TokenExchangeAuthenticationToken exchange =
            (TokenExchangeAuthenticationToken) authentication;

        // Validate the subject token (e.g., external JWT)
        // Issue a new token for the target service
        // ...

        return new OAuth2AccessTokenAuthenticationToken(
            registeredClient, clientPrincipal, accessToken);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return TokenExchangeAuthenticationToken.class
            .isAssignableFrom(authentication);
    }
}

// Register custom grant type:
http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
    .tokenEndpoint(tokenEndpoint -> tokenEndpoint
        .authenticationProviders(providers -> {
            providers.add(tokenExchangeProvider);
        })
    );
```

---

### Example 5 — Securing the Authorization Server Itself

```java
@Configuration
public class AuthServerSecurity {

    // The Authorization Server needs its OWN security:
    // 1. Authenticate users (for authorization endpoint)
    // 2. Protect admin endpoints (e.g., token revocation for admins)
    // 3. Client authentication (for token endpoint — handled internally)

    @Bean
    @Order(2)  // After auth server chain (@Order(1))
    public SecurityFilterChain appFilterChain(
            HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                // Allow OAuth2 discovery endpoints publicly
                .requestMatchers(
                    "/.well-known/openid-configuration",
                    "/.well-known/jwks.json",
                    "/oauth2/jwks"
                ).permitAll()

                // Admin endpoints require admin role
                .requestMatchers("/admin/**").hasRole("ADMIN")

                // All other endpoints require authentication
                .anyRequest().authenticated()
            )
            // Users authenticate via form login to use OAuth2 flows
            .formLogin(form -> form
                .loginPage("/login")
                .permitAll()
            )
            // For token introspection endpoint (protected by client auth):
            // Spring Authorization Server handles /oauth2/introspect internally
            .csrf(csrf -> csrf
                .ignoringRequestMatchers(
                    "/oauth2/token",
                    "/oauth2/revoke",
                    "/oauth2/introspect"
                )
                // These endpoints use client auth, not CSRF tokens
            );

        return http.build();
    }
}
```

---

### Example 6 — Incorrect Authorization Server Configurations

```java
// ❌ WRONG 1 — In-memory stores in production
@Bean
public OAuth2AuthorizationService authorizationService() {
    return new InMemoryOAuth2AuthorizationService();
    // Authorizations lost on restart/crash
    // No cluster support → tokens on Node 1 can't be introspected by Node 2
    // Memory leak: no automatic cleanup of expired authorizations
}
// ✓ CORRECT: JdbcOAuth2AuthorizationService

// ❌ WRONG 2 — In-memory JWK source in production
@Bean
public JWKSource<SecurityContext> jwkSource() {
    KeyPair keyPair = generateRsaKey();  // new key on every restart!
    // All JWTs issued before restart become invalid
    // Different cluster nodes have different keys → verification fails cross-node
    return new ImmutableJWKSet<>(new JWKSet(buildRsaKey(keyPair)));
}
// ✓ CORRECT: Load keys from external store (Vault, KMS, encrypted DB)

// ❌ WRONG 3 — Missing issuer URI
@Bean
public AuthorizationServerSettings settings() {
    return AuthorizationServerSettings.builder()
        // Missing: .issuer("https://auth.example.com")
        .build();
    // iss claim in JWTs will be wrong
    // OIDC discovery endpoint returns wrong configuration
    // Resource Servers that validate iss claim will reject ALL tokens!
}

// ❌ WRONG 4 — Wildcard redirect URI
RegisteredClient.withId("id")
    .clientId("my-client")
    .redirectUri("https://app.example.com/*")  // WILDCARDS NOT ALLOWED
    // OAuth 2.1: redirect URIs must be exact matches
    // Spring Authorization Server rejects wildcard redirect URIs
    // Use multiple exact URIs instead:
    .redirectUri("https://app.example.com/callback1")
    .redirectUri("https://app.example.com/callback2")

// ❌ WRONG 5 — reuseRefreshTokens=true (default in some versions)
TokenSettings.builder()
    .reuseRefreshTokens(true)  // old default
    // Stolen refresh token remains valid until expiry
    // No detection of theft via token rotation
// ✓ CORRECT:
TokenSettings.builder()
    .reuseRefreshTokens(false)  // rotation enabled
    // Stolen token use detected: old token reuse = theft signal
```

---

## 3️⃣ Exam-Style Questions

---

**Q1 (MCQ):** Which Spring Authorization Server component stores the record of what was authorized (authorization code, access token, refresh token) for a specific user-client pair?

A. `RegisteredClientRepository`
B. `OAuth2AuthorizationService`
C. `OAuth2AuthorizationConsentService`
D. `OAuth2TokenGenerator`

**Answer: B — `OAuth2AuthorizationService`**
`OAuth2AuthorizationService` stores `OAuth2Authorization` objects which represent the complete record of an authorization: which client, which user, which tokens (code, access, refresh, id_token), which scopes, and associated attributes (state, code_challenge, nonce).

---

**Q2 (MCQ):** A client is configured with `requireProofKey(true)`. An authorization code request arrives WITHOUT a `code_challenge` parameter. What happens?

A. Authorization proceeds normally — PKCE is added automatically
B. The request is rejected with `invalid_request` error
C. A warning is logged but the request proceeds
D. The client is prompted to provide PKCE parameters

**Answer: B — Rejected with `invalid_request`**
When `requireProofKey(true)` is configured on the `RegisteredClient`, every authorization code request MUST include PKCE parameters (`code_challenge` and `code_challenge_method`). Requests without them are immediately rejected at the authorization endpoint with `invalid_request` error.

---

**Q3 (Select All That Apply):** Which are true about `OAuth2TokenCustomizer<JwtEncodingContext>`?

A. It can add custom claims to access token JWTs
B. It can modify the JWT header (algorithm, kid, etc.)
C. It runs after token signature is applied
D. It has access to the authenticated user's `Authentication` object
E. It can add claims to ID tokens as well as access tokens

**Answer: A, B, D, E**
C is false — the customizer runs BEFORE signing. `JwtEncodingContext` provides `getClaims()` (modify payload) and `getJwsHeader()` (modify header). The JWT is signed AFTER customization. If it ran after signing, modifications would invalidate the signature.

---

**Q4 (Scenario):**

```java
TokenSettings.builder()
    .reuseRefreshTokens(false)
    .refreshTokenTimeToLive(Duration.ofDays(30))
    .build()
```

Day 1: User authenticates. Receives `refresh_token_1` and `access_token_1`.
Day 2: `access_token_1` expires. Client sends `refresh_token_1` → receives `access_token_2` and `refresh_token_2`.
Day 3: Attacker uses stolen `refresh_token_1`. What happens?

**Answer:**
Day 3 — Attacker presents `refresh_token_1`:
1. `OAuth2RefreshTokenAuthenticationProvider` looks up `OAuth2Authorization` by `refresh_token_1`
2. `refresh_token_1` was already **invalidated** when `refresh_token_2` was issued (`reuseRefreshTokens=false`)
3. Token not found or marked invalid → `InvalidGrantException`
4. Response: `400 Bad Request` with `error=invalid_grant`

Additionally, Spring Authorization Server detects that a previously-used refresh token was presented — this is a **theft signal**. Spring Authorization Server can be configured to invalidate ALL tokens for this authorization (revoke the entire session) upon detecting refresh token reuse.

---

**Q5 (Component Responsibility):**

Match each component to its responsibility:

| Component | Responsibility |
|-----------|---------------|
| A. `RegisteredClientRepository` | ? |
| B. `OAuth2AuthorizationService` | ? |
| C. `OAuth2AuthorizationConsentService` | ? |
| D. `JWKSource` | ? |
| E. `OAuth2TokenGenerator` | ? |
| F. `AuthorizationServerSettings` | ? |

**Answers:**
- A → Stores OAuth2 client configurations (client_id, secret, grant types, redirect URIs)
- B → Stores active authorizations (codes, tokens, their metadata)
- C → Stores user consent decisions (which scopes approved for which client)
- D → Provides cryptographic keys for JWT signing/verification
- E → Generates token values (JWT access tokens, opaque refresh tokens, auth codes)
- F → Configures Auth Server settings (issuer URI, endpoint paths)

---

**Q6 (PKCE Validation):**

During token exchange, the client sends:
```
code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
```

The stored `code_challenge` (from the authorization request) was:
```
code_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
code_challenge_method = "S256"
```

Is this a valid PKCE exchange? Show the validation logic.

**Answer:** Validation:
```
BASE64URL(SHA256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"))
= BASE64URL(SHA256 hash bytes)
= "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
```

This matches the stored `code_challenge` → **VALID — token issued**.

If they didn't match (e.g., attacker intercepted code but doesn't know verifier), validation fails → `invalid_grant` error → token NOT issued.

---

**Q7 (Architecture):**

You're deploying Spring Authorization Server in a 3-node cluster. List the components that MUST be externalized (not in-memory) for the cluster to work correctly.

**Answer:**

**Must externalize:**

1. **`RegisteredClientRepository`** → Use `JdbcRegisteredClientRepository`
   - All nodes must see the same client registrations

2. **`OAuth2AuthorizationService`** → Use `JdbcOAuth2AuthorizationService`
   - Authorization codes, tokens must be accessible from all nodes
   - Token validation fails if token only exists in one node's memory

3. **`OAuth2AuthorizationConsentService`** → Use `JdbcOAuth2AuthorizationConsentService`
   - Consent decisions must be shared

4. **`JWKSource`** → Use persistent key store (DB, Vault, KMS)
   - SAME keys on all nodes (different keys = tokens from Node 1 can't be verified by Node 2)
   - Keys must survive restarts

5. **HTTP Session storage** → Use Spring Session (Redis/JDBC)
   - Authorization requests stored in session during auth flow
   - Must be accessible from any node (if load balancer routes differently)

**Can stay in-memory:**
- `OAuth2TokenGenerator` — stateless, identical on all nodes
- `AuthorizationServerSettings` — configuration, same value on all nodes

---

**Q8 (Token Customizer):**

```java
@Bean
public OAuth2TokenCustomizer<JwtEncodingContext> customizer() {
    return context -> {
        context.getClaims().claim("env", "production");
    };
}
```

This customizer runs for ALL token types (access token, refresh token, id_token). What is the actual behavior for each?

**Answer:**

- **Access Token (JWT):** `env: "production"` claim added ✅
- **Refresh Token:** Refresh tokens are typically **opaque** (not JWT) in Spring Authorization Server. `JwtEncodingContext` only applies to JWT tokens. Refresh token is NOT a JWT by default → customizer does NOT run for refresh tokens ✅
- **ID Token (OIDC):** `env: "production"` claim added ✅ (id_token IS always JWT)

**Check in customizer if needed:**
```java
if (context.getTokenType().equals(OAuth2TokenType.ACCESS_TOKEN)) {
    // Only for access tokens
}
if (context.getTokenType().getValue().equals(OidcParameterNames.ID_TOKEN)) {
    // Only for ID tokens
}
```

---

## 4️⃣ Trick Analysis

---

**Trick 1 — `@Order(1)` for Auth Server Chain Is Mandatory**

```java
// Spring Authorization Server adds its filter chain at @Order(Ordered.LOWEST_PRECEDENCE)
// by default — this means it matches LAST

// Your application's SecurityFilterChain MUST be @Order(2) or higher number
// Auth server chain MUST be @Order(1)

// Typical setup:
@Bean @Order(1)
public SecurityFilterChain authServerChain(HttpSecurity http) { ... }
// Handles: /oauth2/authorize, /oauth2/token, /.well-known/*, /userinfo

@Bean @Order(2)
public SecurityFilterChain appChain(HttpSecurity http) { ... }
// Handles: everything else (login form, protected resources)

// If orders are reversed:
// App chain catches /oauth2/authorize first
// Redirects to /login → infinite loop
// Auth Server endpoints never reached
```

---

**Trick 2 — `applyDefaultSecurity()` vs Manual Configuration**

```java
// Quick setup:
OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
// Applies: all protocol endpoint filters with default settings
// Good for: getting started, development

// Full control:
http.apply(new OAuth2AuthorizationServerConfigurer())
    .authorizationEndpoint(auth -> auth
        .authorizationRequestConverter(customConverter)
        .consentPage("/custom-consent")
    )
    .tokenEndpoint(token -> token
        .accessTokenRequestConverter(customConverter)
        .authenticationProviders(providers -> {
            providers.add(customProvider);
        })
    )
    .tokenIntrospectionEndpoint(introspect -> introspect
        .introspectionResponseHandler(customHandler)
    );
// Good for: production, custom grant types, custom flows
```

---

**Trick 3 — `OAuth2AuthorizationService` vs `OAuth2AuthorizedClientService`**

```
These are DIFFERENT classes for DIFFERENT roles:

OAuth2AuthorizationService (Spring Authorization Server):
     Used BY: Authorization Server
     Stores: Active authorizations (codes issued, tokens issued)
     Purpose: Track what has been authorized

OAuth2AuthorizedClientService (Spring Security OAuth2 Client):
     Used BY: OAuth2 Client applications
     Stores: Authorized clients (access tokens obtained BY the client)
     Purpose: Manage tokens obtained from external Auth Servers

EXAM TRAP: "Where does the Authorization Server store issued tokens?"
Answer: OAuth2AuthorizationService (server-side)

"Where does the client app store tokens it received?"
Answer: OAuth2AuthorizedClientService (client-side)
```

---

**Trick 4 — Redirect URI Exact Match (OAuth 2.1)**

```
OAuth 2.0 (lenient):
     Some implementations allowed partial matching or wildcards
     Registered: https://app.example.com/callback
     Request:    https://app.example.com/callback?extra=param → accepted by some

OAuth 2.1 + Spring Authorization Server (strict):
     Exact match ONLY
     Registered: https://app.example.com/callback
     Request:    https://app.example.com/callback?extra=param → REJECTED
     Request:    https://app.example.com/callback/ (trailing slash) → REJECTED
     Request:    http://app.example.com/callback (HTTP not HTTPS) → REJECTED

This breaks some legacy clients that added query parameters to redirect URIs
Solution: Register exact URIs used in actual requests
```

---

**Trick 5 — JWK Set Published vs JWK Used for Signing**

```
/.well-known/jwks.json publishes:
     ALL keys in the JWK set (public keys only — private keys NEVER exposed)
     Including keys no longer used for signing (for verification of old tokens)

Signing uses:
     The SELECTED key from JWKSource.get()
     By default: first key in the set

Key rotation:
     Add new key → new key used for signing
     Old key still in JWK set → old tokens still verifiable
     After all old tokens expire → remove old key from JWK set

EXAM TRAP: "Does Spring Authorization Server expose private keys at /.well-known/jwks.json?"
Answer: NEVER. Only public key components (n, e for RSA) are included.
        Private key (d, p, q, dp, dq, qi for RSA) are NEVER published.
```

---

**Trick 6 — Client Credentials Grant Has No `sub` (User) Context**

```
Authorization Code Grant:
     User authenticates → token contains user's sub, email, roles
     context.getPrincipal() = UsernamePasswordAuthenticationToken (real user)

Client Credentials Grant:
     NO user involved
     context.getPrincipal() = OAuth2ClientAuthenticationToken (the CLIENT itself)
     sub = client_id (not a user ID)
     No user email, roles, etc.

OAuth2TokenCustomizer trap:
     context.getPrincipal().getName()
          Authorization Code: "alice" (username)
          Client Credentials: "order-service" (client_id)

     context.getClaims().claim("user_email",
         extractEmailFromPrincipal(context.getPrincipal()))
     → NPE or ClassCastException for client credentials grant!

Always check grant type in customizer:
     if (AuthorizationGrantType.CLIENT_CREDENTIALS
             .equals(context.getAuthorizationGrantType())) {
         // No user context available
         return;
     }
```

---

**Trick 7 — Consent vs. Authentication — Two Different Redirects**

```
Authorization code flow with consent:

1. User NOT authenticated:
     → Redirect to: /login
     → User logs in
     → Return to: /oauth2/authorize (original request)

2. User IS authenticated but NO consent given:
     → Redirect to: /oauth2/consent (consent page)
     → User approves/denies scopes
     → POST /oauth2/authorize (with approved scopes)
     → Authorization code issued
     → Redirect to: redirect_uri?code=...

3. User IS authenticated AND consent previously given:
     → No redirect for consent
     → Authorization code issued immediately
     → Redirect to: redirect_uri?code=...

Common mistake: customizing /login intercept but not /oauth2/consent
     → Custom login page works
     → Consent page is Spring default (ugly, not branded)
     → Need to configure custom consent page too
```

---

## 5️⃣ Summary Sheet

---

### Spring Authorization Server Architecture Diagram

```
                    Spring Authorization Server
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│  Client          /.well-known/openid-configuration              │
│  Registration   ──────────────────────────────────►  Discovery  │
│  Repository                                                     │
│      │           /.well-known/jwks.json                         │
│      │          ──────────────────────────────────►  JWK Set    │
│      │                                                    ↑     │
│      │           /oauth2/authorize                    JWKSource │
│      ├──────────────────────────────────────────► Auth Endpoint │
│      │           (user auth + consent)                          │
│      │                                                          │
│  OAuth2          /oauth2/token                                  │
│  Authorization  ──────────────────────────────────► Token       │
│  Service             (code exchange, CC, refresh)   Endpoint    │
│      │                                                 │        │
│      │                                           Token Generator│
│  Consent         /oauth2/introspect              Token Customizer│
│  Service        ──────────────────────────────────► Introspect  │
│                                                                 │
│                  /oauth2/revoke                                  │
│                 ──────────────────────────────────► Revoke      │
│                                                                 │
│                  /userinfo (OIDC)                               │
│                 ──────────────────────────────────► UserInfo    │
└─────────────────────────────────────────────────────────────────┘
```

---

### RegisteredClient Key Settings

| Setting | Options | Recommended |
|---------|---------|-------------|
| `clientAuthenticationMethod` | `CLIENT_SECRET_BASIC`, `PRIVATE_KEY_JWT`, `NONE` | `CLIENT_SECRET_BASIC` (confidential) / `NONE` (public) |
| `requireProofKey` | `true` / `false` | `true` (OAuth 2.1 compliance) |
| `requireAuthorizationConsent` | `true` / `false` | `true` (user control) |
| `accessTokenFormat` | `SELF_CONTAINED` (JWT), `REFERENCE` (opaque) | `SELF_CONTAINED` for APIs |
| `reuseRefreshTokens` | `true` / `false` | `false` (rotation = theft detection) |

---

### Token Types Generated by Auth Server

| Token | Format | Signed By | For | Typical TTL |
|-------|--------|-----------|-----|-------------|
| Access Token | JWT (default) or opaque | Auth Server private key | Resource Server | 15-60 min |
| Refresh Token | Opaque | N/A (stored in DB) | Client | Days-Months |
| ID Token | JWT (always) | Auth Server private key | Client | Same as access |
| Auth Code | Opaque | N/A | One-time code exchange | < 5 min |

---

### Storage Requirements for Production

| Component | Dev | Production |
|-----------|-----|-----------|
| `RegisteredClientRepository` | `InMemory` | `Jdbc` |
| `OAuth2AuthorizationService` | `InMemory` | `Jdbc` |
| `OAuth2AuthorizationConsentService` | `InMemory` | `Jdbc` |
| `JWKSource` | Generated (in-memory) | External (Vault/KMS/DB) |
| HTTP Session | In-memory | Spring Session (Redis/JDBC) |

---

### Common Interview One-Liners

- **Spring Authorization Server** is a separate project from Spring Security — implements OAuth 2.1 and OIDC
- **`RegisteredClient`** is the server-side client config — `ClientRegistration` is the client-side consumer config
- **`OAuth2AuthorizationService`** stores authorizations (tokens); **`OAuth2AuthorizedClientService`** (Spring Security) stores obtained tokens
- **In-memory stores** are development-only — `JdbcOAuth2AuthorizationService` required for production/clustering
- **`reuseRefreshTokens(false)`** enables rotation — stolen token reuse detected and all tokens invalidated
- **`JWKSource`** must be persistent across restarts and shared across cluster nodes
- **Redirect URIs** must be EXACT matches — no wildcards, no trailing slashes (OAuth 2.1 strict)
- **`OAuth2TokenCustomizer<JwtEncodingContext>`** runs BEFORE signing — modifies claims in JWT
- **Client Credentials grant** has NO user context — `sub` = client_id, not a user
- **Auth Server chain must be `@Order(1)`** — lower number = higher priority — app chain at `@Order(2)`

---
