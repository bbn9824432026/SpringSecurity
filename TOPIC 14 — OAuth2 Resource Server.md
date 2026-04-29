# TOPIC 14 — OAuth2 Resource Server

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

---

## 1️⃣ Conceptual Explanation

---

### 14.1 What Is a Resource Server — The Architectural Role

A Resource Server is the component that **hosts and protects resources** (APIs, data) and **validates access tokens** on every request. It is the "backend API" in the OAuth2 ecosystem.

```
OAuth2 Ecosystem — Resource Server's Position:

Client (SPA/Mobile)          Resource Server (Your Spring Boot API)
     │                                    │
     │ 1. Get access token               │
     │    (via Auth Server)               │
     │                                    │
     │ 2. GET /api/orders                 │
     │    Authorization: Bearer JWT_TOKEN │
     │───────────────────────────────────►│
     │                                    │ 3. Validate token
     │                                    │    (signature, expiry, audience)
     │                                    │ 4. Extract claims → authorities
     │◄───────────────────────────────────│
     │ 5. Return protected data           │

Key responsibilities of Resource Server:
     ├── Extract Bearer token from Authorization header
     ├── Validate token (JWT: locally; Opaque: introspection)
     ├── Map token claims → Spring Security Authentication
     ├── Enforce access control (authorities from token)
     └── Return WWW-Authenticate on failure (RFC 6750)
```

**Resource Server vs OAuth2 Login Client:**

```
OAuth2 Login (Topic 13):
     Role: OAuth2 CLIENT
     Purpose: Authenticate USERS via Authorization Server
     Flow: Authorization Code → get tokens → create session
     Incoming: No Bearer token (user session)
     State: Stateful (session-based)

OAuth2 Resource Server (Topic 14):
     Role: RESOURCE SERVER
     Purpose: Protect APIs, validate tokens from clients
     Flow: Receive token → validate → serve resource
     Incoming: Bearer token in Authorization header
     State: Stateless (no session)
```

---

### 14.2 BearerTokenAuthenticationFilter — Complete Internal Architecture

`BearerTokenAuthenticationFilter` is the core filter for Resource Server functionality. It extends `OncePerRequestFilter`.

**Position in filter chain:** Between `BasicAuthenticationFilter` and `RequestCacheAwareFilter` (approximately order 1000).

```java
public class BearerTokenAuthenticationFilter extends OncePerRequestFilter {

    private final AuthenticationManagerResolver<HttpServletRequest>
        authenticationManagerResolver;
    private BearerTokenResolver bearerTokenResolver =
        new DefaultBearerTokenResolver();
    private AuthenticationEntryPoint authenticationEntryPoint =
        new BearerTokenAuthenticationEntryPoint();
    private AuthenticationFailureHandler authenticationFailureHandler =
        new BearerTokenAuthenticationFailureHandler();

    @Override
    protected void doFilterInternal(HttpServletRequest request,
            HttpServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        // Step 1: Extract Bearer token from request
        String token;
        try {
            token = this.bearerTokenResolver.resolve(request);
        } catch (OAuth2AuthenticationException invalid) {
            // Malformed token in header → 401
            this.authenticationEntryPoint.commence(
                request, response, invalid);
            return;
        }

        if (token == null) {
            // No Bearer token → not a resource server request
            // Pass through — AnonymousAuthenticationFilter sets anonymous token
            chain.doFilter(request, response);
            return;
        }

        // Step 2: Check if already authenticated (avoid re-processing)
        if (authenticationIsRequired(token)) {

            // Step 3: Build unauthenticated token
            BearerTokenAuthenticationToken authRequest =
                new BearerTokenAuthenticationToken(token);
            authRequest.setDetails(
                this.authenticationDetailsSource.buildDetails(request));

            try {
                // Step 4: Authenticate via AuthenticationManager
                // (JwtAuthenticationProvider or OpaqueTokenAuthenticationProvider)
                AuthenticationManager authenticationManager =
                    this.authenticationManagerResolver.resolve(request);

                Authentication authenticationResult =
                    authenticationManager.authenticate(authRequest);

                // Step 5: Success — store in SecurityContext
                SecurityContext context =
                    this.securityContextHolderStrategy.createEmptyContext();
                context.setAuthentication(authenticationResult);
                this.securityContextHolderStrategy.setContext(context);

                this.securityContextRepository.saveContext(
                    context, request, response);

                chain.doFilter(request, response);

            } catch (AuthenticationException failed) {
                // Step 6: Failure — clear context, send 401
                this.securityContextHolderStrategy.clearContext();
                this.authenticationFailureHandler
                    .onAuthenticationFailure(request, response, failed);
            }
        } else {
            chain.doFilter(request, response);
        }
    }

    private boolean authenticationIsRequired(String token) {
        Authentication existingAuth =
            this.securityContextHolderStrategy
                .getContext().getAuthentication();
        if (existingAuth == null || !existingAuth.isAuthenticated()) {
            return true;  // no existing auth → authenticate
        }
        // Already authenticated with same token?
        if (existingAuth instanceof AbstractOAuth2TokenAuthenticationToken<?> oauthToken) {
            // Re-authenticate if token value changed
            return !token.equals(oauthToken.getToken().getTokenValue());
        }
        return false;
    }
}
```

---

### 14.3 DefaultBearerTokenResolver — Token Extraction

```java
public final class DefaultBearerTokenResolver implements BearerTokenResolver {

    private static final Pattern AUTHORIZATION_PATTERN =
        Pattern.compile("^Bearer (?<token>[a-zA-Z0-9-._~+/]+=*)$",
            Pattern.CASE_INSENSITIVE);

    // Configuration flags:
    private boolean allowFormEncodedBodyParameter = false;
    // Allow token in: POST body as "access_token" parameter
    // RFC 6750 allows this but it's less secure

    private boolean allowUriQueryParameter = false;
    // Allow token in: URL query string ?access_token=TOKEN
    // RFC 6750 allows but STRONGLY DISCOURAGED (URL in logs/history)
    // OAuth 2.1 PROHIBITS this entirely!

    @Override
    public String resolve(HttpServletRequest request) {
        final String authorizationHeaderToken =
            resolveFromAuthorizationHeader(request);

        final String parameterToken = isParameterTokenSupportedForRequest(request)
            ? resolveFromRequestParameters(request)
            : null;

        if (authorizationHeaderToken != null) {
            if (parameterToken != null) {
                // Token in BOTH places → ambiguous → error
                BearerTokenError error = new BearerTokenError(
                    BearerTokenErrorCodes.INVALID_REQUEST, ...);
                throw new OAuth2AuthenticationException(error);
            }
            return authorizationHeaderToken;
        }
        return parameterToken;  // may be null
    }

    private String resolveFromAuthorizationHeader(HttpServletRequest request) {
        String authorization = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (StringUtils.startsWithIgnoreCase(authorization, "bearer")) {
            Matcher matcher = AUTHORIZATION_PATTERN.matcher(authorization);
            if (!matcher.matches()) {
                // "Authorization: Bearer" present but malformed
                BearerTokenError error = ...INVALID_TOKEN...;
                throw new OAuth2AuthenticationException(error);
            }
            return matcher.group("token");
        }
        return null;
    }
}
```

**Token location priority:**

```
1. Authorization: Bearer {token}  ← RECOMMENDED (header)
2. POST body: access_token={token} ← Allowed if configured
3. URL query: ?access_token={token} ← Allowed if configured, PROHIBITED in OAuth 2.1

If token appears in multiple places → InvalidRequest (400)
```

---

### 14.4 JWT Authentication — JwtAuthenticationProvider

When the Resource Server is configured for JWT, `JwtAuthenticationProvider` handles token validation:

```java
public final class JwtAuthenticationProvider
        implements AuthenticationProvider {

    private final JwtDecoder jwtDecoder;
    private Converter<Jwt, ? extends AbstractAuthenticationToken>
        jwtAuthenticationConverter =
            new JwtAuthenticationConverter();  // default

    @Override
    public Authentication authenticate(Authentication authentication)
            throws AuthenticationException {

        BearerTokenAuthenticationToken bearer =
            (BearerTokenAuthenticationToken) authentication;

        // Step 1: Decode and validate JWT
        Jwt jwt;
        try {
            jwt = this.jwtDecoder.decode(bearer.getToken());
            // Validates:
            // - Signature (RS256/HS256/etc.)
            // - exp (not expired)
            // - iss (issuer — if configured)
            // - nbf (not before — if present)
        } catch (BadJwtException failed) {
            // Invalid JWT (signature, expiry, etc.)
            throw new InvalidBearerTokenException(failed.getMessage(), failed);
        } catch (JwtException failed) {
            throw new AuthenticationServiceException(failed.getMessage(), failed);
        }

        // Step 2: Convert JWT → AbstractAuthenticationToken
        // (extracts claims, maps to GrantedAuthority)
        AbstractAuthenticationToken token =
            this.jwtAuthenticationConverter.convert(jwt);

        token.setDetails(bearer.getDetails());

        return token;  // JwtAuthenticationToken with authorities
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return BearerTokenAuthenticationToken.class
            .isAssignableFrom(authentication);
    }
}
```

---

### 14.5 NimbusJwtDecoder — Deep Internal Architecture

`NimbusJwtDecoder` is the standard JWT decoder in Spring Security, backed by the **Nimbus JOSE + JWT** library.

**Three construction modes:**

```java
// Mode 1: JWK Set URI (production — asymmetric, key rotation supported)
NimbusJwtDecoder decoder = NimbusJwtDecoder
    .withJwkSetUri("https://auth.example.com/.well-known/jwks.json")
    .jwsAlgorithm(SignatureAlgorithm.RS256)  // optional, restricts algorithms
    .build();

// Mode 2: Public Key (asymmetric, static key)
NimbusJwtDecoder decoder = NimbusJwtDecoder
    .withPublicKey(rsaPublicKey)
    .signatureAlgorithm(SignatureAlgorithm.RS256)
    .build();

// Mode 3: Secret Key (symmetric — HMAC)
SecretKey secretKey = new SecretKeySpec(secret.getBytes(), "HmacSHA256");
NimbusJwtDecoder decoder = NimbusJwtDecoder
    .withSecretKey(secretKey)
    .macAlgorithm(MacAlgorithm.HS256)
    .build();

// Mode 4: Issuer URI (auto-discovers JWKS via OIDC discovery)
JwtDecoder decoder = JwtDecoders.fromIssuerLocation(
    "https://auth.example.com");
// Calls: https://auth.example.com/.well-known/openid-configuration
// Auto-discovers: jwks_uri, issuer
// Sets up: signature validation + issuer claim validation
```

**Internal decode process:**

```
decoder.decode(tokenString):

Step 1: Parse JWT structure
     Split by "." → header, payload, signature
     Base64URL decode each part
     header = {"alg": "RS256", "kid": "key-id-1", "typ": "JWT"}
     payload = {"sub": "alice", "iss": "...", "exp": 1699999, ...}

Step 2: Get JWS verifier
     Look up "kid" (key ID) in JWK cache:
          FOUND → use cached JWK
          NOT FOUND → fetch from jwks_uri (HTTP call to auth server)
                   → cache new JWKs
                   → retry verification

     Build RSASSAVerifier with the RSA public key

Step 3: Verify signature
     RSA-SHA256 verify: (header.payload, signature, publicKey)
     FAIL → BadJwtException("Failed to verify JWT signature")

Step 4: Build Jwt object
     Parse claims from payload
     Return Jwt{headers, claims, tokenValue, issuedAt, expiresAt, ...}

Step 5: Run validators
     JwtValidators.createDefaultWithIssuer(issuerUri) contains:
          ├── JwtTimestampValidator
          │       exp < now → JwtValidationException("JWT expired")
          │       nbf > now → JwtValidationException("JWT not yet valid")
          └── JwtIssuerValidator
                  iss != expected → JwtValidationException("Invalid issuer")
     Custom validators (audience, etc.) also run here

Step 6: Return validated Jwt or throw
```

**JWK Set caching:**

```
JWKSet cache behavior:
     First request with new "kid":
          HTTP GET to jwks_uri
          Parse JSON Web Key Set
          Cache keys (in-memory)
          Verify with appropriate key

     Subsequent requests with known "kid":
          Use cached key (no HTTP call)

     Unknown "kid" (key rotation):
          Cache miss
          Fresh HTTP GET to jwks_uri
          Cache updated
          Verify with new key

     Cache invalidation:
          JWK set re-fetched when unknown kid encountered
          Keys cached until application restart (no TTL by default)
          For production: consider configuring cache duration
```

---

### 14.6 JWT Claim Mapping to GrantedAuthority — JwtAuthenticationConverter

```java
public final class JwtAuthenticationConverter
        implements Converter<Jwt, AbstractAuthenticationToken> {

    private Converter<Jwt, Collection<GrantedAuthority>>
        jwtGrantedAuthoritiesConverter =
            new JwtGrantedAuthoritiesConverter();  // default

    private String principalClaimName = JwtClaimNames.SUB;  // default: "sub"

    @Override
    public final AbstractAuthenticationToken convert(Jwt jwt) {
        // Get authorities from JWT claims
        Collection<GrantedAuthority> authorities =
            this.jwtGrantedAuthoritiesConverter.convert(jwt);

        // Get principal name from configured claim
        String principalClaimValue =
            jwt.getClaimAsString(this.principalClaimName);

        return new JwtAuthenticationToken(jwt, authorities, principalClaimValue);
    }
}
```

**JwtGrantedAuthoritiesConverter — default scope extraction:**

```java
public final class JwtGrantedAuthoritiesConverter
        implements Converter<Jwt, Collection<GrantedAuthority>> {

    private String authoritiesClaimName = null;  // auto-detect
    private String authorityPrefix = "SCOPE_";  // default prefix

    @Override
    public Collection<GrantedAuthority> convert(Jwt jwt) {
        // Resolve claim name
        String claimName = resolveAuthoritiesClaimName(jwt);
        // resolveAuthoritiesClaimName():
        //   If authoritiesClaimName set → use it
        //   Else if jwt has "scope" claim → use "scope"
        //   Else if jwt has "scp" claim → use "scp"
        //   Else → return empty collection

        // Extract scope value(s)
        Collection<String> authorities = getAuthorities(jwt, claimName);
        // "scope" claim can be:
        //   String: "read write admin" → split by space
        //   Array:  ["read", "write", "admin"]

        // Map to GrantedAuthority with prefix
        return authorities.stream()
            .map(authority -> authorityPrefix + authority)
            .map(SimpleGrantedAuthority::new)
            .collect(Collectors.toList());
    }
}
```

**Default authority mapping example:**

```
JWT payload:
{
  "sub": "alice",
  "scope": "read:orders write:orders",
  "roles": ["ADMIN", "USER"]
}

Default JwtGrantedAuthoritiesConverter:
     scope claim → ["read:orders", "write:orders"]
     prefix "SCOPE_" → [SCOPE_read:orders, SCOPE_write:orders]

Result authorities: [SCOPE_read:orders, SCOPE_write:orders]

Custom configuration for roles claim:
     converter.setAuthoritiesClaimName("roles");
     converter.setAuthorityPrefix("ROLE_");
     → ["ADMIN", "USER"] → [ROLE_ADMIN, ROLE_USER]

Combining both:
     Custom converter returning ALL authorities:
     [SCOPE_read:orders, SCOPE_write:orders, ROLE_ADMIN, ROLE_USER]
```

---

### 14.7 JWT Validation — Custom Validators

```java
// OAuth2TokenValidator<Jwt> — the validation contract:
@FunctionalInterface
public interface OAuth2TokenValidator<T extends AbstractOAuth2Token> {
    OAuth2TokenValidatorResult validate(T token);
}

// Built-in validators:
JwtTimestampValidator    // validates exp and nbf
JwtIssuerValidator       // validates iss claim
JwtClaimValidator<T>     // validates any specific claim

// DelegatingOAuth2TokenValidator — compose multiple validators:
OAuth2TokenValidator<Jwt> validator =
    new DelegatingOAuth2TokenValidator<>(
        JwtValidators.createDefault(),  // timestamp + issuer
        audienceValidator(),
        customClaimValidator()
    );
```

**Custom audience validator:**

```java
@Bean
public JwtDecoder jwtDecoder() {
    NimbusJwtDecoder decoder = NimbusJwtDecoder
        .withJwkSetUri("https://auth.example.com/.well-known/jwks.json")
        .build();

    // Audience validator
    OAuth2TokenValidator<Jwt> audienceValidator =
        new JwtClaimValidator<List<String>>(
            JwtClaimNames.AUD,
            aud -> aud != null && aud.contains("my-api-service")
        );

    // Combine default validators + audience
    OAuth2TokenValidator<Jwt> validator =
        new DelegatingOAuth2TokenValidator<>(
            JwtValidators.createDefaultWithIssuer(
                "https://auth.example.com"),
            audienceValidator
        );

    decoder.setJwtValidator(validator);
    return decoder;
}
```

**Custom claim validator:**

```java
// Validate that "tenant" claim matches expected value
OAuth2TokenValidator<Jwt> tenantValidator = token -> {
    String tenant = token.getClaimAsString("tenant");
    if ("expected-tenant".equals(tenant)) {
        return OAuth2TokenValidatorResult.success();
    }
    OAuth2Error error = new OAuth2Error(
        "invalid_token",
        "Invalid tenant: " + tenant,
        "https://tools.ietf.org/html/rfc6750#section-3.1"
    );
    return OAuth2TokenValidatorResult.failure(error);
};
```

---

### 14.8 Opaque Token Introspection — Complete Architecture

For non-JWT (opaque) access tokens, the Resource Server cannot validate locally. It must call the Authorization Server's **introspection endpoint** (RFC 7662).

```
Opaque Token Introspection Flow:

Client → Resource Server:
     GET /api/orders
     Authorization: Bearer OPAQUE_TOKEN_XYZ123

Resource Server → Authorization Server:
     POST /oauth2/introspect
     Authorization: Basic {client_id:client_secret}
     Content-Type: application/x-www-form-urlencoded
     Body: token=OPAQUE_TOKEN_XYZ123

Authorization Server → Resource Server:
     {
       "active": true,
       "sub": "alice",
       "client_id": "my-client",
       "scope": "read write",
       "exp": 1699999999,
       "iat": 1699996399
     }
     OR if invalid:
     {"active": false}

Resource Server:
     active=true → authenticate as alice with scopes [read, write]
     active=false → 401 Unauthorized
```

**Spring Security's introspection implementation:**

```java
// OpaqueTokenAuthenticationProvider:
public class OpaqueTokenAuthenticationProvider
        implements AuthenticationProvider {

    private final OpaqueTokenIntrospector introspector;
    private OpaqueTokenAuthoritiesConverter authoritiesConverter =
        new JwtBearerTokenOpaqueTokenAuthoritiesConverter();

    @Override
    public Authentication authenticate(Authentication authentication) {
        BearerTokenAuthenticationToken bearer =
            (BearerTokenAuthenticationToken) authentication;

        // Step 1: Introspect the token
        OAuth2AuthenticatedPrincipal principal =
            this.introspector.introspect(bearer.getToken());
        // If active=false → throws OAuth2IntrospectionException

        // Step 2: Map claims to authorities
        Collection<GrantedAuthority> authorities =
            this.authoritiesConverter.convert(principal);

        // Step 3: Return authenticated token
        return new BearerTokenAuthentication(
            principal,
            bearer.getToken(),
            authorities);
    }
}
```

**NimbusOpaqueTokenIntrospector — HTTP call:**

```java
@Bean
public OpaqueTokenIntrospector introspector() {
    return new NimbusOpaqueTokenIntrospector(
        "https://auth.example.com/oauth2/introspect",
        "resource-server-client-id",
        "resource-server-client-secret"
    );
}
```

**Performance implication of introspection:**

```
Introspection = HTTP call to Auth Server on EVERY request
     High traffic → Auth Server becomes bottleneck
     Network latency × request volume = performance problem

Solutions:
     1. JWT (self-contained) → no introspection needed
     2. Introspection result caching:
          Cache (token → principal) with TTL = token expiry
          Reduces Auth Server calls dramatically
     3. Token Reference with JWT combination:
          Opaque token contains pointer to JWT
          First call → introspect, cache JWT
          Subsequent calls → validate JWT locally
```

---

### 14.9 BearerTokenAuthenticationEntryPoint — WWW-Authenticate Header

When JWT validation fails or no token is present:

```java
public final class BearerTokenAuthenticationEntryPoint
        implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException authException) throws IOException {

        HttpStatus status = HttpStatus.UNAUTHORIZED;
        Map<String, String> parameters = new LinkedHashMap<>();

        if (this.realmName != null) {
            parameters.put("realm", this.realmName);
        }

        if (authException instanceof OAuth2AuthenticationException oauth2Ex) {
            OAuth2Error error = oauth2Ex.getError();
            parameters.put("error", error.getErrorCode());
            if (StringUtils.hasLength(error.getDescription())) {
                parameters.put("error_description",
                    error.getDescription());
            }
            if (StringUtils.hasLength(error.getUri())) {
                parameters.put("error_uri", error.getUri());
            }

            // RFC 6750 error codes:
            // invalid_request → 400
            // invalid_token   → 401
            // insufficient_scope → 403
            if (error instanceof BearerTokenError bearerError) {
                status = bearerError.getHttpStatus();
            }
        }

        // Build WWW-Authenticate header per RFC 6750
        String wwwAuthenticate = computeWWWAuthenticateHeaderValue(parameters);
        // Example: Bearer realm="API", error="invalid_token",
        //          error_description="JWT expired"

        response.addHeader(HttpHeaders.WWW_AUTHENTICATE, wwwAuthenticate);
        response.setStatus(status.value());
    }
}
```

**WWW-Authenticate examples:**

```
No token (anonymous request):
     HTTP/1.1 401 Unauthorized
     WWW-Authenticate: Bearer realm="API"

Expired JWT:
     HTTP/1.1 401 Unauthorized
     WWW-Authenticate: Bearer realm="API",
          error="invalid_token",
          error_description="JWT expired at 2023-11-15T10:30:00Z"

Insufficient scope:
     HTTP/1.1 403 Forbidden
     WWW-Authenticate: Bearer realm="API",
          error="insufficient_scope",
          error_description="The token does not have required scope: write"
```

---

### 14.10 Resource Server + Form Login Combination

In some architectures, the same Spring Boot application serves both a web UI (form login) and an API (Bearer token). Spring Security supports this with multiple `SecurityFilterChain` beans:

```java
@Configuration
@EnableWebSecurity
public class HybridSecurityConfig {

    // Chain 1: API endpoints — Bearer token
    @Bean
    @Order(1)
    public SecurityFilterChain apiChain(HttpSecurity http) throws Exception {
        http
            .securityMatcher("/api/**")
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(Customizer.withDefaults()))
            .sessionManagement(s -> s
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .csrf(AbstractHttpConfigurer::disable)
            .authorizeHttpRequests(auth -> auth
                .anyRequest().authenticated()
            );
        return http.build();
    }

    // Chain 2: Web UI — Form login
    @Bean
    @Order(2)
    public SecurityFilterChain webChain(HttpSecurity http) throws Exception {
        http
            .formLogin(Customizer.withDefaults())
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/login", "/public/**").permitAll()
                .anyRequest().authenticated()
            );
        return http.build();
    }
}
```

**Why separate chains are necessary:**

```
Problem with single chain:
     BearerTokenAuthenticationFilter tries JWT validation
     FormLogin: no Bearer token → null → anonymous → redirect to /login
     
     But API clients expect 401, not redirect!
     And web clients expect form login redirect, not 401!

Solution with separate chains:
     Chain 1 (/api/**): JWT → stateless → 401 on failure
     Chain 2 (/**):     Form login → stateful → redirect on failure
     
     Each chain is completely independent in its auth mechanism
```

---

### 14.11 Multi-Tenancy — Dynamic Auth Server Discovery

In multi-tenant scenarios, different tenants use different Authorization Servers:

```java
// AuthenticationManagerResolver — per-request auth server selection
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http
        .oauth2ResourceServer(oauth2 -> oauth2
            // Resolve auth manager based on request context
            .authenticationManagerResolver(
                multiTenantAuthenticationManagerResolver())
        )
        .authorizeHttpRequests(auth -> auth
            .anyRequest().authenticated()
        );
    return http.build();
}

@Bean
public AuthenticationManagerResolver<HttpServletRequest>
        multiTenantAuthenticationManagerResolver() {

    // Cache of tenant → AuthenticationManager
    Map<String, AuthenticationManager> managers = new ConcurrentHashMap<>();

    return request -> {
        // Extract tenant from request (header, path, subdomain, etc.)
        String tenantId = request.getHeader("X-Tenant-ID");
        if (tenantId == null) {
            throw new IllegalArgumentException("Missing X-Tenant-ID header");
        }

        // Create/cache AuthenticationManager per tenant
        return managers.computeIfAbsent(tenantId, id -> {
            // Each tenant has their own Auth Server
            String issuerUri = "https://auth." + id + ".example.com";

            NimbusJwtDecoder decoder =
                JwtDecoders.fromIssuerLocation(issuerUri);

            JwtAuthenticationProvider provider =
                new JwtAuthenticationProvider(decoder);
            provider.setJwtAuthenticationConverter(
                jwtAuthenticationConverter());

            return new ProviderManager(provider);
        });
    };
}
```

---

### 14.12 Spring Security 5.x vs 6.x Resource Server Changes

| Aspect | Spring Security 5.x | Spring Security 6.x |
|--------|--------------------|--------------------|
| Config DSL | `.oauth2ResourceServer().jwt()` | `.oauth2ResourceServer(o -> o.jwt(...))` |
| JWK caching | Basic caching | Enhanced caching with metrics |
| Audience validation | Manual | `JwtDecoders.fromIssuerLocation` auto-validates |
| `BearerTokenError` | Same | Same |
| Token extraction | Header/form/query | Header/form/query (query deprecated) |
| Error response | RFC 6750 | RFC 6750 (enhanced) |
| `SecurityContextRepository` | `HttpSessionSecurityContextRepository` | `RequestAttributeSecurityContextRepository` (stateless by design) |

**Key 6.x change — `RequestAttributeSecurityContextRepository`:**

```
In 6.x, oauth2ResourceServer() automatically uses:
     RequestAttributeSecurityContextRepository
     (stores SecurityContext in request attribute, NOT session)

Why: Resource Server is stateless — no session should be created
     JWT validated on every request → session unnecessary

Result: No session created for API requests even with IF_REQUIRED policy
        Authentication lives only for current request
```

---

## 2️⃣ Code Examples

---

### Example 1 — Complete JWT Resource Server Configuration

```java
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class JwtResourceServerConfig {

    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
    private String issuerUri;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // ── Authorization ─────────────────────────────────────────
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/public/**").permitAll()
                .requestMatchers("/api/admin/**")
                    .hasRole("ADMIN")
                .requestMatchers("/api/orders/**")
                    .hasAuthority("SCOPE_read:orders")
                .anyRequest().authenticated()
            )
            // ── OAuth2 Resource Server ────────────────────────────────
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt
                    .decoder(jwtDecoder())
                    .jwtAuthenticationConverter(jwtAuthConverter())
                )
                // Custom entry point for 401 responses
                .authenticationEntryPoint(bearerTokenEntryPoint())
                // Custom 403 handler
                .accessDeniedHandler(bearerTokenAccessDeniedHandler())
            )
            // ── Stateless ─────────────────────────────────────────────
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            .csrf(AbstractHttpConfigurer::disable)
            .cors(cors -> cors
                .configurationSource(corsConfigurationSource())
            );

        return http.build();
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        // fromIssuerLocation: calls /.well-known/openid-configuration
        // Auto-configures: jwksUri, issuer validation
        NimbusJwtDecoder decoder =
            (NimbusJwtDecoder) JwtDecoders.fromIssuerLocation(issuerUri);

        // Add custom validators on top of defaults
        OAuth2TokenValidator<Jwt> withAudience =
            new DelegatingOAuth2TokenValidator<>(
                JwtValidators.createDefaultWithIssuer(issuerUri),
                audienceValidator()
            );
        decoder.setJwtValidator(withAudience);
        return decoder;
    }

    @Bean
    public JwtAuthenticationConverter jwtAuthConverter() {
        // Composite converter: extract BOTH scopes AND roles
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();

        converter.setJwtGrantedAuthoritiesConverter(jwt -> {
            List<GrantedAuthority> authorities = new ArrayList<>();

            // Extract scopes: "scope" → SCOPE_read, SCOPE_write
            JwtGrantedAuthoritiesConverter scopeConverter =
                new JwtGrantedAuthoritiesConverter();
            authorities.addAll(scopeConverter.convert(jwt));

            // Extract roles: "roles" → ROLE_ADMIN, ROLE_USER
            List<String> roles = jwt.getClaimAsStringList("roles");
            if (roles != null) {
                roles.stream()
                    .map(r -> new SimpleGrantedAuthority("ROLE_" + r))
                    .forEach(authorities::add);
            }

            return authorities;
        });

        // Use "email" as principal name instead of "sub"
        converter.setPrincipalClaimName("email");

        return converter;
    }

    @Bean
    public OAuth2TokenValidator<Jwt> audienceValidator() {
        return new JwtClaimValidator<List<String>>(
            JwtClaimNames.AUD,
            aud -> aud != null && aud.contains("my-api")
        );
    }
}
```

---

### Example 2 — Opaque Token Introspection

```yaml
spring:
  security:
    oauth2:
      resourceserver:
        opaquetoken:
          introspection-uri: https://auth.example.com/oauth2/introspect
          client-id: resource-server
          client-secret: ${INTROSPECTION_CLIENT_SECRET}
```

```java
@Configuration
@EnableWebSecurity
public class OpaqueTokenResourceServerConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .oauth2ResourceServer(oauth2 -> oauth2
                .opaqueToken(opaque -> opaque
                    .introspectionUri(
                        "https://auth.example.com/oauth2/introspect")
                    .introspectionClientCredentials(
                        "resource-server",
                        "secret")
                    // Custom introspector with caching:
                    .introspector(cachingIntrospector())
                )
            )
            .authorizeHttpRequests(auth -> auth
                .anyRequest().authenticated()
            )
            .sessionManagement(s -> s
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .csrf(AbstractHttpConfigurer::disable);

        return http.build();
    }

    @Bean
    public OpaqueTokenIntrospector cachingIntrospector() {
        // Base introspector
        NimbusOpaqueTokenIntrospector delegate =
            new NimbusOpaqueTokenIntrospector(
                "https://auth.example.com/oauth2/introspect",
                "resource-server", "secret");

        // Caching wrapper — avoids introspection call on every request
        return new CachingOpaqueTokenIntrospector(delegate,
            Caffeine.newBuilder()
                .expireAfterWrite(Duration.ofMinutes(5))
                .maximumSize(1000)
                .build());
    }
}

// Custom caching introspector:
public class CachingOpaqueTokenIntrospector
        implements OpaqueTokenIntrospector {

    private final OpaqueTokenIntrospector delegate;
    private final Cache<String, OAuth2AuthenticatedPrincipal> cache;

    @Override
    public OAuth2AuthenticatedPrincipal introspect(String token) {
        return cache.get(token, key -> delegate.introspect(key));
    }
}
```

---

### Example 3 — Custom JWT Converter with Local User Enrichment

```java
// Enrich JWT authentication with local database user data
@Component
public class EnrichingJwtConverter
        implements Converter<Jwt, AbstractAuthenticationToken> {

    private final UserRepository userRepository;
    private final JwtGrantedAuthoritiesConverter scopeConverter =
        new JwtGrantedAuthoritiesConverter();

    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        String email = jwt.getClaimAsString("email");

        // Load additional authorities from local DB
        List<GrantedAuthority> authorities = new ArrayList<>();

        // Add JWT scopes
        authorities.addAll(scopeConverter.convert(jwt));

        // Add local DB roles
        userRepository.findByEmail(email).ifPresent(user -> {
            user.getRoles().stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                .forEach(authorities::add);
        });

        return new JwtAuthenticationToken(jwt, authorities, email);
    }
}
```

---

### Example 4 — Accessing JWT Claims in Controller

```java
@RestController
@RequestMapping("/api")
public class OrderController {

    // Method 1: Via Authentication
    @GetMapping("/orders")
    public List<Order> getOrders(Authentication authentication) {
        JwtAuthenticationToken jwtAuth =
            (JwtAuthenticationToken) authentication;
        Jwt jwt = jwtAuth.getToken();

        String userId = jwt.getSubject();
        List<String> scopes = jwt.getClaimAsStringList("scope");
        String email = jwt.getClaimAsString("email");
        Instant expiry = jwt.getExpiresAt();

        return orderService.getOrdersForUser(userId);
    }

    // Method 2: @AuthenticationPrincipal Jwt
    @PostMapping("/orders")
    @PreAuthorize("hasAuthority('SCOPE_write:orders')")
    public Order createOrder(
            @RequestBody OrderRequest request,
            @AuthenticationPrincipal Jwt jwt) {

        String userId = jwt.getSubject();
        String tenantId = jwt.getClaimAsString("tenant");

        return orderService.createOrder(
            request, userId, tenantId);
    }

    // Method 3: Custom annotation
    @GetMapping("/profile")
    public UserProfile getProfile(
            @AuthenticationPrincipal(expression = "claims['email']")
            String email) {
        return userService.getProfileByEmail(email);
    }
}
```

---

### Example 5 — JWT Algorithm Restriction

```java
@Bean
public JwtDecoder jwtDecoder() {
    // Restrict to only RS256 — reject other algorithms
    // Prevents algorithm confusion attacks (e.g., none algorithm)
    NimbusJwtDecoder decoder = NimbusJwtDecoder
        .withJwkSetUri("https://auth.example.com/.well-known/jwks.json")
        .jwsAlgorithm(SignatureAlgorithm.RS256)  // ONLY RS256
        // .jwsAlgorithm(SignatureAlgorithm.RS384)  // OR add more
        .build();

    // Also add custom validator
    decoder.setJwtValidator(
        new DelegatingOAuth2TokenValidator<>(
            JwtValidators.createDefaultWithIssuer(
                "https://auth.example.com"),
            audienceValidator()
        )
    );

    return decoder;
}
```

---

### Example 6 — Incorrect Resource Server Configurations

```java
// ❌ WRONG 1 — No audience validation
@Bean
public JwtDecoder jwtDecoder() {
    return NimbusJwtDecoder
        .withJwkSetUri("https://auth.example.com/.well-known/jwks.json")
        .build();
    // Missing: audience validator
    // Token for "other-service" accepted by this service!
    // Cross-service token abuse vulnerability
}

// ❌ WRONG 2 — Creating session in stateless Resource Server
http
    .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()))
    // Missing: .sessionManagement(s -> s.sessionCreationPolicy(STATELESS))
    // Result: Sessions created for API clients (unexpected overhead)
    // But actually: 6.x oauth2ResourceServer uses RequestAttributeRepo by default
    // so sessions NOT created — just unnecessary config omission

// ❌ WRONG 3 — hasRole check for scope claim
http.authorizeHttpRequests(auth -> auth
    .requestMatchers("/api/read/**").hasRole("read")
    // "SCOPE_read" != "ROLE_read"
    // hasRole("read") checks for "ROLE_read"
    // JwtGrantedAuthoritiesConverter produces "SCOPE_read"
    // → Access always denied!
);
// ✓ CORRECT:
.requestMatchers("/api/read/**").hasAuthority("SCOPE_read")
// OR configure converter with:
// converter.setAuthorityPrefix("ROLE_")
// converter.setAuthoritiesClaimName("scope")
// Then: hasRole("read") works

// ❌ WRONG 4 — Using symmetric key in distributed system
@Bean
public JwtDecoder jwtDecoder() {
    return NimbusJwtDecoder
        .withSecretKey(new SecretKeySpec("shared-secret".getBytes(), "HS256"))
        .build();
    // HMAC: Auth Server AND Resource Server share same secret
    // If Resource Server is compromised → attacker can FORGE tokens!
    // Use asymmetric (RS256/ES256): only Auth Server needs private key
}

// ❌ WRONG 5 — No CSRF disable for stateless API
http
    .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()))
    .sessionManagement(s -> s.sessionCreationPolicy(STATELESS));
    // Missing: .csrf(AbstractHttpConfigurer::disable)
    // With STATELESS: HttpSessionCsrfTokenRepository cannot store token (no session)
    // All POST/PUT/DELETE requests fail with 403 (invalid CSRF token)
```

---

## 3️⃣ Exam-Style Questions

---

**Q1 (MCQ):** What is the default claim name used by `JwtGrantedAuthoritiesConverter` to extract authorities from a JWT?

A. `roles`
B. `authorities`
C. `scope` or `scp`
D. `permissions`

**Answer: C — `scope` or `scp`**
`JwtGrantedAuthoritiesConverter` first looks for `scope` claim, then `scp` claim (fallback). If neither exists, it returns an empty collection. The default authority prefix is `SCOPE_`. You must configure `setAuthoritiesClaimName("roles")` to use a different claim.

---

**Q2 (MCQ):** A JWT arrives with `exp` claim set to 30 seconds in the past. What does `NimbusJwtDecoder` do?

A. Accepts the token with a deprecation warning in logs
B. Throws `JwtValidationException` with message "JWT expired"
C. Calls the introspection endpoint to verify current validity
D. Accepts the token if the clock skew is within 60 seconds

**Answer: B — `JwtValidationException: JWT expired`**
`JwtTimestampValidator` (included in `JwtValidators.createDefault()`) validates `exp`. By default, there is 60 seconds of clock skew tolerance. If the token expired more than 60 seconds ago, `JwtValidationException` is thrown → converted to `InvalidBearerTokenException` → 401 response.

Actually, the default clock skew IS 60 seconds, so "30 seconds in the past" might actually pass. For exam purposes: `exp` in the past beyond clock skew tolerance → rejected with `JwtValidationException`.

---

**Q3 (Select All That Apply):** Which are true about opaque token introspection?

A. The Resource Server calls the Auth Server's introspection endpoint on every request
B. An introspection result of `{"active": false}` causes 401
C. Introspection is faster than JWT validation because no cryptographic operations needed
D. Caching introspection results reduces load on the Authorization Server
E. The Resource Server must present its own credentials when calling the introspection endpoint

**Answer: A, B, D, E**
C is false — introspection requires an HTTP call to the Auth Server on every request (without caching), which is SLOWER than JWT local validation (which only needs a public key and math). Introspection has higher latency due to network round-trip.

---

**Q4 (Code Prediction):**

```java
http.authorizeHttpRequests(auth -> auth
    .requestMatchers("/api/write/**").hasRole("write")
    .anyRequest().authenticated()
);

// JWT payload: {"scope": "read write", "sub": "alice"}
// JwtAuthenticationConverter with default settings
```

A request arrives at `POST /api/write/data` with a valid JWT. What is the response?

**Answer: 403 Forbidden**

Default `JwtGrantedAuthoritiesConverter`:
- Extracts `scope` claim → `["read", "write"]`
- Adds prefix `SCOPE_` → authorities = `[SCOPE_read, SCOPE_write]`

`hasRole("write")` checks for `ROLE_write` (adds `ROLE_` prefix).
`ROLE_write` is NOT in `[SCOPE_read, SCOPE_write]`.
→ `AccessDeniedException` → 403 Forbidden.

**Fix:** `.hasAuthority("SCOPE_write")` or configure converter with `setAuthorityPrefix("ROLE_")`.

---

**Q5 (Architecture Scenario):**

```java
http
    .securityMatcher("/api/**")
    .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()))
    .authorizeHttpRequests(auth -> auth
        .anyRequest().authenticated()
    );
```

An unauthenticated request arrives at `GET /api/orders` with no Authorization header. Trace the complete flow and response.

**Answer:**
```
1. SecurityContextHolderFilter: loads empty SecurityContext (no session for stateless)
2. BearerTokenAuthenticationFilter:
   - DefaultBearerTokenResolver.resolve(): no Authorization header → returns null
   - token == null → chain.doFilter() (passes through)
3. AnonymousAuthenticationFilter:
   - SecurityContext has no auth → sets AnonymousAuthenticationToken
4. ExceptionTranslationFilter: wraps rest in try-catch
5. AuthorizationFilter:
   - anyRequest().authenticated()
   - isAuthenticated() = false (anonymous) → AccessDeniedException
6. ExceptionTranslationFilter catches AccessDeniedException
   - isAnonymous(auth) = true
   - sendStartAuthentication()
   - requestCache.saveRequest() (NullRequestCache for stateless — no-op)
   - authenticationEntryPoint.commence()
   - BearerTokenAuthenticationEntryPoint:
     response.addHeader("WWW-Authenticate", "Bearer realm=\"API\"")
     response.setStatus(401)
Result: HTTP 401 Unauthorized
        WWW-Authenticate: Bearer realm="API"
```

---

**Q6 (JWT Claim Mapping):**

```java
JwtGrantedAuthoritiesConverter converter = new JwtGrantedAuthoritiesConverter();
converter.setAuthoritiesClaimName("permissions");
converter.setAuthorityPrefix("");  // no prefix

JwtAuthenticationConverter jwtConverter = new JwtAuthenticationConverter();
jwtConverter.setJwtGrantedAuthoritiesConverter(converter);
jwtConverter.setPrincipalClaimName("preferred_username");
```

JWT payload:
```json
{
  "sub": "user-123",
  "preferred_username": "alice@example.com",
  "permissions": ["ORDER_READ", "ORDER_WRITE", "ADMIN"]
}
```

What authorities and principal name does the resulting `JwtAuthenticationToken` have?

**Answer:**
- Authorities: `[ORDER_READ, ORDER_WRITE, ADMIN]` (no prefix, from `permissions` claim)
- Principal name: `"alice@example.com"` (from `preferred_username` claim)
- Note: `sub` is NOT used as principal name — `preferred_username` is configured

Access check examples:
- `hasAuthority("ORDER_READ")` → ✅ granted
- `hasRole("ADMIN")` → ❌ denied (checks `ROLE_ADMIN`, not `ADMIN`)
- `hasAuthority("ADMIN")` → ✅ granted

---

**Q7 (Security Vulnerability):**

```java
@Bean
public JwtDecoder jwtDecoder() {
    return NimbusJwtDecoder
        .withSecretKey(secretKey)
        .macAlgorithm(MacAlgorithm.HS256)
        .build();
}
```

In a microservices architecture with 5 Resource Server instances, each holds the same `secretKey`. What is the security vulnerability?

**Answer: Token forgery vulnerability.**

With HMAC (symmetric) keys, ANY party holding the secret can BOTH sign AND verify tokens. This means:
1. Each of the 5 Resource Server instances can **forge** valid tokens
2. A compromised Resource Server → attacker has `secretKey` → can create tokens with arbitrary claims (admin roles, any `sub`, etc.)
3. These forged tokens are valid on ALL other Resource Servers (same key)

**Correct approach:** Use asymmetric RS256/ES256:
- Authorization Server: holds private key (signs tokens)
- Resource Servers: hold ONLY public key (verify tokens only, cannot forge)
- Compromise of Resource Server → attacker gets public key only (useless for forgery)

---

**Q8 (Multi-Chain Scenario):**

```java
@Bean @Order(1)
public SecurityFilterChain apiChain(HttpSecurity http) throws Exception {
    http.securityMatcher("/api/**")
        .oauth2ResourceServer(o -> o.jwt(Customizer.withDefaults()))
        .authorizeHttpRequests(a -> a.anyRequest().authenticated());
    return http.build();
}

@Bean @Order(2)
public SecurityFilterChain webChain(HttpSecurity http) throws Exception {
    http.formLogin(Customizer.withDefaults())
        .authorizeHttpRequests(a -> a.anyRequest().authenticated());
    return http.build();
}
```

Request 1: `GET /api/data` with no token
Request 2: `GET /web/page` with no session

What is the response for each?

**Answer:**

**Request 1 — `GET /api/data` (matches Chain 1 `/api/**`):**
- `BearerTokenAuthenticationFilter`: no token → anonymous
- `AuthorizationFilter`: not authenticated → `AccessDeniedException`
- `ExceptionTranslationFilter`: anonymous → `BearerTokenAuthenticationEntryPoint`
- Response: **401 Unauthorized** with `WWW-Authenticate: Bearer` header

**Request 2 — `GET /web/page` (matches Chain 2 — no prefix):**
- No `BearerTokenAuthenticationFilter` in this chain
- `AuthorizationFilter`: not authenticated → `AccessDeniedException`
- `ExceptionTranslationFilter`: anonymous → `LoginUrlAuthenticationEntryPoint`
- Response: **302 redirect to `/login`**

This demonstrates the clean separation of concerns between the two chains.

---

## 4️⃣ Trick Analysis

---

**Trick 1 — `hasRole("scope")` vs `hasAuthority("SCOPE_scope")` — The Most Common Resource Server Bug**

```
Default JwtGrantedAuthoritiesConverter:
     scope claim "read" → SimpleGrantedAuthority("SCOPE_read")

hasRole("read") checks for: "ROLE_read"   ← WRONG!
hasAuthority("SCOPE_read") checks for: "SCOPE_read"  ← CORRECT!
hasAuthority("read") checks for: "read"  ← ALSO WRONG!

Two ways to fix:
     Option A: Use hasAuthority with "SCOPE_" prefix
          .hasAuthority("SCOPE_read")

     Option B: Configure converter with empty/ROLE_ prefix
          converter.setAuthorityPrefix("ROLE_");
          .hasRole("read")  // now checks ROLE_read which is stored

This is the #1 most reported "why doesn't my security work" in Spring Security OAuth2
```

---

**Trick 2 — JWT Validation Order Matters**

```
DelegatingOAuth2TokenValidator runs validators IN ORDER:

Correct order:
     1. JwtTimestampValidator (exp, nbf)
     2. JwtIssuerValidator (iss)
     3. Custom audience validator (aud)
     4. Custom claim validators

Why order matters for security:
     An expired token from the wrong issuer:
          Bad order: audience check first → passes (aud is correct)
                     then issuer check → fails (but already started processing)
          Good order: timestamp first → immediately rejects expired tokens
                      before any other processing

JwtValidators.createDefault() = JwtTimestampValidator + JwtIssuerValidator
JwtValidators.createDefaultWithIssuer(issuer) = same + issuer configured
```

---

**Trick 3 — JWK Refresh on Unknown `kid`**

```
JWT header: {"kid": "new-key-2024", "alg": "RS256"}

Resource Server JWK cache: {kid: "old-key-2023", ...}

Process:
     1. Look up "new-key-2024" → NOT IN CACHE
     2. Fetch https://auth.example.com/.well-known/jwks.json
     3. Parse: {"keys": [{kid: "new-key-2024", ...}, {kid: "old-key-2023", ...}]}
     4. Update cache with both keys
     5. Retry verification with "new-key-2024" → SUCCESS

This is AUTOMATIC key rotation handling!
No application restart needed when Auth Server rotates keys.

Attack: Sending tokens with random "kid" values
     → Resource Server fetches JWKS every time
     → Denial of Service on Auth Server!
     
Mitigation:
     Rate limit JWKS fetches
     Validate "kid" format before lookup
     NimbusJwtDecoder has built-in rate limiting in recent versions
```

---

**Trick 4 — Clock Skew in JWT Validation**

```
JwtTimestampValidator default clock skew: 60 seconds

Token expires at 12:00:00
Request arrives at 12:00:45 (45 seconds after expiry)
     45 < 60 (skew) → ACCEPTED ← might surprise teams

Request arrives at 12:01:10 (70 seconds after expiry)
     70 > 60 (skew) → REJECTED ← now expired

Configuring clock skew:
JwtTimestampValidator timestampValidator =
    new JwtTimestampValidator(Duration.ofSeconds(30));  // tighter skew

OAuth2TokenValidator<Jwt> validator =
    new DelegatingOAuth2TokenValidator<>(
        timestampValidator,
        new JwtIssuerValidator(issuerUri)
    );
decoder.setJwtValidator(validator);

Important for high-security scenarios:
     Payment processing → set skew to 0 (no tolerance)
     Regular APIs → 60s default is fine
```

---

**Trick 5 — `BearerTokenAuthenticationToken` vs `JwtAuthenticationToken`**

```
Before validation:
     BearerTokenAuthenticationToken(rawTokenString)
     → unauthenticated
     → just carries the raw token string

After JwtAuthenticationProvider validates:
     JwtAuthenticationToken(Jwt, authorities, principalName)
     → authenticated = true
     → carries the decoded Jwt object with claims
     → carries GrantedAuthorities from claims

In controller:
     Authentication auth = ...
     auth instanceof BearerTokenAuthenticationToken
          → Impossible (this is never the post-auth type)
     auth instanceof JwtAuthenticationToken
          → Correct for JWT resource server
     ((JwtAuthenticationToken) auth).getToken()
          → Gets the Jwt object with all claims
```

---

**Trick 6 — Opaque Token Introspection Response Mapping**

```
Introspection response:
{
  "active": true,
  "scope": "read write",
  "sub": "alice",
  "client_id": "my-client",
  "username": "alice@example.com",
  "token_type": "Bearer",
  "exp": 1699999999
}

Maps to OAuth2AuthenticatedPrincipal with attributes

Default authorities from introspection:
     scope "read write" → [SCOPE_read, SCOPE_write]
     Same as JWT scope handling

Principal name:
     Uses "sub" claim by default (not "username")
     Even though "username" is present in introspection response

Customizing:
@Bean
public OpaqueTokenIntrospector introspector() {
    NimbusOpaqueTokenIntrospector delegate = new NimbusOpaqueTokenIntrospector(...);
    return token -> {
        OAuth2AuthenticatedPrincipal principal = delegate.introspect(token);
        // Add custom authorities
        return new DefaultOAuth2AuthenticatedPrincipal(
            principal.getName(),
            principal.getAttributes(),
            customAuthorities(principal)
        );
    };
}
```

---

**Trick 7 — `@AuthenticationPrincipal Jwt` vs `@AuthenticationPrincipal OAuth2AuthenticatedPrincipal`**

```
JWT Resource Server:
     @AuthenticationPrincipal Jwt jwt
     → Gets the Jwt object directly
     → jwt.getSubject(), jwt.getClaim("email"), etc.

Opaque Token Resource Server:
     @AuthenticationPrincipal OAuth2AuthenticatedPrincipal principal
     → Gets the introspection response principal
     → principal.getName(), principal.getAttribute("sub"), etc.

WRONG combinations:
     JWT server: @AuthenticationPrincipal OAuth2AuthenticatedPrincipal
          → ClassCastException (Jwt != OAuth2AuthenticatedPrincipal)
     Opaque server: @AuthenticationPrincipal Jwt
          → ClassCastException (DefaultOAuth2AuthenticatedPrincipal != Jwt)

SAFE: use Authentication and instanceof check
     Authentication auth = SecurityContextHolder.getContext().getAuthentication();
     if (auth instanceof JwtAuthenticationToken jwtAuth) { ... }
     if (auth instanceof BearerTokenAuthentication opaqueAuth) { ... }
```

---

## 5️⃣ Summary Sheet

---

### Resource Server Request Flow

```
HTTP Request: GET /api/orders
Authorization: Bearer JWT_TOKEN
     │
     ▼
BearerTokenAuthenticationFilter
     ├── DefaultBearerTokenResolver.resolve()
     │       └── Extract "JWT_TOKEN" from Authorization header
     │
     ├── BearerTokenAuthenticationToken(JWT_TOKEN) [unauthenticated]
     │
     └── AuthenticationManager.authenticate()
               │
               ▼
         JwtAuthenticationProvider
               ├── JwtDecoder.decode(JWT_TOKEN)
               │       ├── Parse header: kid, alg
               │       ├── Fetch public key from JWKS (if needed)
               │       ├── Verify RS256 signature
               │       ├── Run validators: exp, iss, aud
               │       └── Return Jwt{sub, scope, roles, ...}
               │
               └── JwtAuthenticationConverter.convert(jwt)
                       ├── Extract scope → [SCOPE_read, SCOPE_write]
                       ├── Extract roles → [ROLE_ADMIN]
                       └── Return JwtAuthenticationToken(jwt, authorities)
     │
     ▼
SecurityContextHolder.setAuthentication(JwtAuthenticationToken)
     │
     ▼
AuthorizationFilter → check rules
     │
     ▼
Controller: @AuthenticationPrincipal Jwt jwt
```

---

### JWT vs Opaque Token Comparison

| Aspect | JWT | Opaque Token |
|--------|-----|-------------|
| Validation | Local (cryptographic) | Remote (introspection HTTP call) |
| Performance | Fast (no network) | Slow (network round-trip) |
| Revocation | Hard (until expiry) | Easy (server-side check) |
| Claims | Self-contained in token | Returned by introspection |
| Auth Server load | Low | High (every request) |
| Suitable for | High-traffic APIs | Sensitive/short-lived tokens |
| Caching needed | No (local) | Yes (performance) |

---

### JwtDecoder Construction Methods

| Method | Key Type | Key Rotation | Auth Server Dependency |
|--------|----------|-------------|----------------------|
| `withJwkSetUri()` | Asymmetric (public) | ✅ Automatic | JWK endpoint |
| `withPublicKey()` | Asymmetric (public) | ❌ Manual | None (static) |
| `withSecretKey()` | Symmetric (shared) | ❌ Manual | None (static) |
| `fromIssuerLocation()` | Asymmetric (auto-discovered) | ✅ Automatic | Discovery endpoint |

---

### Authority Mapping Quick Reference

| JWT Claim | Default Prefix | Result | Check With |
|-----------|---------------|--------|-----------|
| `scope: "read write"` | `SCOPE_` | `SCOPE_read, SCOPE_write` | `hasAuthority("SCOPE_read")` |
| `scope: "read write"` (custom `""`) | none | `read, write` | `hasAuthority("read")` |
| `roles: ["ADMIN"]` (custom `ROLE_`) | `ROLE_` | `ROLE_ADMIN` | `hasRole("ADMIN")` |

---

### Common Interview One-Liners

- **`BearerTokenAuthenticationFilter`** extracts token, delegates to `JwtAuthenticationProvider` or `OpaqueTokenAuthenticationProvider`
- **Default authority prefix** for JWT scopes is `SCOPE_` — use `hasAuthority("SCOPE_x")` not `hasRole("x")`
- **`JwtDecoder.decode()`** validates signature, expiry, issuer — throws `JwtValidationException` on failure
- **Unknown `kid`** triggers JWK Set refresh — automatic key rotation support
- **Audience validation NOT automatic** — must add `JwtClaimValidator<List<String>>(AUD, ...)` manually
- **HMAC (symmetric) keys** allow Resource Servers to forge tokens — use asymmetric RS256 in production
- **Opaque token introspection** requires HTTP call on every request — cache results for performance
- **`RequestAttributeSecurityContextRepository`** used by default in 6.x Resource Server — no session created
- **Clock skew default: 60 seconds** — expired-by-less-than-60s tokens still accepted
- **`JwtAuthenticationToken.getToken()`** returns the `Jwt` object with all claims — use in controllers

---
