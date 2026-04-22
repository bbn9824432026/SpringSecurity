# Topic 3: HTTP Basic & Digest Authentication — Complete Developer Mastery

Let me build this up the same way we did form login — layer by layer, from foundational contracts to framework internals, with every important architectural decision explained.

---

## Layer 1: The Protocol Foundation — What HTTP Basic Actually Is

Before touching a single Spring class, you must internalize the HTTP-level behavior, because Spring Security's entire `BasicAuthenticationFilter` is a direct translation of RFC 7617 into Java.

The protocol is a simple challenge-response cycle. A client requests a resource, the server challenges with a `401 + WWW-Authenticate` header, and the client retries with a Base64-encoded `username:password` in the `Authorization` header.

```
Step 1: Client requests without credentials
GET /api/orders HTTP/1.1
Host: example.com

Step 2: Server challenges
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Basic realm="Order Management API"

Step 3: Client encodes and retries
GET /api/orders HTTP/1.1
Authorization: Basic YWxpY2U6c2VjcmV0
                      └─ Base64.encode("alice:secret")

Step 4: Server validates → 200 OK
```

The single most important fact to burn into your memory: **Base64 is encoding, not encryption.** It is trivially reversible by anyone with a terminal:

```bash
echo "YWxpY2U6c2VjcmV0" | base64 --decode
# Output: alice:secret
```

This is why HTTP Basic is only acceptable over HTTPS. Without TLS, every credential in every request is effectively transmitted in plaintext to anyone who can observe the network.

---

## Layer 2: The Core Architectural Difference — Why `OncePerRequestFilter`?

This is the first deep architectural insight, and it's a favourite interview question. Form login uses `AbstractAuthenticationProcessingFilter` as its base class. Basic auth uses `OncePerRequestFilter`. Understanding *why* reveals how the framework thinks about these two mechanisms fundamentally differently.

`AbstractAuthenticationProcessingFilter` is designed around the idea of **a single dedicated login URL**. It wakes up only for `POST /login`, authenticates, then redirects. After that, the session carries the identity — the filter is irrelevant for subsequent requests.

`BasicAuthenticationFilter` cannot work that way. There is no dedicated login URL. Every single request *is* a potential authentication attempt, because every request *might* carry an `Authorization: Basic` header. The filter must inspect every incoming request, decode credentials if present, verify them, and then step aside to let the request reach the controller. `OncePerRequestFilter` is the right base class for this pattern because it guarantees execution on every request but prevents accidental double-execution on internal forwards and includes.

```
Form Login architecture:          HTTP Basic architecture:
                                   
POST /login only                   EVERY request
      ↓                                  ↓
AbstractAuthenticationProcessing   OncePerRequestFilter
Filter                             checks for Authorization header
      ↓                                  ↓ (if header present)
Redirect to /dashboard             Decode → authenticate → pass through
```

---

## Layer 3: `BasicAuthenticationFilter` — Full Internal Execution Flow

```java
/**
 * LAYER 3: BasicAuthenticationFilter internals.
 *
 * The doFilterInternal() template is simpler than form login's doFilter()
 * but runs on EVERY request, not just /login. Understanding the short-circuit
 * logic at the top is essential — it's what makes the filter efficient.
 */
public class BasicAuthenticationFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain)
            throws IOException, ServletException {

        // ─────────────────────────────────────────────────────────────────
        // SHORT-CIRCUIT 1: Already authenticated?
        // If RememberMeAuthenticationFilter or a previous filter has already
        // set an authenticated token, skip entirely — first auth wins.
        // This is why filter ORDER matters profoundly.
        // ─────────────────────────────────────────────────────────────────
        if (SecurityContextHolder.getContext().getAuthentication() != null
                && SecurityContextHolder.getContext().getAuthentication().isAuthenticated()) {
            chain.doFilter(request, response);
            return;
        }

        // ─────────────────────────────────────────────────────────────────
        // SHORT-CIRCUIT 2: No Authorization header, or not Basic scheme?
        // The filter is transparent to requests that don't carry Basic creds.
        // They continue down the chain — other filters or the
        // ExceptionTranslationFilter will handle the 401 if auth is required.
        // ─────────────────────────────────────────────────────────────────
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (header == null || !header.toLowerCase().startsWith("basic ")) {
            chain.doFilter(request, response);
            return;
        }

        // ─────────────────────────────────────────────────────────────────
        // DECODE: Base64 → username:password
        // Note: if the Base64 is malformed, the IllegalArgumentException is
        // caught and converted to a clean 401 via onUnsuccessfulAuthentication
        // — it never propagates as a 500.
        // ─────────────────────────────────────────────────────────────────
        String base64Credentials = header.substring(6); // strip "Basic "
        byte[] decodedBytes = Base64.getDecoder().decode(base64Credentials);
        String credentials = new String(decodedBytes, StandardCharsets.UTF_8);

        int colonIndex = credentials.indexOf(':'); // first colon is the delimiter
        String username = credentials.substring(0, colonIndex);
        String password = credentials.substring(colonIndex + 1);
        // Note: passwords CAN contain colons — only the FIRST colon is the delimiter

        // ─────────────────────────────────────────────────────────────────
        // BUILD UNAUTHENTICATED TOKEN — same pattern as form login
        // ─────────────────────────────────────────────────────────────────
        UsernamePasswordAuthenticationToken authRequest =
            UsernamePasswordAuthenticationToken.unauthenticated(username, password);
        authRequest.setDetails(
            authenticationDetailsSource.buildDetails(request)); // WebAuthenticationDetails

        try {
            // ─────────────────────────────────────────────────────────────
            // AUTHENTICATE — delegates to the same ProviderManager +
            // DaoAuthenticationProvider pipeline you already know from form login.
            // The same UserDetailsService, same PasswordEncoder, same checks.
            // ─────────────────────────────────────────────────────────────
            Authentication authResult =
                this.authenticationManager.authenticate(authRequest);

            // SUCCESS PATH
            SecurityContext context = SecurityContextHolder.createEmptyContext();
            context.setAuthentication(authResult);
            SecurityContextHolder.setContext(context);

            // saveContext() is a no-op with NullSecurityContextRepository (STATELESS)
            // or saves to HTTP session with HttpSessionSecurityContextRepository
            this.securityContextRepository.saveContext(context, request, response);

            chain.doFilter(request, response); // ← proceed to controller

        } catch (AuthenticationException ex) {
            // FAILURE PATH
            SecurityContextHolder.clearContext();
            this.authenticationEntryPoint.commence(request, response, ex);
            // → 401 + WWW-Authenticate header. No redirect. No chain.doFilter().
        }
    }
}
```

The key insight in that flow is the failure path. Form login calls `unsuccessfulAuthentication()` which eventually redirects to `/login?error`. Basic auth's failure path calls `authenticationEntryPoint.commence()` directly, which sends a `401` and stops the filter chain dead. No redirect. No session. Clean and stateless.

---

## Layer 4: `BasicAuthenticationEntryPoint` and the `AuthenticationEntryPoint` Contract

```java
/**
 * LAYER 4: AuthenticationEntryPoint — the "how do I ask for credentials?" contract.
 *
 * This interface answers one question: when an unauthenticated request hits a
 * protected resource, what do you send back to the client?
 *
 * Form login's answer: 302 redirect to /login
 * Basic auth's answer: 401 + WWW-Authenticate header
 * REST API's answer:   401 + JSON error body
 */
public interface AuthenticationEntryPoint {
    void commence(HttpServletRequest request,
                  HttpServletResponse response,
                  AuthenticationException authException)
            throws IOException, ServletException;
}

// ─── Spring's default Basic implementation ─────────────────────────────────
public class BasicAuthenticationEntryPoint implements AuthenticationEntryPoint,
                                                      InitializingBean {
    private String realmName;

    @Override
    public void commence(HttpServletRequest request,
                         HttpServletResponse response,
                         AuthenticationException authException) throws IOException {

        // The WWW-Authenticate header is what triggers the browser's native
        // credentials dialog. Without it, the browser just shows the 401 body.
        response.setHeader("WWW-Authenticate", "Basic realm=\"" + this.realmName + "\"");
        response.sendError(HttpStatus.UNAUTHORIZED.value(),
                           HttpStatus.UNAUTHORIZED.getReasonPhrase());
    }

    @Override
    public void afterPropertiesSet() {
        Assert.hasText(this.realmName, "realmName must be specified"); // validated at startup
    }
}

// ─── Production REST API custom implementation ──────────────────────────────
/**
 * For REST/SPA clients, a JSON body is far more useful than the plain text
 * "Unauthorized" that BasicAuthenticationEntryPoint sends. This replaces it.
 *
 * Notice: we intentionally omit WWW-Authenticate here for REST APIs because
 * we don't want the browser to show its native popup dialog — our JS client
 * handles the 401 programmatically and shows a proper login screen instead.
 */
@Component
@RequiredArgsConstructor
public class RestAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final ObjectMapper objectMapper;

    @Override
    public void commence(HttpServletRequest request,
                         HttpServletResponse response,
                         AuthenticationException authException) throws IOException {

        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("timestamp", Instant.now().toString());
        body.put("status", 401);
        body.put("error", "Unauthorized");
        body.put("message", sanitizeMessage(authException)); // don't leak internals
        body.put("path", request.getRequestURI());

        objectMapper.writeValue(response.getOutputStream(), body);
    }

    // Never expose raw exception messages in production — they can leak
    // information about your user storage strategy
    private String sanitizeMessage(AuthenticationException ex) {
        if (ex instanceof BadCredentialsException) return "Invalid credentials";
        if (ex instanceof DisabledException)       return "Account is disabled";
        if (ex instanceof LockedException)         return "Account is locked";
        return "Authentication required";
    }
}
```

---

## Layer 5: The 401 vs 403 Decision — `ExceptionTranslationFilter` Internals

This is the most nuanced and exam-critical part of HTTP Basic. The distinction between 401 and 403 isn't arbitrary — it follows a precise decision tree inside `ExceptionTranslationFilter`.

```java
/**
 * LAYER 5: ExceptionTranslationFilter — the traffic cop that routes auth exceptions.
 *
 * Positioned AFTER BasicAuthenticationFilter in the chain. It wraps the rest
 * of the chain in a try-catch and makes the 401 vs 403 routing decision.
 *
 * This is the complete internal logic:
 */
private void handleSpringSecurityException(HttpServletRequest request,
                                           HttpServletResponse response,
                                           FilterChain chain,
                                           RuntimeException exception)
        throws IOException, ServletException {

    if (exception instanceof AuthenticationException authEx) {
        // Something is wrong with the identity claim itself — 401
        sendStartAuthentication(request, response, chain, authEx);

    } else if (exception instanceof AccessDeniedException accessDenied) {

        Authentication authentication =
            SecurityContextHolder.getContext().getAuthentication();

        // ← THE CRITICAL BRANCH: is this user anonymous?
        if (authenticationTrustResolver.isAnonymous(authentication)
                || authenticationTrustResolver.isRememberMe(authentication)) {
            // Anonymous = effectively unauthenticated → ask for credentials → 401
            sendStartAuthentication(request, response, chain,
                new InsufficientAuthenticationException("Full authentication required"));
        } else {
            // Real authenticated user who lacks the required role → 403
            accessDeniedHandler.handle(request, response, accessDenied);
        }
    }
}
```

The reason `AnonymousAuthenticationFilter` (which runs before `ExceptionTranslationFilter`) matters so much is that it ensures `SecurityContextHolder` is *never* null. An unauthenticated request doesn't have a null authentication — it has an `AnonymousAuthenticationToken`. The `ExceptionTranslationFilter` uses `authenticationTrustResolver.isAnonymous()` to detect this and route it to the 401 path rather than the 403 path.

```
Request with no credentials hits /api/admin (requires ROLE_ADMIN):
     │
     ▼
BasicAuthenticationFilter           ← no Authorization header → passes through
     ↓
AnonymousAuthenticationFilter       ← sets AnonymousAuthenticationToken
     ↓
AuthorizationFilter                 ← ROLE_ADMIN check fails → AccessDeniedException
     ↓
ExceptionTranslationFilter          ← catches AccessDeniedException
     ↓
isAnonymous(token)?                 ← YES (AnonymousAuthenticationToken)
     ↓
sendStartAuthentication()           ← calls AuthenticationEntryPoint
     ↓
BasicAuthenticationEntryPoint       ← 401 + WWW-Authenticate

─────────────────────────────────────────────────────────────────────────────

Request with valid credentials (alice, ROLE_USER) hits /api/admin:
     │
     ▼
BasicAuthenticationFilter           ← decodes alice:secret → authenticates → SUCCESS
     ↓
AuthorizationFilter                 ← ROLE_ADMIN check fails → AccessDeniedException
     ↓
ExceptionTranslationFilter          ← catches AccessDeniedException
     ↓
isAnonymous(token)?                 ← NO (UsernamePasswordAuthenticationToken, authenticated)
     ↓
accessDeniedHandler.handle()        ← 403 Forbidden
```

---

## Layer 6: Stateless vs Stateful — The `SecurityContextRepository` Choice

```java
/**
 * LAYER 6: SecurityContextRepository — whether authentication "sticks" between requests.
 *
 * This is the same repository concept from form login, but the choice matters
 * far more for Basic auth because stateful Basic is an anti-pattern.
 */

// ─── Stateful (default — wrong for Basic auth) ─────────────────────────────
// Request 1: Authorization: Basic YWxpY2U6c2VjcmV0
//   → Authenticated → SecurityContext saved to HttpSession → JSESSIONID cookie set
// Request 2: Cookie: JSESSIONID=abc123 (no Authorization header)
//   → SecurityContextHolderFilter restores context from session
//   → BasicAuthenticationFilter sees authenticated context → SKIPS
//   → You now have a stateful session from a "stateless" protocol. Wasteful.

// ─── Stateless (correct for REST APIs) ─────────────────────────────────────
// Every Request: Authorization: Basic YWxpY2U6c2VjcmV0
//   → Decode → authenticate → set context (in-memory, thread-local only)
//   → End of request: context cleared, nothing persisted, no JSESSIONID

@Bean
public SecurityFilterChain apiFilterChain(HttpSecurity http) throws Exception {
    http
        .httpBasic(basic -> basic
            .realmName("My API")
            .authenticationEntryPoint(restAuthenticationEntryPoint)
        )
        .sessionManagement(session -> session
            // STATELESS = NullSecurityContextRepository is used automatically.
            // No session is ever created. No JSESSIONID cookie. No memory overhead.
            .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        )
        // CSRF protection is irrelevant without sessions — disable it.
        // CSRF attacks rely on the browser auto-sending session cookies.
        // A stateless API has no cookies to exploit.
        .csrf(AbstractHttpConfigurer::disable);

    return http.build();
}
```

Now here is the performance trap that catches production teams. With `STATELESS`, every request triggers the full authentication pipeline: Base64 decode → `UserDetailsService.loadUserByUsername()` (database query) → `PasswordEncoder.matches()`. That last step is the killer.

`BCryptPasswordEncoder(strength=12)` takes ~250-500ms per verification by design — that's the entire point of BCrypt. A server handling 100 requests per second would spend 25-50 CPU-seconds per second *just on password hashing*. The solution for high-traffic APIs is to move to JWT: one BCrypt operation at login to issue the token, then fast HMAC/RSA signature verification on every subsequent request.

---

## Layer 7: The Complete Security Configuration — Production Patterns

```java
/**
 * LAYER 7A: Clean stateless REST API with HTTP Basic.
 *
 * This is the pattern you'd use for a machine-to-machine API where clients
 * authenticate with an API key (clientId) and secret.
 */
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class ApiSecurityConfig {

    private final RestAuthenticationEntryPoint authEntryPoint;
    private final JsonAccessDeniedHandler accessDeniedHandler;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/actuator/health", "/actuator/info").permitAll()
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                .requestMatchers("/api/**").hasAnyRole("API_CLIENT", "ADMIN")
                .anyRequest().denyAll()  // fail-safe: deny anything not explicitly permitted
            )
            .httpBasic(basic -> basic
                .realmName("My Company API v2")
                .authenticationEntryPoint(authEntryPoint)
            )
            .sessionManagement(s -> s
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .csrf(AbstractHttpConfigurer::disable)
            .exceptionHandling(ex -> ex
                .authenticationEntryPoint(authEntryPoint)  // 401
                .accessDeniedHandler(accessDeniedHandler)  // 403
            );

        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager(
            ApiClientDetailsService userDetailsService,
            PasswordEncoder passwordEncoder) {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder);
        provider.setHideUserNotFoundExceptions(true); // prevent client ID enumeration
        return new ProviderManager(provider);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        // BCrypt strength 10 (default) is fine for low-traffic APIs.
        // For high-traffic, consider strength 8 or migrate to JWT.
        return new BCryptPasswordEncoder(10);
    }
}

/**
 * LAYER 7B: Dual-chain configuration — Basic for /api/**, Form for /web/**
 *
 * The @Order annotation determines which chain gets matched first.
 * SecurityFilterChains are evaluated in order — first matching chain wins.
 * The /api/** securityMatcher prevents this chain from touching /web/** requests.
 */
@Configuration
@EnableWebSecurity
public class DualAuthSecurityConfig {

    @Bean
    @Order(1)  // ← checked first — handles /api/** with Basic auth
    public SecurityFilterChain apiChain(HttpSecurity http) throws Exception {
        http
            .securityMatcher("/api/**")   // this chain ONLY applies to /api/** paths
            .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
            .httpBasic(basic -> basic.authenticationEntryPoint(jsonEntryPoint()))
            .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .csrf(AbstractHttpConfigurer::disable);
        return http.build();
    }

    @Bean
    @Order(2)  // ← checked second — handles everything else with Form login
    public SecurityFilterChain webChain(HttpSecurity http) throws Exception {
        http
            // No securityMatcher = matches everything not matched by chain 1
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/login", "/register").permitAll()
                .anyRequest().authenticated()
            )
            .formLogin(form -> form.defaultSuccessUrl("/dashboard"));
        return http.build();
    }
}
```

---

## Layer 8: Custom `AuthenticationEntryPoint` and `AccessDeniedHandler` — The Complete Pair

```java
/**
 * LAYER 8: The complete error handling pair for a REST API.
 *
 * AuthenticationEntryPoint → handles 401 (who are you?)
 * AccessDeniedHandler      → handles 403 (I know who you are, but you can't do this)
 *
 * Both must be implemented for a well-behaved API.
 */

// ─── 403 Handler ────────────────────────────────────────────────────────────
@Component
@RequiredArgsConstructor
public class JsonAccessDeniedHandler implements AccessDeniedHandler {

    private final ObjectMapper objectMapper;

    @Override
    public void handle(HttpServletRequest request,
                       HttpServletResponse response,
                       AccessDeniedException ex) throws IOException {

        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        objectMapper.writeValue(response.getOutputStream(), Map.of(
            "timestamp", Instant.now().toString(),
            "status",    403,
            "error",     "Forbidden",
            "message",   "Insufficient permissions to access this resource",
            "path",      request.getRequestURI()
        ));
    }
}

// ─── Custom BasicAuthenticationFilter (extension example) ───────────────────
/**
 * Extension: add request logging and structured audit trail to every
 * Basic auth attempt. Demonstrates the customization point.
 */
@Component
@Slf4j
public class AuditingBasicAuthFilter extends BasicAuthenticationFilter {

    private final AuditService auditService;

    public AuditingBasicAuthFilter(AuthenticationManager authManager,
                                    AuditService auditService) {
        super(authManager);
        this.auditService = auditService;
    }

    @Override
    protected void onSuccessfulAuthentication(HttpServletRequest request,
                                              HttpServletResponse response,
                                              Authentication authResult) throws IOException {
        // Called after successful authentication — hook for audit logging
        auditService.recordAuthSuccess(
            authResult.getName(),
            request.getRemoteAddr(),
            request.getRequestURI());
        log.info("Basic auth success: user={}, uri={}", authResult.getName(),
                 request.getRequestURI());
    }

    @Override
    protected void onUnsuccessfulAuthentication(HttpServletRequest request,
                                                HttpServletResponse response,
                                                AuthenticationException failed) throws IOException {
        // Called after failed authentication — hook for lockout tracking
        auditService.recordAuthFailure(request.getRemoteAddr(), failed.getClass().getSimpleName());
        log.warn("Basic auth failure: ip={}, reason={}", request.getRemoteAddr(),
                 failed.getMessage());
    }
}
```

---

## Layer 9: The Entry Point Conflict — The Biggest Production Trap

This is the single most common production misconfiguration with HTTP Basic, and it's subtle enough to pass code review without anyone noticing.

```java
/**
 * LAYER 9: The Entry Point Override Problem.
 *
 * When you configure BOTH formLogin and httpBasic, the LAST registered
 * AuthenticationEntryPoint wins as the default in ExceptionTranslationFilter.
 * Form login always registers LoginUrlAuthenticationEntryPoint, which issues
 * 302 redirects — completely wrong for API clients.
 */

// ❌ WRONG — this silently makes Basic auth return 302 redirects
http
    .httpBasic(Customizer.withDefaults())   // registers BasicAuthenticationEntryPoint
    .formLogin(Customizer.withDefaults());  // overrides with LoginUrlAuthenticationEntryPoint
// Result: unauthenticated /api/** requests get 302 → /login
// API clients that don't follow redirects see a 302 and break silently.

// ✓ CORRECT — explicitly set the entry point for unambiguous behavior
http
    .httpBasic(basic -> basic.authenticationEntryPoint(jsonEntryPoint()))
    .exceptionHandling(ex -> ex
        .authenticationEntryPoint(jsonEntryPoint()) // this is what ETF actually uses
        .accessDeniedHandler(jsonAccessDeniedHandler)
    );

// ✓ EVEN BETTER — use separate SecurityFilterChains (Layer 7B above)
// so Basic and Form login never compete for the same requests.
```

The reason this is such a dangerous trap is that in development, you're usually testing with tools that *do* follow redirects (browsers, Postman with redirect enabled) and everything appears to work. The breakage only surfaces when a real API client (curl without `-L`, fetch() in a browser, a backend service) hits the endpoint and receives an unexpected 302.

---

## Layer 10: Digest Authentication — Why It Died

```java
/**
 * LAYER 10: Digest Authentication architecture and its fatal flaws.
 *
 * Digest was designed to solve Basic's plaintext-over-wire problem.
 * The client hashes the password instead of sending it directly.
 *
 * Protocol flow:
 *   Server → Client: nonce="abc123", realm="App"
 *   Client computes:
 *     HA1 = MD5("alice:App:secret")         ← username:realm:password
 *     HA2 = MD5("GET:/api/data")            ← method:URI
 *     response = MD5(HA1 + ":abc123:" + HA2) ← HA1:nonce:HA2
 *   Client → Server: Authorization: Digest username="alice", response="..."
 *
 * To VERIFY the response, the server must compute the same MD5.
 * For MD5(HA1) = MD5("alice:App:secret"), the server needs the RAW password.
 *
 * This is the fatal flaw: Digest requires storing plaintext passwords.
 * BCrypt is a one-way function — you CANNOT recover the input from the hash.
 * Therefore Digest is fundamentally incompatible with modern password hashing.
 *
 * Additionally:
 *   - MD5 is cryptographically broken since 1996 (practical collisions)
 *   - Nonce management is complex; weak nonces enable replay attacks
 *   - HTTPS solves the eavesdropping problem Digest was designed for
 *
 * Spring Security 5.x: DigestAuthenticationFilter exists, labeled legacy
 * Spring Security 6.x: DigestAuthenticationFilter REMOVED entirely
 *
 * There is no correct way to implement Digest in a Spring Security 6 app.
 * If you need it, you're on the wrong architecture.
 */
```

The conceptual summary worth memorising: Digest Auth tried to solve the problem of sending passwords over unencrypted connections. The correct solution to that problem turned out to be TLS, not Digest. Once HTTPS became the baseline, Digest's complexity bought nothing while its server-side plaintext storage requirement became an active liability.

---

## Layer 11: Testing HTTP Basic Security

```java
/**
 * LAYER 11: Testing strategies for Basic auth.
 *
 * spring-security-test provides httpBasic() RequestPostProcessor
 * which sets the Authorization header automatically.
 */
@SpringBootTest
@AutoConfigureMockMvc
class BasicAuthSecurityTest {

    @Autowired MockMvc mockMvc;

    @Test
    @DisplayName("Valid credentials → 200 OK")
    void validCredentials() throws Exception {
        mockMvc.perform(get("/api/orders")
                .with(httpBasic("alice", "secret"))) // sets Authorization: Basic header
            .andExpect(status().isOk());
    }

    @Test
    @DisplayName("No credentials → 401 with JSON body")
    void noCredentials() throws Exception {
        mockMvc.perform(get("/api/orders"))
            .andExpect(status().isUnauthorized())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON))
            .andExpect(jsonPath("$.status").value(401))
            .andExpect(jsonPath("$.error").value("Unauthorized"));
    }

    @Test
    @DisplayName("Wrong password → 401, not 500")
    void wrongPassword() throws Exception {
        mockMvc.perform(get("/api/orders")
                .with(httpBasic("alice", "wrongpassword")))
            .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Valid credentials, wrong role → 403")
    void insufficientRole() throws Exception {
        // alice has ROLE_USER only, /api/admin requires ROLE_ADMIN
        mockMvc.perform(get("/api/admin/users")
                .with(httpBasic("alice", "secret")))
            .andExpect(status().isForbidden())
            .andExpect(jsonPath("$.status").value(403));
    }

    @Test
    @DisplayName("Malformed Base64 → 401, not 500")
    void malformedBase64() throws Exception {
        mockMvc.perform(get("/api/orders")
                .header("Authorization", "Basic @@@@INVALID_BASE64@@@@"))
            .andExpect(status().isUnauthorized()); // clean 401, not 500
    }

    @Test
    @DisplayName("STATELESS — no session cookie created")
    void noSessionCreated() throws Exception {
        MvcResult result = mockMvc.perform(get("/api/orders")
                .with(httpBasic("alice", "secret")))
            .andExpect(status().isOk())
            .andReturn();

        // For stateless APIs, no JSESSIONID should ever be set
        assertThat(result.getResponse().getCookie("JSESSIONID")).isNull();
    }
}
```

---

## The Complete Mental Model

Here is how all layers connect for HTTP Basic, mapped against the form login flow you already know:

```
Every HTTP Request
      │
      ▼
SecurityContextHolderFilter          ← Layer 6: loads context (empty if STATELESS)
      │
      ▼
BasicAuthenticationFilter            ← Layer 3: the core filter
      │
      ├──[Already authenticated?]─YES──────────────────────────────────► chain.doFilter()
      │
      ├──[No Authorization header?]─YES────────────────────────────────► chain.doFilter()
      │                                                                         │
      ├── Decode Base64 → username:password                               AuthorizationFilter
      ├── Build UPAuthToken(username, password, unauthenticated)               │
      │                                                                    AccessDeniedException?
      ├── AuthenticationManager.authenticate()                                  │
      │       └── DaoAuthenticationProvider                              ExceptionTranslationFilter
      │               ├── loadUserByUsername()  [Layer 2 — same as form login]  │
      │               ├── preAuthChecks()                                  ├── isAnonymous?
      │               ├── passwordEncoder.matches()                        │       YES → 401
      │               └── postAuthChecks()                                 └── authenticated?
      │                                                                             YES → 403
      ├──[SUCCESS]:
      │       SecurityContextHolder.setContext(auth)
      │       SecurityContextRepository.saveContext()  ← no-op if STATELESS
      │       chain.doFilter()  ──────────────────────────────────► Controller → 200 OK
      │
      └──[FAILURE — AuthenticationException]:
              SecurityContextHolder.clearContext()
              AuthenticationEntryPoint.commence()      ← Layer 4
                    └── 401 + WWW-Authenticate: Basic realm="..."
                        (or JSON body for REST APIs)
```

The deepest insight connecting everything: HTTP Basic and Form Login share the entire authentication pipeline from `AuthenticationManager` downward — the same `DaoAuthenticationProvider`, the same `UserDetailsService`, the same `PasswordEncoder`. What differs entirely is the *input extraction* (Base64 header vs form params) and the *output handling* (pass-through vs redirect, 401 vs 302). Spring Security's design isolates these two variable parts behind `BasicAuthenticationFilter` and `AuthenticationEntryPoint` respectively, leaving everything else shared and reusable.
