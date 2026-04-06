# TOPIC 3 — HTTP Basic & Digest Authentication

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

---

## 1️⃣ Conceptual Explanation

---

### 3.1 HTTP Basic Authentication — Protocol Level First

Before diving into Spring Security internals, understanding the HTTP protocol behavior is essential because Spring Security's implementation directly mirrors it.

**RFC 7617 — The Basic Authentication Flow:**

```
Step 1: Client requests protected resource (no credentials)
GET /api/data HTTP/1.1
Host: example.com

Step 2: Server challenges the client
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Basic realm="My App"

Step 3: Client sends credentials (Base64 encoded — NOT encrypted)
GET /api/data HTTP/1.1
Authorization: Basic YWxpY2U6c2VjcmV0
                      └── Base64("alice:secret")

Step 4: Server validates and responds
HTTP/1.1 200 OK
```

**Critical security fact:** Base64 is **encoding, not encryption**. Anyone who intercepts the `Authorization` header can decode it instantly:
```
Base64.decode("YWxpY2U6c2VjcmV0") = "alice:secret"
```
This is why HTTP Basic **must always be used over HTTPS in production**.

---

### 3.2 BasicAuthenticationFilter — Deep Internal Architecture

`BasicAuthenticationFilter` extends `OncePerRequestFilter` — not `AbstractAuthenticationProcessingFilter`. This is a **fundamental architectural difference** from form login.

**Why `OncePerRequestFilter` and not `AbstractAuthenticationProcessingFilter`?**

- `AbstractAuthenticationProcessingFilter` is designed for **one specific login URL** — it intercepts, authenticates, and redirects
- `BasicAuthenticationFilter` must **attempt authentication on EVERY request** that carries an `Authorization: Basic` header — there is no dedicated login URL
- `OncePerRequestFilter` guarantees the filter runs exactly once per request, even with forward/include dispatches

---

#### Complete Internal Execution Flow

```
Every HTTP Request
     │
     ▼
BasicAuthenticationFilter.doFilterInternal()
     │
     ├── Step 1: Check for existing authentication
     │     SecurityContext already has authenticated token?
     │           YES → skip (don't re-authenticate)
     │           NO  → continue
     │
     ├── Step 2: Extract Authorization header
     │     request.getHeader("Authorization")
     │           NULL or not "Basic ..." → chain.doFilter() (pass through)
     │           Starts with "Basic " → extract and decode
     │
     ├── Step 3: Decode credentials
     │     String base64 = header.substring(6)  // remove "Basic "
     │     byte[] decoded = Base64.decode(base64)
     │     String credentials = new String(decoded, StandardCharsets.UTF_8)
     │     int colonIndex = credentials.indexOf(":")
     │     username = credentials.substring(0, colonIndex)
     │     password = credentials.substring(colonIndex + 1)
     │
     ├── Step 4: Build unauthenticated token
     │     UsernamePasswordAuthenticationToken.unauthenticated(username, password)
     │
     ├── Step 5: Delegate to AuthenticationManager
     │     authManager.authenticate(token)
     │           SUCCESS → continue to Step 6
     │           AuthenticationException → go to Step 7 (failure)
     │
     ├── Step 6: Store in SecurityContext
     │     SecurityContextHolder.getContext().setAuthentication(authResult)
     │     securityContextRepository.saveContext(...)
     │           (saves to session if stateful, no-op if stateless)
     │     chain.doFilter()  ← pass to next filter / eventually controller
     │
     └── Step 7: Handle failure
           SecurityContextHolder.clearContext()
           authenticationEntryPoint.commence(request, response, exception)
                 └── BasicAuthenticationEntryPoint
                       response.setHeader("WWW-Authenticate", "Basic realm=\"...\"")
                       response.sendError(401, "Unauthorized")
```

**Key behavioral difference from form login:**

| Behavior | Form Login | HTTP Basic |
|----------|-----------|-----------|
| Failure response | 302 redirect to login page | 401 with `WWW-Authenticate` header |
| Authentication URL | Specific POST URL | Every request with `Authorization` header |
| Base class | `AbstractAuthenticationProcessingFilter` | `OncePerRequestFilter` |
| Session creation | Creates session on success | Optional (can be stateless) |
| Browser behavior | HTML form | Native browser popup dialog |

---

### 3.3 BasicAuthenticationEntryPoint — The 401 Generator

`BasicAuthenticationEntryPoint` implements `AuthenticationEntryPoint`:

```java
public interface AuthenticationEntryPoint {
    void commence(
        HttpServletRequest request,
        HttpServletResponse response,
        AuthenticationException authException
    ) throws IOException, ServletException;
}
```

When `BasicAuthenticationFilter` encounters a failure, or when `ExceptionTranslationFilter` catches an `AuthenticationException` on a Basic-secured endpoint, `BasicAuthenticationEntryPoint.commence()` is called:

```java
// Internal implementation:
public void commence(HttpServletRequest request,
                     HttpServletResponse response,
                     AuthenticationException authException) throws IOException {

    response.setHeader("WWW-Authenticate", "Basic realm=\"" + this.realmName + "\"");
    response.sendError(HttpStatus.UNAUTHORIZED.value(),
                       HttpStatus.UNAUTHORIZED.getReasonPhrase());
}
```

This produces:
```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Basic realm="Spring Security Application"
```

The `realm` is a string identifying the protected area. The browser uses it to display in its native credentials popup dialog. **The realm name has no security function** — it is purely informational.

---

### 3.4 Stateless vs Stateful HTTP Basic — The Architectural Decision

HTTP Basic can be used in two modes in Spring Security:

**Mode 1 — Stateful (default, not recommended for Basic):**
```
Request 1: Authorization: Basic YWxpY2U6c2VjcmV0
     → Authenticated
     → SecurityContext saved to HTTP session (JSESSIONID cookie set)

Request 2: Cookie: JSESSIONID=abc123 (no Authorization header)
     → SecurityContextPersistenceFilter/SecurityContextHolderFilter loads from session
     → Already authenticated — BasicAuthenticationFilter skips
```

This is wasteful — you get the overhead of sessions while using Basic auth.

**Mode 2 — Stateless (correct for REST APIs):**
```java
http
    .httpBasic(Customizer.withDefaults())
    .sessionManagement(s -> s
        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
```

```
Every Request: Authorization: Basic YWxpY2U6c2VjcmV0
     → Filter decodes and authenticates on every single request
     → SecurityContext NEVER saved to session
     → No JSESSIONID cookie ever created
```

**Performance implication of stateless Basic:**
Every request triggers:
1. Base64 decoding
2. `UserDetailsService.loadUserByUsername()` (likely a DB query)
3. `PasswordEncoder.matches()` — **BCrypt is intentionally slow (CPU-intensive)**

For high-traffic APIs, BCrypt on every request is a serious performance concern. This is why JWT (stateless but without per-request password verification) is preferred for REST APIs.

---

### 3.5 Digest Authentication — Architecture & Why It's Deprecated

**Digest Auth (RFC 2617)** was designed to solve Basic Auth's plaintext-over-the-wire problem:

```
Client → Server: GET /resource
Server → Client: 401 + WWW-Authenticate: Digest realm="...",
                      nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093",
                      algorithm=MD5

Client computes:
  HA1 = MD5(username:realm:password)
  HA2 = MD5(method:digestURI)
  response = MD5(HA1:nonce:HA2)

Client → Server: Authorization: Digest username="alice",
                       realm="...", nonce="...", response="..."
```

**Why Digest is deprecated/removed in Spring Security 6.x:**

1. **MD5 is cryptographically broken** — collisions are practical
2. **Requires storing plaintext passwords** on server — to verify the digest, server must compute `MD5(username:realm:password)`, which requires knowing the raw password. This defeats the purpose of password hashing
3. **Not replay-attack resistant** without proper nonce management
4. **HTTP over TLS** (HTTPS) solves the original problem (eavesdropping) that Digest was designed for — making Digest's complexity unnecessary

**Spring Security status:**
- Spring Security 5.x: `DigestAuthenticationFilter` exists but is labeled legacy
- Spring Security 6.x: `DigestAuthenticationFilter` is **removed**

---

### 3.6 HTTP Basic in Spring Boot Auto-Configuration

When you add `spring-boot-starter-security` with no custom configuration, Spring Boot auto-configures:

```
SpringBootWebSecurityConfiguration
     └── Creates default SecurityFilterChain:
           ├── All requests require authentication
           ├── HTTP Basic enabled
           ├── Form login enabled
           └── Generated password printed to console:
                 "Using generated security password: a1b2c3d4-..."
```

The generated password is from `UserDetailsServiceAutoConfiguration` which creates an in-memory `UserDetailsService` with username `"user"` and a UUID password. This is purely for development convenience and must be replaced in any real application.

---

### 3.7 SecurityContext Propagation in Stateless vs Stateful Scenarios

**Stateful (session-based) propagation:**
```
Request 1 (with credentials)
     │
     ├── Filter authenticates
     ├── SecurityContext saved to HttpSession
     └── Response includes Set-Cookie: JSESSIONID=xyz

Request 2 (with session cookie, no credentials)
     │
     ├── SecurityContextHolderFilter
     │       └── HttpSessionSecurityContextRepository.loadContext(request)
     │               └── session.getAttribute("SPRING_SECURITY_CONTEXT")
     │                       └── Returns saved SecurityContext
     └── Filter chain sees authenticated context
```

**Stateless propagation:**
```
Every Request (must include credentials)
     │
     ├── SecurityContextHolderFilter
     │       └── NullSecurityContextRepository.loadContext()
     │               └── Returns empty SecurityContext (always)
     │
     ├── BasicAuthenticationFilter (or BearerTokenAuthenticationFilter)
     │       └── Authenticates from header
     │       └── Sets SecurityContext in SecurityContextHolder (in-memory only)
     │
     └── End of request:
           SecurityContextHolderFilter clears SecurityContextHolder
           Context is NOT saved anywhere (NullSecurityContextRepository)
```

---

## 2️⃣ Code Examples

---

### Example 1 — Basic HTTP Basic Configuration (6.x)

```java
@Configuration
@EnableWebSecurity
public class BasicAuthSecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/public/**").permitAll()
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
            )
            .httpBasic(basic -> basic
                .realmName("My Application API")
                // Custom entry point for 401 response
                .authenticationEntryPoint(customEntryPoint())
            )
            // Stateless — no session
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            // No CSRF for stateless API
            .csrf(AbstractHttpConfigurer::disable);

        return http.build();
    }

    @Bean
    public AuthenticationEntryPoint customEntryPoint() {
        BasicAuthenticationEntryPoint entryPoint =
            new BasicAuthenticationEntryPoint();
        entryPoint.setRealmName("My Application API");
        return entryPoint;
    }

    @Bean
    public UserDetailsService userDetailsService(PasswordEncoder encoder) {
        UserDetails api = User.builder()
            .username("api-client")
            .password(encoder.encode("secret"))
            .roles("API")
            .build();
        return new InMemoryUserDetailsManager(api);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
}
```

---

### Example 2 — Custom JSON AuthenticationEntryPoint (REST API)

```java
// For REST APIs, returning a JSON error body on 401 is better than
// the default plain text "Unauthorized"

@Component
public class JsonAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public void commence(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException authException) throws IOException {

        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        Map<String, Object> errorBody = Map.of(
            "status",    401,
            "error",     "Unauthorized",
            "message",   authException.getMessage(),
            "path",      request.getRequestURI(),
            "timestamp", Instant.now().toString()
        );

        objectMapper.writeValue(response.getOutputStream(), errorBody);
    }
}
```

```java
// Register:
http.httpBasic(basic -> basic
    .authenticationEntryPoint(jsonAuthenticationEntryPoint)
);
```

**Response produced:**
```json
{
  "status": 401,
  "error": "Unauthorized",
  "message": "Bad credentials",
  "path": "/api/data",
  "timestamp": "2025-01-15T10:30:00Z"
}
```

---

### Example 3 — Custom AccessDeniedHandler (for 403)

```java
// Note: AuthenticationEntryPoint handles 401 (not authenticated)
// AccessDeniedHandler handles 403 (authenticated but not authorized)
// Both needed for complete REST API error handling

@Component
public class JsonAccessDeniedHandler implements AccessDeniedHandler {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public void handle(
            HttpServletRequest request,
            HttpServletResponse response,
            AccessDeniedException accessDeniedException) throws IOException {

        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        Map<String, Object> errorBody = Map.of(
            "status",    403,
            "error",     "Forbidden",
            "message",   "You do not have permission to access this resource",
            "path",      request.getRequestURI(),
            "timestamp", Instant.now().toString()
        );

        objectMapper.writeValue(response.getOutputStream(), errorBody);
    }
}
```

```java
// Register both handlers together:
http
    .httpBasic(basic -> basic
        .authenticationEntryPoint(jsonAuthenticationEntryPoint)
    )
    .exceptionHandling(ex -> ex
        .authenticationEntryPoint(jsonAuthenticationEntryPoint)  // 401
        .accessDeniedHandler(jsonAccessDeniedHandler)            // 403
    );
```

---

### Example 4 — Combining Basic Auth + Form Login (Dual Strategy)

```java
@Configuration
@EnableWebSecurity
public class DualAuthConfig {

    // Chain 1: REST API — Basic Auth, stateless
    @Bean
    @Order(1)
    public SecurityFilterChain apiChain(HttpSecurity http) throws Exception {
        http
            .securityMatcher("/api/**")
            .authorizeHttpRequests(auth -> auth
                .anyRequest().authenticated()
            )
            .httpBasic(basic -> basic
                .authenticationEntryPoint(jsonEntryPoint())
            )
            .sessionManagement(s -> s
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            .csrf(AbstractHttpConfigurer::disable);
        return http.build();
    }

    // Chain 2: Web UI — Form Login, stateful
    @Bean
    @Order(2)
    public SecurityFilterChain webChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/login", "/public/**").permitAll()
                .anyRequest().authenticated()
            )
            .formLogin(Customizer.withDefaults());
        return http.build();
    }
}
```

---

### Example 5 — Basic Auth with Custom UserDetailsService

```java
@Service
public class ApiKeyUserDetailsService implements UserDetailsService {

    private final ApiClientRepository apiClientRepository;

    @Override
    public UserDetails loadUserByUsername(String clientId)
            throws UsernameNotFoundException {

        ApiClient client = apiClientRepository
            .findByClientId(clientId)
            .orElseThrow(() -> new UsernameNotFoundException(
                "API client not found: " + clientId));

        return User.builder()
            .username(client.getClientId())
            .password(client.getHashedSecret())  // BCrypt stored hash
            .authorities(client.getPermissions()
                .stream()
                .map(SimpleGrantedAuthority::new)
                .toList())
            .accountExpired(!client.isActive())
            .credentialsExpired(client.isSecretExpired())
            .build();
    }
}
```

---

### Example 6 — Incorrect Configurations & Why They Fail

```java
// ❌ WRONG 1 — Basic auth without HTTPS in production
// Basic auth sends credentials as Base64 (not encrypted)
// Anyone intercepting the network sees: alice:secret
// NEVER use without TLS!

// ❌ WRONG 2 — Using BCrypt with high cost factor for high-traffic stateless API
http
    .httpBasic(Customizer.withDefaults())
    .sessionManagement(s -> s.sessionCreationPolicy(STATELESS));

// BCryptPasswordEncoder(14) = ~1 second per verification
// 1000 requests/sec = 1000 BCrypt operations/sec → server melts
// ✓ SOLUTION: Use JWT — verify once at token issue, then verify signature only

// ❌ WRONG 3 — Both entry points configured, wrong one takes effect
http
    .httpBasic(basic -> basic
        .authenticationEntryPoint(basicEntryPoint())  // This is overridden!
    )
    .exceptionHandling(ex -> ex
        .authenticationEntryPoint(otherEntryPoint())  // This wins — global setting
    );
// The exceptionHandling().authenticationEntryPoint() takes precedence
// over the one configured inside httpBasic()

// ✓ CORRECT: Configure in exceptionHandling() for global effect
http.exceptionHandling(ex -> ex
    .authenticationEntryPoint(jsonEntryPoint())
);

// ❌ WRONG 4 — Session creation with stateless Basic
http
    .httpBasic(Customizer.withDefaults())
    // Missing: .sessionManagement(s -> s.sessionCreationPolicy(STATELESS))
    // Result: Session created after first Basic auth
    //         Subsequent requests use session — no Authorization header needed
    //         This defeats the purpose of API key-based Basic auth
```

---

## 3️⃣ Exam-Style Questions

---

**Q1 (MCQ):** `BasicAuthenticationFilter` extends which class?

A. `AbstractAuthenticationProcessingFilter`
B. `GenericFilterBean`
C. `OncePerRequestFilter`
D. `UsernamePasswordAuthenticationFilter`

**Answer: C — `OncePerRequestFilter`**
This is a key architectural distinction. Basic auth must attempt authentication on **every request** carrying credentials, not just a specific login URL. `OncePerRequestFilter` is the correct base for this behavior.

---

**Q2 (MCQ):** What does Spring Security return when Basic authentication fails?

A. 302 redirect to `/login`
B. 403 Forbidden
C. 401 Unauthorized with `WWW-Authenticate` header
D. 400 Bad Request

**Answer: C**
`BasicAuthenticationEntryPoint.commence()` sends HTTP 401 with the `WWW-Authenticate: Basic realm="..."` header. This is the RFC-specified challenge response, not a redirect.

---

**Q3 (MCQ):** What is the value of `Authorization` header for username `bob` and password `pass123`?

A. `Basic bob:pass123`
B. `Basic Ym9iOnBhc3MxMjM=`
C. `Bearer Ym9iOnBhc3MxMjM=`
D. `Basic Ym9i:cGFzczEyMw==`

**Answer: B**
`Base64("bob:pass123") = "Ym9iOnBhc3MxMjM="`. The format is `Basic <Base64(username:password)>` — the colon delimiter is inside the Base64 encoding, not visible in the header value.

---

**Q4 (Select All That Apply):** Which are true about HTTP Basic in Spring Security?

A. Credentials are validated on every request when `STATELESS` session policy is used
B. `BasicAuthenticationFilter` creates a new HTTP session on every successful authentication
C. `BasicAuthenticationFilter` skips processing if `SecurityContext` already contains an authenticated token
D. Failed Basic authentication triggers a redirect to `/login` by default
E. The `Authorization` header value can be decoded without a key or password

**Answer: A, C, E**
B is false — with `STATELESS`, no session is created. Even with stateful, sessions are reused.
D is false — Basic failure returns 401, not a redirect. Redirects are form login behavior.
E is true — Base64 is encoding, not encryption. No key required to decode.

---

**Q5 (Code Behavior):**

```java
http
    .httpBasic(Customizer.withDefaults())
    .formLogin(Customizer.withDefaults())
    .sessionManagement(s -> s
        .sessionCreationPolicy(SessionCreationPolicy.STATELESS));
```

A browser makes a request to `/dashboard` with no credentials and no session. What happens?

A. 401 with `WWW-Authenticate` header
B. 302 redirect to `/login`
C. 403 Forbidden
D. Depends on which entry point is configured last

**Answer: B — 302 redirect to `/login`**
When both form login and Basic are configured, form login's `LoginUrlAuthenticationEntryPoint` takes precedence as the default `AuthenticationEntryPoint` (it is registered last and overrides Basic's entry point). For browser requests to web endpoints, the redirect wins. This is a major trap — even though Basic is configured, the form login entry point governs `ExceptionTranslationFilter`'s behavior.

To make Basic return 401, you must explicitly set the entry point:
```java
.exceptionHandling(ex -> ex
    .authenticationEntryPoint(new BasicAuthenticationEntryPoint()))
```

---

**Q6 (Scenario — Performance Trap):**

Your team builds a microservice API secured with HTTP Basic and `BCryptPasswordEncoder(strength=12)`. Load testing reveals the service can only handle 50 requests/second despite a powerful server. What is the root cause?

**Answer:**
BCrypt with strength 12 takes approximately 250-500ms per password verification. With `STATELESS` session policy, every single request triggers a full BCrypt verification. At 50 req/sec, the server spends nearly all CPU time on BCrypt operations. Solutions:
1. Switch to JWT — issue a JWT on login (one BCrypt operation), subsequent requests only verify the JWT signature (fast HMAC/RSA operation)
2. Reduce BCrypt strength (security tradeoff)
3. Cache authenticated principals (breaks stateless model)

---

**Q7 (Exception Trace):**

```
Request: GET /api/admin  
Authorization: Basic YWxpY2U6c2VjcmV0  (alice:secret)
Alice has ROLE_USER only
```

Trace the complete exception flow and final HTTP response.

**Answer:**
```
1. BasicAuthenticationFilter decodes → alice:secret
2. AuthenticationManager authenticates → SUCCESS (alice is valid)
3. SecurityContextHolder set with alice's Authentication (ROLE_USER)
4. chain.doFilter() continues
5. AuthorizationFilter checks: hasRole("ADMIN") → FAILS
6. Throws AccessDeniedException
7. ExceptionTranslationFilter catches it
8. Is alice anonymous? NO — she is authenticated
9. Calls AccessDeniedHandler.handle()
10. Default: response.sendError(403)
Result: HTTP 403 Forbidden
```

This is the 401 vs 403 distinction in practice. Alice was authenticated (Basic worked) but not authorized (wrong role) → 403, not 401.

---

**Q8 (Filter Order Prediction):**

When both `BasicAuthenticationFilter` and `UsernamePasswordAuthenticationFilter` are active, and a request comes in with BOTH a `Authorization: Basic ...` header AND as a POST to `/login` — which filter processes it?

**Answer:**
`UsernamePasswordAuthenticationFilter` runs first (order ~800) before `BasicAuthenticationFilter` (order ~900). The form login filter intercepts POST `/login` first. After setting the `SecurityContext`, `BasicAuthenticationFilter` sees an already-authenticated context and **skips processing** (because of the `SecurityContext` check at the start). The Basic header is effectively ignored.

---

## 4️⃣ Trick Analysis

---

**Trick 1 — 401 vs 403 — The definitive REST API decision**

```
Unauthenticated request (no credentials, or bad credentials):
     └──► AuthenticationException
               └──► ExceptionTranslationFilter
                         └──► AuthenticationEntryPoint.commence()
                                   └──► 401 Unauthorized
                                         + WWW-Authenticate: Basic realm="..."

Authenticated request (valid credentials) but insufficient role:
     └──► AccessDeniedException
               └──► ExceptionTranslationFilter
                         └──► User is anonymous? YES → AuthenticationEntryPoint (401)
                         └──► User is authenticated? YES → AccessDeniedHandler (403)
```

**The anonymous trap:** If you use `AnonymousAuthenticationFilter` (always active by default), an unauthenticated request still has an `Authentication` object (anonymous token). But `ExceptionTranslationFilter` specifically checks `instanceof AnonymousAuthenticationToken` to decide between 401 and 403 paths.

---

**Trick 2 — Form Login Entry Point Overrides Basic Entry Point**

When both are configured without explicit entry point:

```java
http
    .httpBasic(Customizer.withDefaults())   // registers BasicAuthenticationEntryPoint
    .formLogin(Customizer.withDefaults());  // registers LoginUrlAuthenticationEntryPoint
                                            // ← This WINS as the default
```

For a pure REST API that accidentally has `.formLogin()` in the config, unauthenticated requests get 302 redirects to `/login` instead of 401 responses. This breaks all API clients that don't follow redirects.

---

**Trick 3 — `OncePerRequestFilter` vs Re-entry**

`BasicAuthenticationFilter` extends `OncePerRequestFilter`. This means it sets a request attribute marking itself as executed:
```
"FILTER_CLASS_NAME.FILTERED" = true
```

On a forward (`RequestDispatcher.forward()`), the filter does NOT re-execute because the attribute already exists. This is important in Spring MVC error forwarding — if an error handler forwards a request, the Basic filter won't try to re-authenticate.

---

**Trick 4 — Security Context Check at Filter Start**

```java
// BasicAuthenticationFilter internal check:
if (SecurityContextHolder.getContext().getAuthentication() != null
        && SecurityContextHolder.getContext().getAuthentication().isAuthenticated()) {
    // Skip — already authenticated
    chain.doFilter(request, response);
    return;
}
```

This means if `RememberMeAuthenticationFilter` (which runs before Basic) has already set an authenticated token, `BasicAuthenticationFilter` skips entirely — even if an `Authorization: Basic` header is present. The first authentication wins.

---

**Trick 5 — Digest Auth Server-Side Password Storage Requirement**

A common exam question: "Why can't you use BCrypt with Digest authentication?"

Answer: Digest requires the server to compute `MD5(username:realm:password)` to verify the client's digest. To do this, the server needs the **raw plaintext password**. BCrypt is a one-way function — you cannot recover the plaintext. Therefore Digest authentication is fundamentally incompatible with one-way password hashing. This is a primary reason Digest is considered obsolete.

---

**Trick 6 — `WWW-Authenticate` header absence = browser won't show dialog**

If your `AuthenticationEntryPoint` sends 401 but forgets the `WWW-Authenticate` header, browsers will NOT show their native credentials dialog. They'll just display the 401 error response body. The header is what triggers the browser's built-in Basic auth prompt.

```java
// Missing WWW-Authenticate = browser shows error, no dialog
response.sendError(401);  // ← Missing header

// Correct
response.setHeader("WWW-Authenticate", "Basic realm=\"App\"");
response.sendError(401);
```

---

**Trick 7 — Base64 decoding failure handling**

What happens if the `Authorization` header contains malformed Base64?

```
Authorization: Basic @@@@INVALID@@@@
```

Spring Security's `BasicAuthenticationFilter` catches the `IllegalArgumentException` from Base64 decoding and calls the `AuthenticationEntryPoint` with a custom exception — it does NOT propagate as a 500 error. The client gets a clean 401 response.

---

## 5️⃣ Summary Sheet

---

### BasicAuthenticationFilter Execution Diagram

```
Request (with/without Authorization header)
     │
     ▼
BasicAuthenticationFilter.doFilterInternal()
     │
     ├──[SecurityContext already authenticated?]──YES──► chain.doFilter() (skip)
     │
     ├──[No Authorization header / not Basic?]────YES──► chain.doFilter() (pass through)
     │
     ├── Decode Base64 → username:password
     ├── Build UPAuthToken(username, password, authenticated=false)
     │
     ├── AuthenticationManager.authenticate(token)
     │         │
     │         ├── SUCCESS:
     │         │       SecurityContextHolder.setAuthentication()
     │         │       SecurityContextRepository.saveContext()
     │         │       chain.doFilter()  ──► Controller ──► 200 OK
     │         │
     │         └── FAILURE (AuthenticationException):
     │                 SecurityContextHolder.clearContext()
     │                 AuthenticationEntryPoint.commence()
     │                       └──► 401 + WWW-Authenticate header
```

---

### Form Login vs HTTP Basic — Architecture Comparison

| Aspect | Form Login | HTTP Basic |
|--------|-----------|-----------|
| Base class | `AbstractAuthenticationProcessingFilter` | `OncePerRequestFilter` |
| Trigger | Specific POST URL | Any request with `Authorization` header |
| Failure response | 302 redirect | 401 + `WWW-Authenticate` |
| Success response | 302 redirect | Pass-through to resource |
| Session use | Typically stateful | Typically stateless |
| Credential format | Form parameters | Base64 in header |
| Browser UI | HTML form | Native popup dialog |
| CSRF needed | YES (POST form) | NO (stateless) |
| Entry point | `LoginUrlAuthenticationEntryPoint` | `BasicAuthenticationEntryPoint` |

---

### 401 vs 403 — Complete Decision Tree

```
Exception thrown by AuthorizationFilter or method security
     │
     ▼
ExceptionTranslationFilter catches it
     │
     ├──[AuthenticationException]──────────────────────────────────────────────────────┐
     │                                                                                  │
     └──[AccessDeniedException]                                                         │
               │                                                                        │
               ├──[Principal is AnonymousAuthenticationToken?]──YES──────────────────── ┤
               │                                                                        │
               └──[Principal is real authenticated user?]──YES──► AccessDeniedHandler  │
                                                                       └──► 403         │
                                                                                        ▼
                                                               AuthenticationEntryPoint
                                                               Basic: 401 + WWW-Auth header
                                                               Form:  302 → /login
```

---

### Key Classes Reference

| Class | Role |
|-------|------|
| `BasicAuthenticationFilter` | Extracts + validates Basic credentials per request |
| `BasicAuthenticationEntryPoint` | Sends 401 + `WWW-Authenticate` header |
| `JsonAuthenticationEntryPoint` | Custom: sends JSON 401 body |
| `AccessDeniedHandler` | Handles 403 for authenticated users |
| `OncePerRequestFilter` | Base class: runs exactly once per request |
| `NullSecurityContextRepository` | Used with `STATELESS` — never saves context |
| `HttpSessionSecurityContextRepository` | Saves context to HTTP session |

---

### Digest Auth — Why It's Dead

| Problem | Reason |
|---------|--------|
| Requires plaintext password storage | Incompatible with BCrypt/one-way hashing |
| Uses MD5 | Cryptographically broken |
| Replay attacks | Nonce management is complex and often weak |
| HTTPS makes it redundant | TLS solves eavesdropping — Digest's original problem |
| Removed in Spring Security 6.x | `DigestAuthenticationFilter` deleted |

---

### Common Interview One-Liners

- **Basic Auth** sends credentials as Base64 — **not encrypted** — always use with HTTPS
- **`BasicAuthenticationFilter`** skips if `SecurityContext` already has authenticated token
- **Authentication failure** in Basic Auth = **401**, not 302 (unlike form login)
- **Form login + Basic together**: form login entry point wins → unexpected 302 for API clients
- **Stateless Basic** = BCrypt on every request = severe performance bottleneck at scale
- **Digest Auth** requires plaintext passwords → incompatible with BCrypt → obsolete
- **`WWW-Authenticate` header** is what triggers browser native credentials dialog
- **`OncePerRequestFilter`** prevents double-execution on forwards/includes
- **403 vs 401**: authenticated + wrong role = 403; not authenticated (or anonymous) = 401
- **`AccessDeniedHandler`** handles 403; **`AuthenticationEntryPoint`** handles 401

---
