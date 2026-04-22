# TOPIC 8 — Exception Translation & Handling

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

---

## 1️⃣ Conceptual Explanation

---

### 8.1 Why Exception Translation Exists — The Architecture Problem

Spring Security operates across two completely different execution contexts:

```
Context 1 — Servlet Filter Layer
     Exceptions thrown here are raw Java exceptions
     The Servlet container handles them (500 error page by default)
     Spring MVC @ExceptionHandler does NOT apply here
     ExceptionTranslationFilter is the ONLY handler

Context 2 — Spring MVC / Method Security Layer
     Exceptions thrown here reach Spring MVC's DispatcherServlet
     @ExceptionHandler, @ControllerAdvice CAN handle them
     BUT ExceptionTranslationFilter may also be involved
     (if exception propagates back up the filter chain)
```

**The problem without `ExceptionTranslationFilter`:**

```
AuthorizationFilter throws AccessDeniedException
     │
     Without ExceptionTranslationFilter:
     ▼
Servlet Container catches raw exception
     └── Returns: HTTP 500 Internal Server Error
                  (with ugly stack trace or generic error page)

     With ExceptionTranslationFilter:
     ▼
ExceptionTranslationFilter catches it
     └── Translates to meaningful HTTP response:
               401 Unauthorized (unauthenticated)
               302 Redirect to login (form login)
               403 Forbidden (authorized but insufficient privileges)
```

**The core mission of `ExceptionTranslationFilter`:** Convert Spring Security's internal exception types (`AuthenticationException`, `AccessDeniedException`) into proper HTTP responses using pluggable handlers.

---

### 8.2 ExceptionTranslationFilter — Exact Position and Architecture

**Position in filter chain:** Order ~1500 — directly **before** `AuthorizationFilter` (order ~1600).

**This positioning is architecturally intentional:**

```
Filter Chain:
     ...
     AnonymousAuthenticationFilter (1300)
     ExceptionTranslationFilter    (1500)  ← wraps the rest in try-catch
     AuthorizationFilter           (1600)  ← the exception THROWER
     ─────────────────────────────────────
     DispatcherServlet             (not a filter — the Servlet)
```

`ExceptionTranslationFilter` wraps the remainder of the filter chain execution in a `try-catch` block. `AuthorizationFilter` (and any filter/code that runs after `ExceptionTranslationFilter`) throws exceptions that are caught and handled here.

---

### 8.3 ExceptionTranslationFilter — Complete Internal Source Architecture

```java
public class ExceptionTranslationFilter extends GenericFilterBean
        implements MessageSourceAware {

    private AccessDeniedHandler accessDeniedHandler;
    private AuthenticationEntryPoint authenticationEntryPoint;
    private AuthenticationTrustResolver authenticationTrustResolver
        = new AuthenticationTrustResolverImpl();
    private ThrowableAnalyzer throwableAnalyzer = new DefaultThrowableAnalyzer();
    private RequestCache requestCache = new HttpSessionRequestCache();

    @Override
    public void doFilter(ServletRequest request, ServletResponse response,
            FilterChain chain) throws IOException, ServletException {
        doFilter((HttpServletRequest) request,
                 (HttpServletResponse) response, chain);
    }

    private void doFilter(HttpServletRequest request,
            HttpServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        try {
            // ← Everything AFTER this filter runs inside the try block
            chain.doFilter(request, response);

        } catch (IOException ex) {
            // IOException: re-throw — not a security exception
            throw ex;

        } catch (Exception ex) {
            // ← Catches ALL exceptions from downstream filters

            // Step 1: Unwrap nested exceptions to find root cause
            // (Spring MVC wraps exceptions in ServletException sometimes)
            Throwable[] causeChain = throwableAnalyzer.determineCauseChain(ex);

            // Step 2: Look for AuthenticationException in cause chain
            RuntimeException securityException =
                (AuthenticationException) throwableAnalyzer
                    .getFirstThrowableOfType(
                        AuthenticationException.class, causeChain);

            if (securityException == null) {
                // Step 3: Look for AccessDeniedException in cause chain
                securityException =
                    (AccessDeniedException) throwableAnalyzer
                        .getFirstThrowableOfType(
                            AccessDeniedException.class, causeChain);
            }

            if (securityException == null) {
                // Not a security exception — rethrow as-is
                rethrow(ex);
            }

            if (response.isCommitted()) {
                // Response already started (headers sent) — cannot modify
                // Log warning and rethrow
                throw new ServletException("Unable to handle the Spring " +
                    "Security Exception because the response is already " +
                    "committed.", ex);
            }

            // Step 4: Route to correct handler
            handleSpringSecurityException(request, response, chain,
                securityException);
        }
    }

    private void handleSpringSecurityException(HttpServletRequest request,
            HttpServletResponse response, FilterChain chain,
            RuntimeException exception) throws IOException, ServletException {

        if (exception instanceof AuthenticationException authException) {
            // ─── PATH A: Authentication Exception ─────────────────────
            handleAuthenticationException(request, response,
                chain, authException);

        } else if (exception instanceof AccessDeniedException accessDeniedException) {
            // ─── PATH B: Access Denied Exception ──────────────────────
            handleAccessDeniedException(request, response,
                chain, accessDeniedException);
        }
    }

    private void handleAuthenticationException(HttpServletRequest request,
            HttpServletResponse response, FilterChain chain,
            AuthenticationException exception) throws ServletException, IOException {

        // Always: save request, send to entry point
        sendStartAuthentication(request, response, chain, exception);
    }

    private void handleAccessDeniedException(HttpServletRequest request,
            HttpServletResponse response, FilterChain chain,
            AccessDeniedException exception) throws ServletException, IOException {

        Authentication authentication =
            SecurityContextHolder.getContext().getAuthentication();

        // THE CORE 401 vs 403 DECISION:
        if (authenticationTrustResolver.isAnonymous(authentication)
                || authenticationTrustResolver.isRememberMe(authentication)) {

            // Anonymous or remember-me → not fully authenticated
            // → Treat as authentication failure → PATH A behavior
            sendStartAuthentication(request, response, chain,
                new InsufficientAuthenticationException(
                    this.messages.getMessage(
                        "ExceptionTranslationFilter.insufficientAuthentication",
                        "Full authentication is required to access this resource")));

        } else {
            // Fully authenticated but insufficient privileges → 403
            this.accessDeniedHandler.handle(request, response, exception);
        }
    }

    protected void sendStartAuthentication(HttpServletRequest request,
            HttpServletResponse response, FilterChain chain,
            AuthenticationException reason) throws ServletException, IOException {

        // Clear any partial authentication from context
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        SecurityContextHolder.setContext(context);

        // Save the original request for redirect-after-login
        this.requestCache.saveRequest(request, response);

        // Delegate to AuthenticationEntryPoint
        this.authenticationEntryPoint.commence(request, response, reason);
    }
}
```

**The `ThrowableAnalyzer` — unwrapping nested exceptions:**

This is subtle but important. Exceptions can be wrapped:

```
ServletException
     └── cause: InvocationTargetException
                    └── cause: AccessDeniedException  ← the real one

ThrowableAnalyzer.determineCauseChain() unwraps all layers
ThrowableAnalyzer.getFirstThrowableOfType(AccessDeniedException.class, chain)
     └── Finds AccessDeniedException even deeply nested
```

This is why `@PreAuthorize` exceptions from method security (which propagate through Spring MVC's proxy infrastructure) are correctly caught — they may be several layers deep.

---

### 8.4 The 401 vs 403 Decision — Complete Decision Tree

This is one of the most tested concepts in Spring Security:

```
Exception reaches ExceptionTranslationFilter
     │
     ├──► instanceof AuthenticationException?
     │         YES:
     │         └──► sendStartAuthentication()
     │                   ├── Form login → 302 redirect to /login
     │                   ├── HTTP Basic → 401 + WWW-Authenticate header
     │                   ├── REST/JWT  → 401 JSON response
     │                   └── No entry point → 403 (Http403ForbiddenEntryPoint)
     │
     └──► instanceof AccessDeniedException?
               YES:
               └──► Check current Authentication:
                         │
                         ├──► isAnonymous(auth) == true?
                         │         YES → sendStartAuthentication()
                         │                   (same as above — 401 / redirect)
                         │
                         ├──► isRememberMe(auth) == true?
                         │         YES → sendStartAuthentication()
                         │                   (same as above — 401 / redirect)
                         │                   [requires full authentication]
                         │
                         └──► Fully authenticated user?
                                   YES → accessDeniedHandler.handle()
                                             └──► 403 Forbidden
```

**The remember-me → 401 behavior:**

This surprises many developers. Even a **remember-me authenticated user** getting `AccessDeniedException` results in the `sendStartAuthentication()` path (401/redirect), not 403. The reasoning: remember-me is not "full authentication" — the user never proved their identity interactively in this session. For sensitive operations, the system demands full re-authentication.

```java
// Example triggering this:
@PreAuthorize("isFullyAuthenticated()")
public void changePasword() { ... }

// Called by remember-me user:
// → AccessDeniedException
// → ExceptionTranslationFilter: isRememberMe() = true
// → sendStartAuthentication() → redirect to login
// NOT 403 — because user needs to fully authenticate
```

---

### 8.5 AuthenticationEntryPoint — Deep Architecture

`AuthenticationEntryPoint` is called when authentication is required but not present (or insufficient). It is the component that tells the client "you need to authenticate."

```java
public interface AuthenticationEntryPoint {
    void commence(
        HttpServletRequest request,
        HttpServletResponse response,
        AuthenticationException authException
    ) throws IOException, ServletException;
}
```

**Built-in implementations:**

```
AuthenticationEntryPoint (interface)
     │
     ├── LoginUrlAuthenticationEntryPoint
     │       Purpose: Form login redirect
     │       Behavior: response.sendRedirect("/login")
     │       Used by: formLogin() configurer
     │
     ├── BasicAuthenticationEntryPoint
     │       Purpose: HTTP Basic challenge
     │       Behavior: response.setHeader("WWW-Authenticate", "Basic realm=...")
     │                 response.sendError(401)
     │       Used by: httpBasic() configurer
     │
     ├── BearerTokenAuthenticationEntryPoint
     │       Purpose: OAuth2 Bearer token challenge
     │       Behavior: response.setHeader("WWW-Authenticate", "Bearer error=...")
     │                 response.sendError(401)
     │       Used by: oauth2ResourceServer() configurer
     │
     ├── Http403ForbiddenEntryPoint
     │       Purpose: Default when no other entry point configured
     │       Behavior: response.sendError(403)
     │       Note: Returns 403 even for unauthenticated! (historical behavior)
     │
     ├── HttpStatusEntryPoint
     │       Purpose: Simple HTTP status response
     │       Behavior: response.setStatus(statusCode)
     │       Commonly used for: 401 for REST APIs
     │
     └── DelegatingAuthenticationEntryPoint
             Purpose: Route to different entry points based on request
             Behavior: Checks RequestMatcher → delegates to matching entry point
             Use case: Form login for browsers, 401 for API clients
```

---

### 8.6 AccessDeniedHandler — Deep Architecture

`AccessDeniedHandler` is called when a **fully authenticated** user is denied access (insufficient privileges → 403).

```java
public interface AccessDeniedHandler {
    void handle(
        HttpServletRequest request,
        HttpServletResponse response,
        AccessDeniedException accessDeniedException
    ) throws IOException, ServletException;
}
```

**Built-in implementations:**

```
AccessDeniedHandler (interface)
     │
     ├── AccessDeniedHandlerImpl (default)
     │       Behavior: If errorPage configured → forward to error page
     │                 Otherwise → response.sendError(403)
     │
     └── InvalidSessionAccessDeniedHandler
             Purpose: For expired/invalid session scenarios
             Behavior: Redirects to session-expired URL
```

---

### 8.7 DelegatingAuthenticationEntryPoint — Multi-Strategy Routing

For applications that serve both browser clients and REST API clients, you need different behaviors:

```
Browser request → 302 redirect to /login
API request     → 401 JSON response
```

`DelegatingAuthenticationEntryPoint` enables this:

```java
// Routes entry point based on request characteristics
DelegatingAuthenticationEntryPoint delegating =
    new DelegatingAuthenticationEntryPoint(entryPoints);

// entryPoints is a LinkedHashMap<RequestMatcher, AuthenticationEntryPoint>
// First matching entry point is used
```

---

### 8.8 RequestCache — Saving the Original Request

When `sendStartAuthentication()` is called, the original request is saved in `RequestCache` before redirecting to login. After successful authentication, `SavedRequestAwareAuthenticationSuccessHandler` retrieves and redirects to it.

```
User requests /dashboard (unauthenticated)
     │
     ▼
ExceptionTranslationFilter.sendStartAuthentication()
     ├── requestCache.saveRequest(request, response)
     │       └── HttpSessionRequestCache saves:
     │               session.setAttribute(
     │                   "SPRING_SECURITY_SAVED_REQUEST",
     │                   new DefaultSavedRequest(request, portResolver))
     │           DefaultSavedRequest captures:
     │               - URL: /dashboard
     │               - Method: GET
     │               - Parameters
     │               - Headers
     │               - Cookies
     └── authenticationEntryPoint.commence() → redirect to /login

User logs in successfully
     │
     ▼
SavedRequestAwareAuthenticationSuccessHandler
     └── requestCache.getRequest(request, response)
             └── Returns saved /dashboard request
             └── Redirects to /dashboard
```

**`NullRequestCache` — disabling request saving:**

```java
// Disable request caching (for stateless APIs)
http.requestCache(cache -> cache
    .requestCache(new NullRequestCache())
);
// Prevents session creation just to save the request
// Required when using STATELESS session policy with form login
// (though STATELESS + form login is itself unusual)
```

---

### 8.9 Exception Propagation — Filter Chain vs Method Security

This is a critical architectural distinction:

**Scenario A — Exception from `AuthorizationFilter` (URL security):**

```
Request → ExceptionTranslationFilter (try-catch active)
               → AuthorizationFilter throws AccessDeniedException
                         │
                         ↑ caught by ExceptionTranslationFilter
                         └── handleAccessDeniedException()
                                   → 401 or 403 response
```

`ExceptionTranslationFilter` directly catches this.

---

**Scenario B — Exception from `@PreAuthorize` in Service (method security):**

```
Request → ExceptionTranslationFilter (try-catch active)
               → AuthorizationFilter (passes — URL access allowed)
                    → DispatcherServlet
                         → Controller
                              → Service (AOP proxy)
                                   → @PreAuthorize throws AccessDeniedException
                                             │
                                  ↑──────────┘ propagates up the call stack
                         ↑────────────────────┘ Spring MVC sees it
                         │
                         ├── @ExceptionHandler / @ControllerAdvice?
                         │       If defined: handles it → returns response
                         │       (ExceptionTranslationFilter never sees it)
                         │
                         └── No @ExceptionHandler?
                                 Propagates further up
                              ↑─────────────────────┘
                    Propagates through DispatcherServlet as 500
                         │
                    But DispatcherServlet re-throws as ServletException
                         │
                    ↑────┘ caught by ExceptionTranslationFilter
                    └── ThrowableAnalyzer unwraps → finds AccessDeniedException
                              → handleAccessDeniedException() → 401 or 403
```

**Key insight:** Method security exceptions can be handled by either:
1. `@ControllerAdvice` (if defined) — Spring MVC handles before filter layer
2. `ExceptionTranslationFilter` — if exception propagates all the way up

This means you may have **two places** handling the same exception type. Ensure they behave consistently.

---

### 8.10 Response Committed — The Silent Failure

A critical edge case:

```java
// Response committed = headers already sent to client
// HTTP protocol: once headers sent, you cannot change status code

response.getWriter().write("Some data...");  // ← Response started
// Now if AccessDeniedException is thrown:

ExceptionTranslationFilter:
     if (response.isCommitted()) {
         // CANNOT send 403 — headers already sent!
         throw new ServletException("Response already committed", ex);
         // Results in: broken response / connection reset
     }
```

This happens when:
- A filter or controller starts writing the response before authorization completes
- Streaming responses where first byte triggers commit
- Error occurs after response streaming begins

**Prevention:** Always complete authorization checks before writing response body.

---

### 8.11 Spring Security 5.x vs 6.x — Exception Handling Changes

| Aspect | Spring Security 5.x | Spring Security 6.x |
|--------|--------------------|--------------------|
| Core filter | `ExceptionTranslationFilter` | `ExceptionTranslationFilter` (unchanged) |
| Default CSRF failure | `AccessDeniedException` | `AccessDeniedException` (same) |
| Default entry point | `Http403ForbiddenEntryPoint` if none | Same |
| Custom handler DSL | `.exceptionHandling().accessDeniedHandler()` | `.exceptionHandling(ex -> ex.accessDeniedHandler(...))` |
| Authorization events | Not published | `AuthorizationDeniedEvent` published |
| `FilterSecurityInterceptor` | Throws `AccessDeniedException` | Replaced by `AuthorizationFilter` |

---

## 2️⃣ Code Examples

---

### Example 1 — Complete Exception Handling Configuration (6.x)

```java
@Configuration
@EnableWebSecurity
public class ExceptionHandlingConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/public/**").permitAll()
                .requestMatchers("/api/**").hasRole("USER")
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
            )
            .formLogin(form -> form
                .loginPage("/login")
                .permitAll()
            )
            .exceptionHandling(ex -> ex
                // Handles 401 — authentication required
                .authenticationEntryPoint(customAuthenticationEntryPoint())
                // Handles 403 — access denied for authenticated user
                .accessDeniedHandler(customAccessDeniedHandler())
                // Handles 403 for specific paths differently
                .defaultAccessDeniedHandlerFor(
                    apiAccessDeniedHandler(),
                    new AntPathRequestMatcher("/api/**"))
            );

        return http.build();
    }

    @Bean
    public AuthenticationEntryPoint customAuthenticationEntryPoint() {
        // Browser clients → redirect to login
        // API clients → 401 JSON
        LoginUrlAuthenticationEntryPoint loginEntryPoint =
            new LoginUrlAuthenticationEntryPoint("/login");

        HttpStatusEntryPoint apiEntryPoint =
            new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED);

        // Route based on request characteristics
        LinkedHashMap<RequestMatcher, AuthenticationEntryPoint> entryPoints =
            new LinkedHashMap<>();

        // API requests (Accept: application/json)
        entryPoints.put(
            new MediaTypeRequestMatcher(MediaType.APPLICATION_JSON),
            apiEntryPoint
        );

        DelegatingAuthenticationEntryPoint delegating =
            new DelegatingAuthenticationEntryPoint(entryPoints);

        // Default (browser requests)
        delegating.setDefaultEntryPoint(loginEntryPoint);

        return delegating;
    }

    @Bean
    public AccessDeniedHandler customAccessDeniedHandler() {
        AccessDeniedHandlerImpl handler = new AccessDeniedHandlerImpl();
        handler.setErrorPage("/error/403");  // forward to error page
        return handler;
    }

    @Bean
    public AccessDeniedHandler apiAccessDeniedHandler() {
        return (request, response, ex) -> {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.getWriter().write("""
                {
                    "status": 403,
                    "error": "Forbidden",
                    "message": "Insufficient privileges"
                }
                """);
        };
    }
}
```

---

### Example 2 — JSON AuthenticationEntryPoint for REST API

```java
@Component
public class RestAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final ObjectMapper objectMapper;

    @Override
    public void commence(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException authException) throws IOException {

        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("timestamp", Instant.now().toString());
        body.put("status",    401);
        body.put("error",     "Unauthorized");
        body.put("message",   resolveMessage(authException));
        body.put("path",      request.getRequestURI());

        objectMapper.writeValue(response.getOutputStream(), body);
    }

    private String resolveMessage(AuthenticationException ex) {
        // Provide user-friendly messages without exposing internals
        return switch (ex) {
            case BadCredentialsException e ->
                "Invalid credentials";
            case InsufficientAuthenticationException e ->
                "Full authentication is required to access this resource";
            case AccountExpiredException e ->
                "Account has expired";
            case LockedException e ->
                "Account is locked";
            default ->
                "Authentication is required";
        };
    }
}
```

---

### Example 3 — JSON AccessDeniedHandler for REST API

```java
@Component
public class RestAccessDeniedHandler implements AccessDeniedHandler {

    private final ObjectMapper objectMapper;

    @Override
    public void handle(
            HttpServletRequest request,
            HttpServletResponse response,
            AccessDeniedException accessDeniedException) throws IOException {

        // Log with user context for audit
        Authentication auth =
            SecurityContextHolder.getContext().getAuthentication();

        log.warn(
            "Access denied: user={}, uri={}, method={}",
            auth != null ? auth.getName() : "unknown",
            request.getRequestURI(),
            request.getMethod()
        );

        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        Map<String, Object> body = Map.of(
            "timestamp", Instant.now().toString(),
            "status",    403,
            "error",     "Forbidden",
            "message",   "You do not have permission to access this resource",
            "path",      request.getRequestURI()
        );

        objectMapper.writeValue(response.getOutputStream(), body);
    }
}
```

---

### Example 4 — DelegatingAuthenticationEntryPoint (Browser + API)

```java
@Bean
public AuthenticationEntryPoint delegatingEntryPoint() {

    // Different entry points for different client types
    LinkedHashMap<RequestMatcher, AuthenticationEntryPoint> map =
        new LinkedHashMap<>();

    // REST API clients that send Accept: application/json
    map.put(
        new MediaTypeRequestMatcher(MediaType.APPLICATION_JSON),
        new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)
    );

    // Requests to /api/** paths (regardless of Accept header)
    map.put(
        new AntPathRequestMatcher("/api/**"),
        restAuthenticationEntryPoint()
    );

    // XMLHttpRequest (AJAX from browser)
    map.put(
        new RequestHeaderRequestMatcher("X-Requested-With", "XMLHttpRequest"),
        new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)
    );

    DelegatingAuthenticationEntryPoint delegating =
        new DelegatingAuthenticationEntryPoint(map);

    // Default: form login redirect for browser navigation
    delegating.setDefaultEntryPoint(
        new LoginUrlAuthenticationEntryPoint("/login"));

    return delegating;
}
```

---

### Example 5 — @ControllerAdvice for Method Security Exceptions

```java
// Handles AccessDeniedException from @PreAuthorize at Spring MVC layer
// BEFORE it propagates to ExceptionTranslationFilter
@RestControllerAdvice
public class SecurityExceptionHandler {

    @ExceptionHandler(AccessDeniedException.class)
    @ResponseStatus(HttpStatus.FORBIDDEN)
    public Map<String, Object> handleAccessDenied(
            AccessDeniedException ex,
            HttpServletRequest request) {

        log.warn("Method security access denied: {}", ex.getMessage());

        return Map.of(
            "timestamp", Instant.now().toString(),
            "status",    403,
            "error",     "Forbidden",
            "message",   "You do not have the required permissions",
            "path",      request.getRequestURI()
        );
    }

    @ExceptionHandler(AuthenticationException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public Map<String, Object> handleAuthentication(
            AuthenticationException ex,
            HttpServletRequest request) {

        return Map.of(
            "timestamp", Instant.now().toString(),
            "status",    401,
            "error",     "Unauthorized",
            "message",   ex.getMessage(),
            "path",      request.getRequestURI()
        );
    }
}
```

**Important note:** When `@ControllerAdvice` handles `AccessDeniedException`, `ExceptionTranslationFilter` never sees it. The response is generated by Spring MVC directly. Ensure your `@ControllerAdvice` and `ExceptionTranslationFilter` produce consistent responses — having one return JSON 403 and the other returning an HTML 403 page for the same exception type creates inconsistency.

---

### Example 6 — Custom ExceptionTranslationFilter with Extended Behavior

```java
// Extending ExceptionTranslationFilter for audit logging
public class AuditingExceptionTranslationFilter
        extends ExceptionTranslationFilter {

    private final AuditService auditService;

    public AuditingExceptionTranslationFilter(
            AuthenticationEntryPoint entryPoint,
            AuditService auditService) {
        super(entryPoint);
        this.auditService = auditService;
    }

    @Override
    protected void sendStartAuthentication(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain chain,
            AuthenticationException reason) throws ServletException, IOException {

        // Audit unauthenticated access attempt
        auditService.recordUnauthenticatedAccess(
            request.getRequestURI(),
            request.getRemoteAddr(),
            reason.getMessage()
        );

        super.sendStartAuthentication(request, response, chain, reason);
    }
}
```

```java
// Register custom filter:
http.addFilterAt(
    new AuditingExceptionTranslationFilter(entryPoint, auditService),
    ExceptionTranslationFilter.class
);
```

---

### Example 7 — Incorrect Configurations & Common Bugs

```java
// ❌ WRONG 1 — Writing response before authorization check
@GetMapping("/data")
public void streamData(HttpServletResponse response) throws IOException {
    response.setContentType("text/plain");
    response.getWriter().write("Starting stream...");
    // ← Response COMMITTED here

    // If @PreAuthorize on a called service throws AccessDeniedException:
    // ExceptionTranslationFilter: response.isCommitted() = true
    // Cannot send 403 — connection broken!

    dataService.securedStreamOperation();  // might throw AccessDeniedException
}

// ✓ CORRECT — check authorization before writing
@GetMapping("/data")
@PreAuthorize("hasRole('USER')")  // checked BEFORE method body executes
public ResponseEntity<String> streamData() {
    return ResponseEntity.ok(dataService.getData());
}
```

```java
// ❌ WRONG 2 — Swallowing security exceptions in @ControllerAdvice
@ExceptionHandler(Exception.class)
public ResponseEntity<String> handleAll(Exception ex) {
    // This catches AccessDeniedException and AuthenticationException too!
    // Returns 200 OK with error message instead of 403/401
    return ResponseEntity.ok("An error occurred: " + ex.getMessage());
}

// ✓ CORRECT — let security exceptions propagate
@ExceptionHandler(Exception.class)
public ResponseEntity<String> handleAll(Exception ex) {
    // Re-throw security exceptions — let ExceptionTranslationFilter handle them
    if (ex instanceof AccessDeniedException
            || ex instanceof AuthenticationException) {
        throw (RuntimeException) ex;  // re-throw
    }
    return ResponseEntity.internalServerError()
        .body("An error occurred");
}
```

```java
// ❌ WRONG 3 — Configuring entry point inside httpBasic() but expecting
//             it to handle all 401s
http
    .httpBasic(basic -> basic
        .authenticationEntryPoint(basicEntryPoint())
    )
    .exceptionHandling(ex -> ex
        // This OVERRIDES the httpBasic entry point for all paths!
        .authenticationEntryPoint(jsonEntryPoint())
    );
// The exceptionHandling() entry point wins for ExceptionTranslationFilter
// The httpBasic() entry point is used by BasicAuthenticationFilter internally
// when credential extraction/verification fails

// ✓ CORRECT: configure entry point in exceptionHandling() only
http
    .httpBasic(Customizer.withDefaults())
    .exceptionHandling(ex -> ex
        .authenticationEntryPoint(jsonEntryPoint())  // handles all 401s
        .accessDeniedHandler(jsonDeniedHandler())    // handles all 403s
    );
```

---

## 3️⃣ Exam-Style Questions

---

**Q1 (MCQ):** What is the exact position of `ExceptionTranslationFilter` in the default Spring Security filter chain?

A. Before `AnonymousAuthenticationFilter`
B. Between `AnonymousAuthenticationFilter` and `AuthorizationFilter`
C. After `AuthorizationFilter`
D. Before `SecurityContextHolderFilter`

**Answer: B**
`ExceptionTranslationFilter` (order ~1500) sits between `AnonymousAuthenticationFilter` (~1300) and `AuthorizationFilter` (~1600). This positioning is deliberate — anonymous token must be set before the exception handler runs (so it can make the 401 vs 403 decision), and the authorization check must happen inside the try-catch block.

---

**Q2 (MCQ):** A fully authenticated user with `ROLE_USER` accesses `/admin/**` which requires `ROLE_ADMIN`. Which handler is invoked?

A. `AuthenticationEntryPoint`
B. `AccessDeniedHandler`
C. Both, in sequence
D. `Http403ForbiddenEntryPoint`

**Answer: B — `AccessDeniedHandler`**
The user IS fully authenticated (not anonymous, not remember-me). `AccessDeniedException` is thrown by `AuthorizationFilter`. `ExceptionTranslationFilter` checks `isAnonymous()` → false, `isRememberMe()` → false → routes to `AccessDeniedHandler` → 403.

---

**Q3 (Select All That Apply):** Which are true about `ExceptionTranslationFilter`?

A. It catches `IOException` and translates it to a security response
B. It uses `ThrowableAnalyzer` to unwrap nested exceptions
C. It saves the original request in `RequestCache` before redirecting to login
D. It calls `SecurityContextHolder.clearContext()` before invoking `AuthenticationEntryPoint`
E. It handles exceptions thrown by `@PreAuthorize` at the method security layer

**Answer: B, C, D, E**
A is false — `IOException` is explicitly re-thrown without handling. Only `AuthenticationException` and `AccessDeniedException` (and subclasses) are handled as security exceptions.

---

**Q4 (Scenario — Remember-Me Trap):**

```java
http.rememberMe(Customizer.withDefaults())
    .authorizeHttpRequests(auth -> auth
        .requestMatchers("/account/password-change")
            .fullyAuthenticated()
        .anyRequest().authenticated()
    );
```

A remember-me authenticated user accesses `/account/password-change`. Trace the complete exception flow and final response.

**Answer:**
```
1. Request arrives for /account/password-change
2. SecurityContextHolderFilter loads RememberMeAuthenticationToken from session
3. AnonymousAuthenticationFilter: auth already set → skips
4. ExceptionTranslationFilter: wraps rest in try-catch
5. AuthorizationFilter: .fullyAuthenticated()
   → isFullyAuthenticated() = !isAnonymous() && !isRememberMe()
   → isRememberMe() = true → NOT fully authenticated
   → AuthorizationDecision(false) → throws AccessDeniedException
6. ExceptionTranslationFilter catches AccessDeniedException
7. isAnonymous(auth)? NO (it's RememberMeAuthenticationToken)
8. isRememberMe(auth)? YES → sendStartAuthentication()
9. requestCache.saveRequest() → saves /account/password-change
10. authenticationEntryPoint.commence()
    → Form login configured → 302 redirect to /login
11. User logs in interactively → UsernamePasswordAuthenticationToken
12. SuccessHandler redirects to saved /account/password-change
13. Now fully authenticated → access granted
```
Final result: **302 redirect to /login**, not 403. User must re-authenticate interactively.

---

**Q5 (Code Prediction):**

```java
@RestControllerAdvice
public class GlobalExceptionHandler {
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<String> handleAccessDenied(AccessDeniedException ex) {
        return ResponseEntity.status(403).body("FORBIDDEN BY ADVICE");
    }
}
```

A user with `ROLE_USER` calls a method annotated with `@PreAuthorize("hasRole('ADMIN')")`. What response is returned?

A. `AccessDeniedHandler` configured in `exceptionHandling()` handles it → standard 403
B. `GlobalExceptionHandler` handles it → 403 with body "FORBIDDEN BY ADVICE"
C. `ExceptionTranslationFilter` handles it → 403
D. Depends on which runs first

**Answer: B**
`@ControllerAdvice` operates at the Spring MVC layer, which is "closer" to the exception origin. When `@PreAuthorize` throws `AccessDeniedException` inside a controller/service call, Spring MVC's `HandlerExceptionResolver` processes it via `@ControllerAdvice` BEFORE the exception propagates up to `ExceptionTranslationFilter`. The `@ControllerAdvice` response is returned directly.

---

**Q6 (HTTP Status Prediction):**

```java
// No formLogin, no httpBasic, no oauth2ResourceServer configured
http.authorizeHttpRequests(auth -> auth
    .anyRequest().authenticated()
);
```

An anonymous user requests any URL. What HTTP status is returned?

A. 401 Unauthorized
B. 302 redirect to `/login`
C. 403 Forbidden
D. 500 Internal Server Error

**Answer: C — 403 Forbidden**
This is the famous `Http403ForbiddenEntryPoint` trap. When no `AuthenticationEntryPoint` is explicitly configured AND no form login/httpBasic is set up, Spring Security defaults to `Http403ForbiddenEntryPoint`. Despite the name suggesting a handler for authenticated users, it is used as the default `AuthenticationEntryPoint` — returning **403** even for unauthenticated requests.

This counter-intuitive default exists for historical reasons. To get 401, explicitly configure:
```java
.exceptionHandling(ex -> ex
    .authenticationEntryPoint(
        new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)))
```

---

**Q7 (Exception Trace):**

```java
@Service
public class DataService {
    @PreAuthorize("hasRole('ADMIN')")
    public String getData() { return "data"; }
}

@RestController
public class DataController {
    @Autowired DataService dataService;

    @GetMapping("/data")
    public String getData() {
        return dataService.getData();
    }
}

// No @ControllerAdvice defined
// URL security: anyRequest().authenticated() (no admin check at URL level)
```

A user with `ROLE_USER` (fully authenticated) calls `GET /data`. Trace the COMPLETE exception path.

**Answer:**
```
1. Request arrives — GET /data
2. SecurityContextHolderFilter loads Authentication (ROLE_USER)
3. AuthorizationFilter: anyRequest().authenticated()
   → isAuthenticated() = true → GRANTED → passes
4. DispatcherServlet routes to DataController.getData()
5. DataController calls dataService.getData()
6. AOP Proxy intercepts: @PreAuthorize("hasRole('ADMIN')")
   → ROLE_USER does not have ROLE_ADMIN → false
   → throws AccessDeniedException
7. Exception propagates: DataController → DispatcherServlet
8. No @ExceptionHandler in @ControllerAdvice → Spring MVC cannot handle
9. DispatcherServlet wraps in NestedServletException (5.x) or re-throws (6.x)
10. ExceptionTranslationFilter catches it
11. ThrowableAnalyzer unwraps → finds AccessDeniedException
12. isAnonymous()? NO. isRememberMe()? NO. Fully authenticated? YES
13. accessDeniedHandler.handle() → response.sendError(403)
Result: HTTP 403 Forbidden
```

---

**Q8 (Filter Order + Exception Interaction):**

```java
@Component
public class MyFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest req,
            HttpServletResponse res, FilterChain chain) {
        throw new AccessDeniedException("Blocked by custom filter");
    }
}
```

```java
http.addFilterAfter(myFilter, ExceptionTranslationFilter.class);
```

What happens when any request arrives?

**Answer:**
`MyFilter` is placed **AFTER** `ExceptionTranslationFilter`. `ExceptionTranslationFilter`'s try-catch block wraps filters that run AFTER it in the chain. Since `MyFilter` runs after `ExceptionTranslationFilter`:

- `ExceptionTranslationFilter` sets up try-catch
- `chain.doFilter()` → eventually reaches `MyFilter`
- `MyFilter` throws `AccessDeniedException`
- Exception propagates back up the chain
- `ExceptionTranslationFilter` catches it ✓
- Current auth is anonymous → `sendStartAuthentication()` → 401/redirect

The filter is **after** `ExceptionTranslationFilter` so the exception IS caught and properly handled as a 403/401. If it were placed **before** `ExceptionTranslationFilter`, the exception would escape the try-catch and result in a 500.

---

## 4️⃣ Trick Analysis

---

**Trick 1 — `Http403ForbiddenEntryPoint` Returns 403 for Unauthenticated Users**

```
Most developers expect:
   Unauthenticated + no formLogin/httpBasic → 401

Actual Spring Security behavior:
   Unauthenticated + no formLogin/httpBasic → 403
   (via Http403ForbiddenEntryPoint default)

Why? Historical design decision — it's the "safe default"
     The name "403" is misleading — it's used as the AuthenticationEntryPoint

Fix:
http.exceptionHandling(ex -> ex
    .authenticationEntryPoint(
        new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)));
```

---

**Trick 2 — Remember-Me `AccessDeniedException` → 401, NOT 403**

```
Intuition: "User is authenticated (remember-me) → 403 for insufficient role"
Reality:   "Remember-me is NOT full authentication → 401 / redirect to login"

ExceptionTranslationFilter:
if (authenticationTrustResolver.isRememberMe(authentication)) {
    sendStartAuthentication(...)  // ← 401 path, not 403!
}

This is intentional: sensitive operations require re-authentication
```

---

**Trick 3 — `@ControllerAdvice` Intercepts Before `ExceptionTranslationFilter`**

```
Method security exception propagation path:

With @ControllerAdvice for AccessDeniedException:
     AOP proxy throws → DispatcherServlet → @ControllerAdvice handles
     → ExceptionTranslationFilter NEVER SEES IT

Without @ControllerAdvice:
     AOP proxy throws → DispatcherServlet → propagates up
     → ExceptionTranslationFilter catches and handles

TRAP: You have TWO places that might handle the same exception
      They may produce INCONSISTENT responses (different JSON format, etc.)

BEST PRACTICE: Handle in ONE place — either @ControllerAdvice OR
               ExceptionTranslationFilter, not both
```

---

**Trick 4 — Custom Filter Before `ExceptionTranslationFilter` Cannot Be Caught**

```java
// Custom filter throws AccessDeniedException:
http.addFilterBefore(myThrowingFilter, ExceptionTranslationFilter.class);

// myThrowingFilter throws BEFORE ExceptionTranslationFilter sets up try-catch
// → Exception escapes filter chain entirely
// → Servlet container handles it → 500 error page

// Only filters AFTER ExceptionTranslationFilter are inside the try-catch
```

---

**Trick 5 — `requestCache.saveRequest()` and STATELESS Sessions**

```java
// With STATELESS session policy:
http.sessionManagement(s -> s
    .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
.formLogin(Customizer.withDefaults());  // unusual but possible

// When ExceptionTranslationFilter calls requestCache.saveRequest():
// → HttpSessionRequestCache tries to save to session
// → But STATELESS policy prevents session creation!
// → Request is NOT saved
// → After login, user redirected to defaultSuccessUrl (not original URL)

// Fix: Use NullRequestCache
http.requestCache(cache -> cache.requestCache(new NullRequestCache()));
```

---

**Trick 6 — `response.isCommitted()` Silent Failure**

```
If response is already committed (headers sent) when security exception occurs:

ExceptionTranslationFilter:
     if (response.isCommitted()) {
         throw new ServletException("Unable to handle...", ex);
     }

Result:
- Client gets partial response + connection close
- No 401/403 sent
- Server logs: "Unable to handle the Spring Security Exception because
               the response is already committed"

This is NOT a Spring Security bug — HTTP protocol limitation
Prevention: Never write to response before all security checks complete
```

---

**Trick 7 — `ThrowableAnalyzer` Unwraps Nested Exceptions**

```java
// Spring MVC wraps exceptions in various ways:

// Without unwrapping, ExceptionTranslationFilter would see:
//   ServletException (caused by InvocationTargetException (caused by AccessDeniedException))
// And miss the real AccessDeniedException

// ThrowableAnalyzer.determineCauseChain() produces:
// [ServletException, InvocationTargetException, AccessDeniedException]

// getFirstThrowableOfType(AccessDeniedException.class, chain)
// → finds AccessDeniedException despite wrapping

// This is why method security AccessDeniedException works with ExceptionTranslationFilter
// even though it travels through many proxy layers
```

---

**Trick 8 — Multiple `exceptionHandling()` DSL Calls**

```java
// In 6.x Lambda DSL, calling exceptionHandling() twice:
http
    .exceptionHandling(ex -> ex
        .authenticationEntryPoint(entryPoint1()))
    .exceptionHandling(ex -> ex
        .accessDeniedHandler(handler1()));

// Is this valid? YES — in 6.x, each lambda call customizes the same
// ExceptionHandlingConfigurer. Both entry point and handler are set.
// This is DIFFERENT from 5.x where second call might reset the first.

// Safe to split for readability:
http.exceptionHandling(ex -> ex
    .authenticationEntryPoint(entryPoint1())
    .accessDeniedHandler(handler1())
);
```

---

## 5️⃣ Summary Sheet

---

### ExceptionTranslationFilter — Complete Architecture Diagram

```
  ┌─────────────────────────────────────────────────────────────────┐
  │                  ExceptionTranslationFilter                     │
  │                                                                 │
  │  try {                                                          │
  │      chain.doFilter(request, response)                         │
  │      ┌────────────────────────────────────────┐                │
  │      │     AuthorizationFilter                │                │
  │      │     (or downstream code)               │                │
  │      │     throws:                            │                │
  │      │     ├── AccessDeniedException          │                │
  │      │     └── AuthenticationException        │                │
  │      └────────────────────────────────────────┘                │
  │  } catch (Exception ex) {                                       │
  │      throwableAnalyzer.unwrap(ex)                              │
  │           │                                                     │
  │           ├── AuthenticationException?                          │
  │           │       └── sendStartAuthentication()                 │
  │           │               ├── requestCache.saveRequest()        │
  │           │               └── entryPoint.commence()            │
  │           │                       ├── Form: 302→/login         │
  │           │                       ├── Basic: 401+WWW-Auth      │
  │           │                       └── API: 401 JSON            │
  │           │                                                     │
  │           └── AccessDeniedException?                            │
  │                   │                                             │
  │                   ├── isAnonymous(auth)?    ─┐                  │
  │                   ├── isRememberMe(auth)?    ├─ sendStartAuth() │
  │                   │                         ─┘                  │
  │                   └── Fully authenticated?                      │
  │                           └── accessDeniedHandler.handle()      │
  │                                   └── 403 Forbidden             │
  │  }                                                              │
  └─────────────────────────────────────────────────────────────────┘
```

---

### 401 vs 403 — Definitive Reference

| Situation | Exception | Auth State | Handler | Response |
|-----------|-----------|------------|---------|----------|
| No credentials | `AccessDeniedException` | Anonymous | `AuthenticationEntryPoint` | 401 or redirect |
| Bad credentials | `AuthenticationException` | None | `AuthenticationEntryPoint` | 401 or redirect |
| Remember-me + sensitive op | `AccessDeniedException` | Remember-me | `AuthenticationEntryPoint` | 401 or redirect |
| Authenticated + wrong role | `AccessDeniedException` | Full auth | `AccessDeniedHandler` | 403 |
| No auth configured (default) | `AccessDeniedException` | Anonymous | `Http403ForbiddenEntryPoint` | **403** (trap!) |

---

### Built-in AuthenticationEntryPoint Reference

| Implementation | Behavior | Used By |
|---------------|----------|---------|
| `LoginUrlAuthenticationEntryPoint` | 302 → `/login` | `formLogin()` |
| `BasicAuthenticationEntryPoint` | 401 + `WWW-Authenticate: Basic` | `httpBasic()` |
| `BearerTokenAuthenticationEntryPoint` | 401 + `WWW-Authenticate: Bearer` | `oauth2ResourceServer()` |
| `Http403ForbiddenEntryPoint` | 403 | Default (no auth configured) |
| `HttpStatusEntryPoint` | Configured status code | Manual/REST APIs |
| `DelegatingAuthenticationEntryPoint` | Routes to matching entry point | Multi-client apps |

---

### Exception Flow — Method Security vs URL Security

```
URL Security (AuthorizationFilter):
     AccessDeniedException → directly in filter chain
     → ExceptionTranslationFilter catches → 401/403

Method Security (@PreAuthorize):
     AccessDeniedException → propagates through MVC layers
     → @ControllerAdvice? YES → handled there (ETF never sees it)
                          NO  → propagates to ETF → 401/403

Key: @ControllerAdvice intercepts FIRST for method security exceptions
     Only if not handled does ETF get involved
```

---

### Common Interview One-Liners

- **`ExceptionTranslationFilter` wraps `chain.doFilter()`** in try-catch — only catches downstream exceptions
- **`ThrowableAnalyzer`** unwraps nested exceptions — finds `AccessDeniedException` inside `ServletException`
- **Anonymous + `AccessDeniedException`** → `AuthenticationEntryPoint` (NOT `AccessDeniedHandler`)
- **Remember-me + `AccessDeniedException`** → `AuthenticationEntryPoint` (401/redirect, NOT 403)
- **`Http403ForbiddenEntryPoint`** is the default `AuthenticationEntryPoint` — returns 403 even for unauthenticated!
- **`response.isCommitted()`** = security exception cannot be translated — broken response
- **`@ControllerAdvice` intercepts method security exceptions BEFORE `ExceptionTranslationFilter`**
- **`requestCache.saveRequest()`** stores original URL before login redirect — enables redirect-after-login
- **Filters placed BEFORE `ExceptionTranslationFilter`** throw exceptions that escape the try-catch → 500
- **`AccessDeniedHandler`** handles 403; **`AuthenticationEntryPoint`** handles 401/redirect — never mixed up

---
