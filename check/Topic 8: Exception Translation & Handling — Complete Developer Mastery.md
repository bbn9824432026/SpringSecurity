# Topic 8: Exception Translation & Handling — Complete Developer Mastery

Exception handling is where Spring Security's internal machinery becomes visible to the outside world. Everything we've covered so far — authentication, authorization, anonymous tokens — produces exceptions when something goes wrong. This topic is about what happens to those exceptions: who catches them, how they're translated into HTTP responses, and why the translation logic is far more nuanced than a simple "throw 403 if access denied."

---

## Layer 1: The Architectural Problem — Two Execution Contexts

Before touching a single class, you need to understand why a dedicated exception translation mechanism exists at all. Spring Security operates across two fundamentally different execution contexts, and exceptions behave differently in each.

The first context is the servlet filter layer — the chain of filters that runs before your request reaches Spring MVC's `DispatcherServlet`. When a filter throws an exception here, Spring MVC's `@ExceptionHandler` and `@ControllerAdvice` cannot help you, because those mechanisms live *inside* the `DispatcherServlet` and the exception never gets that far. The servlet container itself would catch the raw exception and return a generic HTTP 500 error page.

The second context is the Spring MVC application layer — your controllers, services, and everything that runs inside `DispatcherServlet`. Exceptions here *can* be handled by `@ControllerAdvice`, but they can also propagate back up through the `DispatcherServlet` into the filter chain, where they eventually reach `ExceptionTranslationFilter`.

```
Filter Chain (Context 1):
     SecurityContextHolderFilter
     BasicAuthenticationFilter
     AnonymousAuthenticationFilter
     ExceptionTranslationFilter    ← the bridge between contexts
     AuthorizationFilter           ← throws here, inside the try-catch
     ─────────────────────────────
     DispatcherServlet (Context 2):
          Controller
               └── Service (@PreAuthorize throws here)
                        └── exception propagates back up...
                             ...through DispatcherServlet...
                              ...back into ExceptionTranslationFilter
```

`ExceptionTranslationFilter` is the bridge. It sits at the boundary of the two contexts, wraps everything downstream in a try-catch, and translates Spring Security's internal exception types into meaningful HTTP responses. Without it, your users would see raw 500 errors for every authentication failure and access denial.

---

## Layer 2: `ExceptionTranslationFilter` — The Complete Internal Architecture

Understanding the internal `doFilter()` logic reveals several non-obvious design decisions that explain the behavior you observe in production.

```java
/**
 * LAYER 2: ExceptionTranslationFilter — the complete execution template.
 *
 * Position in chain: order ~1500, between AnonymousAuthenticationFilter (~1300)
 * and AuthorizationFilter (~1600).
 *
 * The positioning is deliberate on both sides:
 *   - AFTER AnonymousAuthenticationFilter: the anonymous token must already
 *     be set when this filter makes the 401 vs 403 decision. It needs to
 *     call authenticationTrustResolver.isAnonymous(auth), which requires
 *     a non-null Authentication object.
 *   - BEFORE AuthorizationFilter: the authorization check must happen inside
 *     the try-catch block so exceptions can be caught and translated.
 */
public class ExceptionTranslationFilter extends GenericFilterBean {

    private AuthenticationEntryPoint authenticationEntryPoint;
    private AccessDeniedHandler accessDeniedHandler = new AccessDeniedHandlerImpl();
    private AuthenticationTrustResolver authenticationTrustResolver
        = new AuthenticationTrustResolverImpl();

    // Unwraps nested exceptions to find root cause (e.g., AccessDeniedException
    // wrapped inside InvocationTargetException wrapped inside NestedServletException)
    private ThrowableAnalyzer throwableAnalyzer = new DefaultThrowableAnalyzer();

    // Saves the original request before redirecting to login,
    // so the user can be sent back after successful authentication
    private RequestCache requestCache = new HttpSessionRequestCache();

    private void doFilter(HttpServletRequest request,
                          HttpServletResponse response,
                          FilterChain chain)
            throws IOException, ServletException {
        try {
            // Everything after this filter runs inside this try block.
            // AuthorizationFilter, DispatcherServlet, controllers, services —
            // any security exception from any of them lands here.
            chain.doFilter(request, response);

        } catch (IOException ex) {
            // IOExceptions are NOT security exceptions — re-throw immediately.
            // This is intentional: broken connections, write failures, etc.
            // should not be swallowed by the security layer.
            throw ex;

        } catch (Exception ex) {
            // Step 1: Unwrap. Spring's proxy infrastructure and servlet container
            // often wrap exceptions in other exceptions. ThrowableAnalyzer
            // traverses the entire cause chain to find the root security exception.
            // Without this, a @PreAuthorize AccessDeniedException wrapped inside
            // three layers of proxy wrappers would be missed entirely.
            Throwable[] causeChain = throwableAnalyzer.determineCauseChain(ex);

            // Step 2: Look for AuthenticationException first
            RuntimeException securityException =
                (AuthenticationException) throwableAnalyzer.getFirstThrowableOfType(
                    AuthenticationException.class, causeChain);

            if (securityException == null) {
                // Step 3: Then look for AccessDeniedException
                securityException =
                    (AccessDeniedException) throwableAnalyzer.getFirstThrowableOfType(
                        AccessDeniedException.class, causeChain);
            }

            if (securityException == null) {
                // Not a security exception at all — rethrow unchanged.
                // NullPointerExceptions, IllegalStateExceptions, etc. pass through.
                rethrow(ex);
                return;
            }

            if (response.isCommitted()) {
                // Headers already sent to client — HTTP protocol won't allow us
                // to change the status code or add headers now. This is a fatal
                // situation: we cannot send a 401 or 403. The best we can do is
                // log and throw, which typically causes a broken connection.
                // Prevention: never start writing the response before security checks complete.
                throw new ServletException(
                    "Unable to handle the Spring Security Exception " +
                    "because the response is already committed.", ex);
            }

            // Step 4: Route to the correct handler based on exception type
            handleSpringSecurityException(request, response, chain, securityException);
        }
    }

    /**
     * THE 401 vs 403 ROUTING DECISION — the most important logic in this filter.
     *
     * This method is what the entire anonymous authentication topic (Topic 4) was
     * building toward. The AnonymousAuthenticationToken exists precisely so that
     * this code can make a type-safe routing decision rather than checking for null.
     */
    private void handleSpringSecurityException(HttpServletRequest request,
                                                HttpServletResponse response,
                                                FilterChain chain,
                                                RuntimeException exception)
            throws IOException, ServletException {

        if (exception instanceof AuthenticationException authException) {
            // PATH A: Identity claim itself is broken (bad credentials, expired token, etc.)
            // Always routes to AuthenticationEntryPoint → ask client to authenticate
            sendStartAuthentication(request, response, chain, authException);

        } else if (exception instanceof AccessDeniedException accessDenied) {
            // PATH B: Access was denied — but WHY? Need to inspect the current auth.
            Authentication authentication =
                SecurityContextHolder.getContext().getAuthentication();

            if (authenticationTrustResolver.isAnonymous(authentication)
                    || authenticationTrustResolver.isRememberMe(authentication)) {
                // Anonymous users and remember-me users are treated as
                // "not sufficiently authenticated" — they need to log in.
                // This is why remember-me users get redirected to login
                // when accessing sensitive endpoints, NOT a 403.
                sendStartAuthentication(request, response, chain,
                    new InsufficientAuthenticationException(
                        "Full authentication is required to access this resource"));
            } else {
                // Fully authenticated user with insufficient privileges → 403
                this.accessDeniedHandler.handle(request, response, accessDenied);
            }
        }
    }

    protected void sendStartAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain chain,
                                            AuthenticationException reason)
            throws ServletException, IOException {
        // Clear any partial security context — clean slate before re-authentication
        SecurityContextHolder.clearContext();

        // Save the request the user was trying to make. After they log in,
        // SavedRequestAwareAuthenticationSuccessHandler will retrieve this
        // and redirect them back to their original destination.
        this.requestCache.saveRequest(request, response);

        // Tell the client how to authenticate
        this.authenticationEntryPoint.commence(request, response, reason);
    }
}
```

The `ThrowableAnalyzer` step is worth pausing on, because it explains something that many developers find mysterious: why do `@PreAuthorize` exceptions get caught by `ExceptionTranslationFilter` even though they originate deep inside a service call? The answer is that when an AOP proxy throws `AccessDeniedException` inside a Spring MVC controller call, that exception travels back up through multiple proxy layers, through `DispatcherServlet`, and arrives at `ExceptionTranslationFilter` wrapped inside other exceptions. The `ThrowableAnalyzer` unwraps all those layers to find the original `AccessDeniedException` at the root.

---

## Layer 3: The 401 vs 403 Decision — The Complete Decision Tree

This is the most examined concept in this entire topic, and the answer is genuinely surprising in several edge cases. Let me build the decision tree from first principles.

The key insight is that `ExceptionTranslationFilter` doesn't simply map exception types to HTTP status codes. It makes a *semantic* distinction: is the client asking for something they're not allowed to access *because they haven't identified themselves*, or *because they're identified but lack permission*? The former demands authentication (401), the latter reports a permission failure (403).

```
Any security exception bubbles up to ExceptionTranslationFilter
     │
     ├── instanceof AuthenticationException?
     │       YES → The identity claim itself failed.
     │             Always call AuthenticationEntryPoint.
     │             Form login  → 302 redirect to /login
     │             HTTP Basic  → 401 + WWW-Authenticate header
     │             REST/JWT    → 401 JSON response
     │             No config   → 403 (Http403ForbiddenEntryPoint — the trap!)
     │
     └── instanceof AccessDeniedException?
               YES → Access was denied. WHO is this person?
                     │
                     ├── isAnonymous(auth)?
                     │       YES → They haven't identified themselves.
                     │             Treat as authentication failure.
                     │             → Same as AuthenticationException path above
                     │             (401 or redirect, NOT 403)
                     │
                     ├── isRememberMe(auth)?
                     │       YES → They're cookie-authenticated, but that's
                     │             not "full" authentication. For sensitive ops,
                     │             demand interactive login.
                     │             → Same as AuthenticationException path
                     │             (401 or redirect, NOT 403)
                     │
                     └── Fully authenticated user?
                               YES → They proved who they are, but lack the
                                     required role/permission.
                                     → AccessDeniedHandler → 403 Forbidden
```

The remember-me case is the one that surprises most developers. Intuitively, "the user is authenticated, so a permission failure should be 403." But Spring Security's design philosophy says remember-me is a weaker form of authentication — the user never *interactively* proved their identity in this session. For sensitive operations like changing a password, this distinction matters enormously, and routing to the login page (with the original request saved for after login) is the correct behavior.

---

## Layer 4: `AuthenticationEntryPoint` — The "How To Authenticate" Contract

```java
/**
 * LAYER 4: AuthenticationEntryPoint — answers "how should this client authenticate?"
 *
 * This interface is called in two situations:
 *   1. Directly when authentication fails (AuthenticationException)
 *   2. Indirectly when an unauthenticated/remember-me user gets AccessDeniedException
 *      (via sendStartAuthentication())
 *
 * The implementation determines the HTTP response that tells the client
 * what to do next — redirect to a form, present an HTTP Basic dialog,
 * return a JSON 401, etc.
 */
public interface AuthenticationEntryPoint {
    void commence(HttpServletRequest request,
                  HttpServletResponse response,
                  AuthenticationException authException)
            throws IOException, ServletException;
}

// ─── Production REST API implementation ─────────────────────────────────────
/**
 * For REST/SPA clients, JSON is more useful than either a redirect or
 * plain text "Unauthorized". This implementation returns a structured
 * JSON body that API clients can parse and display meaningfully.
 *
 * Notice we provide user-friendly messages that don't expose internal details
 * about your user storage strategy or authentication mechanism.
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
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());

        // Build structured error response — consistent with your API's error format
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("timestamp", Instant.now().toString());
        body.put("status",    401);
        body.put("error",     "Unauthorized");
        body.put("message",   resolveUserFriendlyMessage(authException));
        body.put("path",      request.getRequestURI());

        objectMapper.writeValue(response.getOutputStream(), body);
    }

    private String resolveUserFriendlyMessage(AuthenticationException ex) {
        // Map specific exception types to messages the user can act on,
        // without revealing implementation details (e.g., don't say
        // "user not found in LDAP directory" — just "invalid credentials")
        return switch (ex) {
            case BadCredentialsException e ->
                "Invalid username or password";
            case InsufficientAuthenticationException e ->
                "Please log in to access this resource";
            case AccountExpiredException e ->
                "Your account has expired — please contact support";
            case LockedException e ->
                "Your account is temporarily locked";
            case DisabledException e ->
                "Your account has been disabled";
            default ->
                "Authentication is required to access this resource";
        };
    }
}

// ─── DelegatingAuthenticationEntryPoint — multi-client routing ───────────────
/**
 * Real applications often serve both browser users (who should get a login
 * page redirect) and API clients (who should get a JSON 401). This delegate
 * routes to different entry points based on the request's characteristics.
 *
 * The map is evaluated in insertion order — first matching entry point wins.
 * The default entry point handles everything that doesn't match.
 */
@Bean
public AuthenticationEntryPoint multiClientEntryPoint(
        RestAuthenticationEntryPoint restEntryPoint) {

    LinkedHashMap<RequestMatcher, AuthenticationEntryPoint> entryPoints =
        new LinkedHashMap<>();

    // API requests by path
    entryPoints.put(
        new AntPathRequestMatcher("/api/**"),
        restEntryPoint  // → JSON 401
    );

    // Any request that says it accepts JSON (includes most REST clients)
    entryPoints.put(
        new MediaTypeRequestMatcher(MediaType.APPLICATION_JSON),
        restEntryPoint  // → JSON 401
    );

    // AJAX requests from browsers
    entryPoints.put(
        new RequestHeaderRequestMatcher("X-Requested-With", "XMLHttpRequest"),
        new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)  // → bare 401
    );

    DelegatingAuthenticationEntryPoint delegating =
        new DelegatingAuthenticationEntryPoint(entryPoints);

    // Browser navigation requests → form login redirect
    delegating.setDefaultEntryPoint(
        new LoginUrlAuthenticationEntryPoint("/login"));

    return delegating;
}
```

The `Http403ForbiddenEntryPoint` trap is one of the most famous in Spring Security and worth calling out explicitly. When you configure neither `formLogin()` nor `httpBasic()` nor `oauth2ResourceServer()`, Spring Security has no `AuthenticationEntryPoint` configured. It falls back to `Http403ForbiddenEntryPoint` as the default — which returns HTTP 403, not 401, even for completely unauthenticated requests. The name is misleading. This is a historical design decision, and the fix is simply to explicitly configure an entry point for REST APIs:

```java
http.exceptionHandling(ex -> ex
    .authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)));
```

---

## Layer 5: `AccessDeniedHandler` — The 403 Response Generator

```java
/**
 * LAYER 5: AccessDeniedHandler — generates the HTTP 403 response.
 *
 * Called ONLY for fully authenticated users who lack the required permission.
 * Never called for anonymous users or authentication failures.
 *
 * The default AccessDeniedHandlerImpl either forwards to a configured error page
 * or calls response.sendError(403). For REST APIs, you want JSON instead.
 */
public interface AccessDeniedHandler {
    void handle(HttpServletRequest request,
                HttpServletResponse response,
                AccessDeniedException accessDeniedException)
            throws IOException, ServletException;
}

// ─── Production REST API implementation ──────────────────────────────────────
@Component
@RequiredArgsConstructor
@Slf4j
public class RestAccessDeniedHandler implements AccessDeniedHandler {

    private final ObjectMapper objectMapper;

    @Override
    public void handle(HttpServletRequest request,
                       HttpServletResponse response,
                       AccessDeniedException accessDeniedException) throws IOException {

        // Log with user context — useful for security auditing.
        // By the time we get here, we KNOW the user is authenticated,
        // so auth.getName() is always safe and meaningful.
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        log.warn("Access denied: user={}, uri={}, method={}",
            auth != null ? auth.getName() : "unknown",
            request.getRequestURI(),
            request.getMethod());

        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());

        // Don't expose WHY access was denied — "insufficient privileges" is enough.
        // Saying "missing ROLE_FINANCE_MANAGER" leaks your role structure.
        objectMapper.writeValue(response.getOutputStream(), Map.of(
            "timestamp", Instant.now().toString(),
            "status",    403,
            "error",     "Forbidden",
            "message",   "You do not have permission to access this resource",
            "path",      request.getRequestURI()
        ));
    }
}
```

---

## Layer 6: `RequestCache` — The Original Request Preservation Mechanism

The `RequestCache` is a subtle but important piece of the puzzle. When `sendStartAuthentication()` is called — whether for a real authentication failure or for an anonymous user hitting a protected resource — the filter saves the original request before redirecting to the login page. After successful login, `SavedRequestAwareAuthenticationSuccessHandler` retrieves this saved request and redirects the user to where they originally wanted to go.

```java
/**
 * LAYER 6: RequestCache — how Spring Security implements "redirect after login."
 *
 * When a user tries to access /dashboard without being logged in:
 *   1. ExceptionTranslationFilter catches the AccessDeniedException
 *   2. requestCache.saveRequest() stores the /dashboard request in the session
 *   3. authenticationEntryPoint.commence() redirects to /login
 *   4. User logs in successfully
 *   5. SavedRequestAwareAuthenticationSuccessHandler checks the cache
 *   6. Finds the saved /dashboard request
 *   7. Redirects to /dashboard instead of defaultSuccessUrl
 *
 * DefaultSavedRequest captures: URL, query parameters, method, headers, cookies.
 * This means the user seamlessly continues where they left off.
 */

// ─── Configuring RequestCache behavior ───────────────────────────────────────
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http
        // Default: HttpSessionRequestCache — saves to HTTP session
        // Fine for stateful web apps, problematic for stateless APIs

        // For stateless APIs, use NullRequestCache to prevent session creation.
        // Without this, even a STATELESS app would create a session just to
        // store the saved request, defeating the purpose.
        .requestCache(cache -> cache
            .requestCache(new NullRequestCache()))

        // Or customize the default cache's behavior:
        .requestCache(cache -> cache
            .requestCache(customRequestCache()));

    return http.build();
}

@Bean
public HttpSessionRequestCache customRequestCache() {
    HttpSessionRequestCache cache = new HttpSessionRequestCache();
    // Only save GET requests — don't save POST/PUT/DELETE (user can't be
    // meaningfully redirected to repeat a form submission after login)
    cache.setRequestMatcher(new AntPathRequestMatcher("/**", "GET"));
    return cache;
}
```

---

## Layer 7: Exception Propagation — Method Security vs URL Security

This is the most architecturally nuanced part of this topic, and where many developers encounter unexpected behavior. The fundamental question is: when `@PreAuthorize` throws `AccessDeniedException` deep inside a service method, how does it reach `ExceptionTranslationFilter`?

The answer involves two possible paths, and knowing which path fires in your application is critical for producing consistent error responses.

```java
/**
 * LAYER 7: The two exception propagation paths — and why they matter.
 *
 * Path A (with @ControllerAdvice handling AccessDeniedException):
 *   @PreAuthorize throws → propagates through service → through controller
 *   → DispatcherServlet's HandlerExceptionResolver sees it
 *   → @ControllerAdvice @ExceptionHandler matches
 *   → @ControllerAdvice writes the response directly
 *   → ExceptionTranslationFilter NEVER sees this exception
 *   → The filter's try-catch block completes normally (no exception escapes)
 *
 * Path B (no @ControllerAdvice for AccessDeniedException):
 *   @PreAuthorize throws → propagates through service → through controller
 *   → DispatcherServlet cannot handle it
 *   → Exception propagates BACK UP through the filter chain
 *   → ExceptionTranslationFilter catches it
 *   → ThrowableAnalyzer unwraps the nested exception
 *   → Routes to AccessDeniedHandler or AuthenticationEntryPoint
 */

// ─── Path A: Handle at Spring MVC layer (ControllerAdvice) ───────────────────
/**
 * If you define this, ALL AccessDeniedException from method security will be
 * handled HERE — ExceptionTranslationFilter never gets involved for method security.
 *
 * Advantage: clean, centralized error handling at the MVC layer.
 * Risk: if your ControllerAdvice and ExceptionTranslationFilter produce
 *       DIFFERENT response formats, you'll have inconsistent 403 responses
 *       depending on whether the exception came from URL security or method security.
 */
@RestControllerAdvice
public class SecurityExceptionControllerAdvice {

    @ExceptionHandler(AccessDeniedException.class)
    @ResponseStatus(HttpStatus.FORBIDDEN)
    public Map<String, Object> handleAccessDenied(
            AccessDeniedException ex, HttpServletRequest request) {
        // This handles method security @PreAuthorize exceptions.
        // Make sure this response format matches your AccessDeniedHandler format!
        return Map.of(
            "timestamp", Instant.now().toString(),
            "status",    403,
            "error",     "Forbidden",
            "message",   "You do not have permission to access this resource",
            "path",      request.getRequestURI()
        );
    }

    @ExceptionHandler(AuthenticationException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public Map<String, Object> handleAuthentication(
            AuthenticationException ex, HttpServletRequest request) {
        return Map.of(
            "timestamp", Instant.now().toString(),
            "status",    401,
            "error",     "Unauthorized",
            "message",   "Authentication is required",
            "path",      request.getRequestURI()
        );
    }
}

// ─── Critical consistency trap ───────────────────────────────────────────────
/**
 * The danger of handling security exceptions in BOTH places:
 *
 * URL security (AuthorizationFilter) AccessDeniedException:
 *   → ExceptionTranslationFilter → your AccessDeniedHandler
 *   → Returns: {"status": 403, "error": "Forbidden", "format": "A"}
 *
 * Method security (@PreAuthorize) AccessDeniedException:
 *   → @ControllerAdvice → your @ExceptionHandler
 *   → Returns: {"status": 403, "error": "Forbidden", "format": "B"}
 *
 * Same HTTP status code, different JSON structure → API clients break
 * depending on which security layer fired. This is subtle and hard to debug.
 *
 * PRODUCTION RECOMMENDATION: Pick ONE approach and be consistent.
 *   Option 1: Use only ExceptionTranslationFilter (AccessDeniedHandler + AuthenticationEntryPoint)
 *             — handle everything at the filter layer
 *   Option 2: Use only @ControllerAdvice for method security + configure ETF to match
 *             — handle everything at the MVC layer
 *   Option 3: Use @ControllerAdvice that re-throws security exceptions
 *             — explicitly route them to ExceptionTranslationFilter
 */
@RestControllerAdvice
public class SafeGlobalExceptionHandler {

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handleAll(Exception ex,
                                                          HttpServletRequest request) {
        // Re-throw security exceptions — let ExceptionTranslationFilter handle them
        // consistently. This ensures URL security and method security produce
        // identical responses for the same exception types.
        if (ex instanceof AccessDeniedException || ex instanceof AuthenticationException) {
            throw (RuntimeException) ex; // re-throw to ETF
        }

        // Handle everything else here
        return ResponseEntity.internalServerError().body(Map.of(
            "status", 500,
            "error",  "Internal Server Error",
            "path",   request.getRequestURI()
        ));
    }
}
```

---

## Layer 8: The `response.isCommitted()` Problem

This is a runtime error that's difficult to debug because it produces a broken HTTP response rather than a clean error status, and the server logs a message that many developers don't immediately recognize as a Spring Security issue.

```java
/**
 * LAYER 8: The response committed problem — when exception translation is impossible.
 *
 * HTTP protocol rule: once you send the response status line and headers
 * (i.e., once you start writing the body), you cannot change any of them.
 * response.isCommitted() returns true at that point.
 *
 * Spring Security's exception translation requires sending a 401 or 403
 * response — which means setting the status code and headers. If the
 * response is already committed, this is physically impossible.
 *
 * ExceptionTranslationFilter handles this by throwing a ServletException
 * wrapping the original exception, which typically causes the server to
 * abruptly close the connection — the client sees a truncated response.
 */

// ❌ WRONG: Writing to the response before security checks complete
@GetMapping("/data")
public void streamLargeDataset(HttpServletResponse response) throws IOException {
    // This commits the response! Headers are sent with first write.
    response.setContentType("application/octet-stream");
    response.getOutputStream().write(firstChunkOfData); // ← COMMITTED HERE

    // If this service method throws AccessDeniedException:
    dataService.securedOperation(); // might throw if user lacks permission

    // ExceptionTranslationFilter cannot help — response.isCommitted() = true
    // Server logs: "Unable to handle the Spring Security Exception
    //              because the response is already committed"
    // Client receives: broken/truncated response
}

// ✓ CORRECT: Complete all authorization before writing response
@GetMapping("/data")
@PreAuthorize("hasRole('DATA_ACCESS')") // authorization check before method body
public ResponseEntity<byte[]> getData() {
    // Authorization is resolved by @PreAuthorize BEFORE the method runs.
    // If denied, AccessDeniedException is thrown and the response hasn't
    // been written yet — ExceptionTranslationFilter can handle it cleanly.
    byte[] data = dataService.getSecuredData();
    return ResponseEntity.ok()
        .contentType(MediaType.APPLICATION_OCTET_STREAM)
        .body(data);
}
```

---

## Layer 9: The Complete Production Configuration

```java
/**
 * LAYER 9: Wiring all exception handling components together for production.
 *
 * This configuration demonstrates:
 *   - Consistent exception handling for URL and method security
 *   - Multi-client routing (browsers vs API clients)
 *   - Proper RequestCache for stateful web layer
 *   - Correct handler placement in exceptionHandling() DSL
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final RestAuthenticationEntryPoint restAuthEntryPoint;
    private final RestAccessDeniedHandler restAccessDeniedHandler;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/login", "/public/**").permitAll()
                .requestMatchers("/api/**").hasRole("API_USER")
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
            )
            .formLogin(form -> form
                .loginPage("/login")
                .permitAll()
            )
            .exceptionHandling(ex -> ex
                // The entry point for this chain — what to do when authentication is needed.
                // Using DelegatingAuthenticationEntryPoint to handle browsers and API clients
                // differently. Browsers get a login redirect; API clients get JSON 401.
                .authenticationEntryPoint(multiClientEntryPoint())

                // The handler for fully-authenticated users with insufficient permissions.
                // Same delegate pattern: browsers get a 403 page; API clients get JSON 403.
                .defaultAccessDeniedHandlerFor(
                    restAccessDeniedHandler,
                    new AntPathRequestMatcher("/api/**"))
                .defaultAccessDeniedHandlerFor(
                    webAccessDeniedHandler(),
                    AnyRequestMatcher.INSTANCE)
            )
            // For the web (stateful) portion, save requests so users return
            // to their original destination after login
            .requestCache(cache -> cache
                .requestCache(new HttpSessionRequestCache()));

        return http.build();
    }

    @Bean
    public AuthenticationEntryPoint multiClientEntryPoint() {
        LinkedHashMap<RequestMatcher, AuthenticationEntryPoint> entryPoints =
            new LinkedHashMap<>();
        entryPoints.put(
            new AntPathRequestMatcher("/api/**"), restAuthEntryPoint);
        entryPoints.put(
            new MediaTypeRequestMatcher(MediaType.APPLICATION_JSON), restAuthEntryPoint);

        DelegatingAuthenticationEntryPoint delegating =
            new DelegatingAuthenticationEntryPoint(entryPoints);
        delegating.setDefaultEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"));
        return delegating;
    }

    @Bean
    public AccessDeniedHandler webAccessDeniedHandler() {
        // For browser users, forward to a friendly 403 error page
        AccessDeniedHandlerImpl handler = new AccessDeniedHandlerImpl();
        handler.setErrorPage("/error/403");
        return handler;
    }
}
```

---

## Layer 10: Testing Exception Translation

```java
/**
 * LAYER 10: Testing exception handling — verifying correct status codes
 * and response formats for different authentication states.
 *
 * The key is testing all three combinations:
 *   1. Unauthenticated (anonymous) → should get 401 or redirect, not 403
 *   2. Authenticated, wrong role → should get 403, not 401
 *   3. Remember-me, sensitive endpoint → should get 401 or redirect, not 403
 */
@SpringBootTest
@AutoConfigureMockMvc
class ExceptionTranslationTest {

    @Autowired MockMvc mockMvc;

    @Test
    @DisplayName("Anonymous user hitting protected endpoint → 401, not 403")
    void anonymousGets401() throws Exception {
        mockMvc.perform(get("/api/data"))
            .andExpect(status().isUnauthorized()) // 401 — needs to authenticate
            .andExpect(content().contentType(MediaType.APPLICATION_JSON))
            .andExpect(jsonPath("$.status").value(401))
            .andExpect(jsonPath("$.error").value("Unauthorized"));
    }

    @Test
    @DisplayName("Authenticated user, wrong role → 403, not 401")
    @WithMockUser(username = "alice", roles = "USER")
    void authenticatedWrongRoleGets403() throws Exception {
        mockMvc.perform(get("/admin/users"))
            .andExpect(status().isForbidden()) // 403 — knows who you are, wrong permission
            .andExpect(jsonPath("$.status").value(403));
    }

    @Test
    @DisplayName("Response format consistent: URL security and method security give same JSON")
    @WithMockUser(username = "alice", roles = "USER")
    void consistentResponseFormat() throws Exception {
        // URL security 403
        MvcResult urlResult = mockMvc.perform(get("/admin/config"))
            .andExpect(status().isForbidden())
            .andReturn();

        // Method security 403 (controller calls @PreAuthorize("hasRole('ADMIN')") service)
        MvcResult methodResult = mockMvc.perform(get("/api/admin-data"))
            .andExpect(status().isForbidden())
            .andReturn();

        // Both should return the same JSON structure
        assertThat(urlResult.getResponse().getContentAsString())
            .contains("\"error\":\"Forbidden\"");
        assertThat(methodResult.getResponse().getContentAsString())
            .contains("\"error\":\"Forbidden\"");
    }

    @Test
    @DisplayName("No configured auth → Http403ForbiddenEntryPoint default trap")
    void noAuthConfiguredReturnsForbiddenNotUnauthorized() throws Exception {
        // Without explicit formLogin/httpBasic/entryPoint configured,
        // Spring Security uses Http403ForbiddenEntryPoint by default.
        // This is the famous "403 for unauthenticated" trap.
        // This test documents the behavior so future developers aren't surprised.
        mockMvc.perform(get("/no-config-endpoint"))
            // NOTE: this returns 403, NOT 401!
            // Configure .exceptionHandling(ex -> ex.authenticationEntryPoint(...))
            // explicitly to get 401 for unauthenticated requests.
            .andExpect(status().isForbidden());
    }
}
```

---

## The Complete Mental Model

Here is how every component in this topic connects, mapped against the complete exception lifecycle:

```
Any HTTP Request
     │
     ▼ Order ~1300
AnonymousAuthenticationFilter          ← sets anonymous token if no auth
     │ auth is now guaranteed non-null
     ▼ Order ~1500
ExceptionTranslationFilter
     ╔══════════════════════════════════════╗
     ║  try {                               ║
     ║      chain.doFilter(request, res)    ║
     ║                                      ║
     ║   ┌──────────────────────────┐       ║
     ║   │ AuthorizationFilter(1600)│       ║
     ║   │ throws AccessDenied?     │       ║
     ║   └──────────────────────────┘       ║
     ║        │ ↑ exception bubbles up      ║
     ║   ┌─── ─ ─ ─ ─ ─ ─ ─────────┐       ║
     ║   │ DispatcherServlet        │       ║
     ║   │  Controller              │       ║
     ║   │   Service (AOP proxy)    │       ║
     ║   │    @PreAuthorize throws  │       ║
     ║   │    ↑ propagates up       │       ║
     ║   │    @ControllerAdvice?    │       ║
     ║   │      YES → handles here  │       ║
     ║   │      NO → propagates up  │       ║
     ║   └──────────────────────────┘       ║
     ║                                      ║
     ║  } catch (Exception ex) {            ║
     ║      throwableAnalyzer.unwrap(ex)    ║
     ║      → AuthenticationException?      ║
     ║          sendStartAuthentication()   ║
     ║          requestCache.saveRequest()  ║
     ║          entryPoint.commence()       ║
     ║            ├─ formLogin → 302/login  ║
     ║            ├─ httpBasic → 401+header ║
     ║            ├─ REST     → JSON 401    ║
     ║            └─ default  → 403 (trap!) ║
     ║      → AccessDeniedException?        ║
     ║          isAnonymous(auth)?          ║
     ║            YES → sendStartAuth() ↑  ║
     ║          isRememberMe(auth)?         ║
     ║            YES → sendStartAuth() ↑  ║
     ║          else → accessDeniedHandler  ║
     ║                  → JSON/page 403     ║
     ║  }                                   ║
     ╚══════════════════════════════════════╝

─────────────────────── KEY INSIGHTS ───────────────────────────────────────────

Anonymous + AccessDeniedException  → AuthenticationEntryPoint → 401/redirect
Remember-me + AccessDeniedException → AuthenticationEntryPoint → 401/redirect
Full auth + AccessDeniedException  → AccessDeniedHandler → 403
No entry point configured          → Http403ForbiddenEntryPoint → 403 (even for anon!)
@ControllerAdvice handles first    → ExceptionTranslationFilter never sees it
response.isCommitted()             → Cannot translate → broken connection
```

The deepest architectural insight in this topic is that `ExceptionTranslationFilter` is not just an error handler — it's the component that makes Spring Security's exception model semantically coherent. Without it, `AccessDeniedException` and `AuthenticationException` would be indistinguishable from any other runtime exception. The filter adds the crucial layer of reasoning: it looks at *who* is making the request, not just *what* exception was thrown, and uses that context to decide whether the right response is "please identify yourself" (401) or "I know who you are, but no" (403). That context-sensitive routing is only possible because `AnonymousAuthenticationFilter` runs before it, ensuring every request carries a typed `Authentication` object that can be inspected to make the decision.
