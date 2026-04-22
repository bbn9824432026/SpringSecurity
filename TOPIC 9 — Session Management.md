# TOPIC 9 — Session Management

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

---

## 1️⃣ Conceptual Explanation

---

### 9.1 Session Management — Design Philosophy & The Security Stakes

HTTP is a stateless protocol. Sessions are the mechanism by which web applications maintain state between requests. From a security perspective, sessions are both **essential** (for maintaining authentication state) and **dangerous** (session theft = identity theft).

**The attack surface that session management protects against:**

```
Attack 1 — Session Fixation
     Attacker plants a known session ID in victim's browser
     Victim logs in → session ID becomes authenticated
     Attacker uses the known session ID → authenticated as victim
     Protection: Change session ID on authentication

Attack 2 — Session Hijacking
     Attacker steals victim's session cookie via XSS or network sniffing
     Uses stolen cookie to impersonate victim
     Protection: HTTPS, HttpOnly/Secure cookie flags, short session timeout

Attack 3 — Session Riding (CSRF)
     Attacker tricks victim's browser into making authenticated requests
     Browser automatically sends session cookie
     Protection: CSRF tokens (Topic 10)

Attack 4 — Concurrent Session Abuse
     Single account logged in from many locations simultaneously
     Used for credential sharing or account takeover detection
     Protection: ConcurrentSessionFilter + SessionRegistry

Attack 5 — Session Replay
     Old session credentials replayed after logout
     Protection: Session invalidation on logout, stateless JWT
```

---

### 9.2 Session Management Architecture — The Components

Spring Security's session management involves multiple collaborating components:

```
Session Management Components:
     │
     ├── SessionManagementFilter
     │       Purpose: Detects authenticated sessions, applies strategies
     │       Position: Order 1400
     │
     ├── SessionAuthenticationStrategy
     │       Purpose: Actions taken on new authentication
     │       Implementations: ChangeSessionIdAuthenticationStrategy,
     │                        CsrfAuthenticationStrategy,
     │                        RegisterSessionAuthenticationStrategy,
     │                        CompositeSessionAuthenticationStrategy
     │
     ├── SessionCreationPolicy
     │       Purpose: Control when sessions are created
     │       Options: ALWAYS, IF_REQUIRED, NEVER, STATELESS
     │
     ├── ConcurrentSessionFilter
     │       Purpose: Detect expired concurrent sessions per-request
     │       Position: Order ~350 (early in chain)
     │
     ├── SessionRegistry
     │       Purpose: Track all active sessions and their principals
     │       Default: SessionRegistryImpl (in-memory)
     │
     └── HttpSessionSecurityContextRepository
             Purpose: Persist SecurityContext to/from HttpSession
             Used by: SecurityContextHolderFilter (6.x)
```

---

### 9.3 SessionManagementFilter — Internal Architecture

`SessionManagementFilter` has a **narrow, specific job** in Spring Security 6.x:

**Primary responsibility:** Detect when a user has been authenticated by an external mechanism (e.g., pre-authentication) during the current request and apply the `SessionAuthenticationStrategy`.

```java
public class SessionManagementFilter extends GenericFilterBean {

    // Flag: has this filter already handled a new authentication in this request?
    static final String FILTER_APPLIED =
        "__spring_security_session_mgmt_filter_applied";

    private final SecurityContextRepository securityContextRepository;
    private SessionAuthenticationStrategy sessionAuthenticationStrategy;
    private AuthenticationTrustResolver trustResolver =
        new AuthenticationTrustResolverImpl();
    private InvalidSessionStrategy invalidSessionStrategy = null;
    private AuthenticationFailureHandler failureHandler =
        new SimpleUrlAuthenticationFailureHandler();

    @Override
    public void doFilter(ServletRequest request, ServletResponse response,
            FilterChain chain) throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        // Only process once per request
        if (request.getAttribute(FILTER_APPLIED) != null) {
            chain.doFilter(request, response);
            return;
        }
        request.setAttribute(FILTER_APPLIED, Boolean.TRUE);

        // Step 1: Check for invalid session (if configured)
        if (!securityContextRepository.containsContext(httpRequest)) {
            Authentication authentication =
                SecurityContextHolder.getContext().getAuthentication();

            if (authentication != null
                    && !trustResolver.isAnonymous(authentication)) {
                // A real authentication exists but no SecurityContext in repo
                // This means: authentication was set during THIS request
                // by a filter like PreAuthFilter (not loaded from session)
                // → Apply session strategy for new authentication
                try {
                    sessionAuthenticationStrategy.onAuthentication(
                        authentication, httpRequest, httpResponse);
                } catch (SessionAuthenticationException ex) {
                    // Session strategy rejected — e.g., concurrent session limit
                    SecurityContextHolder.clearContext();
                    failureHandler.onAuthenticationFailure(
                        httpRequest, httpResponse, ex);
                    return;
                }
            } else if (invalidSessionStrategy != null) {
                // No authentication AND no context in repo
                // Could be invalid/expired session
                if (httpRequest.getRequestedSessionId() != null
                        && !httpRequest.isRequestedSessionIdValid()) {
                    invalidSessionStrategy.onInvalidSessionDetected(
                        httpRequest, httpResponse);
                    return;
                }
            }
        }

        chain.doFilter(request, response);
    }
}
```

**Important 6.x context:** In Spring Security 6.x, `SessionManagementFilter`'s role is significantly reduced compared to 5.x. Much of the session management (particularly for form login and Basic auth) now happens **within the authentication filters themselves** via `SessionAuthenticationStrategy` callbacks. `SessionManagementFilter` mainly handles edge cases and invalid session detection.

---

### 9.4 SessionAuthenticationStrategy — The Action Layer

`SessionAuthenticationStrategy` is called during successful authentication to perform session-related operations. It is called from:

1. `AbstractAuthenticationProcessingFilter.successfulAuthentication()` (form login, etc.)
2. `BasicAuthenticationFilter` (after successful Basic auth)
3. `SessionManagementFilter` (for pre-auth scenarios)

**The composite strategy (default):**

```java
CompositeSessionAuthenticationStrategy
     │
     ├── [1] ChangeSessionIdAuthenticationStrategy
     │       (Session Fixation Protection)
     │       Order: first
     │
     ├── [2] CsrfAuthenticationStrategy
     │       (CSRF token rotation)
     │       Order: second
     │       (only if CSRF enabled)
     │
     └── [3] RegisterSessionAuthenticationStrategy
             (Concurrent session tracking)
             Order: last
             (only if concurrent session control enabled)
```

---

### 9.5 Session Fixation Protection — Four Strategies Deep Dive

Session fixation is prevented by changing the session identifier at the moment of authentication.

**Strategy 1 — `changeSessionId()` (DEFAULT in Spring Security 4.1+):**

```java
// Uses Servlet 3.1 HttpServletRequest.changeSessionId()
// Changes the session ID but PRESERVES all session attributes

Before authentication:
     Session ID: "ABC123"
     Attributes: {cart=[item1, item2], locale="en"}

After authentication (changeSessionId):
     Session ID: "XYZ789"  ← CHANGED
     Attributes: {cart=[item1, item2], locale="en"}  ← PRESERVED
     + SPRING_SECURITY_CONTEXT = [authenticated SecurityContext]
```

**Strategy 2 — `newSession()`:**

```java
// Creates a completely new session
// Copies ONLY attributes matching migratedSessionAttributeName patterns

Before authentication:
     Session ID: "ABC123"
     Attributes: {cart=[item1, item2], locale="en", LAST_PAGE="/orders"}

After authentication (newSession):
     Session ID: "XYZ789"  ← CHANGED
     Attributes: {}  ← ALL CLEARED (unless migration configured)
     + SPRING_SECURITY_CONTEXT = [authenticated SecurityContext]
```

**Strategy 3 — `migrateSession()` (Legacy name for pre-Servlet 3.1 behavior):**
Same as `changeSessionId()` in modern implementations — creates new session and migrates attributes. In Spring Security 5.x docs, `migrateSession()` was the name before Servlet 3.1 support was standardized.

**Strategy 4 — `none()`:**

```java
// NO session fixation protection
// Session ID remains the same before and after authentication
// DANGEROUS — only use when you manage session fixation externally

// USE CASE: Stateless APIs (STATELESS policy) — no sessions at all
//           Pre-authentication where container handles fixation
```

**Configuration in 6.x:**

```java
http.sessionManagement(session -> session
    .sessionFixation(fixation -> fixation
        .changeSessionId()    // default — recommended
        // .newSession()      // alternative
        // .migrateSession()  // legacy equivalent to changeSessionId
        // .none()            // disable — dangerous
    )
);
```

---

### 9.6 SessionCreationPolicy — Four Modes Deep Internals

`SessionCreationPolicy` controls WHEN Spring Security creates or uses HTTP sessions:

**`IF_REQUIRED` (default):**

```java
SessionCreationPolicy.IF_REQUIRED

Behavior:
- Spring Security creates a session IF AND ONLY IF it needs to
- Creates session when: saving SecurityContext, saving CSRF token,
  saving request cache, concurrent session registration
- Does NOT create session for every request
- Uses existing session if available

Use case: Traditional web applications with form login
```

**`ALWAYS`:**

```java
SessionCreationPolicy.ALWAYS

Behavior:
- Spring Security ensures a session EXISTS for every request
- Creates a session if one doesn't exist
- Even for completely anonymous, unauthenticated requests
- ForceEagerSessionCreationFilter is added to chain (6.x)

Use case: Applications that always need session (legacy apps,
          apps with heavy session attribute usage)
```

**`NEVER`:**

```java
SessionCreationPolicy.NEVER

Behavior:
- Spring Security will NEVER create a new session
- BUT will USE an existing session if one already exists
  (created by application code or other framework components)
- Subtle difference from STATELESS

Use case: Application manages sessions itself,
          Spring Security should not create them but can use them
```

**`STATELESS`:**

```java
SessionCreationPolicy.STATELESS

Behavior:
- Spring Security will NEVER create OR use a session
- SecurityContextRepository = NullSecurityContextRepository
  (never loads or saves SecurityContext to/from session)
- Even if session exists (created by application), Spring Security ignores it
- Every request is independently authenticated
- Maximum isolation

Use case: REST APIs with JWT, microservices, stateless APIs
```

**Internal implementation difference between `NEVER` and `STATELESS`:**

```
NEVER:
     SecurityContextRepository = HttpSessionSecurityContextRepository
          (but createSession=false → never creates new session)
     Will load SecurityContext from existing session if present

STATELESS:
     SecurityContextRepository = NullSecurityContextRepository
          Always returns empty context, never saves
     Session is completely ignored — even existing sessions not consulted
```

---

### 9.7 HttpSessionSecurityContextRepository — The Persistence Engine

This is the component responsible for storing and retrieving the `SecurityContext` from the HTTP session.

**Complete flow:**

```java
// On every request start (SecurityContextHolderFilter 6.x):
HttpSessionSecurityContextRepository.loadDeferredContext(request)
     │
     ├── Look for HttpSession: request.getSession(false)
     │       NULL? → Return empty SecurityContext supplier
     │
     └── Session exists:
             attribute = session.getAttribute(
                 "SPRING_SECURITY_CONTEXT")  // the key
             │
             ├── NULL? → Return empty SecurityContext
             │
             ├── Not instanceof SecurityContext? → Log warning, return empty
             │
             └── SecurityContext found:
                     authentication = context.getAuthentication()
                     │
                     ├── NULL? → Return empty context
                     │
                     └── Not instanceof Authentication? → Return empty
                         └── Return loaded SecurityContext

// On authentication success (explicit save in 6.x):
HttpSessionSecurityContextRepository.saveContext(context, request, response)
     │
     ├── Is authentication anonymous? → Don't save (no point saving anonymous)
     │
     ├── Is context empty? → Remove attribute from session
     │
     └── Save:
             session = getSession(createNew=true if IF_REQUIRED/ALWAYS)
             session.setAttribute("SPRING_SECURITY_CONTEXT", context)
```

**The session attribute key:**

```java
public static final String SPRING_SECURITY_CONTEXT_KEY =
    "SPRING_SECURITY_CONTEXT";
// session.getAttribute("SPRING_SECURITY_CONTEXT") = SecurityContext object
```

**Serialization requirement for clustered environments:**

```java
// In clustered deployments, sessions are serialized:
// - Tomcat cluster → session replicated via serialization
// - Redis/Hazelcast session store → must serialize

// ALL objects in SecurityContext must implement Serializable:
public class CustomUserDetails implements UserDetails, Serializable {
    private static final long serialVersionUID = 1L;
    // All fields must be serializable
}

// SimpleGrantedAuthority IS Serializable ✓
// UsernamePasswordAuthenticationToken IS Serializable ✓
// Your custom Authentication implementations MUST be Serializable
```

---

### 9.8 Concurrent Session Control — Deep Architecture

Concurrent session control prevents a single user account from having more than N active sessions simultaneously.

**Component architecture:**

```
ConcurrentSessionControlAuthenticationStrategy
     │
     ├── On new authentication:
     │       count = sessionRegistry.getAllSessions(principal, false).size()
     │       count >= maxSessions?
     │               NO  → proceed (allow new session)
     │               YES → maxSessionsPreventsLogin?
     │                         TRUE  → throw SessionAuthenticationException
     │                                  "Maximum sessions exceeded"
     │                         FALSE → expire OLDEST session(s)
     │                                  (mark SessionInformation.expired = true)

RegisterSessionAuthenticationStrategy
     │
     └── On new authentication:
             sessionRegistry.registerNewSession(sessionId, principal)

ConcurrentSessionFilter (per-request)
     │
     └── On every request:
             sessionInfo = sessionRegistry.getSessionInformation(sessionId)
             sessionInfo.isExpired()?
                     YES → sessionRegistry.removeSessionInformation(sessionId)
                           session.invalidate()
                           response → redirect to expiredUrl OR 401
```

**The per-request check is critical:**
When the oldest session is "expired" (marked in `SessionRegistry`), the session itself is NOT immediately invalidated. The user is NOT logged out immediately. Instead, **the next request on that session** (caught by `ConcurrentSessionFilter`) detects the expired marker and forces logout. This is eventually consistent behavior.

---

### 9.9 SessionRegistry — The Session Tracking Store

`SessionRegistry` maintains a bidirectional mapping:

```
SessionRegistry stores:
     sessionId → SessionInformation {
                     sessionId,
                     principal (usually String username or UserDetails),
                     lastRequest (timestamp),
                     expired (boolean)
                 }

     principal → List<SessionInformation>
                 (all sessions for this user)
```

**`SessionRegistryImpl` — in-memory implementation:**

```java
// Internal storage:
ConcurrentMap<Object, Set<String>> principals
    // principal → Set<sessionId>

ConcurrentMap<String, SessionInformation> sessionIds
    // sessionId → SessionInformation
```

**Clustered environment problem:**
`SessionRegistryImpl` is in-memory and **not replicated** across cluster nodes. In a multi-instance deployment:

```
Node 1: User logs in → session1 registered in Node1's SessionRegistry
Node 2: User logs in → session2 registered in Node2's SessionRegistry

Node1's registry thinks: 1 session for user
Node2's registry thinks: 1 session for user
Reality: 2 sessions (maxSessions=1 violated)

Solution: Spring Session with shared session store (Redis)
          → HttpSessionEventPublisher publishes to shared SessionRegistry
```

---

### 9.10 ConcurrentSessionFilter — Per-Request Session Validation

`ConcurrentSessionFilter` runs **early in the chain** (order ~350) to catch expired sessions before they reach the rest of the security infrastructure.

```java
public class ConcurrentSessionFilter extends GenericFilterBean {

    @Override
    public void doFilter(ServletRequest req, ServletResponse res,
            FilterChain chain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;

        HttpSession session = request.getSession(false);

        if (session != null) {
            SessionInformation info =
                sessionRegistry.getSessionInformation(session.getId());

            if (info != null) {
                if (info.isExpired()) {
                    // Session was marked expired by concurrent session control
                    doLogout(request, response);

                    // Redirect to expiredURL or send error
                    String targetUrl = determineExpiredUrl(request, info);
                    if (targetUrl != null) {
                        redirectStrategy.sendRedirect(request, response, targetUrl);
                    } else {
                        response.getWriter().print(
                            "This session has been expired...");
                        response.flushBuffer();
                    }
                    return;  // Don't process the request further
                } else {
                    // Update last access time
                    info.refreshLastRequest();
                }
            }
        }

        chain.doFilter(request, response);
    }

    private void doLogout(HttpServletRequest request,
                          HttpServletResponse response) {
        Authentication auth =
            SecurityContextHolder.getContext().getAuthentication();
        logoutHandlers.forEach(handler ->
            handler.logout(request, response, auth));
        SecurityContextHolder.clearContext();
    }
}
```

---

### 9.11 Invalid Session Strategy

When a request arrives with an invalid (expired or non-existent) session ID (the `JSESSIONID` cookie points to a session that no longer exists on the server):

```java
http.sessionManagement(session -> session
    .invalidSessionUrl("/session-expired")
    // OR
    .invalidSessionStrategy(new SimpleRedirectInvalidSessionStrategy(
        "/session-expired"))
);
```

**Internal detection:**

```java
// In SessionManagementFilter:
if (httpRequest.getRequestedSessionId() != null
        && !httpRequest.isRequestedSessionIdValid()) {
    // Cookie has a session ID but it's not valid
    invalidSessionStrategy.onInvalidSessionDetected(request, response);
}
```

**Difference from expired concurrent session:**
- **Invalid session:** `JSESSIONID` cookie exists but session is gone from server (timeout, server restart, manual invalidation)
- **Expired concurrent session:** Session exists and is valid but marked expired by `SessionRegistry` due to concurrent login limit

---

### 9.12 SecurityContext Propagation — The Complete Picture

```
Request Arrives:
     │
     ▼
SecurityContextHolderFilter (6.x)
     └── securityContextRepository.loadDeferredContext(request)
               └── HttpSessionSecurityContextRepository
                       └── Load context from session attribute
                       └── Return as DeferredSecurityContext (lazy)

     ▼
[Authentication Filters run]
     └── May set new Authentication in SecurityContextHolder

     ▼
[AnonymousAuthenticationFilter]
     └── Sets anonymous token if still null

     ▼
[Business Logic (Controller, Service)]
     └── SecurityContextHolder.getContext().getAuthentication()
               → Returns current Authentication

     ▼
[End of Request]
SecurityContextHolderFilter
     └── context = SecurityContextHolder.getContext()
     └── securityContextRepository.saveContext(context, request, response)
               └── HttpSessionSecurityContextRepository.saveContext()
               └── If context changed: session.setAttribute(...)
     └── SecurityContextHolder.clearContext()  ← CRITICAL — prevents thread pool leaks
```

**The `DeferredSecurityContext` optimization (6.x):**

```java
// In 6.x, context loading is DEFERRED — lazy
// The session is NOT accessed until the SecurityContext is actually needed

// For permitAll() requests: SecurityContext never accessed → session never opened
// Performance improvement: no unnecessary session lookup for public endpoints
```

---

### 9.13 Spring Session Integration — Distributed Session Management

For clustered deployments, Spring Session replaces `HttpSession` with a shared store:

```java
// pom.xml dependency:
// spring-session-data-redis

@Configuration
@EnableRedisHttpSession(maxInactiveIntervalInSeconds = 3600)
public class SessionConfig {
    // Spring Session auto-configures:
    // - RedisIndexedSessionRepository
    // - SessionRepositoryFilter (wraps HttpRequest to use Redis sessions)
    // - HttpSessionEventPublisher (for SessionRegistry integration)
}
```

```java
// For concurrent session control with clustered sessions:
@Bean
public HttpSessionEventPublisher httpSessionEventPublisher() {
    return new HttpSessionEventPublisher();
    // Publishes HttpSessionDestroyedEvent when sessions expire/invalidate
    // SessionRegistryImpl listens and removes session from registry
    // Required for proper concurrent session cleanup in clustered environments
}
```

---

## 2️⃣ Code Examples

---

### Example 1 — Complete Session Management Configuration (6.x)

```java
@Configuration
@EnableWebSecurity
public class SessionManagementConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .anyRequest().authenticated()
            )
            .formLogin(Customizer.withDefaults())
            .sessionManagement(session -> session

                // ── Session Creation Policy ────────────────────────────
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)

                // ── Session Fixation Protection ────────────────────────
                .sessionFixation(fixation -> fixation
                    .changeSessionId()  // default — recommended
                )

                // ── Invalid Session Handling ───────────────────────────
                .invalidSessionUrl("/session-invalid")

                // ── Concurrent Session Control ─────────────────────────
                .maximumSessions(1)
                    // Prevent new login when limit reached (default: false)
                    .maxSessionsPreventsLogin(false)
                    // Where to redirect when session expires
                    .expiredUrl("/session-expired")
                    // Session registry for tracking
                    .sessionRegistry(sessionRegistry())
            );

        return http.build();
    }

    @Bean
    public SessionRegistry sessionRegistry() {
        return new SessionRegistryImpl();
    }

    // Required for SessionRegistry to receive session destruction events
    @Bean
    public HttpSessionEventPublisher httpSessionEventPublisher() {
        return new HttpSessionEventPublisher();
    }
}
```

---

### Example 2 — Stateless JWT Configuration (No Sessions)

```java
@Configuration
@EnableWebSecurity
public class StatelessJwtConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // ── Stateless — no sessions at all ────────────────────────
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            // ── No CSRF needed for stateless APIs ─────────────────────
            .csrf(AbstractHttpConfigurer::disable)
            // ── No request caching (stateless) ────────────────────────
            .requestCache(cache -> cache
                .requestCache(new NullRequestCache())
            )
            // ── JWT resource server ───────────────────────────────────
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(Customizer.withDefaults())
            )
            .authorizeHttpRequests(auth -> auth
                .anyRequest().authenticated()
            );

        return http.build();
    }
}
```

---

### Example 3 — Concurrent Session Control — Preventing Login

```java
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http
        .authorizeHttpRequests(auth -> auth
            .anyRequest().authenticated()
        )
        .formLogin(Customizer.withDefaults())
        .sessionManagement(session -> session
            .maximumSessions(2)  // allow 2 concurrent sessions
            .maxSessionsPreventsLogin(true)
            // true: 3rd login attempt rejected with error
            // false: 1st session expired (default)
        );

    return http.build();
}
```

**Login behavior with `maxSessionsPreventsLogin=true`:**

```
User has 2 active sessions.
3rd login attempt:
     ConcurrentSessionControlAuthenticationStrategy
          count=2, maxSessions=2, maxSessionsPreventsLogin=true
          → throws SessionAuthenticationException
               "Maximum sessions of 2 for this principal exceeded"
     AbstractAuthenticationProcessingFilter
          → failureHandler.onAuthenticationFailure()
          → redirects to /login?error

User sees: /login?error (cannot log in until one session is ended)
```

---

### Example 4 — Viewing Active Sessions (Admin Feature)

```java
@RestController
@RequestMapping("/admin/sessions")
@PreAuthorize("hasRole('ADMIN')")
public class SessionManagementController {

    @Autowired
    private SessionRegistry sessionRegistry;

    @GetMapping
    public List<SessionInfo> getAllSessions() {
        return sessionRegistry.getAllPrincipals().stream()
            .filter(principal -> !sessionRegistry
                .getAllSessions(principal, false).isEmpty())
            .flatMap(principal ->
                sessionRegistry.getAllSessions(principal, false)
                    .stream()
                    .map(info -> new SessionInfo(
                        getPrincipalName(principal),
                        info.getSessionId(),
                        info.getLastRequest(),
                        info.isExpired()
                    ))
            )
            .collect(Collectors.toList());
    }

    @DeleteMapping("/{sessionId}")
    public ResponseEntity<Void> expireSession(@PathVariable String sessionId) {
        SessionInformation info =
            sessionRegistry.getSessionInformation(sessionId);
        if (info != null) {
            info.expireNow();  // marks as expired — user kicked on next request
            return ResponseEntity.ok().build();
        }
        return ResponseEntity.notFound().build();
    }

    private String getPrincipalName(Object principal) {
        if (principal instanceof UserDetails ud) return ud.getUsername();
        return principal.toString();
    }
}

record SessionInfo(String username, String sessionId,
                   Date lastRequest, boolean expired) {}
```

---

### Example 5 — Custom SessionAuthenticationStrategy

```java
// Strategy that logs all new session creations for audit
@Component
public class AuditingSessionStrategy implements SessionAuthenticationStrategy {

    private final AuditService auditService;
    private final SessionAuthenticationStrategy delegate;

    public AuditingSessionStrategy(AuditService auditService) {
        this.auditService = auditService;
        // Delegate to standard protection
        this.delegate = new ChangeSessionIdAuthenticationStrategy();
    }

    @Override
    public void onAuthentication(Authentication authentication,
            HttpServletRequest request,
            HttpServletResponse response)
            throws SessionAuthenticationException {

        String oldSessionId = request.getSession(false) != null
            ? request.getSession(false).getId() : null;

        // Perform actual session fixation protection
        delegate.onAuthentication(authentication, request, response);

        String newSessionId = request.getSession(false) != null
            ? request.getSession(false).getId() : null;

        // Audit: log old → new session ID for security monitoring
        auditService.recordSessionCreation(
            authentication.getName(),
            oldSessionId,
            newSessionId,
            request.getRemoteAddr()
        );
    }
}
```

```java
// Register custom strategy:
http.sessionManagement(session -> session
    .sessionAuthenticationStrategy(auditingSessionStrategy)
);
```

---

### Example 6 — Redis Spring Session Integration

```java
@Configuration
@EnableRedisIndexedHttpSession(
    maxInactiveIntervalInSeconds = 1800,  // 30 minutes
    redisNamespace = "myapp:session"
)
public class RedisSessionConfig {

    @Bean
    public LettuceConnectionFactory connectionFactory() {
        return new LettuceConnectionFactory(
            new RedisStandaloneConfiguration("localhost", 6379));
    }

    // Required for concurrent session control cleanup
    @Bean
    public HttpSessionEventPublisher httpSessionEventPublisher() {
        return new HttpSessionEventPublisher();
    }
}
```

```java
// With Spring Session, the session is stored in Redis:
// Key: "myapp:session:sessions:<sessionId>"
// Value: Hash with session attributes including SPRING_SECURITY_CONTEXT

// All cluster nodes share the same session store
// SecurityContext is deserialized from Redis on every request
// Concurrent session control works correctly across nodes
```

---

### Example 7 — Incorrect Session Configurations

```java
// ❌ WRONG 1 — STATELESS with form login expecting persistence
http
    .sessionManagement(s -> s
        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
    .formLogin(Customizer.withDefaults());
// Form login succeeds but SecurityContext never saved
// User is unauthenticated on next request
// Redirect-after-login broken (RequestCache can't save to session)

// ❌ WRONG 2 — Missing HttpSessionEventPublisher for concurrent sessions
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http.sessionManagement(s -> s.maximumSessions(1));
    return http.build();
}
// No HttpSessionEventPublisher bean
// When sessions naturally expire (timeout), SessionRegistry
// is NOT notified → stale entries accumulate
// SessionRegistry grows unbounded → memory leak
// Concurrent session count never decreases → users can't log in after timeout

// ✓ CORRECT — always register publisher:
@Bean
public HttpSessionEventPublisher httpSessionEventPublisher() {
    return new HttpSessionEventPublisher();
}
```

```java
// ❌ WRONG 3 — session fixation none() with public-facing app
http.sessionManagement(s -> s
    .sessionFixation(fixation -> fixation.none())
);
// Attacker can pre-set session ID via URL parameter in some containers
// → After victim logs in, attacker uses same session
// → Session fixation attack succeeds

// ✓ CORRECT — use changeSessionId() (default)
http.sessionManagement(s -> s
    .sessionFixation(fixation -> fixation.changeSessionId())
);
```

```java
// ❌ WRONG 4 — Clustered deployment with in-memory SessionRegistry
// Node 1 and Node 2 both have SessionRegistryImpl
// Each tracks only sessions created on that node
// maximumSessions(1) is enforced per-node, not globally
// User can have 1 session on Node1 + 1 session on Node2 = 2 sessions total!

// ✓ CORRECT — Use Spring Session with shared store
// @EnableRedisIndexedHttpSession + HttpSessionEventPublisher
// All nodes share the same session registry via Redis events
```

---

## 3️⃣ Exam-Style Questions

---

**Q1 (MCQ):** Which `SessionCreationPolicy` ensures Spring Security never creates a session but WILL use an existing one if present?

A. `STATELESS`
B. `NEVER`
C. `IF_REQUIRED`
D. `ALWAYS`

**Answer: B — `NEVER`**
`NEVER` means Spring Security will not create sessions itself, but it WILL use an existing session if the application or another framework created one. `STATELESS` is more strict — it never creates OR uses sessions (uses `NullSecurityContextRepository`).

---

**Q2 (MCQ):** When `maxSessionsPreventsLogin=false` (default) and a user logs in exceeding the session limit, what happens to their previous sessions?

A. All previous sessions are immediately invalidated
B. The oldest session is marked as expired in `SessionRegistry`
C. The newest session is rejected with an exception
D. All sessions are cleared and a new single session is created

**Answer: B**
The oldest session is **marked as expired** (`SessionInformation.expired = true`) in the `SessionRegistry`. The actual session is NOT immediately invalidated. The user on the oldest session will be forced out on their **next request** when `ConcurrentSessionFilter` detects the expired marker.

---

**Q3 (Select All That Apply):** Which are true about `changeSessionId()` (default session fixation strategy)?

A. It creates a brand new session object
B. It changes the session identifier using `HttpServletRequest.changeSessionId()`
C. It preserves all existing session attributes
D. It is available since Servlet 3.1
E. It removes CSRF token from the old session

**Answer: B, C, D**
A is false — `changeSessionId()` does NOT create a new session object. It uses the same session object but with a new ID. The session data remains intact.
E is false — `CsrfAuthenticationStrategy` rotates the CSRF token (creates new token in the session), but `changeSessionId()` itself doesn't touch CSRF tokens. The CSRF strategy is a separate member of the composite strategy.

---

**Q4 (Scenario):**

```java
http.sessionManagement(session -> session
    .maximumSessions(1)
    .maxSessionsPreventsLogin(false)
);
// No HttpSessionEventPublisher bean
```

A user logs in, gets session S1. User logs in again from different browser, gets session S2. What happens to S1?

**Short term:**
S1 is marked expired in `SessionRegistryImpl`. User on S1 gets `redirected to /session-expired` on next request.

**Long term problem:**
Without `HttpSessionEventPublisher`, when S1 eventually times out on the server:
- Servlet container destroys the session
- `HttpSessionEventPublisher` would have published `HttpSessionDestroyedEvent`
- `SessionRegistryImpl` would have received the event and removed S1's entry
- **Without the publisher:** `SessionRegistryImpl` still thinks S1 is "active" (just expired)
- Over time: `SessionRegistry` accumulates stale entries for timed-out sessions
- **Result:** Memory leak + incorrect session count → users may be incorrectly blocked from logging in

---

**Q5 (Code Prediction):**

```java
http.sessionManagement(session -> session
    .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
);
```

User successfully authenticates via form login POST `/login`. On the next request `GET /dashboard`, what is in `SecurityContextHolder`?

**Answer:** Empty `SecurityContext` — no authentication.
With `STATELESS`, `NullSecurityContextRepository` is used. After the login request, the `SecurityContext` is NOT saved to any session or store. On the next request, `SecurityContextHolderFilter` loads from `NullSecurityContextRepository` which always returns an empty context. The user appears unauthenticated on every subsequent request.

---

**Q6 (Session Fixation Attack):**

Without session fixation protection (`none()`), describe a step-by-step attack:

**Answer:**
```
1. Attacker visits the site → gets Session ID: "ATTACK123"
   (In some implementations, attacker can set a specific session ID via URL:
   https://victim.com/login;jsessionid=ATTACK123)

2. Attacker sends victim a link:
   https://victim.com/login;jsessionid=ATTACK123

3. Victim clicks link → authenticates with username/password
   → Session "ATTACK123" is now authenticated as victim
   (without fixation protection, session ID doesn't change)

4. Attacker uses cookie: JSESSIONID=ATTACK123
   → Attacker IS victim (session hijacked without stealing a cookie)

Protection: changeSessionId() after authentication
   → Session "ATTACK123" becomes "NEWID456"
   → Attacker's cookie "ATTACK123" is now invalid
```

---

**Q7 (Filter Order):**

Where does `ConcurrentSessionFilter` sit in the filter chain, and why?

**Answer:**
`ConcurrentSessionFilter` runs at order **~350** — very early, before almost all other filters including `SecurityContextHolderFilter` (order 300... actually after it, specifically between DisableEncodeUrl and WebAsync).

More precisely: it runs **before `UsernamePasswordAuthenticationFilter`** and most authentication filters.

**Why early?** If a session is expired (due to concurrent login limit), there is no point loading the `SecurityContext`, running CSRF checks, or performing authentication. The session should be invalidated and the request rejected BEFORE any other processing. Running early prevents wasted work on rejected sessions.

---

**Q8 (Tricky Scenario):**

```java
http.sessionManagement(session -> session
    .sessionCreationPolicy(SessionCreationPolicy.NEVER)
);
```

A request arrives with a valid `JSESSIONID` cookie that has a stored `SPRING_SECURITY_CONTEXT`. Is the user authenticated?

**Answer: YES.**
`NEVER` policy means Spring Security won't CREATE new sessions, but it WILL USE existing ones. `HttpSessionSecurityContextRepository` loads the `SecurityContext` from the existing session. The user's authentication is retrieved successfully. This is the key distinction between `NEVER` and `STATELESS`.

---

## 4️⃣ Trick Analysis

---

**Trick 1 — `NEVER` vs `STATELESS` — The Most Confused Policy Pair**

```
NEVER:
     SecurityContextRepository = HttpSessionSecurityContextRepository
          (createSession=false)
     Behavior: Won't create sessions, but READS from existing sessions
     "I won't start sessions, but I'll use yours if you have one"

STATELESS:
     SecurityContextRepository = NullSecurityContextRepository
     Behavior: Complete session blindness — never creates, never reads
     "Sessions don't exist for me"

EXAM TRAP: "Which policy never creates a session but uses existing ones?"
Answer: NEVER (not STATELESS)
```

---

**Trick 2 — `changeSessionId()` vs `newSession()` — Attribute Preservation**

```
changeSessionId():
     ✓ Old session attributes PRESERVED (cart, locale, etc.)
     ✓ Best for user experience
     ✓ Default and recommended

newSession():
     ✗ Old session attributes LOST (unless migrated)
     Can break: shopping cart, wizard state, locale preferences
     Use only when you explicitly want to clear pre-auth session data

EXAM TRAP: "Which strategy creates a new session object?"
Answer: newSession() — changeSessionId() reuses the same session object
```

---

**Trick 3 — Concurrent Session Expiry Is Lazy (Eventually Consistent)**

```
User S1 logs in (maxSessions=1)
User S2 logs in → S1 marked as expired in SessionRegistry

At this point:
✗ S1 is NOT immediately logged out
✗ S1's session is NOT invalidated
✓ S1 WILL be logged out on their NEXT request
   (ConcurrentSessionFilter detects expired marker)

Enterprise implication:
There is a WINDOW where both S1 and S2 are "active"
between S2's login and S1's next request
This window could be seconds or minutes depending on user activity
```

---

**Trick 4 — `HttpSessionEventPublisher` — The Forgotten Bean**

```
When is it needed?
✓ Whenever concurrent session control is used

What happens without it?
✗ Session timeouts don't trigger SessionRegistry cleanup
✗ SessionRegistry accumulates stale entries
✗ Stale entries count toward maxSessions
✗ Users eventually can't log in (limit appears reached)
✗ Memory leak (stale SessionInformation objects)

What it does:
Servlet container publishes HttpSessionEvent on session creation/destruction
HttpSessionEventPublisher propagates to Spring's ApplicationEventPublisher
SessionRegistryImpl listens for HttpSessionDestroyedEvent
→ Removes session from registry

Required in web.xml (traditional):
<listener>
    <listener-class>
        org.springframework.security.web.session.HttpSessionEventPublisher
    </listener-class>
</listener>

Required in Spring Boot:
@Bean
public HttpSessionEventPublisher httpSessionEventPublisher() {
    return new HttpSessionEventPublisher();
}
```

---

**Trick 5 — Session Fixation Happens BEFORE SecurityContext Save**

```
Authentication success sequence:
1. ChangeSessionIdAuthenticationStrategy.onAuthentication()
   → Session ID changed (fixation protection)
2. CsrfAuthenticationStrategy.onAuthentication()
   → New CSRF token created
3. RegisterSessionAuthenticationStrategy.onAuthentication()
   → New session ID registered in SessionRegistry
4. SecurityContextHolder.setAuthentication(authResult)
5. SecurityContextRepository.saveContext(context, req, res)
   → SecurityContext saved to NEW session (with new ID)

Why order matters:
If context were saved BEFORE session ID change:
→ Context saved to old session ID
→ Session ID changes
→ Context in old session ID — not accessible via new session ID!
```

---

**Trick 6 — `maximumSessions()` Without `sessionRegistry()` Bean**

```java
// Spring Boot auto-configures SessionRegistry IF you use:
http.sessionManagement(s -> s.maximumSessions(1));

// Spring Boot DOES register a SessionRegistryImpl bean automatically
// when you configure maximumSessions()

// BUT: Without @Bean HttpSessionEventPublisher, the auto-configured
// SessionRegistry still has the stale entry problem

// AND: In clustered deployments, auto-configured in-memory
// SessionRegistry doesn't help — still need Spring Session
```

---

**Trick 7 — `SessionCreationPolicy.ALWAYS` Creates ForceEagerSessionCreationFilter**

```java
// In Spring Security 6.x:
SessionCreationPolicy.ALWAYS
→ Adds ForceEagerSessionCreationFilter to filter chain
→ This filter ensures HttpSession exists for EVERY request
→ Runs very early in chain (before SecurityContextHolderFilter)
→ Creates session if not already present

// This is different from IF_REQUIRED which creates sessions lazily
// ALWAYS creates sessions proactively — more overhead but predictable
```

---

**Trick 8 — Session Attributes Must Be Serializable for Clustering**

```java
// Silent failure mode in clustered deployments:

// ❌ Custom UserDetails not Serializable
public class CustomUserDetails implements UserDetails {
    // Missing: implements Serializable
    private transient DatabaseConnection conn;  // non-serializable field
}

// What happens in Redis session store:
// SecurityContext contains Authentication with CustomUserDetails
// Redis serializes SecurityContext → CustomUserDetails
// NotSerializableException → session save fails SILENTLY or throws
// User appears logged out on every request on any node but the original

// ✓ CORRECT
public class CustomUserDetails implements UserDetails, Serializable {
    private static final long serialVersionUID = 1L;
    // Ensure all fields are serializable or marked transient
}
```

---

## 5️⃣ Summary Sheet

---

### Session Management Architecture Diagram

```
HTTP Request with JSESSIONID cookie
     │
     ▼
[ConcurrentSessionFilter] (~350)
     └── Is session expired in SessionRegistry?
               YES → logout, redirect to expiredUrl → STOP
               NO  → refreshLastRequest(), continue

     ▼
[SecurityContextHolderFilter] (300)
     └── HttpSessionSecurityContextRepository.loadDeferredContext()
               └── Load SecurityContext from session (lazy/deferred)

     ▼
[Authentication Filters]
     └── If credentials present → authenticate
         └── SessionAuthenticationStrategy.onAuthentication()
               ├── ChangeSessionIdAuthenticationStrategy (fixation protection)
               ├── CsrfAuthenticationStrategy (rotate CSRF token)
               └── RegisterSessionAuthenticationStrategy (track in registry)

     ▼
[SessionManagementFilter] (1400)
     └── Invalid session? → invalidSessionStrategy
         New authentication not from session? → apply strategy

     ▼
[Business Logic]

     ▼
[End of request - SecurityContextHolderFilter cleanup]
     └── saveContext() → session.setAttribute("SPRING_SECURITY_CONTEXT", ctx)
     └── SecurityContextHolder.clearContext()
```

---

### Session Creation Policy Reference

| Policy | Creates Sessions | Uses Existing Sessions | Repository Used | Use Case |
|--------|-----------------|----------------------|----------------|----------|
| `ALWAYS` | Always | Yes | `HttpSessionSecurityContextRepository` | Legacy apps |
| `IF_REQUIRED` | When needed | Yes | `HttpSessionSecurityContextRepository` | Web apps (default) |
| `NEVER` | Never | Yes | `HttpSessionSecurityContextRepository` (createNew=false) | App-managed sessions |
| `STATELESS` | Never | Never | `NullSecurityContextRepository` | REST APIs, JWT |

---

### Session Fixation Strategies Comparison

| Strategy | New Session Object | ID Changed | Attributes Preserved | Recommended |
|----------|-------------------|------------|---------------------|-------------|
| `changeSessionId()` | ❌ No | ✅ Yes | ✅ Yes | ✅ Default |
| `newSession()` | ✅ Yes | ✅ Yes | ❌ No | Only if needed |
| `migrateSession()` | ✅ Yes | ✅ Yes | ✅ Yes | Legacy alias |
| `none()` | ❌ No | ❌ No | ✅ Yes | ❌ Never (vulnerable) |

---

### Concurrent Session Control Behavior Matrix

| `maxSessionsPreventsLogin` | New Login When Limit Reached | Effect on Existing Sessions |
|---------------------------|-----------------------------|-----------------------------|
| `false` (default) | Allowed | Oldest session marked expired |
| `true` | Rejected (`SessionAuthenticationException`) | No change |

---

### Key Classes Reference

| Class | Responsibility |
|-------|---------------|
| `SessionManagementFilter` | Detects new authentications, applies strategy, invalid session handling |
| `ConcurrentSessionFilter` | Per-request expired session check (early in chain) |
| `SessionRegistry` | Tracks all active sessions and their principals |
| `SessionRegistryImpl` | In-memory session registry (not cluster-safe) |
| `HttpSessionSecurityContextRepository` | Load/save `SecurityContext` to `HttpSession` |
| `NullSecurityContextRepository` | No-op repository for `STATELESS` policy |
| `ChangeSessionIdAuthenticationStrategy` | Session fixation protection via ID change |
| `ConcurrentSessionControlAuthenticationStrategy` | Enforce max sessions on new auth |
| `RegisterSessionAuthenticationStrategy` | Register new session in `SessionRegistry` |
| `CompositeSessionAuthenticationStrategy` | Combines multiple strategies |
| `HttpSessionEventPublisher` | Bridges servlet session events to Spring events |

---

### Common Interview One-Liners

- **`STATELESS`** uses `NullSecurityContextRepository` — ignores sessions completely including existing ones
- **`NEVER`** uses `HttpSessionSecurityContextRepository` with `createNew=false` — reads but won't create sessions
- **`changeSessionId()`** preserves session attributes; **`newSession()`** does NOT — breaks cart/locale state
- **Concurrent session expiry is lazy** — old session marked expired, user kicked on NEXT request
- **`HttpSessionEventPublisher` is required** for concurrent session cleanup on session timeout
- **`SessionRegistryImpl`** is in-memory — NOT suitable for clustered deployments without Spring Session
- **Session fixation protection happens BEFORE** `SecurityContext` is saved to session
- **`ConcurrentSessionFilter` runs early (~350)** — before authentication filters to prevent wasted work
- **`SecurityContext` serialization** — all objects must implement `Serializable` for Redis/clustered sessions
- **Session attribute `SPRING_SECURITY_CONTEXT`** — the exact key used by `HttpSessionSecurityContextRepository`

---
