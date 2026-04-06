# TOPIC 4 — Anonymous Authentication

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

---

## 1️⃣ Conceptual Explanation

---

### 4.1 What Is Anonymous Authentication — Design Philosophy

Anonymous authentication is one of the most **misunderstood and underestimated** concepts in Spring Security. Most developers think of it as "no authentication" — but architecturally, it is a **first-class authentication mechanism** that plays a critical structural role in the security pipeline.

**The core design principle:**

Spring Security's authorization layer always expects an `Authentication` object to be present in the `SecurityContext`. If no real authentication has occurred, rather than leaving the `SecurityContext` empty (null), Spring Security inserts a well-defined `AnonymousAuthenticationToken`. This transforms a "no authentication" state into a **deterministic, typed state** that the authorization layer can reason about consistently.

**Why this matters architecturally:**

```
Without anonymous authentication:
     Authorization check → SecurityContext.getAuthentication() == null
          → NullPointerException or explicit null check everywhere
          → Inconsistent behavior across filters

With anonymous authentication:
     Authorization check → SecurityContext.getAuthentication() == AnonymousAuthenticationToken
          → Consistent type-safe check
          → ExceptionTranslationFilter can make definitive 401 vs 403 decisions
          → SpEL expressions like isAnonymous(), isAuthenticated() work uniformly
```

---

### 4.2 AnonymousAuthenticationFilter — Internal Architecture

`AnonymousAuthenticationFilter` extends `GenericFilterBean` and implements the filter contract directly. It does not extend `OncePerRequestFilter`.

**Position in filter chain:** Order 1300 — runs **after all authentication filters** (`UsernamePasswordAuthenticationFilter`, `BasicAuthenticationFilter`, `BearerTokenAuthenticationFilter`, `RememberMeAuthenticationFilter`). This positioning is intentional and critical.

**The logic is beautifully simple:**

```java
// Internal doFilter() logic:
public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
        throws IOException, ServletException {

    // Only set anonymous token if NO authentication has been set yet
    if (SecurityContextHolder.getContext().getAuthentication() == null) {

        // Create anonymous token
        Authentication anonymous = createAuthentication((HttpServletRequest) req);

        // Capture current SecurityContext
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(anonymous);
        SecurityContextHolder.setContext(context);

        if (logger.isTraceEnabled()) {
            logger.trace("Set SecurityContextHolder to {}", anonymous);
        }
    }

    chain.doFilter(req, res);
    // NOTE: Anonymous context is NOT saved to session
    // It only lives for the duration of this request thread
}
```

**The single guard clause is the entire logic:**
`if (getAuthentication() == null)` — if any prior filter has already set an `Authentication`, this filter is completely transparent. It only acts in the absence of any previous authentication.

---

### 4.3 AnonymousAuthenticationToken — Internal Structure

```java
AnonymousAuthenticationToken
     │
     ├── principal    = "anonymousUser"  (String, configurable)
     ├── credentials  = null             (no credentials — anonymous)
     ├── authorities  = [ROLE_ANONYMOUS] (configurable)
     ├── keyHash      = hash of secret key (for validation)
     └── authenticated = true            ← CRITICAL DETAIL
```

**The `authenticated = true` trap:**

`AnonymousAuthenticationToken.isAuthenticated()` returns **`true`**. This surprises most developers who expect anonymous users to have `isAuthenticated() = false`.

**Why is it true?**

`Authentication.isAuthenticated()` does not mean "the user proved their identity." It means "this token has been processed and is a legitimate security context." `AnonymousAuthenticationToken` is a fully processed, legitimate security token — it just represents an identity-less principal.

The correct way to check for a real authenticated user is **not** `isAuthenticated()` alone:

```java
// ❌ WRONG — anonymous users pass this check
authentication.isAuthenticated()   // true for AnonymousAuthenticationToken!

// ✓ CORRECT — excludes anonymous
!(authentication instanceof AnonymousAuthenticationToken)
    && authentication.isAuthenticated()

// ✓ BETTER — use Spring Security's SpEL
@PreAuthorize("isAuthenticated()")       // EXCLUDES anonymous (Spring handles this)
@PreAuthorize("!isAnonymous()")          // explicit
@PreAuthorize("isFullyAuthenticated()")  // excludes anonymous AND remember-me
```

**Spring Security's SpEL handles this correctly:**
`isAuthenticated()` in Spring Security's SpEL expressions is implemented as:
```java
// SecurityExpressionRoot.isAuthenticated():
return !isAnonymous();
// NOT → authentication.isAuthenticated()
```

So `isAuthenticated()` in SpEL correctly excludes anonymous. But `authentication.isAuthenticated()` in raw Java code does NOT. This is a critical distinction.

---

### 4.4 The Key — Anonymous Token Validation

`AnonymousAuthenticationToken` contains a **key hash**:

```java
public AnonymousAuthenticationFilter(String key) {
    // key is a secret string configured for the app
    this.keyHash = key.hashCode();
}

protected Authentication createAuthentication(HttpServletRequest request) {
    AnonymousAuthenticationToken token = new AnonymousAuthenticationToken(
        this.key,                    // key for hash validation
        this.principal,              // "anonymousUser"
        this.authorities             // [ROLE_ANONYMOUS]
    );
    return token;
}
```

The key serves a **validation purpose** with `AnonymousAuthenticationProvider`:

```java
// AnonymousAuthenticationProvider.authenticate():
public Authentication authenticate(Authentication authentication) {
    if (this.key.hashCode() != ((AnonymousAuthenticationToken) authentication).getKeyHash()) {
        throw new BadCredentialsException("The presented AnonymousAuthenticationToken
            does not contain the expected key");
    }
    return authentication;
}
```

**Why does this exist?**
To prevent a malicious actor from crafting a fake `AnonymousAuthenticationToken` from a different security context and injecting it. The key ensures the anonymous token was created by **this application's** `AnonymousAuthenticationFilter`. In practice, since `AnonymousAuthenticationToken` never crosses process/network boundaries, this is mainly a defense-in-depth measure.

**Auto-generated key in Spring Boot:**
Spring Boot auto-generates a random UUID as the key on startup. This means anonymous tokens do not survive application restart — but since they're never persisted, this doesn't matter.

---

### 4.5 SecurityContext Lifecycle for Anonymous Requests

```
Anonymous Request (no credentials)
     │
     ▼
SecurityContextHolderFilter (6.x)
     └── Loads SecurityContext from session/repository
     └── No session exists → returns empty SecurityContext
     └── SecurityContextHolder set with EMPTY context

     ▼
[All auth filters run — UsernamePasswordAuth, BasicAuth, BearerToken, RememberMe]
     └── None match (no credentials) → all pass through
     └── SecurityContext remains EMPTY

     ▼
AnonymousAuthenticationFilter
     └── SecurityContext.getAuthentication() == null → YES
     └── Creates AnonymousAuthenticationToken
     └── Sets it in SecurityContext
     └── SecurityContext now has AnonymousAuthenticationToken
     [NOTE: This is set in SecurityContextHolder but NOT saved to session]

     ▼
ExceptionTranslationFilter
     └── Wraps rest of chain in try-catch

     ▼
AuthorizationFilter
     └── Checks authorization rules
     └── anyRequest().authenticated() → isAuthenticated() = false for anonymous
     └── Throws AccessDeniedException

     ▼
ExceptionTranslationFilter catches AccessDeniedException
     └── Is Authentication instanceof AnonymousAuthenticationToken? YES
     └── → AuthenticationEntryPoint.commence() (401 / redirect to login)

     ▼
End of request:
SecurityContextHolderFilter clears SecurityContextHolder
Anonymous context is NOT saved anywhere
```

---

### 4.6 How Anonymous Authentication Drives 401 vs 403 — The Core Mechanism

This is the most architecturally significant role of anonymous authentication:

```java
// ExceptionTranslationFilter internal logic:
private void handleSpringSecurityException(
        HttpServletRequest request,
        HttpServletResponse response,
        FilterChain chain,
        RuntimeException exception) throws IOException, ServletException {

    if (exception instanceof AuthenticationException) {
        // → Always calls AuthenticationEntryPoint (401)
        sendStartAuthentication(request, response, chain,
            (AuthenticationException) exception);
    }
    else if (exception instanceof AccessDeniedException) {
        Authentication authentication =
            SecurityContextHolder.getContext().getAuthentication();

        // THE CRITICAL CHECK:
        if (authenticationTrustResolver.isAnonymous(authentication)
                || authenticationTrustResolver.isRememberMe(authentication)) {
            // Anonymous or remember-me → treat as unauthenticated → 401 / redirect
            sendStartAuthentication(request, response, chain,
                new InsufficientAuthenticationException(
                    "Full authentication is required to access this resource"));
        }
        else {
            // Fully authenticated → access denied → 403
            this.accessDeniedHandler.handle(request, response,
                (AccessDeniedException) exception);
        }
    }
}
```

**`AuthenticationTrustResolver`** is the component that decides:
- `isAnonymous()` → checks `instanceof AnonymousAuthenticationToken`
- `isRememberMe()` → checks `instanceof RememberMeAuthenticationToken`
- `isFullyAuthenticated()` → neither anonymous nor remember-me

---

### 4.7 Customizing Anonymous Authentication

You can customize the anonymous principal, authorities, and key:

```java
http.anonymous(anon -> anon
    .principal("guest")                          // Change from "anonymousUser"
    .authorities("ROLE_GUEST", "READ_PUBLIC")    // Change from [ROLE_ANONYMOUS]
    .key("my-anonymous-key")                     // Custom key
);
```

**Disabling anonymous authentication:**

```java
http.anonymous(AbstractHttpConfigurer::disable)
```

**When to disable:**
- When `SecurityContextHolder.getContext().getAuthentication() == null` is explicitly used in code
- For highly restricted internal APIs where even anonymous context shouldn't exist
- Performance micro-optimization (saves one filter operation)

**When NOT to disable (99% of cases):**
Disabling anonymous authentication breaks `isAnonymous()`, `isAuthenticated()` SpEL expressions, and the 401/403 decision in `ExceptionTranslationFilter`. Almost always leave it enabled.

---

### 4.8 Anonymous Authentication in Method Security

```java
@RestController
public class DataController {

    @GetMapping("/public")
    // No security annotation — everyone can call this
    // Including anonymous users
    public String publicData() { return "public"; }

    @GetMapping("/user-data")
    @PreAuthorize("isAuthenticated()")
    // isAuthenticated() in SpEL = !isAnonymous()
    // Anonymous users get AccessDeniedException → 401
    public String userData() { return "user data"; }

    @GetMapping("/full-auth")
    @PreAuthorize("isFullyAuthenticated()")
    // Excludes BOTH anonymous AND remember-me users
    // Remember-me users get AccessDeniedException → 401
    // Full auth users with wrong role get AccessDeniedException → 403
    public String sensitiveAction() { return "sensitive"; }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    // Anonymous → AccessDeniedException → 401 (anonymous check)
    // ROLE_USER → AccessDeniedException → 403 (authorized but wrong role)
    public String adminData() { return "admin"; }
}
```

---

## 2️⃣ Code Examples

---

### Example 1 — Default Anonymous Configuration (6.x)

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/public/**").permitAll()
                .requestMatchers("/user/**").hasRole("USER")
                .anyRequest().authenticated()
            )
            // Anonymous authentication is ON by default
            // No need to configure unless customizing
            .formLogin(Customizer.withDefaults());

        return http.build();
    }
}
```

---

### Example 2 — Custom Anonymous Principal with Authorities

```java
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http
        .anonymous(anon -> anon
            // Custom principal object (not just a String)
            .principal(new GuestPrincipal("guest", "Guest User"))
            // Extended authorities for guest access
            .authorities(
                new SimpleGrantedAuthority("ROLE_ANONYMOUS"),
                new SimpleGrantedAuthority("READ_PUBLIC_CONTENT"),
                new SimpleGrantedAuthority("VIEW_CATALOG")
            )
        )
        .authorizeHttpRequests(auth -> auth
            // Guests can view catalog (has VIEW_CATALOG authority)
            .requestMatchers("/catalog/**").hasAuthority("VIEW_CATALOG")
            .anyRequest().authenticated()
        );

    return http.build();
}

// Custom guest principal:
public record GuestPrincipal(String username, String displayName)
        implements Serializable {}
```

**Accessing custom anonymous principal in controller:**
```java
@GetMapping("/catalog")
public String catalog(Authentication authentication) {
    if (authentication instanceof AnonymousAuthenticationToken) {
        GuestPrincipal guest = (GuestPrincipal) authentication.getPrincipal();
        log.info("Guest viewing catalog: {}", guest.displayName());
    }
    return "catalog";
}
```

---

### Example 3 — Checking Anonymous Status Correctly

```java
@Service
public class ContentService {

    public String getContent(Authentication authentication) {

        // ❌ WRONG — anonymous returns true here
        if (authentication.isAuthenticated()) {
            return "authenticated content";
        }

        // ✓ CORRECT — raw Java check
        if (authentication != null
                && !(authentication instanceof AnonymousAuthenticationToken)
                && authentication.isAuthenticated()) {
            return "authenticated content";
        }

        return "public content";
    }

    // ✓ BEST — use AuthenticationTrustResolver
    @Autowired
    private AuthenticationTrustResolver trustResolver;

    public String getContentWithResolver(Authentication auth) {
        if (!trustResolver.isAnonymous(auth)) {
            return "authenticated content";
        }
        return "public content";
    }
}
```

---

### Example 4 — isAuthenticated() vs isFullyAuthenticated() vs isAnonymous()

```java
@RestController
@RequestMapping("/api")
public class SecurityDemoController {

    // Accessible by everyone including anonymous
    @GetMapping("/open")
    public String open() {
        return "Open to all";
    }

    // Accessible by any non-anonymous user
    // (includes remember-me authenticated users)
    @GetMapping("/authenticated")
    @PreAuthorize("isAuthenticated()")
    public String authenticated() {
        return "Any authenticated user";
    }

    // Requires full authentication — NOT remember-me
    // Use for sensitive operations: password change, payment, etc.
    @GetMapping("/sensitive")
    @PreAuthorize("isFullyAuthenticated()")
    public String sensitive() {
        return "Full authentication required";
    }

    // Explicitly checking anonymous (for conditional behavior)
    @GetMapping("/personalized")
    public ResponseEntity<String> personalized(Authentication auth) {
        if (auth instanceof AnonymousAuthenticationToken) {
            return ResponseEntity.ok("Hello, Guest! Please login for personalized content.");
        }
        return ResponseEntity.ok("Hello, " + auth.getName() + "!");
    }
}
```

---

### Example 5 — Anonymous Authentication in Filter — Manual Check

```java
// Custom filter that logs access patterns
@Component
public class AccessAuditFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        // NOTE: This filter runs BEFORE AnonymousAuthenticationFilter
        // if placed at order < 1300
        // So auth could still be null at this point!

        if (auth == null) {
            log.debug("Request with no authentication yet: {}", request.getRequestURI());
        } else if (auth instanceof AnonymousAuthenticationToken) {
            log.debug("Anonymous request to: {}", request.getRequestURI());
        } else {
            log.info("Authenticated request by {} to: {}",
                auth.getName(), request.getRequestURI());
        }

        filterChain.doFilter(request, response);
    }
}
```

```java
// Register AFTER AnonymousAuthenticationFilter to ensure
// anonymous token is always set before this filter runs:
http.addFilterAfter(accessAuditFilter, AnonymousAuthenticationFilter.class);
```

---

### Example 6 — Custom AuthenticationTrustResolver

```java
// Custom trust resolver that also treats
// "service account" tokens as anonymous for UI purposes
@Component
public class CustomTrustResolver extends AuthenticationTrustResolverImpl {

    @Override
    public boolean isAnonymous(Authentication authentication) {
        // Default anonymous check
        if (super.isAnonymous(authentication)) return true;

        // Also treat service accounts as "anonymous" for UI decisions
        if (authentication instanceof ServiceAccountAuthenticationToken) {
            return true;
        }
        return false;
    }
}
```

```java
// Register in config:
@Bean
public SecurityFilterChain filterChain(HttpSecurity http,
        CustomTrustResolver trustResolver) throws Exception {
    http
        // ExceptionTranslationFilter uses this resolver
        .exceptionHandling(ex -> ex
            .withObjectPostProcessor(new ObjectPostProcessor<ExceptionTranslationFilter>() {
                @Override
                public <O extends ExceptionTranslationFilter> O postProcess(O filter) {
                    filter.setAuthenticationTrustResolver(trustResolver);
                    return filter;
                }
            })
        );
    return http.build();
}
```

---

### Example 7 — Disabling Anonymous Auth + Consequences

```java
// ❌ DANGEROUS — disabling without understanding consequences
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http
        .anonymous(AbstractHttpConfigurer::disable)
        .authorizeHttpRequests(auth -> auth
            .anyRequest().authenticated()
        );

    return http.build();
}

// Consequence 1: With anonymous disabled, SecurityContext.getAuthentication() = null
//               for unauthenticated requests
// Consequence 2: ExceptionTranslationFilter uses AuthenticationTrustResolver
//               which calls isAnonymous() — with null, behavior may differ
// Consequence 3: SpEL isAnonymous() returns false for null auth
//               (not an AnonymousAuthenticationToken)
// Consequence 4: Code that does getAuthentication().getName() → NullPointerException

// ✓ Better: keep anonymous enabled, customize what anonymous users can access
```

---

## 3️⃣ Exam-Style Questions

---

**Q1 (MCQ):** What is returned by `AnonymousAuthenticationToken.isAuthenticated()`?

A. `false` — because the user has not proven their identity
B. `true` — because the token is a fully processed security token
C. Throws `UnsupportedOperationException`
D. Depends on Spring Security version

**Answer: B — `true`**
This is the most common anonymous auth trap. `isAuthenticated()` on `AnonymousAuthenticationToken` returns `true` because it is a fully processed, legitimate token. It does NOT mean "the user proved their identity." Use `isAnonymous()` SpEL or `instanceof AnonymousAuthenticationToken` check to detect anonymous users.

---

**Q2 (MCQ):** At what point in the filter chain does `AnonymousAuthenticationFilter` run?

A. Before `UsernamePasswordAuthenticationFilter`
B. Before `CsrfFilter`
C. After all authentication filters, before `ExceptionTranslationFilter`
D. After `ExceptionTranslationFilter`

**Answer: C**
`AnonymousAuthenticationFilter` (order ~1300) runs after all authentication filters but before `ExceptionTranslationFilter` (~1500) and `AuthorizationFilter` (~1600). This ordering is deliberate — it sets the anonymous token only if no real authentication occurred, then authorization proceeds with a consistent non-null `Authentication`.

---

**Q3 (Select All That Apply):** Which Spring Security SpEL expressions correctly exclude anonymous users?

A. `isAuthenticated()`
B. `isFullyAuthenticated()`
C. `!isAnonymous()`
D. `authentication.isAuthenticated()`
E. `hasRole('USER')`

**Answer: A, B, C, E**
D is false — `authentication.isAuthenticated()` in raw Java returns `true` for `AnonymousAuthenticationToken`. Spring Security's SpEL `isAuthenticated()` is implemented as `!isAnonymous()`, not as `authentication.isAuthenticated()`. E is correct — anonymous users have `ROLE_ANONYMOUS`, not `ROLE_USER`, so `hasRole('USER')` fails for anonymous.

---

**Q4 (Code Prediction):**

```java
http.authorizeHttpRequests(auth -> auth
    .anyRequest().authenticated()
);
// No formLogin, no httpBasic configured
```

An anonymous user (no credentials) requests `GET /data`. What is the HTTP response?

A. 401 Unauthorized
B. 403 Forbidden
C. 302 redirect to `/login`
D. 500 Internal Server Error

**Answer: A — 401 Unauthorized**
Without form login or Basic auth configured, there is no `AuthenticationEntryPoint` that redirects to a login page. The default `Http403ForbiddenEntryPoint` or `HttpStatusEntryPoint(401)` applies. The anonymous user hits the `AuthorizationFilter`, throws `AccessDeniedException`, `ExceptionTranslationFilter` sees it is anonymous → calls `AuthenticationEntryPoint` → returns 401.

Actually, the precise answer depends on the default entry point. With no form login, the default `ExceptionTranslationFilter` uses `Http403ForbiddenEntryPoint` which returns **403**. This is another version-dependent trap.

**Precise answer:** With no form login and no HTTP basic configured — the default `AuthenticationEntryPoint` is `Http403ForbiddenEntryPoint` → returns **403** (not 401). This is a famous trap. To get 401, you must configure an `AuthenticationEntryPoint` explicitly.

---

**Q5 (Scenario):**

```java
@PreAuthorize("isAuthenticated()")
public String getData() { ... }
```

An anonymous user (with `AnonymousAuthenticationToken`) calls `getData()`. Trace the exception path and final response.

**Answer:**
```
1. AOP proxy intercepts getData()
2. AuthorizationManagerBeforeMethodInterceptor evaluates isAuthenticated()
3. SpEL: isAuthenticated() = !isAnonymous() = false for AnonymousAuthenticationToken
4. Throws AccessDeniedException
5. Exception propagates through Spring MVC
6. ExceptionTranslationFilter (if still in filter scope) OR
   Spring MVC @ExceptionHandler / BasicErrorController handles it
7. ExceptionTranslationFilter: isAnonymous? YES
   → AuthenticationEntryPoint → 401 (or redirect if form login)
```

---

**Q6 (Filter Order Drag-and-Drop):**

Order these from first to last execution for an unauthenticated request:

- `AuthorizationFilter`
- `AnonymousAuthenticationFilter`
- `SecurityContextHolderFilter`
- `ExceptionTranslationFilter`
- `BasicAuthenticationFilter`

**Answer:**
1. `SecurityContextHolderFilter`
2. `BasicAuthenticationFilter`
3. `AnonymousAuthenticationFilter`
4. `ExceptionTranslationFilter`
5. `AuthorizationFilter`

---

**Q7 (Tricky Scenario):**

```java
http.anonymous(anon -> anon
    .authorities("ROLE_ANONYMOUS", "READ_PUBLIC")
);

http.authorizeHttpRequests(auth -> auth
    .requestMatchers("/public").hasAuthority("READ_PUBLIC")
    .anyRequest().denyAll()
);
```

Does an anonymous user get access to `/public`?

**Answer: YES.**
The anonymous token has `READ_PUBLIC` authority (explicitly configured). `hasAuthority("READ_PUBLIC")` checks for exactly `"READ_PUBLIC"` — the anonymous user has it. Access is granted.

This demonstrates that anonymous users are full participants in the authorization model — they can be granted specific authorities beyond just `ROLE_ANONYMOUS`.

---

**Q8 (Code Behavior — The null trap):**

```java
// Filter placed BEFORE AnonymousAuthenticationFilter
@Component
@Order(1200)  // Before AnonymousAuthenticationFilter (1300)
public class MyFilter extends OncePerRequestFilter {
    protected void doFilterInternal(HttpServletRequest req,
            HttpServletResponse res, FilterChain chain) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String name = auth.getName();  // ← What happens?
        chain.doFilter(req, res);
    }
}
```

For an unauthenticated request, what happens at `auth.getName()`?

**Answer: `NullPointerException`.**
This filter runs at order 1200 — BEFORE `AnonymousAuthenticationFilter` (order 1300). At this point, no prior authentication filter has set any `Authentication`. `SecurityContext.getAuthentication()` returns `null`. Calling `.getName()` on null throws NPE.

**Fix:** Either move the filter to run after `AnonymousAuthenticationFilter`, or add a null check:
```java
if (auth != null) { String name = auth.getName(); }
```

---

## 4️⃣ Trick Analysis

---

**Trick 1 — `isAuthenticated()` SpEL vs Java — The Most Common Bug**

```java
// In SpEL (authorization expressions):
@PreAuthorize("isAuthenticated()")
// Internally: SecurityExpressionRoot.isAuthenticated() = !isAnonymous()
// ✓ Correctly EXCLUDES anonymous users

// In raw Java code:
Authentication auth = SecurityContextHolder.getContext().getAuthentication();
if (auth.isAuthenticated()) { ... }
// ✗ AnonymousAuthenticationToken.isAuthenticated() = TRUE
// ✗ INCLUDES anonymous users — BUG!

// Correct Java equivalent:
AuthenticationTrustResolver resolver = new AuthenticationTrustResolverImpl();
if (!resolver.isAnonymous(auth) && auth.isAuthenticated()) { ... }
```

This asymmetry between SpEL and Java API is a classic enterprise bug source.

---

**Trick 2 — Anonymous Token Is Never Saved to Session**

```java
// AnonymousAuthenticationFilter does NOT call:
// SecurityContextRepository.saveContext()

// The anonymous token exists ONLY in SecurityContextHolder
// for the duration of the current request thread.

// On the next request:
// SecurityContextHolderFilter loads empty context from session
// → AnonymousAuthenticationFilter sets anonymous token again
// → Fresh anonymous token each request (new object, same content)
```

This means anonymous authentication has **zero session overhead** — no session is created, no session attribute is written. It is purely in-memory, per-request.

---

**Trick 3 — `permitAll()` Does Not Mean Anonymous Users Are "Logged In"**

```java
.requestMatchers("/public/**").permitAll()
```

Anonymous users accessing `/public/**` still get `AnonymousAuthenticationToken` set by `AnonymousAuthenticationFilter`. `permitAll()` tells `AuthorizationFilter` to allow access regardless of what `Authentication` is present. The anonymous token is still there — it just doesn't matter for access control on that path.

If your code calls `SecurityContextHolder.getContext().getAuthentication().getName()` in a `permitAll()` endpoint, you get `"anonymousUser"` — not null, not an exception, but `"anonymousUser"`.

---

**Trick 4 — `denyAll()` vs Missing Rule for Anonymous**

```java
// Config A:
.anyRequest().authenticated()
// Anonymous → isAuthenticated() = false → AccessDeniedException → 401

// Config B:
.anyRequest().denyAll()
// Anonymous → denyAll() always denies → AccessDeniedException → 401
// (same result for anonymous, but also denies authenticated users!)

// Config C — missing rule (older Spring Security 5.x behavior):
// If no rule matches, the default was to permit
// In 6.x: if no rule matches → deny by default
```

---

**Trick 5 — Anonymous Principal Is a String, Not UserDetails**

```java
Authentication anon = SecurityContextHolder.getContext().getAuthentication();

// This works:
String name = (String) anon.getPrincipal();  // "anonymousUser"

// This FAILS:
UserDetails ud = (UserDetails) anon.getPrincipal();  // ClassCastException!
```

Code that blindly casts `getPrincipal()` to `UserDetails` will crash on anonymous requests. Always check `instanceof` first:

```java
Object principal = auth.getPrincipal();
if (principal instanceof UserDetails ud) {
    // real user
} else {
    // anonymous — principal is a String
}
```

---

**Trick 6 — Remember-Me and Anonymous — The `isFullyAuthenticated()` Distinction**

```
isAnonymous()          → AnonymousAuthenticationToken only
isAuthenticated()      → NOT anonymous (includes remember-me)
isFullyAuthenticated() → NOT anonymous AND NOT remember-me
isRememberMe()         → RememberMeAuthenticationToken only

Practical use:
- Password change page  → @PreAuthorize("isFullyAuthenticated()")
  (prevent remember-me users from changing password without re-login)
- Payment page          → @PreAuthorize("isFullyAuthenticated()")
- Profile view          → @PreAuthorize("isAuthenticated()")
  (remember-me users can view their profile)
```

---

**Trick 7 — Multiple SecurityFilterChain and Anonymous Config**

When multiple `SecurityFilterChain` beans exist, each chain has its **own** `AnonymousAuthenticationFilter` with potentially different principal/authorities. A request matched by Chain 1 gets the Chain 1 anonymous token; a request matched by Chain 2 gets Chain 2's anonymous token.

This is an enterprise architecture point — you can have different anonymous configurations for your API chain vs your web UI chain.

---

## 5️⃣ Summary Sheet

---

### Anonymous Authentication — Complete Flow Diagram

```
HTTP Request (no credentials)
     │
     ▼
[SecurityContextHolderFilter]
     └── Loads context → empty (no session)
     └── SecurityContext.getAuthentication() = null

     ▼
[UsernamePasswordAuthenticationFilter] → no POST /login → pass through
[BasicAuthenticationFilter]            → no Authorization header → pass through
[RememberMeAuthenticationFilter]       → no remember-me cookie → pass through

     ▼
[AnonymousAuthenticationFilter]
     └── getAuthentication() == null? YES
     └── Creates AnonymousAuthenticationToken{
               principal   = "anonymousUser",
               credentials = null,
               authorities = [ROLE_ANONYMOUS],
               authenticated = true    ← !!! not null, not false
         }
     └── Sets in SecurityContextHolder (NOT saved to session)

     ▼
[ExceptionTranslationFilter] — wraps in try-catch

     ▼
[AuthorizationFilter]
     └── Rule: anyRequest().authenticated()
     └── isAuthenticated() = !isAnonymous() = false
     └── Throws AccessDeniedException

     ▼
[ExceptionTranslationFilter catches AccessDeniedException]
     └── authenticationTrustResolver.isAnonymous(auth) → TRUE
     └── sendStartAuthentication()
           └── Form login configured → 302 to /login
           └── Basic configured → 401 + WWW-Authenticate
           └── Neither → 403 (Http403ForbiddenEntryPoint default)
```

---

### SpEL Security Expressions — Authentication Level Table

| Expression | Anonymous | Remember-Me | Full Auth |
|-----------|-----------|------------|-----------|
| `isAnonymous()` | ✅ true | ❌ false | ❌ false |
| `isAuthenticated()` | ❌ false | ✅ true | ✅ true |
| `isRememberMe()` | ❌ false | ✅ true | ❌ false |
| `isFullyAuthenticated()` | ❌ false | ❌ false | ✅ true |
| `permitAll()` | ✅ allowed | ✅ allowed | ✅ allowed |
| `denyAll()` | ❌ denied | ❌ denied | ❌ denied |

---

### Anonymous Token vs Null — Key Differences

| Aspect | `AnonymousAuthenticationToken` | `null` (auth disabled) |
|--------|-------------------------------|----------------------|
| `getAuthentication()` | Returns token object | Returns null |
| `isAuthenticated()` | `true` (trap!) | NPE if not null-checked |
| `getPrincipal()` | `"anonymousUser"` (String) | NPE |
| SpEL `isAnonymous()` | `true` | `false` (null check in resolver) |
| ExceptionTranslation 401/403 | Correctly routes to 401 | May produce 403 or NPE |
| Session saved | Never | N/A |

---

### Key Classes Reference

| Class | Role |
|-------|------|
| `AnonymousAuthenticationFilter` | Sets anonymous token if no auth present |
| `AnonymousAuthenticationToken` | The anonymous identity carrier |
| `AnonymousAuthenticationProvider` | Validates anonymous token key |
| `AuthenticationTrustResolver` | Determines if auth is anonymous/remember-me |
| `AuthenticationTrustResolverImpl` | Default implementation |
| `SecurityExpressionRoot` | SpEL methods: `isAuthenticated()`, `isAnonymous()` |

---

### Common Interview One-Liners

- **`AnonymousAuthenticationToken.isAuthenticated()`** returns **`true`** — does NOT mean identity proven
- **SpEL `isAuthenticated()`** is implemented as **`!isAnonymous()`** — excludes anonymous correctly
- **Anonymous token** is set ONLY if `SecurityContext.getAuthentication() == null` — first auth wins
- **Anonymous context is NEVER saved to session** — pure in-memory, per-request
- **`getPrincipal()`** on anonymous token returns a **`String`**, not `UserDetails` — cast carefully
- **`AuthenticationTrustResolver`** is what `ExceptionTranslationFilter` uses for 401 vs 403 decision
- **`isFullyAuthenticated()`** excludes both anonymous AND remember-me users
- **Disabling anonymous auth** can cause NPEs in code that assumes non-null `Authentication`
- **`permitAll()` endpoints** still receive `AnonymousAuthenticationToken` — principal is `"anonymousUser"`
- **Custom anonymous authorities** allow anonymous users to pass `hasAuthority()` checks

---
