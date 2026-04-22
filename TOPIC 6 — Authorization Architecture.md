# TOPIC 6 — Authorization Architecture

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

---

## 1️⃣ Conceptual Explanation

---

### 6.1 Authorization Architecture — The Big Picture

Authorization in Spring Security answers one question: **"Does this authenticated principal have permission to perform this action?"** The architecture that answers this question is completely separate from authentication and has undergone a major redesign between Spring Security 5.x and 6.x.

**The two authorization domains:**

```
Domain 1 — HTTP Request Authorization
     "Can this principal access this URL?"
     Enforced by: AuthorizationFilter (6.x) / FilterSecurityInterceptor (5.x)
     Position: Last filter in the chain
     Applies to: HTTP requests before reaching controllers

Domain 2 — Method Security Authorization
     "Can this principal call this method?"
     Enforced by: AOP interceptors (AuthorizationManagerBeforeMethodInterceptor, etc.)
     Position: Spring AOP proxy around @Service / @Controller beans
     Applies to: Java method invocations
```

Both domains share the same underlying authorization infrastructure but operate at different layers. Understanding this distinction is fundamental.

---

### 6.2 Spring Security 5.x Authorization — AccessDecisionManager Architecture

In Spring Security 5.x, HTTP authorization was built on the **voter pattern** — multiple independent voters each cast a vote, and a manager aggregates the votes into a final decision.

**The complete 5.x architecture:**

```
FilterSecurityInterceptor
     │
     ├── SecurityMetadataSource.getAttributes(request)
     │       └── Returns: [ConfigAttribute("hasRole('ADMIN')"), ...]
     │
     └── AccessDecisionManager.decide(authentication, object, configAttributes)
               │
               ├── AffirmativeBased   (default) — ANY grant = access
               ├── ConsensusBased     — majority grants = access
               └── UnanimousBased     — ALL must grant = access
                         │
                         Each delegates to voters:
                         ├── RoleVoter
                         │       supports("ROLE_") prefixed attributes
                         │       ACCESS_GRANTED / ACCESS_DENIED / ACCESS_ABSTAIN
                         ├── AuthenticatedVoter
                         │       supports("IS_AUTHENTICATED_FULLY", etc.)
                         └── WebExpressionVoter
                                 supports SpEL expressions
                                 evaluates: hasRole('ADMIN'), isAuthenticated(), etc.
```

**Voter return values:**

```java
public interface AccessDecisionVoter<S> {
    int ACCESS_GRANTED  =  1;   // voter approves
    int ACCESS_DENIED   = -1;   // voter denies
    int ACCESS_ABSTAIN  =  0;   // voter abstains (doesn't apply to this attribute)

    boolean supports(ConfigAttribute attribute);
    boolean supports(Class<?> clazz);
    int vote(Authentication authentication, S object,
             Collection<ConfigAttribute> attributes);
}
```

**Three manager strategies:**

```
AffirmativeBased (default):
     At least ONE voter returns ACCESS_GRANTED → ALLOW
     All voters ABSTAIN → depends on allowIfAllAbstainDecisions (default: deny)

ConsensusBased:
     Count grants vs denies
     grants > denies → ALLOW
     grants < denies → DENY
     grants == denies → depends on allowIfEqualGrantedDeniedDecisions (default: allow)

UnanimousBased:
     ALL voters must return ACCESS_GRANTED (or ABSTAIN)
     ANY single ACCESS_DENIED → DENY
     Most restrictive — used for high-security scenarios
```

---

### 6.3 Spring Security 6.x Authorization — AuthorizationManager Architecture

Spring Security 6.x replaced the entire voter architecture with a single, elegant interface:

```java
@FunctionalInterface
public interface AuthorizationManager<T> {

    // Optional: pre-check without full context
    default void verify(Supplier<Authentication> authentication, T object) {
        AuthorizationDecision decision = check(authentication, object);
        if (decision != null && !decision.isGranted()) {
            throw new AccessDeniedException("Access Denied");
        }
    }

    // The core method — make the authorization decision
    @Nullable
    AuthorizationDecision check(Supplier<Authentication> authentication, T object);
}
```

**Key architectural improvements in 6.x:**

```
1. Lazy Authentication Loading:
   Authentication is wrapped in Supplier<Authentication>
   → Not loaded from SecurityContext until actually needed
   → Performance optimization for permitAll() rules (no auth load needed)

2. Single Interface:
   Replaces AccessDecisionManager + AccessDecisionVoter + ConfigAttribute
   → Simpler to implement, compose, and test

3. Composable:
   AuthorizationManagers can be composed:
   AuthorizationManagers.anyOf(manager1, manager2)  → OR logic
   AuthorizationManagers.allOf(manager1, manager2)  → AND logic

4. Return type:
   AuthorizationDecision (not integer constants)
   └── isGranted() → boolean
   └── Can carry additional context (why denied, confidence level)
```

---

### 6.4 AuthorizationFilter (6.x) — Complete Internal Architecture

`AuthorizationFilter` is the replacement for `FilterSecurityInterceptor`. It is the **last filter** in the security filter chain and performs the final access control check before the request reaches `DispatcherServlet`.

**Complete internal flow:**

```java
public class AuthorizationFilter extends GenericFilterBean {

    private final AuthorizationManager<HttpServletRequest> authorizationManager;

    @Override
    public void doFilter(ServletRequest servletRequest,
                         ServletResponse servletResponse,
                         FilterChain chain) throws IOException, ServletException {

        HttpServletRequest request = (HttpServletRequest) servletRequest;

        // Step 1: Check if this request should be observed
        // (skip for ASYNC, ERROR dispatches if configured)
        if (this.observeOncePerRequest && isApplied(request)) {
            chain.doFilter(request, servletResponse);
            return;
        }

        // Step 2: Check if request matches any configured rules
        if (skipDispatch(request)) {
            chain.doFilter(request, servletResponse);
            return;
        }

        // Step 3: Mark as applied
        String alreadyFilteredAttributeName = getAlreadyFilteredAttributeName();
        request.setAttribute(alreadyFilteredAttributeName, Boolean.TRUE);

        try {
            // Step 4: THE AUTHORIZATION CHECK
            // Supplier wraps SecurityContextHolder.getContext().getAuthentication()
            // → Lazy — only called if authorizationManager needs it
            AuthorizationDecision decision = this.authorizationManager.check(
                this::getAuthentication,   // Supplier<Authentication>
                request
            );

            // Step 5: Publish authorization event
            this.eventPublisher.publishAuthorizationEvent(
                this::getAuthentication, request, decision);

            // Step 6: If denied → throw
            if (decision != null && !decision.isGranted()) {
                throw new AccessDeniedException("Access Denied");
            }

            // Step 7: Granted → continue chain
            chain.doFilter(request, servletResponse);

        } finally {
            request.removeAttribute(alreadyFilteredAttributeName);
        }
    }

    private Authentication getAuthentication() {
        return SecurityContextHolder.getContext().getAuthentication();
    }
}
```

**The `RequestMatcherDelegatingAuthorizationManager` — the actual decision maker:**

```
AuthorizationFilter
     └── RequestMatcherDelegatingAuthorizationManager.check(auth, request)
               │
               Iterates list of (RequestMatcher → AuthorizationManager) pairs:
               │
               ├── RequestMatcher[0]: /api/public/** → AuthorityAuthorizationManager("permitAll")
               │       Matches /api/public/data? YES → check() → granted
               │       (Returns here — first match wins)
               │
               ├── RequestMatcher[1]: /admin/**       → AuthorityAuthorizationManager("ROLE_ADMIN")
               │       Checked only if previous didn't match
               │
               └── RequestMatcher[N]: /** (anyRequest) → AuthenticatedAuthorizationManager
                       Checked last — catch-all rule
```

---

### 6.5 FilterSecurityInterceptor (5.x) — Internal Architecture

For completeness and backward-compatibility exam preparation:

```
FilterSecurityInterceptor extends AbstractSecurityInterceptor
     │
     ├── obtainSecurityMetadataSource()
     │       → DefaultFilterInvocationSecurityMetadataSource
     │               → Maps URL patterns to ConfigAttributes
     │               → e.g., /admin/** → [hasRole('ADMIN')]
     │
     ├── beforeInvocation(FilterInvocation fi)
     │       (from AbstractSecurityInterceptor)
     │       │
     │       ├── attributes = securityMetadataSource.getAttributes(fi)
     │       ├── authentication = SecurityContextHolder.getAuthentication()
     │       │       └── If null → throw AuthenticationCredentialsNotFoundException
     │       ├── authentication = authenticationManager.authenticate(authentication)
     │       │       (re-authenticates if token is not "trusted" — complex edge case)
     │       └── accessDecisionManager.decide(authentication, fi, attributes)
     │               └── Throws AccessDeniedException if denied
     │
     ├── proceed() → chain.doFilter() (the actual request processing)
     │
     └── afterInvocation() (for post-invocation authorization — rare for HTTP)
```

---

### 6.6 ConfigAttribute & SecurityMetadataSource (5.x)

In 5.x, authorization rules were expressed as `ConfigAttribute` strings tied to URL patterns:

```
URL Pattern             ConfigAttribute string
/public/**           →  "permitAll"
/admin/**            →  "hasRole('ADMIN')"
/user/**             →  "hasAnyRole('USER','ADMIN')"
/**                  →  "isAuthenticated()"
```

`SecurityMetadataSource` is the lookup engine that maps a request (URL + method) to its `ConfigAttribute` collection. `DefaultFilterInvocationSecurityMetadataSource` is the standard implementation backed by a `LinkedHashMap` (ordered map — first match wins).

**This entire mechanism is replaced in 6.x** by `RequestMatcherDelegatingAuthorizationManager` with its list of `(RequestMatcher, AuthorizationManager)` pairs.

---

### 6.7 Built-in AuthorizationManager Implementations (6.x)

```
AuthorizationManager<HttpServletRequest> (interface)
     │
     ├── AuthorityAuthorizationManager
     │       └── hasRole("ADMIN") → checks for "ROLE_ADMIN" in authorities
     │       └── hasAuthority("READ") → checks for "READ" in authorities
     │       └── hasAnyRole(...) / hasAnyAuthority(...)
     │
     ├── AuthenticatedAuthorizationManager
     │       └── authenticated()   → !isAnonymous()
     │       └── fullyAuthenticated() → !isAnonymous() && !isRememberMe()
     │       └── rememberMe()      → isRememberMe()
     │       └── anonymous()       → isAnonymous()
     │
     ├── WebExpressionAuthorizationManager
     │       └── Evaluates SpEL: "hasRole('ADMIN') and hasIpAddress('192.168.1.0/24')"
     │
     ├── RequestMatcherDelegatingAuthorizationManager
     │       └── Delegates to first matching (RequestMatcher → AuthorizationManager)
     │
     └── AuthorizationManagers (utility class)
               └── anyOf(manager1, manager2)  → OR composition
               └── allOf(manager1, manager2)  → AND composition
               └── not(manager)               → NOT composition
```

---

### 6.8 Request Matching — `requestMatchers` Deep Internals

**`requestMatchers()` auto-detection in 6.x:**

```java
// Spring Security 6.x requestMatchers() auto-detects:
// If Spring MVC on classpath → MvcRequestMatcher (context-path aware, method aware)
// If no Spring MVC → AntPathRequestMatcher

// MvcRequestMatcher advantages:
// /admin matches /admin, /admin/, /admin.html
// Aware of @RequestMapping suffixes, forward slashes
// Context-path transparent

// AntPathRequestMatcher:
// Literal pattern matching
// /admin only matches /admin exactly
// /admin/ and /admin.html are different
```

**Rule ordering — critical:**

```java
http.authorizeHttpRequests(auth -> auth
    // Rules evaluated IN ORDER — first match wins
    .requestMatchers("/admin/public").permitAll()    // Rule 1
    .requestMatchers("/admin/**").hasRole("ADMIN")  // Rule 2
    .anyRequest().authenticated()                    // Rule 3 — catch-all
);

// /admin/public → Rule 1 matches → permitAll → ALLOW
// /admin/secret → Rule 1 no match → Rule 2 matches → hasRole("ADMIN")
// /user/profile → Rule 1 no match → Rule 2 no match → Rule 3 → authenticated
```

**The ordering trap (reversed rules):**

```java
// ❌ WRONG — more specific rule after less specific rule
http.authorizeHttpRequests(auth -> auth
    .requestMatchers("/admin/**").hasRole("ADMIN")  // Rule 1: catches /admin/public too!
    .requestMatchers("/admin/public").permitAll()   // Rule 2: NEVER REACHED
    .anyRequest().authenticated()
);
// /admin/public → Rule 1 matches (/** is greedy) → requires ROLE_ADMIN
// Rule 2 is dead code — it never executes
```

---

### 6.9 SpEL in Authorization — How It Works Internally

SpEL (Spring Expression Language) authorization expressions like `"hasRole('ADMIN') and hasIpAddress('192.168.0.0/16')"` are evaluated by `WebExpressionAuthorizationManager`.

**Evaluation pipeline:**

```
SpEL string: "hasRole('ADMIN') and !isAnonymous()"
     │
     ▼
ExpressionParser.parseExpression(spel)
     └── Returns Expression object (compiled, cached)

     ▼
SecurityExpressionHandler.createEvaluationContext(auth, request)
     └── Returns StandardEvaluationContext with root object:
               WebSecurityExpressionRoot
                    │
                    ├── hasRole(String role)
                    ├── hasAuthority(String authority)
                    ├── hasAnyRole(String... roles)
                    ├── hasAnyAuthority(String... authorities)
                    ├── isAuthenticated()    → !isAnonymous()
                    ├── isAnonymous()        → instanceof AnonymousAuthenticationToken
                    ├── isFullyAuthenticated()
                    ├── isRememberMe()
                    ├── permitAll()          → always true
                    ├── denyAll()            → always false
                    ├── hasIpAddress(String) → checks remote IP/CIDR
                    └── authentication       → current Authentication object

     ▼
expression.getValue(evaluationContext, Boolean.class)
     └── Returns true (ALLOW) or false (DENY)
```

**Custom SpEL beans:**

```java
// In SpEL, you can reference Spring beans with @beanName syntax:
.requestMatchers("/api/**")
    .access("@myAuthorizationBean.canAccess(authentication, request)")

@Component("myAuthorizationBean")
public class MyAuthorizationBean {
    public boolean canAccess(Authentication auth, HttpServletRequest request) {
        // Custom logic
        return auth.getAuthorities().stream()
            .anyMatch(a -> a.getAuthority().startsWith("SCOPE_"));
    }
}
```

---

### 6.10 hasRole vs hasAuthority — The Complete Internal Mechanics

```java
// hasRole("ADMIN") internal implementation:
public boolean hasRole(String role) {
    // Prepends ROLE_ automatically
    return hasAuthority("ROLE_" + role);
}

// hasAuthority("READ") internal implementation:
public boolean hasAuthority(String authority) {
    return authentication.getAuthorities()
        .stream()
        .anyMatch(ga -> ga.getAuthority().equals(authority));
}
```

**The `ROLE_` prefix mechanics — complete picture:**

```
Storage:
UserDetails.getAuthorities() = [SimpleGrantedAuthority("ROLE_ADMIN")]
                                ↑ stored WITH prefix

Check:
hasRole("ADMIN")     → checks "ROLE_ADMIN" ✓
hasAuthority("ADMIN")→ checks "ADMIN"      ✗ (no ROLE_ prefix in stored value)
hasAuthority("ROLE_ADMIN") → checks "ROLE_ADMIN" ✓

User builder:
User.builder().roles("ADMIN")        → stores "ROLE_ADMIN" (adds prefix)
User.builder().authorities("ADMIN")  → stores "ADMIN" (no prefix)

The trap:
User.builder().authorities("ROLE_ADMIN")  → stores "ROLE_ADMIN" (correct)
User.builder().roles("ROLE_ADMIN")        → stores "ROLE_ROLE_ADMIN" ← DOUBLE PREFIX BUG
```

---

### 6.11 Authorization Events — 6.x Enhancement

```java
// Spring Security 6.x publishes authorization events automatically:

AuthorizationGrantedEvent  → published when access is granted
AuthorizationDeniedEvent   → published when access is denied

// Listen to these for audit logging:
@Component
public class AuthorizationAuditListener {

    @EventListener
    public void onGranted(AuthorizationGrantedEvent event) {
        // Optional — can be very noisy (every successful request)
    }

    @EventListener
    public void onDenied(AuthorizationDeniedEvent event) {
        log.warn("Access denied: principal={}, resource={}",
            event.getAuthentication().get().getName(),
            event.getObject());
    }
}
```

---

## 2️⃣ Code Examples

---

### Example 1 — Complete Authorization Config (6.x)

```java
@Configuration
@EnableWebSecurity
public class AuthorizationConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth

                // ── Public resources ─────────────────────────────────────
                .requestMatchers("/public/**", "/actuator/health").permitAll()
                .requestMatchers(HttpMethod.GET, "/api/products/**").permitAll()

                // ── Static resources (skip filter chain entirely) ─────────
                // Done via WebSecurityCustomizer, not here

                // ── Admin section ─────────────────────────────────────────
                .requestMatchers("/admin/**").hasRole("ADMIN")

                // ── API section with authority check ─────────────────────
                .requestMatchers("/api/write/**").hasAuthority("WRITE_ACCESS")
                .requestMatchers("/api/read/**").hasAnyAuthority(
                    "READ_ACCESS", "WRITE_ACCESS")

                // ── Multiple conditions with SpEL ─────────────────────────
                .requestMatchers("/api/internal/**")
                    .access(new WebExpressionAuthorizationManager(
                        "hasRole('API') and hasIpAddress('10.0.0.0/8')"))

                // ── Require full authentication (no remember-me) ──────────
                .requestMatchers("/account/password").fullyAuthenticated()

                // ── Custom AuthorizationManager ───────────────────────────
                .requestMatchers("/api/dynamic/**")
                    .access(customAuthorizationManager())

                // ── Catch-all ─────────────────────────────────────────────
                .anyRequest().authenticated()
            );

        return http.build();
    }

    @Bean
    public AuthorizationManager<RequestAuthorizationContext> customAuthorizationManager() {
        return (authSupplier, context) -> {
            Authentication auth = authSupplier.get();
            HttpServletRequest request = context.getRequest();

            // Dynamic authorization logic
            String resourceId = request.getParameter("resourceId");
            boolean canAccess = checkDynamicPermission(auth, resourceId);

            return new AuthorizationDecision(canAccess);
        };
    }
}
```

---

### Example 2 — Static Resource Bypass (WebSecurityCustomizer)

```java
@Bean
public WebSecurityCustomizer webSecurityCustomizer() {
    // These paths BYPASS FilterChainProxy entirely
    // No security filters run — maximum performance for truly static content
    return web -> web.ignoring()
        .requestMatchers(
            "/static/**",
            "/css/**",
            "/js/**",
            "/images/**",
            "/favicon.ico",
            "/webjars/**"
        );
}

// vs permitAll() which still runs all filters:
// .requestMatchers("/static/**").permitAll()
// ← CsrfFilter, SecurityContextHolderFilter, etc. still execute
// Use WebSecurityCustomizer.ignoring() for truly static resources
```

---

### Example 3 — 5.x AccessDecisionManager (Legacy)

```java
// Spring Security 5.x — custom voter
public class MinimumAgeVoter implements AccessDecisionVoter<FilterInvocation> {

    @Override
    public boolean supports(ConfigAttribute attribute) {
        return attribute.getAttribute() != null
            && attribute.getAttribute().startsWith("MIN_AGE_");
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return FilterInvocation.class.isAssignableFrom(clazz);
    }

    @Override
    public int vote(Authentication authentication,
                    FilterInvocation fi,
                    Collection<ConfigAttribute> attributes) {

        for (ConfigAttribute attribute : attributes) {
            if (supports(attribute)) {
                int minAge = Integer.parseInt(
                    attribute.getAttribute().substring(8));

                // Extract age from UserDetails
                if (authentication.getPrincipal() instanceof CustomUserDetails ud) {
                    return ud.getAge() >= minAge
                        ? ACCESS_GRANTED : ACCESS_DENIED;
                }
                return ACCESS_ABSTAIN;
            }
        }
        return ACCESS_ABSTAIN;
    }
}

// Register with AccessDecisionManager:
@Bean
public AccessDecisionManager accessDecisionManager() {
    List<AccessDecisionVoter<?>> voters = List.of(
        new RoleVoter(),
        new AuthenticatedVoter(),
        new WebExpressionVoter(),
        new MinimumAgeVoter()         // custom voter
    );
    return new AffirmativeBased(voters);
}

// 5.x config:
http.authorizeRequests()
    .antMatchers("/adult/**").access("MIN_AGE_18")
    .withObjectPostProcessor(new ObjectPostProcessor<FilterSecurityInterceptor>() {
        @Override
        public <O extends FilterSecurityInterceptor> O postProcess(O fsi) {
            fsi.setAccessDecisionManager(accessDecisionManager());
            return fsi;
        }
    });
```

---

### Example 4 — Custom AuthorizationManager (6.x)

```java
// Custom AuthorizationManager for resource ownership check
@Component
public class ResourceOwnerAuthorizationManager
        implements AuthorizationManager<RequestAuthorizationContext> {

    private final ResourceRepository resourceRepository;

    @Override
    public AuthorizationDecision check(
            Supplier<Authentication> authenticationSupplier,
            RequestAuthorizationContext context) {

        // Lazy — only load auth if needed
        Authentication auth = authenticationSupplier.get();

        // Extract resource ID from path variable
        String resourceId = context.getVariables().get("resourceId");

        if (resourceId == null) {
            return new AuthorizationDecision(false);
        }

        // Check if user owns the resource
        boolean isOwner = resourceRepository
            .existsByIdAndOwnerUsername(
                Long.parseLong(resourceId),
                auth.getName()
            );

        // Admin can access any resource
        boolean isAdmin = auth.getAuthorities().stream()
            .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"));

        return new AuthorizationDecision(isOwner || isAdmin);
    }
}
```

```java
// Register with path variable extraction:
http.authorizeHttpRequests(auth -> auth
    .requestMatchers("/api/resources/{resourceId}")
        .access(resourceOwnerAuthorizationManager)
    .anyRequest().authenticated()
);
```

---

### Example 5 — Composing AuthorizationManagers

```java
// Compose multiple AuthorizationManagers
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

    // Manager 1: must be authenticated
    AuthorizationManager<RequestAuthorizationContext> authenticated =
        AuthenticatedAuthorizationManager.authenticated();

    // Manager 2: must have specific IP
    AuthorizationManager<RequestAuthorizationContext> internalIp =
        new WebExpressionAuthorizationManager(
            "hasIpAddress('10.0.0.0/8')");

    // Manager 3: must have ROLE_API
    AuthorizationManager<RequestAuthorizationContext> hasApiRole =
        AuthorityAuthorizationManager.hasRole("API");

    // Compose: must satisfy ALL three (AND logic)
    AuthorizationManager<RequestAuthorizationContext> combined =
        AuthorizationManagers.allOf(authenticated, internalIp, hasApiRole);

    http.authorizeHttpRequests(auth -> auth
        .requestMatchers("/internal/api/**").access(combined)
        .anyRequest().authenticated()
    );

    return http.build();
}
```

---

### Example 6 — Incorrect Configurations & Why They Fail

```java
// ❌ WRONG 1 — anyRequest() before specific rules
http.authorizeHttpRequests(auth -> auth
    .anyRequest().authenticated()      // catches EVERYTHING including /admin
    .requestMatchers("/admin/**").hasRole("ADMIN")  // DEAD CODE — never reached
);
// Spring Security 6.x actually throws an exception:
// "Can't configure requestMatchers after anyRequest"

// ✓ CORRECT — anyRequest() ALWAYS last
http.authorizeHttpRequests(auth -> auth
    .requestMatchers("/admin/**").hasRole("ADMIN")
    .anyRequest().authenticated()
);
```

```java
// ❌ WRONG 2 — hasRole with ROLE_ prefix (double prefix)
http.authorizeHttpRequests(auth -> auth
    .requestMatchers("/admin/**").hasRole("ROLE_ADMIN")
    // checks for "ROLE_ROLE_ADMIN" — will NEVER match!
);

// ✓ CORRECT
.requestMatchers("/admin/**").hasRole("ADMIN")       // checks "ROLE_ADMIN"
.requestMatchers("/admin/**").hasAuthority("ROLE_ADMIN")  // also correct
```

```java
// ❌ WRONG 3 — using authorizeRequests() in 6.x
http.authorizeRequests()  // REMOVED in Spring Security 6.x
    .antMatchers("/admin/**").hasRole("ADMIN");

// ✓ CORRECT in 6.x
http.authorizeHttpRequests(auth -> auth
    .requestMatchers("/admin/**").hasRole("ADMIN")
);
```

```java
// ❌ WRONG 4 — method-level + URL-level conflict (silent override)
// URL config:
.requestMatchers("/api/admin/**").permitAll()

// Method config:
@PreAuthorize("hasRole('ADMIN')")
public ResponseEntity<?> adminEndpoint() { ... }

// Request to /api/admin/data:
// URL config: permitAll() → passes AuthorizationFilter
// Method config: @PreAuthorize("hasRole('ADMIN')") → evaluated by AOP
// → User without ROLE_ADMIN gets 403 DESPITE permitAll() at URL level!

// Both layers are enforced independently
// URL permitAll() does NOT bypass method security
```

---

## 3️⃣ Exam-Style Questions

---

**Q1 (MCQ):** Which `AccessDecisionManager` strategy grants access if **any single voter** returns `ACCESS_GRANTED`?

A. `UnanimousBased`
B. `ConsensusBased`
C. `AffirmativeBased`
D. `DelegatingBased`

**Answer: C — `AffirmativeBased`**
`AffirmativeBased` is the default strategy. It grants access if at least one voter returns `ACCESS_GRANTED`, regardless of other voters' decisions. `UnanimousBased` requires all voters to grant. `ConsensusBased` uses majority.

---

**Q2 (MCQ):** In Spring Security 6.x, what replaced `FilterSecurityInterceptor`?

A. `SecurityInterceptorFilter`
B. `AuthorizationFilter`
C. `AccessDecisionFilter`
D. `RequestAuthorizationFilter`

**Answer: B — `AuthorizationFilter`**
`AuthorizationFilter` is the 6.x replacement for `FilterSecurityInterceptor`. It uses `AuthorizationManager<HttpServletRequest>` instead of `AccessDecisionManager` + voters.

---

**Q3 (Select All That Apply):** Which are true about `AuthorizationManager` in Spring Security 6.x?

A. It accepts a `Supplier<Authentication>` for lazy loading
B. It directly replaces all three: `AccessDecisionManager`, `AccessDecisionVoter`, and `ConfigAttribute`
C. `permitAll()` can be optimized to skip `SecurityContext` loading entirely
D. `AuthorizationDecision` replaces integer constants `ACCESS_GRANTED` and `ACCESS_DENIED`
E. `AuthorizationManagers.allOf()` implements OR logic

**Answer: A, B, C, D**
E is false — `allOf()` is AND logic (all must grant). `anyOf()` is OR logic.

---

**Q4 (Rule Order Prediction):**

```java
http.authorizeHttpRequests(auth -> auth
    .requestMatchers("/api/**").hasRole("USER")
    .requestMatchers("/api/admin/**").hasRole("ADMIN")
    .anyRequest().permitAll()
);
```

A user with only `ROLE_USER` accesses `GET /api/admin/users`. What is the result?

A. 200 OK — user has `ROLE_USER`, matches first rule
B. 403 Forbidden — second rule requires `ROLE_ADMIN`
C. 403 Forbidden — first rule matches (`/api/**`), user has `ROLE_USER`, check passes, but second rule denies
D. 403 Forbidden — first rule matches, user has `ROLE_USER` which satisfies `hasRole("USER")`, access granted, but then second rule also checked

**Answer: A — 200 OK (or rather, access granted by first rule)**
`/api/admin/users` matches `/api/**` (Rule 1) FIRST. Rule 1 requires `ROLE_USER`. The user has `ROLE_USER`. **First match wins — Rule 2 is never evaluated.** Access is GRANTED.

This is a critical security misconfiguration trap. The more specific `/api/admin/**` rule must come BEFORE the broader `/api/**` rule.

---

**Q5 (hasRole vs hasAuthority):**

```java
UserDetails user = User.builder()
    .username("alice")
    .password("...")
    .authorities("ADMIN", "READ")  // Note: authorities(), not roles()
    .build();
```

Which expression grants Alice access?

```java
// A
.requestMatchers("/admin").hasRole("ADMIN")
// B
.requestMatchers("/admin").hasAuthority("ADMIN")
// C
.requestMatchers("/admin").hasRole("ROLE_ADMIN")
// D
.requestMatchers("/admin").hasAuthority("ROLE_ADMIN")
```

**Answer: B only**
`authorities("ADMIN", "READ")` stores `SimpleGrantedAuthority("ADMIN")` and `SimpleGrantedAuthority("READ")` — NO `ROLE_` prefix.
- A: `hasRole("ADMIN")` checks for `"ROLE_ADMIN"` — not present → DENY
- B: `hasAuthority("ADMIN")` checks for `"ADMIN"` — present → GRANT ✓
- C: `hasRole("ROLE_ADMIN")` checks for `"ROLE_ROLE_ADMIN"` — not present → DENY
- D: `hasAuthority("ROLE_ADMIN")` checks for `"ROLE_ADMIN"` — not present → DENY

---

**Q6 (Voter Pattern):**

Three voters evaluate a request:
- `RoleVoter`: `ACCESS_ABSTAIN` (no ROLE_ attribute)
- `AuthenticatedVoter`: `ACCESS_GRANTED`
- `WebExpressionVoter`: `ACCESS_DENIED`

What does each strategy decide?

**Answer:**

| Strategy | Logic | Decision |
|----------|-------|----------|
| `AffirmativeBased` | Any GRANT → allow | **GRANTED** (AuthenticatedVoter granted) |
| `ConsensusBased` | 1 grant, 1 deny (abstain ignored) | **GRANTED** (tie → `allowIfEqualGrantedDeniedDecisions=true` default) |
| `UnanimousBased` | Any DENY → refuse | **DENIED** (WebExpressionVoter denied) |

---

**Q7 (Tricky Scenario):**

```java
http.authorizeHttpRequests(auth -> auth
    .anyRequest().access(new WebExpressionAuthorizationManager(
        "hasRole('ADMIN') or @permissionEvaluator.check(authentication, request)"))
);
```

A user with `ROLE_USER` calls `/api/data`. The `permissionEvaluator.check()` bean is NOT loaded (context initialization failure). What happens?

**Answer:** `SpelEvaluationException` is thrown during filter processing. Since `hasRole('ADMIN')` is false (short-circuit doesn't apply — OR continues), the SpEL evaluator tries to resolve `@permissionEvaluator` bean. If the bean doesn't exist → `SpelEvaluationException` → propagates as a 500 Internal Server Error. SpEL bean references must exist in the application context or the evaluation crashes.

---

**Q8 (5.x vs 6.x Migration):**

```java
// 5.x code:
http.authorizeRequests()
    .antMatchers("/admin/**").hasRole("ADMIN")
    .mvcMatchers("/api/**").hasAuthority("API_ACCESS")
    .anyRequest().authenticated()
    .and()
    .exceptionHandling()
        .accessDeniedHandler(customHandler);
```

Rewrite this for Spring Security 6.x.

**Answer:**
```java
http
    .authorizeHttpRequests(auth -> auth
        .requestMatchers("/admin/**").hasRole("ADMIN")
        .requestMatchers("/api/**").hasAuthority("API_ACCESS")
        .anyRequest().authenticated()
    )
    .exceptionHandling(ex -> ex
        .accessDeniedHandler(customHandler)
    );
```

Changes: `authorizeRequests()` → `authorizeHttpRequests()`, `antMatchers/mvcMatchers` → `requestMatchers()`, `.and()` chaining → lambda DSL, no `and()` needed.

---

## 4️⃣ Trick Analysis

---

**Trick 1 — `anyRequest()` Must Always Be Last**

Spring Security 6.x throws `IllegalStateException` if you try to add rules after `anyRequest()`:

```java
// ❌ Throws: "Can't configure requestMatchers after anyRequest"
.anyRequest().authenticated()
.requestMatchers("/admin/**").hasRole("ADMIN")

// ✓ Correct
.requestMatchers("/admin/**").hasRole("ADMIN")
.anyRequest().authenticated()
```

In 5.x, this was a silent bug — rules after `anyRequest()` were unreachable. In 6.x, it's an explicit error.

---

**Trick 2 — `permitAll()` Optimizes Away SecurityContext Loading**

In Spring Security 6.x with `AuthorizationManager`:

```java
// When a rule is: .requestMatchers("/public/**").permitAll()
// The AuthorizationManager for this rule is:
// PermitAllAuthorizationManager — always returns AuthorizationDecision(true)
// WITHOUT calling authenticationSupplier.get()
// → SecurityContext is NEVER loaded for these requests
// → HttpSession is not accessed at all for permitAll() paths

// This is a significant performance improvement over 5.x
// where FilterSecurityInterceptor always loaded the SecurityContext
```

---

**Trick 3 — URL Security vs Method Security Independence**

```
URL security (.authorizeHttpRequests) and method security (@PreAuthorize)
are COMPLETELY INDEPENDENT layers.

They do NOT know about each other.
Each enforces its own rules independently.

Result:
permitAll() at URL level + @PreAuthorize("hasRole('ADMIN')") at method level
→ URL layer: ALLOWS (permitAll)
→ Method layer: DENIES (no ROLE_ADMIN)
→ Final result: 403 Forbidden

This is actually CORRECT behavior for defense-in-depth.
But it surprises developers who think permitAll() bypasses everything.
```

---

**Trick 4 — `ACCESS_ABSTAIN` in `UnanimousBased` Behavior**

```
UnanimousBased with all voters ABSTAINING:
→ No grants, no denies
→ allowIfAllAbstainDecisions = false (default) → DENY
→ allowIfAllAbstainDecisions = true → GRANT

This is a subtle default that catches teams off-guard when
custom voters ABSTAIN for unexpected paths.
```

---

**Trick 5 — `WebSecurityCustomizer.ignoring()` vs `permitAll()`**

```
ignoring():
✓ Zero security filter overhead (bypasses FilterChainProxy entirely)
✓ Best for truly static files
✗ No SecurityContext — authentication info unavailable
✗ No CSRF protection (not needed for static files)
✗ No security headers (X-Frame-Options, etc.)

permitAll():
✓ All filters still run (headers, CSRF check, etc.)
✓ SecurityContext available — authentication info accessible
✗ More overhead than ignoring()

Rule of thumb:
- CSS, JS, images, fonts → ignoring()
- API endpoints needing headers/context → permitAll()
```

---

**Trick 6 — `roles()` vs `authorities()` in User Builder — The Double Prefix**

```java
// Most dangerous mistake in Spring Security:
User.builder()
    .roles("ROLE_ADMIN")     // stores "ROLE_ROLE_ADMIN" ← BUG
    .build();

// hasRole("ADMIN") checks "ROLE_ADMIN" → NOT FOUND
// hasRole("ROLE_ADMIN") checks "ROLE_ROLE_ADMIN" → FOUND but wrong

// CORRECT PATTERNS:
User.builder().roles("ADMIN")           // stores "ROLE_ADMIN" ✓
User.builder().authorities("ROLE_ADMIN") // stores "ROLE_ADMIN" ✓
User.builder().authorities("ADMIN")      // stores "ADMIN" ✓ (use hasAuthority("ADMIN"))
```

---

**Trick 7 — `AuthorizationManager` Null Return**

```java
// AuthorizationManager.check() can return NULL:
@Nullable
AuthorizationDecision check(Supplier<Authentication> auth, T object);

// NULL means "abstain" — no decision
// AuthorizationFilter treats null as GRANTED (pass-through)
// This is different from AccessDeniedException

// Implication: A custom AuthorizationManager that returns null
// accidentally permits access it should deny!
// Always return new AuthorizationDecision(false) to explicitly deny
// Only return null if you genuinely want to abstain (rare)
```

---

## 5️⃣ Summary Sheet

---

### 5.x vs 6.x Authorization Architecture Comparison

```
SPRING SECURITY 5.x                    SPRING SECURITY 6.x
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
FilterSecurityInterceptor         →    AuthorizationFilter
AccessDecisionManager             →    AuthorizationManager<HttpServletRequest>
AccessDecisionVoter               →    (composed into AuthorizationManager)
ConfigAttribute                   →    (replaced by RequestMatcher+AuthManager pairs)
SecurityMetadataSource            →    RequestMatcherDelegatingAuthorizationManager
AffirmativeBased/Consensus/       →    AuthorizationManagers.anyOf()/allOf()
  Unanimous
authorizeRequests()               →    authorizeHttpRequests()
antMatchers()/mvcMatchers()       →    requestMatchers()
WebExpressionVoter                →    WebExpressionAuthorizationManager
```

---

### Authorization Decision Flow (6.x)

```
HTTP Request
     │
     ▼
AuthorizationFilter
     │
     └── RequestMatcherDelegatingAuthorizationManager
               │
               Iterates (RequestMatcher → AuthorizationManager) pairs in order:
               │
               ├── /public/** → PermitAllAuthorizationManager
               │       → AuthorizationDecision(true) [no auth load]
               │
               ├── /admin/**  → AuthorityAuthorizationManager("ROLE_ADMIN")
               │       → load Authentication (via Supplier)
               │       → check authorities
               │       → AuthorizationDecision(true/false)
               │
               └── /** → AuthenticatedAuthorizationManager
                       → check !isAnonymous()
                       → AuthorizationDecision(true/false)
     │
     ├── decision.isGranted() = true  → chain.doFilter() → Controller
     └── decision.isGranted() = false → throw AccessDeniedException
                                              → ExceptionTranslationFilter
                                                    → 401 (anonymous) or 403 (authenticated)
```

---

### Built-in Authorization Expressions — Quick Reference

| Expression | Checks |
|-----------|--------|
| `permitAll()` | Always grants — no auth check |
| `denyAll()` | Always denies |
| `authenticated()` | Not anonymous |
| `fullyAuthenticated()` | Not anonymous, not remember-me |
| `anonymous()` | Is anonymous |
| `rememberMe()` | Is remember-me authenticated |
| `hasRole("X")` | Has `ROLE_X` authority |
| `hasAuthority("X")` | Has exactly `X` authority |
| `hasAnyRole("X","Y")` | Has `ROLE_X` or `ROLE_Y` |
| `hasAnyAuthority("X","Y")` | Has `X` or `Y` |
| `hasIpAddress("x.x.x.x/n")` | Request from IP/CIDR |
| `@bean.method(auth,req)` | Custom bean-based check |

---

### Voter Strategy Comparison (5.x)

| Strategy | Grant Condition | Tie Behavior |
|----------|----------------|--------------|
| `AffirmativeBased` | Any `GRANTED` | N/A |
| `ConsensusBased` | More `GRANTED` than `DENIED` | `allowIfEqual=true` (default) → GRANT |
| `UnanimousBased` | No `DENIED` (all GRANT or ABSTAIN) | All abstain → `allowIfAllAbstain=false` (default) → DENY |

---

### Common Interview One-Liners

- **`AuthorizationFilter`** is the last filter — makes the final HTTP access decision in 6.x
- **`permitAll()` in 6.x** skips `SecurityContext` loading entirely via lazy `Supplier<Authentication>`
- **`anyRequest()` must be last** — Spring 6.x throws exception if rules follow it
- **`hasRole("ADMIN")`** checks for `"ROLE_ADMIN"` — **never** use `hasRole("ROLE_ADMIN")`
- **`roles("ADMIN")`** in User builder stores `"ROLE_ADMIN"` — **never** use `roles("ROLE_ADMIN")`
- **First matching rule wins** — more specific rules MUST come before broader rules
- **URL `permitAll()`** does NOT bypass **method security** — both layers are independent
- **`WebSecurityCustomizer.ignoring()`** bypasses `FilterChainProxy` entirely — for static files only
- **`AuthorizationManager` returning `null`** means abstain — treated as GRANTED by `AuthorizationFilter`
- **`AffirmativeBased`** (5.x default) grants if ANY voter grants — `UnanimousBased` denies if ANY voter denies

---
