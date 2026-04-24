# Topic 6: Authorization Architecture — Complete Developer Mastery

Authorization is where Spring Security shifts from answering "who are you?" to answering "what are you allowed to do?" These are fundamentally different questions, and Spring Security has two completely separate architectural layers to answer them — one for HTTP requests, one for method calls. Understanding that separation is the conceptual foundation of everything in this topic.

---

## Layer 1: The Two Authorization Domains

Before touching a single class, you need to internalize this architectural split, because conflating the two is the source of most authorization bugs in production Spring applications.

```
Domain 1 — HTTP Request Authorization
     Question: "Can this principal reach this URL?"
     Enforced by: AuthorizationFilter (6.x) / FilterSecurityInterceptor (5.x)
     Position: Last filter in the SecurityFilterChain, before DispatcherServlet
     Granularity: URL patterns + HTTP methods

Domain 2 — Method Security Authorization
     Question: "Can this principal invoke this method?"
     Enforced by: AOP proxies (AuthorizationManagerBeforeMethodInterceptor)
     Position: Spring bean proxy layer, inside the application
     Granularity: Individual method invocations, with access to arguments

CRITICAL: These two domains are completely independent.
They do not know about each other. Each enforces its own rules.
A URL-level permitAll() does NOT bypass a method-level @PreAuthorize.
Both layers fire independently on every request.
```

This independence is actually a feature, not a bug. It enables defense-in-depth — a security layer inside the application that remains effective even if the HTTP layer is misconfigured. But it surprises developers who assume URL-level rules are the single source of truth.

---

## Layer 2: Spring Security 5.x Authorization — The Voter Architecture

Understanding the old voter architecture matters for two reasons: you'll encounter it in legacy codebases, and the 6.x design is much more comprehensible when you see what problem it was solving.

The 5.x model built authorization decisions around three collaborating components: a `SecurityMetadataSource` that translated URL patterns into `ConfigAttribute` strings, a set of `AccessDecisionVoter` implementations that each knew how to interpret certain attributes, and an `AccessDecisionManager` that aggregated the votes into a final decision.

```java
/**
 * LAYER 2A: AccessDecisionVoter — the voting contract.
 *
 * Each voter answers: "for the attributes I understand, should this be granted?"
 * Voters that don't understand the attribute return ABSTAIN — they step aside.
 * This allows multiple independent rules (role check, IP check, age check)
 * to coexist without any single voter knowing about the others.
 *
 * The integer constants are the entire vocabulary of a voter's opinion.
 */
public interface AccessDecisionVoter<S> {
    int ACCESS_GRANTED =  1;  // "I approve"
    int ACCESS_DENIED  = -1;  // "I deny"
    int ACCESS_ABSTAIN =  0;  // "Not my concern — I have no opinion"

    // "Do I understand this attribute?"
    // RoleVoter returns true for "ROLE_*" prefixed strings
    // WebExpressionVoter returns true for SpEL expressions
    boolean supports(ConfigAttribute attribute);

    // "Can this principal access this object given these attributes?"
    int vote(Authentication authentication, S object,
             Collection<ConfigAttribute> attributes);
}
```

The three `AccessDecisionManager` strategies represent three different philosophies about how to aggregate votes, and choosing between them is a genuine architectural decision:

```java
/**
 * LAYER 2B: The three AccessDecisionManager strategies.
 *
 * The choice between them reflects your security posture:
 *   AffirmativeBased = optimistic ("allow if anyone approves")
 *   ConsensusBased   = democratic ("allow if majority approves")
 *   UnanimousBased   = restrictive ("allow only if nobody objects")
 *
 * AffirmativeBased is the 5.x default — it means that if even ONE voter
 * grants access, the request is allowed regardless of how many others deny.
 * This is appropriate for most applications where roles are disjunctive
 * (ROLE_ADMIN OR ROLE_USER can access this endpoint).
 */

// Voter scenario for a request:
//   RoleVoter:             ACCESS_ABSTAIN (no ROLE_ attribute applies)
//   AuthenticatedVoter:    ACCESS_GRANTED (user is authenticated)
//   WebExpressionVoter:    ACCESS_DENIED  (hasRole('ADMIN') is false)

// AffirmativeBased: ACCESS_GRANTED by AuthenticatedVoter → ALLOW
// ConsensusBased:   1 grant, 1 deny (abstain ignored) → tie → GRANT (default)
// UnanimousBased:   ACCESS_DENIED by WebExpressionVoter → DENY

// Production custom voter — adds domain-specific vocabulary to the system:
@Component
public class SubscriptionTierVoter implements AccessDecisionVoter<FilterInvocation> {

    @Override
    public boolean supports(ConfigAttribute attribute) {
        // This voter understands "TIER_PREMIUM", "TIER_ENTERPRISE" etc.
        return attribute.getAttribute() != null
               && attribute.getAttribute().startsWith("TIER_");
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return FilterInvocation.class.isAssignableFrom(clazz);
    }

    @Override
    public int vote(Authentication authentication, FilterInvocation fi,
                    Collection<ConfigAttribute> attributes) {

        for (ConfigAttribute attribute : attributes) {
            if (!supports(attribute)) continue;

            String requiredTier = attribute.getAttribute().substring(5); // strip "TIER_"

            // Only this voter understands subscription tier — others ABSTAIN on it
            if (authentication.getPrincipal() instanceof UserPrincipal principal) {
                return principal.getSubscriptionTier().satisfies(requiredTier)
                    ? ACCESS_GRANTED : ACCESS_DENIED;
            }
            return ACCESS_ABSTAIN;
        }
        return ACCESS_ABSTAIN; // attribute not applicable to this voter
    }
}

// Wiring the custom voter into the AccessDecisionManager (5.x style):
@Bean
public AccessDecisionManager accessDecisionManager() {
    List<AccessDecisionVoter<?>> voters = List.of(
        new RoleVoter(),           // handles ROLE_* attributes
        new AuthenticatedVoter(),  // handles IS_AUTHENTICATED_FULLY etc.
        new WebExpressionVoter(),  // handles SpEL expressions
        new SubscriptionTierVoter() // handles TIER_* attributes
    );
    // AffirmativeBased: any single grant is sufficient
    return new AffirmativeBased(voters);
}

// Plugging it into the 5.x filter chain via ObjectPostProcessor:
http.authorizeRequests()
    .antMatchers("/premium/**").access("TIER_PREMIUM")
    .withObjectPostProcessor(new ObjectPostProcessor<FilterSecurityInterceptor>() {
        @Override
        public <O extends FilterSecurityInterceptor> O postProcess(O fsi) {
            fsi.setAccessDecisionManager(accessDecisionManager());
            return fsi;
        }
    });
```

The fundamental weakness of the voter model is its verbosity and the indirection through `ConfigAttribute` strings. You write a string like `"TIER_PREMIUM"`, and somewhere a voter has to know that string starts with `"TIER_"` and interpret the suffix. This is stringly-typed architecture — refactoring-hostile and hard to understand at a glance. Spring Security 6.x replaced it with something fundamentally more direct.

---

## Layer 3: Spring Security 6.x Authorization — The `AuthorizationManager` Architecture

The 6.x redesign collapses the entire voter architecture — `AccessDecisionManager`, `AccessDecisionVoter`, `ConfigAttribute`, `SecurityMetadataSource` — into a single functional interface. This is one of the cleanest API simplifications in the framework's history.

```java
/**
 * LAYER 3: AuthorizationManager<T> — the entire authorization contract in one interface.
 *
 * T is what you're authorizing access to:
 *   - HttpServletRequest (for URL authorization)
 *   - MethodInvocation (for method security)
 *   - RequestAuthorizationContext (for URL authorization with path variables)
 *
 * The Supplier<Authentication> parameter is the key innovation.
 * Authentication is LAZY — it's only fetched from SecurityContext when you
 * actually call authenticationSupplier.get(). This means for permitAll()
 * rules, the SecurityContext is never accessed at all — no session lookup,
 * no deserialization, zero overhead.
 */
@FunctionalInterface
public interface AuthorizationManager<T> {

    /**
     * THE CORE METHOD: should this authentication be allowed to access this object?
     *
     * Return AuthorizationDecision(true)  → GRANT
     * Return AuthorizationDecision(false) → DENY
     * Return null                         → ABSTAIN (treated as GRANT by AuthorizationFilter!)
     *                                       — be careful with null returns
     */
    @Nullable
    AuthorizationDecision check(Supplier<Authentication> authentication, T object);

    /**
     * Convenience default — calls check() and throws AccessDeniedException if denied.
     * AuthorizationFilter calls this, which means the throw happens inside the filter.
     */
    default void verify(Supplier<Authentication> authentication, T object) {
        AuthorizationDecision decision = check(authentication, object);
        if (decision != null && !decision.isGranted()) {
            throw new AccessDeniedException("Access Denied");
        }
        // Note: null decision → no exception → access granted (the abstain-as-grant trap)
    }
}
```

The most important conceptual difference from 5.x is how rules are represented. In 5.x, a rule was a `ConfigAttribute` string interpreted by a voter. In 6.x, a rule *is* an `AuthorizationManager` instance. The URL pattern `"/admin/**"` is mapped directly to an `AuthorityAuthorizationManager("ROLE_ADMIN")` instance. The abstraction is type-safe and composable rather than stringly-typed.

---

## Layer 4: `AuthorizationFilter` — The Complete Internal Execution

```java
/**
 * LAYER 4: AuthorizationFilter — the last filter in the chain.
 *
 * Its position matters: it runs AFTER authentication filters (Basic, Form, PreAuth)
 * and AFTER AnonymousAuthenticationFilter. By the time this filter runs,
 * SecurityContext holds the final Authentication (real user or anonymous token).
 *
 * The filter delegates entirely to its AuthorizationManager, which is a
 * RequestMatcherDelegatingAuthorizationManager under the hood — it iterates
 * your configured rules in order and delegates to the first matching manager.
 */
public class AuthorizationFilter extends GenericFilterBean {

    // This is what the authorizeHttpRequests() DSL builds:
    // RequestMatcherDelegatingAuthorizationManager with your rules
    private final AuthorizationManager<HttpServletRequest> authorizationManager;

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest request = (HttpServletRequest) req;

        // ─── THE AUTHORIZATION CHECK ──────────────────────────────────────
        // this::getAuthentication is the Supplier<Authentication>
        // It's passed but NOT called yet — lazy evaluation
        AuthorizationDecision decision = this.authorizationManager.check(
            this::getAuthentication,  // Supplier — called only if manager needs auth
            request
        );

        // Publish event for audit logging (AuthorizationGrantedEvent / AuthorizationDeniedEvent)
        this.eventPublisher.publishAuthorizationEvent(
            this::getAuthentication, request, decision);

        // Check result — null means abstain → treated as grant
        if (decision != null && !decision.isGranted()) {
            // Throws AccessDeniedException → caught by ExceptionTranslationFilter
            // → 401 if anonymous, 403 if authenticated
            throw new AccessDeniedException("Access Denied");
        }

        // Granted → request continues to DispatcherServlet
        chain.doFilter(request, res);
    }

    private Authentication getAuthentication() {
        // This is called ONLY when the AuthorizationManager actually needs it.
        // For permitAll() rules, this is never called.
        return SecurityContextHolder.getContext().getAuthentication();
    }
}
```

The `RequestMatcherDelegatingAuthorizationManager` is the heart of rule evaluation. Understanding its first-match-wins logic is critical because it's the source of the most common production security misconfiguration — rules in the wrong order:

```java
/**
 * LAYER 4B: RequestMatcherDelegatingAuthorizationManager internals.
 *
 * Internally holds an ordered list of (RequestMatcher, AuthorizationManager) pairs.
 * Evaluates them in insertion order — first match wins entirely.
 * This is why rule ordering in authorizeHttpRequests() is a security concern,
 * not just a style preference.
 */

// What the DSL builds internally:
List<RequestMatcherEntry<AuthorizationManager<RequestAuthorizationContext>>> mappings = [
    Entry("/public/**",     PermitAllAuthorizationManager),           // Rule 1
    Entry("/admin/**",      AuthorityAuthorizationManager("ROLE_ADMIN")), // Rule 2
    Entry("/api/**",        AuthenticatedAuthorizationManager),       // Rule 3
    Entry("/**",            AuthenticatedAuthorizationManager)        // Rule 4 (anyRequest)
];

// For request GET /admin/users:
//   Rule 1: AntPathRequestMatcher("/public/**").matches? → NO
//   Rule 2: AntPathRequestMatcher("/admin/**").matches?  → YES → check ROLE_ADMIN
//   Rules 3, 4: Never evaluated — first match wins

// For request GET /admin/public-notice:  ← THE ORDERING TRAP
// If rules were in wrong order (broader before specific):
//   Rule: /admin/**    → requires ROLE_ADMIN
//   Rule: /admin/public-notice → permitAll  ← DEAD CODE, never reached
// /admin/** matches first → requires ROLE_ADMIN → user denied
// The permitAll rule is unreachable because /** swallows it
```

---

## Layer 5: Built-in `AuthorizationManager` Implementations

```java
/**
 * LAYER 5: The built-in implementations you'll use daily.
 *
 * Each corresponds to one of the DSL methods in authorizeHttpRequests().
 * Knowing which class backs each DSL call is essential for understanding
 * what's actually happening and for writing custom alternatives.
 */

// .permitAll() → PermitAllAuthorizationManager
// Always returns AuthorizationDecision(true) WITHOUT calling authSupplier.get()
// This is the performance optimization: no SecurityContext access for public paths
AuthorizationManager<RequestAuthorizationContext> permitAll = (auth, ctx) ->
    new AuthorizationDecision(true); // auth supplier never called

// .denyAll() → DenyAllAuthorizationManager
// Always returns AuthorizationDecision(false)
AuthorizationManager<RequestAuthorizationContext> denyAll = (auth, ctx) ->
    new AuthorizationDecision(false); // fail-safe default for unlisted paths

// .hasRole("ADMIN") → AuthorityAuthorizationManager
// Prepends "ROLE_" and checks authorities collection
AuthorizationManager<RequestAuthorizationContext> hasAdmin =
    AuthorityAuthorizationManager.hasRole("ADMIN");
// Internally: checks for "ROLE_ADMIN" in auth.getAuthorities()

// .hasAuthority("READ_ACCESS") → AuthorityAuthorizationManager
// Checks the exact string, no prefix manipulation
AuthorizationManager<RequestAuthorizationContext> hasRead =
    AuthorityAuthorizationManager.hasAuthority("READ_ACCESS");

// .authenticated() → AuthenticatedAuthorizationManager
// Checks !isAnonymous() — same as SpEL isAuthenticated()
AuthorizationManager<RequestAuthorizationContext> isAuthenticated =
    AuthenticatedAuthorizationManager.authenticated();

// .fullyAuthenticated() → AuthenticatedAuthorizationManager (different mode)
// Checks !isAnonymous() AND !isRememberMe()
AuthorizationManager<RequestAuthorizationContext> fullyAuth =
    AuthenticatedAuthorizationManager.fullyAuthenticated();

// Composition — AND logic:
// "Must be authenticated AND have ROLE_API AND come from internal IP"
AuthorizationManager<RequestAuthorizationContext> combined =
    AuthorizationManagers.allOf(
        AuthenticatedAuthorizationManager.authenticated(),
        AuthorityAuthorizationManager.hasRole("API"),
        new WebExpressionAuthorizationManager("hasIpAddress('10.0.0.0/8')")
    );

// Composition — OR logic:
// "Must be ADMIN or SUPER_USER"
AuthorizationManager<RequestAuthorizationContext> adminOrSuper =
    AuthorizationManagers.anyOf(
        AuthorityAuthorizationManager.hasRole("ADMIN"),
        AuthorityAuthorizationManager.hasRole("SUPER_USER")
    );
```

---

## Layer 6: SpEL in Authorization — The Evaluation Pipeline

```java
/**
 * LAYER 6: How SpEL expressions are evaluated in authorization.
 *
 * WebExpressionAuthorizationManager wraps a SpEL string and evaluates it
 * against a WebSecurityExpressionRoot — a special object that exposes all
 * the built-in security methods (hasRole, isAuthenticated, hasIpAddress, etc.)
 * as if they were local methods.
 *
 * The expression is compiled once and cached — repeated evaluation is cheap.
 */

// ─── Built-in WebSecurityExpressionRoot methods ─────────────────────────────
// These are what you're actually calling in SpEL strings:
// hasRole('ADMIN')              → checks "ROLE_ADMIN" in authorities
// hasAuthority('READ')          → checks "READ" in authorities
// hasAnyRole('USER','ADMIN')    → checks either "ROLE_USER" or "ROLE_ADMIN"
// isAuthenticated()             → !isAnonymous()
// isAnonymous()                 → instanceof AnonymousAuthenticationToken
// isFullyAuthenticated()        → !isAnonymous() && !isRememberMe()
// isRememberMe()                → instanceof RememberMeAuthenticationToken
// permitAll                     → always true
// denyAll                       → always false
// hasIpAddress('192.168.0.0/16') → checks request.getRemoteAddr() against CIDR

// ─── Custom bean reference in SpEL — most powerful extension point ────────────
// @beanName.method(authentication, request) — references a Spring bean by name
// This lets you implement ANY authorization logic as a Spring service

@Component("authorizationPolicies")  // the @beanName in SpEL
@RequiredArgsConstructor
public class AuthorizationPolicies {

    private final ResourceRepository resourceRepository;
    private final SubscriptionService subscriptionService;

    // Called as: @authorizationPolicies.canAccessResource(authentication, request)
    public boolean canAccessResource(Authentication auth, HttpServletRequest request) {
        String resourceId = extractResourceId(request.getRequestURI());
        if (resourceId == null) return false;

        // Admin can always access
        if (auth.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"))) {
            return true;
        }

        // Resource owner can access
        return resourceRepository.existsByIdAndOwner(
            Long.parseLong(resourceId), auth.getName());
    }

    // Called as: @authorizationPolicies.hasActivePremiumSubscription(authentication)
    public boolean hasActivePremiumSubscription(Authentication auth) {
        return subscriptionService.isActivePremium(auth.getName());
    }
}

// Wiring SpEL bean references into authorization rules:
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http.authorizeHttpRequests(auth -> auth
        .requestMatchers("/premium/**")
            .access(new WebExpressionAuthorizationManager(
                "@authorizationPolicies.hasActivePremiumSubscription(authentication)"))
        .requestMatchers("/api/resources/**")
            .access(new WebExpressionAuthorizationManager(
                "hasRole('ADMIN') or " +
                "@authorizationPolicies.canAccessResource(authentication, request)"))
        .anyRequest().authenticated()
    );
    return http.build();
}
```

---

## Layer 7: Custom `AuthorizationManager` — Type-Safe Alternative to SpEL

```java
/**
 * LAYER 7: Custom AuthorizationManager — the clean, type-safe alternative
 * to SpEL bean references for complex authorization logic.
 *
 * Prefer this over @bean.method() SpEL when:
 *   - Your logic is complex enough to benefit from compile-time checking
 *   - You want proper unit test support (no SpEL evaluation context needed)
 *   - You need access to path variables from the URL pattern
 *
 * RequestAuthorizationContext carries both the request AND any path variables
 * extracted by the RequestMatcher — this is richer than raw HttpServletRequest.
 */
@Component
@RequiredArgsConstructor
public class ResourceOwnershipAuthorizationManager
        implements AuthorizationManager<RequestAuthorizationContext> {

    private final ResourceRepository resourceRepository;

    @Override
    public AuthorizationDecision check(
            Supplier<Authentication> authSupplier,
            RequestAuthorizationContext context) {

        // Path variables are extracted from the URL pattern by RequestMatcher
        // e.g., for pattern "/api/resources/{id}", variables = {"id": "42"}
        String resourceId = context.getVariables().get("id");
        if (resourceId == null) {
            return new AuthorizationDecision(false); // defensive: no id → deny
        }

        // Only load authentication now that we actually need it
        // (lazy loading — the Supplier defers SecurityContext access)
        Authentication auth = authSupplier.get();

        // Admins have unrestricted access
        boolean isAdmin = auth.getAuthorities().stream()
            .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"));
        if (isAdmin) return new AuthorizationDecision(true);

        // Resource owners can access their own resources
        boolean isOwner = resourceRepository.existsByIdAndOwnerUsername(
            Long.parseLong(resourceId), auth.getName());

        return new AuthorizationDecision(isOwner);
        // NOTE: never return null to deny — return new AuthorizationDecision(false)
        // null means abstain, which AuthorizationFilter treats as GRANT!
    }
}

// Registration — path variable extraction requires the matcher syntax to match:
@Bean
public SecurityFilterChain filterChain(HttpSecurity http,
        ResourceOwnershipAuthorizationManager ownershipManager) throws Exception {
    http.authorizeHttpRequests(auth -> auth
        // {id} in the pattern enables path variable extraction in the manager
        .requestMatchers("/api/resources/{id}").access(ownershipManager)
        .requestMatchers("/api/resources/**").hasRole("USER") // broader fallback
        .anyRequest().authenticated()
    );
    return http.build();
}
```

---

## Layer 8: `hasRole` vs `hasAuthority` — The Complete Mechanics

This is the single most common source of silent authorization failures. The mechanics are simple but the implications of getting it wrong are severe, because failures are silent — no exception, just a 403 that's hard to trace.

```java
/**
 * LAYER 8: The ROLE_ prefix mechanics — every combination you'll encounter.
 *
 * hasRole() adds ROLE_ prefix before checking.
 * hasAuthority() checks the exact string, no manipulation.
 *
 * The correct mental model: hasRole("X") is exactly equivalent to
 * hasAuthority("ROLE_X"). That's the entire difference.
 */

// ─── User.builder() — how authorities are stored ────────────────────────────
User.builder().roles("ADMIN")                 // stores "ROLE_ADMIN"  ✓
User.builder().roles("ROLE_ADMIN")            // stores "ROLE_ROLE_ADMIN" ← BUG!
User.builder().authorities("ROLE_ADMIN")      // stores "ROLE_ADMIN"  ✓
User.builder().authorities("ADMIN")           // stores "ADMIN"       ✓ (different!)

// ─── Checking authority — what each expression actually looks for ─────────────
// User stored with roles("ADMIN") → has "ROLE_ADMIN" in authorities:
hasRole("ADMIN")         // looks for "ROLE_ADMIN"  → FOUND → GRANT ✓
hasAuthority("ADMIN")    // looks for "ADMIN"       → NOT FOUND → DENY ✗
hasAuthority("ROLE_ADMIN") // looks for "ROLE_ADMIN" → FOUND → GRANT ✓
hasRole("ROLE_ADMIN")    // looks for "ROLE_ROLE_ADMIN" → NOT FOUND → DENY ✗

// User stored with authorities("ADMIN") → has "ADMIN" in authorities:
hasRole("ADMIN")         // looks for "ROLE_ADMIN"  → NOT FOUND → DENY ✗
hasAuthority("ADMIN")    // looks for "ADMIN"       → FOUND → GRANT ✓

// ─── Production recommendation ─────────────────────────────────────────────
// Be consistent: always store with ROLE_ prefix and always use hasRole().
// This is the conventional pattern in Spring Security and avoids confusion.
// Use hasAuthority() only for fine-grained permissions that are NOT roles
// (e.g., "user:read", "order:cancel", "report:export").
@Bean
public UserDetailsService userDetailsService(PasswordEncoder encoder) {
    UserDetails admin = User.builder()
        .username("admin")
        .password(encoder.encode("password"))
        .roles("ADMIN", "USER")          // stored as "ROLE_ADMIN", "ROLE_USER"
        .build();

    UserDetails apiClient = User.builder()
        .username("api-client")
        .password(encoder.encode("secret"))
        .authorities(
            "ROLE_API",                  // role — check with hasRole("API")
            "user:read",                 // fine-grained permission — check with hasAuthority("user:read")
            "order:write"                // fine-grained permission
        )
        .build();

    return new InMemoryUserDetailsManager(admin, apiClient);
}
```

---

## Layer 9: The Complete Production Configuration

```java
/**
 * LAYER 9: Production-grade authorization configuration.
 *
 * This example demonstrates every important pattern from this topic:
 * - Correct rule ordering (specific before broad)
 * - Static resource bypass
 * - SpEL with bean reference
 * - Custom AuthorizationManager
 * - hasRole vs hasAuthority correctly used
 * - Dual-layer defense (URL + method security)
 * - Authorization event auditing
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true) // enables @PreAuthorize, @PostAuthorize
@RequiredArgsConstructor
public class AuthorizationConfig {

    private final ResourceOwnershipAuthorizationManager ownershipManager;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth

                // ── Static resources bypass the security filter completely ──
                // Done via WebSecurityCustomizer.ignoring(), not here

                // ── Publicly accessible ───────────────────────────────────
                // permitAll() → PermitAllAuthorizationManager → never loads SecurityContext
                .requestMatchers("/actuator/health", "/actuator/info").permitAll()
                .requestMatchers(HttpMethod.GET, "/api/products/**").permitAll()
                .requestMatchers("/auth/login", "/auth/register").permitAll()

                // ── SPECIFIC rules BEFORE broad rules — ordering is security-critical ──

                // Admin gets full access to their section
                .requestMatchers("/admin/**").hasRole("ADMIN")

                // Fine-grained permission check (not a role — use hasAuthority)
                .requestMatchers(HttpMethod.POST, "/api/orders/**").hasAuthority("order:write")
                .requestMatchers(HttpMethod.GET, "/api/orders/**").hasAnyAuthority(
                    "order:read", "order:write") // write implies read

                // Resource ownership — custom AuthorizationManager with path variable
                .requestMatchers("/api/resources/{id}/**").access(ownershipManager)

                // Internal API: must be authenticated AND from internal network AND have role
                .requestMatchers("/api/internal/**")
                    .access(AuthorizationManagers.allOf(
                        AuthenticatedAuthorizationManager.authenticated(),
                        new WebExpressionAuthorizationManager("hasIpAddress('10.0.0.0/8')"),
                        AuthorityAuthorizationManager.hasRole("INTERNAL_SERVICE")
                    ))

                // Sensitive operations: must NOT be remember-me authenticated
                .requestMatchers("/account/password", "/account/email").fullyAuthenticated()

                // Everything else requires login (but not a specific role)
                .anyRequest().authenticated() // ← ALWAYS LAST
            )
            .exceptionHandling(ex -> ex
                .authenticationEntryPoint(restAuthEntryPoint())  // 401
                .accessDeniedHandler(restAccessDeniedHandler())  // 403
            );

        return http.build();
    }

    // Static files bypass FilterChainProxy entirely — no filter overhead at all
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return web -> web.ignoring()
            .requestMatchers("/static/**", "/css/**", "/js/**",
                             "/images/**", "/favicon.ico", "/webjars/**");
    }
}

/**
 * Authorization event listener — audit trail for security decisions.
 * 6.x publishes AuthorizationGrantedEvent and AuthorizationDeniedEvent automatically.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class AuthorizationAuditListener {

    private final AuditLogService auditLogService;

    // Only log denials — logging every successful request would be extremely noisy
    @EventListener
    public void onAuthorizationDenied(AuthorizationDeniedEvent<?> event) {
        Authentication auth = event.getAuthentication().get();
        log.warn("Authorization denied: principal={}, resource={}, authorities={}",
            auth.getName(),
            event.getObject(),
            auth.getAuthorities());

        auditLogService.recordDenial(auth.getName(), event.getObject().toString());
    }
}
```

---

## Layer 10: The 5.x → 6.x Migration Map

```java
/**
 * LAYER 10: Complete API migration reference.
 *
 * If you're working with legacy code or upgrading an existing application,
 * these are the direct equivalents.
 */

// ─── DSL ────────────────────────────────────────────────────────────────────
// 5.x: http.authorizeRequests()
// 6.x: http.authorizeHttpRequests()

// ─── URL matchers ────────────────────────────────────────────────────────────
// 5.x: .antMatchers("/admin/**")
// 5.x: .mvcMatchers("/admin/**")
// 6.x: .requestMatchers("/admin/**")  ← auto-selects MVC or Ant based on classpath

// ─── Core components ─────────────────────────────────────────────────────────
// 5.x: FilterSecurityInterceptor + AccessDecisionManager + AccessDecisionVoter + ConfigAttribute
// 6.x: AuthorizationFilter + AuthorizationManager<HttpServletRequest>

// ─── Decision aggregation ────────────────────────────────────────────────────
// 5.x: AffirmativeBased / ConsensusBased / UnanimousBased
// 6.x: AuthorizationManagers.anyOf() / allOf() / not()

// ─── SpEL evaluation ─────────────────────────────────────────────────────────
// 5.x: WebExpressionVoter + WebSecurityExpressionRoot
// 6.x: WebExpressionAuthorizationManager + WebSecurityExpressionRoot (same root!)

// ─── Full 5.x → 6.x rewrite example ─────────────────────────────────────────

// BEFORE (5.x):
http.authorizeRequests()
    .antMatchers("/admin/**").hasRole("ADMIN")
    .mvcMatchers(HttpMethod.GET, "/api/**").hasAuthority("API_READ")
    .anyRequest().authenticated()
    .and()
    .exceptionHandling()
        .accessDeniedHandler(customHandler)
        .authenticationEntryPoint(customEntryPoint);

// AFTER (6.x):
http
    .authorizeHttpRequests(auth -> auth
        .requestMatchers("/admin/**").hasRole("ADMIN")
        .requestMatchers(HttpMethod.GET, "/api/**").hasAuthority("API_READ")
        .anyRequest().authenticated()
    )
    .exceptionHandling(ex -> ex
        .accessDeniedHandler(customHandler)
        .authenticationEntryPoint(customEntryPoint)
    );
// Note: no .and() needed — lambda DSL doesn't require it
```

---

## Layer 11: Testing Authorization

```java
/**
 * LAYER 11: Testing the two authorization layers independently.
 *
 * The independence of URL and method security means you should test each
 * layer separately. URL security tests verify filter chain behavior.
 * Method security tests verify business logic protection.
 */
@SpringBootTest
@AutoConfigureMockMvc
class AuthorizationTest {

    @Autowired MockMvc mockMvc;

    // ─── URL-level authorization tests ───────────────────────────────────────

    @Test
    @DisplayName("Admin endpoint denied to USER → 403, not 401")
    @WithMockUser(username = "alice", roles = {"USER"})
    void adminEndpointDeniedToUser() throws Exception {
        // Alice is authenticated (ROLE_USER), but lacks ROLE_ADMIN → 403
        mockMvc.perform(get("/admin/users"))
            .andExpect(status().isForbidden()); // 403, not 401!
    }

    @Test
    @DisplayName("Admin endpoint denied to anonymous → 401, not 403")
    void adminEndpointDeniedToAnonymous() throws Exception {
        // No credentials → anonymous → ExceptionTranslationFilter → 401
        mockMvc.perform(get("/admin/users"))
            .andExpect(status().isUnauthorized()); // 401, not 403!
    }

    @Test
    @DisplayName("Admin endpoint accessible to ADMIN role")
    @WithMockUser(username = "bob", roles = {"ADMIN"})
    void adminEndpointAccessibleToAdmin() throws Exception {
        mockMvc.perform(get("/admin/users"))
            .andExpect(status().isOk());
    }

    @Test
    @DisplayName("permitAll() endpoint accessible to anonymous")
    void publicEndpointAnonymous() throws Exception {
        mockMvc.perform(get("/api/products/1"))
            .andExpect(status().isOk());
    }

    // ─── Rule ordering test — verifying the trap ─────────────────────────────

    @Test
    @DisplayName("Specific rule before broad — /admin/public accessible to USER")
    @WithMockUser(roles = {"USER"})
    void specificRuleBeforeBroad() throws Exception {
        // This test verifies that /admin/public (permitAll) matches before /admin/** (ADMIN only)
        mockMvc.perform(get("/admin/public-notice"))
            .andExpect(status().isOk()); // passes because specific rule listed first
    }

    // ─── URL + Method security independence ──────────────────────────────────

    @Test
    @DisplayName("URL permitAll doesn't bypass method @PreAuthorize")
    @WithMockUser(roles = {"USER"}) // has USER but not ADMIN
    void urlPermitAllDoesntBypassMethodSecurity() throws Exception {
        // /api/products GET is permitAll() at URL level
        // But ProductController.getAdminDetails() has @PreAuthorize("hasRole('ADMIN')")
        mockMvc.perform(get("/api/products/admin-details"))
            .andExpect(status().isForbidden()); // method security kicks in!
    }
}
```

---

## The Complete Mental Model

Here is how the entire 6.x authorization pipeline connects, from HTTP request to final response:

```
HTTP Request arrives
     │
     ▼ (skips FilterChainProxy entirely)
WebSecurityCustomizer.ignoring()     ← /static/**, /css/**, etc.
     │
     ▼ (enters SecurityFilterChain)
SecurityContextHolderFilter          ← loads Authentication from session / repository
     │
     ▼
[Authentication Filters]             ← BasicAuth, FormLogin, PreAuth, RememberMe
     │
     ▼
AnonymousAuthenticationFilter        ← sets anonymous token if no auth yet
     │
     ▼
ExceptionTranslationFilter           ← wraps downstream in try-catch
     │
     ▼
AuthorizationFilter                  ← THE DECISION POINT (last filter)
     │
     └── RequestMatcherDelegatingAuthorizationManager
               │
               Evaluates rules in ORDER until first match:
               │
               ├── /public/** → PermitAllAuthorizationManager
               │       → auth.get() NEVER CALLED
               │       → AuthorizationDecision(true) → GRANT
               │
               ├── /admin/**  → AuthorityAuthorizationManager("ROLE_ADMIN")
               │       → auth.get() → loads Authentication
               │       → checks "ROLE_ADMIN" in authorities
               │       → AuthorizationDecision(true/false)
               │
               └── /** → AuthenticatedAuthorizationManager
                       → auth.get() → checks !isAnonymous()
                       → AuthorizationDecision(true/false)
     │
     ├── decision.isGranted() = true
     │       → chain.doFilter() → DispatcherServlet
     │               │
     │               ▼
     │         AOP Proxy (if @EnableMethodSecurity)
     │               └── @PreAuthorize("hasRole('ADMIN')")
     │                       → evaluates independently of URL rules
     │                       → throws AccessDeniedException if denied
     │                       → 403 even if URL was permitAll()
     │
     └── decision.isGranted() = false
             → AccessDeniedException thrown
             → ExceptionTranslationFilter catches it
                   ├── isAnonymous(auth)? YES → AuthenticationEntryPoint → 401
                   └── isAnonymous(auth)? NO  → AccessDeniedHandler → 403
```

The deepest architectural insight in this topic is the `Supplier<Authentication>` pattern in 6.x. It's not just a Java 8 nicety — it's a fundamental performance optimization that means Spring Security can evaluate authorization rules without ever touching the `SecurityContext` for requests matched by `permitAll()`. In high-traffic applications serving public content, this means no session lookups, no context deserialization, and no thread-local access for a significant fraction of your total request volume. The 5.x `FilterSecurityInterceptor` always loaded the `Authentication` regardless of the rule outcome. The 6.x `AuthorizationFilter` defers that cost until the rule actually needs it. That's the architectural philosophy: lazy by default, expensive only when necessary.
