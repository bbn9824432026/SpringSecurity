# Topic 4: Anonymous Authentication — Complete Developer Mastery

Anonymous authentication is the most architecturally misunderstood piece of Spring Security. Most developers think it means "no authentication" — but it's actually a first-class security mechanism that makes the entire authorization model coherent. Let me build this up from first principles.

---

## Layer 1: The Design Problem Anonymous Authentication Solves

Before writing a single line of code, you need to understand *why* anonymous authentication exists. Spring Security's authorization layer is built around one invariant: **there must always be an `Authentication` object in the `SecurityContext`**. Every authorization decision assumes a non-null token to inspect.

Without anonymous authentication, an unauthenticated request would leave `SecurityContext.getAuthentication()` returning null. Every filter, every authorization check, every SpEL expression would need to guard against null. The framework would be riddled with null checks, and the 401-vs-403 decision in `ExceptionTranslationFilter` would require special-casing null instead of dispatching cleanly on type.

Anonymous authentication solves this elegantly: instead of null, an unauthenticated request gets a well-typed `AnonymousAuthenticationToken`. The authorization layer never sees null. It sees a token it can inspect, whose type it can check, and whose authorities it can evaluate. Null becomes a typed state.

```
Without anonymous auth:           With anonymous auth:
                                   
SecurityContext = null             SecurityContext = AnonymousAuthenticationToken{
                                     principal   = "anonymousUser",
  → Null checks everywhere           credentials = null,
  → NPE risk                         authorities = [ROLE_ANONYMOUS],
  → 401/403 needs special logic       authenticated = true
                                   }
                                     → Type-safe checks everywhere
                                     → Consistent authorization model
                                     → Clean 401/403 routing
```

---

## Layer 2: `AnonymousAuthenticationToken` — The Identity Carrier

```java
/**
 * LAYER 2: AnonymousAuthenticationToken — what the anonymous state looks like.
 *
 * This is a concrete Authentication implementation, not a marker interface.
 * It carries a principal, authorities, and a key hash — all three matter.
 *
 * The MOST IMPORTANT detail is at the bottom: isAuthenticated() = true.
 * This is the single most common source of security bugs in Spring Security.
 */
public class AnonymousAuthenticationToken
        extends AbstractAuthenticationToken {

    private final int keyHash;   // hash of secret key — prevents forgery
    private final Object principal; // "anonymousUser" by default

    public AnonymousAuthenticationToken(String key,
                                         Object principal,
                                         Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.keyHash = key.hashCode();
        this.principal = principal;
        // ← setAuthenticated(true) is called in the superclass constructor
        // when authorities are provided. This is why isAuthenticated() = true.
        super.setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return null; // Anonymous users have no credentials — nothing to verify
    }

    @Override
    public Object getPrincipal() {
        return this.principal; // "anonymousUser" — a String, NOT a UserDetails object!
    }

    // isAuthenticated() returns TRUE — this is intentional and often misunderstood.
    // It means "this token is a legitimate, fully-processed security context."
    // It does NOT mean "the user proved their identity."
}
```

The `isAuthenticated() = true` behavior deserves a dedicated mental model. Think of it this way: `isAuthenticated()` answers the question "has this token been properly constructed and is it safe to use?" not "did a human prove who they are?" An `AnonymousAuthenticationToken` is fully constructed and safe to reason about — it just represents *the absence of a proven identity*, which is a valid state. The flag means "processed", not "verified".

```java
/**
 * The asymmetry that causes most production bugs.
 *
 * Spring Security's SpEL isAuthenticated() and Java's isAuthenticated()
 * mean DIFFERENT things for anonymous tokens. This is not a bug —
 * it's a deliberate design where the SpEL layer adds semantic meaning
 * that the raw API doesn't carry.
 */

// ─── In SpEL (annotation-based security) ────────────────────────────────────
@PreAuthorize("isAuthenticated()")
// Internally implemented in SecurityExpressionRoot as:
//   return !isAnonymous();
// ✓ CORRECTLY excludes anonymous users — "authenticated" means "real identity"

// ─── In raw Java code ────────────────────────────────────────────────────────
Authentication auth = SecurityContextHolder.getContext().getAuthentication();
auth.isAuthenticated(); // returns TRUE for AnonymousAuthenticationToken!
// ✗ DOES NOT exclude anonymous — "authenticated" means "token is valid"

// ─── The correct Java equivalents ────────────────────────────────────────────
// Option 1: instanceof check
boolean isRealUser = !(auth instanceof AnonymousAuthenticationToken)
                     && auth.isAuthenticated();

// Option 2: use the framework's own resolver (cleanest)
AuthenticationTrustResolver resolver = new AuthenticationTrustResolverImpl();
boolean isRealUser = !resolver.isAnonymous(auth);

// Option 3: Spring Security's helper (Spring 5.8+)
boolean isRealUser = AuthorityUtils.authorityListToSet(auth.getAuthorities())
                         .contains("ROLE_ANONYMOUS") == false; // crude but works
```

Burn this into your memory: **SpEL `isAuthenticated()` = `!isAnonymous()`**. The SpEL layer adds the semantic meaning you intuitively expect. Raw Java `isAuthenticated()` is a lower-level flag about token validity, not user identity.

---

## Layer 3: `AnonymousAuthenticationFilter` — The Filter Internals

```java
/**
 * LAYER 3: AnonymousAuthenticationFilter — the simplest filter in the chain.
 *
 * Extends GenericFilterBean directly (not OncePerRequestFilter!).
 * Positioned at order ~1300 — AFTER every authentication filter.
 * This ordering is the entire mechanism: it fills the gap that real auth leaves empty.
 *
 * The complete logic is one guard clause. Everything else is setup.
 */
public class AnonymousAuthenticationFilter extends GenericFilterBean
        implements InitializingBean {

    private final String key;         // random UUID by default in Spring Boot
    private Object principal;         // "anonymousUser" — configurable
    private List<GrantedAuthority> authorities; // [ROLE_ANONYMOUS] — configurable

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {

        // ─── THE ENTIRE LOGIC ─────────────────────────────────────────────
        // If any prior filter (UsernamePasswordAuth, BasicAuth, BearerToken,
        // RememberMe) has set an Authentication, this filter does nothing.
        // It only fires in the gap — when no real authentication occurred.
        if (SecurityContextHolder.getContext().getAuthentication() == null) {

            Authentication anon = createAuthentication((HttpServletRequest) req);

            SecurityContext context = SecurityContextHolder.createEmptyContext();
            context.setAuthentication(anon);
            SecurityContextHolder.setContext(context);

            // ← IMPORTANT: No saveContext() call here.
            // The anonymous token is NEVER persisted to the HTTP session.
            // It lives only for this request's thread lifetime.
        }
        // else: Authentication already set → transparent pass-through

        chain.doFilter(req, res);
        // After chain returns, SecurityContextHolderFilter clears the holder.
        // The anonymous token evaporates. No session entry. Zero overhead.
    }

    protected Authentication createAuthentication(HttpServletRequest request) {
        AnonymousAuthenticationToken token = new AnonymousAuthenticationToken(
            this.key,          // used for validation — prevents cross-app token injection
            this.principal,    // "anonymousUser"
            this.authorities   // [ROLE_ANONYMOUS]
        );
        // Note: no WebAuthenticationDetails set here — anonymous users
        // don't go through WebAuthenticationDetailsSource
        return token;
    }
}
```

The filter's position in the chain is its entire mechanism. Here is the complete execution sequence for an unauthenticated request, showing exactly where each filter runs and why ordering matters:

```
HTTP Request (no credentials, no session)
     │
     ▼ Order ~200
SecurityContextHolderFilter
     └── Loads from session/repository → empty → SecurityContext.auth = null

     ▼ Order ~400
UsernamePasswordAuthenticationFilter
     └── Checks: is this POST /login? → NO → chain.doFilter() (pass through)

     ▼ Order ~900
BasicAuthenticationFilter
     └── Checks: is there an Authorization: Basic header? → NO → pass through

     ▼ Order ~1100
RememberMeAuthenticationFilter
     └── Checks: is there a remember-me cookie? → NO → pass through

     ▼ Order ~1300
AnonymousAuthenticationFilter         ← FINALLY fires: auth is still null
     └── getAuthentication() == null → YES
     └── Creates AnonymousAuthenticationToken
     └── Sets in SecurityContextHolder (in-memory only, never saved to session)

     ▼ Order ~1500
ExceptionTranslationFilter
     └── Wraps downstream in try-catch for auth/access exceptions

     ▼ Order ~1600
AuthorizationFilter
     └── Evaluates authorization rules against AnonymousAuthenticationToken
     └── Rule: anyRequest().authenticated() → isAuthenticated() = false → DENY
     └── Throws AccessDeniedException

ExceptionTranslationFilter catches it ← bubbles back up
     └── trustResolver.isAnonymous(auth) → TRUE
     └── Routes to AuthenticationEntryPoint → 401 / redirect
```

---

## Layer 4: `AuthenticationTrustResolver` — The 401 vs 403 Decision Engine

This is the component that makes the critical routing decision in `ExceptionTranslationFilter`. Understanding it is key to understanding why anonymous authentication is architecturally necessary.

```java
/**
 * LAYER 4: AuthenticationTrustResolver — the judge that decides:
 * "is this user anonymous (needs to log in) or authenticated (just lacks permission)?"
 *
 * ExceptionTranslationFilter holds a reference to this resolver and uses it
 * every time an AccessDeniedException bubbles up from downstream.
 */
public interface AuthenticationTrustResolver {
    boolean isAnonymous(Authentication authentication);
    boolean isRememberMe(Authentication authentication);
    // isFullyAuthenticated = !isAnonymous && !isRememberMe
}

// Default implementation — straightforward instanceof checks:
public class AuthenticationTrustResolverImpl implements AuthenticationTrustResolver {

    @Override
    public boolean isAnonymous(Authentication authentication) {
        if (authentication == null) return false;
        return authentication instanceof AnonymousAuthenticationToken;
    }

    @Override
    public boolean isRememberMe(Authentication authentication) {
        if (authentication == null) return false;
        return authentication instanceof RememberMeAuthenticationToken;
    }
}

/**
 * ExceptionTranslationFilter's routing logic — this is why anonymous auth
 * enables the clean 401/403 split. Without the typed AnonymousAuthenticationToken,
 * this check would need to compare against null, which is fragile.
 */
private void handleSpringSecurityException(HttpServletRequest request,
                                           HttpServletResponse response,
                                           RuntimeException exception) throws IOException {

    if (exception instanceof AuthenticationException authEx) {
        // Identity claim itself is broken → definitely 401
        sendStartAuthentication(request, response, authEx);

    } else if (exception instanceof AccessDeniedException accessDenied) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if (authenticationTrustResolver.isAnonymous(auth)   // ← key check
                || authenticationTrustResolver.isRememberMe(auth)) {
            // Anonymous/remember-me = "effectively not logged in" → 401
            sendStartAuthentication(request, response,
                new InsufficientAuthenticationException("Full authentication required"));
        } else {
            // Real authenticated user, wrong role → 403
            accessDeniedHandler.handle(request, response, accessDenied);
        }
    }
}
```

The complete 401 vs 403 decision tree is worth drawing out explicitly, because getting this wrong means users see the wrong error codes:

```
AccessDeniedException thrown by AuthorizationFilter
     │
     ▼
ExceptionTranslationFilter
     │
     ├── Is auth an AnonymousAuthenticationToken?
     │         YES → "You need to log in first" → AuthenticationEntryPoint
     │                   ├── formLogin configured → 302 redirect to /login
     │                   ├── httpBasic configured → 401 + WWW-Authenticate
     │                   └── neither configured   → 403 (Http403ForbiddenEntryPoint)
     │
     └── Is auth a real authenticated user?
               YES → "You're logged in but lack permission" → AccessDeniedHandler
                         └── 403 Forbidden
```

Notice the trap at the bottom of the first branch: if you configure neither form login nor HTTP Basic, the default `AuthenticationEntryPoint` is `Http403ForbiddenEntryPoint`, which returns 403 even for unauthenticated requests. This means you can have an anonymous user hit a protected endpoint and get 403 instead of 401 — technically wrong semantics. Always configure an explicit entry point for REST APIs.

---

## Layer 5: `AnonymousAuthenticationProvider` — The Key Validation Mechanism

```java
/**
 * LAYER 5: AnonymousAuthenticationProvider — validates that an AnonymousAuthenticationToken
 * was created by THIS application, not forged or injected from somewhere else.
 *
 * This is a defense-in-depth measure. Since anonymous tokens never cross
 * network boundaries in normal usage, the key mainly prevents edge cases
 * like deserializing stale tokens or sharing tokens across applications
 * that happen to share a session store.
 */
public class AnonymousAuthenticationProvider implements AuthenticationProvider {

    private final String key;

    @Override
    public Authentication authenticate(Authentication authentication) {
        // Verify the key hash matches — token was created by our filter, not forged
        if (this.key.hashCode()
                != ((AnonymousAuthenticationToken) authentication).getKeyHash()) {
            throw new BadCredentialsException(
                "The presented AnonymousAuthenticationToken does not contain expected key");
        }
        return authentication; // Return as-is — no transformation needed
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return AnonymousAuthenticationToken.class.isAssignableFrom(authentication);
    }
}

/**
 * Spring Boot auto-generates a random UUID key on each startup.
 * This means anonymous tokens don't survive restarts — which is fine
 * because they're never persisted to any store anyway.
 *
 * Key flow: AnonymousAuthenticationFilter creates token with key X
 *           AnonymousAuthenticationProvider validates token has key X
 *           Both get the same key from the configuration.
 */
```

---

## Layer 6: Complete Configuration — Every Customization Point

```java
/**
 * LAYER 6A: Default configuration — anonymous auth is on by default.
 * You don't need to configure anything for it to work.
 * This is here to show the explicit equivalent of the default.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/public/**").permitAll()
                .requestMatchers("/api/**").hasRole("API_USER")
                .anyRequest().authenticated()
            )
            // This is what Spring Boot enables by default — you'd never write this
            // unless you're customizing:
            .anonymous(anon -> anon
                .principal("anonymousUser")              // default
                .authorities("ROLE_ANONYMOUS")           // default
                .key(UUID.randomUUID().toString())       // default (auto-generated)
            )
            .formLogin(Customizer.withDefaults());

        return http.build();
    }
}

/**
 * LAYER 6B: Custom anonymous configuration.
 *
 * Use case: e-commerce site where anonymous users should have meaningful
 * authorities — they can browse the catalog and view public products,
 * but cannot place orders or access their profile.
 */
@Bean
public SecurityFilterChain ecommerceFilterChain(HttpSecurity http) throws Exception {
    http
        .anonymous(anon -> anon
            .principal(new GuestIdentity("guest", "Guest Shopper")) // custom object
            .authorities(
                new SimpleGrantedAuthority("ROLE_ANONYMOUS"),
                new SimpleGrantedAuthority("BROWSE_CATALOG"),
                new SimpleGrantedAuthority("VIEW_PRODUCT_DETAILS")
            )
        )
        .authorizeHttpRequests(auth -> auth
            // Anonymous users with BROWSE_CATALOG can access these:
            .requestMatchers("/catalog/**").hasAuthority("BROWSE_CATALOG")
            .requestMatchers("/products/{id}").hasAuthority("VIEW_PRODUCT_DETAILS")
            // Everything else requires a real login:
            .requestMatchers("/cart/**", "/checkout/**", "/profile/**").authenticated()
            .anyRequest().authenticated()
        );

    return http.build();
}

// Custom principal — gives your anonymous users a real domain object to work with:
public record GuestIdentity(String id, String displayName) implements Serializable {}

/**
 * LAYER 6C: Disabling anonymous authentication — use with caution.
 *
 * The ONLY legitimate use cases:
 *   1. Internal machine-to-machine APIs where every caller MUST authenticate
 *   2. You explicitly want NPEs as a loud failure when auth is missing
 *   3. You're building a custom security context pipeline that manages null itself
 */
@Bean
public SecurityFilterChain internalApiChain(HttpSecurity http) throws Exception {
    http
        .securityMatcher("/internal/**")
        .anonymous(AbstractHttpConfigurer::disable) // dangerous — read the consequences below
        .authorizeHttpRequests(auth -> auth
            .anyRequest().authenticated()
        )
        .httpBasic(Customizer.withDefaults());

    return http.build();
    // CONSEQUENCE: SecurityContext.getAuthentication() = null for unauthenticated requests.
    // Any code that calls getAuthentication().getName() on an unauthenticated request
    // will throw NullPointerException. ExceptionTranslationFilter may behave
    // differently for null vs AnonymousAuthenticationToken.
    // Only disable this if you're absolutely sure every request will be authenticated.
}
```

---

## Layer 7: Anonymous Authentication in Method Security — The SpEL Hierarchy

```java
/**
 * LAYER 7: The four SpEL expressions and exactly what they include/exclude.
 *
 * Understanding which users each expression accepts is critical for
 * placing authorization correctly in your endpoints.
 *
 * Anonymous:    has AnonymousAuthenticationToken
 * Remember-Me:  has RememberMeAuthenticationToken (logged in via cookie)
 * Full Auth:    has UsernamePasswordAuthenticationToken with authenticated=true
 *               (logged in this session with real credentials)
 */
@RestController
@RequestMapping("/api")
public class AuthLevelDemoController {

    // Everyone can call this — anonymous, remember-me, full auth.
    // Anonymous users get principal="anonymousUser" (String).
    @GetMapping("/public")
    public ResponseEntity<String> publicEndpoint(Authentication auth) {
        // auth is never null here — worst case it's AnonymousAuthenticationToken
        String who = (auth instanceof AnonymousAuthenticationToken)
            ? "Guest"
            : auth.getName();
        return ResponseEntity.ok("Hello, " + who + "!");
    }

    // isAuthenticated() = !isAnonymous()
    // Allows: remember-me, full auth
    // Blocks: anonymous → AccessDeniedException → 401
    @GetMapping("/profile")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<UserProfileDto> getProfile(Authentication auth) {
        // Safe to cast here — we know it's not anonymous
        UserPrincipal principal = (UserPrincipal) auth.getPrincipal();
        return ResponseEntity.ok(buildProfile(principal));
    }

    // isFullyAuthenticated() = !isAnonymous() && !isRememberMe()
    // Allows: full auth only
    // Blocks: anonymous → 401, remember-me → 401 (forces re-login)
    // Use for: password changes, payment, anything requiring fresh credentials
    @PostMapping("/change-password")
    @PreAuthorize("isFullyAuthenticated()")
    public ResponseEntity<Void> changePassword(@RequestBody PasswordChangeRequest req,
                                                Authentication auth) {
        // User definitely authenticated this session with real credentials
        passwordService.change(auth.getName(), req.getOldPassword(), req.getNewPassword());
        return ResponseEntity.noContent().build();
    }

    // hasRole('ADMIN') implicitly requires authentication too
    // Anonymous → AccessDeniedException → trustResolver.isAnonymous() → 401
    // ROLE_USER → AccessDeniedException → trustResolver says NOT anonymous → 403
    @DeleteMapping("/users/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> deleteUser(@PathVariable Long id) {
        userService.delete(id);
        return ResponseEntity.noContent().build();
    }
}
```

The `isFullyAuthenticated()` case is particularly important in real applications. Consider a scenario where a user logs in with "Remember Me," then tries to change their password two weeks later. You don't want that password change to succeed based on a cookie that was set weeks ago — you want them to re-enter their current password first. `isFullyAuthenticated()` forces that re-login, because `RememberMeAuthenticationToken` is not "full" authentication.

---

## Layer 8: Production Patterns — Where Anonymous Auth Actually Matters

```java
/**
 * LAYER 8A: The principal casting trap in production code.
 *
 * This is the most common runtime bug caused by anonymous authentication.
 * Any code that assumes getPrincipal() returns UserDetails will crash
 * on anonymous requests — even on permitAll() endpoints.
 */
@Service
@RequiredArgsConstructor
public class ActivityTrackingService {

    // ❌ WRONG — crashes on anonymous requests
    public void trackActivity(Authentication auth, String action) {
        UserDetails user = (UserDetails) auth.getPrincipal(); // ClassCastException for anonymous!
        activityRepo.save(new Activity(user.getUsername(), action));
    }

    // ✓ CORRECT — defensive principal extraction
    public void trackActivitySafe(Authentication auth, String action) {
        String username;

        if (auth == null) {
            username = "unknown"; // shouldn't happen if anonymous auth is on
        } else if (auth instanceof AnonymousAuthenticationToken) {
            username = "anonymous"; // explicit anonymous handling
        } else if (auth.getPrincipal() instanceof UserDetails userDetails) {
            username = userDetails.getUsername(); // real user
        } else {
            username = auth.getName(); // fallback to getName() — always safe
        }

        activityRepo.save(new Activity(username, action));
    }

    // ✓ BEST for most cases — auth.getName() is always safe, never throws
    // For anonymous: returns "anonymousUser" (the principal's toString())
    // For real users: returns UserDetails.getUsername()
    public void trackActivitySimple(Authentication auth, String action) {
        String username = (auth != null) ? auth.getName() : "unknown";
        activityRepo.save(new Activity(username, action));
    }
}

/**
 * LAYER 8B: Custom filter that must handle the null-before-anonymous ordering.
 *
 * This is the order-dependent NPE trap. If your filter runs before
 * AnonymousAuthenticationFilter (order 1300), auth CAN be null.
 * If it runs after, auth is guaranteed to be non-null.
 */
@Component
@Slf4j
public class RequestAuditFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain)
            throws ServletException, IOException {

        // This filter runs AFTER AnonymousAuthenticationFilter
        // (registered via addFilterAfter — see configuration below)
        // so auth is guaranteed non-null.
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        String principal = switch (auth) {
            case AnonymousAuthenticationToken a -> "anonymous[" + request.getRemoteAddr() + "]";
            case null -> "pre-auth"; // shouldn't happen if placed after anonymous filter
            default -> auth.getName();
        };

        log.info("Request: {} {} by {}", request.getMethod(), request.getRequestURI(), principal);

        try {
            chain.doFilter(request, response);
        } finally {
            // log response status
            log.debug("Response: {} for {} {}", response.getStatus(),
                      request.getMethod(), request.getRequestURI());
        }
    }
}

/**
 * LAYER 8C: Registering custom filters at the right position.
 */
@Bean
public SecurityFilterChain filterChain(HttpSecurity http,
                                        RequestAuditFilter auditFilter) throws Exception {
    http
        // Place AFTER AnonymousAuthenticationFilter — guarantees non-null auth
        .addFilterAfter(auditFilter, AnonymousAuthenticationFilter.class)
        // ... rest of config
        ;
    return http.build();
}

/**
 * LAYER 8D: Custom AuthenticationTrustResolver — advanced extension point.
 *
 * Use case: your app has "service account" tokens that should be treated
 * as anonymous for UI-facing 401/403 decisions but as authenticated for
 * audit purposes. You extend the resolver to teach ExceptionTranslationFilter
 * about your custom token type.
 */
@Component
public class EnterpriseAuthTrustResolver extends AuthenticationTrustResolverImpl {

    @Override
    public boolean isAnonymous(Authentication authentication) {
        if (super.isAnonymous(authentication)) return true;
        // Service accounts accessing UI endpoints should get 401, not 403
        return authentication instanceof ServiceAccountAuthenticationToken serviceToken
               && serviceToken.isUiRequest();
    }
}

// Wire it into ExceptionTranslationFilter via ObjectPostProcessor:
@Bean
public SecurityFilterChain filterChain(HttpSecurity http,
                                        EnterpriseAuthTrustResolver trustResolver) throws Exception {
    http.exceptionHandling(ex -> ex
        .withObjectPostProcessor(
            new ObjectPostProcessor<ExceptionTranslationFilter>() {
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

## Layer 9: Testing Anonymous Authentication

```java
/**
 * LAYER 9: Testing strategies for anonymous auth scenarios.
 *
 * spring-security-test provides @WithAnonymousUser for explicit anonymous
 * testing, and the default for unauthenticated requests is anonymous too.
 */
@SpringBootTest
@AutoConfigureMockMvc
class AnonymousAuthTest {

    @Autowired MockMvc mockMvc;

    @Test
    @DisplayName("Anonymous request to protected endpoint → 401, not 403")
    void anonymousGets401NotForbidden() throws Exception {
        // No credentials → AnonymousAuthenticationFilter sets anonymous token
        // AuthorizationFilter denies → ExceptionTranslationFilter sees anonymous → 401
        mockMvc.perform(get("/api/profile"))
            .andExpect(status().isUnauthorized()); // 401, not 403!
    }

    @Test
    @DisplayName("Authenticated user with wrong role → 403, not 401")
    @WithMockUser(username = "alice", roles = {"USER"})
    void authenticatedWrongRole() throws Exception {
        // Real authenticated user → ExceptionTranslationFilter sees NOT anonymous → 403
        mockMvc.perform(delete("/api/users/5"))
            .andExpect(status().isForbidden()); // 403, not 401!
    }

    @Test
    @DisplayName("Anonymous user can access permitAll endpoint")
    @WithAnonymousUser // explicit anonymous — same as no credentials
    void anonymousAccessesPublicEndpoint() throws Exception {
        mockMvc.perform(get("/api/public"))
            .andExpect(status().isOk())
            .andExpect(content().string(containsString("Guest")));
    }

    @Test
    @DisplayName("getPrincipal() for anonymous is String, not UserDetails")
    @WithAnonymousUser
    void anonymousPrincipalIsString() throws Exception {
        MvcResult result = mockMvc.perform(get("/api/public"))
            .andExpect(status().isOk())
            .andReturn();

        // Verify our controller correctly handled String principal
        assertThat(result.getResponse().getContentAsString())
            .contains("Guest"); // controller detected anonymous and returned "Guest"
    }

    @Test
    @DisplayName("isAuthenticated() correctly blocks anonymous in method security")
    void isAuthenticatedBlocksAnonymous() throws Exception {
        // @PreAuthorize("isAuthenticated()") should block anonymous
        mockMvc.perform(get("/api/profile")) // no credentials
            .andExpect(status().isUnauthorized()); // isAuthenticated() = !isAnonymous() = false
    }
}
```

---

## The Complete Mental Model

Here is how anonymous authentication connects to every other piece of the security pipeline, and why removing it would break the entire 401/403 routing mechanism:

```
HTTP Request (no credentials)
     │
     ▼
SecurityContextHolderFilter          ← loads empty context (no session)
     │ auth = null
     ▼
[All auth filters]                   ← no credentials → all pass through
     │ auth still = null
     ▼
AnonymousAuthenticationFilter        ← the gap-filler
     └── auth == null → creates AnonymousAuthenticationToken{
           principal="anonymousUser", authorities=[ROLE_ANONYMOUS], authenticated=true
         }
     │ auth = AnonymousAuthenticationToken (never saved to session)
     ▼
ExceptionTranslationFilter           ← wraps downstream in try-catch
     │
     ▼
AuthorizationFilter                  ← evaluates rules
     └── anyRequest().authenticated()
     └── SpEL: !isAnonymous() = false → DENY
     └── throws AccessDeniedException
     │
     ▼ (bubbles back up)
ExceptionTranslationFilter
     └── trustResolver.isAnonymous(auth) = TRUE  ← anonymous token enables this!
     └── sendStartAuthentication()
           ├── formLogin → 302 /login
           ├── httpBasic → 401 + WWW-Authenticate
           └── neither  → 403 (Http403ForbiddenEntryPoint default)

─────────────────────────────────────────────────────────────────────────────
Same path, real user alice (ROLE_USER) hitting /admin (requires ROLE_ADMIN):

BasicAuthenticationFilter sets UsernamePasswordAuthenticationToken(alice, ROLE_USER)
     │ auth = UsernamePasswordAuthenticationToken, authenticated=true
     ▼
AnonymousAuthenticationFilter        ← auth != null → transparent pass-through
     ▼
AuthorizationFilter                  ← hasRole('ADMIN') → alice has ROLE_USER only → DENY
     └── throws AccessDeniedException
     ▼
ExceptionTranslationFilter
     └── trustResolver.isAnonymous(auth) = FALSE  ← real user, not anonymous!
     └── accessDeniedHandler.handle() → 403 Forbidden
```

The deepest insight is this: `AnonymousAuthenticationToken` is the *bridge* between "no authentication happened" and "the authorization layer can make type-safe decisions." Without it, `ExceptionTranslationFilter` would need to check for null, and the clean 401/403 split would require special-casing null everywhere. With it, the entire security model is consistent — every state in the system is represented by a typed token, and every decision is based on type inspection rather than null checks.
