# TOPIC 17 — Logout Mechanism

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

---

## 1️⃣ Conceptual Explanation

---

### 17.1 What Is Logout — The Complete Security Picture

Logout is not simply "deleting a cookie." A complete, secure logout must:

```
Complete logout checklist:
     ├── 1. Invalidate server-side HTTP session
     │        (prevents session replay attacks)
     │
     ├── 2. Clear SecurityContext from SecurityContextHolder
     │        (prevents in-memory authentication reuse)
     │
     ├── 3. Delete session cookie (JSESSIONID)
     │        (prevents browser from sending dead session)
     │
     ├── 4. Delete remember-me cookie
     │        (prevents automatic re-authentication)
     │
     ├── 5. Remove persistent remember-me tokens from database
     │        (prevents token replay even if cookie restored)
     │
     ├── 6. Revoke OAuth2 tokens (if applicable)
     │        (prevents access token reuse after logout)
     │
     ├── 7. Initiate OIDC RP-Initiated Logout (if applicable)
     │        (signals Identity Provider that user has logged out)
     │
     └── 8. Redirect to appropriate post-logout URL
               (confirm logout to user)
```

**Spring Security handles all of these** through its `LogoutFilter` + `LogoutHandler` chain architecture.

---

### 17.2 LogoutFilter — Complete Internal Architecture

`LogoutFilter` extends `GenericFilterBean` and is positioned at **order 700** — early in the filter chain, before authentication filters.

**Why so early?**

```
Logout URL: /logout (POST by default)

If LogoutFilter were placed AFTER authentication filters:
     POST /logout → Authentication filters run first
     → If session invalid → redirect to /login
     → Logout request NEVER processed!

By running EARLY:
     POST /logout → LogoutFilter intercepts FIRST
     → Logout processed → redirect to /login?logout
     → Never reaches authentication filters
```

**Complete internal flow:**

```java
public class LogoutFilter extends GenericFilterBean {

    private RequestMatcher logoutRequestMatcher;
    // Default: AntPathRequestMatcher("/logout", "POST")
    // Note: POST method enforcement requires CSRF token!

    private final LogoutHandler handler;
    // CompositeLogoutHandler wrapping all configured handlers

    private final LogoutSuccessHandler logoutSuccessHandler;
    // Default: SimpleUrlLogoutSuccessHandler → redirect to /login?logout

    @Override
    public void doFilter(ServletRequest request, ServletResponse response,
            FilterChain chain) throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        // Step 1: Does this request match logout URL?
        if (requiresLogout(httpRequest, httpResponse)) {

            // Step 2: Get current authentication
            Authentication auth = SecurityContextHolder.getContext()
                .getAuthentication();

            // Step 3: Execute all logout handlers in order
            try {
                this.handler.logout(httpRequest, httpResponse, auth);
            } catch (LogoutException ex) {
                // Handler threw exception — log but continue
                // Logout should not throw to user
            }

            // Step 4: Handle logout success (redirect)
            this.logoutSuccessHandler.onLogoutSuccess(
                httpRequest, httpResponse, auth);

            // NOTE: Chain is NOT continued after logout
            // Response is committed (redirect sent) — done
            return;
        }

        // Not a logout request → continue filter chain
        chain.doFilter(request, response);
    }

    protected boolean requiresLogout(HttpServletRequest request,
            HttpServletResponse response) {
        return this.logoutRequestMatcher.matches(request);
    }
}
```

---

### 17.3 LogoutHandler — The Handler Chain Architecture

`LogoutHandler` is the interface for individual logout operations:

```java
public interface LogoutHandler {
    void logout(HttpServletRequest request,
                HttpServletResponse response,
                Authentication authentication);
}
```

**`CompositeLogoutHandler` — orchestrates multiple handlers:**

```java
public final class CompositeLogoutHandler implements LogoutHandler {
    private final List<LogoutHandler> logoutHandlers;

    @Override
    public void logout(HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication) {
        // Execute each handler in REGISTRATION ORDER
        for (LogoutHandler handler : this.logoutHandlers) {
            handler.logout(request, response, authentication);
        }
    }
}
```

**Built-in `LogoutHandler` implementations:**

```
LogoutHandler implementations (in typical registration order):
     │
     ├── CookieClearingLogoutHandler
     │       Deletes specified cookies by name
     │       Sets: cookie.setMaxAge(0); cookie.setValue("");
     │
     ├── SecurityContextLogoutHandler (MOST IMPORTANT)
     │       Invalidates HttpSession
     │       Clears SecurityContext from SecurityContextHolder
     │       Clears SecurityContext from SecurityContextRepository
     │
     ├── RememberMeServices (implements LogoutHandler)
     │       Hash-based: clears remember-me cookie
     │       Persistent: clears cookie + removes DB token
     │
     ├── HeaderWriterLogoutHandler
     │       Writes security headers on logout response
     │       (e.g., Clear-Site-Data header)
     │
     ├── OidcClientInitiatedLogoutSuccessHandler
     │       Initiates OIDC RP-Initiated Logout
     │       (not a LogoutHandler but LogoutSuccessHandler)
     │
     └── Custom LogoutHandler implementations
             OAuth2 token revocation
             Audit logging
             Cache clearing
```

---

### 17.4 SecurityContextLogoutHandler — The Core Handler

`SecurityContextLogoutHandler` is the most critical logout handler — it performs the core security cleanup:

```java
public class SecurityContextLogoutHandler implements LogoutHandler {

    private boolean invalidateHttpSession = true;
    private boolean clearAuthentication = true;

    @Override
    public void logout(HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication) {

        // Step 1: Invalidate HTTP Session
        if (this.invalidateHttpSession) {
            HttpSession session = request.getSession(false);
            if (session != null) {
                logger.debug("Invalidating session: " + session.getId());
                session.invalidate();
                // This:
                //   - Removes all session attributes
                //   - Makes session ID invalid
                //   - Triggers HttpSessionDestroyedEvent
                //   - Notifies HttpSessionEventPublisher
                //   - SessionRegistry removes session (for concurrent control)
            }
        }

        // Step 2: Clear SecurityContext
        if (this.clearAuthentication) {
            SecurityContext context =
                SecurityContextHolder.getContext();
            context.setAuthentication(null);
            // Removes Authentication from in-memory context

            SecurityContextHolder.clearContext();
            // Removes the SecurityContext itself from ThreadLocal
        }

        // Step 3: Clear from SecurityContextRepository
        // (prevents re-loading from session on same request)
        SecurityContextRepository repo = ...;
        repo.saveContext(
            SecurityContextHolder.createEmptyContext(),
            request, response);
    }
}
```

**What happens if `invalidateHttpSession = false`?**

```
SecurityContextLogoutHandler with invalidateHttpSession=false:
     → Session NOT invalidated
     → Session still exists on server
     → Session still accessible (could replay)

USE CASE for false:
     Application needs to preserve some session attributes after logout
     (e.g., locale preference, shopping cart for anonymous session)
     Extremely rare — almost always keep true

SECURITY NOTE:
     Even with false, SecurityContext IS cleared
     Authentication is removed from session attribute
     But session itself still accessible → attack surface
```

---

### 17.5 CookieClearingLogoutHandler — Cookie Deletion

```java
public final class CookieClearingLogoutHandler
        implements LogoutHandler {

    private final List<Function<HttpServletRequest, Cookie>>
        cookiesToClear;

    public CookieClearingLogoutHandler(String... cookiesToClear) {
        // For each cookie name, create a deletion cookie:
        // cookie.setMaxAge(0) → tells browser to delete
        // cookie.setValue("") → empty value
        // cookie.setPath("/") → matches the original path
    }

    @Override
    public void logout(HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication) {
        this.cookiesToClear.forEach(cookieFunction -> {
            Cookie cookie = cookieFunction.apply(request);
            response.addCookie(cookie);
        });
    }
}
```

**Cookie deletion mechanics:**

```
To delete a cookie, the server sends:
     Set-Cookie: JSESSIONID=; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT;
                 Path=/; HttpOnly; Secure

Browser interprets Max-Age=0 → delete the cookie immediately

CRITICAL: Path and Domain must EXACTLY match the original cookie
     Original: Set-Cookie: JSESSIONID=abc; Path=/; HttpOnly
     Delete:   Set-Cookie: JSESSIONID=; Max-Age=0; Path=/; HttpOnly ✓
     WRONG:    Set-Cookie: JSESSIONID=; Max-Age=0; Path=/app      ← wrong path
     → Cookie not deleted! (different path = different cookie)
```

---

### 17.6 LogoutSuccessHandler — Post-Logout Behavior

`LogoutSuccessHandler` is called AFTER all `LogoutHandler` instances complete successfully:

```java
public interface LogoutSuccessHandler {
    void onLogoutSuccess(HttpServletRequest request,
                         HttpServletResponse response,
                         Authentication authentication)
            throws IOException, ServletException;
}
```

**Built-in implementations:**

```
SimpleUrlLogoutSuccessHandler (default):
     response.sendRedirect(logoutSuccessUrl)
     Default URL: /login?logout
     Customizable: .logoutSuccessUrl("/custom-logout-success")

HttpStatusReturningLogoutSuccessHandler:
     response.setStatus(httpStatus.value())
     Returns HTTP status (e.g., 200 OK) instead of redirect
     Use case: REST APIs where redirect doesn't make sense

OidcClientInitiatedLogoutSuccessHandler:
     Initiates OIDC RP-Initiated Logout
     Redirects to: {end_session_endpoint}?
                   post_logout_redirect_uri={appUrl}&
                   id_token_hint={idToken}
```

---

### 17.7 Logout Request Matching — GET vs POST

**Default behavior:**

```java
// Spring Security default:
// Logout URL: /logout
// Method: POST ONLY (CSRF protection)

// Why POST?
// GET /logout link could be exploited:
//     Attacker embeds: <img src="https://app.com/logout"/>
//     Victim's browser: loads image → GET /logout → victim logged out!
//     This is a "logout CSRF" attack

// POST requires CSRF token → cross-site logout impossible
```

**Allowing GET logout (with caution):**

```java
http.logout(logout -> logout
    .logoutRequestMatcher(
        new AntPathRequestMatcher("/logout"))
    // Matches ANY method (GET, POST, DELETE, etc.)
    // CSRF protection must be considered separately!
);

// OR: explicit GET logout (less secure):
http.logout(logout -> logout
    .logoutRequestMatcher(
        new AntPathRequestMatcher("/logout", "GET"))
    // Only GET /logout triggers logout
    // Vulnerable to logout CSRF if used without protection
);
```

**For REST APIs (CSRF disabled):**

```java
// With CSRF disabled (stateless JWT API):
http
    .csrf(AbstractHttpConfigurer::disable)
    .logout(logout -> logout
        .logoutUrl("/api/logout")
        // POST /api/logout works without CSRF token
        // (no CSRF needed when CSRF protection is disabled)
    );
```

---

### 17.8 OIDC RP-Initiated Logout — Complete Architecture

When using OIDC (OpenID Connect) for login, logout must notify the Identity Provider. This is **RP-Initiated Logout** (RP = Relying Party = your application).

**The problem without RP-Initiated Logout:**

```
User logged in via Google OIDC:
     Your app session: JSESSIONID (authenticated as alice)
     Google session:   Google account still active

User clicks "Logout" in your app:
     Your app: session invalidated, SecurityContext cleared ✓
     Google:   Still authenticated!

User navigates to your app again:
     OAuth2 login flow initiated
     Google: "User is already authenticated (session active)"
     → Auto-redirects back with new code
     → Your app: authenticates again automatically!
     → User never actually "logged out"!
```

**OIDC RP-Initiated Logout solves this:**

```
User clicks "Logout":

Step 1: Your app clears local session (as normal)

Step 2: Your app redirects to end_session_endpoint:
     GET https://accounts.google.com/o/oauth2/logout
     ?id_token_hint=eyJhbGc...    (the user's ID token)
     &post_logout_redirect_uri=https://app.example.com/logged-out
     &state=random-state          (optional CSRF protection)

Step 3: Google:
     Validates id_token_hint → identifies user and client
     Logs user out of Google session (or shows confirmation page)
     Redirects to post_logout_redirect_uri

Step 4: Your app receives redirect to /logged-out:
     Confirms complete logout
     Shows "You have been successfully logged out" page
```

**Spring Security implementation:**

```java
@Bean
public SecurityFilterChain filterChain(HttpSecurity http,
        ClientRegistrationRepository clients) throws Exception {
    http
        .oauth2Login(Customizer.withDefaults())
        .logout(logout -> logout
            .logoutSuccessHandler(
                oidcLogoutSuccessHandler(clients))
        );
    return http.build();
}

@Bean
public OidcClientInitiatedLogoutSuccessHandler oidcLogoutSuccessHandler(
        ClientRegistrationRepository clients) {

    OidcClientInitiatedLogoutSuccessHandler handler =
        new OidcClientInitiatedLogoutSuccessHandler(clients);

    // Where to redirect AFTER Google completes logout
    handler.setPostLogoutRedirectUri(
        "{baseUrl}/logged-out");
    // {baseUrl} is replaced at runtime with actual base URL

    return handler;
}
```

**`OidcClientInitiatedLogoutSuccessHandler` internal flow:**

```java
// onLogoutSuccess():

Step 1: Get current authentication
     OAuth2AuthenticationToken oauth2Token =
         (OAuth2AuthenticationToken) authentication;

Step 2: Extract ID token
     OidcUser oidcUser = (OidcUser) oauth2Token.getPrincipal();
     OidcIdToken idToken = oidcUser.getIdToken();
     String idTokenValue = idToken.getTokenValue();
     // This is the JWT id_token from login — used as "hint" to IdP

Step 3: Load client registration
     ClientRegistration registration =
         clientRegistrationRepository.findByRegistrationId(
             oauth2Token.getAuthorizedClientRegistrationId());

Step 4: Find end_session_endpoint
     ProviderDetails providerDetails =
         registration.getProviderDetails();
     URI endSessionEndpoint = providerDetails
         .getConfigurationMetadata()
         .get("end_session_endpoint");
     // Auto-discovered from /.well-known/openid-configuration

Step 5: Build logout URL
     UriComponentsBuilder builder =
         UriComponentsBuilder.fromUri(endSessionEndpoint)
             .queryParam("id_token_hint", idTokenValue)
             .queryParam("post_logout_redirect_uri",
                 postLogoutRedirectUri);

Step 6: Redirect browser to IdP logout URL
     response.sendRedirect(builder.toUriString());
```

---

### 17.9 Back-Channel Logout (OIDC)

In addition to RP-Initiated (front-channel) logout, OIDC also supports **back-channel logout** where the IdP notifies the application server-to-server (without browser involvement):

```
Back-Channel Logout Flow:

1. User logs out at IdP (or another RP in the same SSO session)

2. IdP sends POST request DIRECTLY to your application:
     POST https://app.example.com/logout/back-channel
     Content-Type: application/x-www-form-urlencoded
     Body: logout_token=<signed JWT>

3. Your application:
     Validates logout_token (signature, issuer, audience)
     Finds session by "sub" and "sid" claims in logout_token
     Invalidates that session
     Returns 200 OK to IdP

4. User's browser session: invalidated server-side
   (browser not involved — this is server-to-server)
```

**Spring Security 6.2+ back-channel logout support:**

```java
http.oidcLogout(oidc -> oidc
    .backChannel(Customizer.withDefaults())
    // Enables: POST /logout/connect/back-channel/{registrationId}
    // Validates logout token, invalidates session
);
```

---

### 17.10 Logout in Stateless JWT Applications

For stateless JWT applications (no server-side session), logout is architecturally different:

```
Stateless JWT logout challenge:
     JWTs are self-contained — server has no record of issued tokens
     "Logout" = delete client-side JWT (from localStorage/cookie)
     But: old JWT still valid until expiry (no server-side revocation)

     Attacker who has captured the JWT can still use it!

Solutions for stateless JWT logout:

Option A: Short-lived tokens (recommended)
     access_token expires in 5-15 minutes
     Even if captured, valid for short time only
     Combined with refresh token rotation

Option B: JWT denylist (server-side)
     On logout: add JWT ID (jti) to Redis denylist
     On each request: check if jti is in denylist
     But: this makes it stateful! (defeats purpose)

Option C: Opaque reference tokens
     Client uses opaque token
     Server looks up associated data
     On logout: delete server-side data → token immediately invalid

Spring Security approach for stateless logout:
```

```java
@Configuration
@EnableWebSecurity
public class StatelessLogoutConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .sessionManagement(s -> s
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .csrf(AbstractHttpConfigurer::disable)
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(Customizer.withDefaults()))
            .logout(logout -> logout
                .logoutUrl("/api/logout")
                // For stateless: no session to invalidate
                // Client must discard token
                .logoutSuccessHandler(
                    new HttpStatusReturningLogoutSuccessHandler(
                        HttpStatus.OK))
                // Return 200 OK instead of redirect
                .addLogoutHandler(jwtRevocationHandler())
                // Custom: add JWT jti to denylist
            );

        return http.build();
    }
}
```

---

### 17.11 Spring Security 5.x vs 6.x Logout Changes

| Aspect | Spring Security 5.x | Spring Security 6.x |
|--------|--------------------|--------------------|
| DSL | `.logout().logoutUrl()...` | `.logout(logout -> logout.logoutUrl()...)` |
| Default URL | `/logout` POST | `/logout` POST (same) |
| CSRF requirement | POST + CSRF token | POST + CSRF token (same) |
| OIDC logout | Manual `OidcClientInitiatedLogoutSuccessHandler` | Same + back-channel support |
| `SecurityContextLogoutHandler` | `clearContext()` | Also clears `SecurityContextRepository` |
| Back-channel logout | Not built-in | Built-in (6.2+) |
| `LogoutFilter` position | Same | Same (order 700) |

---

## 2️⃣ Code Examples

---

### Example 1 — Complete Logout Configuration (6.x)

```java
@Configuration
@EnableWebSecurity
public class ComprehensiveLogoutConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/login", "/public/**").permitAll()
                .anyRequest().authenticated()
            )
            .formLogin(form -> form
                .loginPage("/login")
                .permitAll()
            )
            .rememberMe(rm -> rm
                .key("${app.remember-me.key}")
                .tokenRepository(persistentTokenRepository())
                .userDetailsService(userDetailsService())
            )
            .logout(logout -> logout
                // ── Logout URL ──────────────────────────────────────
                .logoutUrl("/logout")
                // POST /logout (default, requires CSRF token)

                // ── Success URL ─────────────────────────────────────
                .logoutSuccessUrl("/login?logout")
                // OR use handler for more control:
                // .logoutSuccessHandler(customSuccessHandler())

                // ── Session cleanup ──────────────────────────────────
                .invalidateHttpSession(true)
                .clearAuthentication(true)

                // ── Cookie deletion ──────────────────────────────────
                .deleteCookies("JSESSIONID", "REMEMBER_ME")
                // Adds CookieClearingLogoutHandler

                // ── Custom handlers ──────────────────────────────────
                .addLogoutHandler(auditLogoutHandler())
                // Runs AFTER default handlers in registration order

                // ── Permit all users to access logout ────────────────
                .permitAll()
                // (Logout URL accessible without authentication)
            );

        return http.build();
    }

    @Bean
    public LogoutHandler auditLogoutHandler() {
        return (request, response, authentication) -> {
            if (authentication != null) {
                String username = authentication.getName();
                String ipAddress = request.getRemoteAddr();
                log.info("User {} logged out from IP {}",
                    username, ipAddress);
                auditService.recordLogout(username, ipAddress,
                    LocalDateTime.now());
            }
        };
    }
}
```

---

### Example 2 — OIDC RP-Initiated Logout

```java
@Configuration
@EnableWebSecurity
public class OidcLogoutConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http,
            ClientRegistrationRepository clients) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/", "/login/**", "/logged-out").permitAll()
                .anyRequest().authenticated()
            )
            .oauth2Login(oauth2 -> oauth2
                .defaultSuccessUrl("/dashboard", true)
            )
            .logout(logout -> logout
                .logoutUrl("/logout")

                // OIDC logout: redirect to IdP after local cleanup
                .logoutSuccessHandler(
                    oidcLogoutSuccessHandler(clients))

                // Still clean up local session
                .invalidateHttpSession(true)
                .deleteCookies("JSESSIONID")

                .permitAll()
            );

        return http.build();
    }

    @Bean
    public OidcClientInitiatedLogoutSuccessHandler oidcLogoutSuccessHandler(
            ClientRegistrationRepository clients) {

        OidcClientInitiatedLogoutSuccessHandler handler =
            new OidcClientInitiatedLogoutSuccessHandler(clients);

        // After IdP logs out user, redirect here:
        handler.setPostLogoutRedirectUri("{baseUrl}/logged-out");

        return handler;
    }

    // Post-logout landing page controller:
    @Controller
    public static class LoggedOutController {
        @GetMapping("/logged-out")
        public String loggedOut() {
            return "logged-out";  // renders logged-out.html template
        }
    }
}
```

---

### Example 3 — REST API Logout (No Redirect)

```java
@Configuration
@EnableWebSecurity
public class RestApiLogoutConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(AbstractHttpConfigurer::disable)
            .sessionManagement(s -> s
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(Customizer.withDefaults()))
            .logout(logout -> logout
                .logoutUrl("/api/v1/logout")
                // POST /api/v1/logout

                // Return 200 OK instead of redirect (APIs don't redirect)
                .logoutSuccessHandler(
                    new HttpStatusReturningLogoutSuccessHandler(
                        HttpStatus.OK))

                // For stateless: no session to invalidate
                // But still clear SecurityContext
                .addLogoutHandler((request, response, auth) -> {
                    SecurityContextHolder.clearContext();

                    // Optionally: add JWT jti to denylist
                    if (auth instanceof JwtAuthenticationToken jwtAuth) {
                        String jti = jwtAuth.getToken()
                            .getClaimAsString("jti");
                        tokenDenylistService.addToDenylist(jti,
                            jwtAuth.getToken().getExpiresAt());
                    }
                })
            );

        return http.build();
    }
}
```

```java
// JWT denylist service (Redis-backed):
@Service
public class JwtDenylistService {

    private final RedisTemplate<String, String> redisTemplate;

    public void addToDenylist(String jti, Instant expiry) {
        Duration ttl = Duration.between(Instant.now(), expiry);
        if (!ttl.isNegative()) {
            // Store jti until token naturally expires
            redisTemplate.opsForValue()
                .set("denylist:" + jti, "revoked", ttl);
        }
    }

    public boolean isDenylisted(String jti) {
        return Boolean.TRUE.equals(
            redisTemplate.hasKey("denylist:" + jti));
    }
}

// JWT validation filter checks denylist:
@Bean
public JwtDecoder jwtDecoder() {
    NimbusJwtDecoder decoder = ...;

    // Add custom validator that checks denylist
    OAuth2TokenValidator<Jwt> denylistValidator = token -> {
        String jti = token.getClaimAsString("jti");
        if (jti != null && jwtDenylistService.isDenylisted(jti)) {
            return OAuth2TokenValidatorResult.failure(
                new OAuth2Error("invalid_token", "Token revoked", null));
        }
        return OAuth2TokenValidatorResult.success();
    };

    decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
        JwtValidators.createDefault(),
        denylistValidator
    ));
    return decoder;
}
```

---

### Example 4 — Custom LogoutSuccessHandler with Audit

```java
@Component
public class AuditingLogoutSuccessHandler
        implements LogoutSuccessHandler {

    private final AuditService auditService;
    private final String defaultTargetUrl = "/login?logout";

    @Override
    public void onLogoutSuccess(HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication)
            throws IOException, ServletException {

        // Perform audit AFTER successful logout
        if (authentication != null) {
            String username = authentication.getName();
            String sessionId = request.getSession(false) != null
                ? request.getSession(false).getId()
                : "no-session";

            auditService.recordLogoutEvent(
                AuditEvent.builder()
                    .eventType("USER_LOGOUT")
                    .username(username)
                    .sessionId(sessionId)
                    .ipAddress(request.getRemoteAddr())
                    .userAgent(request.getHeader("User-Agent"))
                    .timestamp(Instant.now())
                    .build()
            );

            log.info("Successful logout: user={}, session={}",
                username, sessionId);
        }

        // Determine redirect URL
        String targetUrl = determineTargetUrl(request, authentication);

        if (!response.isCommitted()) {
            // Redirect only if response not already committed
            response.sendRedirect(targetUrl);
        }
    }

    private String determineTargetUrl(HttpServletRequest request,
            Authentication authentication) {
        // Role-based redirect after logout
        if (authentication != null) {
            boolean isAdmin = authentication.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"));
            if (isAdmin) {
                return "/admin/login?logout";
            }
        }
        return defaultTargetUrl;
    }
}
```

---

### Example 5 — Multiple Security Chains with Different Logout Behaviors

```java
@Configuration
@EnableWebSecurity
public class MultiChainLogoutConfig {

    // Chain 1: REST API — 200 OK on logout, no redirect
    @Bean
    @Order(1)
    public SecurityFilterChain apiChain(HttpSecurity http) throws Exception {
        http
            .securityMatcher("/api/**")
            .csrf(AbstractHttpConfigurer::disable)
            .sessionManagement(s -> s
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .oauth2ResourceServer(o -> o.jwt(Customizer.withDefaults()))
            .logout(logout -> logout
                .logoutUrl("/api/logout")
                .logoutSuccessHandler(
                    new HttpStatusReturningLogoutSuccessHandler(
                        HttpStatus.NO_CONTENT))
                // 204 No Content — RESTful logout response
            );
        return http.build();
    }

    // Chain 2: Web UI — redirect to login page on logout
    @Bean
    @Order(2)
    public SecurityFilterChain webChain(HttpSecurity http,
            ClientRegistrationRepository clients) throws Exception {
        http
            .oauth2Login(Customizer.withDefaults())
            .logout(logout -> logout
                .logoutUrl("/web/logout")
                .logoutSuccessHandler(
                    oidcLogoutHandler(clients))
                .invalidateHttpSession(true)
                .deleteCookies("JSESSIONID")
            );
        return http.build();
    }
}
```

---

### Example 6 — Incorrect Logout Configurations

```java
// ❌ WRONG 1 — GET logout without CSRF consideration
http.logout(logout -> logout
    .logoutUrl("/logout")
    // No method restriction → GET /logout triggers logout
    // Attacker embeds: <img src="https://app.com/logout"/>
    // → Victim visits attacker page → logged out!
    // → "Logout CSRF" attack
);
// ✓ CORRECT: Keep POST (default) or disable CSRF for stateless APIs
http.logout(logout -> logout
    .logoutRequestMatcher(
        new AntPathRequestMatcher("/logout", "POST"))
);

// ❌ WRONG 2 — Not deleting remember-me cookie
http.logout(logout -> logout
    .logoutUrl("/logout")
    .logoutSuccessUrl("/login?logout")
    .invalidateHttpSession(true)
    // Missing: .deleteCookies("remember-me")
    // Session invalidated but remember-me cookie persists
    // User "logs out" → next visit → auto-logged in via remember-me!
);
// ✓ CORRECT:
http.logout(logout -> logout
    .deleteCookies("JSESSIONID", "remember-me")
    .invalidateHttpSession(true)
);

// ❌ WRONG 3 — LogoutSuccessHandler that writes to response AND redirects
public class BrokenLogoutHandler implements LogoutSuccessHandler {
    @Override
    public void onLogoutSuccess(...) throws IOException {
        response.getWriter().write("Logged out!");  // commits response
        response.sendRedirect("/login?logout");     // FAILS — response committed!
        // IllegalStateException: Cannot call sendRedirect after response committed
    }
}
// ✓ CORRECT: Either write response body OR redirect, never both
// For REST: write body and set status
// For web: sendRedirect only

// ❌ WRONG 4 — Logout handler that throws exception
public class ThrowingLogoutHandler implements LogoutHandler {
    @Override
    public void logout(HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication) {
        // Some operation that might fail:
        auditService.recordLogout(authentication.getName());
        // If auditService throws RuntimeException:
        // → Logout process stops!
        // → Session NOT invalidated
        // → Cookies NOT deleted
        // → Partial logout — security vulnerability!
    }
}
// ✓ CORRECT: Wrap in try-catch — logout MUST complete
@Override
public void logout(...) {
    try {
        auditService.recordLogout(authentication.getName());
    } catch (Exception ex) {
        log.error("Audit failed during logout", ex);
        // Continue — don't let audit failure prevent logout!
    }
}
```

---

## 3️⃣ Exam-Style Questions

---

**Q1 (MCQ):** What is the default HTTP method required for Spring Security's logout URL?

A. GET
B. PUT
C. POST
D. DELETE

**Answer: C — POST**
`LogoutFilter` defaults to `AntPathRequestMatcher("/logout", "POST")`. POST is required because:
1. GET requests can be forged cross-site (via `<img src>`, `<a href>`)
2. POST requires a CSRF token (protected against cross-site forgery)
3. HTTP semantics: GET should be idempotent and safe — logout is a state change

---

**Q2 (MCQ):** In what order does Spring Security execute logout handlers?

A. Reverse registration order (last registered runs first)
B. Registration order (first registered runs first)
C. Alphabetical by class name
D. `SecurityContextLogoutHandler` always runs last

**Answer: B — Registration order**
`CompositeLogoutHandler` iterates `List<LogoutHandler>` in registration order. Spring Security registers its default handlers first (`SecurityContextLogoutHandler`, `CookieClearingLogoutHandler`, `RememberMeServices`), then any handlers added via `.addLogoutHandler()`. Custom handlers added via `.addLogoutHandler()` run AFTER the defaults.

---

**Q3 (Select All That Apply):** Which are true about `SecurityContextLogoutHandler`?

A. It invalidates the HTTP session by default
B. It removes authentication from `SecurityContextHolder`
C. It deletes the `JSESSIONID` cookie
D. It is the default logout handler registered by Spring Security
E. Setting `invalidateHttpSession=false` skips session invalidation but still clears `SecurityContext`

**Answer: A, B, D, E**
C is false — `SecurityContextLogoutHandler` does NOT delete cookies. Cookie deletion is performed by `CookieClearingLogoutHandler` (registered when `.deleteCookies()` is configured) or explicitly via `LogoutFilter`'s cookie configuration.

---

**Q4 (Flow Prediction):**

```java
http.logout(logout -> logout
    .logoutUrl("/logout")
    .logoutSuccessUrl("/login?logout")
    .invalidateHttpSession(true)
    .deleteCookies("JSESSIONID")
    .addLogoutHandler(auditHandler)
);
```

List the complete execution order when `POST /logout` is received.

**Answer:**
```
1. LogoutFilter.requiresLogout("/logout", POST) → true
2. Get Authentication from SecurityContextHolder
3. CompositeLogoutHandler.logout():
   a. SecurityContextLogoutHandler.logout()
      → session.invalidate()
      → SecurityContextHolder.clearContext()
   b. CookieClearingLogoutHandler.logout()
      → response.addCookie(JSESSIONID deletion cookie)
   c. auditHandler.logout()
      → logs the logout event
4. logoutSuccessHandler.onLogoutSuccess()
   → SimpleUrlLogoutSuccessHandler
   → response.sendRedirect("/login?logout")
5. LogoutFilter returns (does NOT call chain.doFilter())
```

---

**Q5 (OIDC Logout Scenario):**

A user authenticates via Google OIDC. They click "Logout" in your app. Your app is configured with `OidcClientInitiatedLogoutSuccessHandler`. Trace the complete logout flow including what happens at Google.

**Answer:**
```
1. User clicks logout → POST /logout + CSRF token

2. LogoutFilter activates:
   a. SecurityContextLogoutHandler:
      - Invalidates local HTTP session
      - Clears SecurityContextHolder
   b. CookieClearingLogoutHandler:
      - Deletes JSESSIONID cookie

3. OidcClientInitiatedLogoutSuccessHandler.onLogoutSuccess():
   a. Gets OAuth2AuthenticationToken from authentication
   b. Gets OidcUser.getIdToken() → the JWT id_token from Google login
   c. Loads ClientRegistration for "google"
   d. Finds end_session_endpoint from provider metadata:
      https://accounts.google.com/o/oauth2/logout
   e. Builds URL:
      https://accounts.google.com/o/oauth2/logout
      ?id_token_hint=eyJhbGc...
      &post_logout_redirect_uri=https://app.example.com/logged-out
   f. response.sendRedirect(built URL)

4. Browser redirected to Google:
   - Google validates id_token_hint → identifies user and client
   - Google ends user's Google session (for this client)
   - Google redirects to: https://app.example.com/logged-out

5. Browser arrives at /logged-out:
   - App shows "You have been logged out successfully"
   - User must log in again (both to app AND Google)
```

---

**Q6 (Security Vulnerability):**

```java
http.logout(logout -> logout
    .logoutRequestMatcher(
        new AntPathRequestMatcher("/logout", "GET"))
    .logoutSuccessUrl("/login?logout")
);
```

Identify the security vulnerability and explain the attack.

**Answer: Logout CSRF (Cross-Site Request Forgery for logout)**

Attack:
1. Attacker creates evil.com with: `<img src="https://target-app.com/logout"/>`
2. Victim visits evil.com while logged into target-app.com
3. Browser loads the "image" → `GET https://target-app.com/logout`
4. Victim's JSESSIONID cookie automatically included
5. Target app: `GET /logout` matches → victim is logged out!
6. Victim: session invalidated → redirected to /login

**Impact:** Attacker can force-logout any user who visits evil.com. While not as severe as login CSRF, it can be used for:
- Denial of service (constant forced logout)
- Timing attacks (logout then trick re-login to attacker-controlled session)
- Disruption of long-running authenticated operations

**Fix:** Use POST (default) which requires CSRF token — prevents cross-site forgery.

---

**Q7 (Handler Order):**

```java
http.logout(logout -> logout
    .addLogoutHandler(handlerA)
    .addLogoutHandler(handlerB)
    .deleteCookies("JSESSIONID")
);
```

In what order do handlers execute? (Note: `deleteCookies()` internally adds a `CookieClearingLogoutHandler`)

**Answer:**
Spring Security registers internal handlers FIRST, then handlers added via `.addLogoutHandler()`:

**Actual execution order:**
1. `SecurityContextLogoutHandler` (always registered by default)
2. `CookieClearingLogoutHandler` (from `.deleteCookies("JSESSIONID")`)
3. `handlerA` (from `.addLogoutHandler(handlerA)`)
4. `handlerB` (from `.addLogoutHandler(handlerB)`)

Note: The exact order between Spring's built-in handlers (SecurityContextLogoutHandler and CookieClearingLogoutHandler) depends on the internal `LogoutConfigurer` implementation. `addLogoutHandler()` handlers run AFTER the configurers' own handlers.

---

**Q8 (REST API Logout):**

For a stateless JWT REST API, a client sends `POST /api/logout`. What should ideally happen, and what are the limitations?

**Answer:**

**What should happen:**
1. Server validates the JWT (confirm it's a real authenticated request)
2. Server adds the JWT's `jti` (JWT ID) claim to a denylist (Redis with TTL = token expiry)
3. Server returns `200 OK` or `204 No Content` (no redirect)
4. Client discards the JWT locally (localStorage/cookie deletion)

**Spring Security configuration:**
```java
.logout(logout -> logout
    .logoutSuccessHandler(
        new HttpStatusReturningLogoutSuccessHandler(HttpStatus.NO_CONTENT))
    .addLogoutHandler(jwtDenylistHandler)
)
```

**Limitations of stateless JWT logout:**
1. **Without denylist:** JWT is still valid until expiry (client cannot truly invalidate it — only discard it locally). Attacker with captured JWT can continue using it.
2. **With denylist:** Now stateful (Redis dependency) — partially defeats stateless design.
3. **Access vs refresh tokens:** Must revoke both. Refresh tokens (if opaque) can be deleted from token store.
4. **Other clients:** If user has multiple clients (mobile + web), logout from one doesn't affect others.

**Best practice:** Short-lived access tokens (5-15 minutes) + token rotation + optional denylist for high-security scenarios.

---

## 4️⃣ Trick Analysis

---

**Trick 1 — `LogoutFilter` Does NOT Continue the Filter Chain**

```java
// LogoutFilter.doFilter():
if (requiresLogout(request, response)) {
    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    this.handler.logout(request, response, auth);
    this.logoutSuccessHandler.onLogoutSuccess(request, response, auth);
    return;  // ← STOPS here — does NOT call chain.doFilter()
}
chain.doFilter(request, response);  // Only for non-logout requests

// Implication:
// Filters AFTER LogoutFilter (authentication filters, authorization filter)
// are NEVER reached for logout requests
// This is correct — post-logout handlers shouldn't need auth anyway
```

---

**Trick 2 — Session Invalidation Order Matters**

```java
// SecurityContextLogoutHandler internally:
// Step 1: session.invalidate() ← invalidates BEFORE clearing context
// Step 2: SecurityContextHolder.clearContext()

// Why this order?
// After session.invalidate():
//   HttpSession is gone from server
//   Any subsequent session.getAttribute() on the old session throws IllegalStateException
//
// After SecurityContextHolder.clearContext():
//   SecurityContext removed from ThreadLocal
//   Authentication no longer accessible via SecurityContextHolder

// TRAP: If you access session AFTER invalidation in a LogoutHandler:
public void logout(HttpServletRequest req, ...) {
    req.getSession().setAttribute("farewell", "goodbye");
    // If SecurityContextLogoutHandler ran before this handler:
    // → session.invalidate() already called
    // → IllegalStateException: Session already invalidated!
}
// RULE: If you need session data, access it BEFORE it's invalidated
//       OR use addLogoutHandler() which runs before SecurityContextLogoutHandler
//       in some configurations — check the order!
```

---

**Trick 3 — `deleteCookies()` vs Cookie Path Mismatch**

```
deleteCookies("JSESSIONID") creates:
     Set-Cookie: JSESSIONID=; Max-Age=0; Path=/; HttpOnly

Original cookie may have been set with different path:
     Set-Cookie: JSESSIONID=abc; Path=/app; HttpOnly

MISMATCH: /app ≠ /
→ Deletion cookie doesn't match original → browser keeps JSESSIONID!

Fix: Use CookieClearingLogoutHandler with explicit path:
     new CookieClearingLogoutHandler(cookieName -> {
         Cookie cookie = new Cookie(cookieName, "");
         cookie.setPath("/app");  // match original path!
         cookie.setMaxAge(0);
         return cookie;
     });

OR: Ensure application sets cookies with consistent paths
    Typically use Path=/ for simplicity
```

---

**Trick 4 — OIDC Logout Requires `id_token` to Be Stored**

```
OidcClientInitiatedLogoutSuccessHandler needs:
     oidcUser.getIdToken().getTokenValue()  ← the raw id_token JWT

This requires:
     1. User authenticated via OIDC (scope includes "openid")
     2. OidcUser stored in Authentication (not just OAuth2User)
     3. id_token preserved in OidcUser

Trap: If you replace OidcUser with a custom UserDetails in successHandler:
     return new CustomUserDetails(oidcUser.getAttributes());
     // OidcUser lost → id_token lost → OIDC logout fails!

CORRECT: Keep OidcUser as principal OR store id_token separately:
     // Option A: Keep OidcUser
     return new DefaultOidcUser(authorities, oidcUser.getIdToken(),
         oidcUser.getUserInfo());

     // Option B: Custom class that wraps OidcUser
     public class CustomOidcUser extends DefaultOidcUser {
         private final String tenantId;
         // Preserves OidcUser behavior including getIdToken()
     }
```

---

**Trick 5 — Logout with Remember-Me Requires TWO Cookie Deletions**

```
After login with remember-me, browser has:
     Cookie 1: JSESSIONID (session cookie)
     Cookie 2: remember-me (persistent cookie)

On logout:
     Without deleteCookies("remember-me"):
          JSESSIONID deleted (session invalidated)
          remember-me STILL PRESENT

     User "logged out" → next request:
          No JSESSIONID (deleted)
          BUT: remember-me cookie present
          RememberMeAuthenticationFilter: auto-login!
          → User "logged back in" immediately after logout!

ALWAYS delete BOTH cookies:
     http.logout(logout -> logout
         .deleteCookies("JSESSIONID", "remember-me")
         // OR whatever name you configured
     );

AND for persistent tokens:
     RememberMeServices.logout() removes DB entry
     (Spring Security calls this automatically if rememberMe() is configured)
```

---

**Trick 6 — `permitAll()` on Logout — Why It's Needed**

```java
http.logout(logout -> logout
    .logoutUrl("/logout")
    .permitAll()  // ← Why is this needed?
);

// Without .permitAll():
// LogoutFilter at order 700 runs BEFORE AuthorizationFilter (order 1600)
// So technically, AuthorizationFilter hasn't checked access yet

// BUT: If anyRequest().authenticated() is configured:
// The ExceptionTranslationFilter might redirect unauthenticated users
// to /login before they even reach LogoutFilter if:
//   - The session expired
//   - The user cleared cookies manually
//   - The request is from a different browser

// .permitAll() ensures AuthorizationFilter allows /logout for everyone
// This prevents: "I can't log out because I'm not authenticated enough"

// Practical example:
// User's session expires while they're on a page
// They click "Logout"
// Without .permitAll(): redirect to login (confusing)
// With .permitAll(): logout processed (session cleaned up), redirect to login?logout
```

---

**Trick 7 — `HttpStatusReturningLogoutSuccessHandler` for REST APIs**

```java
// FOR REST APIS: Never redirect on logout — return HTTP status

// ❌ WRONG for REST (redirects):
.logoutSuccessUrl("/login?logout")
// REST clients: follow redirect → unexpected behavior

// ✓ CORRECT for REST (returns status):
.logoutSuccessHandler(
    new HttpStatusReturningLogoutSuccessHandler(HttpStatus.OK))
// Returns: HTTP 200 OK with empty body

// OR:
.logoutSuccessHandler(
    new HttpStatusReturningLogoutSuccessHandler(HttpStatus.NO_CONTENT))
// Returns: HTTP 204 No Content (more RESTful for delete-like operation)

// Client handles:
// 200/204 → clear local token storage → redirect to login screen
//            (client-side redirect, not server-side)
```

---

## 5️⃣ Summary Sheet

---

### Logout Execution Flow Diagram

```
POST /logout (with CSRF token)
     │
     ▼
LogoutFilter (order 700)
     │
     ├── requiresLogout("/logout", "POST") → true
     │
     ├── Get Authentication from SecurityContextHolder
     │
     ├── CompositeLogoutHandler.logout()  [IN ORDER]:
     │       ├── SecurityContextLogoutHandler
     │       │       ├── session.invalidate()
     │       │       └── SecurityContextHolder.clearContext()
     │       │
     │       ├── CookieClearingLogoutHandler
     │       │       └── Set-Cookie: JSESSIONID=; Max-Age=0
     │       │           Set-Cookie: remember-me=; Max-Age=0
     │       │
     │       ├── RememberMeServices.logout()  [if configured]
     │       │       └── Delete DB token (persistent) / clear cookie (hash)
     │       │
     │       └── Custom LogoutHandlers [via addLogoutHandler()]
     │               └── Audit logging, cache clearing, etc.
     │
     ├── LogoutSuccessHandler.onLogoutSuccess()
     │       ├── SimpleUrlLogoutSuccessHandler → redirect /login?logout
     │       ├── HttpStatusReturningLogoutSuccessHandler → 200 OK
     │       └── OidcClientInitiatedLogoutSuccessHandler → redirect to IdP
     │
     └── return (does NOT continue filter chain)
```

---

### LogoutHandler Implementations

| Handler | Responsibility | When Auto-Registered |
|---------|---------------|---------------------|
| `SecurityContextLogoutHandler` | Invalidate session + clear context | Always (default) |
| `CookieClearingLogoutHandler` | Delete named cookies | When `.deleteCookies()` configured |
| `RememberMeServices` | Clean up remember-me | When `.rememberMe()` configured |
| `HeaderWriterLogoutHandler` | Write response headers | When configured |
| Custom (via `.addLogoutHandler()`) | Application-specific | When explicitly added |

---

### Logout Success Handler Selection

| Scenario | Handler | Response |
|----------|---------|---------|
| Traditional web app | `SimpleUrlLogoutSuccessHandler` | 302 → `/login?logout` |
| OIDC login | `OidcClientInitiatedLogoutSuccessHandler` | 302 → IdP end_session_endpoint |
| REST API | `HttpStatusReturningLogoutSuccessHandler` | 200 or 204 |
| Custom logic | Custom `LogoutSuccessHandler` | Any |

---

### Complete Logout Checklist

```
✓ POST method (default) — prevents logout CSRF
✓ invalidateHttpSession(true) — prevents session replay
✓ clearAuthentication(true) — removes SecurityContext
✓ deleteCookies("JSESSIONID") — browser cookie cleanup
✓ deleteCookies("remember-me") — prevents auto re-login
✓ RememberMeServices configured — DB token removed
✓ OIDC logout handler — IdP session terminated
✓ JWT denylist (if JWT) — token revoked server-side
✓ .permitAll() — accessible even for expired sessions
✓ Error handling in custom handlers — never throw from logout
```

---

### Common Interview One-Liners

- **`LogoutFilter` is at order 700** — runs before authentication filters to ensure logout always succeeds
- **POST required by default** — prevents logout CSRF via `<img src="/logout"/>` attack
- **`LogoutFilter` does NOT call `chain.doFilter()`** after logout — request terminates at the handler
- **`SecurityContextLogoutHandler`** invalidates session AND clears `SecurityContextHolder`
- **`CookieClearingLogoutHandler`** deletes cookies — must match original cookie path exactly
- **Forget `deleteCookies("remember-me")`** = user auto-logs in after logout via remember-me cookie
- **`OidcClientInitiatedLogoutSuccessHandler`** needs `id_token` stored in `OidcUser.getIdToken()`
- **REST API logout** = `HttpStatusReturningLogoutSuccessHandler` (200/204) — never redirect
- **JWT logout limitation** = no server-side revocation without denylist (stateless tradeoff)
- **Custom logout handlers must catch exceptions** — failure in one handler must not prevent others from running

---

**Say "Next topic" to proceed to Topic 18: Password Management** — covering `DelegatingPasswordEncoder` internals, the `{id}encoding` prefix system, `BCryptPasswordEncoder` cost factor analysis, transparent password upgrade on login, and secure password storage strategies.
