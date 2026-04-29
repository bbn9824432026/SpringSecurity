# TOPIC 16 — Remember-Me Authentication

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

---

## 1️⃣ Conceptual Explanation

---

### 16.1 What Is Remember-Me Authentication — Design Philosophy

Remember-me authentication allows users to remain authenticated across **browser sessions** — even after closing the browser and reopening it later. Without remember-me, the session cookie (`JSESSIONID`) is typically a session cookie (expires when browser closes), requiring re-login on every browser restart.

**The fundamental challenge:**

```
Normal session lifecycle:
     User logs in → JSESSIONID cookie (session cookie)
     Browser closes → session cookie deleted
     Browser reopens → no cookie → user unauthenticated → must log in again

Remember-me goal:
     User logs in + checks "Remember me" → persistent cookie stored
     Browser closes → persistent cookie survives (has expiry date)
     Browser reopens → cookie sent → user re-authenticated automatically
     No username/password entry needed (until cookie expires)

Security tradeoff:
     Convenience ↑ but security ↓
     Persistent credential (cookie) stored on device
     If device/cookie stolen → attacker authenticated as user
     Must balance: cookie lifetime vs user experience
```

**Where remember-me fits in the authentication hierarchy:**

```
Authentication strength levels (strongest to weakest):

Level 1: isFullyAuthenticated()
     → Interactive login (username + password in this session)
     → Suitable for: password changes, payment, security settings

Level 2: isAuthenticated() (but not fully)
     → Remember-me token
     → Suitable for: viewing data, general app usage
     → NOT suitable for sensitive operations

Level 3: isAnonymous()
     → No authentication
     → Suitable for: public content only
```

---

### 16.2 RememberMeAuthenticationFilter — Architecture and Position

`RememberMeAuthenticationFilter` extends `GenericFilterBean` and runs at **order ~1050** — after `BasicAuthenticationFilter` but before `AnonymousAuthenticationFilter`.

**Why this position matters:**

```
Filter chain order for remember-me:
     ...
     BasicAuthenticationFilter (900)
          → If Basic auth header present, authenticates here → remember-me skipped
     RememberMeAuthenticationFilter (1050)
          → If no prior auth AND remember-me cookie present → authenticates here
     AnonymousAuthenticationFilter (1300)
          → If still no auth → sets anonymous token
     ...

Logic: "More interactive" auth mechanisms run first.
       Remember-me is a fallback — only activates if no other auth occurred.
```

**Complete internal flow:**

```java
public class RememberMeAuthenticationFilter extends GenericFilterBean
        implements ApplicationEventPublisherAware {

    private RememberMeServices rememberMeServices;
    private AuthenticationManager authenticationManager;

    @Override
    public void doFilter(ServletRequest req, ServletResponse res,
            FilterChain chain) throws IOException, ServletException {

        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;

        // Step 1: Skip if already authenticated
        if (SecurityContextHolder.getContext()
                .getAuthentication() == null) {

            // Step 2: Try to auto-login via remember-me cookie
            Authentication rememberMeAuth =
                rememberMeServices.autoLogin(request, response);

            if (rememberMeAuth != null) {
                // Step 3: Validate the remember-me token
                try {
                    rememberMeAuth = authenticationManager
                        .authenticate(rememberMeAuth);

                    // Step 4: Success — store in SecurityContext
                    SecurityContext context =
                        SecurityContextHolder.createEmptyContext();
                    context.setAuthentication(rememberMeAuth);
                    SecurityContextHolder.setContext(context);

                    // Step 5: Optionally call success handler
                    onSuccessfulAuthentication(
                        request, response, rememberMeAuth);

                    // Step 6: Save context (to session)
                    // Note: SessionCreationPolicy affects this
                    if (this.securityContextRepository != null) {
                        this.securityContextRepository
                            .saveContext(context, request, response);
                    }

                    // Step 7: Publish event
                    if (this.eventPublisher != null) {
                        this.eventPublisher.publishEvent(
                            new InteractiveAuthenticationSuccessEvent(
                                rememberMeAuth, this.getClass()));
                    }

                } catch (AuthenticationException ex) {
                    // Step 8: Remember-me validation failed
                    // (cookie tampered, user deleted, etc.)
                    rememberMeServices.loginFail(request, response);
                    onUnsuccessfulAuthentication(
                        request, response, ex);
                }
            }
        }

        // Always continue the chain
        chain.doFilter(request, response);
    }
}
```

**Critical design details:**

```
1. Filter ALWAYS calls chain.doFilter() — even on remember-me failure
   (Unlike form login which stops on success via redirect)
   Remember-me is transparent — sets context if possible, continues either way

2. On remember-me SUCCESS:
   → Authentication type = RememberMeAuthenticationToken
   → isAuthenticated() = true
   → isFullyAuthenticated() = FALSE (crucial for sensitive operation protection)
   → isRememberMe() = TRUE

3. On remember-me FAILURE (bad cookie):
   → rememberMeServices.loginFail() → deletes the cookie
   → No authentication set → anonymous token set by later filter
   → No redirect to login (chain continues)
```

---

### 16.3 Strategy 1 — Simple Hash-Based Token (Stateless)

This is the simpler, stateless strategy. The cookie itself contains all information needed for validation.

**Cookie composition:**

```
Cookie name: remember-me (default)
Cookie value: Base64(username + ":" + expirationTime + ":" +
              md5Hex(username + ":" + expirationTime + ":" +
                     password + ":" + key))

Example breakdown:
     username     = "alice"
     expirationTime = 1700000000000  (Unix milliseconds)
     password     = "$2a$10$hashedPassword"  (from UserDetails)
     key          = "mySecretKey"

     signature = md5Hex("alice:1700000000000:$2a$10$hashedPassword:mySecretKey")

     cookieValue = Base64("alice:1700000000000:<md5signature>")
```

**Validation process (autoLogin):**

```java
// TokenBasedRememberMeServices.processAutoLoginCookie():

Step 1: Base64 decode cookie value
Step 2: Split by ":" → [username, expirationTime, md5Signature]
Step 3: Check expiration
     Long.parseLong(expirationTime) < System.currentTimeMillis()
     → Expired → throw InvalidCookieException

Step 4: Load UserDetails from UserDetailsService
     userDetailsService.loadUserByUsername(username)
     → User deleted → UsernameNotFoundException
     → Which becomes: RememberMeAuthenticationException

Step 5: Recompute expected signature
     expectedSignature = md5Hex(username + ":" + expirationTime + ":" +
                                userDetails.getPassword() + ":" + key)

Step 6: Compare signatures
     !expectedSignature.equals(receivedSignature)
     → Cookie tampered → throw InvalidCookieException

Step 7: Return RememberMeAuthenticationToken(username, key, authorities)
```

**Security properties:**

```
✓ Stateless — no server-side storage needed
✓ Password change invalidates cookies automatically
  (signature includes password — new password = new expected signature)
✓ Key rotation invalidates all cookies
  (signature includes key — new key = new expected signature)

✗ Cookie theft cannot be detected
  (no per-token tracking — any holder of valid cookie = authenticated)
✗ Logout on one device doesn't invalidate other devices' cookies
  (only password change or key change does this)
✗ Uses MD5 for signature — cryptographically weak
  (but combined with password hash + key, practical security is reasonable)
```

---

### 16.4 Strategy 2 — Persistent Token (Database-Backed)

The persistent token strategy is more secure. The cookie contains a database key, not the credentials themselves.

**Cookie composition:**

```
Cookie value: series + ":" + token
     (both are URL-safe random strings)

Server database stores:
     ┌──────────────────────────────────────────────────────────┐
     │  username  │  series    │  token     │  last_used        │
     ├────────────┼────────────┼────────────┼───────────────────┤
     │  alice     │  abc123    │  xyz789    │  2024-01-15 10:30 │
     │  alice     │  def456    │  uvw123    │  2024-01-14 08:15 │
     │  bob       │  ghi789    │  rst456    │  2024-01-15 09:00 │
     └──────────────────────────────────────────────────────────┘

series = identifies the browser/device (fixed for the device's session)
token  = single-use value (changes on every successful auto-login)
```

**Validation process:**

```java
// PersistentTokenBasedRememberMeServices.processAutoLoginCookie():

Step 1: Split cookie by ":" → [series, token]

Step 2: Load from database by series
     PersistentRememberMeToken stored =
         tokenRepository.getTokenForSeries(series);
     stored == null → cookie series unknown → throw exception

Step 3: Compare token values
     !stored.getTokenValue().equals(token)
     → TOKENS DON'T MATCH → THEFT DETECTED!
     → This series was already used → someone else used it
     → Delete ALL tokens for this user (invalidate ALL sessions)
     → Throw CookieTheftException("Presented token "
           + token + " but expected " + stored.getTokenValue())
     → Log security event

Step 4: Check expiration
     stored.getDate().getTime() + tokenValiditySeconds * 1000
         < System.currentTimeMillis()
     → Expired → delete token → throw exception

Step 5: Generate new token (ROTATION)
     newToken = generateTokenData()  // UUID random

Step 6: Update database
     tokenRepository.updateToken(series, newToken, new Date())
     → Same series, NEW token, updated timestamp

Step 7: Update cookie on response
     setCookie([series, newToken], ...)
     → Browser gets new cookie with new token value

Step 8: Load UserDetails and return RememberMeAuthenticationToken
```

**The theft detection mechanism — explained:**

```
Normal flow:
     Time 0: User logs in → series="S1", token="T1" → cookie: S1:T1
     Time 1: User returns → sends S1:T1 → valid → rotates to S1:T2 → cookie: S1:T2
     Time 2: User returns → sends S1:T2 → valid → rotates to S1:T3 → cookie: S1:T3

Theft scenario:
     Time 0: User logs in → series="S1", token="T1" → cookie: S1:T1
     Time 1: ATTACKER steals S1:T1 → uses it → rotates to S1:T2
                                               → ATTACKER has S1:T2
     Time 2: LEGITIMATE USER tries S1:T1 (old token) → MISMATCH with stored S1:T2
             → THEFT DETECTED!
             → ALL tokens for user deleted
             → User forced to re-login
             → Attacker's S1:T2 also now invalid (all tokens deleted)

Why this works:
     The series identifies the auth chain
     Token rotation means OLD tokens become invalid
     If old token presented → someone has been using this series → theft
     Nuclear option: delete all series for the user → everyone logs out
```

**Security properties:**

```
✓ Theft detection via token rotation
✓ Per-device revocation (delete specific series)
✓ Logout cleans up database entries
✓ Token values never derived from user credentials

✗ Requires database storage
✗ Database becomes a target (if stolen, attacker has token values)
✗ Network latency per request for DB lookup (mitigated by caching)
```

---

### 16.5 RememberMeAuthenticationProvider — Token Validation

The `AuthenticationManager` validates the `RememberMeAuthenticationToken` via `RememberMeAuthenticationProvider`:

```java
public class RememberMeAuthenticationProvider
        implements AuthenticationProvider {

    private final String key;

    @Override
    public Authentication authenticate(Authentication authentication) {
        RememberMeAuthenticationToken auth =
            (RememberMeAuthenticationToken) authentication;

        // Validate that token was created by THIS application
        // (prevents tokens from other applications being accepted)
        if (this.key.hashCode() != auth.getKeyHash()) {
            throw new BadCredentialsException(
                "The presented RememberMeAuthenticationToken "
                + "does not contain the expected key");
        }

        return authentication;  // Token is valid
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return RememberMeAuthenticationToken.class
            .isAssignableFrom(authentication);
    }
}
```

**The `key` parameter — cross-application isolation:**

```
Key purpose:
     Each application instance has a configured key
     RememberMeAuthenticationToken includes hash of the key
     Provider validates key hash matches

     Prevents: Tokens from AppA being used on AppB
     (if they share the same Auth Server but different key configs)

Spring Boot auto-generates key:
     If not configured: UUID generated at startup
     Different on every restart → all remember-me tokens invalidated on restart!

Always configure explicitly:
     http.rememberMe(rm -> rm.key("stable-secret-key-from-config"))
     → Tokens survive application restarts
     → Key should be stored in secure configuration (Vault, env var)
```

---

### 16.6 Remember-Me Cookie — HTTP Properties

```java
// Cookie configuration:
http.rememberMe(rm -> rm
    .tokenValiditySeconds(14 * 24 * 60 * 60)  // 14 days
    .rememberMeParameter("remember-me")         // HTML form parameter name
    .rememberMeCookieName("REMEMBER_ME")        // Cookie name
    .rememberMeCookieDomain("example.com")      // Cookie domain
    // Setting domain = cookie valid for *.example.com (subdomain sharing)
    .useSecureCookie(true)                      // HTTPS only
    .tokenRepository(persistentTokenRepository())
);
```

**Cookie attributes critical for security:**

```
Secure flag:
     response.addCookie(cookie) where cookie.setSecure(true)
     → Cookie only sent over HTTPS connections
     → Prevents interception on HTTP (network sniffing)
     → MUST be true in production

HttpOnly flag:
     cookie.setHttpOnly(true) (default for session cookie)
     → Cookie not accessible by JavaScript
     → Prevents XSS theft of remember-me cookie
     → Spring sets this by default on remember-me cookies

SameSite attribute:
     Not directly configurable in older Spring versions
     Spring Boot 2.x/3.x: configure via server.servlet.session.cookie.same-site
     → Lax: Prevents CSRF for most cross-site requests
     → Strict: Prevents all cross-site cookie sending (may break OAuth2 redirects)

Domain scope:
     No domain set: cookie scoped to exact host
     Domain set: cookie valid for domain + all subdomains
     Be careful: .example.com = api.example.com, admin.example.com, etc.
```

---

### 16.7 Always-Remember vs Opt-In Remember

```java
// Opt-in (default): User must check checkbox
http.rememberMe(rm -> rm
    .rememberMeParameter("remember-me")  // form checkbox
    // Only creates remember-me cookie if "remember-me=true" in request
);

// HTML form:
// <input type="checkbox" name="remember-me"/> Remember me

// Always remember (no user choice):
http.rememberMe(rm -> rm
    .alwaysRemember(true)
    // Always creates remember-me cookie regardless of request parameter
);
```

---

### 16.8 Remember-Me Logout — Cleanup

```java
// When user explicitly logs out:
// LogoutFilter calls LogoutHandler chain including:

RememberMeServices.logout(request, response, authentication)
// For hash-based: just deletes the cookie (no server state to clean)
// For persistent: deletes cookie AND database row for this series
//                 Other series (other devices) remain active

// Force logout on ALL devices:
// Requires custom implementation:
public void logoutAllDevices(String username) {
    // Persistent strategy:
    ((PersistentTokenRepository) tokenRepository)
        .removeUserTokens(username);
    // Deletes ALL series for this user → all devices logged out
}
```

---

### 16.9 SecurityContext Implications — isRememberMe() vs isFullyAuthenticated()

```java
// After remember-me auto-login:
Authentication auth = SecurityContextHolder.getContext().getAuthentication();

auth instanceof RememberMeAuthenticationToken  // true
auth.isAuthenticated()                         // true
// isAuthenticated() returns true — remember-me IS authenticated

// BUT:
AuthenticationTrustResolver resolver = new AuthenticationTrustResolverImpl();
resolver.isRememberMe(auth)          // true
resolver.isFullyAuthenticated(auth)  // false

// Spring Security SpEL:
// isAuthenticated()       → true  (remember-me counts)
// isFullyAuthenticated()  → false (remember-me does NOT count)
// isRememberMe()          → true

// ExceptionTranslationFilter behavior:
// If remember-me user hits AccessDeniedException:
//     isRememberMe() = true → sendStartAuthentication()
//     → redirects to login page (401 path, not 403!)
//     → User must fully authenticate for the sensitive resource
```

---

## 2️⃣ Code Examples

---

### Example 1 — Hash-Based Remember-Me Configuration (6.x)

```java
@Configuration
@EnableWebSecurity
public class HashBasedRememberMeConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/public/**").permitAll()
                .requestMatchers("/sensitive/**").fullyAuthenticated()
                // sensitive operations require FULL auth — not remember-me!
                .anyRequest().authenticated()
            )
            .formLogin(form -> form
                .loginPage("/login")
                .permitAll()
            )
            .rememberMe(rm -> rm
                // Strategy: hash-based (default when no tokenRepository set)
                .userDetailsService(userDetailsService())
                // Key: must be stable across restarts!
                .key("${remember.me.key:changeme-use-secret}")
                // Cookie validity: 14 days
                .tokenValiditySeconds(14 * 24 * 60 * 60)
                // Parameter name in login form
                .rememberMeParameter("remember-me")
                // Cookie name
                .rememberMeCookieName("APP_REMEMBER_ME")
                // HTTPS only in production
                .useSecureCookie(true)
            )
            .logout(logout -> logout
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login?logout")
                .deleteCookies("JSESSIONID", "APP_REMEMBER_ME")
            );

        return http.build();
    }
}
```

**Login form:**
```html
<form th:action="@{/login}" method="post">
    <input type="text" name="username" placeholder="Username"/>
    <input type="password" name="password" placeholder="Password"/>

    <!-- Remember-me checkbox — parameter name must match config -->
    <label>
        <input type="checkbox" name="remember-me"/>
        Keep me signed in for 14 days
    </label>

    <button type="submit">Sign In</button>
</form>
```

---

### Example 2 — Persistent Token Remember-Me (Secure)

```java
@Configuration
@EnableWebSecurity
public class PersistentRememberMeConfig {

    @Autowired
    private DataSource dataSource;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/public/**").permitAll()
                .requestMatchers("/account/change-password")
                    .fullyAuthenticated()
                .anyRequest().authenticated()
            )
            .formLogin(Customizer.withDefaults())
            .rememberMe(rm -> rm
                // Strategy: persistent token (database-backed)
                .tokenRepository(persistentTokenRepository())
                .userDetailsService(userDetailsService())
                .key("${remember.me.key}")
                .tokenValiditySeconds(30 * 24 * 60 * 60)  // 30 days
                .rememberMeParameter("remember-me")
                .rememberMeCookieName("PERSISTENT_REMEMBER_ME")
                .useSecureCookie(true)
            )
            .logout(logout -> logout
                .addLogoutHandler(rememberMeLogoutHandler())
                .logoutSuccessUrl("/login?logout")
            );

        return http.build();
    }

    @Bean
    public PersistentTokenRepository persistentTokenRepository() {
        JdbcTokenRepositoryImpl tokenRepository =
            new JdbcTokenRepositoryImpl();
        tokenRepository.setDataSource(dataSource);
        // Create table on startup if not exists:
        // tokenRepository.setCreateTableOnStartup(true);
        // Better: manage with Flyway/Liquibase
        return tokenRepository;
    }

    @Bean
    public RememberMeAuthenticationFilter rememberMeFilter(
            AuthenticationManager authManager) {
        return new RememberMeAuthenticationFilter(
            authManager,
            rememberMeServices());
    }
}
```

```sql
-- persistent_logins table (JdbcTokenRepositoryImpl schema):
CREATE TABLE persistent_logins (
    username  VARCHAR(64)  NOT NULL,
    series    VARCHAR(64)  PRIMARY KEY,
    token     VARCHAR(64)  NOT NULL,
    last_used TIMESTAMP    NOT NULL
);

CREATE INDEX idx_persistent_logins_username
    ON persistent_logins(username);
-- Index on username for efficient "delete all for user" operation
```

---

### Example 3 — Custom RememberMeServices

```java
// Custom persistent remember-me that also tracks device info
@Component
public class DeviceAwareRememberMeServices
        extends PersistentTokenBasedRememberMeServices {

    private final DeviceRepository deviceRepository;

    public DeviceAwareRememberMeServices(
            String key,
            UserDetailsService userDetailsService,
            PersistentTokenRepository tokenRepository,
            DeviceRepository deviceRepository) {
        super(key, userDetailsService, tokenRepository);
        this.deviceRepository = deviceRepository;
    }

    @Override
    protected void onLoginSuccess(HttpServletRequest request,
            HttpServletResponse response,
            Authentication successfulAuthentication) {

        // Call parent to create/store the token
        super.onLoginSuccess(request, response, successfulAuthentication);

        // Additionally: record device information
        String username = successfulAuthentication.getName();
        String userAgent = request.getHeader("User-Agent");
        String ipAddress = request.getRemoteAddr();

        deviceRepository.recordDevice(username, userAgent, ipAddress,
            LocalDateTime.now());

        log.info("New remember-me device registered for user: {} "
            + "from IP: {}", username, ipAddress);
    }

    @Override
    protected UserDetails processAutoLoginCookie(String[] cookieTokens,
            HttpServletRequest request, HttpServletResponse response) {

        UserDetails user = super.processAutoLoginCookie(
            cookieTokens, request, response);

        // Log auto-login for audit
        log.info("Remember-me auto-login: user={}, ip={}",
            user.getUsername(), request.getRemoteAddr());

        return user;
    }
}
```

---

### Example 4 — Protecting Sensitive Operations from Remember-Me

```java
@Service
public class AccountService {

    // Only fully authenticated users can change password
    @PreAuthorize("isFullyAuthenticated()")
    public void changePassword(String oldPassword, String newPassword) {
        // If called by remember-me user:
        // → AccessDeniedException
        // → ExceptionTranslationFilter: isRememberMe() = true
        // → sendStartAuthentication() → redirect to login
        // → After re-login → can change password
    }

    // Remember-me users CAN view their profile
    @PreAuthorize("isAuthenticated()")
    public UserProfile getProfile() {
        // Both full auth AND remember-me users can access
    }

    // Explicit check in code:
    public void performSensitiveOperation(
            Authentication authentication) {
        AuthenticationTrustResolver resolver =
            new AuthenticationTrustResolverImpl();

        if (resolver.isRememberMe(authentication)) {
            // Redirect to re-authentication
            throw new InsufficientAuthenticationException(
                "Please re-authenticate to perform this operation");
        }
        // Proceed with sensitive operation
    }
}
```

```java
// URL-level protection:
http.authorizeHttpRequests(auth -> auth
    // Operations requiring full authentication (not remember-me):
    .requestMatchers("/account/password").fullyAuthenticated()
    .requestMatchers("/account/email").fullyAuthenticated()
    .requestMatchers("/account/delete").fullyAuthenticated()
    .requestMatchers("/payment/**").fullyAuthenticated()

    // Operations OK with remember-me:
    .requestMatchers("/dashboard/**").authenticated()
    .requestMatchers("/profile/view/**").authenticated()
    .requestMatchers("/orders/view/**").authenticated()

    .anyRequest().authenticated()
);
```

---

### Example 5 — Logout All Devices (Admin Feature)

```java
@RestController
@RequestMapping("/account")
public class AccountController {

    @Autowired
    private PersistentTokenRepository tokenRepository;

    @Autowired
    private HttpSession session;

    // User logs out from all devices
    @PostMapping("/logout-all-devices")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<Void> logoutAllDevices(
            Authentication authentication) {

        String username = authentication.getName();

        // Remove all remember-me tokens for this user
        tokenRepository.removeUserTokens(username);

        // Also invalidate current session
        session.invalidate();
        SecurityContextHolder.clearContext();

        log.info("User {} logged out from all devices", username);
        return ResponseEntity.ok().build();
    }

    // Admin force-logout a specific user
    @PostMapping("/admin/force-logout/{username}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> forceLogout(
            @PathVariable String username) {
        tokenRepository.removeUserTokens(username);
        // Note: active sessions on other servers not affected
        // Need distributed session management for full effect
        return ResponseEntity.ok().build();
    }
}
```

---

### Example 6 — Incorrect Remember-Me Configurations

```java
// ❌ WRONG 1 — Auto-generated key (default in some configurations)
http.rememberMe(rm -> rm
    .userDetailsService(userDetailsService)
    // Missing: .key("stable-key")
    // Spring Boot generates random UUID key on startup
    // Every restart → all remember-me cookies invalidated
    // Users complain: "I get logged out every time you deploy!"
);

// ✓ CORRECT: Always set explicit, stable key
http.rememberMe(rm -> rm
    .key(environment.getProperty("app.remember-me.key"))
    .userDetailsService(userDetailsService)
);
```

```java
// ❌ WRONG 2 — Allowing remember-me for admin accounts
// Admin accounts should ALWAYS require full authentication
// Remember-me on admin = low-security backdoor for privileged access
http.authorizeHttpRequests(auth -> auth
    .requestMatchers("/admin/**").hasRole("ADMIN")
    // No fullyAuthenticated() requirement!
    // Admin with remember-me cookie → full admin access without password!
);

// ✓ CORRECT:
http.authorizeHttpRequests(auth -> auth
    .requestMatchers("/admin/**")
        .access("hasRole('ADMIN') and isFullyAuthenticated()")
);
```

```java
// ❌ WRONG 3 — Hash-based remember-me without stable password
// If user resets password via "forgot password" → hash changes
// All existing remember-me cookies become INVALID (good for security)
// BUT: if you use BCrypt with random salt:
//     UserDetails.getPassword() returns stored hash
//     Hash is stable → password-based invalidation works correctly
//
// PROBLEM: If you store plain-text password or use NoOpPasswordEncoder:
//     userDetails.getPassword() = "plaintext"
//     signature = md5("alice:expiry:plaintext:key")
//     Anyone who knows the algorithm can forge cookies!

// ✓ CORRECT: Always use BCrypt (or other strong encoder)
// + Never use NoOpPasswordEncoder in production
// + Consider persistent tokens instead (password not in signature)
```

```java
// ❌ WRONG 4 — Not deleting cookie on logout
http.logout(logout -> logout
    .logoutUrl("/logout")
    .logoutSuccessUrl("/login")
    // Missing: .deleteCookies("remember-me")
    // Cookie remains in browser after logout
    // User logs out → visits login page → remember-me auto-logs them back in!
);

// ✓ CORRECT:
http.logout(logout -> logout
    .logoutUrl("/logout")
    .logoutSuccessUrl("/login?logout")
    .deleteCookies("JSESSIONID", "REMEMBER_ME")
    .invalidateHttpSession(true)
    .clearAuthentication(true)
);
```

```java
// ❌ WRONG 5 — No createTableOnStartup with new database
@Bean
public PersistentTokenRepository tokenRepository() {
    JdbcTokenRepositoryImpl repo = new JdbcTokenRepositoryImpl();
    repo.setDataSource(dataSource);
    // Missing: repo.setCreateTableOnStartup(true);
    // OR: missing Flyway/Liquibase migration
    // Result: persistent_logins table doesn't exist
    // → SQLException on first remember-me login
}
// ✓ CORRECT: Use schema management
// Option A (dev):
repo.setCreateTableOnStartup(true);
// Option B (production):
// Manage with Flyway/Liquibase migration
```

---

## 3️⃣ Exam-Style Questions

---

**Q1 (MCQ):** `RememberMeAuthenticationFilter` activates only when which condition is true?

A. The user has a valid `JSESSIONID` cookie
B. The `SecurityContextHolder` has no existing `Authentication`
C. The user has clicked "Remember Me" checkbox
D. The session has expired

**Answer: B**
`RememberMeAuthenticationFilter` checks if `SecurityContextHolder.getContext().getAuthentication() == null`. If any prior filter (form login, Basic auth) has already set authentication, remember-me is completely skipped. This is a "last chance" authentication — only activates when no other mechanism succeeded.

---

**Q2 (MCQ):** In persistent token remember-me, what happens when an already-used (rotated) token is presented?

A. The old token is reactivated and used
B. A new token is generated and the old one ignored
C. All tokens for the user are deleted and a `CookieTheftException` is thrown
D. The request is redirected to login

**Answer: C**
Token reuse detection: if `stored.getToken() != presented.getToken()` for the same series, it means the token was already rotated — someone else used it first. Spring Security's `PersistentTokenBasedRememberMeServices` calls `tokenRepository.removeUserTokens(username)` (deletes ALL tokens for the user) and throws `CookieTheftException`. This is the **theft detection mechanism**.

---

**Q3 (Select All That Apply):** Which are true about hash-based remember-me?

A. Changing the user's password invalidates all existing remember-me cookies
B. A stolen cookie can be detected and invalidated
C. No server-side storage is required
D. The cookie contains an MD5 signature of username, expiry, password, and key
E. Changing the configured `key` invalidates all existing cookies

**Answer: A, C, D, E**
B is false — hash-based remember-me has NO theft detection. Once a cookie is stolen, there is no way to know it was stolen until the legitimate user explicitly logs out or the cookie expires. This is the primary disadvantage compared to persistent tokens.

---

**Q4 (Code Prediction):**

```java
http.authorizeHttpRequests(auth -> auth
    .requestMatchers("/checkout").fullyAuthenticated()
    .anyRequest().authenticated()
);
```

A remember-me authenticated user navigates to `/checkout`. Trace the complete flow.

**Answer:**
```
1. SecurityContextHolderFilter loads RememberMeAuthenticationToken from session
2. AuthorizationFilter evaluates: .fullyAuthenticated()
   → checks: !isAnonymous() && !isRememberMe()
   → isRememberMe() = true → NOT fully authenticated
   → throws AccessDeniedException
3. ExceptionTranslationFilter catches AccessDeniedException
4. authenticationTrustResolver.isRememberMe(auth) = true
5. sendStartAuthentication()
   → requestCache.saveRequest() → saves /checkout to session
   → authenticationEntryPoint.commence()
   → LoginUrlAuthenticationEntryPoint: 302 redirect to /login

User logs in interactively:
6. UsernamePasswordAuthenticationFilter authenticates → UsernamePasswordAuthenticationToken
7. SuccessHandler: requestCache → saved /checkout
8. Redirect to /checkout

9. AuthorizationFilter: .fullyAuthenticated()
   → auth is UsernamePasswordAuthenticationToken → not remember-me
   → isFullyAuthenticated() = true → GRANTED
10. Checkout page rendered
```
Final result: User redirected to login, then to checkout after full re-authentication.

---

**Q5 (Strategy Comparison):**

For an e-commerce application requiring 30-day persistent login, which strategy would you choose and why?

**Answer: Persistent Token Strategy (`PersistentTokenBasedRememberMeServices`)**

Reasoning:
1. **Theft detection:** 30-day cookies are valuable targets. Persistent tokens detect theft via rotation — if the attacker uses the cookie, the legitimate user's next access detects the mismatch and forces re-login for everyone.
2. **Per-device revocation:** Users can log out of specific devices (by series) or all devices (all series).
3. **Password not in signature:** Hash-based includes password hash in signature — any exposure of the signature leaks password hash.
4. **Audit capability:** Database records show exactly when and how many times each token was used.

Trade-off: Requires database storage and a DB call per remember-me authentication (mitigated by the fact that remember-me tokens are longer-lived — less frequent authentication).

---

**Q6 (Filter Order):**

A request arrives with BOTH an `Authorization: Basic alice:password` header AND a remember-me cookie. Which filter handles authentication and why?

**Answer: `BasicAuthenticationFilter`** handles it.

`BasicAuthenticationFilter` (order ~900) runs **before** `RememberMeAuthenticationFilter` (order ~1050). `BasicAuthenticationFilter` extracts credentials from the `Authorization` header, authenticates alice, and sets `UsernamePasswordAuthenticationToken` in `SecurityContextHolder`.

When `RememberMeAuthenticationFilter` runs, it checks:
```java
if (SecurityContextHolder.getContext().getAuthentication() == null) {
    // Try remember-me...
}
```
Authentication is NOT null (Basic auth already set it) → remember-me is completely skipped.

Result: User authenticated via Basic auth, not remember-me. The remember-me cookie is ignored.

---

**Q7 (Security Analysis):**

```java
http.rememberMe(rm -> rm
    .alwaysRemember(true)
    .tokenValiditySeconds(365 * 24 * 60 * 60)  // 1 year
    .key("remember-me-key")
);
```

Identify all security concerns with this configuration.

**Answer:**

1. **`alwaysRemember(true)`** — No user opt-in. Remember-me cookie set on every login, even on shared/public computers. User may not want persistent login.

2. **365-day validity** — Extremely long-lived cookie. If stolen, attacker has access for up to 1 year. Best practice: 30-60 days maximum.

3. **Using hash-based (no `tokenRepository`)** — No theft detection for a 1-year cookie. A stolen cookie is valid for up to a year with no way to detect or revoke it.

4. **No `useSecureCookie(true)`** — Cookie may be sent over HTTP, enabling network interception.

5. **Static key `"remember-me-key"`** — Short, predictable key. Should be a long, random, externally-configured secret.

6. **No `fullyAuthenticated()` protection** — Sensitive operations accessible to remember-me users.

**Fixed version:**
```java
http.rememberMe(rm -> rm
    .alwaysRemember(false)                          // opt-in only
    .tokenValiditySeconds(30 * 24 * 60 * 60)        // 30 days max
    .tokenRepository(persistentTokenRepository())   // theft detection
    .useSecureCookie(true)                          // HTTPS only
    .key(env.getProperty("app.remember-me.key"))    // external config
);
// + .fullyAuthenticated() on sensitive endpoints
```

---

**Q8 (Authentication Type Distinction):**

After remember-me auto-login, which `Authentication` type is in `SecurityContextHolder`, and what happens when `authentication.isAuthenticated()` is called?

**Answer:**

- **Type:** `RememberMeAuthenticationToken`
- **`isAuthenticated()`:** Returns `true` — remember-me IS authenticated

BUT:
- `authenticationTrustResolver.isRememberMe(auth)` → `true`
- `authenticationTrustResolver.isFullyAuthenticated(auth)` → `false`
- SpEL `isAuthenticated()` → `true` (remember-me counts)
- SpEL `isFullyAuthenticated()` → `false` (remember-me does NOT count)

**The critical implication:** Simply checking `auth.isAuthenticated()` in Java code incorrectly treats remember-me as "fully authenticated." Always use `AuthenticationTrustResolver` for proper distinction, or use Spring Security's SpEL expressions which handle this correctly.

---

## 4️⃣ Trick Analysis

---

**Trick 1 — Auto-Generated Key = Logout on Every Restart**

```
Spring Security (without Spring Boot auto-config):
     No key configured → RememberMeConfigurer generates UUID at startup
     Every restart = new UUID = new key
     All existing cookies invalid = all users logged out

Spring Boot auto-configuration:
     RememberMeProperties: spring.security.remember-me.key
     If not set → random key generated on startup

PRODUCTION RULE:
     ALWAYS configure an explicit key from external config (Vault/env vars)
     Key should be: long (32+ chars), random, secret, stable

http.rememberMe(rm -> rm
    .key(environment.getRequiredProperty("REMEMBER_ME_KEY")));

EXAM TRAP: "Why are users logged out after every deployment?"
Answer: Auto-generated remember-me key changes on restart
```

---

**Trick 2 — `fullyAuthenticated()` vs `authenticated()` for Remember-Me**

```
.authenticated()
     → Passes: UsernamePasswordAuthenticationToken (full auth)
     → Passes: RememberMeAuthenticationToken (remember-me)
     → Fails:  AnonymousAuthenticationToken

.fullyAuthenticated()
     → Passes: UsernamePasswordAuthenticationToken (full auth)
     → FAILS:  RememberMeAuthenticationToken (remember-me!)
     → Fails:  AnonymousAuthenticationToken

Use fullyAuthenticated() for:
     Password changes, payment processing, sensitive data access,
     security settings, account deletion

Use authenticated() for:
     Regular content viewing, profile display, non-sensitive operations

EXAM TRAP: "A remember-me user accesses a .authenticated() URL"
Answer: ACCESS GRANTED — remember-me passes authenticated()

"A remember-me user accesses a .fullyAuthenticated() URL"
Answer: Redirected to login (401 path via ExceptionTranslationFilter)
```

---

**Trick 3 — Remember-Me Cookie vs JSESSIONID — Two Different Cookies**

```
After remember-me login:
     Browser has TWO cookies:
          JSESSIONID=xyz  (session cookie — expires on browser close)
          remember-me=Base64...  (persistent cookie — survives browser close)

After browser restart:
     JSESSIONID: GONE (session cookie deleted on browser close)
     remember-me: STILL PRESENT (persistent — has expiry date)

On new request:
     No JSESSIONID → SecurityContextHolderFilter: empty context
     RememberMeAuthenticationFilter: cookie present → auto-login
     New session created → new JSESSIONID assigned
     User authenticated via remember-me

TRAP: "Session is gone after browser restart" ← This is by design!
     Remember-me re-creates authentication WITHOUT session
     Then session is created fresh for the new browser session
```

---

**Trick 4 — `loginFail()` Deletes Cookie Even Without Valid Session**

```java
// In AbstractRememberMeServices.loginFail():
public final void loginFail(HttpServletRequest request,
        HttpServletResponse response) {
    cancelCookie(request, response);
    // Sends Set-Cookie: remember-me=; Max-Age=0; expires=Thu, 01 Jan 1970...
    // Effectively deletes the cookie
    onLoginFail(request, response);
}

// When is loginFail() called?
// 1. RememberMeAuthenticationFilter: AuthenticationException during validation
// 2. UsernamePasswordAuthenticationFilter.unsuccessfulAuthentication():
//    rememberMeServices.loginFail() always called on form login failure
//    Even if user didn't use remember-me!
//    Cleans up any existing remember-me cookie (security measure)

// Result: Failed form login ALWAYS deletes remember-me cookie
// Design intent: If credentials are wrong, don't trust the remember-me either
```

---

**Trick 5 — Persistent Token Lookup is by `series`, Not `token`**

```
Database query on each remember-me request:
     SELECT * FROM persistent_logins WHERE series = ?
     (lookup by series, NOT by token)

Why by series?
     series identifies the auth chain (browser/device)
     token is the current value within that series (changes each use)

     Looking up by token would require full table scan (no efficient index)
     Looking up by series uses primary key → efficient

After lookup:
     Compare: returned token column == cookie token field
     Match: proceed
     Mismatch: theft detected (wrong token for known series)

INDEX recommendation:
     PRIMARY KEY on series (default)
     INDEX on username (for removeUserTokens operation)
     No need to index token column
```

---

**Trick 6 — `alwaysRemember(true)` Ignores the Checkbox**

```java
http.rememberMe(rm -> rm.alwaysRemember(true));

// HTML form:
<input type="checkbox" name="remember-me"/>

// User does NOT check the checkbox
// → remember-me cookie is STILL created (alwaysRemember overrides)

// User DOES check the checkbox
// → same behavior as not checking (alwaysRemember makes checkbox irrelevant)

// Use case for alwaysRemember:
//   Mobile apps where staying logged in is the expected default
//   Internal tools where users always want persistent sessions
//   When your UX decision is "always remember" without user choice

// Security risk:
//   On shared computers, user may not realize they're creating persistent cookies
//   Another user on the same computer could access the account
```

---

**Trick 7 — Remember-Me Token Is Validated by `RememberMeAuthenticationProvider` via Key Hash**

```java
// RememberMeAuthenticationToken carries a key hash:
new RememberMeAuthenticationToken(key, userDetails, authorities)
// Internally: this.keyHash = key.hashCode()

// RememberMeAuthenticationProvider validates:
if (this.key.hashCode() != auth.getKeyHash()) {
    throw new BadCredentialsException("...");
}

// Why this matters:
// If you have TWO applications with different keys:
//   App1 key = "key-A" → creates RememberMeAuthenticationToken with hash(key-A)
//   App2 key = "key-B" → RememberMeAuthenticationProvider has hash(key-B)
//   Token from App1 presented to App2 → hash mismatch → rejected

// Security benefit: Remember-me tokens are app-specific
// They can't be transferred between applications with different keys

// SAME key → tokens accepted by any instance (intended for clustering)
// DIFFERENT keys → tokens rejected across apps (isolation)
```

---

## 5️⃣ Summary Sheet

---

### Remember-Me Authentication Flow Diagram

```
Browser Request (no JSESSIONID, has remember-me cookie)
     │
     ▼
SecurityContextHolderFilter
     └── No session → empty SecurityContext

     ▼
[UsernamePasswordAuthenticationFilter] → no POST /login → pass
[BasicAuthenticationFilter]            → no Authorization header → pass

     ▼
RememberMeAuthenticationFilter
     ├── SecurityContext has auth? YES → skip entirely
     │
     └── NO auth yet:
           rememberMeServices.autoLogin(request, response)
               │
               ├── Hash-based: decode cookie → validate MD5 → load user
               └── Persistent: lookup series in DB → validate token →
                               rotate token → update DB → load user
               │
               ├── SUCCESS: RememberMeAuthenticationToken
               │       AuthenticationManager validates key hash
               │       SecurityContextHolder.setAuthentication()
               │       Context saved to new session
               │
               └── FAILURE: loginFail() → delete cookie → continue

     ▼
[AnonymousAuthenticationFilter] → skipped (auth already set)
[AuthorizationFilter]           → checks rules
     ├── .authenticated()     → RememberMeAuthToken PASSES ✓
     └── .fullyAuthenticated() → RememberMeAuthToken FAILS ✗ → redirect to login
```

---

### Strategy Comparison Table

| Feature | Hash-Based | Persistent Token |
|---------|-----------|-----------------|
| Server storage | ❌ None | ✅ Database |
| Theft detection | ❌ None | ✅ Token rotation |
| Per-device revocation | ❌ Impossible | ✅ Delete series |
| All-device logout | ✅ Password change | ✅ Delete all series |
| Restart resilience | ✅ (if stable key) | ✅ (DB survives) |
| Security level | Medium | High |
| Complexity | Low | Medium |
| Recommendation | Dev/low-security | Production |

---

### Remember-Me vs Session Lifecycle

```
With remember-me:
     Login (check box) → JSESSIONID (session) + remember-me (persistent)
     Browser close    → JSESSIONID GONE, remember-me SURVIVES
     Browser reopen   → Remember-me auto-login → new JSESSIONID created
     Explicit logout  → Both cookies deleted + DB token removed (persistent)
     Cookie expires   → User must manually re-login

Without remember-me:
     Login            → JSESSIONID only
     Browser close    → JSESSIONID GONE
     Browser reopen   → No cookie → login required
```

---

### Authentication Trust Levels

| Authentication | `isAuthenticated()` | `isRememberMe()` | `isFullyAuthenticated()` |
|---------------|--------------------|-----------------|-----------------------|
| `UsernamePasswordAuthenticationToken` | ✅ true | ❌ false | ✅ true |
| `RememberMeAuthenticationToken` | ✅ true | ✅ true | ❌ false |
| `AnonymousAuthenticationToken` | ⚠️ true* | ❌ false | ❌ false |

*`isAuthenticated()` raw Java returns true for anonymous; SpEL `isAuthenticated()` = `!isAnonymous()` = false

---

### Common Interview One-Liners

- **`RememberMeAuthenticationFilter`** only activates when `SecurityContextHolder` has NO existing authentication
- **Persistent token rotation** detects theft — old token reuse = `CookieTheftException` + delete all user tokens
- **Hash-based remember-me** is stateless but has NO theft detection — stolen cookie valid until expiry
- **`isFullyAuthenticated()`** = false for remember-me — use `.fullyAuthenticated()` for sensitive operations
- **`ExceptionTranslationFilter`** treats remember-me `AccessDeniedException` as unauthenticated → redirect to login
- **Auto-generated `key`** = new key every restart = all remember-me cookies invalidated — always set explicit key
- **`alwaysRemember(true)`** creates cookie regardless of checkbox — ignores user preference
- **Failed form login** calls `rememberMeServices.loginFail()` — always deletes existing remember-me cookie
- **`persistent_logins.series`** = primary key for efficient lookup; **`token`** = single-use value that rotates
- **Remember-me cookie** must have `Secure` + `HttpOnly` flags in production

---
