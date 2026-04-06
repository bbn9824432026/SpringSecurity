# TOPIC 2 — Form-Based Authentication

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

---

## 1️⃣ Conceptual Explanation

---

### 2.1 UsernamePasswordAuthenticationFilter — Deep Internals

`UsernamePasswordAuthenticationFilter` extends `AbstractAuthenticationProcessingFilter`, which is the **base class for all authentication filters** that process a specific URL. Understanding the base class is as important as understanding the subclass.

---

#### AbstractAuthenticationProcessingFilter — The Template

```
AbstractAuthenticationProcessingFilter
     │
     ├──► requiresAuthentication(request, response)
     │         └──► Does this request match the loginProcessingUrl?
     │                   YES → proceed
     │                   NO  → chain.doFilter() (pass through, do nothing)
     │
     ├──► attemptAuthentication(request, response)   ← ABSTRACT — subclass implements
     │         └──► UsernamePasswordAuthenticationFilter overrides this
     │
     ├──► On SUCCESS:
     │         └──► sessionStrategy.onAuthentication()
     │         └──► successfulAuthentication()
     │                   └──► SecurityContextHolder.getContext().setAuthentication()
     │                   └──► securityContextRepository.saveContext()  (6.x explicit)
     │                   └──► rememberMeServices.loginSuccess()
     │                   └──► ApplicationEventPublisher → InteractiveAuthenticationSuccessEvent
     │                   └──► successHandler.onAuthenticationSuccess()
     │
     └──► On FAILURE:
               └──► SecurityContextHolder.clearContext()
               └──► rememberMeServices.loginFail()
               └──► failureHandler.onAuthenticationFailure()
```

**Critical insight:** The filter only activates when `requiresAuthentication()` returns true. For all other URLs, it calls `chain.doFilter()` and does nothing — it is transparent. This is why the filter doesn't interfere with normal page requests.

---

#### UsernamePasswordAuthenticationFilter — Core Logic

```java
// Internal flow of attemptAuthentication():

public Authentication attemptAuthentication(
        HttpServletRequest request,
        HttpServletResponse response) throws AuthenticationException {

    // 1. Check HTTP method — POST only by default
    if (this.postOnly && !request.getMethod().equals("POST")) {
        throw new AuthenticationServiceException(
            "Authentication method not supported: " + request.getMethod());
    }

    // 2. Extract credentials from request parameters
    String username = obtainUsername(request);  // request.getParameter("username")
    String password = obtainPassword(request);  // request.getParameter("password")

    username = (username != null) ? username.trim() : "";
    password = (password != null) ? password : "";

    // 3. Build unauthenticated token
    UsernamePasswordAuthenticationToken authRequest =
        UsernamePasswordAuthenticationToken.unauthenticated(username, password);

    // 4. Copy request details (IP address, session ID)
    setDetails(request, authRequest);
    // authRequest.details = new WebAuthenticationDetails(request)
    //   ├── remoteAddress = request.getRemoteAddr()
    //   └── sessionId = request.getSession(false)?.getId()

    // 5. Delegate to AuthenticationManager
    return this.getAuthenticationManager().authenticate(authRequest);
}
```

**What `setDetails()` captures:**
`WebAuthenticationDetails` stores the client IP and session ID at the time of authentication. This is used for:
- Audit logging
- IP-based session binding
- Security event enrichment

---

#### The Full Internal Call Chain — Every Step

```
POST /login (username=alice&password=secret)
     │
     ▼
UsernamePasswordAuthenticationFilter.doFilter()
     │
     ├── requiresAuthentication("/login", POST) → true
     │
     ├── attemptAuthentication()
     │       │
     │       ├── Extract: username="alice", password="secret"
     │       ├── Create: UPAuthToken(alice, secret, authenticated=false)
     │       ├── setDetails: IP=192.168.1.1, sessionId=null (no session yet)
     │       │
     │       └── authManager.authenticate(token)
     │               │
     │               └── ProviderManager
     │                       │
     │                       └── DaoAuthenticationProvider.authenticate()
     │                               │
     │                               ├── retrieveUser("alice")
     │                               │       └── userDetailsService.loadUserByUsername("alice")
     │                               │               └── Returns: UserDetails{
     │                               │                     username="alice",
     │                               │                     password="{bcrypt}$2a$...",
     │                               │                     authorities=[ROLE_USER],
     │                               │                     enabled=true, ...}
     │                               │
     │                               ├── preAuthenticationChecks(userDetails)
     │                               │       ├── isEnabled()           → true ✓
     │                               │       ├── isAccountNonExpired() → true ✓
     │                               │       └── isAccountNonLocked()  → true ✓
     │                               │
     │                               ├── additionalAuthenticationChecks()
     │                               │       └── passwordEncoder.matches("secret", "{bcrypt}...")
     │                               │               → true ✓
     │                               │
     │                               ├── postAuthenticationChecks(userDetails)
     │                               │       └── isCredentialsNonExpired() → true ✓
     │                               │
     │                               └── Return: UPAuthToken(userDetails, null, [ROLE_USER])
     │                                           (credentials=null, authenticated=true)
     │
     ├── SESSION STRATEGY: SessionFixationProtectionStrategy
     │       └── Creates NEW session, migrates attributes from old session
     │       └── Invalidates old session
     │
     ├── successfulAuthentication()
     │       ├── SecurityContextHolder.getContext().setAuthentication(token)
     │       ├── SecurityContextRepository.saveContext(context, request, response)
     │       │       └── HttpSessionSecurityContextRepository
     │       │               └── session.setAttribute(
     │       │                     "SPRING_SECURITY_CONTEXT", securityContext)
     │       ├── RememberMeServices.loginSuccess() (if remember-me configured)
     │       └── successHandler.onAuthenticationSuccess()
     │               └── Default: SavedRequestAwareAuthenticationSuccessHandler
     │                       └── Was there a saved request? (user tried /dashboard first)
     │                               YES → redirect to /dashboard (302)
     │                               NO  → redirect to defaultSuccessUrl (302)
     │
     └── Response: HTTP 302 Location: /dashboard
```

---

### 2.2 AuthenticationSuccessHandler — Internals & Strategies

The `AuthenticationSuccessHandler` interface:

```java
public interface AuthenticationSuccessHandler {
    void onAuthenticationSuccess(
        HttpServletRequest request,
        HttpServletResponse response,
        Authentication authentication
    ) throws IOException, ServletException;
}
```

**Default implementation: `SavedRequestAwareAuthenticationSuccessHandler`**

This is the most important built-in handler. Its logic:

```
onAuthenticationSuccess()
     │
     ├── Check RequestCache for a saved request
     │       └── DefaultSavedRequest: was there a request BEFORE the login redirect?
     │                 Example: user tried to access /orders → redirected to /login
     │                           → now stores /orders in session
     │
     ├── If saved request EXISTS:
     │       └── Redirect to savedRequest.getRedirectUrl() (/orders)
     │               (honors original HTTP method, parameters, headers)
     │
     └── If NO saved request:
               └── alwaysUseDefaultTargetUrl?
                       YES → redirect to defaultTargetUrl
                       NO  → targetUrlParameter set in request?
                                   YES → redirect to that URL
                                   NO  → redirect to defaultTargetUrl
```

**`RequestCache` and `RequestCacheAwareFilter`:**

When an unauthenticated user accesses a protected resource:
1. `ExceptionTranslationFilter` catches `AccessDeniedException`
2. Saves the original request into `RequestCache` (default: `HttpSessionRequestCache`)
3. Redirects user to login page
4. After login, `SavedRequestAwareAuthenticationSuccessHandler` retrieves the saved request and redirects there

This is how the "redirect back after login" behavior works seamlessly.

---

### 2.3 AuthenticationFailureHandler — Internals & Strategies

**Default implementation: `SimpleUrlAuthenticationFailureHandler`**

```
onAuthenticationFailure()
     │
     ├── SecurityContextHolder.clearContext()    ← important security step
     │
     ├── Map exception type to behavior:
     │       BadCredentialsException     → /login?error (default)
     │       LockedException             → /login?error
     │       DisabledException           → /login?error
     │       AccountExpiredException     → /login?error
     │       (all mapped to same URL by default)
     │
     └── forwardToDestination?
               YES → forward (request attribute preserved — expose exception to JSP)
               NO  → redirect (URL visible, no request attributes)
```

**Exception hierarchy — critical for exam:**

```
AuthenticationException (abstract)
     ├── BadCredentialsException          (wrong password)
     ├── UsernameNotFoundException        (masked as BadCredentials by default)
     ├── DisabledException                (isEnabled() = false)
     ├── LockedException                  (isAccountNonLocked() = false)
     ├── AccountExpiredException          (isAccountNonExpired() = false)
     ├── CredentialsExpiredException      (isCredentialsNonExpired() = false)
     ├── InsufficientAuthenticationException
     └── AuthenticationServiceException   (infrastructure failure — DB down)
```

---

### 2.4 RememberMeServices — Persistent Token Strategy

Remember-me authentication creates a **persistent authentication token** stored in a cookie, allowing users to be authenticated across browser sessions without re-entering credentials.

**Two strategies:**

**Strategy 1 — Hash-Based (Simple)**
```
Cookie value = Base64(username + ":" + expirationTime + ":" +
               MD5(username + ":" + expirationTime + ":" + password + ":" + key))
```
- Stateless — no server-side storage
- **Security weakness:** If the cookie is stolen, it's valid until expiry. Password change does NOT invalidate it (the hash still matches old password if old password is used to verify)
- Actually, password change DOES invalidate it since the hash includes password

**Strategy 2 — Persistent Token (Secure)**
```
Cookie value = series + ":" + token

Server stores: (series, tokenHash, username, lastUsed) in database
```

- `series` is fixed per device — identifies the browser/device
- `token` changes on **every login** — single-use
- If stolen token is presented after it was already consumed → **theft detected** → all sessions for user invalidated
- Stored via `PersistentTokenRepository` (implement with JdbcTokenRepositoryImpl)

---

### 2.5 Session Creation on Authentication

When authentication succeeds, Spring Security creates a new session. This is controlled by `SessionAuthenticationStrategy`:

**Default strategy chain:**
```
CompositeSessionAuthenticationStrategy
     ├── ChangeSessionIdAuthenticationStrategy   ← default session fixation protection
     │       └── request.changeSessionId()
     │               (changes session ID but preserves all attributes)
     │
     ├── CsrfAuthenticationStrategy              ← rotate CSRF token on auth
     │       └── Generates new CSRF token, binds to new session
     │
     └── RegisterSessionAuthenticationStrategy   ← for concurrent session control
             └── sessionRegistry.registerNewSession(sessionId, principal)
```

**Why change session ID on login?**
Session Fixation Attack: attacker pre-sets a known session ID in victim's browser → victim logs in → session ID is now authenticated. By changing the session ID on successful login, this attack is prevented.

---

## 2️⃣ Code Examples

---

### Example 1 — Custom Login Page with Form Login (6.x)

```java
@Configuration
@EnableWebSecurity
public class FormLoginConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/login", "/login-error", "/css/**").permitAll()
                .anyRequest().authenticated()
            )
            .formLogin(form -> form
                // Custom login page URL (GET — renders the form)
                .loginPage("/login")

                // URL that processes the form submission (POST)
                // UsernamePasswordAuthenticationFilter intercepts this URL
                .loginProcessingUrl("/login")

                // Redirect here on success (if no saved request)
                .defaultSuccessUrl("/dashboard", true)
                // true = always redirect to defaultSuccessUrl
                // false = redirect to saved request if available (default behavior)

                // Redirect here on failure
                .failureUrl("/login-error")

                // OR use a handler for more control:
                // .failureHandler(customFailureHandler())

                // Custom parameter names (default: "username", "password")
                .usernameParameter("email")
                .passwordParameter("passwd")

                .permitAll()
            );

        return http.build();
    }
}
```

**Login controller:**
```java
@Controller
public class LoginController {

    @GetMapping("/login")
    public String loginPage() {
        return "login";  // renders login.html template
    }

    @GetMapping("/login-error")
    public String loginError(Model model) {
        model.addAttribute("loginError", true);
        return "login";
    }
}
```

**Thymeleaf form — correct CSRF usage:**
```html
<form th:action="@{/login}" method="post">
    <!-- Thymeleaf auto-injects CSRF token -->
    <input type="text"     name="email"  />
    <input type="password" name="passwd" />
    <button type="submit">Login</button>
</form>
```

---

### Example 2 — Custom AuthenticationSuccessHandler

```java
@Component
public class RoleBasedSuccessHandler implements AuthenticationSuccessHandler {

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication) throws IOException {

        // Inspect granted authorities to decide redirect
        Collection<? extends GrantedAuthority> authorities =
            authentication.getAuthorities();

        String redirectUrl = "/dashboard";  // default

        for (GrantedAuthority authority : authorities) {
            switch (authority.getAuthority()) {
                case "ROLE_ADMIN"   -> redirectUrl = "/admin/home";
                case "ROLE_MANAGER" -> redirectUrl = "/manager/home";
                case "ROLE_USER"    -> redirectUrl = "/user/home";
            }
        }

        // Clear authentication attributes from session
        // (prevents re-use of auth details)
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.removeAttribute(
                WebAttributes.AUTHENTICATION_EXCEPTION);
        }

        response.sendRedirect(redirectUrl);
    }
}
```

```java
// Register in config:
.formLogin(form -> form
    .successHandler(roleBasedSuccessHandler)
    .failureHandler(customFailureHandler)
)
```

---

### Example 3 — Custom AuthenticationFailureHandler

```java
@Component
public class DetailedFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    public DetailedFailureHandler() {
        super("/login?error");
    }

    @Override
    public void onAuthenticationFailure(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException exception) throws IOException, ServletException {

        // Log the specific exception type for audit
        String username = request.getParameter("username");

        if (exception instanceof BadCredentialsException) {
            // Could increment lockout counter here
            log.warn("Bad credentials for user: {}", username);
        } else if (exception instanceof LockedException) {
            log.warn("Locked account access attempt: {}", username);
            getRedirectStrategy().sendRedirect(request, response, "/login?locked");
            return;
        } else if (exception instanceof DisabledException) {
            getRedirectStrategy().sendRedirect(request, response, "/login?disabled");
            return;
        }

        // For other cases, use parent behavior
        super.onAuthenticationFailure(request, response, exception);
    }
}
```

---

### Example 4 — Persistent Remember-Me Configuration

```java
@Configuration
@EnableWebSecurity
public class RememberMeConfig {

    @Autowired
    private DataSource dataSource;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .anyRequest().authenticated()
            )
            .formLogin(Customizer.withDefaults())
            .rememberMe(remember -> remember
                // Persistent token strategy
                .tokenRepository(persistentTokenRepository())
                // Cookie validity (14 days)
                .tokenValiditySeconds(14 * 24 * 60 * 60)
                // Parameter name in login form
                .rememberMeParameter("remember-me")
                // Cookie name
                .rememberMeCookieName("REMEMBER_ME")
                // Key for HMAC (hash-based strategy) — not used with persistent
                .key("uniqueAndSecretKey-change-in-production")
                // Always create remember-me cookie (even without checkbox)
                // .alwaysRemember(true)
            );

        return http.build();
    }

    @Bean
    public PersistentTokenRepository persistentTokenRepository() {
        JdbcTokenRepositoryImpl tokenRepository = new JdbcTokenRepositoryImpl();
        tokenRepository.setDataSource(dataSource);
        // Creates table on startup if missing:
        // tokenRepository.setCreateTableOnStartup(true);
        return tokenRepository;
    }
}
```

**Required database table for persistent remember-me:**
```sql
CREATE TABLE persistent_logins (
    username  VARCHAR(64)  NOT NULL,
    series    VARCHAR(64)  PRIMARY KEY,
    token     VARCHAR(64)  NOT NULL,
    last_used TIMESTAMP    NOT NULL
);
```

---

### Example 5 — Custom UsernamePasswordAuthenticationFilter

```java
// Custom filter that reads credentials from JSON body (REST login endpoint)
public class JsonLoginFilter extends UsernamePasswordAuthenticationFilter {

    private final ObjectMapper objectMapper = new ObjectMapper();

    public JsonLoginFilter(AuthenticationManager authenticationManager) {
        super(authenticationManager);
        // Override the default login processing URL
        setRequiresAuthenticationRequestMatcher(
            new AntPathRequestMatcher("/api/auth/login", "POST")
        );
    }

    @Override
    public Authentication attemptAuthentication(
            HttpServletRequest request,
            HttpServletResponse response) throws AuthenticationException {

        try {
            // Read JSON body instead of form parameters
            LoginRequest loginRequest = objectMapper.readValue(
                request.getInputStream(),
                LoginRequest.class
            );

            UsernamePasswordAuthenticationToken token =
                UsernamePasswordAuthenticationToken.unauthenticated(
                    loginRequest.username(),
                    loginRequest.password()
                );

            setDetails(request, token);
            return getAuthenticationManager().authenticate(token);

        } catch (IOException e) {
            throw new AuthenticationServiceException(
                "Failed to parse login request", e);
        }
    }
}

// LoginRequest record:
record LoginRequest(String username, String password) {}
```

**Register the custom filter:**
```java
@Bean
public SecurityFilterChain filterChain(
        HttpSecurity http,
        AuthenticationManager authManager) throws Exception {

    JsonLoginFilter jsonLoginFilter = new JsonLoginFilter(authManager);
    jsonLoginFilter.setAuthenticationSuccessHandler(jwtSuccessHandler());
    jsonLoginFilter.setAuthenticationFailureHandler(jsonFailureHandler());

    http
        .addFilterAt(jsonLoginFilter,
            UsernamePasswordAuthenticationFilter.class)  // replaces default
        .csrf(AbstractHttpConfigurer::disable)
        .sessionManagement(s -> s
            .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

    return http.build();
}

@Bean
public AuthenticationManager authManager(
        UserDetailsService uds,
        PasswordEncoder encoder) {
    DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
    provider.setUserDetailsService(uds);
    provider.setPasswordEncoder(encoder);
    return new ProviderManager(provider);
}
```

---

### Example 6 — Incorrect Configuration & Why It Fails

```java
// ❌ WRONG — loginPage and loginProcessingUrl are the same
http.formLogin(form -> form
    .loginPage("/login")
    .loginProcessingUrl("/login")  // same as loginPage — this is actually OK
    // BUT if you forget to permitAll():
    .anyRequest().authenticated()
    // ← Without .permitAll() on form login,
    //   GET /login itself requires authentication
    //   → infinite redirect loop!
);

// ✓ CORRECT
http.formLogin(form -> form
    .loginPage("/login")
    .loginProcessingUrl("/process-login")
    .permitAll()  // allows GET /login and POST /process-login without auth
);
```

```java
// ❌ WRONG — wrong parameter names (form uses "user" but filter expects "username")
// HTML form: <input name="user" />
// Config:
http.formLogin(form -> form
    .loginPage("/login")
    // Missing: .usernameParameter("user")
    // Result: username will always be empty string → always BadCredentialsException
);

// ✓ CORRECT
http.formLogin(form -> form
    .loginPage("/login")
    .usernameParameter("user")
    .passwordParameter("pass")
);
```

```java
// ❌ WRONG — defaultSuccessUrl with alwaysUse=false (default)
//            but no saved request logic understood
http.formLogin(form -> form
    .defaultSuccessUrl("/dashboard")
    // If user bookmarked /profile and went directly to login,
    // they get redirected to /dashboard instead of /profile
    // because alwaysUse defaults to FALSE — it should redirect
    // to saved request if one exists

    // Actual trap: if SessionCreationPolicy.STATELESS is used,
    // RequestCache cannot save the request (no session!)
    // → always falls back to defaultSuccessUrl regardless
);
```

---

## 3️⃣ Exam-Style Questions

---

**Q1 (MCQ):** `UsernamePasswordAuthenticationFilter` extends which class?

A. `GenericFilterBean`
B. `OncePerRequestFilter`
C. `AbstractAuthenticationProcessingFilter`
D. `BasicAuthenticationFilter`

**Answer: C**
`UsernamePasswordAuthenticationFilter` extends `AbstractAuthenticationProcessingFilter`, which provides the template method pattern for authentication filters. `BasicAuthenticationFilter` extends `OncePerRequestFilter` directly — different base class.

---

**Q2 (MCQ):** After successful form login, what is the default behavior if the user originally requested `/orders` before being redirected to `/login`?

A. Redirect to `/dashboard` (defaultSuccessUrl)
B. Redirect to `/orders` (saved request)
C. Return 200 OK with the `/orders` response directly
D. Redirect to `/login?success`

**Answer: B**
`SavedRequestAwareAuthenticationSuccessHandler` checks `RequestCache` first. Since `/orders` was saved before the redirect to `/login`, it redirects there after successful authentication — unless `defaultSuccessUrl("/dashboard", true)` is used with `alwaysUse=true`.

---

**Q3 (Select All That Apply):** Which statements about `DaoAuthenticationProvider` are correct?

A. It calls `UserDetailsService.loadUserByUsername()` during authentication
B. It throws `UsernameNotFoundException` directly to the caller by default
C. It checks `isEnabled()`, `isAccountNonLocked()` before password verification
D. It erases credentials after successful authentication
E. It uses `PasswordEncoder` to verify the submitted password

**Answer: A, C, E**
B is false — `UsernameNotFoundException` is masked as `BadCredentialsException` by default (`hideUserNotFoundExceptions=true`).
D is partially false — credentials are erased by `ProviderManager`, not `DaoAuthenticationProvider` itself. However, `DaoAuthenticationProvider` does call `eraseCredentials()` if it's configured to do so. Technically `ProviderManager` handles this. **In exam context**: D is false because erasure is `ProviderManager`'s responsibility.

---

**Q4 (Code Behavior Prediction):**

```java
http.formLogin(form -> form
    .defaultSuccessUrl("/home", false)  // alwaysUse = false
);
```

User flow:
1. User visits `/profile` (unauthenticated)
2. Redirected to `/login`
3. Logs in successfully

Where is the user redirected?

A. `/home`
B. `/profile`
C. `/`
D. `/login?success`

**Answer: B — `/profile`**
`alwaysUse=false` (default) means: if a saved request exists, use it. `/profile` was saved in `RequestCache` by `ExceptionTranslationFilter` before the login redirect. The user is sent to `/profile`.

---

**Q5 (Scenario):** You configure:
```java
.sessionManagement(s -> s
    .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
.formLogin(Customizer.withDefaults())
```

After successful form login, will the user stay authenticated on the next request?

**Answer: NO.**
With `STATELESS` policy, `HttpSessionSecurityContextRepository` is replaced with `NullSecurityContextRepository`. The `SecurityContext` is **never saved to the HTTP session**. On the next request, the filter loads an empty context. The user appears unauthenticated. Form login with `STATELESS` is almost always a misconfiguration — it should be paired with JWT or similar stateless token mechanisms.

---

**Q6 (HTTP Status Trap):** A user submits login with wrong password. What HTTP status does Spring Security return by default?

A. 401 Unauthorized
B. 403 Forbidden
C. 302 Found (redirect)
D. 200 OK with error message

**Answer: C — 302 Found (redirect to /login?error)**
This is a critical trap. Authentication failure does **NOT** return 401 by default for form login. It redirects to the failure URL. 401 would be returned by HTTP Basic or REST APIs using a custom failure handler. Default form login always redirects.

---

**Q7 (Filter Order):** Where does `RememberMeAuthenticationFilter` sit relative to `UsernamePasswordAuthenticationFilter` and `AnonymousAuthenticationFilter`?

**Answer:**
```
UsernamePasswordAuthenticationFilter  (order 800)
RememberMeAuthenticationFilter        (order 1050 — between Basic and Anonymous)
AnonymousAuthenticationFilter         (order 1300)
```

Remember-me runs AFTER form/basic auth but BEFORE anonymous. Logic: if form login found credentials, remember-me is skipped. If no credentials, remember-me checks for the cookie. If no cookie, anonymous sets the anonymous token.

---

**Q8 (Drag-and-Drop):** Number these events in the order they occur during successful form login:

- RememberMeServices.loginSuccess()
- SecurityContextHolder.setAuthentication()
- PasswordEncoder.matches()
- SessionFixationProtectionStrategy.onAuthentication()
- successHandler.onAuthenticationSuccess()
- UserDetailsService.loadUserByUsername()

**Answer:**
1. `UserDetailsService.loadUserByUsername()`
2. `PasswordEncoder.matches()`
3. `SessionFixationProtectionStrategy.onAuthentication()`
4. `SecurityContextHolder.setAuthentication()`
5. `RememberMeServices.loginSuccess()`
6. `successHandler.onAuthenticationSuccess()`

---

## 4️⃣ Trick Analysis

---

**Trick 1 — `loginPage()` vs `loginProcessingUrl()` confusion**

```
loginPage("/login")            → GET /login  → renders the HTML form
                                 (your @GetMapping controller handles this)

loginProcessingUrl("/login")   → POST /login → UsernamePasswordAuthenticationFilter
                                 intercepts and processes credentials
                                 (NO controller needed — filter handles it)
```

If you create a `@PostMapping("/login")` controller, it **never executes** — the filter intercepts POST `/login` first and the request never reaches `DispatcherServlet`.

---

**Trick 2 — `permitAll()` scope on formLogin**

```java
.formLogin(form -> form
    .loginPage("/login")
    .permitAll()  // What exactly does this permit?
)
```

`.permitAll()` in form login config permits:
- `GET /login` (login page)
- `POST /login` (form submission)
- `GET /login?error` (error page)
- `GET /login?logout` (after logout)

It does NOT automatically permit `/logout`. That requires `.logout().permitAll()` separately.

---

**Trick 3 — `defaultSuccessUrl` trap with `true` vs `false`**

```java
.defaultSuccessUrl("/dashboard")           // alwaysUse=false — HONORS saved request
.defaultSuccessUrl("/dashboard", true)     // alwaysUse=true  — ALWAYS /dashboard
.defaultSuccessUrl("/dashboard", false)    // same as no second arg
```

Enterprise trap: teams set `alwaysUse=true` for "consistency" and then wonder why bookmarked deep links don't work after login. The correct behavior for a good UX is `alwaysUse=false` (default).

---

**Trick 4 — Session fixation `newSession` vs `changeSessionId`**

```java
.sessionFixation().newSession()       // Creates brand new session, does NOT migrate attributes
.sessionFixation().changeSessionId()  // Changes session ID, PRESERVES attributes (default)
.sessionFixation().migrateSession()   // Old name for changeSessionId behavior in 5.x
.sessionFixation().none()             // No protection — DANGEROUS
```

**Exam trap:** `newSession()` can break shopping cart or wizard state because attributes aren't migrated. `changeSessionId()` is the safe default that provides protection without breaking app state.

---

**Trick 5 — Remember-Me cookie theft detection**

```
Persistent remember-me:
- Series: abc123 (identifies device)
- Token: xyz789 (single-use, rotates each login)

Attacker steals cookie: abc123:xyz789
Attacker uses it → Server sees series=abc123, token=xyz789 → valid → log in
Server now stores new token: abc123:newtoken

Legitimate user comes back with abc123:xyz789 (old token)
→ series abc123 exists BUT token mismatch → THEFT DETECTED
→ ALL sessions for this user invalidated
→ User forced to re-authenticate
```

This is the security advantage of persistent over hash-based remember-me.

---

**Trick 6 — `AuthenticationSuccessEvent` vs `InteractiveAuthenticationSuccessEvent`**

```
InteractiveAuthenticationSuccessEvent  → published by AbstractAuthenticationProcessingFilter
                                          (form login, basic auth — human-interactive)

AuthenticationSuccessEvent             → published by ProviderManager on any
                                          successful authentication
                                          (includes remember-me, pre-auth)
```

`InteractiveAuthenticationSuccessEvent` is a **subclass** of `AuthenticationSuccessEvent`. If you listen for `AuthenticationSuccessEvent`, you catch BOTH. If you only want to react to actual human logins (not remember-me auto-login), listen for `InteractiveAuthenticationSuccessEvent`.

---

**Trick 7 — `HttpSessionSecurityContextRepository` key name**

The security context is stored in the HTTP session under the attribute name:
```java
HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY
// = "SPRING_SECURITY_CONTEXT"
```

If you manually inspect session attributes and wonder where authentication is stored — that's the key. Some serialization issues (clustered sessions with non-serializable `Authentication` objects) cause `ClassCastException` on session restore. `Authentication` objects must be serializable for distributed sessions.

---

## 5️⃣ Summary Sheet

---

### Form Login Request Flow Diagram

```
POST /login (username, password)
     │
     ▼
AbstractAuthenticationProcessingFilter.doFilter()
     │
     ├── requiresAuthentication? YES
     ▼
attemptAuthentication()
     │
     ▼
ProviderManager → DaoAuthenticationProvider
     │
     ├── loadUserByUsername()
     ├── preAuthChecks (enabled, nonLocked, nonExpired)
     ├── passwordEncoder.matches()
     └── postAuthChecks (credentialsNonExpired)
     │
     ▼
SUCCESS?
  YES ──► SessionFixationStrategy (changeSessionId)
          SecurityContextHolder.setAuthentication()
          SecurityContextRepository.saveContext()
          RememberMeServices.loginSuccess()
          SuccessHandler → redirect to /dashboard or saved URL

  NO ──►  SecurityContextHolder.clearContext()
          RememberMeServices.loginFail()
          FailureHandler → redirect to /login?error
```

---

### Key Classes & Responsibilities

| Class | Responsibility |
|-------|---------------|
| `UsernamePasswordAuthenticationFilter` | Extracts credentials from POST form |
| `AbstractAuthenticationProcessingFilter` | Template: try auth → success/failure routing |
| `DaoAuthenticationProvider` | Loads UserDetails, checks password |
| `SavedRequestAwareAuthenticationSuccessHandler` | Redirect to saved URL or default |
| `SimpleUrlAuthenticationFailureHandler` | Redirect to failure URL |
| `SessionFixationProtectionStrategy` | Rotate session ID on login |
| `HttpSessionSecurityContextRepository` | Save/load SecurityContext in HTTP session |
| `PersistentTokenRepository` | Store remember-me tokens in DB |
| `RememberMeAuthenticationFilter` | Auto-login via remember-me cookie |

---

### Session Creation Policy Reference

| Policy | Session Created | Use Case |
|--------|----------------|----------|
| `ALWAYS` | Every request | Legacy apps that need sessions |
| `IF_REQUIRED` | Only when needed | Default — good for most apps |
| `NEVER` | Never by Spring Security | Session managed by app layer |
| `STATELESS` | Never, never used | REST APIs with JWT |

---

### Remember-Me Strategy Comparison

| Feature | Hash-Based | Persistent Token |
|---------|-----------|-----------------|
| Server storage | None | Database table |
| Theft detection | ❌ No | ✅ Yes |
| Password change invalidates | ✅ Yes | ✅ Yes (if token rotated) |
| Scalability | ✅ Stateless | Requires DB |
| Security level | Medium | High |

---

### Common Interview One-Liners

- **`loginProcessingUrl`** is intercepted by the filter — no `@PostMapping` controller needed
- **`permitAll()`** on `formLogin()` permits login page GET + POST + error — not logout
- **`SavedRequestAwareAuthenticationSuccessHandler`** uses `RequestCache` to restore pre-login destination
- **`STATELESS` + form login** = broken authentication (context never saved)
- **`defaultSuccessUrl("/x", true)`** always redirects to `/x`, ignoring saved requests
- **`changeSessionId()`** (default) preserves session attributes; **`newSession()`** does not
- **Authentication failure** in form login returns **302 redirect**, NOT 401
- **Persistent remember-me** detects token theft via series/token mismatch
- **`InteractiveAuthenticationSuccessEvent`** is only for human-driven logins, not remember-me auto-login

---
