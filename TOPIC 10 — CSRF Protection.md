# TOPIC 10 — CSRF Protection

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

---

## 1️⃣ Conceptual Explanation

---

### 10.1 What Is CSRF — The Attack Explained

Cross-Site Request Forgery (CSRF) exploits the fact that browsers **automatically include cookies** (including session cookies) with every request to a domain, regardless of which site initiated the request.

**The attack — step by step:**

```
Setup:
     Legitimate site: bank.com
     User: logged into bank.com (has JSESSIONID cookie)
     Attacker site: evil.com

Attack sequence:
     Step 1: User visits evil.com (while still logged into bank.com)

     Step 2: evil.com serves HTML with hidden form or img tag:
             <form action="https://bank.com/transfer" method="POST">
                 <input type="hidden" name="amount" value="10000"/>
                 <input type="hidden" name="to"     value="attacker"/>
             </form>
             <script>document.forms[0].submit();</script>

     Step 3: Browser submits POST to bank.com/transfer
             AUTOMATICALLY includes: Cookie: JSESSIONID=victim_session
             bank.com sees authenticated request from victim!

     Step 4: Transfer executes — victim loses money
```

**Why it works:**
- Browser sends cookies automatically to any request targeting their domain
- Server cannot distinguish "user-initiated request" from "attacker-forged request"
- Both have identical cookies

**Why CSRF tokens prevent it:**
A CSRF token is a secret value that:
1. The server generates and stores server-side
2. The server embeds in every form rendered to the user
3. The server requires in every state-changing request
4. An attacker on evil.com **cannot read** (Same-Origin Policy prevents JavaScript on evil.com from reading bank.com's pages)

```
With CSRF protection:
     bank.com embeds: <input type="hidden" name="_csrf" value="XYZ-SECRET-TOKEN"/>
     POST to bank.com/transfer must include: _csrf=XYZ-SECRET-TOKEN

     evil.com cannot read XYZ-SECRET-TOKEN (Same-Origin Policy)
     evil.com's forged POST has no _csrf parameter (or wrong value)
     → Server rejects: 403 Forbidden
```

---

### 10.2 When CSRF Protection Is and Is NOT Needed

**CSRF is needed when ALL of these are true:**

```
Condition 1: The application uses cookie-based session authentication
             (browser automatically sends cookies)

Condition 2: The endpoint performs state-changing operations
             (POST, PUT, DELETE, PATCH)

Condition 3: The request can be initiated by a browser
             (web application with HTML forms or browser-based JS)
```

**CSRF is NOT needed when:**

```
Scenario A: Stateless API with JWT in Authorization header
     Browser does NOT automatically include Authorization headers
     Attacker on evil.com cannot forge the Authorization header
     → CSRF attack cannot succeed
     → CSRF protection unnecessary (and should be disabled)

Scenario B: Non-browser clients (mobile apps, backend services)
     These clients don't have automatic cookie behavior
     → CSRF attack vector doesn't apply

Scenario C: Read-only operations (GET, HEAD, OPTIONS)
     HTTP spec: safe methods should not change server state
     Even if forged, no harm done
     → Spring Security defaults to not protecting safe methods

Scenario D: Basic Auth (stateless)
     Each request includes credentials explicitly
     No persistent session cookie
     → No cookie to hijack → CSRF not applicable
```

---

### 10.3 CsrfFilter — Complete Internal Architecture

`CsrfFilter` extends `OncePerRequestFilter`. It is positioned at **order 500** in the filter chain — after `SecurityContextHolderFilter` but before any authentication filters.

**Why so early?**
CSRF validation must happen before authentication processing to prevent forged requests from even reaching the authentication logic.

```java
public final class CsrfFilter extends OncePerRequestFilter {

    public static final RequestMatcher DEFAULT_CSRF_MATCHER =
        new DefaultRequiresCsrfMatcher();
    // Matches: POST, PUT, DELETE, PATCH (NOT GET, HEAD, OPTIONS, TRACE)

    private final CsrfTokenRepository tokenRepository;
    private RequestMatcher requireCsrfProtectionMatcher = DEFAULT_CSRF_MATCHER;
    private AccessDeniedHandler accessDeniedHandler =
        new AccessDeniedHandlerImpl();
    private CsrfTokenRequestHandler requestHandler;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
            HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        // Step 1: Load (or generate) the CSRF token
        DeferredCsrfToken deferredCsrfToken =
            this.tokenRepository.loadDeferredToken(request, response);

        // Step 2: Make token available on request attribute
        // (for template engines to include in forms)
        this.requestHandler.handle(request, response,
            deferredCsrfToken::get);

        // Step 3: Does this request require CSRF validation?
        if (!this.requireCsrfProtectionMatcher.matches(request)) {
            // GET, HEAD, OPTIONS, TRACE → skip validation
            filterChain.doFilter(request, response);
            return;
        }

        // Step 4: Extract actual CSRF token from request
        // (from header or parameter)
        CsrfToken csrfToken = deferredCsrfToken.get();
        String actualToken = this.requestHandler
            .resolveCsrfTokenValue(request, csrfToken);

        // Step 5: Validate
        if (!equalsConstantTime(csrfToken.getToken(), actualToken)) {
            // Invalid CSRF token
            if (this.logger.isDebugEnabled()) {
                this.logger.debug("Invalid CSRF token found for "
                    + UrlUtils.buildFullRequestUrl(request));
            }

            Throwable cause = deferredCsrfToken.isGenerated()
                ? new MissingCsrfTokenException(actualToken)
                : new InvalidCsrfTokenException(csrfToken, actualToken);

            this.accessDeniedHandler.handle(request, response,
                new AccessDeniedException("Invalid CSRF Token", cause));
            return;
        }

        // Step 6: Valid token → proceed
        filterChain.doFilter(request, response);
    }

    // Constant-time comparison prevents timing attacks
    private static boolean equalsConstantTime(String expected, String actual) {
        if (expected == actual) return true;
        if (expected == null || actual == null) return false;
        byte[] expectedBytes = Utf8.encode(expected);
        byte[] actualBytes = Utf8.encode(actual);
        return MessageDigest.isEqual(expectedBytes, actualBytes);
    }
}
```

**The constant-time comparison (`MessageDigest.isEqual`):**
Regular string comparison (`equals()`) short-circuits on first mismatch — different lengths of tokens take different amounts of time. This timing difference can be exploited to guess tokens byte-by-byte. `MessageDigest.isEqual` always compares all bytes regardless of mismatch position — preventing timing attacks.

---

### 10.4 DefaultRequiresCsrfMatcher — What Gets Protected

```java
private static final class DefaultRequiresCsrfMatcher
        implements RequestMatcher {

    private final HashSet<String> allowedMethods =
        new HashSet<>(Arrays.asList("GET", "HEAD", "OPTIONS", "TRACE"));

    @Override
    public boolean matches(HttpServletRequest request) {
        // Returns TRUE (requires CSRF) for:
        // POST, PUT, DELETE, PATCH
        // Returns FALSE (skips CSRF) for:
        // GET, HEAD, OPTIONS, TRACE
        return !this.allowedMethods.contains(request.getMethod());
    }
}
```

**Why safe methods (GET, HEAD, OPTIONS) are excluded:**
HTTP specification says safe methods MUST NOT change server state. CSRF attacks only matter for state-changing operations. If your API changes state via GET requests, CSRF protection is insufficient — you have a bigger design problem.

---

### 10.5 CsrfTokenRepository — Two Major Implementations

#### Implementation 1: `HttpSessionCsrfTokenRepository` (Default, Server-Side)

```java
public final class HttpSessionCsrfTokenRepository
        implements CsrfTokenRepository {

    static final String DEFAULT_CSRF_PARAMETER_NAME = "_csrf";
    static final String DEFAULT_CSRF_HEADER_NAME = "X-CSRF-TOKEN";
    private static final String DEFAULT_CSRF_TOKEN_ATTR_NAME =
        HttpSessionCsrfTokenRepository.class.getName().concat(".CSRF_TOKEN");

    @Override
    public CsrfToken generateToken(HttpServletRequest request) {
        return new DefaultCsrfToken(
            this.csrfHeaderName,      // "X-CSRF-TOKEN"
            this.csrfParameterName,   // "_csrf"
            createNewToken()          // UUID.randomUUID().toString()
        );
    }

    @Override
    public void saveToken(CsrfToken token, HttpServletRequest request,
                          HttpServletResponse response) {
        if (token == null) {
            // Remove token from session
            HttpSession session = request.getSession(false);
            if (session != null) {
                session.removeAttribute(this.sessionAttributeName);
            }
        } else {
            // Save to session
            HttpSession session = request.getSession();
            session.setAttribute(this.sessionAttributeName, token);
        }
    }

    @Override
    public CsrfToken loadToken(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) return null;
        return (CsrfToken) session.getAttribute(this.sessionAttributeName);
    }
}
```

**Token flow with `HttpSessionCsrfTokenRepository`:**

```
First request (GET /login):
     CsrfFilter: loadToken() → null (no session yet)
     CsrfFilter: generateToken() → UUID token
     CsrfFilter: saveToken() → creates HttpSession, stores token
     Template: <input name="_csrf" value="${_csrf.token}"/>
     Response: Set-Cookie: JSESSIONID=abc123

POST /login (form submit):
     CsrfFilter: loadToken() → loads from session
     CsrfFilter: validates _csrf param against session token
     → Match → proceed

On authentication success:
     CsrfAuthenticationStrategy: rotate token
     → Generates NEW token → saves to (new) session
     → Old token invalidated
```

**Security properties:**
- Token stored server-side in session
- Impossible to forge without session access
- Token rotated on authentication (prevents pre-auth token reuse)
- **Downside:** Requires session — not suitable for stateless apps

---

#### Implementation 2: `CookieCsrfTokenRepository` (Cookie-Based, SPA-Friendly)

```java
public final class CookieCsrfTokenRepository
        implements CsrfTokenRepository {

    static final String DEFAULT_CSRF_COOKIE_NAME = "XSRF-TOKEN";
    static final String DEFAULT_CSRF_PARAMETER_NAME = "_csrf";
    static final String DEFAULT_CSRF_HEADER_NAME = "X-XSRF-TOKEN";

    @Override
    public CsrfToken generateToken(HttpServletRequest request) {
        return new DefaultCsrfToken(
            this.headerName,     // "X-XSRF-TOKEN"
            this.parameterName,  // "_csrf"
            createNewToken()     // UUID string
        );
    }

    @Override
    public void saveToken(CsrfToken token, HttpServletRequest request,
                          HttpServletResponse response) {
        String tokenValue = (token != null) ? token.getToken() : "";

        Cookie cookie = new Cookie(this.cookieName, tokenValue);
        cookie.setSecure(request.isSecure());
        cookie.setPath(getCookiePath(request));
        cookie.setDomain(this.cookieDomain);
        cookie.setHttpOnly(this.cookieHttpOnly);  // DEFAULT: false in Spring 6.x!
        if (this.cookieMaxAge != null) {
            cookie.setMaxAge(this.cookieMaxAge);
        }

        response.addCookie(cookie);
    }

    @Override
    public CsrfToken loadToken(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (this.cookieName.equals(cookie.getName())) {
                    String token = cookie.getValue();
                    if (!token.isEmpty()) {
                        return new DefaultCsrfToken(
                            this.headerName, this.parameterName, token);
                    }
                }
            }
        }
        return null;
    }
}
```

**The Double Submit Cookie Pattern:**

```
How CookieCsrfTokenRepository works:

1. Server sends two things:
   a. Session cookie (HttpOnly, Secure, automatic): JSESSIONID=abc123
   b. CSRF cookie (readable by JS): XSRF-TOKEN=SECRET123

2. JavaScript reads XSRF-TOKEN cookie value

3. JavaScript includes token in EVERY state-changing request:
   Header: X-XSRF-TOKEN: SECRET123
   (Angular, Axios do this automatically)

4. Server validates:
   - Cookie: XSRF-TOKEN=SECRET123 (sent automatically by browser)
   - Header: X-XSRF-TOKEN=SECRET123 (set by JavaScript)
   - They must match

Why attacker cannot forge:
   - evil.com's JavaScript CANNOT read bank.com's cookies
     (Same-Origin Policy)
   - evil.com cannot set X-XSRF-TOKEN header for cross-origin requests
     (CORS prevents it)
   - Browser auto-sends XSRF-TOKEN cookie BUT attacker can't read its value
     → Cannot forge the matching header

Why cookieHttpOnly MUST be false:
   HttpOnly cookies are NOT readable by JavaScript
   If XSRF-TOKEN is HttpOnly → JavaScript can't read it
   → SPA cannot extract token to include in header
   → CSRF protection BREAKS for SPAs
   → cookieHttpOnly=false (default in Spring 6.x) is CORRECT for SPAs
```

---

### 10.6 CSRF Token Request Handler — 5.x vs 6.x Architecture

**Spring Security 5.x — Eager Token Loading:**

```
Every request:
     CsrfFilter loads or generates CSRF token IMMEDIATELY
     Token stored as request attribute
     Session created/accessed on EVERY request
     → Even GET /index.html creates a session for CSRF token
     → Performance overhead
```

**Spring Security 6.x — Deferred Token Loading:**

```java
// DeferredCsrfToken — loaded lazily
public interface DeferredCsrfToken extends Supplier<CsrfToken> {
    CsrfToken get();
    boolean isGenerated();  // was token newly generated this request?
}
```

```
Every request (6.x):
     CsrfFilter: tokenRepository.loadDeferredToken(request, response)
          → Returns DeferredCsrfToken (NOT loaded yet)
          → Token is wrapped in a Supplier — lazy evaluation

     Token ONLY loaded if:
          a. A POST/PUT/DELETE request is made (validation needed)
          b. Template engine accesses ${_csrf.token}
          c. Application code accesses the request attribute

     For GET requests that don't access the token:
          → Session NEVER opened for CSRF purposes
          → Performance improvement (no unnecessary session creation)
```

**`CsrfTokenRequestAttributeHandler` (6.x default):**

```java
// In 6.x, the default handler:
// 1. Sets token on request attribute (deferred)
// 2. For validation: reads from header OR parameter
// 3. Does NOT use XOR masking (unlike XorCsrfTokenRequestAttributeHandler)

// XorCsrfTokenRequestAttributeHandler (also available in 6.x):
// 1. Masks the token with a random XOR value before setting as attribute
// 2. Different masked value on every request (even for same underlying token)
// 3. Prevents BREACH attack (compression-based side channel on HTTPS)
// 4. Recommended for high-security applications
```

---

### 10.7 CSRF Token in Forms and AJAX

**Thymeleaf (automatic):**
```html
<form th:action="@{/transfer}" method="post">
    <!-- Thymeleaf auto-injects CSRF token -->
    <!-- Rendered as: -->
    <input type="hidden" name="_csrf" value="a867a-b234-..."/>
    <button type="submit">Transfer</button>
</form>
```

**Manual HTML:**
```html
<form action="/transfer" method="post">
    <!-- Access from request attribute: -->
    <input type="hidden"
           name="${_csrf.parameterName}"
           value="${_csrf.token}"/>
</form>
```

**AJAX with HttpSessionCsrfTokenRepository:**
```javascript
// Read token from meta tag (server-side rendered into HTML):
// <meta name="_csrf" content="${_csrf.token}"/>
// <meta name="_csrf_header" content="${_csrf.headerName}"/>

const csrfToken = document.querySelector('meta[name="_csrf"]').content;
const csrfHeader = document.querySelector('meta[name="_csrf_header"]').content;

fetch('/api/transfer', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        [csrfHeader]: csrfToken  // "X-CSRF-TOKEN": "token-value"
    },
    body: JSON.stringify({amount: 100, to: 'alice'})
});
```

**AJAX with CookieCsrfTokenRepository (Angular/Axios pattern):**
```javascript
// Angular HttpClient automatically reads XSRF-TOKEN cookie
// and sends it as X-XSRF-TOKEN header on every mutating request
// Zero configuration needed for Angular + CookieCsrfTokenRepository

// Axios — configure globally:
axios.defaults.xsrfCookieName = 'XSRF-TOKEN';
axios.defaults.xsrfHeaderName = 'X-XSRF-TOKEN';
// Now all POST/PUT/DELETE requests automatically include the header
```

---

### 10.8 CSRF Token Rotation on Authentication

**Why rotate on authentication?**

```
Without rotation:
     Anonymous user visits GET /login
     → CSRF token generated: "OLD-TOKEN"
     → Stored in pre-authentication session

     User logs in successfully (POST /login with OLD-TOKEN)
     → Authentication succeeds
     → NEW session created (session fixation protection)
     → OLD-TOKEN is still valid in new session

     ATTACK: Attacker visits site, gets their own OLD-TOKEN
     → Tricks victim into clicking link that logs in as victim
     → OLD-TOKEN is still valid after login (not rotated)
     → Attacker can now forge requests using OLD-TOKEN they know!

With rotation (CsrfAuthenticationStrategy):
     → After authentication: generates NEW-TOKEN, invalidates OLD-TOKEN
     → Attacker's pre-obtained token is useless after login
```

**`CsrfAuthenticationStrategy` execution:**

```java
// Called by SessionAuthenticationStrategy composite on authentication success:
public class CsrfAuthenticationStrategy implements SessionAuthenticationStrategy {
    @Override
    public void onAuthentication(Authentication authentication,
            HttpServletRequest request, HttpServletResponse response) {
        // Remove old token
        boolean containsToken = this.csrfTokenRepository
            .loadToken(request) != null;
        if (containsToken) {
            this.csrfTokenRepository.saveToken(null, request, response);
            // null = remove
        }
        // Generate and save new token
        CsrfToken newToken =
            this.csrfTokenRepository.generateToken(request);
        this.csrfTokenRepository.saveToken(newToken, request, response);

        String newTokenValue = newToken.getToken();
        request.setAttribute(CsrfToken.class.getName(), newToken);
        request.setAttribute(newToken.getParameterName(), newTokenValue);
    }
}
```

---

### 10.9 When and How to Disable CSRF

**Correct disable patterns:**

```java
// Pattern 1: Disable entirely (stateless REST API)
http.csrf(AbstractHttpConfigurer::disable);

// Pattern 2: Disable for specific paths (e.g., webhook endpoints)
http.csrf(csrf -> csrf
    .ignoringRequestMatchers("/api/webhooks/**", "/api/external/**")
);

// Pattern 3: Disable for specific request matchers
http.csrf(csrf -> csrf
    .ignoringRequestMatchers(
        new AntPathRequestMatcher("/api/**"),
        new AntPathRequestMatcher("/webhooks/**")
    )
);
```

**Webhook endpoint CSRF consideration:**

```
Webhooks from Stripe, GitHub, etc.:
     - Initiated by external server (not browser)
     - Have no session cookie
     - Use their own signature validation (e.g., HMAC)
     - CSRF protection not applicable
     → Ignore CSRF for webhook paths
     → Validate via webhook signature instead
```

---

### 10.10 CORS vs CSRF — The Conceptual Distinction

This is a perpetual source of confusion — they address different threats:

```
CSRF (Cross-Site Request Forgery):
     Threat: Browser automatically sends cookies to target site
     Victim: THE SERVER (forged state change)
     Prevention: CSRF tokens, SameSite cookies
     Browser behavior exploited: Automatic cookie inclusion

CORS (Cross-Origin Resource Sharing):
     Threat: Browser reads response from different origin
     Victim: THE USER (data theft)
     Prevention: CORS headers controlling who can read responses
     Browser behavior restricted: Same-Origin Policy on reading responses

They are COMPLEMENTARY protections:
     CSRF → prevents writing/changing state via forged requests
     CORS → prevents reading sensitive data from cross-origin responses
```

**Why disabling CORS doesn't prevent CSRF (common misconception):**

```
CORS controls what JavaScript can READ from cross-origin responses.
CSRF exploits what browsers SEND (cookies) in cross-origin requests.

A form submission on evil.com to bank.com:
     → Browser SENDS the POST with cookies (CSRF attack vector)
     → CORS doesn't apply to simple form submissions!
     → Attacker doesn't need to READ the response
     → They just need the state-changing action to execute

Conclusion: CORS permissiveness does NOT increase CSRF risk
            CSRF tokens are needed regardless of CORS configuration
            (though SameSite=Strict cookies also prevent CSRF)
```

---

### 10.11 SameSite Cookie Attribute — Modern CSRF Prevention

Modern browsers support `SameSite` cookie attribute which provides CSRF protection at the browser level:

```
SameSite=Strict:
     Cookie NEVER sent on cross-site requests
     Maximum CSRF protection
     Breaks: links from email → site (cookie not sent → user appears logged out)

SameSite=Lax (browser default in modern browsers):
     Cookie sent on: same-site requests + top-level GET navigations
     Cookie NOT sent on: cross-site POST, PUT, DELETE, iframes
     Covers most CSRF scenarios
     Doesn't break normal navigation

SameSite=None:
     Old behavior — cookies always sent
     Must be paired with Secure attribute
     Required for: embedded content, payment flows, cross-site OAuth
```

**Spring Security 6.x SameSite configuration:**

```java
// Configure SameSite in Spring Boot:
server.servlet.session.cookie.same-site=strict  # application.properties

// Or programmatically:
@Bean
public CookieSameSiteSupplier cookieSameSiteSupplier() {
    return CookieSameSiteSupplier.ofStrict();
}
```

**SameSite + CSRF:** With `SameSite=Strict`, CSRF tokens may be redundant (browser won't send cookies on cross-site requests anyway). But defense-in-depth recommends keeping both.

---

### 10.12 Spring Security 5.x vs 6.x CSRF Changes

| Aspect | Spring Security 5.x | Spring Security 6.x |
|--------|--------------------|--------------------|
| Token loading | Eager (every request) | Deferred (lazy) |
| Default handler | `CsrfTokenRequestAttributeHandler` | `CsrfTokenRequestAttributeHandler` |
| XOR masking | Not default | Available via `XorCsrfTokenRequestAttributeHandler` |
| `CookieCsrfTokenRepository` `HttpOnly` | `true` (broke SPAs!) | `false` (SPA-compatible) |
| Session creation | Could create session eagerly | No unnecessary session creation |
| `loadDeferredToken` API | Not present | New in 6.x |

---

## 2️⃣ Code Examples

---

### Example 1 — Traditional Web App (HttpSessionCsrfTokenRepository)

```java
@Configuration
@EnableWebSecurity
public class TraditionalWebCsrfConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/public/**").permitAll()
                .anyRequest().authenticated()
            )
            .formLogin(form -> form
                .loginPage("/login")
                .permitAll()
            )
            // CSRF enabled by default — HttpSessionCsrfTokenRepository used
            // Explicit config (same as default):
            .csrf(csrf -> csrf
                .csrfTokenRepository(
                    HttpSessionCsrfTokenRepository())
                .csrfTokenRequestHandler(
                    new CsrfTokenRequestAttributeHandler())
            );

        return http.build();
    }
}
```

**Thymeleaf template:**
```html
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<body>
<form th:action="@{/transfer}" method="post">
    <!-- Thymeleaf auto-injects: -->
    <!-- <input type="hidden" name="_csrf" value="TOKEN"/> -->
    <input type="text" name="amount"/>
    <button type="submit">Transfer</button>
</form>
</body>
</html>
```

---

### Example 2 — SPA with CookieCsrfTokenRepository

```java
@Configuration
@EnableWebSecurity
public class SpaCsrfConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/", "/index.html", "/static/**").permitAll()
                .anyRequest().authenticated()
            )
            .csrf(csrf -> csrf
                .csrfTokenRepository(
                    CookieCsrfTokenRepository.withHttpOnlyFalse())
                // withHttpOnlyFalse() = JavaScript CAN read the cookie
                // Required for SPA to extract token and include in header
            )
            // REST API for SPA authentication:
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
            );

        return http.build();
    }
}
```

**Angular app (automatic CSRF):**
```typescript
// Angular's HttpClientModule automatically:
// 1. Reads cookie: XSRF-TOKEN
// 2. Sends header: X-XSRF-TOKEN on all mutating requests

// Zero configuration needed in Angular!
// Just ensure Spring Security uses CookieCsrfTokenRepository.withHttpOnlyFalse()

// Explicit Angular HttpClient interceptor (if needed):
@Injectable()
export class CsrfInterceptor implements HttpInterceptor {
    intercept(req: HttpRequest<any>, next: HttpHandler) {
        const csrfToken = this.getCookie('XSRF-TOKEN');
        if (csrfToken && req.method !== 'GET') {
            req = req.clone({
                headers: req.headers.set('X-XSRF-TOKEN', csrfToken)
            });
        }
        return next.handle(req);
    }
}
```

---

### Example 3 — Mixed: REST API (no CSRF) + Web UI (with CSRF)

```java
@Configuration
@EnableWebSecurity
public class MixedCsrfConfig {

    // Chain 1: REST API — stateless, no CSRF needed
    @Bean
    @Order(1)
    public SecurityFilterChain apiChain(HttpSecurity http) throws Exception {
        http
            .securityMatcher("/api/**")
            .csrf(AbstractHttpConfigurer::disable)
            .sessionManagement(s -> s
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()))
            .authorizeHttpRequests(auth -> auth
                .anyRequest().authenticated()
            );
        return http.build();
    }

    // Chain 2: Web UI — stateful, CSRF enabled
    @Bean
    @Order(2)
    public SecurityFilterChain webChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf
                .csrfTokenRepository(
                    CookieCsrfTokenRepository.withHttpOnlyFalse())
            )
            .formLogin(Customizer.withDefaults())
            .authorizeHttpRequests(auth -> auth
                .anyRequest().authenticated()
            );
        return http.build();
    }
}
```

---

### Example 4 — Webhook Endpoint CSRF Bypass

```java
@Configuration
@EnableWebSecurity
public class WebhookCsrfConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf
                // Ignore CSRF for webhook endpoints
                // These are server-to-server calls, not browser-initiated
                .ignoringRequestMatchers(
                    "/webhooks/stripe/**",
                    "/webhooks/github/**",
                    "/api/external/**"
                )
            )
            .authorizeHttpRequests(auth -> auth
                // Webhooks are secured by signature validation, not session
                .requestMatchers("/webhooks/**").permitAll()
                .anyRequest().authenticated()
            );

        return http.build();
    }
}
```

```java
// Webhook controller with signature validation
@RestController
@RequestMapping("/webhooks/stripe")
public class StripeWebhookController {

    @PostMapping
    public ResponseEntity<Void> handleWebhook(
            @RequestBody String payload,
            @RequestHeader("Stripe-Signature") String signature) {

        // Validate Stripe HMAC signature (alternative to CSRF)
        if (!stripeWebhookValidator.isValid(payload, signature)) {
            return ResponseEntity.status(403).build();
        }

        // Process webhook
        return ResponseEntity.ok().build();
    }
}
```

---

### Example 5 — 6.x Deferred Token Loading with XOR Masking

```java
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http
        .csrf(csrf -> csrf
            .csrfTokenRepository(
                CookieCsrfTokenRepository.withHttpOnlyFalse())
            // XOR masking: different token value shown each request
            // Prevents BREACH compression attack
            .csrfTokenRequestHandler(new XorCsrfTokenRequestAttributeHandler())
        );

    return http.build();
}
```

```javascript
// With XorCsrfTokenRequestAttributeHandler:
// The XSRF-TOKEN cookie contains the REAL token
// The request attribute (for form rendering) contains MASKED token
// Server validates: unmask received token, compare with stored token

// SPA using cookie approach — no change needed
// Form-based apps — Thymeleaf handles the masked value correctly
```

---

### Example 6 — Accessing CSRF Token Programmatically

```java
@RestController
public class CsrfTokenController {

    // Endpoint for SPAs to explicitly fetch CSRF token
    // (Useful when SPA needs token before cookie is set)
    @GetMapping("/api/csrf")
    public Map<String, String> getCsrfToken(HttpServletRequest request) {
        // Token is set as request attribute by CsrfFilter
        CsrfToken csrfToken = (CsrfToken)
            request.getAttribute(CsrfToken.class.getName());

        // Trigger deferred loading (6.x) — accessing the attribute loads the token
        if (csrfToken != null) {
            return Map.of(
                "token",         csrfToken.getToken(),
                "headerName",    csrfToken.getHeaderName(),
                "parameterName", csrfToken.getParameterName()
            );
        }
        return Map.of();
    }
}
```

---

### Example 7 — Incorrect CSRF Configurations

```java
// ❌ WRONG 1 — CookieCsrfTokenRepository with HttpOnly=true (breaks SPA)
http.csrf(csrf -> csrf
    .csrfTokenRepository(new CookieCsrfTokenRepository())
    // Default in OLD versions: cookieHttpOnly=true
    // JavaScript CANNOT read HttpOnly cookies
    // SPA cannot extract XSRF-TOKEN → cannot set X-XSRF-TOKEN header
    // ALL mutating requests fail with 403!
);

// ✓ CORRECT for SPA:
http.csrf(csrf -> csrf
    .csrfTokenRepository(
        CookieCsrfTokenRepository.withHttpOnlyFalse())
);
```

```java
// ❌ WRONG 2 — Disabling CSRF for session-based web app
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http
        .csrf(AbstractHttpConfigurer::disable)  // ← NEVER for session-based apps!
        .formLogin(Customizer.withDefaults())
        .sessionManagement(s -> s
            .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED));
    // This application is now VULNERABLE to CSRF attacks!
    // Any site can forge form submissions and they'll execute
}

// ❌ WRONG 3 — CSRF enabled with STATELESS policy (unnecessary overhead)
http
    .sessionManagement(s -> s
        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
    // Missing: .csrf(AbstractHttpConfigurer::disable)
    // Result: CsrfFilter runs but CsrfToken has nowhere to be stored
    // HttpSessionCsrfTokenRepository tries to create session
    // → Session creation blocked by STATELESS policy
    // → Every POST request fails with 403 (no valid CSRF token)
```

```java
// ❌ WRONG 4 — Using _csrf parameter in AJAX (session-based) but
//             forgetting to include it in the header lookup
http.csrf(csrf -> csrf
    .csrfTokenRepository(
        HttpSessionCsrfTokenRepository())
);

// JavaScript AJAX call missing CSRF:
fetch('/api/action', {
    method: 'POST',
    body: JSON.stringify({data: 'value'})
    // Missing: headers: {'X-CSRF-TOKEN': csrfToken}
    // → 403 Forbidden on every AJAX POST
});

// ✓ CORRECT:
fetch('/api/action', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'X-CSRF-TOKEN': document.querySelector(
            'meta[name="_csrf"]').content
    },
    body: JSON.stringify({data: 'value'})
});
```

---

## 3️⃣ Exam-Style Questions

---

**Q1 (MCQ):** Which HTTP methods does Spring Security protect against CSRF by default?

A. GET, POST, PUT, DELETE
B. POST, PUT, DELETE, PATCH
C. All HTTP methods
D. Only POST

**Answer: B — POST, PUT, DELETE, PATCH**
`DefaultRequiresCsrfMatcher` allows: GET, HEAD, OPTIONS, TRACE (safe methods per HTTP spec). It requires CSRF validation for: POST, PUT, DELETE, PATCH (state-changing methods).

---

**Q2 (MCQ):** Why must `CookieCsrfTokenRepository` be configured with `withHttpOnlyFalse()` for SPAs?

A. HttpOnly cookies cannot be sent cross-origin
B. HttpOnly cookies cannot be read by JavaScript — the SPA cannot extract the token to include in request headers
C. HttpOnly cookies are not sent with AJAX requests
D. HttpOnly cookies expire after session ends

**Answer: B**
The Double Submit Cookie pattern requires the SPA's JavaScript to read the `XSRF-TOKEN` cookie value and include it in the `X-XSRF-TOKEN` request header. `HttpOnly` cookies are inaccessible to JavaScript by browser design (security feature). Therefore `HttpOnly` must be `false` for this pattern to work.

---

**Q3 (Select All That Apply):** Which are true about CSRF token storage and validation?

A. `HttpSessionCsrfTokenRepository` stores the token in the HTTP session
B. `CookieCsrfTokenRepository` stores the token in a cookie named `XSRF-TOKEN` by default
C. Spring Security validates CSRF by comparing the request parameter/header value against the stored token using constant-time comparison
D. CSRF token is validated for GET requests by default
E. CSRF token is rotated after successful authentication

**Answer: A, B, C, E**
D is false — GET requests are explicitly excluded from CSRF validation (`DefaultRequiresCsrfMatcher` allows GET). CSRF is only checked for state-changing methods.

---

**Q4 (Scenario):**

An application uses `SessionCreationPolicy.STATELESS` with JWT but forgot to disable CSRF. A client sends:

```
POST /api/transfer
Authorization: Bearer eyJhbGc...
Content-Type: application/json
```

What is the response and why?

**Answer: 403 Forbidden — `InvalidCsrfTokenException`**

With STATELESS policy:
1. `NullSecurityContextRepository` — no session created or used
2. `CsrfFilter` runs (still enabled)
3. POST request → `DefaultRequiresCsrfMatcher` matches → requires CSRF validation
4. `HttpSessionCsrfTokenRepository.loadToken()` tries to load from session → but STATELESS means no session → returns `null`
5. Request has no `_csrf` parameter or `X-CSRF-TOKEN` header
6. `null` (stored) vs `null` (request) → actually throws `MissingCsrfTokenException` (no stored token) or `InvalidCsrfTokenException`
7. `accessDeniedHandler.handle()` → **403 Forbidden**

**Fix:** `http.csrf(AbstractHttpConfigurer::disable)` for stateless JWT APIs.

---

**Q5 (CSRF vs CORS):**

A developer says: "I have CORS disabled (no `Access-Control-Allow-Origin` header), so CSRF attacks are impossible." Is this correct?

**Answer: NO — Completely incorrect.**

CORS restricts what JavaScript can **read** from cross-origin responses. CSRF exploits what browsers **send** (cookies) in cross-origin requests.

A simple HTML form on evil.com:
```html
<form action="https://bank.com/transfer" method="POST">
    <input type="hidden" name="amount" value="10000"/>
</form>
<script>document.forms[0].submit();</script>
```

This is a **simple request** (form POST). Browsers send simple requests cross-origin without CORS preflight. The JSESSIONID cookie is automatically included. The attacker doesn't need to read the response — just trigger the action. CORS headers have zero impact on this attack vector.

---

**Q6 (Code Prediction):**

```java
http.csrf(csrf -> csrf
    .ignoringRequestMatchers("/api/**")
);
```

A POST to `/api/transfer` arrives with no CSRF token. A POST to `/web/transfer` arrives with no CSRF token. What are the responses?

**Answer:**
- `POST /api/**` → CSRF checking IGNORED for this path → proceeds to authentication/authorization → depends on auth config (likely 401 or 200)
- `POST /web/transfer` → CSRF checking ACTIVE → no token in request → **403 Forbidden** (`MissingCsrfTokenException`)

---

**Q7 (Token Repository Selection):**

Match the scenario to the correct `CsrfTokenRepository`:

| Scenario | Repository |
|----------|-----------|
| A. Server-rendered Thymeleaf forms | ? |
| B. Angular SPA with session auth | ? |
| C. React app with session auth | ? |
| D. REST API with JWT (stateless) | ? |

**Answers:**
- A → `HttpSessionCsrfTokenRepository` (default — server stores, embeds in form)
- B → `CookieCsrfTokenRepository.withHttpOnlyFalse()` (Angular reads `XSRF-TOKEN` cookie automatically)
- C → `CookieCsrfTokenRepository.withHttpOnlyFalse()` (React must read cookie, send in header)
- D → N/A — **CSRF disabled** (`AbstractHttpConfigurer::disable`) — stateless JWT, no session cookie

---

**Q8 (Deferred Loading Behavior — 6.x):**

```java
// Spring Security 6.x
http.csrf(csrf -> csrf
    .csrfTokenRepository(
        CookieCsrfTokenRepository.withHttpOnlyFalse())
);
```

A `GET /home` request arrives (authenticated user). Does Spring Security access the session or set the XSRF-TOKEN cookie?

**Answer:** With deferred loading in 6.x:
- `CsrfFilter` calls `tokenRepository.loadDeferredToken()` → returns `DeferredCsrfToken` (lazy wrapper — token NOT actually loaded yet)
- GET request → `DefaultRequiresCsrfMatcher.matches()` = false → no validation needed
- Template engine does NOT access `${_csrf.token}` (GET returns existing page or JSON — let's assume no form rendering in this request)
- `DeferredCsrfToken.get()` is NEVER called
- **Result:** No cookie set, no session accessed for CSRF purposes

This is a significant performance improvement over 5.x where the CSRF token was always loaded/generated on every request.

---

## 4️⃣ Trick Analysis

---

**Trick 1 — CSRF is a Problem of Trust, Not Encryption**

```
HTTPS does NOT prevent CSRF.
TLS encrypts the channel but the attack doesn't require decryption.

The browser faithfully sends the forged request over HTTPS:
     Browser: "This is a legitimate request to bank.com. Here are the cookies."
     (Browser can't tell it was triggered by evil.com)

CSRF tokens work because:
     They are SECRET values that evil.com cannot know
     Not because of channel encryption

The protection is about KNOWLEDGE (does the requestor know the token?)
not ENCRYPTION (is the channel secure?)
```

---

**Trick 2 — `ignoringRequestMatchers` vs Disabling CSRF Entirely**

```java
// Disables CSRF for ALL paths:
http.csrf(AbstractHttpConfigurer::disable);

// Disables CSRF only for specific paths:
http.csrf(csrf -> csrf
    .ignoringRequestMatchers("/api/**", "/webhooks/**")
);
// Other paths (/web/**, /admin/**) still have CSRF protection

// EXAM TRAP: "What happens to /web/transfer if ignoringRequestMatchers
//             is set for /api/**?"
// Answer: /web/transfer still requires CSRF token → 403 without it
```

---

**Trick 3 — CookieCsrfTokenRepository httpOnly Default Changed in 6.x**

```
Spring Security 5.x:
     CookieCsrfTokenRepository default: cookieHttpOnly = true
     → Default BROKE SPAs!
     → Must explicitly: .withHttpOnlyFalse()

Spring Security 6.x:
     CookieCsrfTokenRepository default: cookieHttpOnly = false
     → Works with SPAs by default
     → No need for .withHttpOnlyFalse() (but still good practice to be explicit)

EXAM TRAP: "Why did SPAs break with default CookieCsrfTokenRepository in 5.x?"
Answer: HttpOnly=true by default → JavaScript couldn't read XSRF-TOKEN cookie
```

---

**Trick 4 — CSRF Token Is NOT Sent in Response Body**

```
Developers often think CSRF token is returned in JSON response:
{
  "csrfToken": "abc-123"  ← NOT how Spring Security works!
}

Actual delivery mechanisms:
     HttpSessionCsrfTokenRepository:
          → Request attribute (accessible to template engines)
          → <input type="hidden" name="_csrf" value="..."/> in HTML
          → <meta name="_csrf" content="..."/> in <head>

     CookieCsrfTokenRepository:
          → Set-Cookie: XSRF-TOKEN=... response cookie
          → JavaScript reads cookie, sends as header
```

---

**Trick 5 — Constant-Time Comparison Prevents Timing Attack**

```
❌ String.equals() — timing attack vulnerable:
"abcdef".equals("abcxyz")
→ Compares char by char: a=a, b=b, c=c, x≠d → STOP (fast, 4 comparisons)
"abcdef".equals("xbcdef")
→ Compares: a≠x → STOP (very fast, 1 comparison)

Attacker can measure time differences to guess the token character by character!

✓ MessageDigest.isEqual() — always compares ALL bytes:
Even if first byte doesn't match → continues comparing to the end
All comparisons take the same amount of time regardless of mismatch position
→ Timing attack impossible
```

---

**Trick 6 — CSRF Filter Runs Before Authentication**

```
Filter order:
     CsrfFilter (500) ← validates CSRF token
     ...
     UsernamePasswordAuthenticationFilter (800) ← authenticates user

This means:
     Even if CSRF is invalid, authentication doesn't even run
     A valid POST to /login with wrong CSRF token → 403 Forbidden
     (Never reaches authentication filter)

This is intentional — validate request integrity before processing credentials
```

---

**Trick 7 — `MissingCsrfTokenException` vs `InvalidCsrfTokenException`**

```
MissingCsrfTokenException:
     Thrown when: No stored token found (no session, first request, stateless)
     Meaning: "We have no token on record to compare against"
     HTTP result: 403 (via AccessDeniedHandler)

InvalidCsrfTokenException:
     Thrown when: Stored token exists but doesn't match request token
     Meaning: "Token exists but is wrong"
     HTTP result: 403 (via AccessDeniedHandler)

Both extend AccessDeniedException → same 403 response to client
But different meanings for debugging and security monitoring
```

---

**Trick 8 — CSRF Does Not Protect Against XSS**

```
If your site has XSS (JavaScript injection) vulnerability:
     Attacker injects JS that reads CSRF token from page/cookie
     Attacker's JS is running ON your site (same origin)
     → No Same-Origin Policy restriction
     → Attacker reads CSRF token easily
     → CSRF token provides ZERO additional protection against XSS

"CSRF protects against cross-site attacks, not same-site attacks"

XSS → attacker CAN read CSRF token
CSRF attack from evil.com → attacker CANNOT read CSRF token

Conclusion: XSS is a prerequisite bypass for CSRF protection
            Fix XSS first — CSRF tokens are not a substitute
```

---

## 5️⃣ Summary Sheet

---

### CsrfFilter Execution Diagram

```
HTTP Request
     │
     ▼
CsrfFilter.doFilterInternal()
     │
     ├── tokenRepository.loadDeferredToken() → DeferredCsrfToken (lazy, 6.x)
     │
     ├── requestHandler.handle() → set token as request attribute
     │       (for template rendering — still lazy until accessed)
     │
     ├── requiresCsrfMatcher.matches(request)?
     │       GET, HEAD, OPTIONS, TRACE → NO → chain.doFilter() ─────────────────►
     │       POST, PUT, DELETE, PATCH  → YES → continue
     │
     ├── csrfToken = deferredCsrfToken.get()  ← NOW actually loaded
     │
     ├── actualToken = extract from request
     │       Check header: X-CSRF-TOKEN (or X-XSRF-TOKEN for cookie repo)
     │       Fallback: parameter: _csrf
     │
     ├── equalsConstantTime(stored, actual)?
     │       MATCH    → chain.doFilter() ─────────────────────────────────────────►
     │       MISMATCH → accessDeniedHandler.handle() → 403 Forbidden
     │                       └── MissingCsrfTokenException (no stored token)
     │                       └── InvalidCsrfTokenException (wrong token)
     └──
```

---

### CSRF Token Repository Comparison

| Feature | `HttpSessionCsrfTokenRepository` | `CookieCsrfTokenRepository` |
|---------|----------------------------------|------------------------------|
| Storage | HTTP Session | Cookie (`XSRF-TOKEN`) |
| Default header | `X-CSRF-TOKEN` | `X-XSRF-TOKEN` |
| Default parameter | `_csrf` | `_csrf` |
| Session required | YES | NO |
| SPA-compatible | Requires meta tag | YES (cookie readable by JS) |
| Stateless-compatible | NO | Partial (cookie still needed) |
| Angular auto-support | NO | YES |
| Token rotation on auth | YES | YES |

---

### When to Enable vs Disable CSRF

| Scenario | CSRF Required | Reason |
|----------|--------------|--------|
| Server-rendered forms (Thymeleaf, JSP) | ✅ YES | Browser session, form submissions |
| SPA + session auth | ✅ YES | Browser session, AJAX requests |
| REST API + JWT (stateless) | ❌ NO | No session cookie, no CSRF vector |
| REST API + HTTP Basic (stateless) | ❌ NO | No session cookie |
| Mobile app backend | ❌ NO | No browser, no auto-cookie |
| Webhook endpoints | ❌ NO | Server-to-server, use signature validation |
| Microservice-to-microservice | ❌ NO | No browser involved |

---

### CSRF vs CORS — One-Line Distinction

```
CSRF → Prevents browsers from SENDING forged requests (exploits cookie auto-send)
CORS → Prevents browsers from READING cross-origin responses (enforces Same-Origin)
Both needed independently — disabling CORS does NOT prevent CSRF
```

---

### Common Interview One-Liners

- **CSRF token** is validated using **constant-time comparison** to prevent timing attacks
- **`CookieCsrfTokenRepository.withHttpOnlyFalse()`** is required for SPAs — JS must read the cookie
- **CSRF filter runs BEFORE authentication filters** (order 500 vs 800) — invalid token = 403 before auth runs
- **`MissingCsrfTokenException`** = no stored token; **`InvalidCsrfTokenException`** = wrong token; both = 403
- **Stateless JWT API + CSRF enabled** = every POST fails (no session to store/retrieve token)
- **CSRF protection is NOT NEEDED** for stateless APIs with JWT in `Authorization` header
- **`ignoringRequestMatchers()`** disables CSRF for specific paths, not globally
- **Spring Security 6.x deferred loading** = CSRF token not loaded until actually needed (GET optimization)
- **`CsrfAuthenticationStrategy`** rotates the CSRF token on successful authentication
- **XSS bypasses CSRF** — injected JS runs same-origin, can read CSRF tokens freely

---
