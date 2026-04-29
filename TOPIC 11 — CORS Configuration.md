# TOPIC 11 — CORS Configuration

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

---

## 1️⃣ Conceptual Explanation

---

### 11.1 What Is CORS — The Browser Security Model

CORS (Cross-Origin Resource Sharing) is a **browser security mechanism** that restricts JavaScript running on one origin from reading responses from a different origin. It is an extension of the Same-Origin Policy (SOP).

**Origin definition — ALL three must match:**

```
Origin = Protocol + Host + Port

https://app.example.com:443/path
│       │               │
│       │               └── Port (443)
│       └── Host (app.example.com)
└── Protocol (https)

Same origin:
     https://app.example.com/api/data         ✓ (same protocol, host, port)
     https://app.example.com/other/path       ✓

Different origin:
     http://app.example.com/api               ✗ (different protocol)
     https://api.example.com/data             ✗ (different subdomain)
     https://app.example.com:8080/api         ✗ (different port)
     https://other.com/api                    ✗ (different host)
```

**What CORS controls:**

```
JavaScript on https://frontend.com tries to:

     fetch('https://api.backend.com/data')
          │
          ▼
     Browser: "This is a cross-origin request"
     Browser sends request → RECEIVES response
     Browser checks response headers:
          Access-Control-Allow-Origin: https://frontend.com?
               YES → JavaScript CAN read the response body
               NO  → JavaScript CANNOT read response body
                      (but request WAS sent and server processed it!)
```

**Critical misconception — CORS does NOT block requests:**

```
CORS does NOT prevent the request from being sent.
CORS does NOT prevent the server from processing it.
CORS ONLY prevents JavaScript from READING the response.

This is why CORS is NOT a server-side security mechanism against CSRF.
CORS is a browser-side restriction on response reading.
```

---

### 11.2 CORS Request Types — Simple vs Preflight

**Type 1 — Simple Requests (no preflight):**

```
Conditions for simple request:
     Method: GET, HEAD, POST
     Headers: Only "safe" headers (Accept, Content-Type with specific values, etc.)
     Content-Type: application/x-www-form-urlencoded, multipart/form-data, text/plain

Flow:
     Browser → Server: Actual request + Origin header
     Server  → Browser: Response + CORS headers
     Browser: Check Access-Control-Allow-Origin → allow/block JS from reading
```

**Type 2 — Preflighted Requests (requires preflight):**

```
Conditions triggering preflight:
     Custom headers (Authorization, X-Custom-Header, etc.)
     Methods: PUT, DELETE, PATCH
     Content-Type: application/json (most API calls!)

Flow:
     Step 1 — Preflight:
     Browser → Server: OPTIONS /api/data
                        Origin: https://frontend.com
                        Access-Control-Request-Method: POST
                        Access-Control-Request-Headers: Content-Type, Authorization

     Server  → Browser: HTTP 200 (or 204)
                        Access-Control-Allow-Origin: https://frontend.com
                        Access-Control-Allow-Methods: GET, POST, PUT, DELETE
                        Access-Control-Allow-Headers: Content-Type, Authorization
                        Access-Control-Max-Age: 3600

     Step 2 — Actual Request (only if preflight approved):
     Browser → Server: POST /api/data
                        Origin: https://frontend.com
                        Authorization: Bearer xxx
                        Content-Type: application/json

     Server  → Browser: 200 OK + response body + CORS headers
```

**The Spring Security / CORS interaction with preflight:**

```
OPTIONS /api/data (preflight)
     │
     ▼
Spring Security Filter Chain
     │
     ├── Should this preflight request be authenticated?
     │       NO! Preflight is sent by BROWSER (not user code)
     │       Browser has no Authorization token to send
     │       Rejecting preflight with 401/403 breaks CORS entirely!
     │
     └── CRITICAL: Spring Security must PERMIT OPTIONS preflight requests
                   BEFORE authentication checks
```

---

### 11.3 CORS Headers — Complete Reference

**Response headers from server:**

```
Access-Control-Allow-Origin: https://frontend.com
     OR: * (wildcard — cannot be used with credentials)
     Specifies which origin can read the response

Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS
     Specifies allowed HTTP methods

Access-Control-Allow-Headers: Content-Type, Authorization, X-Custom
     Specifies allowed request headers

Access-Control-Expose-Headers: X-Total-Count, X-Request-Id
     Headers the browser allows JS to read (beyond default safe headers)

Access-Control-Allow-Credentials: true
     Allows cookies/Authorization headers in cross-origin requests
     CANNOT be used with Access-Control-Allow-Origin: *
     Must specify exact origin when using credentials

Access-Control-Max-Age: 3600
     How long (seconds) browser can cache preflight response
     Reduces repeated OPTIONS requests
```

**Request headers from browser:**

```
Origin: https://frontend.com
     Sent with every cross-origin request

Access-Control-Request-Method: POST
     Sent only in preflight — the method of the actual request

Access-Control-Request-Headers: Content-Type, Authorization
     Sent only in preflight — the custom headers of actual request
```

---

### 11.4 Three Ways to Configure CORS in Spring — Architecture Comparison

**Way 1: `@CrossOrigin` annotation (method/class level)**

```java
// Controller-level CORS — fine-grained but scattered
@RestController
@CrossOrigin(origins = "https://frontend.com")  // class-level
public class ApiController {

    @GetMapping("/data")
    @CrossOrigin(origins = {"https://app1.com", "https://app2.com"},
                 methods = {RequestMethod.GET, RequestMethod.POST},
                 allowedHeaders = {"Content-Type", "Authorization"},
                 maxAge = 3600)
    public ResponseEntity<Data> getData() { ... }
}
```

**Processed by:** Spring MVC's `CorsInterceptor` (inside `DispatcherServlet`) — NOT by Spring Security's `CorsFilter`.

**Problem:** `@CrossOrigin` is processed AFTER Spring Security filters. If Spring Security rejects a request before it reaches `DispatcherServlet` (e.g., 401 for unauthenticated OPTIONS preflight), the `@CrossOrigin` CORS headers are NEVER added to the response. The browser sees a rejection without CORS headers → CORS error in browser, even though the logic is "correct."

---

**Way 2: `CorsConfigurationSource` with Spring Security (recommended)**

```java
// Spring Security-level CORS — processed inside security filter chain
// CORS headers added BEFORE authentication checks
// Preflight OPTIONS requests handled correctly

@Bean
public CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration config = new CorsConfiguration();
    config.setAllowedOrigins(List.of("https://frontend.com"));
    config.setAllowedMethods(List.of("GET","POST","PUT","DELETE","OPTIONS"));
    config.setAllowedHeaders(List.of("*"));
    config.setAllowCredentials(true);
    config.setMaxAge(3600L);

    UrlBasedCorsConfigurationSource source =
        new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", config);
    return source;
}

// Then in SecurityFilterChain:
http.cors(cors -> cors
    .configurationSource(corsConfigurationSource())
);
```

**Processed by:** `CorsFilter` added to Spring Security's filter chain — position order 500 (same as `CsrfFilter`, runs before authentication).

---

**Way 3: `CorsFilter` bean (standalone)**

```java
// Standalone CorsFilter bean
// Processed by servlet container filter chain
// Must be ordered correctly relative to Spring Security

@Bean
@Order(Ordered.HIGHEST_PRECEDENCE)  // CRITICAL — must run before Spring Security
public CorsFilter corsFilter() {
    UrlBasedCorsConfigurationSource source =
        new UrlBasedCorsConfigurationSource();
    CorsConfiguration config = new CorsConfiguration();
    config.setAllowedOrigins(List.of("https://frontend.com"));
    config.setAllowedMethods(List.of("*"));
    config.setAllowedHeaders(List.of("*"));
    source.registerCorsConfiguration("/**", config);
    return new CorsFilter(source);
}
```

---

### 11.5 The Spring Security CORS Ordering Trap — The Most Critical Detail

**The fundamental problem:**

```
Without proper CORS integration:

OPTIONS /api/data (preflight)
     │
     ▼
Spring Security Filter Chain:
     ├── SecurityContextHolderFilter
     ├── CsrfFilter  ← CSRF check on OPTIONS? Actually excluded but...
     ├── BasicAuthenticationFilter ← No auth header in preflight → no auth set
     ├── AnonymousAuthenticationFilter ← Sets anonymous token
     ├── ExceptionTranslationFilter
     └── AuthorizationFilter
               └── anyRequest().authenticated()
               → Anonymous user → AccessDeniedException
               → AuthenticationEntryPoint → 401 Unauthorized
               → Response has NO CORS headers (CORS not processed yet!)

Browser receives: 401 Unauthorized with no Access-Control-Allow-Origin header
Browser sees: CORS error (not 401 error!)
Developer confused: "Why am I getting CORS errors when I have CORS configured?"
```

**The solution — `http.cors()` processes BEFORE authentication:**

```
With http.cors() correctly configured:

OPTIONS /api/data (preflight)
     │
     ▼
Spring Security Filter Chain:
     ├── SecurityContextHolderFilter
     ├── CorsFilter  ← ADDED BY http.cors() — position 500
     │       └── Is this a CORS request? YES (has Origin header)
     │       └── Is this a preflight? YES (OPTIONS + AC-Request-Method)
     │       └── Process preflight:
     │               Add CORS response headers
     │               Return 200 immediately — STOP processing chain
     │               ← Chain does NOT continue! Authentication never checked!
     └── (Never reached for preflight)

Browser receives: 200 OK with Access-Control-Allow-* headers
Browser proceeds with actual request
```

**Why `CorsFilter` short-circuits for preflight:**

```java
// Inside CorsFilter (Spring's CorsFilter, not Spring Security's):
if (CorsUtils.isPreFlightRequest(request)) {
    // Handle preflight completely
    corsProcessor.processRequest(config, request, response);
    return;  // DO NOT call chain.doFilter() — stop here!
}
// For non-preflight CORS requests: add headers AND continue chain
corsProcessor.processRequest(config, request, response);
chain.doFilter(request, response);
```

---

### 11.6 CorsFilter Internal Architecture

When `http.cors()` is configured in Spring Security:

```java
// Spring Security adds CorsFilter at the beginning of its chain
// (Actually uses CorsWebMvcConfigurer integration in Spring MVC context)

public class CorsFilter extends OncePerRequestFilter {

    private final CorsConfigurationSource configSource;
    private CorsProcessor processor = new DefaultCorsProcessor();

    @Override
    protected void doFilterInternal(HttpServletRequest request,
            HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        CorsConfiguration corsConfiguration =
            this.configSource.getCorsConfiguration(request);

        boolean isValid = this.processor.processRequest(
            corsConfiguration, request, response);

        if (!isValid || CorsUtils.isPreFlightRequest(request)) {
            // Invalid CORS request → processor already sent error
            // OR preflight → processor handled it, stop chain
            return;
        }

        // Valid non-preflight CORS request → add headers and continue
        filterChain.doFilter(request, response);
    }
}
```

**`DefaultCorsProcessor.processRequest()` logic:**

```
1. Is this even a CORS request? (Has Origin header?)
     NO  → Not CORS → skip (return true to continue chain)
     YES → continue

2. Is this a preflight (OPTIONS + AC-Request-Method)?
     YES:
          Validate Origin against allowed origins
          Validate Method against allowed methods
          Validate Headers against allowed headers
          → All valid: Write Allow headers + 200
          → Invalid: Write 403

     NO (actual CORS request):
          Validate Origin against allowed origins
          → Valid: Write Access-Control-Allow-Origin header
          → Invalid: Write 403
          Continue to next filter
```

---

### 11.7 CorsConfigurationSource — Configuration Deep Dive

```java
CorsConfiguration config = new CorsConfiguration();

// ── Allowed Origins ──────────────────────────────────────────────────
config.setAllowedOrigins(List.of(
    "https://frontend.com",
    "https://app.example.com"
));

// OR use patterns (Spring 5.3+):
config.setAllowedOriginPatterns(List.of(
    "https://*.example.com",  // any subdomain of example.com
    "http://localhost:[*]"    // any localhost port (dev)
));

// ── Allowed Methods ───────────────────────────────────────────────────
config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
// "*" for all methods — but explicit is better

// ── Allowed Headers ───────────────────────────────────────────────────
config.setAllowedHeaders(List.of("*"));
// OR explicit:
config.setAllowedHeaders(List.of(
    "Content-Type",
    "Authorization",
    "X-Requested-With",
    "Accept"
));

// ── Exposed Headers ───────────────────────────────────────────────────
// Headers JS can read beyond default (Cache-Control, Content-Type, etc.)
config.setExposedHeaders(List.of(
    "X-Total-Count",      // for pagination
    "X-Request-Id",       // for tracing
    "Authorization"       // for token refresh in response header
));

// ── Credentials ───────────────────────────────────────────────────────
config.setAllowCredentials(true);
// CRITICAL: Cannot use setAllowedOrigins("*") with allowCredentials=true!
// Must specify exact origins or use setAllowedOriginPatterns()

// ── Max Age (preflight cache) ─────────────────────────────────────────
config.setMaxAge(3600L);  // 1 hour — browser caches preflight response

// ── Register for URL patterns ─────────────────────────────────────────
UrlBasedCorsConfigurationSource source =
    new UrlBasedCorsConfigurationSource();
source.registerCorsConfiguration("/api/**", config);       // only /api/**
source.registerCorsConfiguration("/**", config);           // all paths
```

---

### 11.8 `allowCredentials=true` — The Wildcard Origin Trap

**The rule:**

```
If allowCredentials = true:
     Access-Control-Allow-Credentials: true
     Access-Control-Allow-Origin: MUST be specific origin (not *)

     WHY: If wildcard (*) were allowed with credentials,
          any site could make authenticated cross-origin requests
          → Credential theft / CSRF via CORS

If allowCredentials = false (or not set):
     Access-Control-Allow-Origin: * is allowed
     No cookies or Authorization headers sent cross-origin
```

**The `allowedOriginPatterns` solution:**

```java
// ❌ WRONG — throws exception at startup:
config.setAllowedOrigins(List.of("*"));
config.setAllowCredentials(true);
// IllegalArgumentException: "When allowCredentials is true,
// allowedOrigins cannot contain the special value '*'"

// ✓ CORRECT — explicit origins:
config.setAllowedOrigins(List.of("https://frontend.com"));
config.setAllowCredentials(true);

// ✓ CORRECT — patterns (Spring 5.3+):
config.setAllowedOriginPatterns(List.of("https://*.example.com"));
config.setAllowCredentials(true);
// Patterns bypass the wildcard restriction while still being flexible
// Each request: pattern matched against actual Origin header → specific value returned
```

---

### 11.9 `@CrossOrigin` vs `CorsConfigurationSource` — When Each Applies

```
@CrossOrigin processing path:
     Request → Spring Security Filters
          → DispatcherServlet
               → HandlerMapping with CorsInterceptor
                    → @CrossOrigin config applied HERE
                    → CORS headers added to response

CorsConfigurationSource (via http.cors()) processing path:
     Request → Spring Security Filters
          → CorsFilter (early in chain)
               → CORS headers added HERE
               → (Only then) → DispatcherServlet

Problem scenario:
     OPTIONS /api/data arrives unauthenticated
     Spring Security: anyRequest().authenticated()
     → Without http.cors(): rejected with 401 BEFORE @CrossOrigin fires
     → With http.cors(): CorsFilter handles OPTIONS preflight, returns 200 with CORS headers

RULE: Always use http.cors() + CorsConfigurationSource for Spring Security apps
      @CrossOrigin alone is insufficient when Spring Security is present
```

---

### 11.10 CORS in Spring Security 5.x vs 6.x

| Aspect | Spring Security 5.x | Spring Security 6.x |
|--------|--------------------|--------------------|
| Enable CORS | `.cors()` or `.cors().configurationSource()` | `.cors(cors -> cors.configurationSource(...))` |
| Default behavior | CORS disabled unless configured | CORS disabled unless configured |
| MVC integration | Auto-detects `CorsConfigurationSource` bean | Same |
| `.cors().disable()` | Available (explicitly disables) | `.cors(AbstractHttpConfigurer::disable)` |
| Filter position | Early in chain (before auth) | Same |

---

### 11.11 CORS With Multiple SecurityFilterChain Beans

```java
// Each SecurityFilterChain can have its own CORS config:

@Bean
@Order(1)
public SecurityFilterChain apiChain(HttpSecurity http) throws Exception {
    http
        .securityMatcher("/api/**")
        .cors(cors -> cors
            .configurationSource(apiCorsConfiguration()))  // permissive for API
        .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
        .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));
    return http.build();
}

@Bean
@Order(2)
public SecurityFilterChain webChain(HttpSecurity http) throws Exception {
    http
        .cors(cors -> cors
            .configurationSource(webCorsConfiguration()))  // stricter for web
        .formLogin(Customizer.withDefaults())
        .authorizeHttpRequests(auth -> auth.anyRequest().authenticated());
    return http.build();
}

@Bean
public CorsConfigurationSource apiCorsConfiguration() {
    CorsConfiguration config = new CorsConfiguration();
    config.setAllowedOriginPatterns(List.of("https://*.trusted-client.com"));
    config.setAllowedMethods(List.of("*"));
    config.setAllowedHeaders(List.of("*"));
    config.setAllowCredentials(true);
    UrlBasedCorsConfigurationSource source =
        new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", config);
    return source;
}
```

---

### 11.12 Global CORS Configuration via `WebMvcConfigurer`

```java
// Alternative: MVC-level global CORS (processed inside DispatcherServlet)
// Works WITH http.cors() — Spring Security detects this automatically

@Configuration
public class WebMvcConfig implements WebMvcConfigurer {

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/api/**")
            .allowedOrigins("https://frontend.com")
            .allowedMethods("GET", "POST", "PUT", "DELETE")
            .allowedHeaders("*")
            .allowCredentials(true)
            .maxAge(3600);
    }
}
```

**Integration with Spring Security:**
When `http.cors()` is called WITHOUT a `configurationSource()`, Spring Security looks for:
1. A `CorsConfigurationSource` bean in the context
2. A `CorsFilter` bean in the context
3. The `HandlerMappingIntrospector` (which picks up `WebMvcConfigurer.addCorsMappings()`)

Spring Security is smart enough to delegate to Spring MVC's CORS configuration if no explicit source is provided.

---

## 2️⃣ Code Examples

---

### Example 1 — Complete CORS Configuration for REST API + SPA

```java
@Configuration
@EnableWebSecurity
public class CorsSecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // ── CORS must come before authentication ──────────────────
            .cors(cors -> cors
                .configurationSource(corsConfigurationSource())
            )
            // ── No CSRF for stateless JWT API ─────────────────────────
            .csrf(AbstractHttpConfigurer::disable)
            // ── Authentication ────────────────────────────────────────
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(Customizer.withDefaults())
            )
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            .authorizeHttpRequests(auth -> auth
                .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                // Belt-and-suspenders: also permitAll OPTIONS explicitly
                // (CorsFilter handles it, but this ensures no other filter blocks)
                .requestMatchers("/api/public/**").permitAll()
                .anyRequest().authenticated()
            );

        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        // Allowed origins — explicit for credential support
        configuration.setAllowedOrigins(List.of(
            "https://app.example.com",
            "https://admin.example.com"
        ));

        // All standard HTTP methods
        configuration.setAllowedMethods(
            List.of("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"));

        // Common headers
        configuration.setAllowedHeaders(List.of(
            "Authorization",
            "Content-Type",
            "Accept",
            "Origin",
            "X-Requested-With",
            "Access-Control-Request-Method",
            "Access-Control-Request-Headers"
        ));

        // Headers JavaScript can read from response
        configuration.setExposedHeaders(List.of(
            "Access-Control-Allow-Origin",
            "Access-Control-Allow-Credentials",
            "Authorization"
        ));

        // Allow cookies and Authorization headers
        configuration.setAllowCredentials(true);

        // Cache preflight for 1 hour
        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source =
            new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}
```

---

### Example 2 — Development vs Production CORS (Profile-Based)

```java
@Configuration
@EnableWebSecurity
public class ProfileAwareCorsConfig {

    @Value("${app.cors.allowed-origins}")
    private List<String> allowedOrigins;

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(allowedOrigins);
        config.setAllowedMethods(List.of("*"));
        config.setAllowedHeaders(List.of("*"));
        config.setAllowCredentials(true);
        config.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source =
            new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }
}
```

```yaml
# application-dev.yml
app:
  cors:
    allowed-origins:
      - http://localhost:3000
      - http://localhost:4200
      - http://127.0.0.1:3000

# application-prod.yml
app:
  cors:
    allowed-origins:
      - https://app.example.com
      - https://admin.example.com
```

---

### Example 3 — Path-Specific CORS Configuration

```java
@Bean
public CorsConfigurationSource corsConfigurationSource() {
    UrlBasedCorsConfigurationSource source =
        new UrlBasedCorsConfigurationSource();

    // Public API — permissive (no credentials needed)
    CorsConfiguration publicConfig = new CorsConfiguration();
    publicConfig.setAllowedOrigins(List.of("*"));
    publicConfig.setAllowedMethods(List.of("GET", "OPTIONS"));
    publicConfig.setAllowedHeaders(List.of("Content-Type", "Accept"));
    publicConfig.setAllowCredentials(false);
    source.registerCorsConfiguration("/api/public/**", publicConfig);

    // Private API — strict (credentials required)
    CorsConfiguration privateConfig = new CorsConfiguration();
    privateConfig.setAllowedOrigins(List.of("https://app.example.com"));
    privateConfig.setAllowedMethods(
        List.of("GET","POST","PUT","DELETE","PATCH","OPTIONS"));
    privateConfig.setAllowedHeaders(List.of("*"));
    privateConfig.setAllowCredentials(true);
    privateConfig.setMaxAge(3600L);
    source.registerCorsConfiguration("/api/private/**", privateConfig);

    // Webhook — no CORS needed (server-to-server)
    // (Just don't register any config for /webhooks/**)

    return source;
}
```

---

### Example 4 — `allowedOriginPatterns` for Wildcard Subdomain

```java
@Bean
public CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration config = new CorsConfiguration();

    // Allow any subdomain of example.com (dev + prod subdomains)
    config.setAllowedOriginPatterns(List.of(
        "https://*.example.com",          // any subdomain
        "http://localhost:[*]",            // any localhost port
        "https://localhost:[8080-9090]"    // specific port range
    ));

    // allowedOriginPatterns works with allowCredentials=true
    // (Unlike allowedOrigins("*") which conflicts with credentials)
    config.setAllowCredentials(true);

    config.setAllowedMethods(List.of("*"));
    config.setAllowedHeaders(List.of("*"));
    config.setMaxAge(3600L);

    UrlBasedCorsConfigurationSource source =
        new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", config);
    return source;
}
```

---

### Example 5 — `@CrossOrigin` + `http.cors()` Together

```java
// Using both — http.cors() handles the security layer,
// @CrossOrigin provides method-level overrides

@Configuration
@EnableWebSecurity
public class HybridCorsConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // Global CORS — handles preflight correctly in security layer
            .cors(cors -> cors
                .configurationSource(globalCorsSource())
            )
            .authorizeHttpRequests(auth -> auth
                .anyRequest().authenticated()
            )
            .httpBasic(Customizer.withDefaults());
        return http.build();
    }

    @Bean
    public CorsConfigurationSource globalCorsSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(List.of("https://default-client.com"));
        config.setAllowedMethods(List.of("GET", "OPTIONS"));
        config.setAllowedHeaders(List.of("*"));
        UrlBasedCorsConfigurationSource source =
            new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }
}

// Controller with stricter per-method override:
@RestController
@RequestMapping("/api")
public class ApiController {

    // This method allows additional origins beyond global config
    // But: @CrossOrigin is processed at MVC level (after security)
    // http.cors() global config handles the preflight
    // @CrossOrigin MERGES with global config for the actual request
    @CrossOrigin(origins = "https://special-client.com",
                 methods = RequestMethod.GET)
    @GetMapping("/special-data")
    public String getSpecialData() { return "data"; }
}
```

---

### Example 6 — Incorrect CORS Configurations

```java
// ❌ WRONG 1 — CORS configured only via @CrossOrigin, no http.cors()
// Spring Security rejects OPTIONS preflight before @CrossOrigin fires
@RestController
public class ApiController {
    @CrossOrigin(origins = "https://frontend.com")
    @PostMapping("/data")
    public String post() { return "ok"; }
}
// http.cors() NOT configured in SecurityFilterChain
// → OPTIONS preflight → Spring Security → 401 (no auth)
// → 401 response has NO CORS headers
// → Browser sees CORS error, not 401

// ✓ CORRECT: Add http.cors() to SecurityFilterChain
http.cors(cors -> cors.configurationSource(corsConfigurationSource()));
```

```java
// ❌ WRONG 2 — allowCredentials=true with wildcard origin
CorsConfiguration config = new CorsConfiguration();
config.setAllowedOrigins(List.of("*"));
config.setAllowCredentials(true);  // ← IllegalArgumentException at startup!
// "When allowCredentials is true, allowedOrigins cannot contain '*'"

// ✓ CORRECT: Specific origins with credentials
config.setAllowedOrigins(List.of("https://frontend.com"));
config.setAllowCredentials(true);

// OR: Patterns with credentials
config.setAllowedOriginPatterns(List.of("https://*.example.com"));
config.setAllowCredentials(true);
```

```java
// ❌ WRONG 3 — Missing OPTIONS in allowedMethods
CorsConfiguration config = new CorsConfiguration();
config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE"));
// OPTIONS not included!
// → Preflight is an OPTIONS request
// → CorsProcessor: OPTIONS not in allowed methods
// → Rejects preflight with 403
// → Actual request never sent

// ✓ CORRECT: Always include OPTIONS
config.setAllowedMethods(
    List.of("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"));
```

```java
// ❌ WRONG 4 — Standalone CorsFilter without @Order(HIGHEST_PRECEDENCE)
@Bean
// Missing: @Order(Ordered.HIGHEST_PRECEDENCE)
public CorsFilter corsFilter() {
    // This filter may run AFTER Spring Security's DelegatingFilterProxy
    // → Spring Security processes request first → may reject before CORS filter
    // → Same problem: no CORS headers on 401/403 responses
    ...
}

// ✓ CORRECT: Ensure ordering
@Bean
@Order(Ordered.HIGHEST_PRECEDENCE)
public CorsFilter corsFilter() { ... }

// OR: Use http.cors() which handles ordering automatically
```

```java
// ❌ WRONG 5 — exposedHeaders not configured for custom response headers
CorsConfiguration config = new CorsConfiguration();
config.setAllowedOrigins(List.of("https://frontend.com"));
// Missing: config.setExposedHeaders(...)

// Response includes: X-Total-Count: 100
// JavaScript: response.headers.get('X-Total-Count') → null!
// Browser hides non-standard headers unless explicitly exposed

// ✓ CORRECT: Expose custom headers
config.setExposedHeaders(List.of("X-Total-Count", "X-Request-Id"));
```

---

## 3️⃣ Exam-Style Questions

---

**Q1 (MCQ):** When Spring Security is configured with `anyRequest().authenticated()` and CORS is NOT configured via `http.cors()`, what happens when a browser sends an OPTIONS preflight request?

A. 200 OK with CORS headers — Spring Security auto-handles OPTIONS
B. 403 Forbidden with CORS headers
C. 401 Unauthorized WITHOUT CORS headers — browser sees CORS error
D. OPTIONS requests always bypass Spring Security

**Answer: C**
Without `http.cors()`, the OPTIONS preflight reaches `AuthorizationFilter`. The anonymous user fails authentication → `AuthenticationEntryPoint` returns 401. The response has NO `Access-Control-Allow-*` headers because `CorsFilter` was never involved. The browser cannot read the 401 status — it only sees "CORS policy blocked the request."

---

**Q2 (MCQ):** Which statement is true about `Access-Control-Allow-Credentials: true` and `Access-Control-Allow-Origin: *`?

A. They can be used together — `*` means all origins including credentialed ones
B. They CANNOT be used together — credentials require a specific origin
C. They can be combined if `Access-Control-Allow-Headers: *` is also set
D. Spring Security automatically replaces `*` with the specific request origin when credentials are enabled

**Answer: B**
The CORS specification explicitly forbids combining `Access-Control-Allow-Credentials: true` with `Access-Control-Allow-Origin: *`. If credentials are allowed, the server must reflect the specific requesting origin. This is enforced by browsers AND by Spring Security which throws `IllegalArgumentException` at startup if you try to configure both.

---

**Q3 (Select All That Apply):** Which are true about Spring Security's `CorsFilter`?

A. It short-circuits (stops the filter chain) for valid preflight requests
B. It runs at order 500 in the Spring Security filter chain, before authentication
C. For actual CORS requests (non-preflight), it adds headers and continues the chain
D. Without `http.cors()`, `@CrossOrigin` handles preflight correctly
E. It uses `CorsConfigurationSource` to determine the CORS policy per request

**Answer: A, B, C, E**
D is false — `@CrossOrigin` is processed inside `DispatcherServlet`, AFTER Spring Security. Without `http.cors()`, preflighted requests may be rejected by Spring Security before reaching `DispatcherServlet`.

---

**Q4 (Code Prediction):**

```java
CorsConfiguration config = new CorsConfiguration();
config.setAllowedOrigins(List.of("https://frontend.com"));
config.setAllowedMethods(List.of("GET", "POST"));
// allowCredentials NOT set (defaults to false/null)
```

Browser sends:
```
OPTIONS /api/data
Origin: https://frontend.com
Access-Control-Request-Method: DELETE
```

What is the response?

**Answer: 403 Forbidden (preflight rejected)**
`DELETE` is not in `allowedMethods` (`List.of("GET", "POST")`). `DefaultCorsProcessor` validates the `Access-Control-Request-Method` against allowed methods. `DELETE` is not allowed → preflight rejected → 403 (or empty response without CORS headers). The actual DELETE request is never sent by the browser.

---

**Q5 (Scenario — The Classic Trap):**

A developer reports: "I configured CORS with `@CrossOrigin` on all my controllers, but I'm still getting CORS errors for POST requests. GET requests work fine."

Explain why and provide the solution.

**Answer:**
GET requests are simple requests (no preflight) — they go directly through to `DispatcherServlet` where `@CrossOrigin` adds CORS headers. They work fine.

POST requests with `Content-Type: application/json` (or with Authorization header) are preflighted requests. The browser first sends:
```
OPTIONS /api/endpoint
```

Spring Security's filter chain intercepts this OPTIONS request. With `anyRequest().authenticated()`, the anonymous OPTIONS request is rejected with 401. The response has NO `Access-Control-Allow-*` headers because `@CrossOrigin` inside `DispatcherServlet` never ran. The browser sees a CORS error.

**Solution:**
```java
// Add to SecurityFilterChain:
http.cors(cors -> cors
    .configurationSource(corsConfigurationSource())
);

@Bean
public CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration config = new CorsConfiguration();
    config.setAllowedOrigins(List.of("https://frontend.com"));
    config.setAllowedMethods(List.of("GET","POST","PUT","DELETE","OPTIONS"));
    config.setAllowedHeaders(List.of("*"));
    UrlBasedCorsConfigurationSource source =
        new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", config);
    return source;
}
```

---

**Q6 (Filter Order):**

A standalone `CorsFilter` bean is declared without `@Order`. Spring Security's `DelegatingFilterProxy` is registered in the servlet container. Which runs first?

**Answer:**
Without explicit `@Order`, the `CorsFilter` bean gets a default order (likely `Integer.MAX_VALUE` or unordered). `DelegatingFilterProxy` for Spring Security (`springSecurityFilterChain`) has a defined order. The relative ordering is unpredictable without `@Order`.

**Safe answer:** The behavior is undefined — Spring Security may run before `CorsFilter`, causing CORS errors for rejected requests. Always use `@Order(Ordered.HIGHEST_PRECEDENCE)` for standalone `CorsFilter` beans, OR use `http.cors()` which handles ordering automatically within Spring Security's chain.

---

**Q7 (allowedOriginPatterns):**

```java
config.setAllowedOriginPatterns(List.of("https://*.example.com"));
```

A request arrives with `Origin: https://sub.example.com`. What is returned in `Access-Control-Allow-Origin`?

**Answer: `https://sub.example.com`**
When `allowedOriginPatterns` is used, Spring Security doesn't return the wildcard pattern in the response header. Instead, it **reflects the actual request origin** (`https://sub.example.com`) in `Access-Control-Allow-Origin` — provided the origin matches the pattern. This enables `allowCredentials=true` to work with pattern-based origin matching, since the response always contains a specific origin value.

---

**Q8 (CORS vs CSRF):**

A developer disables CORS entirely (`http.cors(AbstractHttpConfigurer::disable)`) on a session-authenticated web app, believing this prevents CSRF attacks. Is the app protected from CSRF?

**Answer: NO.**
Disabling CORS does not prevent CSRF. CSRF exploits the browser's automatic cookie inclusion in cross-origin requests. Simple form submissions (POST from evil.com) are NOT subject to CORS preflight — they are "simple requests" that browsers send directly with cookies attached. The server processes them.

CORS only prevents JavaScript from **reading responses**. The attacker doesn't need to read the response — they just need the state-changing action (fund transfer, password change) to execute. CSRF tokens are required regardless of CORS configuration.

---

## 4️⃣ Trick Analysis

---

**Trick 1 — The CORS Error Is Often a Security Error In Disguise**

```
What developer sees in browser console:
"Access to XMLHttpRequest at 'https://api.example.com' from origin
'https://app.example.com' has been blocked by CORS policy:
No 'Access-Control-Allow-Origin' header is present on the requested resource."

What actually happened:
     Spring Security returned 401 or 403
     The security rejection response has NO CORS headers
     Browser cannot read the 401/403 response
     Browser reports it as a "CORS error"

Debugging tip:
     Open browser DevTools → Network tab
     Look at the actual OPTIONS or POST request
     Check the response status code (401? 403? 500?)
     The real problem is that status code — not CORS itself

Fix: Configure CORS correctly so Spring Security adds CORS headers
     even to error responses
```

---

**Trick 2 — `allowedMethods("*")` Still Requires OPTIONS in Some Configs**

```java
// In some Spring versions:
config.setAllowedMethods(List.of("*"));
// "*" may or may not include OPTIONS depending on version
// Explicit is always safer:
config.setAllowedMethods(
    List.of("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"));

// The CORS spec requires the server to list explicitly allowed methods
// in the preflight response — "*" for methods is less standard
```

---

**Trick 3 — `CorsConfiguration.applyPermitDefaultValues()`**

```java
// Quick setup for development — applies sensible defaults:
CorsConfiguration config = new CorsConfiguration();
config.applyPermitDefaultValues();
// Sets:
// allowedOrigins: "*"
// allowedMethods: GET, HEAD, POST
// allowedHeaders: "*"
// maxAge: 1800 (30 minutes)
// allowCredentials: NOT SET (null — browsers treat as false)

// Useful for development but too permissive for production
// Does NOT include PUT, DELETE, PATCH — common API methods
```

---

**Trick 4 — CORS Headers on Error Responses**

```java
// Spring Security's CorsFilter adds headers to ALL responses
// including error responses (401, 403, 500)

// This is important: without CORS headers on error responses,
// JavaScript cannot read the error status or body
// fetch('/api/data').catch(err => ...)
// → err doesn't tell you "401 Unauthorized"
// → It only says "CORS error" (browser hides the real status)

// With properly configured http.cors():
// → 401 response includes Access-Control-Allow-Origin
// → JavaScript CAN read the 401 status and handle it
// → SPA can redirect to login on 401
```

---

**Trick 5 — Max-Age Reduces OPTIONS Requests in Production**

```java
config.setMaxAge(3600L);  // Cache preflight for 1 hour

// Without maxAge:
// EVERY POST/PUT/DELETE request sends OPTIONS preflight first
// Double the number of HTTP requests for all mutating operations
// Significant performance impact for high-traffic APIs

// With maxAge=3600:
// Browser sends OPTIONS once, caches for 1 hour
// Subsequent requests: no preflight → single HTTP request
// Browser enforces max 7200 seconds (2 hours) regardless of what server says

// During development: use maxAge=0 to disable caching
// → Always sends OPTIONS → easier to debug CORS issues
```

---

**Trick 6 — `WebMvcConfigurer.addCorsMappings` vs `CorsConfigurationSource`**

```
When http.cors() is called without explicit CorsConfigurationSource:
Spring Security delegates to HandlerMappingIntrospector
→ Which uses WebMvcConfigurer.addCorsMappings() configuration

When http.cors() is called WITH explicit CorsConfigurationSource:
Spring Security uses that source directly
→ WebMvcConfigurer.addCorsMappings() is IGNORED for security layer

EXAM TRAP: "If I configure addCorsMappings() in WebMvcConfigurer
            and http.cors() without source, does it work?"
Answer: YES — Spring Security delegates to MVC configuration
        But if you provide CorsConfigurationSource explicitly, MVC config is bypassed
```

---

**Trick 7 — Exposed Headers Must Be Explicitly Listed**

```
Default "safe" headers JavaScript can always read:
     Cache-Control, Content-Language, Content-Length,
     Content-Type, Expires, Last-Modified, Pragma

Custom response headers are HIDDEN from JavaScript unless explicitly exposed:
     X-Total-Count: 500       ← JavaScript reads null without exposedHeaders
     X-Request-Id: abc-123    ← JavaScript reads null without exposedHeaders
     Authorization: Bearer..  ← Cannot be read for token refresh without exposure

Configuration:
     config.setExposedHeaders(List.of("X-Total-Count", "X-Request-Id"));
```

---

**Trick 8 — CORS Does Not Apply to Server-Side Requests**

```
CORS is a BROWSER mechanism.

Server-to-server requests:
     Java RestTemplate, WebClient, Feign → NO CORS
     curl, Postman → NO CORS
     Mobile apps → NO CORS (they're not browsers)

Only applies when:
     JavaScript running in a browser
     Makes a cross-origin XMLHttpRequest or fetch()

EXAM TRAP: "My integration tests with RestTemplate fail because of CORS"
Answer: That's IMPOSSIBLE — RestTemplate doesn't use browser CORS
        The actual issue is something else (auth, firewall, wrong URL)
```

---

## 5️⃣ Summary Sheet

---

### CORS Request Handling Diagram

```
Cross-Origin Request from Browser
     │
     ├──[Simple request: GET/POST with standard headers]────────────────────┐
     │                                                                       │
     └──[Complex request: PUT/DELETE/custom headers/JSON]                   │
               │                                                             │
               ▼                                                             │
     OPTIONS /api/endpoint (Preflight)                                      │
               │                                                             │
               ▼                                                             │
     Spring Security Filter Chain                                           │
               │                                                             │
               ▼                                                             ▼
     CorsFilter (order 500)                                    CorsFilter (order 500)
               │                                                             │
               ├── Is Origin allowed?  NO → 403 (no CORS headers)           │
               │                                                             │
               ├── Is Method allowed?  NO → 403                             │
               │                                                             │
               ├── Are Headers allowed? NO → 403                            │
               │                                                             │
               ├── Valid preflight → 200 + Access-Control-Allow-* headers   │
               │      STOP CHAIN (no auth, no controller)                   │
               │                                                             │
               ▼                                                             ▼
     Browser sends actual request                             Add CORS headers
               │                                             Continue chain
               ▼                                                             │
     Spring Security processes actual request                                ▼
     (auth, authorization, controller)               Controller processes request
```

---

### CORS Configuration Methods Comparison

| Method | Processed By | Handles Preflight | Recommended |
|--------|-------------|------------------|-------------|
| `@CrossOrigin` | Spring MVC (inside DispatcherServlet) | ❌ NO (Security rejects first) | ❌ Alone |
| `http.cors()` + `CorsConfigurationSource` | Spring Security `CorsFilter` | ✅ YES | ✅ Primary |
| `WebMvcConfigurer.addCorsMappings()` + `http.cors()` | Spring Security (delegates to MVC) | ✅ YES | ✅ Alternative |
| Standalone `CorsFilter` bean + `@Order(HIGHEST)` | Servlet container (before Spring Security) | ✅ YES | ✅ Works |

---

### CORS Headers Quick Reference

| Header | Direction | Purpose |
|--------|-----------|---------|
| `Origin` | Request | Browser's origin |
| `Access-Control-Request-Method` | Preflight request | Method of actual request |
| `Access-Control-Request-Headers` | Preflight request | Custom headers of actual request |
| `Access-Control-Allow-Origin` | Response | Which origin can read response |
| `Access-Control-Allow-Methods` | Preflight response | Allowed methods |
| `Access-Control-Allow-Headers` | Preflight response | Allowed custom headers |
| `Access-Control-Allow-Credentials` | Response | Allow cookies/auth headers |
| `Access-Control-Expose-Headers` | Response | Response headers JS can read |
| `Access-Control-Max-Age` | Preflight response | Cache duration for preflight |

---

### CORS vs CSRF One-Line Summary

```
CORS:  Browser restriction on READING cross-origin responses (SOP enforcement)
CSRF:  Server protection against FORGED cross-origin WRITE requests (cookie abuse)

CORS restricts: what JavaScript can read
CSRF prevents:  what browsers can submit on behalf of users

Disabling CORS does NOT prevent CSRF
Enabling CSRF does NOT prevent cross-origin data reading

Both needed independently in browser-based web applications
```

---

### Common Interview One-Liners

- **CORS does NOT block requests** — it only prevents JavaScript from reading responses
- **`http.cors()` must be configured** for Spring Security apps — `@CrossOrigin` alone fails for preflight
- **`CorsFilter` short-circuits** for valid preflight — returns 200 without hitting authentication
- **`allowCredentials=true` + `allowedOrigins("*")`** = `IllegalArgumentException` at startup
- **`allowedOriginPatterns`** enables wildcard subdomain matching with credentials support
- **Missing CORS headers on 401/403** = developer sees "CORS error" but real issue is security rejection
- **`exposedHeaders`** must be configured for custom response headers to be readable by JavaScript
- **`maxAge`** reduces preflight overhead — without it, every mutating request sends OPTIONS first
- **Server-to-server requests** (RestTemplate, WebClient) are NOT subject to CORS — browser-only mechanism
- **CORS and CSRF are complementary** — CORS prevents reading, CSRF prevents writing/state changes

---
