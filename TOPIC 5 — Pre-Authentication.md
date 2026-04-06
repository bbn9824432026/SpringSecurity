# TOPIC 5 — Pre-Authentication

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

---

## 1️⃣ Conceptual Explanation

---

### 5.1 What Is Pre-Authentication — Design Philosophy

Pre-authentication addresses a fundamentally different security scenario from form login or Basic auth. In pre-authentication, **the authentication decision has already been made by an external system** before the request reaches Spring Security. Spring Security's job is not to authenticate — it is to **trust and extract** the identity that was established externally.

**Real-world scenarios where pre-authentication applies:**

```
Scenario 1 — API Gateway / Reverse Proxy
     Internet → [Nginx / Kong / AWS API GW] → [Spring Boot App]
                         ↑
                 Gateway authenticates via OAuth2/OIDC
                 Passes identity as HTTP header:
                 X-Authenticated-User: alice
                 X-User-Roles: ROLE_ADMIN,ROLE_USER

Scenario 2 — Java EE Container Authentication
     [Servlet Container (Tomcat with LDAP realm)] → [Spring Boot App]
                         ↑
                 Container authenticates via LDAP
                 Exposes: request.getUserPrincipal() = alice
                           request.isUserInRole("ADMIN") = true

Scenario 3 — X.509 Client Certificate (Mutual TLS)
     [Client with certificate] → [TLS termination layer] → [Spring Boot App]
                                          ↑
                              Certificate verified at TLS level
                              javax.servlet.request.X509Certificate
                              attribute set on request

Scenario 4 — SSO / Shibboleth / Corporate IdP
     [Browser] → [Shibboleth SP] → [Spring Boot App]
                       ↑
               Shibboleth validates against SAML IdP
               Sets request attributes:
               REMOTE_USER = alice@corp.com
```

**The fundamental contract:**
In all these scenarios, Spring Security trusts the external system implicitly. There is no password to check, no credential to verify — only identity extraction and authority mapping.

---

### 5.2 AbstractPreAuthenticatedProcessingFilter — The Core Template

`AbstractPreAuthenticatedProcessingFilter` is an abstract base class that provides the template for all pre-authentication filters. It extends `GenericFilterBean`.

**The template method pattern:**

```java
public abstract class AbstractPreAuthenticatedProcessingFilter
        extends GenericFilterBean {

    // YOU MUST IMPLEMENT THESE TWO:
    protected abstract Object getPreAuthenticatedPrincipal(HttpServletRequest request);
    protected abstract Object getPreAuthenticatedCredentials(HttpServletRequest request);

    // THE TEMPLATE — handles the common flow:
    public void doFilter(ServletRequest request, ServletResponse response,
            FilterChain chain) throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;

        // Step 1: Extract principal from request
        Object principal = getPreAuthenticatedPrincipal(httpRequest);

        // Step 2: If no principal found → not a pre-auth request
        if (principal == null) {
            // checkForPrincipalChanges = false (default) → just continue
            chain.doFilter(request, response);
            return;
        }

        // Step 3: Check if already authenticated with SAME principal
        if (requiresAuthentication(httpRequest)) {

            // Step 4: Extract credentials (often just "N/A" for pre-auth)
            Object credentials = getPreAuthenticatedCredentials(httpRequest);

            // Step 5: Build PreAuthenticatedAuthenticationToken
            PreAuthenticatedAuthenticationToken authRequest =
                new PreAuthenticatedAuthenticationToken(principal, credentials);
            authRequest.setDetails(
                authenticationDetailsSource.buildDetails(httpRequest));

            // Step 6: Authenticate via AuthenticationManager
            Authentication authResult =
                authenticationManager.authenticate(authRequest);

            // Step 7: Store in SecurityContext
            successfulAuthentication(httpRequest, httpResponse, authResult);
        }

        chain.doFilter(request, response);
    }
}
```

**`requiresAuthentication()` logic:**

```java
protected boolean requiresAuthentication(HttpServletRequest request) {
    Authentication currentUser =
        SecurityContextHolder.getContext().getAuthentication();

    if (currentUser == null) return true;  // no auth yet → authenticate

    if (!checkForPrincipalChanges) return false;  // already auth, skip

    // Check if principal has changed (e.g., SSO identity switch)
    Object principal = getPreAuthenticatedPrincipal(request);
    if (!currentUser.getName().equals(principal)) {
        // Principal changed! Re-authenticate with new identity
        return true;
    }
    return false;
}
```

**`checkForPrincipalChanges` flag:**
When `true`, the filter re-authenticates if the pre-auth principal changes between requests on the same session. Critical for SSO scenarios where a user might switch identities within a session.

---

### 5.3 PreAuthenticatedAuthenticationToken — Structure

```java
PreAuthenticatedAuthenticationToken
     │
     ├── principal    = extracted identity (String username, X509Certificate, etc.)
     ├── credentials  = auxiliary data ("N/A", web details, certificate attributes)
     ├── authorities  = [] (empty initially — populated by UserDetailsService)
     └── authenticated = false (before) / true (after AuthenticationManager)
```

This token follows the same two-state lifecycle as `UsernamePasswordAuthenticationToken` but the principal is externally provided rather than user-submitted.

---

### 5.4 PreAuthenticatedAuthenticationProvider — The Trust Bridge

```java
public class PreAuthenticatedAuthenticationProvider
        implements AuthenticationProvider {

    private AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken>
        preAuthenticatedUserDetailsService;

    @Override
    public Authentication authenticate(Authentication authentication)
            throws AuthenticationException {

        // Trust the principal — DO NOT verify credentials
        PreAuthenticatedAuthenticationToken token =
            (PreAuthenticatedAuthenticationToken) authentication;

        // Load UserDetails to get authorities
        UserDetails userDetails =
            preAuthenticatedUserDetailsService.loadUserDetails(token);

        // Validate the loaded user (enabled, non-expired, etc.)
        userDetailsChecker.check(userDetails);

        // Return authenticated token with authorities
        PreAuthenticatedAuthenticationToken result =
            new PreAuthenticatedAuthenticationToken(
                userDetails,              // principal now = UserDetails
                token.getCredentials(),   // credentials unchanged
                userDetails.getAuthorities()  // populated authorities
            );
        result.setDetails(token.getDetails());
        return result;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return PreAuthenticatedAuthenticationToken.class
            .isAssignableFrom(authentication);
    }
}
```

**`AuthenticationUserDetailsService`** is distinct from `UserDetailsService`:

```java
// Regular UserDetailsService:
UserDetails loadUserByUsername(String username);

// AuthenticationUserDetailsService:
UserDetails loadUserDetails(T token);
// Receives the FULL token — can access credentials, details, not just username
// Useful when the token carries role information that should be mapped
```

---

### 5.5 X.509 Certificate Authentication — Deep Internals

X.509 is the most sophisticated pre-authentication mechanism. It uses **TLS client certificates** — the client presents a certificate during the TLS handshake that the server validates.

**Full X.509 flow:**

```
Step 1 — TLS Handshake:
Client → Server: ClientHello
Server → Client: ServerHello + Server Certificate
Client → Server: Client Certificate (if server requests it)
     └── Servlet container validates certificate chain
     └── Sets javax.servlet.request.X509Certificate[] attribute on request

Step 2 — Spring Security X.509 Processing:
X509AuthenticationFilter.getPreAuthenticatedPrincipal()
     └── cert = request.getAttribute("javax.servlet.request.X509Certificate")[0]
     └── Extracts Subject from certificate:
           CN=Alice Smith, OU=Engineering, O=Acme Corp, C=US
     └── principalExtractor.extractPrincipal(cert)
           └── SubjectDnX509PrincipalExtractor (default)
                 └── Applies regex to Subject DN
                 └── Default regex: "CN=(.*?)(?:,|$)"
                 └── Extracts: "Alice Smith"

Step 3 — Authentication:
AuthenticationManager → PreAuthenticatedAuthenticationProvider
     └── userDetailsService.loadUserByUsername("Alice Smith")
     └── Returns UserDetails with authorities from database
     └── Returns authenticated token
```

**`X509AuthenticationFilter`** is the concrete implementation of `AbstractPreAuthenticatedProcessingFilter` for X.509:

```java
public class X509AuthenticationFilter
        extends AbstractPreAuthenticatedProcessingFilter {

    @Override
    protected Object getPreAuthenticatedPrincipal(HttpServletRequest request) {
        X509Certificate[] certs = (X509Certificate[])
            request.getAttribute("javax.servlet.request.X509Certificate");

        if (certs != null && certs.length > 0) {
            return principalExtractor.extractPrincipal(certs[0]);
        }
        return null;
    }

    @Override
    protected Object getPreAuthenticatedCredentials(HttpServletRequest request) {
        X509Certificate[] certs = (X509Certificate[])
            request.getAttribute("javax.servlet.request.X509Certificate");
        return (certs != null && certs.length > 0) ? certs[0] : null;
    }
}
```

---

### 5.6 Header-Based Pre-Authentication — API Gateway Pattern

The most common modern pre-authentication pattern: an API gateway (Kong, AWS ALB, Nginx, Istio) authenticates the user and passes identity via HTTP headers.

**`RequestHeaderAuthenticationFilter`** — Spring Security's built-in header-based pre-auth filter:

```java
public class RequestHeaderAuthenticationFilter
        extends AbstractPreAuthenticatedProcessingFilter {

    private String principalRequestHeader = "SM_USER";  // default (SiteMinder)

    @Override
    protected Object getPreAuthenticatedPrincipal(HttpServletRequest request) {
        String principal = request.getHeader(this.principalRequestHeader);
        if (principal == null && this.exceptionIfHeaderMissing) {
            throw new PreAuthenticatedCredentialsNotFoundException(
                principalRequestHeader + " header not found in request");
        }
        return principal;
    }

    @Override
    protected Object getPreAuthenticatedCredentials(HttpServletRequest request) {
        return "N/A";  // No credentials needed — gateway already authenticated
    }
}
```

**Security concern — header spoofing:**

```
❌ CRITICAL VULNERABILITY if not handled:
Attacker sends: GET /api/admin HTTP/1.1
                X-Authenticated-User: admin

If Spring Security trusts this header directly without
validating it came from a trusted gateway → complete auth bypass!
```

**Protection strategies:**
1. **Network-level:** Only accept requests from gateway IP range (firewall rules)
2. **mTLS:** Require client certificate from gateway (mutual TLS between gateway and app)
3. **Shared secret header:** Gateway adds `X-Internal-Token: <HMAC-signed-value>` that app validates
4. **Remove headers at gateway:** Gateway strips any user-supplied identity headers before forwarding

---

### 5.7 Container-Managed Authentication (`J2eePreAuthenticatedProcessingFilter`)

When the servlet container handles authentication (Tomcat with LDAP realm, WebSphere, JBoss):

```java
public class J2eePreAuthenticatedProcessingFilter
        extends AbstractPreAuthenticatedProcessingFilter {

    @Override
    protected Object getPreAuthenticatedPrincipal(HttpServletRequest request) {
        return request.getUserPrincipal() != null
            ? request.getUserPrincipal().getName()
            : null;
    }

    @Override
    protected Object getPreAuthenticatedCredentials(HttpServletRequest request) {
        return "N/A";
    }
}
```

```java
// For role extraction from container:
public class J2eeBasedPreAuthenticatedWebAuthenticationDetailsSource
        implements AuthenticationDetailsSource<HttpServletRequest, ...> {

    // Extracts roles from request.isUserInRole("ROLE_ADMIN")
    // Bridges container security model to Spring Security GrantedAuthority
}
```

---

### 5.8 SecurityContext Propagation in Pre-Auth — Stateless vs Stateful

Pre-authentication filters follow the same `SecurityContextRepository` mechanism:

**Stateful (session-based):**
```
Request 1: Header X-User: alice
     → PreAuthFilter extracts alice
     → Authenticates, stores in SecurityContext
     → Context saved to session

Request 2: No header, session cookie present
     → SecurityContextHolderFilter loads from session
     → PreAuthFilter: requiresAuthentication() = false (already authenticated)
     → alice is still authenticated
```

**Stateless (JWT/API gateway pattern):**
```
Every Request: Header X-User: alice
     → SecurityContextHolderFilter: loads empty context
     → PreAuthFilter: extracts alice, authenticates every time
     → Context NOT saved to session
     → Next request repeats the process
```

**`checkForPrincipalChanges` with stateful sessions:**
```
Request 1: X-User: alice → authenticated as alice, stored in session
Request 2: X-User: bob (identity switched!) → checkForPrincipalChanges=true
     → requiresAuthentication() detects principal changed
     → invalidateSessionOnPrincipalChange=true → old session invalidated
     → Re-authenticates as bob
```

---

### 5.9 `UserDetailsByNameServiceWrapper` — Bridging the Services

When you have a `UserDetailsService` but need an `AuthenticationUserDetailsService`:

```java
// UserDetailsByNameServiceWrapper wraps a regular UserDetailsService
// to implement AuthenticationUserDetailsService
// It simply calls: userDetailsService.loadUserByUsername(token.getName())

AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> wrapper =
    new UserDetailsByNameServiceWrapper<>(myUserDetailsService);
```

This is the most common setup — your existing `UserDetailsService` works unchanged with pre-authentication.

---

## 2️⃣ Code Examples

---

### Example 1 — Header-Based Pre-Auth (API Gateway Pattern, 6.x)

```java
@Configuration
@EnableWebSecurity
public class PreAuthSecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http,
            AuthenticationManager authManager) throws Exception {

        // Build the pre-auth filter
        RequestHeaderAuthenticationFilter preAuthFilter =
            new RequestHeaderAuthenticationFilter();
        preAuthFilter.setPrincipalRequestHeader("X-Authenticated-User");
        preAuthFilter.setCredentialsRequestHeader("X-User-Roles");
        preAuthFilter.setAuthenticationManager(authManager);
        preAuthFilter.setExceptionIfHeaderMissing(false);
        preAuthFilter.afterPropertiesSet();

        http
            // Add pre-auth filter BEFORE UsernamePasswordAuthenticationFilter
            .addFilterBefore(preAuthFilter,
                UsernamePasswordAuthenticationFilter.class)
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/public/**").permitAll()
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
            )
            .sessionManagement(s -> s
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            .csrf(AbstractHttpConfigurer::disable);

        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager(
            UserDetailsService userDetailsService) {

        PreAuthenticatedAuthenticationProvider provider =
            new PreAuthenticatedAuthenticationProvider();

        // Wrap UserDetailsService for pre-auth
        provider.setPreAuthenticatedUserDetailsService(
            new UserDetailsByNameServiceWrapper<>(userDetailsService));

        return new ProviderManager(provider);
    }

    @Bean
    public UserDetailsService userDetailsService() {
        // Load user from DB by username (extracted from header)
        return username -> {
            // DB lookup omitted for brevity
            return User.builder()
                .username(username)
                .password("{noop}N/A")  // No password for pre-auth users
                .roles("USER")
                .build();
        };
    }
}
```

---

### Example 2 — X.509 Certificate Authentication

```java
@Configuration
@EnableWebSecurity
public class X509SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .anyRequest().authenticated()
            )
            .x509(x509 -> x509
                // Regex to extract username from certificate Subject DN
                // Certificate DN: "CN=alice, OU=Engineering, O=Acme, C=US"
                // Regex extracts: "alice"
                .subjectPrincipalRegex("CN=(.*?)(?:,|$)")

                // Load user details by extracted CN
                .userDetailsService(x509UserDetailsService())
            );

        return http.build();
    }

    @Bean
    public UserDetailsService x509UserDetailsService() {
        return username -> {
            // username = extracted CN from certificate
            return User.builder()
                .username(username)
                .password("{noop}N/A")
                .roles("USER", "CERT_USER")
                .build();
        };
    }
}
```

**Spring Boot application.properties for Tomcat SSL + client cert:**
```properties
server.ssl.enabled=true
server.ssl.key-store=classpath:server-keystore.p12
server.ssl.key-store-password=changeit
server.ssl.key-store-type=PKCS12

# Request (but don't require) client certificate
server.ssl.client-auth=want
# To REQUIRE client certificate:
# server.ssl.client-auth=need
```

---

### Example 3 — Custom Pre-Auth Filter (API Gateway with HMAC Validation)

```java
// Validates that the gateway header is signed with HMAC before trusting
public class GatewayPreAuthenticationFilter
        extends AbstractPreAuthenticatedProcessingFilter {

    private final String hmacSecret;
    private final HmacValidator hmacValidator;

    @Override
    protected Object getPreAuthenticatedPrincipal(HttpServletRequest request) {
        String username = request.getHeader("X-Gateway-User");
        String signature = request.getHeader("X-Gateway-Signature");
        String timestamp = request.getHeader("X-Gateway-Timestamp");

        if (username == null || signature == null) {
            return null;  // Not a gateway request
        }

        // Validate HMAC signature
        String payload = username + ":" + timestamp;
        if (!hmacValidator.validate(payload, signature, hmacSecret)) {
            throw new PreAuthenticatedCredentialsNotFoundException(
                "Invalid gateway signature — possible header spoofing attack");
        }

        // Validate timestamp freshness (prevent replay attacks)
        long requestTime = Long.parseLong(timestamp);
        long now = System.currentTimeMillis();
        if (Math.abs(now - requestTime) > 30_000) {  // 30 second window
            throw new PreAuthenticatedCredentialsNotFoundException(
                "Request timestamp too old — possible replay attack");
        }

        return username;
    }

    @Override
    protected Object getPreAuthenticatedCredentials(HttpServletRequest request) {
        return request.getHeader("X-Gateway-Roles");  // "ROLE_USER,ROLE_API"
    }
}
```

---

### Example 4 — Custom `AuthenticationUserDetailsService` (Role Extraction from Token)

```java
// When the gateway passes roles in the credentials header,
// extract them into GrantedAuthority objects
@Component
public class GatewayUserDetailsService
        implements AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserDetails(
            PreAuthenticatedAuthenticationToken token)
            throws UsernameNotFoundException {

        String username = (String) token.getPrincipal();
        String rolesHeader = (String) token.getCredentials();
        // credentials = "ROLE_USER,ROLE_API,ROLE_ADMIN"

        // Option A: Load from database (most common)
        User dbUser = userRepository.findByUsername(username)
            .orElseThrow(() -> new UsernameNotFoundException(
                "Pre-authenticated user not in local DB: " + username));

        // Option B: Trust gateway-provided roles (less common — only if gateway is trusted)
        List<GrantedAuthority> authorities = Arrays.stream(
                rolesHeader.split(","))
            .map(String::trim)
            .map(SimpleGrantedAuthority::new)
            .collect(Collectors.toList());

        return new org.springframework.security.core.userdetails.User(
            username, "{noop}N/A", true, true, true, true, authorities);
    }
}
```

---

### Example 5 — J2EE Container Authentication

```java
@Configuration
@EnableWebSecurity
public class ContainerAuthConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http,
            AuthenticationManager authManager) throws Exception {

        J2eePreAuthenticatedProcessingFilter filter =
            new J2eePreAuthenticatedProcessingFilter();
        filter.setAuthenticationManager(authManager);
        filter.afterPropertiesSet();

        http
            .addFilterBefore(filter, UsernamePasswordAuthenticationFilter.class)
            .authorizeHttpRequests(auth -> auth
                .anyRequest().authenticated()
            );

        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager(
            UserDetailsService uds) {

        PreAuthenticatedAuthenticationProvider provider =
            new PreAuthenticatedAuthenticationProvider();
        provider.setPreAuthenticatedUserDetailsService(
            new UserDetailsByNameServiceWrapper<>(uds));

        // J2EE role mapper
        J2eeBasedPreAuthenticatedWebAuthenticationDetailsSource detailsSource =
            new J2eeBasedPreAuthenticatedWebAuthenticationDetailsSource();
        detailsSource.setMappableRolesRetriever(
            new WebXmlMappableAttributesRetriever());  // reads web.xml roles
        detailsSource.setUserRoles2GrantedAuthoritiesMapper(
            new SimpleAttributes2GrantedAuthoritiesMapper());

        return new ProviderManager(provider);
    }
}
```

---

### Example 6 — Incorrect Pre-Auth Configurations

```java
// ❌ WRONG 1 — Pre-auth filter not registered in chain
// Defining the bean alone doesn't add it to filter chain
@Bean
public RequestHeaderAuthenticationFilter preAuthFilter() {
    // This bean is NOT added to the chain automatically
    // Must use: http.addFilterBefore(preAuthFilter, ...)
    return new RequestHeaderAuthenticationFilter();
}

// ✓ CORRECT
http.addFilterBefore(preAuthFilter(), UsernamePasswordAuthenticationFilter.class);
```

```java
// ❌ WRONG 2 — Missing afterPropertiesSet() call
RequestHeaderAuthenticationFilter filter = new RequestHeaderAuthenticationFilter();
filter.setPrincipalRequestHeader("X-User");
filter.setAuthenticationManager(authManager);
// Missing: filter.afterPropertiesSet();
// Result: InitializationException or NullPointerException at runtime
// afterPropertiesSet() validates required properties and initializes the filter

// ✓ CORRECT
filter.afterPropertiesSet();  // or use @Bean with InitializingBean contract
```

```java
// ❌ WRONG 3 — exceptionIfHeaderMissing=true for optional pre-auth
RequestHeaderAuthenticationFilter filter = new RequestHeaderAuthenticationFilter();
filter.setExceptionIfHeaderMissing(true);  // DEFAULT is true
// If ANY request arrives without X-User header → exception → 500 or 403
// This is correct for REQUIRED pre-auth (all requests must come via gateway)
// WRONG if you mix pre-auth with other auth (some requests don't have header)

// ✓ CORRECT for mixed auth scenarios:
filter.setExceptionIfHeaderMissing(false);
// Returns null principal → filter passes through → other auth filters handle it
```

```java
// ❌ WRONG 4 — Trusting header without network-level protection
// Anyone can send X-Authenticated-User: admin
// No HMAC, no mTLS, no IP filtering
http.addFilterBefore(
    new RequestHeaderAuthenticationFilter(),  // trusted blindly!
    UsernamePasswordAuthenticationFilter.class);
// Result: Complete authentication bypass — critical vulnerability
```

---

## 3️⃣ Exam-Style Questions

---

**Q1 (MCQ):** What is the primary responsibility of `AbstractPreAuthenticatedProcessingFilter`?

A. Verifying user credentials against a `UserDetailsService`
B. Extracting an externally-established identity from the request and building a security token
C. Delegating authentication to the servlet container
D. Validating JWT tokens from the `Authorization` header

**Answer: B**
The key word is "extracting externally-established identity." Pre-authentication does NOT verify credentials — it trusts that an external system already did that. It extracts the principal (header value, certificate CN, container principal) and delegates authority loading to `AuthenticationUserDetailsService`.

---

**Q2 (MCQ):** Which method MUST be implemented in a custom pre-authentication filter?

A. `doFilter()` and `afterPropertiesSet()`
B. `getPreAuthenticatedPrincipal()` and `getPreAuthenticatedCredentials()`
C. `authenticate()` and `supports()`
D. `loadUserDetails()` and `extractPrincipal()`

**Answer: B**
`AbstractPreAuthenticatedProcessingFilter` uses the Template Method pattern. The two abstract methods that subclasses must implement are `getPreAuthenticatedPrincipal()` and `getPreAuthenticatedCredentials()`. The `doFilter()` template handles everything else.

---

**Q3 (Select All That Apply):** Which are true about `PreAuthenticatedAuthenticationProvider`?

A. It verifies the password in `PreAuthenticatedAuthenticationToken.getCredentials()`
B. It calls `AuthenticationUserDetailsService.loadUserDetails()` to populate authorities
C. It supports `PreAuthenticatedAuthenticationToken` type via `supports()`
D. It throws `BadCredentialsException` if the user is not found in `UserDetailsService`
E. It runs `userDetailsChecker` to verify account status (enabled, non-locked, etc.)

**Answer: B, C, E**
A is false — pre-auth provider explicitly does NOT verify credentials. The external system already did that.
D is false — it throws `UsernameNotFoundException` (or delegates to `AuthenticationUserDetailsService` which may throw it). `BadCredentialsException` is for credential mismatch — irrelevant in pre-auth.

---

**Q4 (Scenario — Security Vulnerability):**

```java
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    RequestHeaderAuthenticationFilter filter =
        new RequestHeaderAuthenticationFilter();
    filter.setPrincipalRequestHeader("X-Remote-User");
    filter.setExceptionIfHeaderMissing(false);
    filter.setAuthenticationManager(authenticationManager());

    http
        .addFilterBefore(filter, UsernamePasswordAuthenticationFilter.class)
        .authorizeHttpRequests(auth -> auth
            .anyRequest().authenticated()
        );
    return http.build();
}
```

This service is deployed publicly on the internet. What is the critical vulnerability?

**Answer: Header Injection / Authentication Bypass.**
Any internet client can send `X-Remote-User: admin` in their request. `RequestHeaderAuthenticationFilter` will extract `"admin"` as the principal and authenticate the request as admin — without any credential verification. The service must be either:
1. Behind a reverse proxy that strips this header from client requests
2. Protected by network firewall (only accept from gateway IP)
3. Using HMAC-signed headers validated by the filter
4. Using mTLS for gateway-to-service communication

Without these, this is a critical auth bypass vulnerability.

---

**Q5 (Code Prediction):**

```java
RequestHeaderAuthenticationFilter filter = new RequestHeaderAuthenticationFilter();
filter.setPrincipalRequestHeader("X-User");
filter.setExceptionIfHeaderMissing(true);  // default
filter.setAuthenticationManager(authManager);
```

Request arrives: `GET /api/data` with no `X-User` header.

What happens?

A. Anonymous token is set and request continues
B. `PreAuthenticatedCredentialsNotFoundException` is thrown → 500 error
C. `null` principal returned, filter passes through
D. `UsernameNotFoundException` is thrown

**Answer: B**
With `exceptionIfHeaderMissing=true` (the default), if the configured header is absent, `RequestHeaderAuthenticationFilter` throws `PreAuthenticatedCredentialsNotFoundException`. This propagates as an authentication failure. The exact HTTP status depends on how `ExceptionTranslationFilter` handles it — typically results in 401 or propagates as a 500 if not properly handled.

---

**Q6 (X.509 Scenario):**

A certificate has the Subject DN:
`CN=john.doe@acme.com, OU=Finance, O=Acme Corp, C=US`

The Spring Security X.509 config uses default `subjectPrincipalRegex`:
`"CN=(.*?)(?:,|$)"`

What username is extracted and used to call `UserDetailsService`?

**Answer:** `"john.doe@acme.com"`
The regex `CN=(.*?)(?:,|$)` captures everything after `CN=` until the next comma or end of string. From the DN `CN=john.doe@acme.com, OU=Finance...`, it captures `"john.doe@acme.com"` (without the trailing comma/space). This exact string is passed to `userDetailsService.loadUserByUsername()`.

---

**Q7 (Filter Placement):**

You have a custom pre-auth filter. Where in the chain should it be placed?

A. After `AnonymousAuthenticationFilter`
B. After `ExceptionTranslationFilter`
C. Before `UsernamePasswordAuthenticationFilter`
D. After `SecurityContextHolderFilter` but at any position before `AuthorizationFilter`

**Answer: C and D (both correct, C is the conventional placement)**
Pre-auth filters must run:
- **After** `SecurityContextHolderFilter` (so SecurityContext is initialized)
- **Before** `AnonymousAuthenticationFilter` (so anonymous token isn't set before pre-auth runs)
- **Before** `AuthorizationFilter` (so authentication is established before access check)

Conventional placement is **before `UsernamePasswordAuthenticationFilter`** using `addFilterBefore()`. This is the standard position for all authentication filters that handle authentication differently from form login.

---

**Q8 (Trick Scenario — `checkForPrincipalChanges`):**

```java
filter.setCheckForPrincipalChanges(true);
filter.setInvalidateSessionOnPrincipalChange(true);
```

A user with an active session (authenticated as `alice`) makes a request. The gateway now sends `X-User: bob` (identity changed).

What does Spring Security do?

**Answer:**
1. `requiresAuthentication()` is called
2. Current principal: `"alice"` (from SecurityContext)
3. Request header principal: `"bob"`
4. `"alice".equals("bob")` → false → **re-authentication required**
5. `invalidateSessionOnPrincipalChange=true` → current session is **invalidated**
6. Filter re-authenticates as `"bob"`
7. New session created with bob's `SecurityContext`

This protects against identity reuse — if the gateway switches the user identity (e.g., SSO token refresh with a different user), the old session is invalidated to prevent session fixation.

---

## 4️⃣ Trick Analysis

---

**Trick 1 — Pre-Auth Filter Is NOT Auto-Registered**

Unlike form login (`.formLogin()`) and Basic auth (`.httpBasic()`), pre-authentication filters are NOT registered via a DSL shortcut (except X.509 which has `.x509()`). You must:

```java
// ❌ WRONG — bean defined but not in chain
@Bean
public RequestHeaderAuthenticationFilter preAuthFilter() { ... }

// ✓ CORRECT — explicitly add to chain
http.addFilterBefore(preAuthFilter(), UsernamePasswordAuthenticationFilter.class);
```

The only DSL method is `.x509()` for X.509. All other pre-auth filters require manual `addFilterBefore()`.

---

**Trick 2 — `afterPropertiesSet()` Must Be Called Manually**

`AbstractPreAuthenticatedProcessingFilter` implements `InitializingBean`. When you instantiate the filter manually (not as a Spring bean), `afterPropertiesSet()` is NOT called automatically:

```java
// ❌ Will fail — authenticationManager is required, not checked
RequestHeaderAuthenticationFilter filter = new RequestHeaderAuthenticationFilter();
filter.setPrincipalRequestHeader("X-User");
// Missing setAuthenticationManager() and afterPropertiesSet()

// ✓ Correct
filter.setAuthenticationManager(authManager);
filter.afterPropertiesSet();  // validates required properties
```

If you declare it as a `@Bean`, Spring calls `afterPropertiesSet()` automatically via `InitializingBean`. But inline instantiation requires manual call.

---

**Trick 3 — `credentials` in Pre-Auth Is Not a Password**

Pre-auth credentials (`getPreAuthenticatedCredentials()`) are NOT a password. They are **auxiliary data** attached to the token:

```
Form login:   credentials = raw password string
Pre-auth:     credentials = "N/A", or certificate object, or roles header

The PreAuthenticatedAuthenticationProvider NEVER checks credentials
It only loads UserDetails by principal name (or token content)
```

This confuses developers who expect a security check on credentials. In pre-auth, credentials are just metadata.

---

**Trick 4 — X.509 Requires Servlet Container SSL, Not Spring**

Spring Security's X.509 support does NOT handle TLS. The **servlet container** (Tomcat, Jetty) must be configured for SSL and client certificate validation. Spring Security only reads the `javax.servlet.request.X509Certificate` attribute that the container sets. If SSL is not configured on Tomcat, `X509AuthenticationFilter` always gets null and never activates.

---

**Trick 5 — `UserDetailsByNameServiceWrapper` vs `AuthenticationUserDetailsService`**

```java
// If you need ONLY username to load user (most common):
provider.setPreAuthenticatedUserDetailsService(
    new UserDetailsByNameServiceWrapper<>(myUserDetailsService));
// Internally calls: myUserDetailsService.loadUserByUsername(token.getName())

// If you need the FULL TOKEN to load user (roles in credentials header):
provider.setPreAuthenticatedUserDetailsService(
    new MyCustomAuthenticationUserDetailsService());
// Receives full PreAuthenticatedAuthenticationToken
// Can inspect credentials, details, not just principal name
```

The wrapper is a convenience. Custom `AuthenticationUserDetailsService` is for when you need more than just the username.

---

**Trick 6 — Pre-Auth + Session = Risk of Stale Identity**

```
Stateful session + pre-auth without checkForPrincipalChanges:

Request 1: X-User: alice → authenticated, session created
Request 2: Cookie: JSESSIONID (no X-User header, session used instead)
     → SecurityContextHolderFilter loads alice's context from session
     → PreAuthFilter: getAuthentication() is not null → SKIP
     → alice is authenticated (even though gateway didn't provide identity!)

ATTACK: Attacker steals session cookie → authenticated as alice
        without providing X-User header
```

For header-based pre-auth, use `STATELESS` session policy to prevent this. Or set `checkForPrincipalChanges=true` and require the header on every request (`exceptionIfHeaderMissing=true`).

---

**Trick 7 — X.509 `client-auth=want` vs `need`**

```properties
# want = request but don't require client certificate
# Certificate absent → request proceeds → X509AuthenticationFilter gets null → anonymous
server.ssl.client-auth=want

# need = require client certificate
# Certificate absent → TLS handshake fails → connection refused (400/SSL error)
server.ssl.client-auth=need
```

For `want`, unauthenticated requests still reach the application — form login or other auth can handle them. For `need`, ALL clients must have a certificate — good for service-to-service mTLS but bad for browser users who don't have client certs.

---

## 5️⃣ Summary Sheet

---

### Pre-Authentication Filter Chain Flow

```
HTTP Request (with gateway header / certificate / container principal)
     │
     ▼
[SecurityContextHolderFilter] — loads empty SecurityContext

     ▼
[AbstractPreAuthenticatedProcessingFilter subclass]
     │
     ├── getPreAuthenticatedPrincipal()
     │       ├── Header filter: request.getHeader("X-User")
     │       ├── X509 filter: cert[0] → SubjectDN → regex → CN value
     │       └── J2EE filter: request.getUserPrincipal().getName()
     │
     ├── principal == null? → chain.doFilter() (pass through)
     │
     ├── requiresAuthentication()?
     │       NO (same principal, already authenticated) → chain.doFilter()
     │       YES → continue
     │
     ├── getPreAuthenticatedCredentials() → "N/A" / cert / roles header
     │
     ├── Build PreAuthenticatedAuthenticationToken(principal, credentials)
     │
     ├── AuthenticationManager.authenticate(token)
     │       └── PreAuthenticatedAuthenticationProvider
     │               ├── Does NOT verify credentials
     │               ├── Calls AuthenticationUserDetailsService.loadUserDetails()
     │               │       └── Loads authorities from DB / token
     │               ├── Runs userDetailsChecker (enabled, locked, expired)
     │               └── Returns authenticated token with authorities
     │
     ├── SecurityContextHolder.setAuthentication(result)
     └── SecurityContextRepository.saveContext() (if stateful)

     ▼
[Rest of filter chain → AuthorizationFilter → Controller]
```

---

### Pre-Authentication Implementations Comparison

| Filter | Principal Source | Credentials | Use Case |
|--------|-----------------|-------------|----------|
| `RequestHeaderAuthenticationFilter` | HTTP header (`SM_USER` default) | Another header or `"N/A"` | API Gateway, SiteMinder, Shibboleth |
| `X509AuthenticationFilter` | X.509 certificate CN (via regex) | Full certificate object | mTLS, client certificates |
| `J2eePreAuthenticatedProcessingFilter` | `request.getUserPrincipal()` | `"N/A"` | Container-managed auth (Tomcat realm) |
| Custom extension | Any request attribute, cookie, etc. | Any auxiliary data | Custom SSO, SAML attributes |

---

### Key Configuration Properties

| Property | Default | Effect |
|----------|---------|--------|
| `exceptionIfHeaderMissing` | `true` | Throw exception if principal header absent |
| `checkForPrincipalChanges` | `false` | Re-auth if principal changes between requests |
| `invalidateSessionOnPrincipalChange` | `true` | Invalidate session when principal changes |
| `continueFilterChainOnUnsuccessfulAuthentication` | `true` | Continue chain even if pre-auth fails |

---

### Security Checklist for Pre-Authentication

```
□ Is the header/attribute source trusted? (network-level protection)
□ Is header spoofing prevented? (firewall, mTLS, HMAC)
□ Is session policy correct? (STATELESS for API, IF_REQUIRED for web)
□ Is checkForPrincipalChanges enabled for SSO scenarios?
□ Is afterPropertiesSet() called if manually instantiated?
□ Is exceptionIfHeaderMissing correct for your deployment?
□ Is UserDetailsService loading correct authorities?
□ For X.509: Is Tomcat configured for SSL + client auth?
```

---

### Common Interview One-Liners

- **Pre-authentication** trusts an external system — Spring Security **extracts identity**, not verifies it
- **`getPreAuthenticatedCredentials()`** returns `"N/A"` in most cases — it is NOT a password
- **`PreAuthenticatedAuthenticationProvider`** loads authorities but **never verifies credentials**
- **`RequestHeaderAuthenticationFilter`** is vulnerable to header spoofing without network-level protection
- **`X509AuthenticationFilter`** reads `javax.servlet.request.X509Certificate` — set by container, not Spring
- **`UserDetailsByNameServiceWrapper`** adapts a `UserDetailsService` to `AuthenticationUserDetailsService`
- **`afterPropertiesSet()`** must be called manually when instantiating filters outside Spring context
- **`exceptionIfHeaderMissing=true`** (default) breaks mixed-auth scenarios — set `false` for optional pre-auth
- **`checkForPrincipalChanges=true`** re-authenticates when gateway switches user identity
- **Stateful session + header pre-auth** = stale identity risk — prefer `STATELESS` for API gateway pattern

---
