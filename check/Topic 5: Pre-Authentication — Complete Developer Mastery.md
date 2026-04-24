# Topic 5: Pre-Authentication — Complete Developer Mastery

Pre-authentication represents a fundamental shift in Spring Security's mental model. In every topic so far, Spring Security *owned* the authentication decision — it extracted credentials, verified them, and made a trust determination. Pre-authentication inverts this entirely: the trust decision has already been made by something else, and Spring Security's job is to *accept and translate* that external decision into its own security model. Understanding this inversion is the entire conceptual key to the topic.

---

## Layer 1: The Design Philosophy — Trust vs Verify

Before touching any code, you need to internalize the three distinct architectural scenarios Spring Security must handle, because each represents a different answer to "who decides if this user is who they claim to be?"

In form login, Spring Security decides — it holds the credentials, runs BCrypt, makes the call. In HTTP Basic, Spring Security decides again — it decodes the header and runs the same pipeline. In pre-authentication, an external system decided *before the request arrived*, and Spring Security must simply trust that decision and extract the resulting identity.

```
Form Login / Basic Auth model:
   Client → Spring Security → "Let me check your credentials" → Decision

Pre-Authentication model:
   Client → [API Gateway / TLS layer / Container] → Spring Security
                           ↑
               "Already checked. Trust me. User is alice."
               Spring Security's job: "OK, what can alice do?"
```

The practical scenarios where this applies all share the same pattern — some infrastructure layer has verified the identity and communicates it to your application through a trustworthy channel:

```
API Gateway (Kong, AWS ALB, Nginx):
  Verifies OAuth2 token → passes X-Authenticated-User: alice header

TLS Mutual Authentication:
  Client presents X.509 certificate → TLS layer verifies it →
  container sets javax.servlet.request.X509Certificate attribute

Java EE Container (Tomcat with LDAP realm):
  Container authenticates via LDAP → exposes request.getUserPrincipal()

Corporate SSO / Shibboleth:
  Shibboleth SP validates SAML assertion → sets REMOTE_USER attribute
```

In all four cases, the verification work is done. Spring Security's job is identity *extraction* and authority *mapping*, not credential *verification*.

---

## Layer 2: `AbstractPreAuthenticatedProcessingFilter` — The Template Engine

This abstract class is the architectural backbone of all pre-authentication. It uses the Template Method pattern — it provides the complete orchestration logic and leaves exactly two methods abstract for subclasses to implement: `getPreAuthenticatedPrincipal()` and `getPreAuthenticatedCredentials()`. Everything else — the security context management, the re-authentication check, the token construction, the delegation to `AuthenticationManager` — is handled by the template.

```java
/**
 * LAYER 2: AbstractPreAuthenticatedProcessingFilter — the complete template.
 *
 * Extends GenericFilterBean (NOT OncePerRequestFilter, NOT AbstractAuthenticationProcessingFilter).
 * This matters because it needs to run on every request AND it doesn't need
 * the "execute exactly once per dispatch" guarantee — it manages that itself
 * via the requiresAuthentication() check.
 *
 * The two abstract methods are the ONLY things you implement in a subclass.
 * Everything else is inherited template logic.
 */
public abstract class AbstractPreAuthenticatedProcessingFilter
        extends GenericFilterBean implements ApplicationEventPublisherAware {

    // ─── THE TWO ABSTRACT METHODS YOU MUST IMPLEMENT ─────────────────────────

    /**
     * WHERE is the pre-authenticated principal in this request?
     * Returns null if this request doesn't carry a pre-auth identity.
     *
     * Examples:
     *   Header filter:  return request.getHeader("X-Authenticated-User");
     *   X.509 filter:   return extractCNFromCertificate(request);
     *   J2EE filter:    return request.getUserPrincipal().getName();
     */
    protected abstract Object getPreAuthenticatedPrincipal(HttpServletRequest request);

    /**
     * WHAT auxiliary data accompanies the principal?
     * This is NOT a password. It's metadata — roles header, certificate object, etc.
     * Often just returns "N/A" because nothing useful is available.
     *
     * The PreAuthenticatedAuthenticationProvider NEVER verifies this.
     * It's passed through to the token for downstream use only.
     */
    protected abstract Object getPreAuthenticatedCredentials(HttpServletRequest request);

    // ─── THE TEMPLATE (you never override this) ───────────────────────────────

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;

        // STEP 1: Extract principal from request
        // If null → not a pre-auth request → pass through transparently
        Object principal = getPreAuthenticatedPrincipal(request);
        if (principal == null) {
            chain.doFilter(request, response);
            return;
        }

        // STEP 2: Should we (re)authenticate?
        // Returns false if already authenticated with the SAME principal.
        // Returns true if: no auth yet, OR principal changed (if checkForPrincipalChanges=true)
        if (!requiresAuthentication(request)) {
            chain.doFilter(request, response);
            return;
        }

        // STEP 3: Build the unauthenticated token
        Object credentials = getPreAuthenticatedCredentials(request);
        PreAuthenticatedAuthenticationToken authRequest =
            new PreAuthenticatedAuthenticationToken(principal, credentials);
        authRequest.setDetails(authenticationDetailsSource.buildDetails(request));

        // STEP 4: Delegate to AuthenticationManager
        // This will call PreAuthenticatedAuthenticationProvider, which loads
        // authorities from your UserDetailsService — but NEVER checks credentials.
        try {
            Authentication authResult =
                this.authenticationManager.authenticate(authRequest);
            successfulAuthentication(request, response, authResult);
        } catch (AuthenticationException failed) {
            unsuccessfulAuthentication(request, response, failed);
            if (!continueFilterChainOnUnsuccessfulAuthentication) return;
        }

        chain.doFilter(request, response);
    }

    /**
     * STEP 2 detail: the re-authentication decision.
     *
     * This is more nuanced than it looks. The checkForPrincipalChanges flag
     * enables detection of SSO identity switches within an existing session —
     * critical for enterprise environments where a proxy might change the
     * forwarded user identity without the session being invalidated.
     */
    protected boolean requiresAuthentication(HttpServletRequest request) {
        Authentication currentAuth = SecurityContextHolder.getContext().getAuthentication();

        if (currentAuth == null) return true; // no auth yet — definitely authenticate

        if (!this.checkForPrincipalChanges) return false; // already auth, skip

        // Principal changed? Re-authenticate with new identity.
        Object newPrincipal = getPreAuthenticatedPrincipal(request);
        if (!currentAuth.getName().equals(newPrincipal)) {
            if (this.invalidateSessionOnPrincipalChange) {
                // Destroy the old session — prevents stale identity reuse
                SecurityContextHolder.clearContext();
                HttpSession session = request.getSession(false);
                if (session != null) session.invalidate();
            }
            return true; // re-authenticate as the new principal
        }

        return false; // same principal, same session, skip
    }
}
```

The `requiresAuthentication()` method is worth dwelling on. Its `checkForPrincipalChanges` behavior addresses a specific enterprise attack scenario: if an API gateway switches the forwarded user identity (e.g., because the OAuth2 token was refreshed with different claims), the old session must be invalidated. Without this flag, an attacker who steals a session cookie could continue operating as the original user even after the gateway says the identity changed.

---

## Layer 3: `PreAuthenticatedAuthenticationToken` — The Two-State Token

```java
/**
 * LAYER 3: PreAuthenticatedAuthenticationToken — same dual lifecycle as
 * UsernamePasswordAuthenticationToken, but the principal is externally provided.
 *
 * BEFORE authentication (created by the filter):
 *   principal   = extracted value ("alice", certificate CN, etc.)
 *   credentials = auxiliary data ("N/A", roles header, certificate object)
 *   authorities = []   (empty — not yet loaded from UserDetailsService)
 *   authenticated = false
 *
 * AFTER authentication (returned by PreAuthenticatedAuthenticationProvider):
 *   principal   = UserDetails object (loaded from DB)
 *   credentials = same as before (unchanged)
 *   authorities = [ROLE_USER, ROLE_API, ...]  (loaded from UserDetailsService)
 *   authenticated = true
 *
 * The critical design difference from UsernamePasswordAuthenticationToken:
 * THERE IS NO CREDENTIAL VERIFICATION. The provider loads authorities but
 * never calls passwordEncoder.matches(). The trust is implicit.
 */

// Created by filter (unauthenticated):
PreAuthenticatedAuthenticationToken unverified =
    new PreAuthenticatedAuthenticationToken("alice", "N/A");
// principal = String "alice", credentials = "N/A", authenticated = false

// Returned by provider (authenticated):
PreAuthenticatedAuthenticationToken verified =
    new PreAuthenticatedAuthenticationToken(userDetails, "N/A", userDetails.getAuthorities());
// principal = UserDetails, credentials = "N/A", authenticated = true
```

---

## Layer 4: `PreAuthenticatedAuthenticationProvider` — The Trust Bridge

This provider is the heart of the semantic difference between pre-authentication and regular authentication. It explicitly *skips* credential verification and goes straight to authority loading.

```java
/**
 * LAYER 4: PreAuthenticatedAuthenticationProvider — the authority loader.
 *
 * This provider does exactly ONE thing: loads the UserDetails for the
 * pre-authenticated principal to get their authorities.
 *
 * It does NOT:
 *   - Check passwords
 *   - Verify any credentials
 *   - Perform any cryptographic operation
 *
 * It DOES:
 *   - Call AuthenticationUserDetailsService.loadUserDetails(token)
 *   - Run userDetailsChecker (enabled, non-locked, non-expired)
 *   - Return an authenticated token with populated authorities
 */
public class PreAuthenticatedAuthenticationProvider implements AuthenticationProvider {

    // Note: AuthenticationUserDetailsService<T>, not UserDetailsService
    // The difference: receives the full Authentication token, not just a username string.
    // This allows the service to inspect credentials (e.g., roles header) if needed.
    private AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken>
        preAuthenticatedUserDetailsService;

    // Validates account status — same checks as DaoAuthenticationProvider:
    // enabled, non-expired, non-locked, credentials-non-expired
    private UserDetailsChecker userDetailsChecker = new AccountStatusUserDetailsChecker();

    @Override
    public Authentication authenticate(Authentication authentication)
            throws AuthenticationException {

        PreAuthenticatedAuthenticationToken token =
            (PreAuthenticatedAuthenticationToken) authentication;

        // Load UserDetails by principal (and optionally credentials)
        // NEVER verifies credentials — just loads authorities from your data store
        UserDetails userDetails =
            preAuthenticatedUserDetailsService.loadUserDetails(token);

        // Account status checks — same as DaoAuthenticationProvider:
        userDetailsChecker.check(userDetails);

        // Build the authenticated token with loaded authorities
        PreAuthenticatedAuthenticationToken result =
            new PreAuthenticatedAuthenticationToken(
                userDetails,                    // principal is now UserDetails
                token.getCredentials(),         // credentials unchanged (still "N/A")
                userDetails.getAuthorities()    // authorities loaded from DB
            );
        result.setDetails(token.getDetails());
        return result; // authenticated = true
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return PreAuthenticatedAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
```

Now let's look at `AuthenticationUserDetailsService` and why it's distinct from `UserDetailsService`:

```java
/**
 * AuthenticationUserDetailsService<T extends Authentication>
 * vs
 * UserDetailsService
 *
 * The difference is what you receive as input.
 *
 * UserDetailsService:             loadUserByUsername(String username)
 *   → You get ONLY the username string. Simple but limited.
 *
 * AuthenticationUserDetailsService: loadUserDetails(T token)
 *   → You get the ENTIRE Authentication token.
 *   → You can inspect token.getPrincipal(), token.getCredentials(), token.getDetails()
 *   → Essential when the gateway passes roles in the credentials header and you
 *     want to map those directly instead of loading from the database.
 *
 * UserDetailsByNameServiceWrapper is the bridge: it wraps a UserDetailsService
 * to implement AuthenticationUserDetailsService, by simply calling
 * userDetailsService.loadUserByUsername(token.getName()).
 * Use this when you only need the username to look up your user — which is most cases.
 */

// The wrapper — adapts your existing UserDetailsService for pre-auth:
AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> adapted =
    new UserDetailsByNameServiceWrapper<>(myExistingUserDetailsService);
// Internally: myExistingUserDetailsService.loadUserByUsername(token.getName())

// Custom implementation — when you need more than the username:
public class GatewayRolesMappingService
        implements AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserDetails(PreAuthenticatedAuthenticationToken token)
            throws UsernameNotFoundException {

        String username = (String) token.getPrincipal();
        // The credentials contain the roles header from the gateway:
        // "ROLE_USER,ROLE_API_READ,ROLE_REPORTING"
        String rolesHeader = (String) token.getCredentials();

        // Optionally verify user exists in local DB (audit trail, deactivation, etc.)
        User dbUser = userRepository.findByUsername(username)
            .orElseThrow(() -> new UsernameNotFoundException(
                "Pre-authenticated user not found: " + username));

        if (!dbUser.isEnabled()) {
            throw new DisabledException("Account deactivated: " + username);
        }

        // Map gateway roles to GrantedAuthority objects
        List<GrantedAuthority> authorities = Arrays.stream(rolesHeader.split(","))
            .map(String::trim)
            .filter(r -> !r.isBlank())
            .map(SimpleGrantedAuthority::new)
            .collect(Collectors.toList());

        return new org.springframework.security.core.userdetails.User(
            username, "{noop}N/A", true, true, true, true, authorities);
    }
}
```

---

## Layer 5: `RequestHeaderAuthenticationFilter` — API Gateway Pattern

This is the most common pre-authentication use case in modern microservices. An API gateway authenticates the user and forwards their identity in an HTTP header.

```java
/**
 * LAYER 5: RequestHeaderAuthenticationFilter — the built-in header pre-auth.
 *
 * Used when an API gateway (Kong, AWS ALB, Nginx, Istio) has already
 * authenticated the user and passes identity via a trusted HTTP header.
 *
 * Default header name is "SM_USER" (SiteMinder legacy) — always override this.
 * Default exceptionIfHeaderMissing=true — controls behavior when header is absent.
 */
public class RequestHeaderAuthenticationFilter
        extends AbstractPreAuthenticatedProcessingFilter {

    private String principalRequestHeader = "SM_USER"; // always override
    private String credentialsRequestHeader;            // optional secondary header
    private boolean exceptionIfHeaderMissing = true;    // critical flag — read below

    @Override
    protected Object getPreAuthenticatedPrincipal(HttpServletRequest request) {
        String principal = request.getHeader(this.principalRequestHeader);

        if (principal == null) {
            if (this.exceptionIfHeaderMissing) {
                // Throws PreAuthenticatedCredentialsNotFoundException
                // → caught by ExceptionTranslationFilter → 401 response
                throw new PreAuthenticatedCredentialsNotFoundException(
                    principalRequestHeader + " header not found");
            }
            return null; // filter passes through transparently
        }
        return principal;
    }

    @Override
    protected Object getPreAuthenticatedCredentials(HttpServletRequest request) {
        if (this.credentialsRequestHeader != null) {
            return request.getHeader(this.credentialsRequestHeader);
        }
        return "N/A"; // most common — no useful credentials from gateway
    }
}
```

The `exceptionIfHeaderMissing` flag is one of the most important configuration decisions for this filter. The right setting depends entirely on your deployment model:

```java
/**
 * exceptionIfHeaderMissing decision guide:
 *
 * true (default):  EVERY request MUST have the principal header.
 *   → Use when: all requests come through the gateway (enforced at network level).
 *   → A missing header means something bypassed the gateway — reject it loudly.
 *   → Missing header → PreAuthenticatedCredentialsNotFoundException → 401
 *
 * false:           The header is optional — other auth mechanisms may handle it.
 *   → Use when: some requests come from gateway (with header), others from
 *     direct clients using form login or Basic auth.
 *   → Missing header → null principal → filter passes through transparently
 *   → Other auth filters (UsernamePasswordAuth, BasicAuth) handle those requests
 */

// Pure gateway deployment — every request must have the header:
filter.setExceptionIfHeaderMissing(true);  // default — makes sense here

// Mixed deployment — gateway + direct browser access:
filter.setExceptionIfHeaderMissing(false); // let other filters handle non-gateway requests
```

---

## Layer 6: The Header Spoofing Vulnerability — The Most Critical Security Concern

This deserves its own layer because it's the most dangerous mistake in pre-authentication and it's invisible in code review.

```java
/**
 * LAYER 6: The header injection vulnerability.
 *
 * RequestHeaderAuthenticationFilter blindly trusts whatever is in the
 * configured header. If your application is publicly accessible, ANY
 * client can send that header with any value.
 *
 * Attack: curl -H "X-Authenticated-User: admin" http://your-api.com/api/admin/users
 * Result: Authenticated as admin with no credentials whatsoever.
 *
 * This is a CRITICAL authentication bypass. The fix is never in Spring Security
 * code alone — it requires infrastructure-level protection.
 */

// ─── VULNERABLE configuration ────────────────────────────────────────────────
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    RequestHeaderAuthenticationFilter filter = new RequestHeaderAuthenticationFilter();
    filter.setPrincipalRequestHeader("X-Authenticated-User");
    filter.setAuthenticationManager(authenticationManager());
    // ← No protection at all. Any client can send this header.

    http.addFilterBefore(filter, UsernamePasswordAuthenticationFilter.class);
    return http.build();
}
```

There are four protection strategies, and you should layer them:

```java
/**
 * Strategy 1: Custom filter with HMAC signature validation.
 *
 * The gateway signs the identity headers with a shared HMAC secret.
 * The application verifies the signature before trusting any header.
 * Attackers can't forge valid signatures without the secret.
 */
public class HmacValidatingGatewayFilter
        extends AbstractPreAuthenticatedProcessingFilter {

    private final String hmacSecret;
    private static final long TIMESTAMP_TOLERANCE_MS = 30_000; // 30 seconds

    @Override
    protected Object getPreAuthenticatedPrincipal(HttpServletRequest request) {
        String username  = request.getHeader("X-Gateway-User");
        String timestamp = request.getHeader("X-Gateway-Timestamp");
        String signature = request.getHeader("X-Gateway-Signature");

        if (username == null || timestamp == null || signature == null) {
            return null; // not a gateway request
        }

        // Validate freshness — prevents replay attacks
        // An attacker who intercepts a valid signed request can't reuse it
        // after 30 seconds
        long requestTime;
        try {
            requestTime = Long.parseLong(timestamp);
        } catch (NumberFormatException e) {
            throw new PreAuthenticatedCredentialsNotFoundException("Invalid timestamp format");
        }

        if (Math.abs(System.currentTimeMillis() - requestTime) > TIMESTAMP_TOLERANCE_MS) {
            throw new PreAuthenticatedCredentialsNotFoundException(
                "Request timestamp expired — possible replay attack");
        }

        // Validate HMAC signature
        // Gateway computes: HMAC-SHA256(username + ":" + timestamp, secret)
        // Application verifies the same
        String expectedSignature = computeHmac(username + ":" + timestamp, hmacSecret);
        if (!MessageDigest.isEqual(
                expectedSignature.getBytes(StandardCharsets.UTF_8),
                signature.getBytes(StandardCharsets.UTF_8))) {
            throw new PreAuthenticatedCredentialsNotFoundException(
                "Invalid gateway signature — possible header spoofing");
        }

        return username;
    }

    @Override
    protected Object getPreAuthenticatedCredentials(HttpServletRequest request) {
        return request.getHeader("X-Gateway-Roles"); // "ROLE_USER,ROLE_API"
    }

    private String computeHmac(String data, String secret) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            return Base64.getEncoder().encodeToString(
                mac.doFinal(data.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new RuntimeException("HMAC computation failed", e);
        }
    }
}
```

Beyond application-level HMAC validation, the other strategies are infrastructure concerns: configure your firewall to only accept traffic from the gateway's IP range, use mTLS between gateway and application so the gateway presents a client certificate, and configure the gateway to strip any user-supplied identity headers before forwarding requests. Defense in depth means using multiple strategies together.

---

## Layer 7: X.509 Certificate Authentication — The Complete Flow

X.509 is the most sophisticated pre-authentication mechanism, and understanding it requires thinking at three levels simultaneously: the TLS protocol layer, the servlet container layer, and the Spring Security layer. Each layer has a distinct responsibility.

```java
/**
 * LAYER 7: X.509 authentication — three layers doing three different jobs.
 *
 * TLS LAYER (handled by your network infrastructure):
 *   Client presents certificate during TLS handshake.
 *   Server validates certificate chain against trusted CA.
 *   If valid: TLS connection established.
 *   If invalid: TLS handshake fails — request never reaches application.
 *
 * SERVLET CONTAINER LAYER (Tomcat/Jetty configuration):
 *   Container extracts the verified certificate from the TLS connection.
 *   Sets it as request attribute: "javax.servlet.request.X509Certificate"
 *   This attribute holds an X509Certificate[] array.
 *   Spring Security reads this attribute — it does NOT do TLS termination.
 *
 * SPRING SECURITY LAYER (X509AuthenticationFilter):
 *   Reads the certificate from the request attribute.
 *   Extracts the principal (usually CN from Subject DN) via regex.
 *   Calls UserDetailsService to load authorities for that principal.
 *   Sets SecurityContext with authenticated token.
 */

// ─── Tomcat SSL configuration (application.properties) ───────────────────────
// server.ssl.enabled=true
// server.ssl.key-store=classpath:server-keystore.p12
// server.ssl.key-store-password=changeit
// server.ssl.key-store-type=PKCS12
// server.ssl.trust-store=classpath:ca-truststore.p12     ← trusted CA for client certs
// server.ssl.trust-store-password=changeit
// server.ssl.client-auth=want   ← request but don't require client cert
// server.ssl.client-auth=need   ← require client cert (TLS fails without it)

// ─── X509AuthenticationFilter internals ─────────────────────────────────────
public class X509AuthenticationFilter
        extends AbstractPreAuthenticatedProcessingFilter {

    // Extracts the principal (username) from the certificate's Subject DN
    private X509PrincipalExtractor principalExtractor =
        new SubjectDnX509PrincipalExtractor();

    @Override
    protected Object getPreAuthenticatedPrincipal(HttpServletRequest request) {
        // Container sets this attribute after TLS validation
        X509Certificate[] certs = (X509Certificate[])
            request.getAttribute("javax.servlet.request.X509Certificate");

        if (certs == null || certs.length == 0) {
            return null; // no client cert — filter transparent
        }

        // Extract principal from certificate Subject DN using regex
        // Default regex: "CN=(.*?)(?:,|$)"
        // Certificate DN: "CN=alice.smith, OU=Engineering, O=Acme Corp, C=US"
        // Extracted:       "alice.smith"
        return principalExtractor.extractPrincipal(certs[0]);
    }

    @Override
    protected Object getPreAuthenticatedCredentials(HttpServletRequest request) {
        // The full certificate object is the "credential" — downstream can inspect it
        X509Certificate[] certs = (X509Certificate[])
            request.getAttribute("javax.servlet.request.X509Certificate");
        return (certs != null && certs.length > 0) ? certs[0] : "N/A";
    }
}
```

Now the Spring Security DSL configuration for X.509, which is the only pre-auth mechanism that has a dedicated DSL shortcut:

```java
/**
 * X.509 is special: it's the ONLY pre-auth mechanism with a dedicated .x509() DSL.
 * All other pre-auth filters require manual addFilterBefore() registration.
 */
@Configuration
@EnableWebSecurity
public class X509SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/internal/**").hasRole("SERVICE")
                .anyRequest().authenticated()
            )
            .x509(x509 -> x509
                // Regex to extract username from certificate Subject DN.
                // Default: "CN=(.*?)(?:,|$)" — extracts CN value
                // For email-based certs: "emailAddress=(.*?)(?:,|$)"
                // For custom field: "OU=(.*?)(?:,|$)"
                .subjectPrincipalRegex("CN=(.*?)(?:,|$)")

                // Load authorities by the extracted CN value
                .userDetailsService(x509UserDetailsService())
            );

        return http.build();
    }

    @Bean
    public UserDetailsService x509UserDetailsService() {
        return username -> {
            // username = "alice.smith" extracted from certificate CN
            // Load from your user store
            return User.builder()
                .username(username)
                .password("{noop}N/A") // no password for certificate auth
                .roles("USER", "CERT_AUTHENTICATED")
                .build();
        };
    }
}
```

The `client-auth=want` vs `client-auth=need` distinction is worth understanding clearly. With `want`, clients without certificates still reach your application — the X.509 filter gets null and passes through, and other authentication mechanisms (form login, Basic) can handle those requests. With `need`, the TLS handshake itself fails if the client has no certificate — the request never reaches Spring Security at all. Use `want` for applications that support both browser users (no cert) and service-to-service mTLS (with cert). Use `need` for internal service APIs where every caller must present a certificate.

---

## Layer 8: The Complete Configuration — Wiring Everything Together

```java
/**
 * LAYER 8A: Full production header-based pre-auth configuration.
 *
 * This is the API gateway pattern used in most modern microservice deployments.
 * The gateway authenticates, the app trusts and extracts.
 */
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class GatewayPreAuthSecurityConfig {

    private final GatewayRolesMappingService gatewayUserDetailsService;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        HmacValidatingGatewayFilter preAuthFilter = buildPreAuthFilter();

        http
            // CRITICAL: addFilterBefore, not addFilter
            // Must run before AnonymousAuthenticationFilter sets anonymous token,
            // and before AuthorizationFilter checks access
            .addFilterBefore(preAuthFilter, UsernamePasswordAuthenticationFilter.class)

            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/actuator/health").permitAll()
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                .requestMatchers("/api/**").hasAnyRole("USER", "API_CLIENT")
                .anyRequest().denyAll() // fail-safe default
            )
            .sessionManagement(s -> s
                // STATELESS: don't create sessions for API calls
                // This forces re-authentication on every request, which is correct
                // for gateway-forwarded requests where the gateway always sends the header
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            .csrf(AbstractHttpConfigurer::disable) // stateless API, no CSRF needed
            .exceptionHandling(ex -> ex
                .authenticationEntryPoint(jsonAuthEntryPoint())   // 401 as JSON
                .accessDeniedHandler(jsonAccessDeniedHandler())    // 403 as JSON
            );

        return http.build();
    }

    private HmacValidatingGatewayFilter buildPreAuthFilter() {
        HmacValidatingGatewayFilter filter = new HmacValidatingGatewayFilter(hmacSecret);
        filter.setAuthenticationManager(authenticationManager());
        filter.setExceptionIfHeaderMissing(true);  // every request must come from gateway
        filter.setCheckForPrincipalChanges(false); // stateless — no session to check
        filter.setContinueFilterChainOnUnsuccessfulAuthentication(false); // stop on failure

        // Must call this when instantiating manually — validates required properties
        try { filter.afterPropertiesSet(); }
        catch (Exception e) { throw new RuntimeException("Pre-auth filter init failed", e); }

        return filter;
    }

    @Bean
    public AuthenticationManager authenticationManager() {
        PreAuthenticatedAuthenticationProvider provider =
            new PreAuthenticatedAuthenticationProvider();

        // Use custom service because we need to inspect credentials (roles header)
        provider.setPreAuthenticatedUserDetailsService(gatewayUserDetailsService);

        // Account status checks: enabled, non-locked, non-expired
        provider.setUserDetailsChecker(new AccountStatusUserDetailsChecker());

        return new ProviderManager(provider);
    }
}

/**
 * LAYER 8B: Dual-chain configuration — pre-auth for /api/**, form login for /web/**
 *
 * This is important for applications that serve both programmatic API clients
 * (via gateway) and browser users (direct form login).
 */
@Configuration
@EnableWebSecurity
public class DualChainConfig {

    @Bean
    @Order(1) // checked first
    public SecurityFilterChain apiChain(HttpSecurity http) throws Exception {
        RequestHeaderAuthenticationFilter preAuthFilter =
            new RequestHeaderAuthenticationFilter();
        preAuthFilter.setPrincipalRequestHeader("X-Gateway-User");
        preAuthFilter.setExceptionIfHeaderMissing(false); // optional — fallthrough if no header
        preAuthFilter.setAuthenticationManager(apiAuthManager());
        preAuthFilter.afterPropertiesSet();

        http
            .securityMatcher("/api/**")
            .addFilterBefore(preAuthFilter, UsernamePasswordAuthenticationFilter.class)
            .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
            .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .csrf(AbstractHttpConfigurer::disable);

        return http.build();
    }

    @Bean
    @Order(2) // checked second
    public SecurityFilterChain webChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/login", "/public/**").permitAll()
                .anyRequest().authenticated()
            )
            .formLogin(form -> form.defaultSuccessUrl("/dashboard"));

        return http.build();
    }
}
```

---

## Layer 9: Testing Pre-Authentication

```java
/**
 * LAYER 9: Testing pre-authentication scenarios.
 *
 * There's no built-in spring-security-test RequestPostProcessor for pre-auth
 * like there is for httpBasic(). You test by either:
 *   1. Setting the header directly (tests the full filter pipeline)
 *   2. Using @WithMockUser / @WithUserDetails (bypasses filter, tests authorization only)
 */
@SpringBootTest
@AutoConfigureMockMvc
class PreAuthSecurityTest {

    @Autowired MockMvc mockMvc;

    @Test
    @DisplayName("Valid gateway header → authenticated and authorized")
    void validGatewayHeader() throws Exception {
        mockMvc.perform(get("/api/orders")
                .header("X-Gateway-User", "alice")
                .header("X-Gateway-Roles", "ROLE_USER"))
            .andExpect(status().isOk());
    }

    @Test
    @DisplayName("No gateway header → 401 when exceptionIfHeaderMissing=true")
    void missingHeader() throws Exception {
        mockMvc.perform(get("/api/orders"))
            .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Valid user, insufficient role → 403 not 401")
    void validUserWrongRole() throws Exception {
        mockMvc.perform(get("/api/admin/users")
                .header("X-Gateway-User", "alice")
                .header("X-Gateway-Roles", "ROLE_USER")) // alice lacks ROLE_ADMIN
            .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("Unknown user rejected by UserDetailsService → 401")
    void unknownUser() throws Exception {
        // UserDetailsService throws UsernameNotFoundException for "unknown"
        mockMvc.perform(get("/api/orders")
                .header("X-Gateway-User", "unknown-user")
                .header("X-Gateway-Roles", "ROLE_USER"))
            .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Disabled account rejected despite valid header → 401")
    void disabledAccount() throws Exception {
        // "disabled-user" exists in UserDetailsService but isEnabled()=false
        // AccountStatusUserDetailsChecker throws DisabledException
        mockMvc.perform(get("/api/orders")
                .header("X-Gateway-User", "disabled-user")
                .header("X-Gateway-Roles", "ROLE_USER"))
            .andExpect(status().isUnauthorized());
    }

    // Testing authorization rules without going through the filter:
    @Test
    @WithMockUser(username = "alice", roles = {"ADMIN"})
    @DisplayName("Admin user can access admin endpoint")
    void adminAccess() throws Exception {
        mockMvc.perform(get("/api/admin/users"))
            .andExpect(status().isOk());
    }
}
```

---

## The Complete Mental Model

Here is how all layers connect for a pre-authentication request, compared side by side with form login to show the key architectural difference:

```
Form Login (Spring Security owns the decision):
     POST /login (username=alice, password=secret)
          ↓
     UsernamePasswordAuthenticationFilter
          ↓ extract credentials
     DaoAuthenticationProvider
          ↓ loadUserByUsername() → UserDetails
          ↓ passwordEncoder.matches("secret", "{bcrypt}...") ← VERIFICATION HERE
          ↓ preAuthChecks(), postAuthChecks()
     Authenticated token → SecurityContext

─────────────────────────────────────────────────────────────────────

Pre-Authentication (external system owns the decision):
     GET /api/orders
     X-Gateway-User: alice       ← already verified by gateway
     X-Gateway-Signature: abc123 ← HMAC proof of authenticity
          ↓
     AbstractPreAuthenticatedProcessingFilter
          ↓ getPreAuthenticatedPrincipal() → "alice"   ← EXTRACTION only
          ↓ getPreAuthenticatedCredentials() → "ROLE_USER,ROLE_API"
          ↓ build PreAuthenticatedAuthenticationToken("alice", "ROLE_USER,ROLE_API")
          ↓
     PreAuthenticatedAuthenticationProvider
          ↓ AuthenticationUserDetailsService.loadUserDetails(token)
          ↓ loads authorities for "alice" from DB (or maps from credentials)
          ↓ userDetailsChecker.check() — account status only, NO password check
     Authenticated token → SecurityContext
          ↓
     AuthorizationFilter → 200 OK
```

The deepest architectural insight in this topic is the separation of concerns between *authentication* (deciding if you are who you say you are) and *authority mapping* (deciding what you're allowed to do). In form login, Spring Security does both. In pre-authentication, Spring Security delegates the first responsibility entirely to an external system and retains only the second. `PreAuthenticatedAuthenticationProvider` is the expression of this: it is the only `AuthenticationProvider` in the framework that deliberately, by design, never touches credentials. The trust is structural, not computational.
