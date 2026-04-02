# SPRING SECURITY MASTERY — COMPLETE STRUCTURED INDEX

---

## 📚 TABLE OF CONTENTS

---

### PART I — FOUNDATIONS & ARCHITECTURE

```
1.  Spring Security Core Architecture
    1.1  What is Spring Security — design philosophy & goals
    1.2  SecurityFilterChain — structure, registration, ordering
    1.3  DelegatingFilterProxy — the bridge between Servlet & Spring
    1.4  FilterChainProxy — the real dispatcher
    1.5  SecurityContext & SecurityContextHolder
    1.6  ThreadLocal strategy — MODE_THREADLOCAL, MODE_INHERITABLETHREADLOCAL, MODE_GLOBAL
    1.7  Authentication object — structure, lifecycle, immutability
    1.8  GrantedAuthority — roles vs authorities internal model
    1.9  AuthenticationManager & ProviderManager
    1.10 AuthenticationProvider — contract & chaining
    1.11 UserDetailsService & UserDetails contract
    1.12 PasswordEncoder — strategies, encoding, upgrading
    1.13 SecurityBuilder & HttpSecurity DSL internals
    1.14 WebSecurityConfigurerAdapter (5.x) vs SecurityFilterChain bean (6.x)
```

---

### PART II — AUTHENTICATION MECHANISMS

```
2.  Form-Based Authentication
    2.1  UsernamePasswordAuthenticationFilter internals
    2.2  AuthenticationSuccessHandler / FailureHandler
    2.3  RememberMeServices & persistent token strategy
    2.4  Session creation on authentication

3.  HTTP Basic & Digest Authentication
    3.1  BasicAuthenticationFilter flow
    3.2  Digest authentication (deprecated path)
    3.3  Stateless vs stateful implications

4.  Anonymous Authentication
    4.1  AnonymousAuthenticationFilter
    4.2  AnonymousAuthenticationToken internals
    4.3  Why anonymousUser matters in authorization

5.  Pre-Authentication
    5.1  AbstractPreAuthenticatedProcessingFilter
    5.2  X.509, header-based, container-managed auth
    5.3  Integration with external identity systems
```

---

### PART III — AUTHORIZATION

```
6.  Authorization Architecture
    6.1  AccessDecisionManager (5.x) → AuthorizationManager (6.x)
    6.2  AccessDecisionVoter pattern — AffirmativeBased, ConsensusBased, UnanimousBased
    6.3  AuthorizationFilter (6.x) replacing FilterSecurityInterceptor (5.x)
    6.4  ConfigAttribute & SecurityMetadataSource internals
    6.5  hasRole vs hasAuthority — ROLE_ prefix mechanics
    6.6  SpEL in authorization expressions
    6.7  HTTP request matching — antMatchers vs requestMatchers vs mvcMatchers

7.  Method Security
    7.1  @EnableMethodSecurity vs @EnableGlobalMethodSecurity
    7.2  @PreAuthorize, @PostAuthorize — SpEL evaluation lifecycle
    7.3  @PreFilter, @PostFilter — collection filtering internals
    7.4  @Secured — simple role checking
    7.5  @RolesAllowed — JSR-250 standard
    7.6  AOP proxy mechanics — CGLIB vs JDK proxy, self-invocation trap
    7.7  Method security vs URL security — priority & conflicts
    7.8  Custom authorization expressions & beans in SpEL
```

---

### PART IV — EXCEPTION HANDLING

```
8.  Exception Translation & Handling
    8.1  ExceptionTranslationFilter — exact position & responsibility
    8.2  AuthenticationException → 401 flow
    8.3  AccessDeniedException → 403 flow
    8.4  AuthenticationEntryPoint — customization
    8.5  AccessDeniedHandler — customization
    8.6  401 vs 403 — decision tree & traps
    8.7  Exception propagation from method security vs filter chain
```

---

### PART V — SESSION MANAGEMENT

```
9.  Session Management
    9.1  SessionManagementFilter & SessionAuthenticationStrategy
    9.2  Session fixation protection — changeSessionId, newSession, none, migrateSession
    9.3  SessionCreationPolicy — ALWAYS, IF_REQUIRED, NEVER, STATELESS
    9.4  Concurrent session control — ConcurrentSessionFilter
    9.5  HttpSessionSecurityContextRepository
    9.6  Session clustering & distributed session considerations
    9.7  SecurityContext persistence across requests
```

---

### PART VI — CSRF & CORS

```
10. CSRF Protection
    10.1 CsrfFilter internals — token generation, validation
    10.2 CsrfTokenRepository — HttpSessionCsrfTokenRepository vs CookieCsrfTokenRepository
    10.3 When to disable CSRF — stateless APIs, reasoning
    10.4 CSRF with SPAs, mobile clients
    10.5 CSRF token in forms, AJAX, custom headers
    10.6 Spring Security 6.x CSRF changes — deferred token loading

11. CORS Configuration
    11.1 CorsFilter vs @CrossOrigin vs CorsConfigurationSource
    11.2 Spring Security CORS integration — ordering trap
    11.3 CORS preflight requests & Spring Security interaction
    11.4 CORS vs CSRF — the conceptual confusion
```

---

### PART VII — OAUTH2 & OIDC

```
12. OAuth2 Core Concepts
    12.1 OAuth2 roles — resource owner, client, server, resource server
    12.2 Grant types — authorization code, PKCE, client credentials, refresh token
    12.3 OAuth2 vs OIDC distinction

13. OAuth2 Login (Client)
    13.1 OAuth2LoginConfigurer internals
    13.2 OAuth2AuthorizationRequestRedirectFilter
    13.3 OAuth2LoginAuthenticationFilter
    13.4 Authorization code exchange flow
    13.5 OAuth2AuthorizedClientService & token storage
    13.6 DefaultOAuth2UserService & OidcUserService

14. OAuth2 Resource Server
    14.1 JWT validation filter — BearerTokenAuthenticationFilter
    14.2 JwtDecoder — NimbusJwtDecoder internals
    14.3 JWT claim mapping → GrantedAuthority conversion
    14.4 Opaque token introspection
    14.5 Custom JWT validation — claim validators, converters
    14.6 Resource server + form login combo

15. OAuth2 Authorization Server (Spring Authorization Server)
    15.1 Spring Authorization Server architecture overview
    15.2 RegisteredClient model
    15.3 Token endpoint, authorization endpoint internals
    15.4 Token customization — claims, format
    15.5 PKCE flow implementation
```

---

### PART VIII — ADVANCED TOPICS

```
16. Remember-Me Authentication
    16.1 Simple hash-based token
    16.2 Persistent token (PersistentTokenRepository)
    16.3 RememberMeAuthenticationFilter chain position

17. Logout Mechanism
    17.1 LogoutFilter & LogoutHandler chain
    17.2 SecurityContextLogoutHandler
    17.3 CookieClearingLogoutHandler
    17.4 OIDC logout (RP-Initiated Logout)

18. Password Management
    18.1 DelegatingPasswordEncoder internals
    18.2 Password encoding upgrade on login
    18.3 BCryptPasswordEncoder cost factor
    18.4 {noop}, {bcrypt}, {pbkdf2} prefix system

19. Custom Filters & Filter Integration
    19.1 OncePerRequestFilter — contract and use
    19.2 addFilterBefore, addFilterAfter, addFilterAt — trap analysis
    19.3 GenericFilterBean lifecycle
    19.4 Custom authentication filter design pattern
    19.5 Filter ordering master table

20. Security Events & Auditing
    20.1 ApplicationEventPublisher integration
    20.2 AuthenticationSuccessEvent, AuthenticationFailureBadCredentialsEvent
    20.3 AbstractSecurityInterceptor events
    20.4 Custom security event handling

21. Testing Spring Security
    21.1 @WithMockUser, @WithUserDetails, @WithAnonymousUser
    21.2 SecurityMockMvcRequestPostProcessors
    21.3 Method security testing
    21.4 OAuth2 / JWT testing support
    21.5 Testing custom filters

22. Spring Boot Auto-Configuration
    22.1 SecurityAutoConfiguration & SpringBootWebSecurityConfiguration
    22.2 UserDetailsServiceAutoConfiguration
    22.3 Conditional security beans
    22.4 Actuator security integration

23. Reactive Security (WebFlux)
    23.1 ReactiveSecurityContextHolder
    23.2 SecurityWebFilterChain
    23.3 ReactiveAuthenticationManager
    23.4 Reactive method security
    23.5 Servlet vs Reactive — key differences

24. Multi-Tenancy & Advanced Patterns
    24.1 Multiple SecurityFilterChain beans — ordering & matching
    24.2 Tenant-aware UserDetailsService
    24.3 Dynamic security configuration

25. Spring Security 5.x → 6.x Migration
    25.1 Removed APIs — WebSecurityConfigurerAdapter
    25.2 Deprecated matchers — antMatchers, mvcMatchers, authorizeRequests
    25.3 Lambda DSL mandatory in 6.x
    25.4 AuthorizationManager replacing AccessDecisionManager
    25.5 CSRF, Headers, and defaults changed in 6.x
```

---

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# TOPIC 1 — Spring Security Core Architecture

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

---

## 1️⃣ Conceptual Explanation

---

### 1.1 What Is Spring Security — Design Philosophy & Goals

Spring Security is a **powerful, highly customizable authentication and authorization framework** built on top of the Java Servlet API and Spring's dependency injection model. It is not just a collection of annotations — it is a **complete security pipeline** that intercepts every HTTP request before it reaches your business logic.

**Three core design pillars:**

**Pillar 1 — Separation of Concerns**
Authentication (who are you?) and Authorization (what can you do?) are handled by completely separate subsystems with separate filter positions, separate exception types, and separate handling strategies. This is not just a conceptual distinction — it manifests structurally in the filter chain.

**Pillar 2 — Servlet Filter Integration**
Spring Security integrates with the Java EE Servlet container through `javax.servlet.Filter` (pre-Jakarta) / `jakarta.servlet.Filter` (Spring 6.x+). Every security operation happens in the filter layer, **before** `DispatcherServlet` and therefore before any Spring MVC controller is ever reached.

**Pillar 3 — Open for Extension, Closed for Modification**
Every major component (`AuthenticationProvider`, `UserDetailsService`, `AccessDecisionManager`, etc.) is an interface. Spring Security provides defaults but expects you to plug in custom implementations for real enterprise use.

---

### 1.2 SecurityFilterChain — Structure, Registration, Ordering

This is the **central concept** of Spring Security. Understanding this deeply separates architects from average developers.

**What is a filter chain?**

A `SecurityFilterChain` is an **ordered list of `javax.servlet.Filter` instances** that are applied to HTTP requests matching a specific URL pattern. Each filter performs one discrete security function and passes the request down to the next filter.

```
HTTP Request
     │
     ▼
DelegatingFilterProxy          ← registered in Servlet container
     │
     ▼
FilterChainProxy               ← Spring bean, owns all SecurityFilterChains
     │
     ├──► SecurityFilterChain #1  (matches /api/**)
     │         Filter1 → Filter2 → Filter3 → ... → FilterN
     │
     ├──► SecurityFilterChain #2  (matches /admin/**)
     │         Filter1 → Filter2 → ...
     │
     └──► SecurityFilterChain #3  (matches /**)
               Filter1 → Filter2 → ...
```

**Critical rule:** `FilterChainProxy` iterates the chains **in order** and uses the **first chain whose RequestMatcher matches**. Once matched, that chain handles the request entirely. No other chain executes.

**Default filter order (Spring Security 6.x) — simplified:**

| Order | Filter | Responsibility |
|-------|--------|---------------|
| 100 | `DisableEncodeUrlFilter` | Prevents session ID in URL |
| 200 | `WebAsyncManagerIntegrationFilter` | Async thread SecurityContext propagation |
| 300 | `SecurityContextHolderFilter` (6.x) / `SecurityContextPersistenceFilter` (5.x) | Load/save SecurityContext |
| 400 | `HeaderWriterFilter` | X-Frame-Options, CSP, etc. |
| 500 | `CorsFilter` | CORS preflight & headers |
| 600 | `CsrfFilter` | CSRF token validation |
| 700 | `LogoutFilter` | Logout URL handling |
| 800 | `UsernamePasswordAuthenticationFilter` | Form login |
| 900 | `BasicAuthenticationFilter` | HTTP Basic |
| 1000 | `BearerTokenAuthenticationFilter` | OAuth2 JWT |
| 1100 | `RequestCacheAwareFilter` | Restore cached request after login |
| 1200 | `SecurityContextHolderAwareRequestWrapper` | HttpServletRequest security methods |
| 1300 | `AnonymousAuthenticationFilter` | Set anonymous token if no auth yet |
| 1400 | `SessionManagementFilter` | Session fixation, concurrency |
| 1500 | `ExceptionTranslationFilter` | Catch AuthN/AuthZ exceptions |
| 1600 | `AuthorizationFilter` (6.x) / `FilterSecurityInterceptor` (5.x) | Final access decision |

**The last two filters are the most architecturally important:**
- `ExceptionTranslationFilter` wraps the remaining chain in a try-catch
- `AuthorizationFilter` performs the actual access check and throws exceptions
- Exceptions bubble up from `AuthorizationFilter` into `ExceptionTranslationFilter`

---

### 1.3 DelegatingFilterProxy — The Bridge Between Servlet & Spring

**The problem it solves:**

The Servlet container (Tomcat, Jetty) initializes filters **before** the Spring `ApplicationContext` is fully loaded. You cannot directly register Spring beans as Servlet filters during container startup because the beans don't exist yet.

**The solution:**

`DelegatingFilterProxy` is a **standard `javax.servlet.Filter`** that is registered with the Servlet container early. It holds a **lazy reference** to a Spring bean by name. When the first request arrives, it looks up the target bean from the `WebApplicationContext` and delegates all filter processing to it.

```
Servlet Container Boot
     │
     └──► Registers DelegatingFilterProxy("springSecurityFilterChain")
               └── No Spring beans loaded yet — just a name reference

First HTTP Request
     │
     └──► DelegatingFilterProxy.doFilter()
               │
               └──► Looks up bean "springSecurityFilterChain" from WebApplicationContext
                         └──► That bean IS FilterChainProxy
                                   └──► Delegates to FilterChainProxy.doFilter()
```

**Key detail:** The lookup bean name defaults to `"springSecurityFilterChain"`. This is why your `SecurityFilterChain` bean registered in Spring Boot auto-configuration works without any explicit Servlet registration code — Spring Boot's `SecurityFilterAutoConfiguration` handles the `DelegatingFilterProxy` registration.

**5.x vs 6.x note:**
In Spring Security 6.x with Spring Boot 3.x, the underlying servlet API migrated from `javax.servlet` to `jakarta.servlet`. The concept is identical but the import packages differ.

---

### 1.4 FilterChainProxy — The Real Dispatcher

`FilterChainProxy` is the **actual Spring bean** (`springSecurityFilterChain`) that owns all your `SecurityFilterChain` instances. It is the brain of the security infrastructure.

**Responsibilities:**
1. Receives all requests delegated by `DelegatingFilterProxy`
2. Iterates its list of `SecurityFilterChain` instances
3. Finds the **first matching chain** using `RequestMatcher`
4. Executes all filters in that chain sequentially
5. If no chain matches → passes request through unfiltered (rare in practice)

**Critical internal detail — Virtual Dispatch:**
`FilterChainProxy` wraps the `HttpServletRequest` in a `FirewalledRequest` before passing it to the chains. This wraps the request in Spring Security's `HttpFirewall` (default: `StrictHttpFirewall`) which rejects:
- Path traversal attacks (`/../`)
- Semicolon in URLs (`;jsessionid=`)
- Null bytes
- Non-normalized paths

This happens **before** any of your custom filters — it is the first real line of defense.

---

### 1.5 SecurityContext & SecurityContextHolder

**SecurityContext** is the container that holds the currently authenticated user's `Authentication` object during the lifecycle of a request.

**SecurityContextHolder** is the static utility class that stores `SecurityContext` using a **strategy pattern**:

```
SecurityContextHolder
     │
     └──► SecurityContextHolderStrategy (interface)
               ├──► ThreadLocalSecurityContextHolderStrategy  (default)
               ├──► InheritableThreadLocalSecurityContextHolderStrategy
               └──► GlobalSecurityContextHolderStrategy
```

**ThreadLocal strategy (default):**

```java
// Internally, the default strategy uses:
private static final ThreadLocal<SecurityContext> contextHolder = new ThreadLocal<>();
```

This means:
- Each thread has its own isolated `SecurityContext`
- Setting auth on thread A does not affect thread B
- **After the request is complete, the context MUST be cleared** to avoid memory leaks in thread pool environments

**5.x vs 6.x — Critical Difference:**

| Version | Filter | Behavior |
|---------|--------|----------|
| 5.x | `SecurityContextPersistenceFilter` | Loads context **at start**, saves context **after chain** using `HttpSessionSecurityContextRepository` |
| 6.x | `SecurityContextHolderFilter` | Loads context **at start**, but **does NOT auto-save** — saving is explicit responsibility of authentication filters |

This 6.x change is significant: in 5.x, the context was saved after every request automatically. In 6.x, authentication filters must call `securityContextRepository.saveContext()` explicitly. This was done to prevent unintentional session creation.

---

### 1.6 ThreadLocal Strategy — Modes & Implications

**MODE_THREADLOCAL (default):**
- Safest for traditional synchronous Servlet applications
- Each request thread has its own isolated context
- Works correctly with thread pools since context is cleared at end of request

**MODE_INHERITABLETHREADLOCAL:**
- Child threads (spawned from request thread) inherit the parent's `SecurityContext`
- Use case: `@Async` methods that need to access `SecurityContextHolder.getContext()`
- **Risk:** Spring's `@Async` uses a thread pool — the "child" thread is actually a reused thread. Without careful configuration, the inherited context may not be cleared properly

**MODE_GLOBAL:**
- Single shared `SecurityContext` for the entire JVM
- Only appropriate for Swing desktop applications
- **Never use in web applications** — catastrophic security flaw

**The `@Async` trap:**

```java
@Async
public void processOrder() {
    // With MODE_THREADLOCAL, SecurityContextHolder.getContext() returns EMPTY here
    // The async thread is a different thread — no SecurityContext

    // With MODE_INHERITABLETHREADLOCAL, it may work — but only if Spring's
    // DelegatingSecurityContextAsyncTaskExecutor is configured
}
```

The correct solution for `@Async` is to configure a `DelegatingSecurityContextAsyncTaskExecutor` which explicitly propagates the `SecurityContext` to async threads.

---

### 1.7 Authentication Object — Structure, Lifecycle & Immutability

`Authentication` is the central data carrier in Spring Security. It extends `Principal` and carries everything about the current user.

```
Authentication (interface)
     │
     ├──► getPrincipal()      → UserDetails object (or username String before auth)
     ├──► getCredentials()    → password (cleared after authentication)
     ├──► getAuthorities()    → Collection<GrantedAuthority>
     ├──► getDetails()        → WebAuthenticationDetails (IP, session ID)
     └──► isAuthenticated()   → boolean
```

**Lifecycle — two states:**

**Pre-authentication (token submitted):**
```
UsernamePasswordAuthenticationToken(principal="john", credentials="password", authenticated=false)
```

**Post-authentication (after successful auth):**
```
UsernamePasswordAuthenticationToken(principal=UserDetails{...}, credentials=null, authenticated=true)
```

Note that credentials are **erased** after successful authentication (by `ProviderManager` by default, controlled by `eraseCredentialsAfterAuthentication` flag). This is a security measure to prevent passwords from lingering in memory.

**Immutability note:**
Once an `Authentication` is placed in `SecurityContext` after successful authentication, it should be treated as immutable. Mutating authorities post-authentication is possible but requires replacing the entire object in `SecurityContextHolder`.

---

### 1.8 GrantedAuthority — Roles vs Authorities

```
GrantedAuthority (interface)
     └──► getAuthority() → String
```

**Role:** A named grouping. By convention prefixed with `ROLE_`.
- Example: `ROLE_ADMIN`, `ROLE_USER`
- Used with `hasRole("ADMIN")` — Spring Security **automatically prepends** `ROLE_`
- Stored as `SimpleGrantedAuthority("ROLE_ADMIN")`

**Authority:** A fine-grained permission string.
- Example: `READ_USERS`, `DELETE_ORDER`, `SCOPE_read`
- Used with `hasAuthority("READ_USERS")` — **no prefix manipulation**

**The critical trap:**
```java
// These are NOT equivalent:
.hasRole("ADMIN")         // checks for GrantedAuthority("ROLE_ADMIN")
.hasAuthority("ADMIN")    // checks for GrantedAuthority("ADMIN") — NO ROLE_ prefix

// This is also a trap:
.hasAuthority("ROLE_ADMIN") // works, but redundant if using hasRole
```

---

### 1.9 AuthenticationManager & ProviderManager

`AuthenticationManager` is the entry point for all authentication operations. It has exactly one method:

```java
public interface AuthenticationManager {
    Authentication authenticate(Authentication authentication) throws AuthenticationException;
}
```

`ProviderManager` is the standard implementation. It holds a **list of `AuthenticationProvider` instances** and delegates to them in order.

```
ProviderManager.authenticate(token)
     │
     ├──► Provider1.supports(token.class)? → NO → skip
     ├──► Provider2.supports(token.class)? → YES → authenticate()
     │         ├──► Returns Authentication → SUCCESS, stop chain, erase credentials
     │         ├──► Throws AuthenticationException → FAILURE, try next provider
     │         └──► Returns null → ABSTAIN, try next provider
     └──► All providers exhausted → throw ProviderNotFoundException
```

**Parent `AuthenticationManager`:**
`ProviderManager` can have a **parent** `ProviderManager`. If all local providers abstain/fail, it delegates to the parent. This is used in Spring Security's internal setup (e.g., global auth manager vs local HTTP security auth manager).

**Credentials erasure:**
After successful authentication, `ProviderManager` calls `eraseCredentials()` on the returned `Authentication` if `eraseCredentialsAfterAuthentication = true` (default). This nulls out the password field.

---

### 1.10 AuthenticationProvider — Contract & Chaining

```java
public interface AuthenticationProvider {
    Authentication authenticate(Authentication authentication) throws AuthenticationException;
    boolean supports(Class<?> authentication);
}
```

`supports()` is checked **before** `authenticate()` is called. This allows multiple providers to coexist without interfering with each other.

**Example providers:**
- `DaoAuthenticationProvider` — UserDetailsService + PasswordEncoder
- `JwtAuthenticationProvider` — OAuth2 JWT validation
- `RememberMeAuthenticationProvider` — remember-me tokens
- `AnonymousAuthenticationProvider` — validates anonymous tokens
- `LdapAuthenticationProvider` — LDAP directory auth

**DaoAuthenticationProvider internals:**
```
DaoAuthenticationProvider.authenticate(UsernamePasswordAuthenticationToken)
     │
     ├──► userDetailsService.loadUserByUsername(username)
     │         └──► Returns UserDetails (or throws UsernameNotFoundException)
     │
     ├──► passwordEncoder.matches(rawPassword, encodedPassword)
     │         └──► Returns false → throw BadCredentialsException
     │
     ├──► userDetails.isEnabled(), isAccountNonExpired(), etc.
     │         └──► false → throw DisabledException, AccountExpiredException, etc.
     │
     └──► Return new UsernamePasswordAuthenticationToken(userDetails, null, authorities)
                    (credentials set to null — erased)
```

---

### 1.11 UserDetailsService & UserDetails Contract

```java
public interface UserDetailsService {
    UserDetails loadUserByUsername(String username) throws UsernameNotFoundException;
}
```

**Critical contract detail:** `UsernameNotFoundException` **should never be thrown to reveal whether a username exists**. `DaoAuthenticationProvider` internally catches `UsernameNotFoundException` and converts it to `BadCredentialsException` (when `hideUserNotFoundExceptions = true`, which is the **default**). This prevents username enumeration attacks.

```java
public interface UserDetails extends Serializable {
    Collection<? extends GrantedAuthority> getAuthorities();
    String getPassword();
    String getUsername();
    boolean isAccountNonExpired();
    boolean isAccountNonLocked();
    boolean isCredentialsNonExpired();
    boolean isEnabled();
}
```

**Each boolean maps to a specific exception:**
| Method | Returns false | Exception thrown |
|--------|--------------|-----------------|
| `isEnabled()` | false | `DisabledException` |
| `isAccountNonExpired()` | false | `AccountExpiredException` |
| `isAccountNonLocked()` | false | `LockedException` |
| `isCredentialsNonExpired()` | false | `CredentialsExpiredException` |

---

### 1.12 PasswordEncoder — Strategies & Upgrading

```java
public interface PasswordEncoder {
    String encode(CharSequence rawPassword);
    boolean matches(CharSequence rawPassword, String encodedPassword);
    default boolean upgradeEncoding(String encodedPassword) { return false; }
}
```

**DelegatingPasswordEncoder** (the modern standard):

```
{bcrypt}$2a$10$... → BCryptPasswordEncoder
{pbkdf2}...        → Pbkdf2PasswordEncoder
{scrypt}...        → SCryptPasswordEncoder
{noop}password     → NoOpPasswordEncoder (NEVER in production)
```

This prefix system allows **transparent password migration** — old `{noop}` passwords continue working while new registrations use `{bcrypt}`. On each login, if `upgradeEncoding()` returns true, the encoded password is re-encoded with the current default encoder and saved back.

---

### 1.13 HttpSecurity DSL — SecurityBuilder Internals

`HttpSecurity` is a `SecurityBuilder<DefaultSecurityFilterChain>`. When you call `.build()` (triggered by Spring Boot), it:

1. Iterates all registered `SecurityConfigurer` instances (each `.formLogin()`, `.csrf()`, etc. registers one)
2. Calls `configurer.init(http)` on each — sets up dependencies between configurers
3. Calls `configurer.configure(http)` on each — adds actual filters to the chain
4. Produces `DefaultSecurityFilterChain(requestMatcher, orderedFilterList)`

**Lambda DSL (mandatory in Spring Security 6.x):**
```java
// 5.x style (deprecated in 6.x)
http.authorizeRequests()
    .antMatchers("/admin/**").hasRole("ADMIN")
    .and()
    .formLogin();

// 6.x style (mandatory)
http
    .authorizeHttpRequests(auth -> auth
        .requestMatchers("/admin/**").hasRole("ADMIN")
    )
    .formLogin(Customizer.withDefaults());
```

The `.and()` chaining was removed in 6.x because it caused deep nesting confusion and made the DSL harder to read. Lambda closures make each configurer self-contained.

---

### 1.14 WebSecurityConfigurerAdapter (5.x) vs SecurityFilterChain Bean (6.x)

**5.x approach (deprecated, removed in 6.x):**
```java
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
            .anyRequest().authenticated()
            .and()
            .formLogin();
    }
}
```

**6.x approach (current standard):**
```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .anyRequest().authenticated()
            )
            .formLogin(Customizer.withDefaults());
        return http.build();
    }
}
```

**Why the change?**
`WebSecurityConfigurerAdapter` used inheritance, which created problems:
- Only one config class could extend it cleanly
- Testing and overriding partial configurations was awkward
- It violated "composition over inheritance"

The bean-based approach allows **multiple `SecurityFilterChain` beans**, each matching a different URL pattern, with full composability.

---

## 2️⃣ Code Examples

---

### Example 1 — XML-Based Configuration (Legacy Spring Security 5.x)

```xml
<!-- security-config.xml -->
<beans:beans xmlns="http://www.springframework.org/schema/security"
    xmlns:beans="http://www.springframework.org/schema/beans"
    xsi:schemaLocation="...">

    <!-- Global Authentication Manager -->
    <authentication-manager>
        <authentication-provider>
            <user-service>
                <user name="alice" password="{bcrypt}$2a$10$..." authorities="ROLE_USER"/>
                <user name="admin" password="{bcrypt}$2a$10$..." authorities="ROLE_ADMIN"/>
            </user-service>
        </authentication-provider>
    </authentication-manager>

    <!-- HTTP Security Filter Chain -->
    <http auto-config="true" use-expressions="true">
        <intercept-url pattern="/admin/**" access="hasRole('ADMIN')"/>
        <intercept-url pattern="/user/**"  access="hasRole('USER')"/>
        <intercept-url pattern="/public/**" access="permitAll"/>
        <intercept-url pattern="/**"       access="isAuthenticated()"/>
        
        <form-login login-page="/login" 
                    default-target-url="/dashboard"
                    authentication-failure-url="/login?error"/>
        
        <logout logout-url="/logout" logout-success-url="/login?logout"/>
        
        <csrf/>
        
        <session-management session-fixation-protection="changeSessionId">
            <concurrency-control max-sessions="1" expired-url="/login?expired"/>
        </session-management>
    </http>

    <!-- DelegatingFilterProxy registered in web.xml -->
    <!-- <filter>
           <filter-name>springSecurityFilterChain</filter-name>
           <filter-class>o.s.web.filter.DelegatingFilterProxy</filter-class>
         </filter> -->
</beans:beans>
```

---

### Example 2 — Annotation-Based Configuration (Spring Security 5.x)

```java
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private CustomUserDetailsService userDetailsService;

    // ─── Authentication ───────────────────────────────────────────────
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth
            .userDetailsService(userDetailsService)
            .passwordEncoder(passwordEncoder());
    }

    // ─── Authorization / Filter Chain ─────────────────────────────────
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .authorizeRequests()
                .antMatchers("/public/**").permitAll()
                .antMatchers("/admin/**").hasRole("ADMIN")
                .antMatchers("/api/**").hasAuthority("API_ACCESS")
                .anyRequest().authenticated()
            .and()
            .formLogin()
                .loginPage("/login")
                .defaultSuccessUrl("/dashboard", true)
                .failureUrl("/login?error")
                .permitAll()
            .and()
            .logout()
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login?logout")
                .invalidateHttpSession(true)
                .deleteCookies("JSESSIONID")
            .and()
            .csrf()
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
            .and()
            .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                .sessionFixation().changeSessionId()
                .maximumSessions(1)
                    .maxSessionsPreventsLogin(false);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }
}
```

---

### Example 3 — Java DSL (Spring Security 6.x — Current Standard)

```java
@Configuration
@EnableWebSecurity
@EnableMethodSecurity  // replaces @EnableGlobalMethodSecurity in 6.x
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/public/**").permitAll()
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .requestMatchers("/api/**").hasAuthority("API_ACCESS")
                .anyRequest().authenticated()
            )
            .formLogin(form -> form
                .loginPage("/login")
                .defaultSuccessUrl("/dashboard", true)
                .failureUrl("/login?error")
                .permitAll()
            )
            .logout(logout -> logout
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login?logout")
                .invalidateHttpSession(true)
                .deleteCookies("JSESSIONID")
            )
            .csrf(csrf -> csrf
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
            )
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                .sessionFixation().changeSessionId()
            );

        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService(PasswordEncoder encoder) {
        UserDetails user = User.builder()
            .username("alice")
            .password(encoder.encode("password"))
            .roles("USER")
            .build();
        return new InMemoryUserDetailsManager(user);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
}
```

---

### Example 4 — Stateless REST API with JWT (Real-World)

```java
@Configuration
@EnableWebSecurity
public class JwtSecurityConfig {

    @Bean
    public SecurityFilterChain apiFilterChain(HttpSecurity http) throws Exception {
        http
            // No session — stateless JWT
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            // No CSRF — stateless APIs don't need it (no session cookie)
            .csrf(AbstractHttpConfigurer::disable)
            // Authorization rules
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/auth/**").permitAll()
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
            )
            // OAuth2 Resource Server JWT validation
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt
                    .jwtAuthenticationConverter(jwtAuthConverter())
                )
            );
        return http.build();
    }

    @Bean
    public JwtAuthenticationConverter jwtAuthConverter() {
        JwtGrantedAuthoritiesConverter grantedAuthoritiesConverter =
            new JwtGrantedAuthoritiesConverter();
        grantedAuthoritiesConverter.setAuthorityPrefix("ROLE_");
        grantedAuthoritiesConverter.setAuthoritiesClaimName("roles");

        JwtAuthenticationConverter jwtConverter = new JwtAuthenticationConverter();
        jwtConverter.setJwtGrantedAuthoritiesConverter(grantedAuthoritiesConverter);
        return jwtConverter;
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        return NimbusJwtDecoder
            .withPublicKey(rsaPublicKey())  // or withJwkSetUri()
            .build();
    }
}
```

---

### Example 5 — Multiple SecurityFilterChain Beans (Advanced)

```java
@Configuration
@EnableWebSecurity
public class MultiChainSecurityConfig {

    // Chain 1: REST API — stateless, JWT
    @Bean
    @Order(1)  // Higher priority
    public SecurityFilterChain apiChain(HttpSecurity http) throws Exception {
        http
            .securityMatcher("/api/**")  // Only matches /api/** requests
            .sessionManagement(s -> s.sessionCreationPolicy(STATELESS))
            .csrf(AbstractHttpConfigurer::disable)
            .authorizeHttpRequests(auth -> auth
                .anyRequest().authenticated()
            )
            .oauth2ResourceServer(o -> o.jwt(Customizer.withDefaults()));
        return http.build();
    }

    // Chain 2: Web UI — stateful, form login
    @Bean
    @Order(2)  // Lower priority — catches everything not matched by Chain 1
    public SecurityFilterChain webChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/public/**").permitAll()
                .anyRequest().authenticated()
            )
            .formLogin(Customizer.withDefaults());
        return http.build();
    }
}
```

---

### Example 6 — What Happens Internally Step-by-Step (Request Trace)

```
POST /login  (username=alice&password=secret)

1. DelegatingFilterProxy.doFilter()
   └── delegates to FilterChainProxy

2. FilterChainProxy
   └── HttpFirewall validates request (no path traversal, etc.)
   └── Finds matching SecurityFilterChain (/** matches)
   └── Wraps in VirtualFilterChain

3. SecurityContextHolderFilter (6.x)
   └── Loads SecurityContext from HttpSessionSecurityContextRepository
   └── Context is empty (no session yet) — sets empty context

4. CsrfFilter
   └── POST request — checks for CSRF token
   └── /login is excluded by default in form login config → passes

5. LogoutFilter
   └── URL is /login, not /logout → passes

6. UsernamePasswordAuthenticationFilter
   └── URL matches /login AND method is POST → INTERCEPTS
   └── Extracts username="alice", password="secret"
   └── Creates UsernamePasswordAuthenticationToken(alice, secret, authenticated=false)
   └── Calls AuthenticationManager.authenticate(token)
         └── ProviderManager → DaoAuthenticationProvider
               └── userDetailsService.loadUserByUsername("alice") → UserDetails
               └── passwordEncoder.matches("secret", storedHash) → true
               └── Checks isEnabled(), isAccountNonLocked(), etc. → all true
               └── Returns authenticated token: (UserDetails, null, [ROLE_USER])
   └── AuthenticationSuccessHandler
         └── SecurityContextHolder.getContext().setAuthentication(authToken)
         └── sessionStrategy.onAuthentication() → new session created, old invalidated
         └── securityContextRepository.saveContext() (6.x explicit save)
         └── Redirects to /dashboard (302)

7. Request ends — FilterChainProxy clears SecurityContextHolder
```

---

## 3️⃣ Exam-Style Questions

---

**Q1 (MCQ):** What is the primary responsibility of `DelegatingFilterProxy`?

A. Performing authentication
B. Delegating Servlet filter calls to a Spring-managed bean
C. Managing the `SecurityContext` lifecycle
D. Routing requests to different `SecurityFilterChain` instances

**Answer: B**
`DelegatingFilterProxy` is purely a bridge. It is a standard Servlet filter that delegates to a Spring bean. It performs no authentication or authorization itself.

---

**Q2 (MCQ):** In Spring Security 6.x, which filter replaced `SecurityContextPersistenceFilter`?

A. `SecurityContextFilter`
B. `SecurityContextHolderFilter`
C. `SecurityContextRepositoryFilter`
D. `SecurityContextSaveFilter`

**Answer: B**
`SecurityContextHolderFilter` replaced `SecurityContextPersistenceFilter` in Spring Security 6.x. The key difference: `SecurityContextHolderFilter` does **not** automatically save the context after the chain — saving is now explicit.

---

**Q3 (Select All That Apply):** Which of the following are true about `ProviderManager`?

A. It can have a parent `AuthenticationManager`
B. It calls all providers regardless of the result of `supports()`
C. It erases credentials after successful authentication by default
D. Returning `null` from `AuthenticationProvider.authenticate()` means authentication failure
E. It throws `ProviderNotFoundException` if no provider supports the token type

**Answer: A, C, E**
B is false — it checks `supports()` first and skips unsupported providers.
D is false — returning `null` means **abstain** (try next provider), not failure. Failure is signaled by throwing `AuthenticationException`.

---

**Q4 (Code Prediction):**

```java
http.authorizeHttpRequests(auth -> auth
    .requestMatchers("/admin/**").hasRole("ADMIN")
    .requestMatchers("/admin/dashboard").permitAll()
    .anyRequest().authenticated()
);
```

A user without `ROLE_ADMIN` accesses `/admin/dashboard`. What HTTP status is returned?

A. 200 OK
B. 401 Unauthorized
C. 403 Forbidden
D. 404 Not Found

**Answer: C — 403 Forbidden**
This is a critical ordering trap. `requestMatchers` rules are evaluated **in order**. The first rule `.requestMatchers("/admin/**").hasRole("ADMIN")` matches `/admin/dashboard` first. The `permitAll()` rule is **never reached**. The user gets 403 because they're authenticated (anonymous gets 401) but unauthorized.

---

**Q5 (Filter Chain Order):** Place these filters in correct execution order:

- `AuthorizationFilter`
- `CsrfFilter`
- `AnonymousAuthenticationFilter`
- `ExceptionTranslationFilter`
- `SecurityContextHolderFilter`
- `UsernamePasswordAuthenticationFilter`

**Answer (correct order):**
1. `SecurityContextHolderFilter`
2. `CsrfFilter`
3. `UsernamePasswordAuthenticationFilter`
4. `AnonymousAuthenticationFilter`
5. `ExceptionTranslationFilter`
6. `AuthorizationFilter`

---

**Q6 (HTTP Status Trap):** An anonymous user accesses `/secure/data`. The filter chain has:
```java
.authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
.formLogin(Customizer.withDefaults())
```
What happens?

**Answer:** `AnonymousAuthenticationFilter` sets an `AnonymousAuthenticationToken`. `AuthorizationFilter` checks access — anonymous is not authenticated → throws `AccessDeniedException`. `ExceptionTranslationFilter` catches it — but the principal is anonymous → treated as unauthenticated → calls `AuthenticationEntryPoint` → **redirects to login page (302)**, not 401 or 403.

This is a classic trap: `AccessDeniedException` on an anonymous user results in **login redirect**, not 403!

---

**Q7 (Exception Tracing):**

```java
@PreAuthorize("hasRole('ADMIN')")
public void deleteUser(Long id) { ... }
```

A user with `ROLE_USER` calls `deleteUser()`. Trace the exact exception flow.

**Answer:**
1. AOP proxy intercepts `deleteUser()` call
2. `AuthorizationManagerBeforeMethodInterceptor` evaluates `hasRole('ADMIN')` → false
3. Throws `AccessDeniedException`
4. Exception propagates up the call stack
5. **Not caught by `ExceptionTranslationFilter`** if the method is called from a service layer
6. If called from a web request: `DispatcherServlet` receives the exception → Spring MVC `@ExceptionHandler` or default error handling returns **403 Forbidden**

The key insight: `ExceptionTranslationFilter` only catches exceptions from within the filter chain. If method security throws `AccessDeniedException` after the filters have completed, it propagates differently.

---

## 4️⃣ Trick Analysis

---

**Trick 1 — 401 vs 403: The definitive decision tree**

```
Request arrives at ExceptionTranslationFilter
     │
     └──► AccessDeniedException thrown
               │
               ├──► Is authentication ANONYMOUS?
               │         YES → AuthenticationEntryPoint.commence()
               │                    └──► Form login: redirect to /login (302)
               │                    └──► REST API: return 401
               │
               └──► Is authentication REAL (authenticated=true)?
                         YES → AccessDeniedHandler.handle()
                                    └──► Return 403 Forbidden
```

**The confusion:** Developers assume `AccessDeniedException` always means 403. It doesn't — for anonymous users, it redirects to login (which eventually may return 401 for REST APIs).

---

**Trick 2 — `permitAll()` still runs ALL filters**

```java
.requestMatchers("/public/**").permitAll()
```

This does **not** skip the filter chain. All filters still execute. `permitAll()` only tells the `AuthorizationFilter` to allow access without checking authorities. This means:
- `CsrfFilter` still runs (CSRF token still checked on POST)
- `SecurityContextHolderFilter` still runs
- Custom filters still run

To skip filters entirely, use `WebSecurity.ignoring()`:
```java
@Bean
public WebSecurityCustomizer webSecurityCustomizer() {
    return web -> web.ignoring().requestMatchers("/static/**");
}
```
This bypasses `FilterChainProxy` entirely for matched paths — use only for truly static resources.

---

**Trick 3 — `hasRole` vs `hasAuthority` ROLE_ prefix**

```java
// In UserDetails.getAuthorities(), you store:
new SimpleGrantedAuthority("ROLE_ADMIN")

// hasRole("ADMIN") checks for "ROLE_ADMIN" ✓
// hasAuthority("ADMIN") checks for "ADMIN" ✗ — won't match!
// hasAuthority("ROLE_ADMIN") checks for "ROLE_ADMIN" ✓

// Using roles() builder method adds ROLE_ automatically:
User.builder().roles("ADMIN")  // stores "ROLE_ADMIN"
// vs authorities() — no prefix added:
User.builder().authorities("ADMIN")  // stores "ADMIN"
```

---

**Trick 4 — `antMatchers` deprecation in Spring Security 6.x**

In Spring Security 6.x, `antMatchers()`, `mvcMatchers()`, and `regexMatchers()` are **removed**. Use `requestMatchers()` which auto-detects:
- If Spring MVC is on the classpath → uses `MvcRequestMatcher` (context-path aware)
- Otherwise → uses `AntPathRequestMatcher`

The key difference: `MvcRequestMatcher` is context-path aware and matches `/admin` and `/admin/` and `/admin.html` in some cases — `AntPathRequestMatcher` is literal. This can cause subtle security gaps when migrating.

---

**Trick 5 — WebSecurityConfigurerAdapter removal trap**

If you have both `WebSecurityConfigurerAdapter` (from a library) **and** `SecurityFilterChain` beans, Spring Security 6.x will throw an error — they cannot coexist. Many legacy starters that extend `WebSecurityConfigurerAdapter` break on Spring Boot 3.x upgrade.

---

## 5️⃣ Summary Sheet

---

### SecurityFilterChain Execution Diagram

```
HTTP Request
     │
     ▼
┌─────────────────────────────────────────────┐
│         DelegatingFilterProxy               │
│    (Servlet container — lazy bean lookup)   │
└──────────────────┬──────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────┐
│              FilterChainProxy               │
│  (HttpFirewall → finds matching chain)      │
└──────────────────┬──────────────────────────┘
                   │
         ┌─────────▼──────────┐
         │  SecurityFilterChain│
         └─────────┬──────────┘
                   │
    ┌──────────────▼───────────────┐
    │  SecurityContextHolderFilter │ ← load context from session
    ├──────────────────────────────┤
    │       HeaderWriterFilter     │ ← security headers
    ├──────────────────────────────┤
    │          CorsFilter          │ ← CORS headers
    ├──────────────────────────────┤
    │          CsrfFilter          │ ← CSRF token check
    ├──────────────────────────────┤
    │         LogoutFilter         │ ← handle /logout
    ├──────────────────────────────┤
    │  UsernamePasswordAuthFilter  │ ← form login
    ├──────────────────────────────┤
    │    BasicAuthenticationFilter │ ← HTTP Basic
    ├──────────────────────────────┤
    │   BearerTokenAuthFilter      │ ← JWT / OAuth2
    ├──────────────────────────────┤
    │  AnonymousAuthenticationFilter│← set anonymous token
    ├──────────────────────────────┤
    │  ExceptionTranslationFilter  │ ← catch AuthN/AuthZ exceptions
    ├──────────────────────────────┤
    │      AuthorizationFilter     │ ← FINAL access decision → throws
    └──────────────────────────────┘
                   │
                   ▼
          DispatcherServlet
          (Spring MVC / Controller)
```

---

### Authentication Flow

```
Request → AuthenticationFilter
              └──► Creates unauthenticated token
                        └──► AuthenticationManager (ProviderManager)
                                  └──► AuthenticationProvider.supports()?
                                            └──► YES: authenticate()
                                                      └──► UserDetailsService.loadByUsername()
                                                                └──► PasswordEncoder.matches()
                                                                          └──► Return authenticated token
                                                                                    └──► SecurityContextHolder.set()
```

---

### Key Annotations Comparison Table

| Annotation | Module | Checks | SpEL |
|-----------|--------|--------|------|
| `@PreAuthorize` | Method Security | Before method | ✅ |
| `@PostAuthorize` | Method Security | After method (return value) | ✅ |
| `@PreFilter` | Method Security | Filter collection param | ✅ |
| `@PostFilter` | Method Security | Filter return collection | ✅ |
| `@Secured` | Method Security | Roles only | ❌ |
| `@RolesAllowed` | JSR-250 | Roles only | ❌ |

---

### 5.x vs 6.x Quick Reference

| Feature | Spring Security 5.x | Spring Security 6.x |
|---------|--------------------|--------------------|
| Config style | `WebSecurityConfigurerAdapter` | `SecurityFilterChain` bean |
| Matchers | `antMatchers()`, `mvcMatchers()` | `requestMatchers()` |
| Method security | `@EnableGlobalMethodSecurity` | `@EnableMethodSecurity` |
| Context persistence | `SecurityContextPersistenceFilter` | `SecurityContextHolderFilter` |
| Access decision | `AccessDecisionManager` + Voters | `AuthorizationManager` |
| URL security | `authorizeRequests()` | `authorizeHttpRequests()` |
| Lambda DSL | Optional | Mandatory |
| Servlet API | `javax.servlet` | `jakarta.servlet` |

---

### Common Interview One-Liners

- **`DelegatingFilterProxy`** bridges the Servlet container and Spring context via lazy bean lookup
- **`FilterChainProxy`** owns all `SecurityFilterChain` instances and dispatches to the first matching one
- **`ExceptionTranslationFilter`** does NOT throw — it only catches; `AuthorizationFilter` throws
- **Anonymous + `AccessDeniedException`** = redirect to login, not 403
- **`permitAll()`** does not skip filters — it only skips the authorization check
- **`ROLE_`** prefix is added by `hasRole()` but NOT by `hasAuthority()`
- **Credentials are erased** by `ProviderManager` after successful authentication (default)
- **`UsernameNotFoundException`** is masked as `BadCredentialsException` by default (prevents username enumeration)
- In 6.x, **`SecurityContextHolderFilter` does NOT auto-save** — auth filters must save explicitly

---
