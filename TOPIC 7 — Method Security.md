# TOPIC 7 — Method Security

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

---

## 1️⃣ Conceptual Explanation

---

### 7.1 What Is Method Security — Design Philosophy & Positioning

Method security brings authorization down from the HTTP layer into the **business logic layer**. While URL-based authorization (Topic 6) protects HTTP endpoints, method security protects **Java method invocations** — regardless of how they are called.

**Why method security exists alongside URL security:**

```
Without method security:
     HTTP Request → URL security (filter layer) → Controller → Service
                         ↑
                    Only protection point
                    Bypassed if:
                    - Service called from another service (internal call)
                    - Service called from @Scheduled task
                    - Service called from message consumer (Kafka, RabbitMQ)
                    - Service called from tests
                    - Service exposed via multiple controllers

With method security:
     HTTP Request → URL security → Controller → @PreAuthorize Service → @PreAuthorize Repository
                                                      ↑
                                              Protection is in the business layer
                                              Applies regardless of call source
```

**The architectural principle:** URL security is your first line of defense. Method security is your **defense-in-depth** — it ensures that even if URL security is misconfigured or bypassed, business operations are still protected.

---

### 7.2 `@EnableMethodSecurity` vs `@EnableGlobalMethodSecurity` — The 5.x vs 6.x Divide

**Spring Security 5.x — `@EnableGlobalMethodSecurity`:**

```java
@EnableGlobalMethodSecurity(
    prePostEnabled  = true,   // enables @PreAuthorize, @PostAuthorize, @PreFilter, @PostFilter
    securedEnabled  = true,   // enables @Secured
    jsr250Enabled   = true    // enables @RolesAllowed, @PermitAll, @DenyAll
)
```

**Spring Security 6.x — `@EnableMethodSecurity`:**

```java
@EnableMethodSecurity(
    // prePostEnabled = true  by DEFAULT (breaking change from 5.x!)
    securedEnabled  = false,  // @Secured disabled by default
    jsr250Enabled   = false   // @RolesAllowed disabled by default
)
```

**Critical differences:**

| Feature | `@EnableGlobalMethodSecurity` (5.x) | `@EnableMethodSecurity` (6.x) |
|---------|--------------------------------------|-------------------------------|
| Default pre/post | `false` — must opt in | `true` — enabled automatically |
| Internal engine | `GlobalMethodSecurityConfiguration` + `MethodSecurityInterceptor` | `AuthorizationManagerBeforeMethodInterceptor` + `AuthorizationManager` |
| Authorization | `AccessDecisionManager` + voters | `AuthorizationManager` directly |
| `@Secured` | Optional opt-in | Optional opt-in (disabled by default) |
| `@RolesAllowed` | Optional opt-in | Optional opt-in (disabled by default) |
| Proxy behavior | Same | Same |

**The breaking change in 6.x:** If you add `@EnableMethodSecurity` to a Spring Boot 3.x app, `@PreAuthorize` and friends are enabled **immediately** without needing `prePostEnabled=true`. If you were relying on them being disabled by default, this surprises you.

---

### 7.3 AOP Proxy Mechanics — The Engine Behind Method Security

Method security is implemented using **Spring AOP**. When you annotate a bean method with `@PreAuthorize`, Spring wraps the bean in a **proxy** that intercepts method calls, evaluates the security expression, and either proceeds or throws `AccessDeniedException`.

**The proxy creation process:**

```
Application startup:
     │
     ├── Spring scans beans for @PreAuthorize, @PostAuthorize, etc.
     │
     ├── For each annotated bean:
     │       Is target class an interface?
     │           YES → JDK Dynamic Proxy (implements same interfaces)
     │           NO  → CGLIB Proxy (subclasses the target class)
     │
     ├── Proxy wraps the target bean
     │       Target bean registered as: orderService (PROXY)
     │       Actual bean accessible via: proxy → target
     │
     └── All @Autowired references receive the PROXY, not the target
```

**JDK Dynamic Proxy:**

```
Interface:   OrderService
Implementation: OrderServiceImpl

Proxy:       $Proxy123 implements OrderService
                  ↓ delegates to
             OrderServiceImpl (actual logic)

@Autowired OrderService service;
// service IS $Proxy123 — the proxy
```

**CGLIB Proxy:**

```
Class:       OrderServiceImpl (no interface)

Proxy:       OrderServiceImpl$$EnhancerBySpringCGLIB$$abc123
             extends OrderServiceImpl
                  ↓ overrides methods, adds interception
             OrderServiceImpl (parent, actual logic)

@Autowired OrderServiceImpl service;
// service IS the CGLIB subclass proxy
```

---

### 7.4 The Self-Invocation Trap — The Most Critical Method Security Pitfall

**The most important concept in method security:**

```java
@Service
public class OrderService {

    @PreAuthorize("hasRole('USER')")
    public void placeOrder(Order order) {
        // ... place order
        validateOrder(order);  // internal call
    }

    @PreAuthorize("hasRole('ADMIN')")  // ← THIS IS NEVER CHECKED on internal call
    public void validateOrder(Order order) {
        // ... validate
    }
}
```

**Why self-invocation bypasses security:**

```
External call to placeOrder():
     Caller → PROXY.placeOrder()
                    ↓ AOP intercepts
               Check @PreAuthorize("hasRole('USER')") → OK
                    ↓ proceeds
               OrderServiceImpl.placeOrder()
                    ↓ calls validateOrder() DIRECTLY
               OrderServiceImpl.validateOrder()
               ← PROXY NEVER INVOLVED
               ← @PreAuthorize("hasRole('ADMIN')") NEVER EVALUATED
```

**Root cause:** When `placeOrder()` calls `validateOrder()` internally (`this.validateOrder()`), it calls the method on `this` — the actual `OrderServiceImpl` instance, NOT the proxy. AOP interception only happens when the proxy handles the call. Internal (`this`) calls bypass the proxy entirely.

**Solutions:**

```java
// Solution 1: Inject self-proxy (Spring-specific, inelegant)
@Service
public class OrderService {

    @Autowired
    @Lazy
    private OrderService self;  // This is the PROXY

    public void placeOrder(Order order) {
        self.validateOrder(order);  // Goes through proxy → AOP intercepts
    }

    @PreAuthorize("hasRole('ADMIN')")
    public void validateOrder(Order order) { ... }
}

// Solution 2: Move to separate bean (architecturally correct)
@Service
public class OrderService {
    @Autowired
    private OrderValidator orderValidator;  // Separate bean = separate proxy

    public void placeOrder(Order order) {
        orderValidator.validate(order);  // Goes through orderValidator's proxy
    }
}

@Service
public class OrderValidator {
    @PreAuthorize("hasRole('ADMIN')")
    public void validate(Order order) { ... }  // Protected correctly
}

// Solution 3: AspectJ mode (compile-time/load-time weaving — no proxy needed)
@EnableMethodSecurity(mode = AdviceMode.ASPECTJ)
// Weaves security checks directly into bytecode — no proxy, no self-invocation issue
// Requires AspectJ on classpath and compile-time/load-time weaving configuration
```

---

### 7.5 `@PreAuthorize` — Deep Internal Architecture

`@PreAuthorize` is the most powerful and most used method security annotation. It evaluates a SpEL expression **before** the method executes.

**Internal execution pipeline:**

```
Caller → Proxy.method()
               │
               ▼
AuthorizationManagerBeforeMethodInterceptor (6.x)
     │
     ├── Retrieve @PreAuthorize annotation from method/class
     │
     ├── Get MethodSecurityExpressionHandler
     │       └── DefaultMethodSecurityExpressionHandler
     │
     ├── Create EvaluationContext
     │       └── MethodSecurityEvaluationContext
     │               ├── authentication (current principal)
     │               ├── method arguments (available as #paramName)
     │               └── return value (null at pre-auth stage)
     │
     ├── Evaluate SpEL expression
     │       "hasRole('ADMIN') and #order.amount < 10000"
     │       └── SecurityExpressionRoot methods available
     │       └── #paramName binds to method parameter values
     │
     ├── Result = false → throw AccessDeniedException
     │
     └── Result = true → proceed to actual method
```

**Method parameter binding in SpEL:**

```java
// Parameters accessible via #parameterName
@PreAuthorize("hasRole('USER') and #userId == authentication.name")
public UserProfile getProfile(String userId) { ... }

// Object field access
@PreAuthorize("hasRole('ADMIN') or #order.customerId == authentication.name")
public void updateOrder(@P("order") Order order) { ... }
// @P("order") explicit binding — useful when param name isn't available at runtime

// Authentication object directly accessible
@PreAuthorize("authentication.name == #username")
public void deleteUser(String username) { ... }

// Principal object (often UserDetails)
@PreAuthorize("principal.email == #email")
public void updateEmail(String email) { ... }
```

**`@P` annotation for parameter name binding:**
Java compiles without parameter names by default (pre-Java 8). If you get "parameter not found in expression" errors, use `@P("name")` to explicitly name parameters, or compile with `-parameters` flag.

---

### 7.6 `@PostAuthorize` — Post-Execution Authorization

`@PostAuthorize` evaluates **after** the method executes. The return value is available as `returnObject` in the SpEL expression.

```java
// Use case: Can't know ownership BEFORE loading from DB
// Load first, then check if caller owns the result
@PostAuthorize("returnObject.owner == authentication.name or hasRole('ADMIN')")
public Order getOrder(Long orderId) {
    return orderRepository.findById(orderId)  // Always loads from DB
        .orElseThrow(() -> new NotFoundException("Order not found"));
}
```

**Internal flow:**

```
Caller → Proxy.getOrder(orderId)
               │
               ▼
AuthorizationManagerAfterMethodInterceptor (6.x)
     │
     ├── Invoke actual method → returns Order object
     │
     ├── Set returnObject = result in EvaluationContext
     │
     ├── Evaluate SpEL: "returnObject.owner == authentication.name"
     │
     ├── Result = false → throw AccessDeniedException
     │       ← Method ALREADY EXECUTED, return value DISCARDED
     │       ← DB was hit, side effects may have occurred
     │
     └── Result = true → return result to caller
```

**Critical implication:** The method always executes. If the method has **side effects** (writes to DB, sends email), those side effects occur even if `@PostAuthorize` denies access. Use `@PostAuthorize` only for **read operations** where the only risk is information disclosure.

---

### 7.7 `@PreFilter` — Collection Parameter Filtering

`@PreFilter` filters a **collection parameter** before the method is invoked. Elements that don't satisfy the expression are removed.

```java
// Only process orders that the current user owns
@PreFilter("filterObject.customerId == authentication.name")
public List<Order> processOrders(List<Order> orders) {
    // orders only contains orders owned by current user
    // other orders were silently removed
    return orderRepository.saveAll(orders);
}
```

**Internal flow:**

```
Caller passes: [Order(owner=alice), Order(owner=bob), Order(owner=alice)]
Current user: alice

@PreFilter("filterObject.customerId == authentication.name")
     │
     ├── Iterate collection
     ├── For each element (filterObject):
     │       filterObject.customerId == "alice"?
     │           Order(owner=alice) → true → KEEP
     │           Order(owner=bob)   → false → REMOVE
     │           Order(owner=alice) → true → KEEP
     │
     └── Filtered collection: [Order(owner=alice), Order(owner=alice)]
     → Method invoked with filtered list
```

**`filterTarget` for multiple collections:**

```java
// When method has multiple collection parameters
@PreFilter(value = "filterObject.status == 'ACTIVE'",
           filterTarget = "orders")  // specify which param to filter
public void processOrders(List<Order> orders, List<Customer> customers) { ... }
```

**Performance warning:** `@PreFilter` iterates the entire collection in memory. For large collections loaded from DB, this is inefficient — the DB loaded everything, then Java discards unwanted elements. Better approach: filter at the query level:

```java
// Better: filter in the query
@Query("SELECT o FROM Order o WHERE o.customerId = :#{authentication.name}")
List<Order> findOwnedOrders();
```

---

### 7.8 `@PostFilter` — Collection Return Filtering

`@PostFilter` filters the collection **returned** by the method, removing elements the current user shouldn't see.

```java
@PostFilter("filterObject.owner == authentication.name or hasRole('ADMIN')")
public List<Order> getAllOrders() {
    return orderRepository.findAll();  // loads ALL orders from DB
    // Spring then filters: removes orders not owned by current user
    // Admin sees all, user sees only their own
}
```

**Same performance concern:** All records loaded from DB, filtered in memory. Better to query with user context.

---

### 7.9 `@Secured` — Simple Role-Based Security

`@Secured` is the legacy annotation for role-based method security. It does NOT support SpEL — only role name strings.

```java
@Secured("ROLE_ADMIN")               // single role
@Secured({"ROLE_ADMIN", "ROLE_USER"}) // any of these roles (OR logic)
public void adminOperation() { ... }
```

**Limitations:**
- No SpEL — cannot access method parameters, return values
- Always OR logic — cannot express AND conditions
- Role strings must include `ROLE_` prefix (unlike `hasRole()` in SpEL)
- **Enabled with:** `@EnableMethodSecurity(securedEnabled = true)`

---

### 7.10 `@RolesAllowed` — JSR-250 Standard

`@RolesAllowed` is the JSR-250 standard annotation (from `javax.annotation.security`). Functionally equivalent to `@Secured` but portable across frameworks.

```java
@RolesAllowed("ADMIN")         // NO ROLE_ prefix — unlike @Secured
@RolesAllowed({"ADMIN", "USER"}) // OR logic
public void adminOperation() { ... }
```

```java
// Other JSR-250 annotations:
@PermitAll   // allow all authenticated users
@DenyAll     // deny all access
```

**Enabled with:** `@EnableMethodSecurity(jsr250Enabled = true)`

---

### 7.11 Annotation Comparison — Priority and Interaction

When multiple annotations exist, they ALL apply. There is no "overriding":

```java
@Secured("ROLE_USER")
@PreAuthorize("hasRole('ADMIN')")
public void conflictingMethod() {
    // To access: must satisfy BOTH @Secured AND @PreAuthorize
    // Must have ROLE_USER AND ROLE_ADMIN
    // Both interceptors run independently
}
```

**Annotation inheritance:**

```java
// Class-level annotation applies to all methods:
@PreAuthorize("isAuthenticated()")
@Service
public class OrderService {

    // Inherits class-level @PreAuthorize
    public void listOrders() { ... }

    // Method-level ADDS to class-level (both evaluated)
    @PreAuthorize("hasRole('ADMIN')")
    public void deleteOrder() {
        // Must satisfy BOTH:
        // isAuthenticated() (class level) AND hasRole('ADMIN') (method level)
    }
}
```

**5.x note:** In 5.x, method-level annotation **overrides** class-level for `@Secured`. In 6.x with `@PreAuthorize`, both are checked. This behavior can vary by annotation type — test thoroughly.

---

### 7.12 CGLIB Proxy Constraints — `final` Class and Method Traps

CGLIB creates subclasses. Subclassing has fundamental Java constraints:

```java
// ❌ CGLIB cannot proxy final class
@Service
public final class OrderService {       // final class → cannot subclass
    @PreAuthorize("hasRole('ADMIN')")   // ← @PreAuthorize SILENTLY IGNORED
    public void deleteOrder() { ... }
}

// ❌ CGLIB cannot override final method
@Service
public class OrderService {
    @PreAuthorize("hasRole('ADMIN')")
    public final void deleteOrder() { ... }  // final method → cannot override → IGNORED
}

// ❌ CGLIB cannot proxy private method
@Service
public class OrderService {
    @PreAuthorize("hasRole('ADMIN')")
    private void deleteOrder() { ... }  // private → cannot override → IGNORED
}
```

**These are silent failures — no exception is thrown. Security annotations on `final` classes, `final` methods, or `private` methods are silently ignored.** This is one of the most dangerous pitfalls in method security.

---

### 7.13 Method Security Interceptor Order (6.x)

In Spring Security 6.x, method security is implemented by multiple interceptors with explicit ordering:

```
Interceptor                                    Order    Annotation
─────────────────────────────────────────────────────────────────
AuthorizationManagerBeforeMethodInterceptor   500      @PreAuthorize
PreFilterAuthorizationMethodInterceptor       100      @PreFilter
AuthorizationManagerAfterMethodInterceptor    500      @PostAuthorize
PostFilterAuthorizationMethodInterceptor      900      @PostFilter
```

**Execution order for a method with all annotations:**

```
1. @PreFilter  (order 100)  — filter input collection
2. @PreAuthorize (order 500) — check pre-conditions
3. METHOD EXECUTES
4. @PostAuthorize (order 500) — check post-conditions
5. @PostFilter (order 900)   — filter output collection
```

---

### 7.14 Custom PermissionEvaluator — `hasPermission()` in SpEL

For complex authorization logic that doesn't fit simple role/authority checks, Spring Security provides `hasPermission()` SpEL function backed by `PermissionEvaluator`:

```java
@PreAuthorize("hasPermission(#order, 'UPDATE')")
public void updateOrder(Order order) { ... }

@PreAuthorize("hasPermission(#orderId, 'com.example.Order', 'DELETE')")
public void deleteOrder(Long orderId) { ... }
```

**Custom `PermissionEvaluator` implementation:**

```java
@Component
public class DomainPermissionEvaluator implements PermissionEvaluator {

    // Called when the actual object is passed:
    // hasPermission(#order, 'UPDATE')
    @Override
    public boolean hasPermission(Authentication auth,
                                 Object targetDomainObject,
                                 Object permission) {
        if (targetDomainObject instanceof Order order) {
            return switch (permission.toString()) {
                case "UPDATE" -> order.getOwnerId()
                    .equals(getUserId(auth)) || hasRole(auth, "ADMIN");
                case "VIEW"   -> true;
                default       -> false;
            };
        }
        return false;
    }

    // Called when only ID and type are passed:
    // hasPermission(#orderId, 'com.example.Order', 'DELETE')
    @Override
    public boolean hasPermission(Authentication auth,
                                 Serializable targetId,
                                 String targetType,
                                 Object permission) {
        // Load object by ID, then check
        if ("com.example.Order".equals(targetType)) {
            Order order = orderRepo.findById((Long) targetId).orElse(null);
            return order != null && hasPermission(auth, order, permission);
        }
        return false;
    }
}
```

**Register:**
```java
@Bean
public MethodSecurityExpressionHandler methodSecurityExpressionHandler(
        DomainPermissionEvaluator permissionEvaluator) {
    DefaultMethodSecurityExpressionHandler handler =
        new DefaultMethodSecurityExpressionHandler();
    handler.setPermissionEvaluator(permissionEvaluator);
    return handler;
}
```

---

## 2️⃣ Code Examples

---

### Example 1 — Complete Method Security Setup (6.x)

```java
@Configuration
@EnableWebSecurity
@EnableMethodSecurity(
    // prePostEnabled = true by default in 6.x
    securedEnabled = true,    // enable @Secured
    jsr250Enabled  = true     // enable @RolesAllowed
)
public class MethodSecurityConfig {

    @Bean
    public MethodSecurityExpressionHandler methodSecurityExpressionHandler(
            DomainPermissionEvaluator permissionEvaluator) {
        DefaultMethodSecurityExpressionHandler handler =
            new DefaultMethodSecurityExpressionHandler();
        handler.setPermissionEvaluator(permissionEvaluator);
        // Optional: set role hierarchy
        handler.setRoleHierarchy(roleHierarchy());
        return handler;
    }

    @Bean
    public RoleHierarchy roleHierarchy() {
        RoleHierarchyImpl hierarchy = new RoleHierarchyImpl();
        // ADMIN inherits all USER authorities
        hierarchy.setHierarchy("ROLE_ADMIN > ROLE_USER");
        return hierarchy;
    }
}
```

---

### Example 2 — Comprehensive Annotation Usage

```java
@Service
@Transactional
public class OrderService {

    // ── @PreAuthorize with SpEL ───────────────────────────────────────
    @PreAuthorize("hasRole('USER')")
    public List<Order> getMyOrders() {
        String username = SecurityContextHolder.getContext()
            .getAuthentication().getName();
        return orderRepository.findByUsername(username);
    }

    // ── @PreAuthorize with parameter access ──────────────────────────
    @PreAuthorize("hasRole('ADMIN') or #username == authentication.name")
    public List<Order> getOrdersForUser(String username) {
        return orderRepository.findByUsername(username);
    }

    // ── @PostAuthorize for ownership check ───────────────────────────
    @PostAuthorize("returnObject.username == authentication.name" +
                   " or hasRole('ADMIN')")
    public Order getOrderById(Long id) {
        return orderRepository.findById(id)
            .orElseThrow(() -> new OrderNotFoundException(id));
    }

    // ── @PreFilter on input collection ───────────────────────────────
    @PreAuthorize("hasRole('USER')")
    @PreFilter("filterObject.username == authentication.name")
    public List<Order> bulkUpdateOrders(List<Order> orders) {
        return orderRepository.saveAll(orders);
    }

    // ── @PostFilter on returned collection ───────────────────────────
    @PostFilter("filterObject.username == authentication.name" +
                " or hasRole('ADMIN')")
    public List<Order> getAllOrders() {
        return orderRepository.findAll();
    }

    // ── @PreAuthorize with hasPermission() ───────────────────────────
    @PreAuthorize("hasPermission(#orderId, 'com.example.Order', 'CANCEL')")
    public void cancelOrder(Long orderId) {
        orderRepository.updateStatus(orderId, OrderStatus.CANCELLED);
    }

    // ── @Secured ─────────────────────────────────────────────────────
    @Secured("ROLE_ADMIN")
    public void deleteOrder(Long orderId) {
        orderRepository.deleteById(orderId);
    }

    // ── @RolesAllowed ────────────────────────────────────────────────
    @RolesAllowed({"ADMIN", "MANAGER"})
    public void approveOrder(Long orderId) {
        orderRepository.updateStatus(orderId, OrderStatus.APPROVED);
    }

    // ── Combined annotations (ALL must pass) ─────────────────────────
    @PreAuthorize("isFullyAuthenticated()")  // not remember-me
    @PreAuthorize("hasRole('ADMIN')")        // must be admin
    public void purgeOrders() {
        orderRepository.deleteAll();
    }
    // NOTE: Only the LAST @PreAuthorize applies in Java!
    // Java doesn't support duplicate annotations without @Repeatable
    // In 6.x, @PreAuthorize IS @Repeatable — both are evaluated
}
```

---

### Example 3 — Self-Invocation Problem & Solutions

```java
// ❌ PROBLEM: self-invocation bypasses security
@Service
public class PaymentService {

    public void processPayment(Payment payment) {
        // Internal call — proxy bypassed!
        validatePayment(payment);  // @PreAuthorize NEVER runs
    }

    @PreAuthorize("hasRole('PAYMENT_VALIDATOR')")
    public void validatePayment(Payment payment) {
        // This security check is BYPASSED when called internally
    }
}

// ✓ SOLUTION 1: Separate bean
@Service
public class PaymentService {
    @Autowired
    private PaymentValidator validator;  // separate proxy

    public void processPayment(Payment payment) {
        validator.validate(payment);  // Goes through validator's proxy ✓
    }
}

@Service
public class PaymentValidator {
    @PreAuthorize("hasRole('PAYMENT_VALIDATOR')")
    public void validate(Payment payment) { ... }
}

// ✓ SOLUTION 2: ApplicationContext self-injection (Spring-managed)
@Service
public class PaymentService implements ApplicationContextAware {

    private PaymentService self;

    @Override
    public void setApplicationContext(ApplicationContext ctx) {
        self = ctx.getBean(PaymentService.class);  // gets the proxy
    }

    public void processPayment(Payment payment) {
        self.validatePayment(payment);  // Through proxy ✓
    }

    @PreAuthorize("hasRole('PAYMENT_VALIDATOR')")
    public void validatePayment(Payment payment) { ... }
}
```

---

### Example 4 — Role Hierarchy in Method Security

```java
@Bean
public RoleHierarchy roleHierarchy() {
    RoleHierarchyImpl hierarchy = new RoleHierarchyImpl();
    // SUPER_ADMIN > ADMIN > MANAGER > USER
    hierarchy.setHierarchy(
        "ROLE_SUPER_ADMIN > ROLE_ADMIN\n" +
        "ROLE_ADMIN > ROLE_MANAGER\n" +
        "ROLE_MANAGER > ROLE_USER"
    );
    return hierarchy;
}
```

```java
@Service
public class ReportService {

    @PreAuthorize("hasRole('USER')")  // MANAGER, ADMIN, SUPER_ADMIN also pass
    public List<Report> getUserReports() { ... }

    @PreAuthorize("hasRole('ADMIN')")  // ADMIN and SUPER_ADMIN pass, USER/MANAGER don't
    public List<Report> getAllReports() { ... }
}
```

**Without role hierarchy registered in `MethodSecurityExpressionHandler`:**
Role hierarchy only works for URL security by default. For method security, you must explicitly register it:

```java
@Bean
public MethodSecurityExpressionHandler handler() {
    DefaultMethodSecurityExpressionHandler h =
        new DefaultMethodSecurityExpressionHandler();
    h.setRoleHierarchy(roleHierarchy());  // ← Required for method security
    return h;
}
// Without this: ADMIN does NOT satisfy hasRole('USER') in @PreAuthorize
```

---

### Example 5 — Method Security in Repository Layer

```java
// Securing at the repository level — defense-in-depth
@Repository
public interface OrderRepository extends JpaRepository<Order, Long> {

    // Only admins can query all orders
    @PreAuthorize("hasRole('ADMIN')")
    List<Order> findAll();

    // Users can only see their own orders
    @PostFilter("filterObject.username == authentication.name")
    List<Order> findByStatus(OrderStatus status);

    // Pre-filter the IDs to delete
    @PreAuthorize("hasRole('ADMIN')")
    void deleteById(Long id);
}
```

---

### Example 6 — Testing Method Security

```java
@SpringBootTest
class OrderServiceSecurityTest {

    @Autowired
    private OrderService orderService;

    // ── Test with mock user ───────────────────────────────────────────
    @Test
    @WithMockUser(roles = "USER")
    void userCanGetOwnOrders() {
        assertDoesNotThrow(() -> orderService.getMyOrders());
    }

    // ── Test authorization failure ────────────────────────────────────
    @Test
    @WithMockUser(roles = "USER")
    void userCannotDeleteOrder() {
        assertThrows(AccessDeniedException.class,
            () -> orderService.deleteOrder(1L));
    }

    // ── Test with specific username ────────────────────────────────────
    @Test
    @WithMockUser(username = "alice", roles = "USER")
    void userCanOnlyAccessOwnProfile() {
        // @PreAuthorize("#username == authentication.name")
        assertDoesNotThrow(() -> orderService.getOrdersForUser("alice"));
        assertThrows(AccessDeniedException.class,
            () -> orderService.getOrdersForUser("bob"));  // not alice
    }

    // ── Test with custom UserDetails ──────────────────────────────────
    @Test
    @WithUserDetails("alice")  // loads from UserDetailsService
    void testWithRealUserDetails() {
        assertDoesNotThrow(() -> orderService.getMyOrders());
    }

    // ── Test anonymous access ──────────────────────────────────────────
    @Test
    @WithAnonymousUser
    void anonymousUserCannotAccessOrders() {
        assertThrows(AuthenticationCredentialsNotFoundException.class,
            () -> orderService.getMyOrders());
        // Note: AccessDeniedException for anonymous in method security
        // becomes AuthenticationCredentialsNotFoundException
        // if SecurityContext is empty (no anonymous token in unit test context)
    }
}
```

---

### Example 7 — Incorrect Configurations

```java
// ❌ WRONG 1 — @PreAuthorize on private method (CGLIB can't proxy)
@Service
public class OrderService {
    @PreAuthorize("hasRole('ADMIN')")
    private void internalAdminOp() { }  // SILENTLY IGNORED
}

// ❌ WRONG 2 — @PreAuthorize on final method (CGLIB can't override)
@Service
public class OrderService {
    @PreAuthorize("hasRole('ADMIN')")
    public final void securedFinalMethod() { }  // SILENTLY IGNORED
}

// ❌ WRONG 3 — Missing @EnableMethodSecurity
@SpringBootApplication
// No @EnableMethodSecurity or @EnableGlobalMethodSecurity
public class App { }

@Service
public class OrderService {
    @PreAuthorize("hasRole('ADMIN')")  // annotations present but DO NOTHING
    public void adminOp() { }
}

// ❌ WRONG 4 — @PreAuthorize on @Bean method in @Configuration
@Configuration
public class AppConfig {
    @Bean
    @PreAuthorize("hasRole('ADMIN')")  // IGNORED — @Bean methods not proxied for security
    public MyService myService() {
        return new MyService();
    }
}

// ❌ WRONG 5 — Expecting 5.x behavior in 6.x
// 5.x: @EnableGlobalMethodSecurity(prePostEnabled = false) by default
// 6.x: @EnableMethodSecurity — prePostEnabled = TRUE by default
// Upgrading from 5.x to 6.x may suddenly enable method security you didn't want
```

---

## 3️⃣ Exam-Style Questions

---

**Q1 (MCQ):** What happens when a Spring bean with `@PreAuthorize` calls another method in the same class that also has `@PreAuthorize`?

A. Both `@PreAuthorize` expressions are evaluated
B. Only the outer method's `@PreAuthorize` is evaluated; the inner call bypasses security
C. Spring Security throws a `SecurityException` to prevent unsafe calls
D. The inner method's security is evaluated by the `SecurityContextHolder`

**Answer: B**
Self-invocation bypasses AOP proxy interception. The inner call goes directly to `this.method()` on the actual bean instance, not through the proxy. The inner `@PreAuthorize` annotation is completely ignored.

---

**Q2 (MCQ):** Which annotation supports SpEL expressions and can access method return values?

A. `@PreAuthorize`
B. `@PostAuthorize`
C. `@Secured`
D. `@RolesAllowed`

**Answer: B**
`@PostAuthorize` evaluates after method execution and provides `returnObject` in the SpEL context. `@PreAuthorize` supports SpEL but runs before execution (no return value). `@Secured` and `@RolesAllowed` do NOT support SpEL at all.

---

**Q3 (Select All That Apply):** Which are true about CGLIB proxies and method security?

A. CGLIB creates a subclass of the target bean
B. `@PreAuthorize` on a `private` method is silently ignored
C. `@PreAuthorize` on a `final` method throws `BeanCreationException` at startup
D. CGLIB is used when the target class implements at least one interface
E. `@PreAuthorize` on a `final` class is silently ignored

**Answer: A, B, E**
C is false — final methods on non-final classes are silently ignored, not exceptions.
D is false — when a class implements an interface, JDK dynamic proxy is used (not CGLIB). CGLIB is used for concrete classes without interfaces (or when `proxyTargetClass=true`).

---

**Q4 (Code Behavior):**

```java
@EnableMethodSecurity  // Spring Security 6.x
@SpringBootApplication
public class App { }

@Service
public class DataService {
    @PreAuthorize("hasRole('ADMIN')")
    public final String sensitiveData() {
        return "TOP SECRET";
    }
}
```

A user with `ROLE_USER` calls `dataService.sensitiveData()`. What happens?

A. `AccessDeniedException` thrown — `@PreAuthorize` enforced
B. `"TOP SECRET"` returned — `@PreAuthorize` silently ignored (final method)
C. `BeanCreationException` at startup
D. `UnsupportedOperationException` at runtime

**Answer: B**
`sensitiveData()` is a `final` method. CGLIB cannot override `final` methods. Therefore the AOP interceptor cannot be applied. `@PreAuthorize` is **silently ignored**. The method executes without any security check. This is a critical silent security failure.

---

**Q5 (Select All That Apply):** Which statements about `@PostAuthorize` are correct?

A. The method body always executes before the authorization check
B. `returnObject` refers to the method's return value in SpEL
C. If authorization fails, the method's return value is still returned to the caller
D. Side effects in the method body persist even if `@PostAuthorize` denies access
E. `@PostAuthorize` is suitable for protecting write operations

**Answer: A, B, D**
C is false — if denied, `AccessDeniedException` is thrown; the return value is discarded.
E is false — `@PostAuthorize` is NOT suitable for writes because side effects (DB writes, etc.) already happened before the check. Use `@PreAuthorize` for write operations.

---

**Q6 (Annotation Comparison):**

```java
@Secured("ADMIN")
public void methodA() { }

@Secured("ROLE_ADMIN")
public void methodB() { }

@PreAuthorize("hasRole('ADMIN')")
public void methodC() { }

@RolesAllowed("ADMIN")
public void methodD() { }
```

A user has `GrantedAuthority("ROLE_ADMIN")`. Which methods can they access?

**Answer:**
- `methodA()`: `@Secured("ADMIN")` — checks for authority `"ADMIN"` exactly (no prefix added). User has `"ROLE_ADMIN"`, not `"ADMIN"`. **DENIED**
- `methodB()`: `@Secured("ROLE_ADMIN")` — checks for authority `"ROLE_ADMIN"`. User has it. **GRANTED**
- `methodC()`: `@PreAuthorize("hasRole('ADMIN')")` — `hasRole` adds `ROLE_` → checks `"ROLE_ADMIN"`. User has it. **GRANTED**
- `methodD()`: `@RolesAllowed("ADMIN")` — checks for authority `"ROLE_ADMIN"` (adds prefix, similar to `hasRole`). **GRANTED**

**Critical trap:** `@Secured` does NOT add `ROLE_` prefix. You must include it explicitly. `@RolesAllowed` DOES add the prefix (similar to `hasRole`).

---

**Q7 (SpEL Parameter Binding):**

```java
@PreAuthorize("#user.id == authentication.principal.id or hasRole('ADMIN')")
public void updateUser(@P("user") UserDto user) { ... }
```

A user with ID `42` and `ROLE_USER` calls `updateUser(new UserDto(id=99))`. What happens?

**Answer:** `AccessDeniedException` is thrown.
- `#user.id` = 99 (from the `UserDto` parameter)
- `authentication.principal.id` = 42 (current user's ID)
- `99 == 42` → false
- `hasRole('ADMIN')` → false (user has ROLE_USER)
- Both conditions false → SpEL result = false → `AccessDeniedException`

---

**Q8 (Tricky — Missing `@EnableMethodSecurity`):**

```java
// No @EnableMethodSecurity anywhere
@Service
public class SecureService {
    @PreAuthorize("hasRole('ADMIN')")
    public String sensitiveOp() { return "data"; }
}
```

A user with only `ROLE_USER` calls `sensitiveOp()`. What happens?

A. `AccessDeniedException` — Spring Boot auto-enables method security
B. `"data"` returned — method security not enabled, annotation ignored
C. `BeanCreationException` — invalid configuration detected at startup
D. `IllegalStateException` — no `AuthenticationManager` configured

**Answer: B**
Without `@EnableMethodSecurity` (or its 5.x equivalent), Spring Security does not create the AOP interceptors. `@PreAuthorize` annotations are present in bytecode but no interceptor processes them. The method executes freely for all callers regardless of their roles.

---

## 4️⃣ Trick Analysis

---

**Trick 1 — `@Secured` Does NOT Auto-Add `ROLE_` Prefix**

```java
// The most common @Secured mistake:
@Secured("ADMIN")       // checks authority "ADMIN" — NO ROLE_ prefix
@Secured("ROLE_ADMIN")  // checks authority "ROLE_ADMIN" — CORRECT if stored with prefix

// vs @PreAuthorize:
@PreAuthorize("hasRole('ADMIN')")  // checks "ROLE_ADMIN" — adds prefix automatically

// If your UserDetails stores "ROLE_ADMIN":
@Secured("ROLE_ADMIN") ✓
@Secured("ADMIN")      ✗ — won't match "ROLE_ADMIN"
```

---

**Trick 2 — `@EnableMethodSecurity` prePostEnabled=true By Default in 6.x**

```java
// 5.x — prePostEnabled is FALSE by default:
@EnableGlobalMethodSecurity  // @PreAuthorize does nothing until prePostEnabled=true

// 6.x — prePostEnabled is TRUE by default:
@EnableMethodSecurity        // @PreAuthorize active immediately

// Migration trap: adding @EnableMethodSecurity to a 5.x app that previously
// had @EnableGlobalMethodSecurity(prePostEnabled=false) suddenly ACTIVATES
// all @PreAuthorize annotations that were previously inert
```

---

**Trick 3 — `@PreAuthorize` on Interface Methods**

```java
public interface OrderService {
    @PreAuthorize("hasRole('ADMIN')")
    void deleteOrder(Long id);
}

@Service
public class OrderServiceImpl implements OrderService {
    @Override
    public void deleteOrder(Long id) { ... }  // no annotation here
}
```

**Does the interface-level annotation work?**
With JDK dynamic proxy (interface-based): **YES** — the proxy reads annotations from the interface method.
With CGLIB proxy (class-based): **DEPENDS** — CGLIB may not read interface annotations. Using `@EnableMethodSecurity` with default settings, Spring 6.x uses `AnnotationUtils` which traverses the class hierarchy including interfaces. Generally works but the explicit recommendation is to annotate the implementation.

---

**Trick 4 — `@PostFilter` Modifies the Returned Collection In-Place**

```java
@PostFilter("filterObject.owner == authentication.name")
public List<Order> getOrders() {
    return orderRepository.findAll();  // returns ArrayList
}
```

`@PostFilter` **modifies the returned collection in-place** (removes elements from it). If the returned collection is **immutable** (e.g., `List.of(...)`, `Collections.unmodifiableList()`), `@PostFilter` throws `UnsupportedOperationException`. Always return a mutable list when using `@PostFilter`.

---

**Trick 5 — Method Security Does Not Apply to `@Configuration` Beans**

```java
@Configuration
public class Config {
    @Bean
    @PreAuthorize("hasRole('ADMIN')")  // COMPLETELY IGNORED
    public DataSource dataSource() { ... }
}
```

`@Configuration` classes are processed at application startup before the security context is available. `@Bean` methods are not proxied for security. Method security only applies to beans managed by the Spring container AFTER full initialization.

---

**Trick 6 — `AuthenticationCredentialsNotFoundException` vs `AccessDeniedException` in Tests**

```java
@Test
// No @WithMockUser — SecurityContext is EMPTY
void testWithNoSecurityContext() {
    assertThrows(
        AuthenticationCredentialsNotFoundException.class,  // NOT AccessDeniedException
        () -> orderService.getMyOrders()
    );
}
```

When there is NO `Authentication` in `SecurityContext` (not even anonymous), method security throws `AuthenticationCredentialsNotFoundException`, not `AccessDeniedException`. In web context with filters, `AnonymousAuthenticationFilter` always sets an anonymous token. But in unit tests without the full filter chain, the context is truly empty.

---

**Trick 7 — Role Hierarchy Must Be Registered Twice for Both URL and Method Security**

```java
// For URL security (automatic via HttpSecurity):
@Bean
public RoleHierarchy roleHierarchy() {
    RoleHierarchyImpl h = new RoleHierarchyImpl();
    h.setHierarchy("ROLE_ADMIN > ROLE_USER");
    return h;
}
// Spring Security auto-configures this for URL security

// For Method security (MANUAL registration required):
@Bean
public MethodSecurityExpressionHandler handler() {
    DefaultMethodSecurityExpressionHandler h =
        new DefaultMethodSecurityExpressionHandler();
    h.setRoleHierarchy(roleHierarchy());  // ← MUST do this explicitly
    return h;
}

// WITHOUT the second bean:
// ADMIN satisfies hasRole('USER') in URL security ✓
// ADMIN does NOT satisfy hasRole('USER') in @PreAuthorize ✗
// This asymmetry is a famous bug in Spring Security setups
```

---

## 5️⃣ Summary Sheet

---

### Method Security Execution Flow

```
External Caller
     │
     ▼
PROXY (JDK Dynamic Proxy or CGLIB Subclass)
     │
     ▼
[1] PreFilterAuthorizationMethodInterceptor  ← @PreFilter  (order 100)
     │  Filters input collection
     ▼
[2] AuthorizationManagerBeforeMethodInterceptor ← @PreAuthorize (order 500)
     │  SpEL evaluated BEFORE execution
     │  false → throw AccessDeniedException ← request never reaches method
     ▼
[3] ACTUAL METHOD EXECUTES
     │  Returns value / mutates state / DB operations
     ▼
[4] AuthorizationManagerAfterMethodInterceptor ← @PostAuthorize (order 500)
     │  SpEL evaluated with returnObject
     │  false → throw AccessDeniedException ← return value discarded, side effects kept
     ▼
[5] PostFilterAuthorizationMethodInterceptor ← @PostFilter (order 900)
     │  Filters return collection in-place
     ▼
Return filtered/validated result to caller
```

---

### Annotation Comparison Table

| Annotation | SpEL | Timing | Param Access | Return Access | ROLE_ prefix |
|-----------|------|--------|-------------|--------------|-------------|
| `@PreAuthorize` | ✅ | Before | ✅ `#param` | ❌ | Auto (via `hasRole`) |
| `@PostAuthorize` | ✅ | After | ✅ `#param` | ✅ `returnObject` | Auto |
| `@PreFilter` | ✅ | Before | ✅ `filterObject` | ❌ | Auto |
| `@PostFilter` | ✅ | After | ❌ | ✅ `filterObject` | Auto |
| `@Secured` | ❌ | Before | ❌ | ❌ | Manual (`ROLE_X`) |
| `@RolesAllowed` | ❌ | Before | ❌ | ❌ | Auto (adds `ROLE_`) |

---

### Proxy Type Decision

```
Target class implements interface(s)?
     │
     ├── YES → JDK Dynamic Proxy (default)
     │             Proxy implements same interface(s)
     │             @Autowire by interface type
     │
     └── NO  → CGLIB Proxy (always)
                   Proxy subclasses target class
                   @Autowire by class type
                   Cannot proxy: final class, final method, private method
```

---

### Self-Invocation Quick Reference

```
FAILS (security bypassed):    this.securedMethod()
FAILS (security bypassed):    securedMethod()  [implicit this]

WORKS (proxy involved):       injectedBean.securedMethod()
WORKS (proxy involved):       self.securedMethod()  [where self = injected proxy]
WORKS (proxy involved):       ((MyService)AopContext.currentProxy()).securedMethod()
```

---

### Common Interview One-Liners

- **`@PreAuthorize` on `private`/`final` methods** = silently ignored — no exception, no security
- **Self-invocation** bypasses AOP proxy — inner `@PreAuthorize` never evaluates
- **`@PostAuthorize` failure** = method already executed, side effects persist, return value discarded
- **`@Secured("ADMIN")`** checks `"ADMIN"` literally — does NOT add `ROLE_` (unlike `hasRole`)
- **`@RolesAllowed("ADMIN")`** checks `"ROLE_ADMIN"` — adds `ROLE_` prefix automatically
- **`@EnableMethodSecurity`** in 6.x enables `prePostEnabled` by DEFAULT (unlike 5.x)
- **Role hierarchy in method security** requires explicit `MethodSecurityExpressionHandler` registration
- **`@PostFilter` modifies collection in-place** — immutable collection → `UnsupportedOperationException`
- **No `Authentication` in context** → `AuthenticationCredentialsNotFoundException` (not `AccessDeniedException`)
- **`@PreAuthorize` on `@Configuration` `@Bean` methods** = silently ignored

---
