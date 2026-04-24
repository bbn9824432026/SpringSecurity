# Topic 7: Method Security — Complete Developer Mastery

Method security is where authorization moves from the infrastructure layer into your business logic. Everything in Topic 6 protected the *door* — method security protects the *room itself*, regardless of which door someone used to enter. Let me build this up layer by layer, starting with the foundational AOP mechanics that make the entire system possible.

---

## Layer 1: The Design Philosophy — Why Method Security Exists

The critical insight is that URL-based authorization has a fundamental blind spot: it only sees HTTP requests. Your `OrderService` doesn't care how it gets called. It can be invoked from a controller, from a scheduled job, from a Kafka consumer, from another service, or from a test. URL security protects exactly one of those paths.

```
URL Security coverage:
     HTTP Request → [SecurityFilterChain] → Controller → OrderService
                           ↑
                    Only this path is protected

Method Security coverage:
     HTTP Request → [SecurityFilterChain] → Controller → [AOP Proxy] → OrderService
                                                                ↑
     Scheduled job ──────────────────────────────────────────► same proxy
     Kafka consumer ─────────────────────────────────────────► same proxy
     Internal service call ──────────────────────────────────► same proxy
                                                     Protection lives IN the service
```

This is why method security is described as defense-in-depth. URL security is your perimeter fence. Method security is the lock on the door of each individual room. Even if someone gets through the fence, the rooms are still protected.

---

## Layer 2: AOP Proxy Mechanics — The Engine Under the Hood

Before understanding any annotation, you must understand how Spring applies security to methods at all. The answer is AOP proxies — one of the most important architectural patterns in the Spring ecosystem.

When you enable method security and annotate a bean, Spring doesn't modify your class. Instead, it wraps it in a proxy object that intercepts method calls, runs the security check, and either proceeds to your actual method or throws `AccessDeniedException`. Your application wires the proxy everywhere your bean is referenced.

```java
/**
 * LAYER 2: AOP Proxy creation — what happens at startup.
 *
 * Spring chooses between two proxy strategies based on whether
 * your class implements an interface:
 *
 *   Interface available → JDK Dynamic Proxy (implements same interfaces)
 *   No interface        → CGLIB Proxy (subclasses the target class)
 *
 * This choice has profound implications for which methods CAN be secured.
 */

// ─── JDK Dynamic Proxy scenario ─────────────────────────────────────────────
// Your interface:
public interface OrderService {
    void placeOrder(Order order);    // public contract
    void cancelOrder(Long orderId);
}

// Your implementation:
@Service
public class OrderServiceImpl implements OrderService {
    @Override
    public void placeOrder(Order order) { /* real logic */ }

    @Override
    public void cancelOrder(Long orderId) { /* real logic */ }
}

// What Spring creates at startup:
// $Proxy123 implements OrderService {
//     void placeOrder(Order order) {
//         // ← AOP advice fires here (security check)
//         delegate.placeOrder(order);  // calls actual bean if check passes
//     }
// }

// What gets injected everywhere:
@Service
public class CheckoutService {
    @Autowired
    private OrderService orderService; // this IS $Proxy123, not OrderServiceImpl
}

// ─── CGLIB Proxy scenario ────────────────────────────────────────────────────
// Your concrete class (no interface):
@Service
public class ReportService {
    public void generateReport() { /* real logic */ }
}

// What Spring creates at startup:
// ReportService$$EnhancerBySpringCGLIB$$abc123 extends ReportService {
//     @Override
//     public void generateReport() {
//         // ← AOP advice fires here (security check)
//         super.generateReport();  // calls actual logic if check passes
//     }
// }
```

The CGLIB approach has one critical constraint: it works by creating a **subclass**. This means the three fundamental limitations of Java subclassing apply directly to method security:

```java
/**
 * The three silent failure scenarios — all produce NO exception,
 * NO warning, and NO security enforcement. The method just runs freely.
 *
 * These are among the most dangerous bugs in Spring Security because
 * the application appears to work normally while providing zero protection.
 */
@Service
public class DangerousExamples {

    // ❌ CGLIB cannot override a private method.
    // The proxy subclass can't see it, so the interceptor is never applied.
    @PreAuthorize("hasRole('ADMIN')")
    private void privateAdminOp() {
        // RUNS FOR ANYONE — @PreAuthorize silently ignored
    }

    // ❌ CGLIB cannot override a final method.
    // Java's final keyword explicitly forbids subclass overrides.
    @PreAuthorize("hasRole('ADMIN')")
    public final void finalAdminOp() {
        // RUNS FOR ANYONE — @PreAuthorize silently ignored
    }
}

// ❌ CGLIB cannot subclass a final class at all.
@Service
public final class FinancialService {
    @PreAuthorize("hasRole('FINANCE')")
    public void processPayroll() {
        // RUNS FOR ANYONE — entire class's security is silently ignored
    }
}
```

There is no startup error, no warning in the logs, no runtime exception. The annotations are present in the bytecode. Spring just can't do anything with them. This is why code review for method security must specifically check for `final` and `private` annotated methods.

---

## Layer 3: `@EnableMethodSecurity` — The Activation Switch

```java
/**
 * LAYER 3: Enabling method security — the 5.x vs 6.x difference.
 *
 * The most important behavioral change between versions is the DEFAULT
 * for prePostEnabled. In 5.x it's false (you must opt in). In 6.x it's
 * true (active the moment you put the annotation on your config class).
 */

// ─── Spring Security 6.x (Spring Boot 3.x) ──────────────────────────────────
@Configuration
@EnableWebSecurity
@EnableMethodSecurity(
    // prePostEnabled = true  ← DEFAULT in 6.x — @PreAuthorize/@PostAuthorize active
    securedEnabled = false,    // @Secured disabled by default — opt in if needed
    jsr250Enabled  = false     // @RolesAllowed disabled by default — opt in if needed
)
public class SecurityConfig {

    /**
     * For method security to use role hierarchy (e.g., ROLE_ADMIN implies ROLE_USER),
     * you MUST register a MethodSecurityExpressionHandler with the hierarchy explicitly.
     *
     * This is a famous asymmetry: URL security picks up RoleHierarchy automatically
     * from the Spring context. Method security does NOT — it requires this explicit
     * registration. Without it, an ADMIN user fails a @PreAuthorize("hasRole('USER')")
     * check in method security, even though they'd pass the same check in URL security.
     */
    @Bean
    public MethodSecurityExpressionHandler methodSecurityExpressionHandler(
            RoleHierarchy roleHierarchy,
            PermissionEvaluator permissionEvaluator) {
        DefaultMethodSecurityExpressionHandler handler =
            new DefaultMethodSecurityExpressionHandler();
        handler.setRoleHierarchy(roleHierarchy);
        handler.setPermissionEvaluator(permissionEvaluator);
        return handler;
    }

    @Bean
    public RoleHierarchy roleHierarchy() {
        RoleHierarchyImpl hierarchy = new RoleHierarchyImpl();
        // ADMIN inherits all MANAGER permissions, MANAGER inherits all USER permissions
        hierarchy.setHierarchy("""
            ROLE_ADMIN > ROLE_MANAGER
            ROLE_MANAGER > ROLE_USER
            """);
        return hierarchy;
    }
}

// ─── Spring Security 5.x (Spring Boot 2.x) ──────────────────────────────────
@EnableGlobalMethodSecurity(
    prePostEnabled = true,  // must explicitly opt in
    securedEnabled = true,
    jsr250Enabled  = true
)
// Uses older engine: MethodSecurityInterceptor + AccessDecisionManager + voters
// Instead of: AuthorizationManagerBeforeMethodInterceptor + AuthorizationManager
```

---

## Layer 4: `@PreAuthorize` — Deep Internal Architecture

`@PreAuthorize` is the workhorse of method security. It evaluates a SpEL expression *before* the method executes, which means it can prevent the method from running at all — no side effects, no DB queries, nothing.

```java
/**
 * LAYER 4A: @PreAuthorize — the complete internal execution pipeline.
 *
 * When your proxy intercepts a call to an @PreAuthorize-annotated method,
 * it runs through this sequence before ever touching your actual code.
 */

// What the AOP interceptor does, step by step:
// 1. Retrieve the @PreAuthorize annotation from the method (or class)
// 2. Ask DefaultMethodSecurityExpressionHandler to create an evaluation context
// 3. The context is populated with: the current Authentication, the method
//    arguments bound to their parameter names, and the target object (this)
// 4. Evaluate the SpEL expression against this context
// 5. If false → throw AccessDeniedException (method never runs)
// 6. If true → proceed to the actual method

@Service
@RequiredArgsConstructor
public class OrderService {

    private final OrderRepository orderRepository;

    // ── Basic role check ─────────────────────────────────────────────────────
    @PreAuthorize("hasRole('USER')")
    public List<Order> getMyOrders() {
        // SecurityContextHolder is always accessible inside the method too,
        // but it's better practice to use SpEL for the authorization decision
        // and extract identity inside the method body for data filtering.
        String username = SecurityContextHolder.getContext()
            .getAuthentication().getName();
        return orderRepository.findByOwnerUsername(username);
    }

    // ── Method parameter access — the #paramName syntax ─────────────────────
    // The SpEL context binds method parameters by their compiled parameter names.
    // If -parameters compiler flag is NOT set, you may get "parameter not found".
    // @P("name") provides an explicit binding as a fallback.
    @PreAuthorize("hasRole('ADMIN') or #username == authentication.name")
    public List<Order> getOrdersForUser(String username) {
        // Admin can see anyone's orders; regular users can only see their own.
        // The #username in the expression refers to the method parameter directly.
        return orderRepository.findByOwnerUsername(username);
    }

    // ── Accessing nested fields on parameter objects ─────────────────────────
    @PreAuthorize("hasRole('ADMIN') or #order.ownerUsername == authentication.name")
    public void updateOrder(@P("order") Order order) {
        // @P("order") provides explicit parameter name binding — safer than
        // relying on -parameters compiler flag
        orderRepository.save(order);
    }

    // ── Accessing the authentication object's fields directly ────────────────
    // authentication.principal gives you your UserDetails implementation,
    // so you can access custom fields like tenantId, userId, etc.
    @PreAuthorize("authentication.principal.tenantId == #tenantId")
    public List<Order> getOrdersByTenant(String tenantId) {
        return orderRepository.findByTenantId(tenantId);
    }

    // ── Compound expressions — AND/OR logic ──────────────────────────────────
    @PreAuthorize("isFullyAuthenticated() and (hasRole('ADMIN') or #amount < 1000)")
    public void placeHighValueOrder(Order order, BigDecimal amount) {
        // isFullyAuthenticated() excludes remember-me users from ANY order placement.
        // hasRole('ADMIN') OR amount < 1000 restricts high-value orders to admins.
        // The parentheses ensure correct operator precedence.
        orderRepository.save(order);
    }

    // ── Bean reference in SpEL — for logic too complex for an expression ──────
    // @beanName.method() allows you to call any Spring bean from a SpEL expression.
    // This keeps your annotation readable while delegating to a service for
    // complex domain logic.
    @PreAuthorize("@orderAuthorizationPolicy.canModify(authentication, #orderId)")
    public void cancelOrder(Long orderId) {
        orderRepository.cancel(orderId);
    }
}

// The bean referenced above — encapsulates complex authorization logic
@Component("orderAuthorizationPolicy")
@RequiredArgsConstructor
public class OrderAuthorizationPolicy {

    private final OrderRepository orderRepository;
    private final SubscriptionService subscriptionService;

    public boolean canModify(Authentication auth, Long orderId) {
        // Admin can always modify
        if (auth.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"))) {
            return true;
        }

        // Owner can modify if order is still pending
        return orderRepository.findById(orderId)
            .map(order -> order.getOwnerUsername().equals(auth.getName())
                          && order.getStatus() == OrderStatus.PENDING)
            .orElse(false);
    }
}
```

---

## Layer 5: `@PostAuthorize` — Post-Execution Authorization

`@PostAuthorize` solves a specific problem that `@PreAuthorize` cannot: when you cannot determine authorization *before* the method runs because you need to inspect the *result* to make the decision.

```java
/**
 * LAYER 5: @PostAuthorize — authorization based on what the method returns.
 *
 * The canonical use case: loading a resource by ID and checking ownership.
 * You don't know who owns order #42 until you load it from the database.
 * @PreAuthorize can't help because the ownership data is in the result.
 *
 * CRITICAL IMPLICATION: The method ALWAYS executes. The database IS queried.
 * If the method has side effects (writes, emails, external calls), those
 * side effects happen BEFORE the authorization check occurs. If the check
 * fails, the side effects are permanent but the caller gets AccessDeniedException.
 *
 * Rule of thumb: @PostAuthorize is safe for READ operations.
 *                @PreAuthorize should be used for WRITE operations.
 */
@Service
@RequiredArgsConstructor
public class OrderService {

    private final OrderRepository orderRepository;

    // Safe use of @PostAuthorize — read-only operation
    // The method loads from DB, then Spring checks: does the caller own this result?
    // If not, the result is discarded and AccessDeniedException is thrown.
    // The DB was read (acceptable side effect) but nothing was changed.
    @PostAuthorize("returnObject.ownerUsername == authentication.name" +
                   " or hasRole('ADMIN')")
    public Order getOrderById(Long orderId) {
        return orderRepository.findById(orderId)
            .orElseThrow(() -> new OrderNotFoundException(orderId));
        // returnObject in the SpEL expression refers to this Order instance
    }

    // ❌ Unsafe use of @PostAuthorize — NEVER do this for writes
    @PostAuthorize("returnObject.ownerUsername == authentication.name")
    public Order updateOrderStatus(Long orderId, OrderStatus newStatus) {
        Order order = orderRepository.findById(orderId).orElseThrow();
        order.setStatus(newStatus);
        orderRepository.save(order); // ← DB WRITE HAPPENS BEFORE AUTH CHECK
        // If the caller doesn't own this order, the write already happened!
        // @PostAuthorize throws but the damage is done.
        return order;
    }
    // ✓ Correct pattern for the above: use @PreAuthorize with @PostAuthorize:
    @PreAuthorize("@orderPolicy.canModify(authentication, #orderId)")
    public Order updateOrderStatusSafely(Long orderId, OrderStatus newStatus) {
        // Auth check happened BEFORE we even touch the database
        Order order = orderRepository.findById(orderId).orElseThrow();
        order.setStatus(newStatus);
        return orderRepository.save(order);
    }
}
```

---

## Layer 6: `@PreFilter` and `@PostFilter` — Collection Filtering

These annotations take a different approach: rather than allowing or denying the entire method call, they *silently remove* elements from collections that the current user shouldn't process or see.

```java
/**
 * LAYER 6: @PreFilter and @PostFilter — element-level access control.
 *
 * The key difference from @PreAuthorize/@PostAuthorize:
 *   @Pre/@PostAuthorize: allow or deny the ENTIRE method call
 *   @Pre/@PostFilter:    allow the call but remove unauthorized ELEMENTS
 *
 * @PreFilter removes elements from an input collection before the method runs.
 * @PostFilter removes elements from the returned collection before returning.
 *
 * In both cases, filterObject is the SpEL variable bound to the current element.
 */
@Service
@RequiredArgsConstructor
public class OrderService {

    private final OrderRepository orderRepository;

    // @PreFilter: user submits multiple orders, we only process the ones they own
    // Elements failing the expression are silently removed from the list
    @PreAuthorize("isAuthenticated()") // still need at least basic auth check
    @PreFilter("filterObject.ownerUsername == authentication.name")
    public List<Order> bulkProcessOrders(List<Order> orders) {
        // By the time we get here, orders contains ONLY orders owned by current user.
        // Orders belonging to others were silently removed before this line.
        // The caller never knows other elements were stripped — no exception thrown.
        return orderRepository.saveAll(orders);
    }

    // filterTarget is required when the method has multiple collection parameters —
    // Spring needs to know which parameter to filter
    @PreFilter(value = "filterObject.ownerUsername == authentication.name",
               filterTarget = "ordersToProcess")
    public void processWithCustomers(List<Order> ordersToProcess,
                                      List<Customer> customers) {
        // ordersToProcess is filtered; customers is left alone
    }

    // @PostFilter: return all orders but remove ones the caller shouldn't see
    // Admin sees everything; regular users see only their own orders
    @PostFilter("hasRole('ADMIN') or filterObject.ownerUsername == authentication.name")
    public List<Order> findOrdersByStatus(OrderStatus status) {
        return orderRepository.findByStatus(status); // loads ALL from DB
        // Spring then iterates and removes elements where expression = false
    }
}
```

The performance trap with these annotations deserves emphasis. Both `@PreFilter` and `@PostFilter` work on in-memory collections — your database already loaded everything, and then Java throws away the elements that failed the check. For large datasets this is wasteful. The better production pattern is to filter at the query level:

```java
// ❌ Inefficient: loads all 50,000 orders, filters 49,900 in memory
@PostFilter("filterObject.ownerUsername == authentication.name")
public List<Order> getAllOrders() {
    return orderRepository.findAll(); // loads everything!
}

// ✓ Efficient: loads only the ~100 orders this user owns
public List<Order> getMyOrders() {
    // Use Spring Security SpEL in the JPQL query — only loads relevant data
    String username = SecurityContextHolder.getContext()
        .getAuthentication().getName();
    return orderRepository.findByOwnerUsername(username);
    // Or use Spring Data JPA's @Query with #{authentication.name}
}
```

There is also a critical runtime trap with `@PostFilter`: it **modifies the returned collection in-place** by calling `Iterator.remove()`. If your repository returns an immutable list (like `List.of(...)` or `Collections.unmodifiableList()`), this throws `UnsupportedOperationException` at runtime. Always ensure that methods annotated with `@PostFilter` return a mutable collection.

---

## Layer 7: The Self-Invocation Trap — The Most Critical Pitfall

This is the concept that causes more production security bugs than any other in method security. You must understand it intuitively, not just memorize it.

The root cause is simple: AOP interception only happens when a method call goes *through the proxy*. When code inside a bean calls another method on `this`, it bypasses the proxy entirely and calls the target object directly. The proxy never gets involved, so no security check runs.

```java
/**
 * LAYER 7: Self-invocation — why internal calls bypass security.
 *
 * The object graph looks like this:
 *
 *   External callers → [PROXY] → [OrderServiceImpl (actual bean)]
 *
 * External callers always talk to the proxy first. The proxy intercepts,
 * runs security checks, then calls into the actual bean.
 *
 * But when OrderServiceImpl calls its own methods internally, it uses
 * 'this' — which refers to the actual bean, NOT the proxy. The call
 * goes directly to the target without touching the proxy at all.
 */
@Service
public class OrderService {

    public void placeOrder(Order order) {
        // This is a call on 'this' — the actual OrderServiceImpl, not the proxy.
        // The proxy is completely bypassed. validateAndReserveInventory() runs
        // regardless of whether the caller has ROLE_INVENTORY_MANAGER.
        validateAndReserveInventory(order); // ← proxy never involved
    }

    @PreAuthorize("hasRole('INVENTORY_MANAGER')")
    public void validateAndReserveInventory(Order order) {
        // This @PreAuthorize runs ONLY when called from outside the bean.
        // When called from placeOrder() above, it silently skips the check.
    }
}
```

There are three production-grade solutions, each with different tradeoffs:

```java
/**
 * Solution 1 (Best): Extract to a separate bean.
 *
 * This is architecturally correct because it respects the Single Responsibility
 * Principle — inventory validation IS a separate concern from order placement.
 * Each bean has its own proxy, so cross-bean calls always go through proxies.
 */
@Service
@RequiredArgsConstructor
public class OrderService {

    private final InventoryService inventoryService; // separate bean = separate proxy

    public void placeOrder(Order order) {
        // This call goes through InventoryService's proxy — AOP intercepts correctly
        inventoryService.validateAndReserve(order);
    }
}

@Service
public class InventoryService {
    @PreAuthorize("hasRole('INVENTORY_MANAGER')")
    public void validateAndReserve(Order order) {
        // Now correctly protected — always called via proxy
    }
}

/**
 * Solution 2: Self-injection via @Lazy.
 *
 * Inject the proxy of the same bean into itself. Use @Lazy to break the
 * circular dependency. The injected 'self' reference IS the proxy.
 * Less clean architecturally but useful for quick fixes in existing code.
 */
@Service
public class OrderService {

    @Autowired
    @Lazy // prevents circular dependency at startup
    private OrderService self; // this field holds the PROXY, not 'this'

    public void placeOrder(Order order) {
        self.validateAndReserveInventory(order); // goes through proxy ✓
    }

    @PreAuthorize("hasRole('INVENTORY_MANAGER')")
    public void validateAndReserveInventory(Order order) {
        // Now correctly protected when called via self.method()
    }
}

/**
 * Solution 3: AopContext for one-off cases.
 *
 * Requires exposeProxy=true in @EnableMethodSecurity.
 * Less readable and more fragile than the other solutions.
 * Only use when refactoring is not feasible.
 */
@EnableMethodSecurity(proxyTargetClass = true)
// Also needs: @EnableAspectJAutoProxy(exposeProxy = true)

@Service
public class OrderService {
    public void placeOrder(Order order) {
        // Retrieve the current proxy from AopContext — goes through proxy
        ((OrderService) AopContext.currentProxy()).validateAndReserveInventory(order);
    }

    @PreAuthorize("hasRole('INVENTORY_MANAGER')")
    public void validateAndReserveInventory(Order order) { }
}
```

---

## Layer 8: `@Secured` and `@RolesAllowed` — The Legacy Annotations

These exist for backward compatibility and JSR-250 compliance. They are simpler and less powerful than `@PreAuthorize`, and their main trap is the `ROLE_` prefix behavior.

```java
/**
 * LAYER 8: @Secured and @RolesAllowed — the prefix trap.
 *
 * @Secured does NOT add ROLE_ prefix. It checks the exact string you provide.
 * @RolesAllowed DOES add ROLE_ prefix, behaving like hasRole().
 *
 * This asymmetry is the most common source of bugs when mixing annotations.
 */
@Service
@EnableMethodSecurity(securedEnabled = true, jsr250Enabled = true)
public class AdminService {

    // User has GrantedAuthority("ROLE_ADMIN"):
    @Secured("ROLE_ADMIN")  // checks for "ROLE_ADMIN" literally → WORKS ✓
    public void securedWithPrefix() { }

    @Secured("ADMIN")  // checks for "ADMIN" literally → FAILS (user has "ROLE_ADMIN") ✗
    public void securedWithoutPrefix() { }

    @RolesAllowed("ADMIN")  // adds ROLE_ → checks "ROLE_ADMIN" → WORKS ✓
    public void jsr250Method() { }

    @PreAuthorize("hasRole('ADMIN')")  // adds ROLE_ → checks "ROLE_ADMIN" → WORKS ✓
    public void preAuthorizedMethod() { }

    // @Secured does not support SpEL — only flat strings
    // @Secured({"ROLE_ADMIN", "ROLE_MANAGER"}) → OR logic only, no AND
    @Secured({"ROLE_ADMIN", "ROLE_MANAGER"})
    public void multiRoleMethod() { }
    // Accessible if user has ROLE_ADMIN OR ROLE_MANAGER — cannot express AND

    // For AND logic, you must use @PreAuthorize:
    @PreAuthorize("hasRole('ADMIN') and hasRole('MANAGER')")
    public void andLogicRequiresPreAuthorize() { }
}
```

---

## Layer 9: `hasPermission()` and `PermissionEvaluator` — Domain Object Security

When your authorization logic cannot be expressed as a simple role or authority check, Spring Security provides `hasPermission()` in SpEL, backed by a `PermissionEvaluator` you implement. This is how you build domain-object-level authorization — "can this user perform this action on this specific resource?"

```java
/**
 * LAYER 9: PermissionEvaluator — domain-object-level authorization.
 *
 * Two method signatures correspond to two SpEL call patterns:
 *
 *   hasPermission(#object, 'ACTION')
 *       → called when the actual domain object is available in the expression
 *       → receives the object instance directly
 *
 *   hasPermission(#id, 'com.example.Type', 'ACTION')
 *       → called when only the ID is available (object not yet loaded)
 *       → you must load the object yourself to check ownership
 */
@Component
@RequiredArgsConstructor
public class DomainPermissionEvaluator implements PermissionEvaluator {

    private final OrderRepository orderRepository;
    private final ProjectRepository projectRepository;

    /**
     * Called by hasPermission(#order, 'UPDATE') — object already available.
     * Use this when your @PreAuthorize has access to the loaded domain object.
     */
    @Override
    public boolean hasPermission(Authentication auth,
                                 Object targetDomainObject,
                                 Object permission) {
        if (targetDomainObject == null) return false;

        return switch (targetDomainObject) {
            case Order order -> evaluateOrderPermission(auth, order, permission.toString());
            case Project project -> evaluateProjectPermission(auth, project, permission.toString());
            default -> false; // unknown type → deny by default
        };
    }

    /**
     * Called by hasPermission(#orderId, 'com.example.Order', 'DELETE') — only ID available.
     * You must load the object to check ownership or other domain-level rules.
     * Be aware this triggers a DB query for every authorization check.
     */
    @Override
    public boolean hasPermission(Authentication auth,
                                 Serializable targetId,
                                 String targetType,
                                 Object permission) {
        return switch (targetType) {
            case "com.example.Order" -> orderRepository.findById((Long) targetId)
                .map(order -> hasPermission(auth, order, permission))
                .orElse(false); // non-existent resource → deny
            default -> false;
        };
    }

    private boolean evaluateOrderPermission(Authentication auth,
                                             Order order,
                                             String permission) {
        boolean isAdmin = auth.getAuthorities().stream()
            .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"));

        return switch (permission) {
            case "VIEW"   -> isAdmin || order.getOwnerUsername().equals(auth.getName());
            case "UPDATE" -> isAdmin || (order.getOwnerUsername().equals(auth.getName())
                                         && order.getStatus() == OrderStatus.PENDING);
            case "DELETE" -> isAdmin; // only admins can delete
            case "CANCEL" -> isAdmin || order.getOwnerUsername().equals(auth.getName());
            default -> false; // unknown permission → deny
        };
    }

    private boolean evaluateProjectPermission(Authentication auth,
                                               Project project,
                                               String permission) {
        // Project permissions might involve team membership, not just ownership
        return project.getMembers().contains(auth.getName())
               || auth.getAuthorities().stream()
                   .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"));
    }
}

// Usage in service layer:
@Service
public class OrderService {

    // Object available in expression — uses first hasPermission() overload
    @PreAuthorize("hasPermission(#order, 'UPDATE')")
    public void updateOrder(@P("order") Order order) { }

    // Only ID available — uses second hasPermission() overload (loads from DB)
    @PreAuthorize("hasPermission(#orderId, 'com.example.Order', 'DELETE')")
    public void deleteOrder(Long orderId) { }

    // Combining with role check
    @PreAuthorize("hasRole('ADMIN') or hasPermission(#orderId, 'com.example.Order', 'CANCEL')")
    public void cancelOrder(Long orderId) { }
}
```

---

## Layer 10: The Complete Production Configuration

```java
/**
 * LAYER 10: Wiring everything together for a production application.
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity(
    securedEnabled = true,
    jsr250Enabled  = true
)
@RequiredArgsConstructor
public class MethodSecurityConfig {

    private final DomainPermissionEvaluator permissionEvaluator;

    @Bean
    public MethodSecurityExpressionHandler methodSecurityExpressionHandler() {
        DefaultMethodSecurityExpressionHandler handler =
            new DefaultMethodSecurityExpressionHandler();

        // Wire the permission evaluator for hasPermission() SpEL calls
        handler.setPermissionEvaluator(permissionEvaluator);

        // Wire role hierarchy — without this, ROLE_ADMIN does NOT satisfy
        // hasRole('USER') in @PreAuthorize, even if the hierarchy bean exists
        handler.setRoleHierarchy(roleHierarchy());

        return handler;
    }

    @Bean
    public RoleHierarchy roleHierarchy() {
        RoleHierarchyImpl hierarchy = new RoleHierarchyImpl();
        hierarchy.setHierarchy("""
            ROLE_ADMIN > ROLE_MANAGER
            ROLE_MANAGER > ROLE_USER
            """);
        return hierarchy;
    }
}

// ─── Production service with all patterns applied correctly ──────────────────
@Service
@Transactional
@RequiredArgsConstructor
public class OrderService {

    private final OrderRepository orderRepository;
    private final InventoryService inventoryService; // separate bean, not self-call

    // Simple role check for listing
    @PreAuthorize("isAuthenticated()")
    public List<Order> getMyOrders() {
        return orderRepository.findByOwnerUsername(
            SecurityContextHolder.getContext().getAuthentication().getName());
    }

    // Ownership + role check with parameter access
    @PreAuthorize("hasRole('ADMIN') or #username == authentication.name")
    public List<Order> getOrdersFor(String username) {
        return orderRepository.findByOwnerUsername(username);
    }

    // Safe post-authorization — read only, side-effect free
    @PostAuthorize("hasRole('ADMIN') or returnObject.ownerUsername == authentication.name")
    public Order getById(Long id) {
        return orderRepository.findById(id).orElseThrow();
    }

    // Pre-check for write operations — prevents side effects on auth failure
    @PreAuthorize("hasPermission(#order, 'UPDATE')")
    public Order update(@P("order") Order order) {
        return orderRepository.save(order);
    }

    // Delegate to separate bean — avoids self-invocation bypass
    @PreAuthorize("hasRole('USER')")
    public Order place(Order order) {
        inventoryService.validateAndReserve(order); // through InventoryService's proxy
        return orderRepository.save(order);
    }

    // Require fresh authentication for sensitive operations
    @PreAuthorize("isFullyAuthenticated() and hasRole('ADMIN')")
    public void deleteOrder(Long id) {
        orderRepository.deleteById(id);
    }
}
```

---

## Layer 11: Testing Method Security

```java
/**
 * LAYER 11: Testing method security — using spring-security-test annotations.
 *
 * The key insight: method security tests go DIRECTLY to the service bean,
 * bypassing the HTTP filter chain entirely. This means:
 *   - No AnonymousAuthenticationFilter runs in unit tests
 *   - If SecurityContext is empty (no @WithMockUser etc.), you get
 *     AuthenticationCredentialsNotFoundException, NOT AccessDeniedException
 *   - @WithMockUser creates a UsernamePasswordAuthenticationToken and puts
 *     it in the SecurityContext before your test method runs
 */
@SpringBootTest
class OrderServiceMethodSecurityTest {

    @Autowired
    private OrderService orderService; // gets the PROXY — AOP applies correctly

    @Test
    @WithMockUser(roles = "USER")
    @DisplayName("User can access their own orders")
    void userCanGetOwnOrders() {
        assertDoesNotThrow(() -> orderService.getMyOrders());
    }

    @Test
    @WithMockUser(username = "alice", roles = "USER")
    @DisplayName("User can only get orders for themselves, not other users")
    void userCannotGetOtherUsersOrders() {
        assertDoesNotThrow(() -> orderService.getOrdersFor("alice")); // own data ✓
        assertThrows(AccessDeniedException.class,
            () -> orderService.getOrdersFor("bob")); // other user's data ✗
    }

    @Test
    @WithMockUser(roles = "USER")
    @DisplayName("User cannot delete orders — wrong role → AccessDeniedException")
    void userCannotDeleteOrder() {
        assertThrows(AccessDeniedException.class,
            () -> orderService.deleteOrder(1L));
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    @DisplayName("Admin can delete orders")
    void adminCanDeleteOrder() {
        assertDoesNotThrow(() -> orderService.deleteOrder(1L));
    }

    @Test
    @DisplayName("No SecurityContext → AuthenticationCredentialsNotFoundException, not AccessDeniedException")
    void noSecurityContextThrowsCorrectException() {
        // Without @WithMockUser, SecurityContext is truly empty in unit tests.
        // AnonymousAuthenticationFilter never ran (no filter chain in unit tests).
        // Spring Security detects null authentication before checking authorities.
        assertThrows(
            AuthenticationCredentialsNotFoundException.class,
            () -> orderService.getMyOrders()
            // NOT AccessDeniedException — important for test assertions!
        );
    }

    @Test
    @WithMockUser(username = "alice", roles = "ADMIN")
    @DisplayName("Role hierarchy: ADMIN satisfies hasRole(USER) check")
    void adminSatisfiesUserRoleCheck() {
        // This only passes if MethodSecurityExpressionHandler has role hierarchy configured.
        // Without it, ADMIN does NOT satisfy hasRole('USER') in @PreAuthorize.
        assertDoesNotThrow(() -> orderService.getMyOrders());
    }
}
```

---

## The Complete Mental Model

Here is how all layers connect for a single method call — from external invocation to the annotated method, and back:

```
External caller (Controller, Test, Scheduler, etc.)
     │
     ▼
PROXY intercepts (JDK Dynamic or CGLIB — wraps your @Service bean)
     │
     ▼
[1] PreFilterAuthorizationMethodInterceptor  (order 100)
     └── @PreFilter: iterates input collection, removes elements where expression = false
     └── Modifies collection in-place (must be mutable!)
     │
     ▼
[2] AuthorizationManagerBeforeMethodInterceptor  (order 500)
     └── @PreAuthorize: evaluates SpEL against authentication + method params
     └── false → AccessDeniedException thrown here — method never runs
     └── true  → proceed
     │
     ▼
[3] ACTUAL METHOD EXECUTES
     └── Runs your business logic, DB queries, side effects, returns a value
     │
     ▼
[4] AuthorizationManagerAfterMethodInterceptor  (order 500)
     └── @PostAuthorize: evaluates SpEL with returnObject bound to return value
     └── false → AccessDeniedException thrown — return value discarded, side effects kept!
     └── true  → pass return value down the chain
     │
     ▼
[5] PostFilterAuthorizationMethodInterceptor  (order 900)
     └── @PostFilter: iterates returned collection, removes elements where expression = false
     └── Modifies collection in-place (must be mutable!)
     │
     ▼
Return filtered, authorized result to external caller

─────────────────────────────────── KEY TRAPS ──────────────────────────────────

Internal call (this.validateOrder()):
     OrderServiceImpl.placeOrder() → this.validateOrder()
                                           ↑
                                     Proxy NEVER involved
                                     @PreAuthorize SILENTLY IGNORED

private/final method:
     CGLIB cannot override → AOP cannot intercept → @PreAuthorize SILENTLY IGNORED

No @EnableMethodSecurity:
     AOP interceptors never created → all annotations exist but DO NOTHING

Missing MethodSecurityExpressionHandler with RoleHierarchy:
     ADMIN fails hasRole('USER') in @PreAuthorize
     even though ADMIN passes hasRole('USER') in URL security
     — asymmetric behavior, silent wrong results
```

The deepest architectural insight in method security is that it represents a trade-off between two competing goods: simplicity (just use URL rules) and correctness (protection regardless of call source). The moment you have a `@Service` method that can be reached through multiple paths — a REST endpoint, a scheduled job, a message consumer — you face a choice between duplicating authorization logic in every caller, or moving it into the method itself. `@PreAuthorize` is Spring's answer to that choice: put the authorization decision exactly where the protected operation is defined, colocated with the code it protects. The rule lives at the method, travels with the method when it's refactored, and applies regardless of how the method is reached.
