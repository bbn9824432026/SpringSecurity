# Spring Security Authorization - Complete Architecture Deep Dive

## Understanding Authorization vs Authentication

Before we dive into the APIs, let's establish the fundamental distinction that shapes the entire architecture.

Authentication answers the question: "Who are you?" It's about verifying the user's identity. You provide your username and password, Spring Security verifies them, and you become authenticated.

Authorization answers the question: "What are you allowed to do?" Once you're authenticated, authorization checks whether you have permission to access a specific resource or perform a specific action. This is what we're studying now.

Think of it like entering a building. Authentication is the security guard checking your ID at the entrance. Authorization is the electronic locks on different doors that only open if your badge has the right permissions.

The key architectural insight is that authorization in Spring Security happens in two places: at the HTTP request level (URL-based authorization) and at the method level (method invocation authorization). Both use the same underlying voting and decision-making mechanisms, but they're triggered at different points in the request lifecycle.

---

## Part 1: The Core Authorization Interfaces

### Understanding SecurityMetadataSource

The first thing to understand is that protected resources need to be configured with what permissions they require. This configuration is stored and retrieved through the `SecurityMetadataSource` interface.

```java
package org.springframework.security.access.intercept;

import org.springframework.security.access.ConfigAttribute;
import java.util.Collection;

/**
 * The SecurityMetadataSource is responsible for telling Spring Security
 * what permissions are required to access a protected resource.
 * 
 * Think of it as a map that says:
 * "For URL /admin/delete, you need ROLE_ADMIN"
 * "For method deleteUser(), you need PERMISSION_USER_DELETE"
 * 
 * Before authorization decisions are made, Spring Security asks this source:
 * "What permissions are required for this resource?"
 * 
 * The source returns a collection of ConfigAttributes.
 * A ConfigAttribute is just a configuration string that represents
 * a required permission, role, or authorization rule.
 */
public interface SecurityMetadataSource {
    
    /**
     * Get the configuration attributes required for the given secured object.
     * 
     * Parameters:
     * - object: The protected resource (could be a URL, method, etc.)
     * 
     * Return:
     * - Collection of ConfigAttributes specifying required permissions
     * - Returns null or empty collection if no special permissions required
     * 
     * Example implementations might say:
     * - For request to /admin/users, return: ["ROLE_ADMIN", "PERMISSION_USER_MANAGE"]
     * - For method deleteUser(), return: ["PERMISSION_DELETE"]
     * - For public URL /home, return: null (no special permissions)
     */
    Collection<ConfigAttribute> getAttributes(Object object)
        throws IllegalArgumentException;
    
    /**
     * Get all possible configuration attributes across all secured objects.
     * Useful for pre-loading or validation.
     */
    Collection<ConfigAttribute> getAllConfigAttributes();
    
    /**
     * Does this source support configuration of this type of object?
     * For example, URL-based sources support FilterInvocation,
     * while method-based sources support MethodInvocation.
     */
    boolean supports(Class<?> clazz);
}

/**
 * Understanding ConfigAttribute
 * 
 * This is a simple interface representing required permission.
 * It's just a container for a string attribute.
 */
public interface ConfigAttribute {
    /**
     * Return the attribute as a string.
     * Examples: "ROLE_ADMIN", "PERMISSION_USER_DELETE", "hasAuthority('REPORT_VIEW')"
     */
    String getAttribute();
}

/**
 * Default implementation
 */
public class SecurityConfig implements ConfigAttribute {
    
    private final String attribute;
    
    public SecurityConfig(String attribute) {
        this.attribute = attribute;
    }
    
    @Override
    public String getAttribute() {
        return this.attribute;
    }
}
```

### Custom SecurityMetadataSource Example

```java
package com.example.security;

import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.intercept.SecurityMetadataSource;
import java.util.*;

/**
 * A database-driven SecurityMetadataSource.
 * 
 * Instead of configuring permissions in code or configuration files,
 * this source loads them from a database.
 * 
 * This allows you to manage permissions without restarting the application.
 * Change a permission in the database, and it takes effect immediately.
 */
public class DatabaseSecurityMetadataSource implements SecurityMetadataSource {
    
    private final UrlPermissionRepository urlPermissionRepository;
    private final PermissionCache permissionCache;
    
    public DatabaseSecurityMetadataSource(
            UrlPermissionRepository urlPermissionRepository,
            PermissionCache permissionCache) {
        this.urlPermissionRepository = urlPermissionRepository;
        this.permissionCache = permissionCache;
    }
    
    /**
     * Get required permissions for a URL.
     * 
     * For example, if someone requests GET /api/admin/users,
     * this method is called with the request URL.
     * We look it up in the database and return required permissions.
     */
    @Override
    public Collection<ConfigAttribute> getAttributes(Object object) 
            throws IllegalArgumentException {
        
        // In real scenarios, object is usually FilterInvocation
        // which contains the HttpServletRequest
        if (!(object instanceof FilterInvocation)) {
            return null;
        }
        
        FilterInvocation fi = (FilterInvocation) object;
        HttpServletRequest request = fi.getRequest();
        
        // Extract the URL path
        String requestUri = request.getRequestURI();
        String method = request.getMethod();
        
        /**
         * Check cache first.
         * This is crucial for performance. Checking permissions
         * on every request is expensive if you hit the database.
         */
        Collection<ConfigAttribute> cached = 
            this.permissionCache.getPermissions(requestUri, method);
        
        if (cached != null) {
            return cached;
        }
        
        /**
         * Cache miss. Query the database.
         * This query finds all permissions required for this URL.
         * 
         * Example query:
         * SELECT * FROM url_permissions
         * WHERE url_pattern = '/api/admin/users'
         * AND http_method = 'GET'
         */
        UrlPermissionEntity urlPermission = 
            this.urlPermissionRepository.findByUrlPatternAndMethod(
                requestUri, method);
        
        if (urlPermission == null) {
            // No special permissions required for this URL
            return null;
        }
        
        /**
         * Convert permission names to ConfigAttributes.
         * 
         * If database says this URL requires ["ROLE_ADMIN", "PERMISSION_DELETE"],
         * we create ConfigAttribute objects for each.
         */
        Collection<ConfigAttribute> attributes = new ArrayList<>();
        for (String permission : urlPermission.getRequiredPermissions()) {
            attributes.add(new SecurityConfig(permission));
        }
        
        // Cache for future requests
        this.permissionCache.putPermissions(requestUri, method, attributes);
        
        return attributes;
    }
    
    @Override
    public Collection<ConfigAttribute> getAllConfigAttributes() {
        // Return all possible permissions across all URLs
        return this.urlPermissionRepository.findAll()
            .stream()
            .flatMap(perm -> perm.getRequiredPermissions().stream())
            .map(SecurityConfig::new)
            .collect(Collectors.toSet());
    }
    
    @Override
    public boolean supports(Class<?> clazz) {
        // This source supports FilterInvocation (URL-based requests)
        return FilterInvocation.class.isAssignableFrom(clazz);
    }
}
```

The `SecurityMetadataSource` is the first link in the authorization chain. It says: "For this resource, these permissions are required." The rest of the authorization system then checks if the user has those permissions.

---

## Part 2: The Authorization Interceptor - Entry Point

After authentication happens, when a user tries to access a protected resource, the authorization interceptor intercepts the request before it reaches the actual resource.

### Understanding AbstractSecurityInterceptor

```java
package org.springframework.security.access.intercept;

import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityMetadataSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;

/**
 * The AbstractSecurityInterceptor is the framework that orchestrates
 * the entire authorization process.
 * 
 * This is the core class that brings everything together. It sits between
 * the user's request and the actual resource, asking:
 * 1. What permissions are required?
 * 2. Does the user have those permissions?
 * 3. Should we allow or deny the request?
 * 
 * The flow is:
 * User Request → SecurityInterceptor → Ask AccessDecisionManager
 *             → AccessDecisionManager asks voters → Return decision
 *             → Allow or deny request
 * 
 * This is an abstract class because different types of resources
 * need different interceptors:
 * - FilterSecurityInterceptor for HTTP requests (URLs)
 * - MethodSecurityInterceptor for method invocations
 */
public abstract class AbstractSecurityInterceptor {
    
    /**
     * These are injected dependencies that power the authorization system.
     * Each plays a specific role in the decision-making process.
     */
    
    // Gets what permissions are required for a resource
    private SecurityMetadataSource securityMetadataSource;
    
    // Decides if user has required permissions
    private AccessDecisionManager accessDecisionManager;
    
    // Sometimes needs to authenticate the user more (e.g., request additional info)
    private AuthenticationManager authenticationManager;
    
    // Runs after authorization (for auditing, logging, etc.)
    private List<AfterInvocationProvider> afterInvocationProviders;
    
    /**
     * This is the main authorization method.
     * All authorization paths eventually call this.
     * 
     * Think of this as the actual security checkpoint where
     * the authorization decision is made.
     */
    protected InterceptorStatusToken beforeInvocation(Object object) {
        
        /**
         * STEP 1: Get required permissions for this resource
         */
        Collection<ConfigAttribute> attributes = 
            this.securityMetadataSource.getAttributes(object);
        
        // If no special permissions are required, allow access
        if (attributes == null || attributes.isEmpty()) {
            return null;  // No authorization needed
        }
        
        /**
         * STEP 2: Get the currently authenticated user
         */
        Authentication authentication = 
            SecurityContextHolder.getContext().getAuthentication();
        
        // No authentication found - deny access
        if (authentication == null) {
            throw new AuthenticationCredentialsNotFoundException(
                "User is not authenticated");
        }
        
        /**
         * STEP 3: Ask AccessDecisionManager if user has required permissions
         * 
         * This is the key decision point. The manager will:
         * 1. Ask all registered voters to vote
         * 2. Aggregate the votes
         * 3. Return (allow) or throw exception (deny)
         */
        try {
            this.accessDecisionManager.decide(
                authentication,  // Who is this user?
                object,          // What are they accessing?
                attributes       // What permissions are required?
            );
        } catch (AccessDeniedException e) {
            // User doesn't have required permissions
            publishEvent(new AuthorizationFailureEvent(
                object, attributes, authentication, e));
            throw e;
        }
        
        // If we get here, authorization succeeded
        publishEvent(new AuthorizedEvent(
            object, attributes, authentication));
        
        /**
         * STEP 4: Possibly authenticate user further
         * 
         * In some cases, you might need additional authentication
         * for sensitive operations. This is where that happens.
         * For example, require user to enter password before deleting.
         */
        if (this.authenticationManager != null) {
            authentication = this.authenticationManager.authenticate(
                authentication);
            
            // Update the SecurityContext with the new authentication
            SecurityContextHolder.getContext()
                .setAuthentication(authentication);
        }
        
        // Return token that will be used in afterInvocation
        return new InterceptorStatusToken(
            SecurityContextHolder.getContext(),
            attributes);
    }
    
    /**
     * After the user's request is processed, post-authorization logic runs.
     * This is for filtering results or additional checks.
     */
    protected Object afterInvocation(
            InterceptorStatusToken token,
            Object returnedObject) {
        
        // Run all after-invocation providers
        for (AfterInvocationProvider provider : this.afterInvocationProviders) {
            // Providers can filter results
            // Example: remove sensitive fields from returned object
            returnedObject = provider.decide(
                token.getAuthentication(),
                token.getSecureObject(),
                token.getAttributes(),
                returnedObject);
        }
        
        return returnedObject;
    }
}
```

### FilterSecurityInterceptor - For URL-Based Authorization

```java
package org.springframework.security.web.access.intercept;

/**
 * The FilterSecurityInterceptor sits in the security filter chain
 * and protects HTTP requests to URLs.
 * 
 * When someone requests a URL, this interceptor runs BEFORE
 * the request reaches the controller.
 * 
 * Flow:
 * HTTP Request → FilterSecurityInterceptor → Check permissions
 *             → Controller (if allowed) or Exception (if denied)
 */
public class FilterSecurityInterceptor extends AbstractSecurityInterceptor 
        implements Filter {
    
    private final SecurityMetadataSource securityMetadataSource;
    private final AccessDecisionManager accessDecisionManager;
    
    @Override
    public void doFilter(
            ServletRequest request,
            ServletResponse response,
            FilterChain filterChain)
            throws IOException, ServletException {
        
        FilterInvocation fi = new FilterInvocation(
            request, response, filterChain);
        
        // Perform authorization check
        invoke(fi);
    }
    
    public void invoke(FilterInvocation fi) 
            throws IOException, ServletException {
        
        /**
         * STEP 1: Check authorization before the request proceeds
         * 
         * The beforeInvocation method from AbstractSecurityInterceptor
         * is called here. It checks:
         * - What permissions are required?
         * - Does user have them?
         */
        InterceptorStatusToken token = beforeInvocation(fi);
        
        try {
            /**
             * STEP 2: If authorization passes, continue to next filter
             * or the actual resource (controller)
             */
            fi.getChain().doFilter(fi.getRequest(), fi.getResponse());
        } finally {
            /**
             * STEP 3: After the resource is processed, run post-authorization
             */
            afterInvocation(token, null);
        }
    }
}
```

### MethodSecurityInterceptor - For Method-Level Authorization

```java
package org.springframework.security.access.intercept.aopalliance;

import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;

/**
 * The MethodSecurityInterceptor protects individual method calls.
 * 
 * When you use @PreAuthorize, @PostAuthorize, @Secured annotations,
 * Spring Security uses AOP to wrap your method with this interceptor.
 * 
 * Flow:
 * Method Call → MethodSecurityInterceptor → Check permissions
 *            → Method (if allowed) or Exception (if denied)
 */
public class MethodSecurityInterceptor extends AbstractSecurityInterceptor 
        implements MethodInterceptor {
    
    private final SecurityMetadataSource securityMetadataSource;
    private final AccessDecisionManager accessDecisionManager;
    
    /**
     * This method is called whenever a protected method is invoked.
     * The method invocation is wrapped by Spring AOP.
     */
    @Override
    public Object invoke(MethodInvocation mi) 
            throws Throwable {
        
        /**
         * STEP 1: Check authorization before method executes
         */
        InterceptorStatusToken token = beforeInvocation(mi);
        
        Object returnedObject;
        try {
            /**
             * STEP 2: If authorization passes, invoke the actual method
             * The mi.proceed() call executes your method
             */
            returnedObject = mi.proceed();
        } finally {
            /**
             * STEP 3: After method returns, run post-authorization
             * This can filter the returned object or verify post-conditions
             */
            returnedObject = afterInvocation(token, returnedObject);
        }
        
        return returnedObject;
    }
}
```

The interceptor pattern ensures that authorization checks happen transparently. The user never directly calls the authorization code—it happens automatically when they try to access protected resources.

---

## Part 3: The AccessDecisionManager - Making the Decision

Once the interceptor has the required permissions and the user's authentication, it delegates to the `AccessDecisionManager` to actually make the allow/deny decision.

```java
package org.springframework.security.access;

import org.springframework.security.core.Authentication;
import java.util.Collection;

/**
 * The AccessDecisionManager is the judge in the authorization system.
 * It makes the final decision: Allow or Deny.
 * 
 * It does this by consulting with multiple AccessDecisionVoters.
 * Each voter independently votes on whether the user should have access.
 * The manager then applies a voting strategy to reach a final decision.
 * 
 * This is the Strategy pattern in action:
 * - Voters are the strategies that provide votes
 * - Manager is the context that uses those strategies
 * - Different manager implementations use different voting strategies
 */
public interface AccessDecisionManager {
    
    /**
     * Make the final authorization decision.
     * 
     * This method is called by the interceptor with:
     * - authentication: The user and their authorities
     * - object: The resource being accessed
     * - configAttributes: The required permissions
     * 
     * The method either:
     * - Returns normally (access granted)
     * - Throws AccessDeniedException (access denied)
     * 
     * It never returns a boolean or vote result to the caller.
     * The contract is: if no exception is thrown, access is granted.
     */
    void decide(
        Authentication authentication,
        Object object,
        Collection<ConfigAttribute> configAttributes)
        throws AccessDeniedException;
    
    /**
     * Check if this manager supports voting on this type of object.
     * For example, URL-based managers support FilterInvocation,
     * while method-based managers support MethodInvocation.
     */
    boolean supports(Class<?> clazz);
    
    /**
     * Check if this manager supports this type of ConfigAttribute.
     */
    boolean supports(ConfigAttribute attribute);
}

/**
 * The most commonly used implementation: AffirmativeBased
 * 
 * Voting strategy: If ANY voter grants access, grant it.
 * This is the most permissive strategy.
 * 
 * Example:
 * - Voter 1 says: ABSTAIN (doesn't care)
 * - Voter 2 says: GRANT (yes, allow)
 * - Voter 3 says: ABSTAIN (doesn't care)
 * Result: GRANT (because at least one voter granted)
 * 
 * Even if Voter 1 said DENY:
 * - Voter 1 says: DENY
 * - Voter 2 says: GRANT
 * - Voter 3 says: ABSTAIN
 * Result: GRANT (because one voter granted, strategy is affirmative)
 */
public class AffirmativeBased implements AccessDecisionManager {
    
    private final List<AccessDecisionVoter> decisionVoters;
    
    @Override
    public void decide(
            Authentication authentication,
            Object object,
            Collection<ConfigAttribute> configAttributes)
            throws AccessDeniedException {
        
        int grant = 0;
        int deny = 0;
        
        /**
         * Ask each voter to vote on this authorization decision.
         */
        for (AccessDecisionVoter voter : this.decisionVoters) {
            // Call the voter's vote method
            int result = voter.vote(
                authentication,
                object,
                configAttributes);
            
            if (logger.isTraceEnabled()) {
                logger.trace(voter.getClass().getSimpleName() 
                    + " voted: " + result);
            }
            
            switch (result) {
                case AccessDecisionVoter.ACCESS_GRANTED:
                    grant++;
                    break;
                case AccessDecisionVoter.ACCESS_DENIED:
                    deny++;
                    break;
                default:
                    // ACCESS_ABSTAIN - voter doesn't care, continue
                    break;
            }
        }
        
        /**
         * AFFIRMATIVE STRATEGY: If any voter granted, allow access
         */
        if (grant > 0) {
            return;  // Access granted - method returns normally
        }
        
        // If we reach here, no voter granted access
        // Check if anyone denied
        if (deny > 0) {
            throw new AccessDeniedException(
                "Access denied by voter");
        }
        
        // All voters abstained - what should we do?
        throw new AccessDeniedException(
            "Access denied - no voter granted access");
    }
    
    @Override
    public boolean supports(Class<?> clazz) {
        for (AccessDecisionVoter voter : this.decisionVoters) {
            if (!voter.supports(clazz)) {
                return false;
            }
        }
        return true;
    }
    
    @Override
    public boolean supports(ConfigAttribute attribute) {
        for (AccessDecisionVoter voter : this.decisionVoters) {
            if (voter.supports(attribute)) {
                return true;  // At least one voter supports it
            }
        }
        return false;
    }
}

/**
 * Alternative strategy: ConsensusBased
 * 
 * Voting strategy: Must have equal grants and denies,
 * but grants must be greater than denies.
 * If all abstain, access is denied.
 * 
 * This is a middle ground between permissive and restrictive.
 */
public class ConsensusBased implements AccessDecisionManager {
    
    @Override
    public void decide(
            Authentication authentication,
            Object object,
            Collection<ConfigAttribute> configAttributes)
            throws AccessDeniedException {
        
        int grant = 0;
        int deny = 0;
        
        for (AccessDecisionVoter voter : this.decisionVoters) {
            int result = voter.vote(authentication, object, configAttributes);
            
            switch (result) {
                case AccessDecisionVoter.ACCESS_GRANTED:
                    grant++;
                    break;
                case AccessDecisionVoter.ACCESS_DENIED:
                    deny++;
                    break;
            }
        }
        
        /**
         * CONSENSUS STRATEGY: grants must be greater than denies
         * This requires more agreement than the affirmative strategy.
         */
        if (grant > deny) {
            return;
        }
        
        throw new AccessDeniedException(
            "Access denied by consensus");
    }
}

/**
 * Most restrictive strategy: UnanimousBased
 * 
 * Voting strategy: ALL voters must grant (or abstain).
 * Even one DENY means access is denied.
 * 
 * Example:
 * - Voter 1 says: GRANT
 * - Voter 2 says: DENY ← Just one DENY
 * - Voter 3 says: GRANT
 * Result: DENY (because one voter said no)
 * 
 * This is the most secure strategy.
 */
public class UnanimousBased implements AccessDecisionManager {
    
    @Override
    public void decide(
            Authentication authentication,
            Object object,
            Collection<ConfigAttribute> configAttributes)
            throws AccessDeniedException {
        
        for (AccessDecisionVoter voter : this.decisionVoters) {
            int result = voter.vote(authentication, object, configAttributes);
            
            /**
             * UNANIMOUS STRATEGY: Any DENY is a veto
             */
            if (result == AccessDecisionVoter.ACCESS_DENIED) {
                throw new AccessDeniedException(
                    "Access denied by voter");
            }
        }
        
        // All voters either granted or abstained
        return;
    }
}
```

The manager implements a voting strategy that determines how individual voter opinions combine into a final decision. This design makes it easy to implement different authorization philosophies—from permissive to restrictive—without changing how voters work.

---

## Part 4: The AccessDecisionVoter - Casting Votes

Voters are the specialists that examine the authorization request and vote whether to grant or deny access. Each voter focuses on one aspect of authorization.

```java
package org.springframework.security.access;

import org.springframework.security.core.Authentication;
import java.util.Collection;

/**
 * An AccessDecisionVoter examines an authorization request
 * and votes: GRANT, DENY, or ABSTAIN.
 * 
 * Different voters can implement different authorization logic:
 * - One voter checks: "Does the user have the required role?"
 * - Another voter checks: "Is it within business hours?"
 * - Another voter checks: "Does the user own this resource?"
 * 
 * Multiple voters work together, each providing their expert opinion.
 * The AccessDecisionManager collects all votes and makes a decision.
 */
public interface AccessDecisionVoter {
    
    // Vote results
    int ACCESS_GRANTED = 1;    // Allow access
    int ACCESS_ABSTAIN = 0;    // Don't have an opinion
    int ACCESS_DENIED = -1;    // Deny access
    
    /**
     * Cast a vote on whether access should be granted.
     * 
     * This method analyzes the authentication, the protected object,
     * and the required permissions, then votes.
     */
    int vote(
        Authentication authentication,
        Object object,
        Collection<ConfigAttribute> attributes);
    
    /**
     * Does this voter care about this type of object?
     * 
     * Different voters support different object types:
     * - URL voters support FilterInvocation
     * - Method voters support MethodInvocation
     * 
     * If a voter doesn't support the object type, it returns false,
     * indicating it won't vote on this request.
     */
    boolean supports(Class<?> clazz);
    
    /**
     * Does this voter care about this type of permission?
     * 
     * A voter can specialize in certain permissions:
     * - RoleVoter only understands "ROLE_" permissions
     * - A custom voter might only understand "OWNER_" permissions
     * 
     * If a required permission is something this voter doesn't understand,
     * it returns false, and it won't vote.
     */
    boolean supports(ConfigAttribute attribute);
}

/**
 * THE ROLEVOTER - Authority/Role-Based Authorization
 * 
 * This is the most basic voter. It checks:
 * "Does the user have the required role/authority?"
 */
public class RoleVoter implements AccessDecisionVoter {
    
    /**
     * The role prefix this voter understands.
     * Only votes on attributes starting with this prefix.
     */
    private final String rolePrefix = "ROLE_";
    
    @Override
    public int vote(
            Authentication authentication,
            Object object,
            Collection<ConfigAttribute> attributes) {
        
        // If no attributes are specified, don't care
        if (attributes == null || attributes.isEmpty()) {
            return ACCESS_ABSTAIN;
        }
        
        // Get the user's authorities
        Collection<? extends GrantedAuthority> authorities = 
            authentication.getAuthorities();
        
        // Iterate through required permissions
        for (ConfigAttribute attribute : attributes) {
            String requiredRole = attribute.getAttribute();
            
            // Does this voter understand this permission?
            if (!requiredRole.startsWith(this.rolePrefix)) {
                // Nope, abstain
                continue;
            }
            
            // Check if user has this role
            for (GrantedAuthority authority : authorities) {
                if (requiredRole.equals(authority.getAuthority())) {
                    // User has this role!
                    return ACCESS_GRANTED;
                }
            }
        }
        
        // If this voter cares about one of the permissions
        // (because it started with "ROLE_") but user doesn't have any of them
        // Check if we found any role-based permissions
        boolean foundRoleAttribute = attributes.stream()
            .anyMatch(attr -> attr.getAttribute()
                .startsWith(this.rolePrefix));
        
        if (foundRoleAttribute) {
            // We care about the permissions, but user doesn't have them
            return ACCESS_DENIED;
        }
        
        // None of the required permissions were role-based, so we abstain
        return ACCESS_ABSTAIN;
    }
    
    @Override
    public boolean supports(Class<?> clazz) {
        // This voter supports any object type
        return true;
    }
    
    @Override
    public boolean supports(ConfigAttribute attribute) {
        // This voter only understands attributes starting with "ROLE_"
        return attribute.getAttribute() != null &&
               attribute.getAttribute().startsWith(this.rolePrefix);
    }
}

/**
 * CUSTOM VOTER EXAMPLE - Permission-Based Authorization
 * 
 * This voter checks: "Does the user have the required permission?"
 * It's different from RoleVoter in that it can use fine-grained permissions
 * instead of just broad roles.
 */
public class PermissionVoter implements AccessDecisionVoter {
    
    private final String permissionPrefix = "PERMISSION_";
    
    @Override
    public int vote(
            Authentication authentication,
            Object object,
            Collection<ConfigAttribute> attributes) {
        
        if (attributes == null || attributes.isEmpty()) {
            return ACCESS_ABSTAIN;
        }
        
        Collection<? extends GrantedAuthority> authorities = 
            authentication.getAuthorities();
        
        for (ConfigAttribute attribute : attributes) {
            String requiredPermission = attribute.getAttribute();
            
            // Only vote on permissions this voter understands
            if (!requiredPermission.startsWith(this.permissionPrefix)) {
                continue;
            }
            
            // Check if user has this permission
            for (GrantedAuthority authority : authorities) {
                if (requiredPermission.equals(authority.getAuthority())) {
                    return ACCESS_GRANTED;
                }
            }
        }
        
        // If we found permission attributes but user doesn't have them
        boolean foundPermissionAttribute = attributes.stream()
            .anyMatch(attr -> attr.getAttribute()
                .startsWith(this.permissionPrefix));
        
        if (foundPermissionAttribute) {
            return ACCESS_DENIED;
        }
        
        return ACCESS_ABSTAIN;
    }
    
    @Override
    public boolean supports(Class<?> clazz) {
        return true;
    }
    
    @Override
    public boolean supports(ConfigAttribute attribute) {
        return attribute.getAttribute() != null &&
               attribute.getAttribute().startsWith(this.permissionPrefix);
    }
}

/**
 * ADVANCED VOTER EXAMPLE - Time-Based Authorization
 * 
 * This voter demonstrates how voters can make decisions based on context
 * beyond just checking user authorities.
 */
public class TimeBasedVoter implements AccessDecisionVoter {
    
    /**
     * Allow access only during business hours (9 AM to 5 PM, Monday-Friday).
     * This is an example of context-aware authorization.
     */
    @Override
    public int vote(
            Authentication authentication,
            Object object,
            Collection<ConfigAttribute> attributes) {
        
        // If someone requires TIME_RESTRICTED permission
        boolean requiresTimeRestriction = attributes.stream()
            .anyMatch(attr -> "TIME_RESTRICTED"
                .equals(attr.getAttribute()));
        
        if (!requiresTimeRestriction) {
            return ACCESS_ABSTAIN;  // Not my concern
        }
        
        // Check current time
        ZonedDateTime now = ZonedDateTime.now();
        int hour = now.getHour();
        DayOfWeek day = now.getDayOfWeek();
        
        boolean isBusinessHours = hour >= 9 && hour < 17;
        boolean isWeekday = day != DayOfWeek.SATURDAY && day != DayOfWeek.SUNDAY;
        
        if (isBusinessHours && isWeekday) {
            return ACCESS_GRANTED;
        }
        
        return ACCESS_DENIED;
    }
    
    @Override
    public boolean supports(Class<?> clazz) {
        return true;
    }
    
    @Override
    public boolean supports(ConfigAttribute attribute) {
        return "TIME_RESTRICTED".equals(attribute.getAttribute());
    }
}
```

---

## Part 5: SecurityMetadataSource in Detail - Configuration Strategy

Let me expand on different SecurityMetadataSource implementations to show you the configuration strategy:

```java
/**
 * ANNOTATION-BASED METADATA SOURCE
 * 
 * When you use @PreAuthorize, @Secured, @PostAuthorize,
 * the metadata comes from the method annotations.
 */
public class AnnotationSecurityMetadataSource implements SecurityMetadataSource {
    
    @Override
    public Collection<ConfigAttribute> getAttributes(Object object) {
        if (!(object instanceof MethodInvocation)) {
            return null;
        }
        
        MethodInvocation methodInvocation = (MethodInvocation) object;
        Method method = methodInvocation.getMethod();
        
        /**
         * Look for @PreAuthorize annotation on the method.
         * If found, return its value as a ConfigAttribute.
         */
        PreAuthorize annotation = method.getAnnotation(PreAuthorize.class);
        
        if (annotation != null) {
            String expression = annotation.value();
            return Arrays.asList(new PreAuthorizeConfigAttribute(expression));
        }
        
        return null;
    }
    
    @Override
    public boolean supports(Class<?> clazz) {
        return MethodInvocation.class.isAssignableFrom(clazz);
    }
    
    @Override
    public boolean supports(ConfigAttribute attribute) {
        return attribute instanceof PreAuthorizeConfigAttribute;
    }
}

/**
 * EXPRESSION-BASED VOTER
 * 
 * When using @PreAuthorize("hasRole('ADMIN')"), the expression is evaluated
 * by a specialized voter.
 */
public class PreAuthorizeExpressionVoter implements AccessDecisionVoter {
    
    private final MethodSecurityExpressionHandler expressionHandler;
    
    @Override
    public int vote(
            Authentication authentication,
            Object object,
            Collection<ConfigAttribute> attributes) {
        
        boolean granted = false;
        
        for (ConfigAttribute attribute : attributes) {
            if (!(attribute instanceof PreAuthorizeConfigAttribute)) {
                continue;
            }
            
            PreAuthorizeConfigAttribute preAuthorize = 
                (PreAuthorizeConfigAttribute) attribute;
            
            /**
             * The expression is evaluated in the context of the user
             * and the method invocation.
             * 
             * Example: hasRole('ADMIN') → checks user has ADMIN role
             * Example: #id == authentication.principal.id → checks parameter
             */
            boolean result = evaluateExpression(
                preAuthorize.getExpression(),
                authentication,
                object);
            
            if (result) {
                granted = true;
                break;
            }
        }
        
        return granted ? ACCESS_GRANTED : ACCESS_DENIED;
    }
    
    private boolean evaluateExpression(String expression,
            Authentication authentication, Object object) {
        // Use a SpEL parser to evaluate the expression
        return this.expressionHandler.createEvaluationContext(
            authentication, object)
            .evaluateExpression(expression, boolean.class);
    }
    
    @Override
    public boolean supports(Class<?> clazz) {
        return MethodInvocation.class.isAssignableFrom(clazz);
    }
    
    @Override
    public boolean supports(ConfigAttribute attribute) {
        return attribute instanceof PreAuthorizeConfigAttribute;
    }
}
```

---

## Part 6: Complete Authorization Flow - Sequence Diagram

Now let's put it all together in a complete sequence:

```
1. USER MAKES REQUEST
   Browser: GET /api/admin/users
   Request includes session cookie with authentication
        ↓
        
2. SECURITY FILTER CHAIN RECEIVES REQUEST
   DelegatingFilterProxy → FilterChainProxy
   Filters run in sequence
        ↓
   SecurityContextPersistenceFilter runs first
   Action: Load SecurityContext from session
   Result: SecurityContext.authentication is populated
        ↓
   
3. REQUEST REACHES AUTHORIZATION INTERCEPTOR
   FilterSecurityInterceptor.doFilter() is called
        ↓
   
4. INTERCEPTOR CREATES FilterInvocation
   FilterInvocation wraps: Request, Response, FilterChain
   This becomes the "object" in authorization decision
        ↓
   
5. SECURITY METADATA SOURCE CONSULTED
   Interceptor calls: SecurityMetadataSource.getAttributes(filterInvocation)
        ↓
   If DatabaseSecurityMetadataSource:
   - Extract URL from request
   - Query database: "What permissions required for /api/admin/users?"
   - Database returns: [ROLE_ADMIN, PERMISSION_USER_MANAGE]
   - Cache this result for future requests
   - Return ConfigAttributes
        ↓
   
6. GET AUTHENTICATED USER
   Interceptor gets: SecurityContext.getAuthentication()
   Result: Authentication object with user's authorities
   Example authorities: [ROLE_ADMIN, PERMISSION_AUDIT]
        ↓
   
7. ACCESS DECISION MANAGER INVOKED
   Interceptor calls: AccessDecisionManager.decide(
       authentication,           // User and their authorities
       filterInvocation,         // The request object
       configAttributes          // Required permissions
   )
        ↓
   
8. ACCESS DECISION MANAGER CONSULTS VOTERS
   Manager loops through registered voters:
   
   8a. RoleVoter.vote() called
       Question: "Does user have required ROLE_ permissions?"
       
       Checks: Does any of [ROLE_ADMIN, PERMISSION_USER_MANAGE]
               match any authority in [ROLE_ADMIN, PERMISSION_AUDIT]?
       
       Yes! User has ROLE_ADMIN
       Vote: ACCESS_GRANTED (1)
        ↓
   
   8b. PermissionVoter.vote() called
       Question: "Does user have required PERMISSION_ permissions?"
       
       Checks: Does any of [ROLE_ADMIN, PERMISSION_USER_MANAGE]
               match any authority in [ROLE_ADMIN, PERMISSION_AUDIT]?
       
       No, user doesn't have PERMISSION_USER_MANAGE
       (they don't have permission to manage users, only audit role)
       Vote: ACCESS_DENIED (-1)
        ↓
   
   8c. TimeBasedVoter.vote() called
       Question: "Is it within allowed time?"
       
       Checks: Is it between 9 AM and 5 PM? Is it a weekday?
       Current time: 2:30 PM on Tuesday
       Answer: Yes, it's within business hours
       Vote: ACCESS_GRANTED (1)
        ↓
   
9. MANAGER AGGREGATES VOTES (Using AffirmativeBased Strategy)
   Votes received:
   - RoleVoter: ACCESS_GRANTED (1)
   - PermissionVoter: ACCESS_DENIED (-1)
   - TimeBasedVoter: ACCESS_GRANTED (1)
   
   Strategy: If ANY voter grants, allow
   Result: ACCESS_GRANTED (at least one voter said yes)
        ↓
   
10. DECISION MADE - ACCESS ALLOWED
    Manager returns normally (no exception)
    Interceptor knows: User is authorized
        ↓
    
11. OPTIONAL AUTHENTICATION REFINEMENT
    If AuthenticationManager is configured:
    Action: Maybe require additional authentication
    Example: User might need to re-enter password for sensitive operation
        ↓
    
12. REQUEST CONTINUES
    Interceptor calls: FilterChain.doFilter()
    Request proceeds to next filter or controller
        ↓
    
13. CONTROLLER EXECUTES
    @GetMapping("/api/admin/users")
    public List<User> getUsers() {
        // Code executes
    }
        ↓
    
14. OPTIONAL POST-AUTHORIZATION
    AfterInvocationProvider can filter results
    Example: Remove sensitive fields from returned User objects
        ↓
    
15. RESPONSE RETURNED TO USER
    User receives list of users (authorization succeeded)
```

---

## Part 7: Complete Configuration Example

```java
package com.example.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.intercept.SecurityMetadataSource;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import java.util.Arrays;
import java.util.List;

/**
 * Complete configuration showing how to customize authorization.
 */
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class CustomAuthorizationConfig {
    
    /**
     * STEP 1: Create custom SecurityMetadataSource
     */
    @Bean
    public SecurityMetadataSource securityMetadataSource(
            UrlPermissionRepository urlPermissionRepository,
            PermissionCache permissionCache) {
        return new DatabaseSecurityMetadataSource(
            urlPermissionRepository,
            permissionCache);
    }
    
    /**
     * STEP 2: Create voters with different authorization logic
     */
    @Bean
    public AccessDecisionVoter roleVoter() {
        return new RoleVoter();
    }
    
    @Bean
    public AccessDecisionVoter permissionVoter() {
        return new PermissionVoter();
    }
    
    @Bean
    public AccessDecisionVoter timeBasedVoter() {
        return new TimeBasedVoter();
    }
    
    /**
     * STEP 3: Create AccessDecisionManager with voters
     */
    @Bean
    public AccessDecisionManager accessDecisionManager(
            List<AccessDecisionVoter> voters) {
        return new AffirmativeBased(voters);
    }
    
    /**
     * STEP 4: Configure HTTP security
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http)
            throws Exception {
        http
            .authorizeRequests()
                // Public URLs
                .antMatchers("/login", "/register").permitAll()
                // Admin area requires ROLE_ADMIN
                .antMatchers("/admin/**").hasRole("ADMIN")
                // API endpoints require specific permission
                .antMatchers(HttpMethod.DELETE, "/api/**")
                    .access("hasAuthority('PERMISSION_DELETE')")
                // Any other request requires authentication
                .anyRequest().authenticated()
            .and()
            .formLogin()
                .loginPage("/login")
            .and()
            .logout()
                .logoutUrl("/logout");
        
        return http.build();
    }
}
```

---

## Key Architectural Insights

1. **Separation of Concerns**: Configuration (SecurityMetadataSource), decision-making (Voters), and aggregation (Manager) are separate, replaceable components.

2. **Filter Chain Pattern**: Authorization happens at multiple levels (URL and method) through interceptors in the filter chain.

3. **Voting Pattern**: Multiple independent voters provide expertise, and the manager applies a strategy to reach a final decision.

4. **Configuration Strategy**: What permissions are required is determined by a pluggable source (annotations, database, properties, etc.).

5. **Context-Aware**: Voters can access the full request/invocation context to make nuanced authorization decisions.

6. **Transparent to User Code**: Controllers don't need to perform authorization checks—they're done automatically by interceptors.

7. **Post-Authorization**: Even after a request is allowed, post-authorization providers can filter results or validate post-conditions.
