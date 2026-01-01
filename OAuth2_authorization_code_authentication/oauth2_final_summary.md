# OAUTH2 AUTHORIZATION CODE FLOW - FINAL INTERNAL FLOW SUMMARY

---

## PHASE 1: INITIAL LOGIN REQUEST

### 1. OAuth2AuthorizationRequestRedirectFilter (Filter)
**Flow:**
```
Request /oauth2/authorization/{regId}
  ↓ Extract registrationId from path
  ↓ Call OAuth2AuthorizationRequestResolver.resolve(request, regId)
  ↓ Call OAuth2AuthorizationRequestRepository.saveAuthorizationRequest()
  ↓ Send HTTP 302 redirect to authorizationUri
```

### 2. OAuth2AuthorizationRequestResolver (Interface)
**Contract:** `resolve(request, registrationId) → OAuth2AuthorizationRequest`
**Flow:**
```
Implementation (DefaultOAuth2AuthorizationRequestResolver):
  ↓ ClientRegistrationRepository.findByRegistrationId(regId) → ClientRegistration
  ↓ Extract authorizationUri, clientId, scopes, redirectUri from ClientRegistration
  ↓ Apply customizers (e.g., PKCE)
  ↓ Generate random state (CSRF token)
  ↓ Build OAuth2AuthorizationRequest
  ↓ Return request
```

### 3. ClientRegistrationRepository (Interface)
**Contract:** `findByRegistrationId(regId) → ClientRegistration`
**Flow:**
```
Implementation (InMemoryClientRegistrationRepository / Property-Based):
  ↓ Look up in Map<String, ClientRegistration>
  ↓ Return matching ClientRegistration or throw exception
```

### 4. ClientRegistration (Class - Data Holder)
**Data Held:**
- registrationId: "google"
- clientId, clientSecret
- authorizationUri, tokenUri, userInfoUri
- redirectUri, scopes, userNameAttributeName
- clientAuthenticationMethod, authorizationGrantType

**Usage:** Configuration reference for all OAuth2 operations

### 5. OAuth2AuthorizationRequest (Class - Data Holder)
**Data Held:**
- authorizationUri, clientId, redirectUri
- scopes, state (random CSRF token)
- responseType: "code"
- codeChallenge, codeChallengeMethod (PKCE)
- additionalParameters

**Conversion:** Built into URL sent to provider

### 6. OAuth2AuthorizationRequestRepository (Interface)
**Contract:** 
```
saveAuthorizationRequest(request, httpReq, httpRes)
loadAuthorizationRequest(httpReq) → OAuth2AuthorizationRequest
removeAuthorizationRequest(httpReq, httpRes) → OAuth2AuthorizationRequest
```

**Flow:**
```
Implementation (HttpSessionOAuth2AuthorizationRequestRepository):
  ↓ Get or create HttpSession
  ↓ Store request under key: SPRING_SECURITY_OAUTH2_AUTHORIZATION_REQUEST_ATTR
  ↓ Session persisted as JSESSIONID cookie
```

---

## PHASE 2: CALLBACK HANDLING & TOKEN EXCHANGE

### 1. OAuth2LoginAuthenticationFilter (Filter)
**Flow:**
```
Request /authorized/{regId}?code=xxx&state=xxx
  ↓ Extract code, state, registrationId
  ↓ OAuth2AuthorizationRequestRepository.loadAuthorizationRequest()
  ↓ Validate state parameter (CSRF check)
  ↓ Create incomplete OAuth2AuthenticationToken
  ↓ Call AuthenticationManager.authenticate(token)
  ↓ Delegate to OAuth2LoginAuthenticationProvider
```

### 2. OAuth2AuthorizationResponse (Class - Data Holder)
**Data Held:**
- code: authorization code from provider
- state: CSRF token to validate
- error, errorDescription (if error)
- additionalParameters

**Usage:** Created from callback query string, validated against stored request

### 3. OAuth2AuthorizationCodeGrantRequest (Class - Data Holder)
**Data Held:**
- clientRegistration: provider config
- authorizationRequest: from Phase 1
- authorizationResponse: from callback

**Usage:** Bundled and passed to token exchange client

### 4. OAuth2LoginAuthenticationProvider (Provider - Orchestrator)
**Flow:**
```
authenticate(incompleteToken)
  ↓ Get clientRegistration by registrationId
  ↓ Build OAuth2AuthorizationCodeGrantRequest
  ↓ Call OAuth2AccessTokenResponseClient.getTokenResponse(grantRequest)
    └─ POST to tokenUri with code, client_id, client_secret
    └─ Return OAuth2AccessTokenResponse with access_token
  ↓ Create OAuth2UserRequest(clientRegistration, accessToken)
  ↓ Call OAuth2UserService.loadUser(userRequest)
    └─ GET to userInfoUri with Bearer token
    └─ Parse response to Map
    └─ Return OAuth2User with attributes
  ↓ Map authorities
  ↓ Create authenticated OAuth2AuthenticationToken
  ↓ Return authenticated token
```

### 5. OAuth2AccessTokenResponseClient (Interface)
**Contract:** `getTokenResponse(grantRequest) → OAuth2AccessTokenResponse`

**Flow:**
```
Implementation (RestClientAuthorizationCodeTokenResponseClient):
  ↓ OAuth2AuthorizationCodeRequestEntityConverter.convert(grantRequest)
    └─ Build POST request body: code, client_id, client_secret, redirect_uri, grant_type
  ↓ Send POST to tokenUri
  ↓ OAuth2AccessTokenResponseHttpMessageConverter.read(response)
    └─ Parse JSON: access_token, refresh_token, expires_in
  ↓ Return OAuth2AccessTokenResponse
```

### 6. OAuth2AccessTokenResponse (Class - Data Holder)
**Data Held:**
- accessToken: OAuth2AccessToken (tokenValue, expiresAt)
- refreshToken: OAuth2RefreshToken (tokenValue)
- scopes: granted permissions
- additionalParameters: provider-specific (id_token, etc.)

**Usage:** Extracted for user info fetch and future API calls

---

## PHASE 3: USER INFO FETCH & AUTHENTICATION

### 1. OAuth2UserService (Interface)
**Contract:** `loadUser(OAuth2UserRequest) → OAuth2User`

**Flow:**
```
Implementation (DefaultOAuth2UserService):
  ↓ OAuth2UserRequestEntityConverter.convert(userRequest)
    └─ Build GET request with Authorization: Bearer {accessToken}
  ↓ Send GET to userInfoUri
  ↓ Parse JSON response to Map<String, Object>
  ↓ Get userNameAttributeName from clientRegistration
  ↓ Create DefaultOAuth2User(authorities, attributes, nameAttrKey)
  ↓ Return OAuth2User
```

### 2. OAuth2UserRequest (Class - Data Holder)
**Data Held:**
- clientRegistration: with userInfoUri, userNameAttributeName
- accessToken: for Authorization header

**Usage:** Packages data for userinfo endpoint call

### 3. OAuth2User (Interface)
**Contract:**
```
getAttributes() → Map<String, Object>
getAuthorities() → Collection<GrantedAuthority>
getName() → String
```

**Represents:** User data from provider (email, name, picture, etc.) + authorities

### 4. DefaultOAuth2User (Class - Data Holder)
**Data Held:**
- authorities: roles/permissions
- attributes: email, name, picture, sub, etc.
- nameAttributeKey: "sub" or "email" or "login"

**Usage:** Holds authenticated user data, passed as principal in token

### 5. OAuth2AuthenticationToken (Class - Data Holder)
**Data Held:**
- principal: OAuth2User (with attributes & authorities)
- authorities: GrantedAuthority collection
- authorizedClientRegistrationId: "google"
- authenticated: boolean (true after auth succeeds)

**Usage:** Final authenticated token stored in SecurityContext

### 6. GrantedAuthoritiesMapper (Interface - Optional)
**Contract:** `mapAuthorities(authorities) → Collection<GrantedAuthority>`

**Flow:**
```
Maps provider scopes/claims to Spring authorities
Example: "email" scope → "ROLE_EMAIL_USER" authority
```

---

## PHASE 4: SESSION STORAGE & TOKEN REFRESH

### 1. OAuth2AuthorizedClientRepository (Interface)
**Contract:**
```
saveAuthorizedClient(client, principal, httpReq, httpRes)
loadAuthorizedClient(regId, principal, httpReq) → OAuth2AuthorizedClient
removeAuthorizedClient(regId, principal, httpReq, httpRes)
```

**Flow:**
```
Implementation (HttpSessionOAuth2AuthorizedClientRepository):
SAVE:
  ↓ Get HttpSession
  ↓ Store under key: SPRING_SECURITY_OAUTH2_AUTHORIZED_CLIENT_{regId}
  ↓ Session persisted as JSESSIONID cookie

LOAD:
  ↓ Get HttpSession from JSESSIONID cookie
  ↓ Retrieve by key: SPRING_SECURITY_OAUTH2_AUTHORIZED_CLIENT_{regId}
  ↓ Return OAuth2AuthorizedClient or null

REMOVE:
  ↓ Get HttpSession
  ↓ Delete by key: SPRING_SECURITY_OAUTH2_AUTHORIZED_CLIENT_{regId}
```

### 2. OAuth2AuthorizedClient (Class - Data Holder)
**Data Held:**
- clientRegistration: provider config
- principalName: authenticated user identifier
- accessToken: OAuth2AccessToken (for API calls)
- refreshToken: OAuth2RefreshToken (for refresh when expired)

**Usage:** Stores user-provider relationship + current tokens

### 3. OAuth2AuthorizedClientManager (Interface)
**Contract:** `authorize(OAuth2AuthorizeRequest) → OAuth2AuthorizedClient`

**Flow:**
```
Implementation (DefaultOAuth2AuthorizedClientManager):
  ↓ Load OAuth2AuthorizedClient from repository
  ↓ If exists:
    ├─ Check if accessToken expired
    ├─ If not expired: return as-is
    └─ If expired: call authorizedClientProvider.authorize()
  ↓ If not exists: call authorizedClientProvider.authorize()
  ↓ If refreshed/created: save to repository
  ↓ Return valid (non-expired) OAuth2AuthorizedClient
```

### 4. OAuth2AuthorizeRequest (Class - Data Holder)
**Data Held:**
- clientRegistrationId: "google"
- principal: authenticated user
- request, response: HTTP objects
- attributes: optional additional data

**Usage:** Request for getting authorized client with refresh

### 5. RefreshTokenOAuth2AuthorizedClientProvider (Provider)
**Flow:**
```
authorize(authorizeRequest)
  ↓ Get authorizedClient
  ↓ If no refreshToken: return null
  ↓ If accessToken not expired: return client as-is
  ↓ If accessToken expired:
    ├─ Build OAuth2RefreshTokenGrantRequest
    ├─ Call OAuth2AccessTokenResponseClient.getTokenResponse()
    │   └─ POST to tokenUri with refresh_token, grant_type=refresh_token
    │   └─ Return new OAuth2AccessTokenResponse
    ├─ Create new OAuth2AuthorizedClient with fresh accessToken
    └─ Return refreshed client
  ↓ If refresh fails: return null
```

### 6. DelegatingOAuth2AuthorizedClientProvider (Provider)
**Flow:**
```
authorize(authorizeRequest)
  ↓ For each provider in delegation list:
    ├─ Call provider.authorize(authorizeRequest)
    ├─ If result not null: return it
  ↓ If all return null: return null

Example chain:
  ↓ Try AuthorizationCodeOAuth2AuthorizedClientProvider
  ↓ If succeeds: return
  ↓ Try RefreshTokenOAuth2AuthorizedClientProvider
  ↓ If succeeds: return (token refreshed)
  ↓ If both fail: return null
```

---

## DATA TRANSFORMATION SUMMARY

```
PHASE 1:
User Click
  → HTTP Request (/oauth2/authorization/google)
  → OAuth2AuthorizationRequestRedirectFilter
  → ClientRegistration (from repository)
  → OAuth2AuthorizationRequest
  → Session Storage
  → HTTP 302 Redirect to Provider

PHASE 2:
Provider Callback
  → HTTP Request (/authorized/google?code=xxx&state=xxx)
  → OAuth2LoginAuthenticationFilter
  → OAuth2AuthorizationResponse
  → OAuth2AuthorizationCodeGrantRequest
  → RestClientAuthorizationCodeTokenResponseClient
  → POST to Token Endpoint
  → OAuth2AccessTokenResponse

PHASE 3:
Access Token
  → OAuth2UserRequest
  → DefaultOAuth2UserService
  → GET to UserInfo Endpoint
  → OAuth2User (DefaultOAuth2User)
  → OAuth2LoginAuthenticationProvider
  → OAuth2AuthenticationToken (AUTHENTICATED)
  → SecurityContext

PHASE 4:
Authenticated Token
  → OAuth2AuthorizedClient Creation
  → OAuth2AuthorizedClientRepository.saveAuthorizedClient()
  → Session Storage
  → Future Requests:
    → OAuth2AuthorizedClientManager.authorize()
    → RefreshTokenOAuth2AuthorizedClientProvider (if expired)
    → Fresh Token
    → API Call with Bearer Token
```

---

## KEY INTERNAL MECHANICS

| Component | Internal Process |
|-----------|------------------|
| **Filter** | Intercepts HTTP request → Routes to handler → Transforms request/response |
| **Interface** | Defines contract → Allows custom implementations → Spring auto-wires |
| **Class (Data)** | Holds data fields → Serializable → Passed between components |
| **Provider** | Checks conditions → Executes logic → Returns result or null |
| **Repository** | Stores/retrieves data → Supports multiple implementations (session, DB, cache) |
| **Converter** | Transforms one type to another → Used by HTTP clients |
| **Manager** | Orchestrates workflow → Delegates to providers → Handles state |

---

## FLOW AT A GLANCE

```
Phase 1: Filter → Resolver → ClientRegistration → AuthorizationRequest → Repository → Redirect
Phase 2: Filter → Response → GrantRequest → TokenClient → POST → AccessTokenResponse
Phase 3: UserService → GET → OAuth2User → AuthProvider → AuthenticationToken → SecurityContext
Phase 4: Manager → Repository → CheckExpiry → RefreshProvider → POST → UpdateToken → API
```