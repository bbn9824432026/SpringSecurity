# OAuth 2.0 Authorization Code Flow - Complete Guide

## Overview

The Authorization Code Flow is the most secure OAuth 2.0 flow for web applications. It's designed to be safe for applications that have a backend server where secrets can be securely stored. The flow involves four main actors:

- **Resource Owner**: The user who owns the data
- **Client Application**: Your web app requesting access
- **Authorization Server**: The OAuth provider (Google, GitHub, etc.) that verifies the user
- **Resource Server**: The API server hosting the protected resources (usually same organization as Authorization Server)

## The Complete Flow - Step by Step

### Step 1: User Initiates Login

The user clicks "Login with Google" or "Login with GitHub" on your application. This is the beginning of the journey.

```
User clicks "Login with Google" button
     ↓
Client application prepares to redirect to Authorization Server
```

### Step 2: Client Redirects to Authorization Server

Your application redirects the user's browser to the Authorization Server with a carefully constructed URL containing important parameters.

**Request URL:**
```
GET https://accounts.google.com/o/oauth2/v2/auth?
  client_id=YOUR_CLIENT_ID.apps.googleusercontent.com&
  redirect_uri=https://yourapp.com/oauth/callback&
  scope=openid%20profile%20email&
  response_type=code&
  state=random_string_xyz&
  nonce=another_random_string
```

**Parameter Explanation:**

- `client_id`: Identifies your application to Google. You get this when you register your app with Google Cloud Console.
- `redirect_uri`: The URL on YOUR server where the user will be sent after authorization. Must match exactly with what you registered.
- `scope`: The permissions you're requesting. "openid profile email" means you want to access the user's identity, basic profile, and email. The user will see these permissions requested.
- `response_type=code`: This tells the server "I want the Authorization Code flow." The server will respond with a short-lived authorization code, not an access token directly.
- `state`: A random string you generate and store in the user's session. This is a security measure against CSRF attacks. The server will send it back, and you verify it matches before proceeding.
- `nonce`: Another random value to prevent token replay attacks, especially important for OpenID Connect.

### Step 3: User Authenticates and Consents

The Authorization Server shows the user a login screen (if they're not already logged in) and then a consent screen showing what permissions your app is requesting.

```
Authorization Server shows login page
     ↓
User enters username/password (or already logged in)
     ↓
Authorization Server shows consent screen:
  "yourapp.com wants to access your:
   - Name
   - Email address  
   - Profile picture"
     ↓
User clicks "Allow"
```

The user never gives their Google password to your application. They authenticate directly with Google's servers. This is the key security benefit of OAuth.

### Step 4: Authorization Server Redirects with Authorization Code

After the user grants permission, Google redirects the browser back to your application with an authorization code.

**Response URL:**
```
GET https://yourapp.com/oauth/callback?
  code=4/0AX4XfWh_Example_Authorization_Code_Long_String&
  state=random_string_xyz
```

**Important Security Point:** Notice that the response contains the `state` parameter you sent earlier. Your server MUST verify this matches what you stored in the user's session. If it doesn't match, someone might be trying to attack your user with a CSRF attack, and you should reject the request.

The authorization code is:
- Short-lived (typically expires in 10 minutes)
- Single-use (can only be exchanged once)
- Not the access token (this is crucial)

### Step 5: Client Backend Exchanges Code for Access Token

This is the most important step for understanding why this flow is secure. Your backend server (not the browser) makes a direct, server-to-server request to the Authorization Server to exchange the authorization code for an access token.

**Backend Request (happens on YOUR server, not in the browser):**
```
POST https://oauth2.googleapis.com/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&
code=4/0AX4XfWh_Example_Authorization_Code_Long_String&
client_id=YOUR_CLIENT_ID.apps.googleusercontent.com&
client_secret=YOUR_CLIENT_SECRET_KEEP_THIS_SAFE&
redirect_uri=https://yourapp.com/oauth/callback
```

**Why This Matters:** The `client_secret` is sent in this request. This is the password to your application. You must NEVER expose this in the browser or in client-side code. It should only exist on your backend server. This is why the Authorization Code Flow is secure - the browser never gets the secret, so even if malicious JavaScript runs on your site, attackers can't use the authorization code to get an access token.

**Backend Response:**
```json
{
  "access_token": "ya29.a0AfH6SMB_Example_Access_Token_String",
  "expires_in": 3600,
  "refresh_token": "1//0gF_Example_Refresh_Token",
  "scope": "openid profile email",
  "token_type": "Bearer"
}
```

**Response Fields Explained:**

- `access_token`: This is what you'll use to call Google's APIs on behalf of the user. It's like a temporary badge proving you have permission to access the user's data. Usually JWT-encoded.
- `expires_in`: How many seconds until this token expires (3600 = 1 hour). After this time, you need to get a new one.
- `refresh_token`: This is special - it lasts much longer (days, months, or indefinitely) and can be used to get a new access token without asking the user to log in again. Store this securely in a database or encrypted session.
- `scope`: Confirmation of what permissions were granted.
- `token_type`: Usually "Bearer", meaning you'll use this token in HTTP Authorization headers as `Authorization: Bearer {access_token}`

### Step 6: Client Stores Tokens and Creates User Session

Your backend server now stores the tokens (securely) and creates a session for the user on your own application.

```
Server validates the access_token response
     ↓
Server stores tokens (in encrypted session or database)
     ↓
Server creates local session/JWT for the user
     ↓
Server sets session cookie on response
     ↓
Browser receives response with session cookie
```

At this point, the user's browser is no longer involved in OAuth. Your server has taken over.

### Step 7: Client Uses Access Token to Fetch User Data

Now your backend can call Google's API to get information about the user.

**Request to Resource Server:**
```
GET https://www.googleapis.com/oauth2/v2/userinfo
Authorization: Bearer ya29.a0AfH6SMB_Example_Access_Token_String
```

**Response from Resource Server:**
```json
{
  "id": "1234567890",
  "email": "user@gmail.com",
  "verified_email": true,
  "name": "John Doe",
  "picture": "https://lh3.googleusercontent.com/a-/AOh14..."
}
```

Your backend now has the user's information and can:
- Create a new user account if they don't exist
- Log them into your application
- Store their information in your database

### Step 8: Client Redirects User Back to Application

Finally, your backend redirects the user back to your application's home page or dashboard, where they're now logged in.

```
Server redirects browser to https://yourapp.com/dashboard
     ↓
Browser now has session cookie from your server
     ↓
User is logged in to YOUR application
     ↓
OAuth flow is complete
```

## Key Security Benefits

**Password Never Shared**: The user's password is only ever given to Google (or whoever the OAuth provider is). Your application never sees it.

**Limited Permissions**: The user grants specific permissions (scopes). If your app is compromised, attackers can't access everything the user can do with Google.

**Revocable Access**: The user can go to Google's settings and revoke your application's access at any time, without changing their password.

**Token Expiration**: Access tokens are short-lived. Even if stolen, they're only useful for a limited time. The refresh token is long-lived but should be stored securely on your backend.

**Secret Never Exposed to Browser**: The client_secret is exchanged on the backend. The browser never sees it, preventing compromise if malicious JavaScript is injected.

## Spring Security Implementation Pattern

In Spring Security, your OAuth 2.0 client configuration looks something like this:

```yaml
spring:
  security:
    oauth2:
      client:
        registration:
          google:
            client-id: YOUR_CLIENT_ID.apps.googleusercontent.com
            client-secret: YOUR_CLIENT_SECRET
            scope:
              - openid
              - profile
              - email
            authorization-grant-type: authorization_code
            redirect-uri: "{baseUrl}/oauth2/callback/{registrationId}"
        provider:
          google:
            authorization-uri: https://accounts.google.com/o/oauth2/v2/auth
            token-uri: https://oauth2.googleapis.com/token
            user-info-uri: https://www.googleapis.com/oauth2/v2/userinfo
            user-name-attribute: id
```

Spring Security automatically handles steps 2-7 for you. When a user clicks your login button, Spring redirects them to Google (Step 2), and when Google redirects them back with the authorization code (Step 4), Spring automatically exchanges it for the access token (Step 5), fetches user info (Step 7), and creates a session.

## Common Pitfalls to Avoid

**Not Validating the State Parameter**: Always verify the state parameter matches what you stored. This prevents CSRF attacks.

**Storing Secrets in Client Code**: Never put client_secret in frontend code or version control. Use environment variables.

**Not Using HTTPS**: OAuth must run over HTTPS. The redirect_uri must be HTTPS in production (HTTP only allowed for localhost development).

**Forgetting to Store Refresh Token**: If you need long-term access without user interaction, store the refresh token securely.

**Not Handling Token Expiration**: Always check if access_token has expired and refresh it if needed before making API calls.
