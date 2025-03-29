# API Troubleshooting Guide

This guide covers common issues you might encounter when integrating with garde

## Authentication Issues

### Getting "Invalid authorization format" error
This usually means:
1. The Bearer token format is incorrect
2. The token has spaces or special characters

Correct format:
```http
Authorization: Bearer 6cc0595f-f3...
```

### Getting "Client certificate not present, valid, or verified" for admin endpoints
This means:
1. No valid client certificate provided
2. The certificate isn't from the CA
3. The certificate's domain doesn't match the service domain

Check:
- Certificate is properly configured in the client
- Certificate is signed by the CA
- Certificate's Common Name matches the domain
- Certificate isn't expired

### Getting "Unauthorized" with valid certificate for admin endpoints
Common causes:
1. User email not in ADMIN_USERS list in .env
2. Wrong session token used
3. Attempting to access users outside assigned groups (except for adding the user to their own group)

Solution:
- Check if email is in ADMIN_USERS
- Ensure using a fresh session token
- Verify sharing at least one group with the target user (Except when adding the user to their own group, in this case groups doesn't matter)

### Getting "Unauthorized" on endpoints
Common causes:
1. Missing authentication for protected endpoints
2. Using endpoint that requires authentication without logging in
3. Using admin endpoint without admin privileges
4. Session expired or invalid

Solution:
1. Check endpoint requirements:
   - Public endpoints (no auth needed):
     ```
     POST /login
     POST /users
     POST /users/password/otp
     POST /users/password/reset
     ```
   - Protected endpoints (login required):
     ```
     GET  /users/me
     POST /logout
     POST /users/mfa/*
     POST /users/password/change
     ```
   - Admin endpoints (login + admin privileges):
     ```
     GET  /users
     GET  /users/{id}
     PUT  /users/{id}
     POST /sessions/revoke
     ```

2. For protected endpoints:
   - Login first to get session token
   - Include token in subsequent requests
   - Check token expiration
   - Verify admin status for admin endpoints

## Permission and Group Issues

### Getting "permissions system not loaded" or "groups system not loaded" error

1. Missing files:
   - If permissions.json is missing:
     - Permission system is disabled
     - Permission-related operations will return "permissions system not loaded"
     - Admin operations not involving permissions remain available but the ones involving permissions are blocked
     - Superuser operations remain unaffected
   - If groups.json is missing:
     - Groups system is disabled
     - Groups-related operations will return "groups system not loaded"
     - Admin operations are restricted
     - Superuser operations remain unaffected

2. Malformed JSON:
   - Invalid JSON syntax
   - Missing required fields
   - Incorrect data types
   - Group references in permissions.json not matching groups.json

Solution:
1. For missing files:
   - Create the missing file(s) in /configs/ directory
   - Use minimal valid structure:
     ```json
     // permissions.json
     {
         "example_permission": {
             "name": "Example Permission",
             "description": "Description"
         }
     }

     // groups.json
     {
         "example_group": {
             "name": "Example Group",
             "description": "Description"
         }
     }
     ```

2. For malformed JSON:
   - Validate JSON syntax using a JSON validator
   - Ensure all required fields are present
   - Check data types match expected format
   - Verify group references in permissions.json exist in groups.json

3. After fixing:
   - Restart the service to reload configurations
   - Check logs for any remaining errors
   - Verify admin operations work as expected

Note: The service will continue to function with basic authentication and user management even if these files are missing or malformed, but with limited functionality:
- Without permissions.json: No permission management
- Without groups.json: No group management
- Superuser operations remain available in both cases

### Getting "Unauthorized" when trying to update a user
This usually means:
1. No shared groups with the target user
2. Attempting to modify a superuser
3. Not an admin

Check:
```http
GET /users
Authorization: Bearer 572a399c-6c...
```
to see manageable users.

### User unable to access resources after permission update
Common causes:
1. Permission update still pending admin approval
2. Permission not associated with user's groups
3. Permission name misspelled

Check:
- User's pending_updates field
- Permission exists in configs/permissions.json
- Group associations are correct

## MFA Issues

### User unable to access any endpoints after login
This usually means:
1. MFA is enforced but not set up
2. MFA verification failed

Solution:
1. Complete MFA setup:
```http
POST /users/mfa/setup
Authorization: Bearer 54492786-1c...
```

2. Verify MFA:
```http
POST /users/mfa/verify
Authorization: Bearer bccf1b28-fd...
{
    "code": "123456"
}
```

### Getting "Unauthorized" during MFA setup
This happens when:
1. MFA setup attempted without authentication when not required
2. MFA already set up and trying to set up again
3. Wrong authentication state for MFA setup
4. User status is not "ok" when attempting unauthenticated setup

Solution:
1. Check MFA requirement state:
   - If MFA is enforced but not set up:
     - User must be in "ok" status
     - Can access setup endpoints without auth
     - Must complete setup before accessing other endpoints
   - If MFA is optional:
     - Must authenticate first
     - Use session token for setup endpoints

2. Verify correct setup flow:
   ```http
   # When MFA is enforced but not set up:
   POST /users/mfa/setup
   {
     "email": "user@example.com"  # Required for unauthenticated setup
   }

   # When MFA is optional:
   POST /users/mfa/setup
   Authorization: Bearer your-session-token
   ```

3. Common mistakes:
   - Trying unauthenticated setup when MFA is optional
   - Using session token when MFA setup is required
   - Attempting setup when MFA is already enabled

4. User needs to contact admin if they are in locked state although they believe they shouldn't be 

### Unable to disable MFA
Check if:
1. MFA is enforced by admin
2. MFA is globally enforced
3. Incorrect MFA code provided

Solution:
- MFA can't be disabled if enforced
- Verify MFA code is correct
- Check user's mfa_enforced status

## Session Management

### All sessions suddenly becoming invalid
This happens when:
1. Password was changed
2. Account was locked
3. Suspicious activity detected
4. Admin revoked sessions

Check:
- Recent password changes
- Account status
- Security logs
- Admin actions

### Getting "Too many requests" error
Rate limits exceeded:
- Login: 5 attempts/minute
- Password reset: 3 attempts/5 minutes
- Other endpoints: 60 requests/minute

Solution:
- Implement exponential backoff
- Cache responses where possible
- Check Retry-After header

## Configuration Issues

### Permission changes not taking effect
Check:
1. permissions.json format:
```json
{
    "permission_name": {
        "name": "Display Name",
        "description": "What this permission does",
        "groups": ["group1", "group2"]
    }
}
```

2. Groups exist in groups.json:
```json
{
    "group1": {
        "name": "Group One",
        "description": "Description"
    }
}
```

3. Referenced groups exist
4. JSON files are valid

### Admin unable to see certain users
This means:
1. Admin doesn't share groups with those users
2. Users are superusers (only visible to superuser)

Solution:
- Check group memberships
- Use superuser for full access
- Update group assignments if needed

## Security Issues

### Account getting locked frequently
This happens when:
1. Too many failed login attempts (5/minute)
2. Multiple IP sessions detected
3. Suspicious activity patterns
4. Password reset attempts exceeded (5 attempts)

Solution:
- Implement proper retry logic
- Use single IP for requests
- Handle MFA properly
- Store session tokens securely

### IP address getting blocked
Occurs when:
1. Rate limits repeatedly exceeded
2. Multiple failed login attempts
3. Suspicious patterns detected

Solution:
- Implement rate limiting on your side
- Use exponential backoff
- Cache responses
- Use consistent IP addresses

## User Status Management

### User status stuck in "pending_approval"
This happens when:
1. New user registration
2. Password reset completed
3. Admin hasn't approved yet

Solution:
Admin needs to approve:
```http
PUT /users/{user_id}
Authorization: Bearer 572a399c-6c...
{
    "status": "ok",
    "security_code": "admin_security_code"
}
```

### User status transitions failing
Check:
1. Current status allows transition
2. Admin has required permissions
3. Status change doesn't conflict with:
   - Pending updates
   - Active sessions
   - MFA requirements
   - Group memberships

Valid status transitions:
- pending_approval → ok
- ok → locked_by_admin
- locked_by_security → ok (requires admin)
- locked_by_admin → ok

## Email Configuration Issues

### Password Reset Emails Not Being Sent
Check:
1. SMTP configuration in .env:
```env
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASSWORD=your-app-specific-password
SMTP_FROM=your-email@gmail.com
```

2. Common issues:
- Incorrect SMTP credentials
- SMTP server connection issues
- Rate limiting by SMTP provider
- Network connectivity to SMTP server

3. If using Gmail:
- Ensure using App Password instead of regular password
- Check if less secure app access is enabled (if required)
- Verify no Google account security blocks

## Admin Operations

### Multiple admins unable to see each other
Check:
1. Admins don't share any groups
2. One admin might be superuser
3. Group membership not properly synchronized

Solution:
- Ensure admins share at least one group
- Use superuser to manage admin relationships
- Review group assignments:
```http
PUT /users/{admin_id}
Authorization: Bearer 572a399c-6c...
{
    "groups": {
        "admin_group": true
    },
    "security_code": "admin_security_code"
}
```

### Admin unable to process update requests
Common causes:
1. Request expired (older than 24 hours)
2. Admin lost group membership
3. Target user changed groups
4. Requested permission/group no longer exists

Solution:
1. Check request status:
```http
GET /users/{user_id}
Authorization: Bearer 572a399c-6c...
```

2. Verify admin still shares groups with user:
```http
GET /users
Authorization: Bearer 572a399c-6c...
```

## Update Request Management

### User permissions not updating after group change
Common causes:
1. Redis connection issues preventing permission updates
2. Group change pending approval
3. Permission requires multiple group memberships
4. Group change conflicts with enforced permissions

Check group status:
```http
GET /users/{user_id}
Authorization: Bearer 572a399c-6c...
```

Look for:
- pending_updates field
- current group memberships
- Redis connectivity (if permissions seem stale)

## Configuration and Setup Issues

### Service failing to start
Common issues:
1. File permissions:
- TLS certificates readable
- Config files (permissions.json, groups.json) accessible
- Proper ownership of files

2. Redis connection:
- Redis server running
- Correct URL format
- Network access allowed

### Permission system not working
Check configuration files:
1. Location of config files:
```
/configs/
  ├── permissions.json
  └── groups.json
```

2. JSON syntax valid:
```json
// permissions.json
{
    "permission_name": {
        "name": "Display Name",
        "description": "Description",
        "groups": ["group1"]  // Optional
    }
}

// groups.json
{
    "group1": {
        "name": "Group One",
        "description": "Description"
    }
}
```

3. File permissions and ownership correct

### TLS/mTLS Issues
Common setup mistakes:
1. Wrong certificate chain:
```
Root CA Certificate
└── Intermediate CA Certificate
    └── Server Certificate
```

2. Missing client verification:
```env
TLS_CA_PATH=/path/to/client/ca.crt
```

3. Domain mismatch:
- Certificate CN/SAN doesn't match DOMAIN_NAME
- Client certificate from different domain

## Password Reset Issues

### Password reset OTP not received
Common causes:
1. Using wrong email address
2. Email service issues
3. Email marked as spam
4. Rate limit exceeded (3 attempts/5 minutes)

Solution:
1. Verify correct email:
```http
POST /users/password/otp
{
    "email": "user@example.com"
}
```

2. Check rate limits before retrying

### Password reset failing
Common causes:
2. OTP code expired (valid for 5 minutes)
3. Account locked or suspended
4. Too many failed attempts (max 5)

Solution:
1. Request a new OTP first:
```http
POST /users/password/otp
{
    "email": "user@example.com"
}
```

2. Contact admin

### Password reset with MFA enabled
Common issues:
1. MFA code missing from request
2. Invalid MFA code
3. MFA device lost/inaccessible

Solution:
1. Include MFA code in reset request:
```http
POST /users/password/reset
{
    "email": "user@example.com",
    "new_password": "newSecurePass123!",
    "otp": "ABCDE",
    "mfa_code": "123456"    // Required if MFA enabled
}
```

2. If MFA device lost:
- Contact administrator for account recovery
- Admin can temporarily disable MFA
- New MFA setup required after reset

### Password reset after account lockout
Check:
1. Account status allows reset:
   - ok: allowed
   - locked_by_security: allowed
   - locked_by_admin: contact admin
2. No pending security investigations
3. Reset attempts within limits

Note:
- Successful reset moves status to "pending_approval"
- Admin approval needed to reactivate account
- All sessions invalidated after reset

## API Key Authentication Issues

### API key validation failing for internal services
Common causes:
1. Wrong API key format
2. API key not matching configuration
3. Missing mTLS certificate
4. Request not from allowed domain

Check:
1. API key header format:
```http
GET /validate
X-API-Key: your_api_key
```

2. Both API key and mTLS required:
```env
# Environment configuration
API_KEY=your_api_key
TLS_CA_PATH=/path/to/client/ca.crt
```

### Getting "Unauthorized" with valid API key
This happens when:
1. Missing or invalid client certificate
2. Wrong endpoint (API key only valid for /validate)
3. Request not using HTTPS
4. Domain mismatch

Solution:
1. Verify complete setup:
```bash
# Check certificate
openssl x509 -in client.crt -text -noout

# Test request
curl --cert client.crt --key client.key \
     -H "X-API-Key: your_api_key" \
     https://your.domain/validate
```

2. Ensure using correct endpoint:
- ✓ /validate (API key allowed)
- ✗ /users (API key not allowed)
- ✗ /sessions (API key not allowed)

### Session validation failing with API key
Common issues:
1. Invalid session ID format
2. Expired or revoked session
3. Missing required parameters

Correct request format:
```http
GET /validate?session_id=bccf1b28-fd...
X-API-Key: your_api_key
// Plus valid client certificate
```

Response indicates session status:
```json
{
    "data": {
        "valid": true/false
    }
}
```

## Frontend Integration Issues

### CORS errors when calling API
Common causes:
1. Origin not in CORS_ALLOW_ORIGINS
2. Using wrong protocol (http instead of https)
3. Missing credentials in request
4. Wrong request headers

Solution:
1. Check environment configuration:
```env
CORS_ALLOW_ORIGINS=https://app.domain.com,https://admin.domain.com
```

2. Configure frontend requests properly:
```javascript
fetch('https://api.domain.com/login', {
    method: 'POST',
    credentials: 'include',  // Required for cookies
    headers: {
        'Content-Type': 'application/json'
    }
})
```

### Session cookie not being set
Common issues:
1. Wrong cookie domain configuration
2. Missing credentials in request
3. Using HTTP in production
4. Browser blocking third-party cookies

Check:
1. Environment setup:
```env
DOMAIN_NAME=.domain.com  // Allows sharing between subdomains
```

2. Frontend configuration:
```javascript
// Axios configuration
axios.defaults.withCredentials = true

// Fetch configuration
credentials: 'include'
```

### Session not persisting after page refresh
Check:
1. Cookie settings correct:
   - Secure flag set
   - HTTP-only enabled
   - Correct domain
   - Path set to "/"

2. Frontend storage handling:
```javascript
// Don't store session ID in localStorage/sessionStorage
// Instead, rely on HTTP-only cookie

// Wrong
localStorage.setItem('session', sessionId)

// Correct - let the API handle session via cookies
fetch('/api/login', {
    credentials: 'include'
})
```

### Multiple tabs causing session conflicts
Issues when:
1. One tab logs out but others stay active
2. Session updates not reflected across tabs
3. Concurrent requests causing session invalidation

Solution:
```javascript
// Listen for storage events
window.addEventListener('storage', (e) => {
    if (e.key === 'logout') {
        // Redirect to login
        window.location.href = '/login'
    }
})

// When logging out
window.localStorage.setItem('logout', Date.now())
```

### MFA flow integration issues
Common problems:
1. Not handling MFA required response
2. Missing MFA setup flow
3. Incorrect error handling

Proper flow implementation:
```javascript
async function login(credentials) {
    try {
        const response = await fetch('/login', {
            method: 'POST',
            credentials: 'include',
            body: JSON.stringify(credentials)
        })
        
        const data = await response.json()
        
        if (response.status === 401 && data.error === 'MFA required') {
            // Redirect to MFA input
            return handleMFARequired()
        }
        
        if (!response.ok) {
            throw new Error(data.error.message)
        }
        
        return data
    } catch (error) {
        handleError(error)
    }
}
```

### Security headers blocking frontend features
Issues with:
1. Content Security Policy blocking scripts
2. X-Frame-Options preventing embedding
3. HSTS forcing HTTPS
4. Strict CSP breaking inline styles

Check response headers:
```http
Content-Security-Policy: default-src 'self'
X-Frame-Options: DENY
Strict-Transport-Security: max-age=31536000
X-Content-Type-Options: nosniff
```

Adjust frontend code to comply:
- Move inline scripts to files
- Host all resources on allowed domains
- Use proper HTTPS everywhere
- Remove inline styles

## Service-to-Service Integration Issues

### Session validation chain failing
Scenario: Frontend → Service A → Auth API → Service A → Frontend

Common issues:
1. Session token not properly forwarded
2. mTLS certificates missing between services
3. Timeouts in validation chain

Solution:
1. Proper header forwarding:
```pseudo
// Service A handling frontend request
function handleRequest(request):
    session_id = request.headers.get("Authorization")
    
    // Validate with Auth API
    auth_response = send_request(
        url: "auth.domain/validate",
        method: "GET",
        headers: {
            "X-API-Key": ENV["API_KEY"]
        },
        params: {
            "session_id": session_id
        },
        certificates: {
            client_cert: "service.crt",
            client_key: "service.key",
            ca_cert: "ca.crt"
        }
    )
    
    if not auth_response.is_valid:
        return error("Unauthorized", code: 401)
```

2. Configure proper timeouts:
```pseudo
// Service configuration
AUTH_TIMEOUT = 5  // seconds
CACHE_TTL = 60   // seconds

// Optional caching setup
cache = new Cache()
cache.set_ttl(CACHE_TTL)
```

### Service discovery and validation
Issues:
1. Auth service endpoint changes
2. DNS resolution problems
3. Load balancer health checks failing
4. Multiple validation attempts needed

Solution:
```pseudo
class AuthClient:
    endpoints: List<string>
    
    function validate_with_failover(session):
        for endpoint in endpoints:
            try:
                return validate(endpoint, session)
            catch Error:
                continue
        throw Error("All validation attempts failed")
    
    function validate(endpoint, session):
        response = send_request(
            url: endpoint + "/validate",
            params: {"session_id": session},
            headers: {"X-API-Key": ENV["API_KEY"]},
            certificates: {
                client_cert: "service.crt",
                client_key: "service.key",
                ca_cert: "ca.crt"
            },
            timeout: 5
        )
        return response.is_success
```

Service registration:
```yaml
# Consul service registration
service:
  name: auth-service
  health_check:
    path: /health
    interval: 10s
    timeout: 5s
```

### Circular service dependencies
Scenario: Service A → Service B → Service C → Service A

Issues:
1. Deadlocks in session validation
2. Request timeouts
3. Infinite validation loops

Prevention:
1. Implement validation caching:
```pseudo
class ValidationCache:
    valid: boolean
    expires_at: timestamp

class SessionValidator:
    cache: Map<string, ValidationCache>
    
    function validate_session(session_id):
        if cache.has(session_id) and not cache.is_expired(session_id):
            return cache.get(session_id).valid
            
        valid = validate_with_auth_service(session_id)
        cache.set(session_id, {
            valid: valid,
            expires_at: now() + CACHE_TTL
        })
        return valid
```

2. Use request tracing:
```pseudo
// Add to each request
request.headers["X-Request-ID"] = generate_uuid()
request.headers["X-Trace-Path"] = append_service(current_path)

function append_service(path):
    if path is empty:
        return "service-a"
    return path + ",service-a"
```

### Service mesh session handling
Common problems:
1. Session validation at every service hop
2. Inconsistent session state across services
3. High latency due to multiple validations

Best practices:
1. Validate at edge:
```pseudo
// API Gateway configuration
routes = {
    "/api/resource": {
        validate_at_edge: true,
        services: [
            {name: "auth-service", validate: true},
            {name: "business-service", validate: false}
        ]
    }
}
```

2. Use shared validation cache:
```pseudo
// Shared cache configuration
CACHE_CONFIG = {
    type: "redis",
    url: "redis://cache.internal:6379",
    ttl: 300  // 5 minutes
}
```

### Cross-service authentication failures
Issues when:
1. Different domains for each service
2. Certificate mismatches
3. Clock skew between services

Solution:
1. Proper certificate configuration:
```env
# Each service needs
TLS_CA_PATH=/path/to/shared/ca.crt
TLS_CERT_PATH=/path/to/service.crt
TLS_KEY_PATH=/path/to/service.key
DOMAIN_NAME=.internal.domain
```

2. Time synchronization:
```bash
# All services should use NTP
ntpd -q pool.ntp.org
```

### High-availability setup issues
Problems in distributed setups:
1. Session valid in one region, invalid in another
2. Replication lag causing validation inconsistencies
3. Split-brain scenarios

Configuration:
```env
# Auth service HA setup
REDIS_CLUSTER_ENABLED=true
REDIS_CLUSTER_NODES=redis-1:6379,redis-2:6379
REPLICATION_LAG_THRESHOLD=2s
```
