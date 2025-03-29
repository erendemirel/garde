# API Integration Guide

This guide explains how to integrate and use garde in your applications.

## Authentication Methods

### 1. Browser-based Authentication
For web applications where users log in through a browser interface.

**Flow:**
1. User submits credentials
2. Receives HTTP-only secure cookie with session ID
3. Cookie is automatically sent with subsequent requests

Example login request:
```json
POST /login
{
    "email": "user@example.com",
    "password": "userPassword123!",
    "mfa_code": "123456"  // Required if MFA is enabled
}
```

Success Response:
```json
{
    "success": true,
    "data": {
        "session_id": "cd374181-b8..."  // Also set in HTTP-only cookie
    }
}
```

Error Response:
```json
{
    "error": {
        "message": "Invalid credentials"
    }
}
```

### 2. API Authentication
For applications making API calls (mobile apps, SPAs, etc.).

**Flow:**
1. Login to get session token
2. Include token in Authorization header

Example:
```http
POST /login
Content-Type: application/json

{
    "email": "user@example.com",
    "password": "userPassword123!"
}
```

Success Response:
```json
{
    "data": {
        "session_id": "02dec731-ce..."
    }
}
```

Error Response:
```json
{
    "error": {
        "message": "Invalid credentials"
    }
}
```

Use the session token in subsequent requests:
```http
GET /api/resource
Authorization: Bearer 6cc0595f-f3...
```

### 3. Internal Service Authentication (mTLS + API Key)
For internal services communicating within your infrastructure.

**Requirements:**
- Valid client certificate from your CA
- API key from configuration
- Must use the same domain as the auth service

Example request:
```http
GET /validate?session_id=8e8217f1-4f...
X-API-Key: your_api_key
// TLS client certificate included in request
```

Success Response:
```json
{
    "data": {
        "valid": true
    }
}
```

Error Response:
```json
{
    "error": {
        "message": "Unauthorized"
    }
}
```

**Important Note:** The `/validate` endpoint is only accessible via API key + mTLS authentication. Admin authentication is not supported for this endpoint.

## Common Workflows

### 1. User Registration and Account Management

#### Initial Registration
```http
POST /users
Content-Type: application/json

{
    "email": "user@example.com",
    "password": "securePass123!"
}
```

Success Response:
```json
{
    "data": {
        "user_id": "usr_xyz..."
    }
}
```

Error Response:
```json
{
    "error": {
        "message": "Email already exists"
    }
}
```

Important Notes:
- User status starts as "pending_approval" until approved by admin
- If email matches ADMIN_USERS list in .env, user gets admin privileges automatically
- Password must meet complexity requirements (min 8 chars, max 64 chars, at least one uppercase, lowercase, number, and special char)

#### View Current User Info
```http
GET /users/me
Authorization: Bearer 6cc0595f-f3...
```

Success Response:
```json
{
    "data": {
        "id": "usr_xyz...",
        "email": "user@example.com",
        "last_login": "2024-03-14T12:00:00Z",
        "created_at": "2024-03-14T12:00:00Z",
        "updated_at": "2024-03-14T12:00:00Z",
        "mfa_enabled": true,
        "mfa_enforced": false,
        "status": "ok",
        "permissions": {
            "a_permission": true,
            "another_permission": false
        },
        "user_groups": ["group1", "group2"]
    }
}
```

Error Response:
```json
{
    "error": {
        "message": "Unauthorized"
    }
}
```

### 2. Authentication Flows

#### Regular Login
```http
POST /login
{
    "email": "user@example.com",
    "password": "securePass123!",
    "mfa_code": "123456"  // Required if MFA enabled
}
```

Important Notes:
- If MFA is enforced but not set up:
  1. Initial login will succeed
  2. User must complete MFA setup before accessing other endpoints
  3. All endpoints except MFA setup will return 401
- Session tokens are delivered two ways:
  - As HTTP-only cookie for browser-based apps
  - In response body for API clients
- Rate limited to 5 attempts per minute

#### Logout
```http
POST /logout
Authorization: Bearer 54492786-1c...
```

Notes:
- Invalidates current session
- Clears session cookie if present
- Cleans up all security records

### 3. Password Management

#### A. Change Password (When Logged In)
```http
POST /users/password/change
Authorization: Bearer 54492786-1c...
{
    "old_password": "currentPass123!",
    "new_password": "newPass123!",
    "mfa_code": "123456"  // Required if MFA enabled
}
```

Notes:
- All active sessions are revoked
- Requires current password verification
- MFA verification if enabled
- New password must meet complexity requirements

#### B. Password Reset Flow (When Locked Out)

1. Request OTP:
```http
POST /users/password/otp
{
    "email": "user@example.com"
}
```

2. Receive 5-letter OTP via email (expires in 5 minutes)

3. Reset password:
```http
POST /users/password/reset
{
    "email": "user@example.com",
    "otp": "ABCDE",          // From email
    "new_password": "newPass123!",
    "mfa_code": "123456"     // Required if MFA enabled
}
```

Success Response:
```json
{
    "data": "Password reset successful. Waiting for admin approval."
}
```

Error Response:
```json
{
    "error": {
        "message": "Invalid OTP"
    }
}
```

Important Notes:
- Process requires OTP
- MFA code required if enabled
- Account gets locked after 5 failed attempts
- Password reset sets status to "pending_approval"
- Rate limited to 3 attempts per 5 minutes
- Cannot reset superuser password through this flow

### 4. MFA Management

#### A. Setting Up MFA
Required when:
- User chooses to enable MFA
- Admin enforces MFA for user
- Global MFA enforcement is enabled

1. Initialize setup:
```http
POST /users/mfa/setup
Authorization: Bearer 54492786-1c...
```

Success Response:
```json
{
    "data": {
        "qr_code_url": "otpauth://..."  // Scan with authenticator app
    }
}
```

Error Response:
```json
{
    "error": {
        "message": "MFA setup failed"
    }
}
```

2. Verify and enable:
```http
POST /users/mfa/verify
Authorization: Bearer bccf1b28-fd...
{
    "code": "123456"  // Code from authenticator app
}
```

Important Notes:
- Setup must be completed within 10 minutes
- If MFA is enforced (either globally or by admin):
  - User cannot access other endpoints until MFA setup is complete
  - MFA cannot be disabled later
- Store backup codes securely (if implementing backup code system)

#### B. Disabling MFA
```http
POST /users/mfa/disable
Authorization: Bearer bccf1b28-fd...
{
    "mfa_code": "123456"
}
```

Notes:
- Cannot disable if MFA is enforced
- Requires valid MFA code verification
- Consider warning users about security implications

### 5. Permission and Group Management

#### A. Overview
The API uses a permission and group structure:
- The permissions and groups systems are optional and can be disabled
- Permissions are individual access rights
- Groups are for easier organization of admins - the users they are responsible of
- Admins can only manage users within their groups, except for when adding those users to their group for the first time, in this case groups doesn't matter, meaning if an admin wants to manage a user, they first need to add the user to their own group
- Superusers have access to all groups and permissions

#### B. Permissions
Permissions are defined in `configs/permissions.json`:

```json
{
    "a_permission": {
        "name": "A Permission",
        "description": "Ability to perform A actions",
        "groups": ["x", "z"]
    },
    "another_permission": {
        "name": "Another permission",
        "description": "Ability to perform something",
        "groups": ["y"]
    },
    "permission_b": {
        "name": "Permission B",
        "description": "Users who have this permission can perform B",
        "groups": []  // Empty array for no group associations
    },
    "some_permission": {
        "name": "Some Permission",
        "description": "To allow something"
        // groups field can be omitted entirely
    }
}
```

Each permission:
- Has a unique identifier (e.g., "a_permission")
- Contains a human-readable name and description
- Can be associated with specific groups (optional)
- Is stored as a boolean (enabled/disabled) for each user
- If permissions.json is missing or empty, the permissions system will be disabled
- When disabled, only permission-related operations (currently: updating the permissions of a user with an admin user) will return "permissions system not loaded"
- Admin operations not involving permissions remain available
- Superuser operations remain unaffected by permissions system state

When writing permissions.json:
1. Permission names (keys):
   - Must be unique
   - Use lowercase with underscores
   - Should be descriptive but concise
   - Avoid special characters except underscore

2. Required fields:
   - "name": Human-readable display name
   - "description": Clear explanation of the permission
   - "groups": Optional array of group IDs (can be empty [] or omitted)


#### C. Groups
Groups are defined in `configs/groups.json`:

```json
{
    "x": {
        "name": "X Group",
        "description": "Users of group x"
    },
    "y": {
        "name": "Y Role",
        "description": "y role"
    },
    "z": {
        "name": "Z Users",
        "description": "z users"
    }
}
```

Group characteristics:
- Each group has a unique identifier
- Contains a display name and description
- Users can belong to multiple groups
- Admins can only manage users in their shared groups
- If groups.json is missing or empty, the groups system will be disabled
- When disabled, all group-related operations (currently: admin user operations) will return "groups system not loaded"
- Superuser operations remain unaffected by groups system state

When writing groups.json:
1. Group names (keys):
   - Must be unique
   - Avoid special characters

2. Required fields:
   - "name": Human-readable display name
   - "description": Clear explanation of the group's purpose

3. Important considerations:
   - Groups referenced in permissions.json must exist in groups.json
   - Changes to group IDs might require updates to permissions.json, if you included any group names in the permissions file
   - Consider future scalability when designing group structure

#### D. Permission Management

1. Viewing User Permissions:
```http
GET /users/me
Authorization: Bearer bccf1b28-fd...
```

Response includes permissions and groups:
```json
{
    "data": {
        "permissions": {
            "a_permission": true,
            "another_permission": false
        },
        "user_groups": {
            "x": true,
            "y": false
        }
    }
}
```

In case of disabled group-permission system, Permissions and Groups will return as empty

2. Requesting Permission Changes:
```http
POST /users/request-update-from-admin
Authorization: Bearer 572a399c-6c...
{
    "updates": {
        "permissions": {
            "a_permission": true
        },
        "groups": {
            "x": true
        }
    }
}
```

3. Admin Approving Changes (requires admin access):
```http
PUT /users/{user_id}
Authorization: Bearer 572a399c-6c...
{
    "approve_update": true,
    "security_code": "admin_security_code"
}
```

Error responses when permissions system is disabled:
```json
{
    "error": {
        "message": "permissions system not loaded"
    }
}
```

- When groups system is disabled:
```json
{
    "error": {
        "message": "groups system not loaded"
    }
}
```

#### E. Admin Group Management

Important rules for admins:
1. Admins can only view and manage users in their groups (except the first time they try to add a user to their own group)
2. Admins cannot modify users with no shared groups (except the first time they try to add a user to their own group)
3. Group membership is just for organization. (But on your frontend, you can make use of it to form roles, permission inheritance etc.)
4. Superusers can manage all groups and permissions
5. Admin operations are blocked when groups system is disabled
6. Permission operations are blocked when permissions system is disabled

Example admin listing users in their groups:
```http
GET /users
Authorization: Bearer 572a399c-6c...
```

Response shows only users in shared groups:
```json
{
    "data": {
        "users": [
            {
                "id": "usr_123",
                "email": "user@example.com",
                "permissions": {
                    "a_permission": true
                },
                "user_groups": {
                    "x": true
                },
                "pending_updates": {
                    "requested_at": "2024-03-14T12:00:00Z",
                    "fields": {
                        "permissions": {
                            "another_permission": true
                        }
                    }
                }
            }
        ]
    }
}
```

### 6. Admin Operations
All admin operations require:
- Admin or superuser credentials
- Valid session token

#### A. User Management
1. List users:
```http
GET /users
Authorization: Bearer 572a399c-6c...
```

Notes:
- Admins see only users in their groups
- Superuser sees all users
- Shows pending update requests

2. Update user:
```http
PUT /users/{user_id}
Authorization: Bearer 572a399c-6c...
{
    "email": "new@example.com",
    "status": "ok",
    "mfa_enforced": true,
    "approve_update": true  // For pending updates
}
```

Important Notes:
- Cannot modify superuser account
- Admin can only modify users in their groups (except for the time they add a user to their group)
- When enforcing MFA:
  - User must set up MFA before next login
  - User cannot disable MFA afterwards
- Status changes to "locked" revoke all sessions

3. Revoke sessions:
```http
POST /sessions/revoke
Authorization: Bearer 572a399c-6c...
{
    "user_id": "usr_xyz..."
}
```

Notes:
- Immediately invalidates all active sessions
- Blacklists sessions for security
- Useful for suspicious activity response

#### B. Session Validation
For internal services to validate sessions of other applications.

```http
GET /validate?session_id=2e8aa13e-3c...
X-API-Key: your_api_key
// Requires mTLS
```

Response:
```json
{
    "success": true,
    "data": {
        "valid": true
    }
}
```

Notes:
- Requires both API key and mTLS
- Used by internal services to verify sessions
- Returns simple valid/invalid response
- Can validate any session, not just own sessions
- This endpoint can ONLY be accessed using API key + mTLS authentication

#### C. User Details
Get detailed information about specific users:

```http
GET /users/{user_id}
Authorization: Bearer 572a399c-6c...
```

Notes:
- Returns full user details including pending updates
- Admin can only access users in their groups
- Superuser can access any user

### 7. Authentication Requirements

#### Endpoints Requiring Authentication
These endpoints require a valid session token:
```
GET    /users/me              # Get current user info
POST   /logout               # Logout current session
POST   /users/mfa/disable    # Disable MFA
POST   /users/password/change # Change password
POST   /users/request-update-from-admin # Request permission/group update
```

#### Endpoints Not Requiring Authentication
These endpoints are accessible without a session:
```
POST   /login                # Login
POST   /users                # Create new user
POST   /users/password/otp   # Request password reset OTP
POST   /users/password/reset # Reset password with OTP
```

#### Admin-Only Endpoints
These require both authentication and admin privileges:
```
GET    /users                # List users
GET    /users/{id}           # Get specific user
PUT    /users/{id}           # Update user
POST   /sessions/revoke      # Revoke user sessions
```

#### Special Case: MFA Setup Endpoints
The MFA setup endpoints have conditional authentication requirements:

```
POST   /users/mfa/setup      # Requires auth UNLESS MFA is enforced but not set up
POST   /users/mfa/verify     # Requires auth UNLESS MFA is enforced but not set up
```

When MFA is enforced (either globally or by admin) but not yet set up:
1. User must be in "ok" status
2. User can log in once without MFA
3. User can access MFA setup endpoints without authentication
4. All other endpoints will return 401 until MFA is set up

In all other cases, these endpoints require authentication.

### 8. Response Status Codes and Headers

#### Status Codes
- 200: Successful operation
- 201: Resource created (new user registration)
- 400: Invalid request format or validation failed
- 401: Unauthorized (invalid/expired session)
- 403: Forbidden (insufficient permissions)
- 404: Resource not found
- 429: Too many requests (rate limit exceeded)
- 500: Server error

#### Required Headers

For authenticated requests:
```http
Authorization: Bearer 572a399c-6c...
Content-Type: application/json
```

For internal service requests:
```http
X-API-Key: your_api_key
Content-Type: application/json
// Plus valid client certificate
```

### 9. Rate Limiting

Different endpoints have different rate limits:
- Login: 5 attempts per minute
- Password reset: 3 attempts per 5 minutes
- Other endpoints: 60 requests per minute

When rate limit is exceeded:
- Returns 429 status code
- Includes Retry-After header
- May trigger security measures on repeated violations

### 10. Account States and Transitions

Users can be in following states:
- pending_approval: After registration or password reset
- ok: Normal active state
- locked_by_admin: Manually locked by admin
- locked_by_security: Automatically locked due to suspicious activity

Important Notes:
- Only admins can change user states
- Locked states prevent all access except password reset
- State changes to "locked" automatically revoke all sessions
- Password reset always sets state to "pending_approval"

### 11. Security Event Responses

#### Suspicious Activity Detection
The API automatically detects:
- Multiple failed login attempts
- Rapid requests from same IP
- Multiple IP sessions
- Unusual request patterns
- Session inactivity timeouts
- Multiple suspicious patterns that trigger session invalidation

System Responses:
- Rate limiting
- Session invalidation
- Account locking
- IP blocking

#### A. Session Termination Events
Sessions are immediately terminated when:
1. Suspicious activity is detected:
   - Multiple concurrent sessions from different IPs
   - Automated/bot-like behavior detected (when requests are < session.AutomatedRequestTimeout apart)
   - Unusual User-Agent patterns (containing bot/crawler identifiers or missing common browser strings)
   - Rapid requests exceeding threshold (>60 requests/minute)
2. Security status changes:
   - User account gets locked
   - Password is changed or reset
   - MFA settings are modified
3. Administrative actions:
   - Admin explicitly revokes sessions
   - User status is changed to any locked state

#### B. Account Locking Events
User accounts are automatically locked (status changes to "locked_by_security") when:
1. Password reset attempts exceed maximum (5 attempts)
2. Multiple failed login attempts (5 attempts per minute)
3. Multiple suspicious activity patterns are detected

When an account is locked:
- All active sessions are terminated
- User must contact administrator for unlock
- Password reset flow is disabled
- Account status changes to "locked_by_security"

#### C. IP Blocking
IPs are automatically blocked when:
1. Failed login attempts exceed threshold (5 attempts per minute)
2. Rate limit is repeatedly exceeded (>60 requests per minute)

When an IP is blocked:
- All requests return 429 (Too Many Requests)
- Includes Retry-After header
- Login attempts are rejected
- Block expires automatically after block duration

#### D. Session Blacklisting
Sessions are blacklisted (permanently invalidated) when:
1. Suspicious activity is detected during session
2. User explicitly logs out
3. Password is changed
4. Account status changes to locked
5. Admin revokes sessions
6. Session expires

When a session is blacklisted:
- Session ID is permanently invalidated
- Cannot be reactivated
- All requests with that session ID return 401
- User must log in again to get new session

#### E. Security Measures and Recovery
1. For locked accounts:
   - Only administrators can unlock
   - User must complete additional verification
   - Status changes to "pending_approval" after unlock

2. For blocked IPs:
   - Block expires automatically after 24 hours
   - Earlier unblock requires admin intervention
   - Multiple blocks may trigger permanent restriction

3. For blacklisted sessions:
   - No automatic recovery
   - User must authenticate again
   - New session ID is issued on successful login

4. Rate Limiting:
   - Rate limiting happens momentarily, recovery is N/A

## Email Management

### Email Configuration
The service requires a valid SMTP server configuration for sending password reset emails(OTP). Configure the following environment variables:

```env
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASSWORD=your-app-specific-password
SMTP_FROM=your-email@gmail.com
```
