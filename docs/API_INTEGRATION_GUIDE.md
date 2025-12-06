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
- Admin status is determined by the `ADMIN_USERS_JSON` configuration and admins are automatically craeted. You cannot create admins via API.
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
- MFA code is required at login only if `mfa_enabled=true` (user has MFA set up)
- If MFA is enforced (`mfa_enforced=true`) but not set up (`mfa_enabled=false`):
  1. Login succeeds without MFA code
  2. User must complete MFA setup before accessing other endpoints
  3. All endpoints except `/users/mfa/setup`, `/users/mfa/verify`, `/users/me`, `/logout` return 403
- Session tokens are delivered two ways:
  - As HTTP-only cookie for browser-based apps
  - In response body for API clients
- Rate limited to 5 attempts per minute
- Users with `locked_by_admin` or `locked_by_security` status cannot log in

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

#### Understanding MFA States

| Field | Meaning |
|-------|---------|
| `mfa_enforced` | User MUST have MFA - cannot disable it |
| `mfa_enabled` | User HAS MFA set up and active |

**Important:** These are independent states:
- `mfa_enforced=true, mfa_enabled=false` → User must set up MFA before accessing endpoints
- `mfa_enforced=true, mfa_enabled=true` → MFA active and cannot be disabled
- `mfa_enforced=false, mfa_enabled=true` → MFA active but user can disable it
- `mfa_enforced=false, mfa_enabled=false` → No MFA

**Note:** Removing MFA enforcement does NOT disable MFA. It only allows the user to disable it themselves.

#### A. Setting Up MFA
Required when:
- User chooses to enable MFA
- Admin enforces MFA for user
- Global MFA enforcement is enabled (`ENFORCE_MFA=true`)

1. Initialize setup:
```http
POST /users/mfa/setup
Authorization: Bearer 54492786-1c...
Content-Type: application/json

{}
```

Success Response:
```json
{
    "data": {
        "secret": "JBSWY3DPEHPK3PXP",
        "qr_code_url": "data:image/png;base64,..."
    }
}
```

The `qr_code_url` is a base64-encoded PNG image that can be displayed directly in an `<img>` tag.

2. Verify and enable:
```http
POST /users/mfa/verify
Authorization: Bearer bccf1b28-fd...
{
    "code": "123456"
}
```

Important Notes:
- Setup must be completed within 5 minutes (temp secret TTL)
- If MFA is enforced but not set up:
  - Login succeeds without MFA code
  - All endpoints except `/users/mfa/setup`, `/users/mfa/verify`, `/users/me`, and `/logout` return 403
  - User must complete MFA setup to access other endpoints
- QR code is generated server-side using the TOTP library (no external services)

#### B. Disabling MFA
```http
POST /users/mfa/disable
Authorization: Bearer bccf1b28-fd...
{
    "mfa_code": "123456"
}
```

Notes:
- Cannot disable if MFA is enforced (`mfa_enforced=true`)
- Requires valid MFA code verification
- MFA secret is cleared from the user record

### 5. Permission and Group Management

#### A. Overview
The API uses a permission and group structure with permission visibility:
- The permissions and groups systems are stored in SQLite database (`data/permissions.db`)
- Permissions are individual access rights
- Groups are for easier organization of admins - the users they are responsible of
- **Permission Visibility**: Permissions are visible to specific groups via the `permission_visibility` table
- Admins can ONLY manage users who share at least one group with them (no exceptions)
- Only superusers can assign initial groups to users who have no groups yet
- Superusers have access to all groups and permissions (exempt from visibility checks)

**Permission Visibility Rules:**
- Users only see permissions visible to at least one of their groups in GET endpoints
- Users can only request permissions visible to their groups
- Admins can only approve/grant permissions visible to their groups
- Superusers see and can manage all permissions regardless of visibility

#### B. Permissions
Permissions are stored in SQLite database with the following structure:

**Database Schema:**
- `permissions` table: `id` (INTEGER PRIMARY KEY), `name` (TEXT UNIQUE), `definition` (TEXT)
- `groups` table: `id` (INTEGER PRIMARY KEY), `name` (TEXT UNIQUE), `definition` (TEXT)
- `permission_visibility` table: `permission_id` (INTEGER), `group_id` (INTEGER), PRIMARY KEY (permission_id, group_id)

**Permission Visibility:**
- A permission is visible to a group if there's an entry in `permission_visibility` linking them
- If a permission has no visibility mappings, it's not visible to any regular users (only superusers can see it)
- Users with multiple groups see the union of all permissions visible to any of their groups

**Sample Data:**
The system initializes with sample permissions, groups, and visibility mappings on first run. The database is created at `data/permissions.db` with memory-mapped I/O enabled for performance.

**Permission Characteristics:**
- Each permission has a unique identifier (name)
- Contains a human-readable name and definition (description)
- Is stored as a boolean (enabled/disabled) for each user
- Visibility is controlled by the `permission_visibility` table
- If the permissions system fails to initialize, permission-related operations will return "permissions system not loaded"
- Superuser operations remain unaffected by permissions system state

#### C. Groups
Groups are stored in SQLite database:

**Group Characteristics:**
- Each group has a unique identifier (name)
- Contains a display name and definition (description)
- Users can belong to multiple groups
- Admins can only manage users in their shared groups
- If the groups system fails to initialize, all group-related operations will return "groups system not loaded"
- Superuser operations remain unaffected by groups system state

#### D. Permission Management

1. Viewing User Permissions:
```http
GET /users/me
Authorization: Bearer bccf1b28-fd...
```

Response includes permissions and groups (filtered by visibility):
```json
{
    "data": {
        "permissions": {
            "a_permission": true,
            "another_permission": false
        },
        "groups": {
            "x": true,
            "y": false
        }
    }
}
```

**Important Notes:**
- Regular users only see permissions visible to at least one of their groups
- Admins see the user's permissions, but filtered to only show permissions visible to the admin's groups
- Superusers see all permissions regardless of visibility
- In case of disabled group-permission system, Permissions and Groups will return as empty

2. Listing Available Permissions:
```http
GET /permissions
Authorization: Bearer bccf1b28-fd...
```

**Response Behavior:**
- Regular users: Only see permissions visible to their groups
- Admins: Only see permissions visible to their groups (same as regular users)
- Superusers: See all permissions

Response example:
```json
{
    "data": [
        {
            "key": "a_permission",
            "name": "A Permission",
            "description": "Ability to perform A actions"
        },
        {
            "key": "another_permission",
            "name": "Another permission",
            "description": "Ability to perform something"
        }
    ]
}
```

3. Requesting Permission Changes:
```http
POST /users/request-update-from-admin
Authorization: Bearer 572a399c-6c...
{
    "updates": {
        "permissions_add": ["a_permission", "another_permission"],
        "permissions_remove": ["old_permission"],
        "groups_add": ["x", "y"],
        "groups_remove": ["z"]
    }
}
```

**Request Format:**
- `permissions_add`: Array of permission names to add
- `permissions_remove`: Array of permission names to remove
- `groups_add`: Array of group names to add
- `groups_remove`: Array of group names to remove
- At least one of these arrays must be non-empty

**Visibility Restrictions:**
- Users can only request permissions visible to at least one of their groups
- If a user tries to request a permission not visible to their groups, the request will fail with an error
- Users can only remove permissions they currently have

**Note:** The system uses explicit add/remove lists to clearly indicate what changes are being requested. This makes it easier for admins to understand what will be added vs removed when reviewing pending update requests.

4. Admin Approving Changes (requires admin access):
```http
PUT /users/{user_id}
Authorization: Bearer 572a399c-6c...
{
    "approve_update": true
}
```

**Approval Behavior:**
- When approving, the system applies the explicit add/remove lists from the pending update request
- **Safeguards:**
  - Cannot approve requests that would remove all permissions (at least one permission must remain)
  - Cannot approve requests that would remove all groups (at least one group must remain)
  - Admins can only approve adding groups they are members of (returns error if attempting to add groups they're not in)
  - **Admins can only approve adding permissions visible to their groups** (returns error if attempting to approve permissions they cannot see)
- **Error Responses:**

When admin tries to approve adding groups they're not in:
```json
{
    "error": {
        "message": "cannot approve adding groups you are not a member of: 'GroupX', 'GroupY'"
    }
}
```
Status Code: `401 Unauthorized`

When admin tries to approve adding permissions they cannot see:
```json
{
    "error": {
        "message": "invalid permission requested: permission_name"
    }
}
```
Status Code: `401 Unauthorized`

**Rejecting Changes:**
```http
PUT /users/{user_id}
Authorization: Bearer 572a399c-6c...
{
    "reject_update": true
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

#### E. Admin Management

Admins are provisioned from secrets (no public signup):
- `ADMIN_USERS_JSON` is a JSON object of email→password (e.g., `{"admin1@example.com":"Pass1!","admin2@example.com":"Pass2!"}`).
- Admin accounts are auto-created/updated at startup and on secret hot-reload (password rotations apply immediately).
- Public `/users` creation for admin emails is blocked.
- Existing admin permissions/groups are preserved on refresh; only credentials/status/MFA flags are updated.
- New admins start with **no groups**. Initial group assignments can only be done by Superuser.

**Group-Based Access Control:**

Admins can only manage users who **already share at least one group** with them. They may add a group only if they themselves are in that group, and they may remove any groups once that shared-group requirement is met:

| Admin Groups | Target User Groups | Can Admin Modify Permissions? | Can Admin Modify Groups? |
|--------------|-------------------|-------------------------------|--------------------------|
| `[]` | `[A]` | ❌ No | ❌ No shared groups |
| `[A]` | `[A]` | ✅ Yes | ✅ Can remove A, cannot add any |
| `[A]` | `[A, B]` | ✅ Yes | ✅ Can remove A and B, cannot add any |
| `[A, B]` | `[A]` | ✅ Yes | ✅ Can add B, can remove A |
| `[A]` | `[B]` | ❌ No | ❌ No shared groups |
| `[A]` | `[]` (none) | ❌ No | ❌ No shared groups |

**Key rules:**
1. Admins can ONLY view and manage users who already share at least one group with them
2. Admins can add users to additional groups, but only groups the admin is already in
3. Admins cannot "claim" users by adding them to their groups if they don't already share a group beforehand
4. Only superusers can assign initial groups to users with no groups
5. Group membership is for organization (you can use it to form roles, permission inheritance etc. on your frontend)
6. Permission operations are blocked when permissions system is disabled

**When groups system is disabled:**
- Admins can manage all users (no group restrictions apply)
- This simplifies admin management when group-based delegation is not needed

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
                        "permissions_add": ["another_permission"],
                        "permissions_remove": ["old_permission"],
                        "groups_add": ["y"],
                        "groups_remove": ["z"]
                    }
                }
            }
        ]
    }
}
```

#### F. Superuser Management

Superuser is provisioned from secrets only (no public signup):
- `SUPERUSER_EMAIL` and `SUPERUSER_PASSWORD` come from secrets.
- The superuser is auto-created/updated at startup and on secret hot reload (password rotations apply immediately).
- Public `/users` creation for the superuser email is blocked.
- To rotate the superuser, update secrets; the app refreshes without restart.


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
- Shows pending update requests (filtered for admins - only shows groups they can approve)
- **Permission Visibility Filtering:**
  - Regular users: Only see permissions visible to their groups in their own data
  - Admins: See user's permissions, but filtered to only show permissions visible to the admin's groups
  - Superusers: See all permissions for all users

2. Update user:
```http
PUT /users/{user_id}
Authorization: Bearer 572a399c-6c...
{
    "status": "ok",
    "mfa_enforced": true,
    "permissions": {"a_permission": true},
    "groups": {"x": true},
    "approve_update": true  // For pending updates
}
```

Important Notes:
- Cannot modify superuser account
- Admin can ONLY modify users who share at least one group with them
- Only superusers can assign initial groups to users with no groups
- When enforcing MFA:
  - User must set up MFA before next login
  - User cannot disable MFA afterwards
- Status changes to "locked" revoke all sessions
- **Approval Restrictions:**
  - Admins can only approve adding groups they are members of
  - Admins can only approve adding permissions visible to their groups
  - If a pending update request includes groups the admin is not in, approval will fail with an error listing those groups
  - If a pending update request includes permissions the admin cannot see, approval will fail with an error
  - Admins can remove any groups (including the last shared group - this will revoke their access to manage that user)
  - Cannot approve requests that would remove all permissions or all groups
- **Direct Permission Updates:**
  - Admins can only grant permissions visible to their groups when using direct updates (not via approval)
  - Superusers can grant any permissions

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
GET    /permissions          # List available permissions
GET    /groups               # List available groups
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
- pending_approval: After registration (for non-admin users) or password reset
- ok: Normal active state
- locked_by_admin: Manually locked by admin
- locked_by_security: Automatically locked due to suspicious activity

Important Notes:
- Only admins/superusers can change user states
- Locked states prevent login (but password reset via OTP is still possible)
- State changes to "locked" automatically revoke all sessions
- Password reset always sets state to "pending_approval"
- Requesting permission/group updates does NOT change user status (the request is tracked separately in pending_updates field)

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
- Login is blocked until admin unlocks the account
- Password reset flow via OTP still works (but sets status to "pending_approval" after reset)
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
The service requires a valid SMTP server configuration for sending password reset emails (OTP). Configure the following secrets in Vault (or in `dev.secrets` for development):

| Secret Path | Description |
|-------------|-------------|
| `secret/garde/smtp_host` | SMTP server hostname (e.g., `smtp.gmail.com`) |
| `secret/garde/smtp_port` | SMTP server port (e.g., `587`) |
| `secret/garde/smtp_user` | SMTP authentication username |
| `secret/garde/smtp_password` | SMTP authentication password |
| `secret/garde/smtp_from` | Sender email address |

These are written to `/run/secrets/` by Vault Agent and read by the application.
