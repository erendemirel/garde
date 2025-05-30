# garde

A lightweight yet secure authentication API. Uses Redis as primary database.

---

## Table of Contents

- [Features](#features)
- [Quick Start](#quick-start)
- [Endpoint Documentation](#endpoint-documentation)
- [Installation](#installation)
  - [Mandatory Steps](#mandatory-steps)
  - [Conditional or Optional Steps](#conditional-or-optional-steps)
- [Verifying Installation](#verifying-installation)
- [Example Configuration Files](#example-configuration-files)
- [Integration Guide](#integration-guide)
- [Security Mandates](#security-mandates)
- [Contributing](#contributing)

---

## Features

- Built-in security features 
  <details>
    <summary>Click here to expand built-in security features</summary>
  
      > Rate limiter
      > Rapid request detection
      > Automated behaviour detection
      > Multiple IP session detection
      > Session blacklisting mechanism
      > Request body size limiting
      > Request headers, query parameters, path parameters and body sanitization
      > mTLS for internal service communication
      > MFA
      > Only superuser and admins can use administrative endpoints
      > Regular users cannot update themselves or any other user. They can only request an update from an admin
      > HTTP security headers
      > Locking on too many failed login attempts

  > garde doesn't use "role"s or "permission group"s or "scope"s as these concepts cause paradoxes that lead to insecure implementations

   </details>

- Secure implementation 
  <details>
    <summary>Click here to expand secure implementation details</summary>
  
      > Hashed IP addresses and user agents for storage
      > Hiding implementation details from error responses during panic
      > No persistence functions that passes user inputs to the database
      > Validation checks for all user inputs
      > No descriptive error messages in responses, only logging internally
      > Session tokens never stored in plain text
      > Separate blacklist mechanism for revoked sessions
      > Automatic cleanup of expired security records
      > Rate limit information in response headers
      > Confusing responses to make it difficult for an attacker to guess whether a user exists when querying for a user by email

  </details>

- Session-based authentication with server side management using http-only cookies

- MFA

- Supports three types of authentication modes, browser-based authentication, API call-based authentication, API key-based authentication

- mTLS

- Minimal dependencies with simple configuration

---

## Quick Start

1. Download the source code

2. Set mandatory parameters in [`.env`](https://github.com/erendemirel/garde/blob/master/.env)

3. Run `docker compose --profile auth-service-with-redis up`

> [!NOTE]
> For endpoint documentation, see [endpoints](https://github.com/erendemirel/garde?tab=readme-ov-file#endpoint-documentation)<br>
> For detailed installation guide, see [installation](https://github.com/erendemirel/garde?tab=readme-ov-file#installation)<br>
> For integration guide, refer to [integration guide](https://github.com/erendemirel/garde/blob/master/docs/API_INTEGRATION_GUIDE.md)<br>
> For troubleshooting, refer to [troubleshooting guide](https://github.com/erendemirel/garde/blob/master/docs/TROUBLESHOOTING.md)

--- 

## Endpoint Documentation

See [endpoints](https://garde-api-docs.netlify.app)

> [!TIP]
> This documentation page will also be available at https://localhost:8443/swagger/index.html on your own API instance once the server starts (if you've set a different port and domain in your `.env` file, use those instead of localhost and 8443).

---

## Installation

### Mandatory Steps

---

#### 1. Download the source code

#### 2. Configure and start Redis
##### a. Using an external Redis instance (if you have your own Redis instance):

- Set in `.env`:
```ini
REDIS_HOST=your_redis_server_host
REDIS_PORT=your_redis_server_port
REDIS_PASSWORD=your_redis_server_password
REDIS_DB=redis_database_to_use  # Optional
```

##### b. Using the bundled Redis container (included in the project's docker-compose):

- Set in `.env`:
```ini
REDIS_PASSWORD=your_redis_server_password
REDIS_DB=redis_database_to_use  # Optional
```

#### 3. Configure domain name

- Set in `.env`:
```ini
DOMAIN_NAME=your_domain  # Can be any value if you are not going to use built-in TLS (See "Configure built-in TLS" section below for detailed information)
```

#### 4. Set superuser credentials
Set in `.env`:
```ini
SUPERUSER_EMAIL=email_of_superuser_account
SUPERUSER_PASSWORD=password_of_superuser_account   # Must meet password complexity and length(8-64) requirements
```

#### 5. Run the application

##### a. Without the project's docker-compose:

- Install [Go](https://go.dev/doc/install)
- Build and run the app:
```bash
go mod download
go build -o garde ./cmd
./garde
```
##### b. With the project's docker-compose:

- If you are going to use your own Redis instance (external Redis):
```bash
docker compose --profile auth-service-without-redis up
```
- If you are going to use the Redis container included in project's docker-compose (bundled Redis container):
```bash
docker compose --profile auth-service-with-redis up
```


### Conditional or Optional Steps

---

#### 1. Configure built-in TLS (Conditional)
Configure the application to use built-in TLS.

> [!IMPORTANT]  
> If you don't use built-in TLS, you cannot use mTLS and API-key authentication

- Gather your SSL certificates:

  - Valid TLS certificate from trusted CA (not self-signed)
  - Certificate chain must include intermediate certificates
  - SAN must include all domain variants (e.g., example.com, *.example.com)

- Set in `.env`:
```ini
USE_TLS=false  # Enable-disable built-in TLS-mTLS
TLS_CERT_PATH=path_to_your_server_cert
TLS_KEY_PATH=path_to_your_server_private_key
PORT=your_https_port  # Optional. The port the application will listen on. Default is 8443
```
#### 2. Configure mTLS and set API key (Conditional)
Required only if auth service will communicate with internal services.

> [!IMPORTANT]  
> Built-in TLS must be enabled for mTLS and API-key authentication to work

Set in `.env`:
```ini
TLS_CA_PATH=path_to_your_client_ca_cert  # Comma-separated paths for multiple CAs. You might have multiple client CA certificates for different services
API_KEY=your_api_key  # Must be at least 20 characters long and contain at least one uppercase letter, one lowercase letter, one number and one special character
```

#### 3. Configure Log Level (Optional)
Control the verbosity of application logs for troubleshooting and monitoring.

Set in `.env`:
```ini
LOG_LEVEL=INFO  # Values: DEBUG, INFO, WARN, ERROR (default is INFO)
```

> [!TIP]
> Available log levels are: DEBUG, INFO, WARN, ERROR

#### 4. Mail Server Configuration (Conditional)
Set configurations to be able to send mails. Resetting password functionality requires sending a mail.

> [!WARNING]  
> Without sending emails, garde cannot reset users' passwords

##### DNS Records Required
- MX record pointing to mail.your-domain.com
- SPF record: `v=spf1 mx -all`
- PTR (reverse DNS) record for your IP

Set in `.env`:
```ini
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASSWORD=your-app-specific-password
SMTP_FROM=your-email@gmail.com
```

#### 5. Permissions and Groups System (Conditional)

In addition to configurations stored in the `.env` file, there are also configurations for application and business logic. These include permissions and groups, defined in JSON files under the `/configs` directory: `permissions.json` and `groups.json`.

The permissions list defines all permissions that your authentication API instance will support, such as access to specific menus in your application dashboard or any other permission you'd like your users to have. If you want to use permissions, you must define them in this file.

The groups list helps organize users and admins. Admins can only manage users who share at least one group with them. Note that admins can edit users even when they're not initially in the same group, but only when adding those users to their group for the first time, meaning if an admin wants to manage a user, they first need to add that user to the their own group.

> [!NOTE]
> Superuser is exempt from permissions-groups logic

Both the permissions and groups systems are optional. 

> [!TIP]
> To disable either system, simply remove the corresponding file (`permissions.json` and/or `groups.json`) from your `/configs` directory. For more information, refer to the integration guide and review the sample JSON files in the `/configs` directory

##### Permissions
Set in `/configs/permissions.json`:
```json
{
    "permission_a": {
        "name": "Permission A",
        "description": "Ability to perform some action",
        "groups": ["x", "z"]  // must match the group names inside groups.json
    }
}
```

##### Groups
Set in `/configs/groups.json`:
```json
{
    "x": {
        "name": "X Group",
        "description": "Users of group x"
    }
}
```

#### 6. Other Configurations (Optional)
See [example .env file](https://github.com/erendemirel/garde/blob/master/.env) for full list of optional parameters:
```ini
GIN_MODE, CORS_ALLOW_ORIGINS, ENFORCE_MFA, ADMIN_USERS, RATE_LIMIT, DISABLE_RAPID_REQUEST_CHECK, DISABLE_USER_AGENT_CHECK, DISABLE_IP_BLACKLISTING, DISABLE_MULTIPLE_IP_CHECK
```

#### 7. Network Configuration (When required)
##### Required Ports
```ini
${PORT:-8443}  # HTTP(S) port (defaults to 8443 if PORT not set)
```

##### Reverse Proxy Setup
Configure Nginx/Apache to:
- Terminate TLS (if not using app's built-in TLS)
- Set `X-Forwarded-For` header
- Forward WebSocket connections

Example Nginx configuration:
```nginx
location / {
    proxy_pass https://localhost:8443;
    proxy_ssl_verify off;  # Only for self-signed certs
    proxy_set_header X-Real-IP $remote_addr;
}
```

##### Firewall Rules
- Allow inbound: Your auth API instance port
- Allow outbound: Redis (if using your own), mail server (if enabled)

> [!IMPORTANT]  
> A restart is needed for any changes to take effect

## Verifying Installation

Try a login:

```bash
curl -X POST https://your-domain/login -H "Content-Type: application/json" -d "{\"email\":\"your_superuser_email\",\"password\":\"your_superuser_password\"}"
```


## Example Configuration Files

- Secrets (required): [.env](https://github.com/erendemirel/garde/blob/master/.env)
- Permissions List (optional): [permissions.json](https://github.com/erendemirel/garde/blob/master/configs/permissions.json)
- Groups List (optional): [groups.json](https://github.com/erendemirel/garde/blob/master/configs/groups.json)

## Integration Guide

For more information on how garde works and how to integrate, see [integration guide](https://github.com/erendemirel/garde/blob/master/docs/API_INTEGRATION_GUIDE.md)

## Security Mandates

- Rotate these frequently:
  ```ini
  API_KEY
  ```
- Rotate these often:
  ```ini
  REDIS_PASSWORD
  SUPERUSER_PASSWORD
  ```
- Enable HSTS with preload directive in production
- Configure TLS on the firewall if not using the in-built one
- Place a proxy server in front of your Redis (if you are using the in-built one, place in front of "redis_network" Docker network)
- Set `RATE_LIMIT` to at least `60` in `.env` in production
- Do not set `DISABLE_RAPID_REQUEST_CHECK` to `true` in `.env` in production
- Do not set `DISABLE_USER_AGENT_CHECK` to `true` in `.env` in production
- Do not set `DISABLE_IP_BLACKLISTING` to `true` in `.env` in production
- Do not set `DISABLE_MULTIPLE_IP_CHECK` to `true` in `.env` in production
- Set `ENFORCE_MFA=true` in `.env` in production
- Use separate CA certificates for different client groups
- Rotate certificates at least once a year


## Contributing

See [contribution guide](https://github.com/erendemirel/garde/blob/master/docs/CONTRIBUTING.md)



