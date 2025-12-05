# Contributing

## Contribution Methods

There are two main ways to contribute to this project:

### 1. Direct Contribution (If you have write access to the repository)

- Clone the repository directly: `git clone ....`
- Create a branch for your changes: `git checkout -b ....`
- Make your changes, commit them, and push directly to the repository
- Open a pull request from your branch to the main branch

### 2. Fork and Pull Request (If you don't have write access to the repository)

- Fork the repository on GitHub to your own account
- Clone your fork locally: `git clone https://github.com/your-username/garde.git`
- Add the original repository as an upstream remote: `git remote add upstream https://github.com/original-owner/garde.git`
- Push your branch to your fork: `git push origin feature/your-feature-name`
- Open a pull request from your branch to the main repository's main branch.


## Testing

#### Tests That Require mTLS (API-key auth flow)

For tests that require mTLS, you need to use TLS - mTLS and generate the necessary certificates. The project includes a standalone script for generating TLS certificates for testing purposes:

```bash
# Run from the root of the project
./generate-certificates.sh
```

This script will create the following certificates in the `certs` directory:
- `ca-cert.pem`: Certificate Authority certificate
- `ca-key.pem`: Certificate Authority private key
- `server-cert.pem`: Server certificate
- `server-key.pem`: Server private key
- `client-cert.pem`: Client certificate for mTLS
- `client-key.pem`: Client private key for mTLS

Make sure your `dev.secrets` file has the following configurations:

```
# TLS Configuration
USE_TLS=true
TLS_CERT_PATH=./certs/server-cert.pem
TLS_KEY_PATH=./certs/server-key.pem
PORT=8443

# mTLS Configuration
TLS_CA_PATH=./certs/ca-cert.pem

# Service Authentication
API_KEY=TestApiKey123!TestApiKey123!  # Must be at least 20 characters with mixed case, numbers, and special chars
```

