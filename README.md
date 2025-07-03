# MCP OAuth Proxy

A comprehensive OAuth 2.1 proxy server implemented in Go that provides OAuth authorization server functionality with PostgreSQL storage. This proxy supports multiple OAuth providers (Google, Microsoft) and can proxy requests to MCP servers with user context headers.

## Features

- **OAuth 2.1 Compliance**: Implements OAuth 2.1 best practices including short-lived access tokens, refresh token rotation, and token revocation
- **Multiple Provider Support**: Supports Google and Microsoft OAuth providers
- **PostgreSQL Storage**: Uses PostgreSQL for storing clients, grants, authorization codes, and tokens
- **JWT Token Management**: Generates and validates JWT tokens with embedded user properties
- **MCP Proxy**: Proxies requests to MCP servers with user context headers
- **CORS Support**: Configurable CORS headers for cross-origin requests
- **Rate Limiting**: Built-in rate limiting to prevent abuse
- **PKCE Support**: Supports PKCE (Proof Key for Code Exchange) for enhanced security

## Architecture

The OAuth proxy follows the Cloudflare Workers OAuth Provider pattern but is implemented in Go with PostgreSQL storage:

- **Authorization Flow**: Clients request authorization, users approve, and authorization codes are generated
- **Token Exchange**: Authorization codes are exchanged for access and refresh tokens
- **Token Validation**: JWT tokens are validated and user properties are extracted
- **MCP Proxying**: Requests to MCP endpoints are proxied with user context headers

## Database Schema

The proxy uses PostgreSQL with the following tables:

- `clients`: OAuth client registrations
- `grants`: Authorization grants with user properties
- `authorization_codes`: Single-use authorization codes
- `access_tokens`: Access and refresh tokens with grant references

## Configuration

The application can be configured using environment variables:

### Required Environment Variables

- `DATABASE_DSN`: PostgreSQL connection string
- `BASE_URL`: Base URL for the OAuth server (e.g., "http://localhost:8080")
- `SCOPES_SUPPORTED`: Comma-separated list of supported OAuth scopes (e.g., "openid,profile,email")
- `MCP_SERVER_URL`: URL of the MCP server to proxy requests to

### Optional Environment Variables

- `GOOGLE_CLIENT_ID`: Google OAuth client ID
- `GOOGLE_CLIENT_SECRET`: Google OAuth client secret
- `MICROSOFT_CLIENT_ID`: Microsoft OAuth client ID
- `MICROSOFT_CLIENT_SECRET`: Microsoft OAuth client secret
- `ENCRYPTION_KEY`: Base64-encoded 32-byte AES-256 key for encrypting sensitive data

### Example Environment Variables

```bash
DATABASE_DSN="postgres://oauth_user:oauth_password@localhost:5432/oauth_proxy?sslmode=disable"
BASE_URL="http://localhost:8080"
SCOPES_SUPPORTED="openid,profile,email"
GOOGLE_CLIENT_ID="your-google-client-id"
GOOGLE_CLIENT_SECRET="your-google-client-secret"
MCP_SERVER_URL="http://localhost:3000"
ENCRYPTION_KEY="base64-encoded-32-byte-aes-256-key"
```

## Setup

### Using Docker (Recommended)

1. **Pull the Docker image**:

   ```bash
   docker pull ghcr.io/YOUR_USERNAME/mcp-oauth-proxy:latest
   ```

2. **Run with environment variables**:

   ```bash
   docker run -d \
     --name oauth-proxy \
     -p 8080:8080 \
     -e DATABASE_DSN="postgres://oauth_user:oauth_password@localhost:5432/oauth_proxy?sslmode=disable" \
     -e BASE_URL="http://localhost:8080" \
     -e SCOPES_SUPPORTED="openid,profile,email" \
     -e GOOGLE_CLIENT_ID="your-google-client-id" \
     -e GOOGLE_CLIENT_SECRET="your-google-client-secret" \
     -e MCP_SERVER_URL="http://localhost:3000" \
     -e ENCRYPTION_KEY="your-base64-encoded-32-byte-key" \
     ghcr.io/YOUR_USERNAME/mcp-oauth-proxy:latest
   ```

### Using Docker Compose

1. **Create a docker-compose.yml file**:

   ```yaml
   version: "3.8"
   services:
     postgres:
       image: postgres:15
       environment:
         POSTGRES_DB: oauth_proxy
         POSTGRES_USER: oauth_user
         POSTGRES_PASSWORD: oauth_password
       volumes:
         - postgres_data:/var/lib/postgresql/data
       ports:
         - "5432:5432"

     oauth-proxy:
       image: ghcr.io/YOUR_USERNAME/mcp-oauth-proxy:latest
       environment:
         DATABASE_DSN: "postgres://oauth_user:oauth_password@postgres:5432/oauth_proxy?sslmode=disable"
         BASE_URL: "http://localhost:8080"
         SCOPES_SUPPORTED: "openid,profile,email"
         GOOGLE_CLIENT_ID: "your-google-client-id"
         GOOGLE_CLIENT_SECRET: "your-google-client-secret"
         MCP_SERVER_URL: "http://localhost:3000"
         ENCRYPTION_KEY: "your-base64-encoded-32-byte-key"
       ports:
         - "8080:8080"
       depends_on:
         - postgres

   volumes:
     postgres_data:
   ```

2. **Start the services**:

   ```bash
   docker-compose up -d
   ```

### Local Development

1. **Start PostgreSQL**:

   ```bash
   docker-compose up -d postgres
   ```

2. **Create a test client**:

   ```bash
   go run scripts/create_client.go "postgres://oauth_user:oauth_password@localhost:5432/oauth_proxy?sslmode=disable"
   ```

3. **Start the OAuth proxy**:
   ```bash
   go run main.go
   ```

## API Endpoints

### OAuth Endpoints

- `GET /authorize` - OAuth authorization endpoint
- `POST /token` - OAuth token endpoint
- `POST /revoke` - OAuth token revocation endpoint

### Metadata Endpoints

- `GET /.well-known/oauth-authorization-server` - OAuth server metadata
- `GET /.well-known/oauth-protected-resource` - Protected resource metadata

### MCP Proxy

- `ANY /mcp/*` - Proxies requests to MCP server with user context headers

## OAuth Flow

1. **Authorization Request**: Client redirects user to `/authorize` with OAuth parameters
2. **User Approval**: User approves the authorization request
3. **Authorization Code**: Server generates and returns an authorization code
4. **Token Exchange**: Client exchanges authorization code for access and refresh tokens
5. **API Access**: Client uses access token to access protected resources

## MCP Integration

The proxy forwards requests to the configured MCP server with the following headers:

- `X-Forwarded-User`: User ID from the token
- `X-Forwarded-Email`: User email from token props
- `X-Forwarded-Name`: User name from token props
- `X-Forwarded-Access-Token`: Original access token from external provider

## Testing

Run the test script to test the OAuth flow:

```bash
chmod +x test_oauth.sh
./test_oauth.sh
```

## Credits

The code is based on the [Cloudflare Workers OAuth Provider](https://github.com/cloudflare/workers-oauth-provider).

## Security Features

- **Short-lived Access Tokens**: Access tokens expire after 1 hour by default
- **Refresh Token Rotation**: New refresh tokens are issued with each use
- **Token Revocation**: Tokens can be revoked via the revocation endpoint
- **PKCE Support**: Supports PKCE for enhanced security in public clients
- **Rate Limiting**: Built-in rate limiting to prevent abuse
- **CORS Configuration**: Configurable CORS headers for security

## Provider Support

### Google Provider

Supports Google OAuth 2.0 with the following scopes:

- `openid`
- `profile`
- `email`

### Microsoft Provider

Supports Microsoft OAuth 2.0 with the following scopes:

- `openid`
- `profile`
- `email`
- `User.Read`

## Development

### Adding New Providers

To add a new OAuth provider:

1. Implement the `Provider` interface in `providers/provider.go`
2. Create a new provider file (e.g., `providers/github.go`)
3. Register the provider in `main.go`

### Database Migrations

The database schema is automatically created when the application starts. For production deployments, consider using proper database migration tools.

### Building Docker Images

The project includes a GitHub Actions workflow that automatically builds and pushes Docker images to GitHub Container Registry (GHCR) on:

- Push to `main` or `master` branch
- Push of tags starting with `v` (e.g., `v1.0.0`)
- Pull requests to `main` or `master` branch (builds but doesn't push)

#### Manual Build

To build the Docker image locally:

```bash
docker build -t mcp-oauth-proxy .
```

#### Using the GitHub Actions Image

The workflow creates images with the following tags:

- `ghcr.io/YOUR_USERNAME/mcp-oauth-proxy:latest` - Latest from main branch
- `ghcr.io/YOUR_USERNAME/mcp-oauth-proxy:v1.0.0` - Specific version tags
- `ghcr.io/YOUR_USERNAME/mcp-oauth-proxy:main-abc123` - Branch-specific builds

Replace `YOUR_USERNAME` with your actual GitHub username.

## License

This project is licensed under the MIT License.
