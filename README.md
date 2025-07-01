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

Create a `config.yaml` file:

```yaml
server:
  port: 8080
  host: "0.0.0.0"

database:
  dsn: "postgres://oauth_user:oauth_password@localhost:5432/oauth_proxy?sslmode=disable"

oauth:
  issuer_url: "http://localhost:8080"
  base_url: "http://localhost:8080"
  service_documentation_url: "https://example.com/docs"
  scopes_supported:
    - "openid"
    - "profile"
    - "email"
  resource_name: "MCP Tools"
  access_token_ttl: 3600 # 1 hour in seconds
  allow_implicit_flow: false

mcp:
  server_url: "http://localhost:8080/mcp"

rate_limit:
  enabled: true
  window_minutes: 15
  max_requests: 100

providers:
  google:
    client_id: "your-google-client-id"
    client_secret: "your-google-client-secret"
  microsoft:
    client_id: "your-microsoft-client-id"
    client_secret: "your-microsoft-client-secret"
```

## Setup

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

## License

This project is licensed under the MIT License.
