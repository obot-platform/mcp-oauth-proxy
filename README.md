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

The OAuth proxy follows the Cloudflare Workers OAuth Provider pattern but is implemented in Go with database storage:

- **Authorization Flow**: Clients request authorization, users approve, and authorization codes are generated
- **Token Exchange**: Authorization codes are exchanged for access and refresh tokens
- **Token Validation**: JWT tokens are validated and user properties are extracted
- **MCP Proxying**: Requests to MCP endpoints are proxied with user context headers

## Database Support

The proxy supports both PostgreSQL and SQLite databases:

### PostgreSQL (Recommended for Production)

- Full ACID compliance
- Better concurrent access
- Advanced features like JSONB for metadata storage
- Set `DATABASE_DSN="postgres://user:pass@host:port/dbname?sslmode=disable"`

### SQLite (Default for Development)

- Zero configuration
- Single file storage
- Perfect for development and small deployments
- Automatically used when `DATABASE_DSN` is not set
- Database file stored at `data/oauth_proxy.db`

## Database Schema

The proxy uses the following tables (compatible with both PostgreSQL and SQLite):

- `clients`: OAuth client registrations
- `grants`: Authorization grants with user properties
- `authorization_codes`: Single-use authorization codes
- `access_tokens`: Access and refresh tokens with grant references

## Configuration

The application can be configured using environment variables:

### Required Environment Variables

- `SCOPES_SUPPORTED`: Comma-separated list of supported OAuth scopes (e.g., "openid,profile,email")
- `MCP_SERVER_URL`: URL of the MCP server to proxy requests to
- `OAUTH_CLIENT_ID`: OAuth client ID from your OAuth provider
- `OAUTH_CLIENT_SECRET`: OAuth client secret from your OAuth provider
- `OAUTH_AUTHORIZE_URL`: Authorization endpoint URL from your OAuth provider

### Optional Environment Variables

- `DATABASE_DSN`: Database connection string (PostgreSQL or SQLite). If not set, SQLite will be used with a local file at `data/oauth_proxy.db`
- `ENCRYPTION_KEY`: Base64-encoded 32-byte AES-256 key for encrypting sensitive data

### Example Environment Variables

```bash
# Example for Google OAuth with PostgreSQL
DATABASE_DSN="postgres://oauth_user:oauth_password@localhost:5432/oauth_proxy?sslmode=disable"
SCOPES_SUPPORTED="openid,profile,email"
OAUTH_CLIENT_ID="your-google-client-id.apps.googleusercontent.com"
OAUTH_CLIENT_SECRET="your-google-client-secret"
OAUTH_AUTHORIZE_URL="https://accounts.google.com"
MCP_SERVER_URL="http://localhost:3000"
ENCRYPTION_KEY="base64-encoded-32-byte-aes-256-key"

# Example for Google OAuth with SQLite (DATABASE_DSN not set, will use data/oauth_proxy.db)
SCOPES_SUPPORTED="openid,profile,email"
OAUTH_CLIENT_ID="your-google-client-id.apps.googleusercontent.com"
OAUTH_CLIENT_SECRET="your-google-client-secret"
OAUTH_AUTHORIZE_URL="https://accounts.google.com"
MCP_SERVER_URL="http://localhost:3000"

# Example for Microsoft Azure AD
# SCOPES_SUPPORTED="openid,profile,email,User.Read"
# OAUTH_AUTHORIZE_URL="https://login.microsoftonline.com/common/v2.0"

# Example for GitHub
# SCOPES_SUPPORTED="read:user,user:email"
# OAUTH_AUTHORIZE_URL="https://github.com/login/oauth"
```

## OAuth Provider Setup

### Google OAuth 2.0

1. **Create a Google Cloud Project**:

   - Go to [Google Cloud Console](https://console.cloud.google.com/)
   - Create a new project or select an existing one

2. **Enable OAuth 2.0 API**:

   - Go to "APIs & Services" > "Library"
   - Search for "Google+ API" or "OAuth 2.0" and enable it

3. **Create OAuth 2.0 Credentials**:

   - Go to "APIs & Services" > "Credentials"
   - Click "Create Credentials" > "OAuth 2.0 Client IDs"
   - Choose "Web application" as the application type
   - Add authorized redirect URIs: `http://localhost:8080/callback` (for development)
   - Note down the Client ID and Client Secret

4. **Environment Variables**:
   ```bash
   OAUTH_CLIENT_ID="your-google-client-id.apps.googleusercontent.com"
   OAUTH_CLIENT_SECRET="your-google-client-secret"
   OAUTH_AUTHORIZE_URL="https://accounts.google.com"
   SCOPES_SUPPORTED="openid,profile,email"
   ```

### Microsoft Azure AD

1. **Register an Application**:

   - Go to [Azure Portal](https://portal.azure.com/)
   - Navigate to "Azure Active Directory" > "App registrations"
   - Click "New registration"
   - Enter a name for your application
   - Set redirect URI to `http://localhost:8080/callback` (for development)

2. **Configure Permissions**:

   - Go to "API permissions"
   - Add "Microsoft Graph" > "Delegated permissions"
   - Select: `User.Read`, `openid`, `profile`, `email`
   - Click "Grant admin consent"

3. **Get Client Credentials**:

   - Go to "Certificates & secrets"
   - Create a new client secret
   - Note down the Application (client) ID and the secret value

4. **Environment Variables**:
   ```bash
   OAUTH_CLIENT_ID="your-azure-client-id"
   OAUTH_CLIENT_SECRET="your-azure-client-secret"
   OAUTH_AUTHORIZE_URL="https://login.microsoftonline.com/common/v2.0"
   SCOPES_SUPPORTED="openid,profile,email,User.Read"
   ```

### GitHub OAuth

1. **Create a GitHub OAuth App**:

   - Go to [GitHub Settings](https://github.com/settings/developers)
   - Click "New OAuth App"
   - Fill in the application details:
     - Application name: Your app name
     - Homepage URL: `http://localhost:8080` (for development)
     - Authorization callback URL: `http://localhost:8080/callback`

2. **Get Client Credentials**:

   - After creating the app, you'll see the Client ID
   - Click "Generate a new client secret" to get the Client Secret

3. **Environment Variables**:
   ```bash
   OAUTH_CLIENT_ID="your-github-client-id"
   OAUTH_CLIENT_SECRET="your-github-client-secret"
   OAUTH_AUTHORIZE_URL="https://github.com/login/oauth"
   SCOPES_SUPPORTED="read:user,user:email"
   ```

### Redirect URI Configuration

When configuring your OAuth provider, use these redirect URIs:

- **Development**: `http://localhost:8080/callback`
- **Production**: `https://yourdomain.com/callback`

The proxy will automatically handle the OAuth flow and redirect users back to your application.

### OAuth Scopes Explained

#### Google OAuth Scopes

- `openid`: Required for OpenID Connect authentication
- `profile`: Access to user's basic profile information (name, picture)
- `email`: Access to user's email address

#### Microsoft Azure AD Scopes

- `openid`: Required for OpenID Connect authentication
- `profile`: Access to user's basic profile information
- `email`: Access to user's email address
- `User.Read`: Access to read user's profile and basic information

#### GitHub OAuth Scopes

- `read:user`: Access to read user's profile information
- `user:email`: Access to read user's email addresses

#### Custom Scopes

You can customize the scopes based on your needs. Common additional scopes include:

- `offline_access`: For refresh tokens (Microsoft)
- `https://www.googleapis.com/auth/userinfo.profile`: Extended Google profile access
- `repo`: GitHub repository access (if needed)

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

   **For PostgreSQL (production):**

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
       image: ghcr.io/obot-platform/mcp-oauth-proxy:master
       environment:
         DATABASE_DSN: "postgres://oauth_user:oauth_password@postgres:5432/oauth_proxy?sslmode=disable"
         SCOPES_SUPPORTED: "openid,profile,email"
         OAUTH_CLIENT_ID: "your-oauth-client-id"
         OAUTH_CLIENT_SECRET: "your-oauth-client-secret"
         OAUTH_AUTHORIZE_URL: "https://your-oauth-provider.com/oauth/authorize"
         MCP_SERVER_URL: "http://localhost:3000"
         ENCRYPTION_KEY: "your-base64-encoded-32-byte-key"
       ports:
         - "8080:8080"
       depends_on:
         - postgres

   volumes:
     postgres_data:
   ```

   **For SQLite (simpler setup):**

   ```yaml
   version: "3.8"
   services:
     oauth-proxy:
       image: ghcr.io/obot-platform/mcp-oauth-proxy:master
       environment:
         # DATABASE_DSN not set - will use SQLite
         SCOPES_SUPPORTED: "openid,profile,email"
         OAUTH_CLIENT_ID: "your-oauth-client-id"
         OAUTH_CLIENT_SECRET: "your-oauth-client-secret"
         OAUTH_AUTHORIZE_URL: "https://your-oauth-provider.com/oauth/authorize"
         MCP_SERVER_URL: "http://localhost:3000"
       volumes:
         - ./data:/app/data # Persist SQLite database
       ports:
         - "8080:8080"
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

- `ANY /*` - Proxies any request not mentioned above to MCP server with user context headers

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

### Quick Test

Run the test script to test the OAuth flow:

```bash
chmod +x test_oauth.sh
./test_oauth.sh
```

### Comprehensive Testing

The project includes comprehensive testing for both PostgreSQL and SQLite databases:

#### Run All Tests

```bash
# Run all tests (PostgreSQL)
make test

# Run SQLite tests only
make test-sqlite

# Run comprehensive CI tests locally
./test_sqlite_ci.sh
```

#### Database-Specific Tests

```bash
# PostgreSQL tests (requires PostgreSQL running)
TEST_DATABASE_DSN="postgres://test:test@localhost:5432/oauth_test?sslmode=disable" go test -v ./...

# SQLite tests (no database setup required)
DATABASE_DSN="" go test -v ./database -run TestSQLiteDatabase
```

#### CI Testing

The project uses GitHub Actions for continuous integration with:

- **PostgreSQL Testing**: Full test suite with PostgreSQL database
- **SQLite Testing**: Full test suite with SQLite database (fallback mode)
- **Code Coverage**: Coverage reports for both database types
- **Linting**: Code quality checks
- **Race Detection**: Concurrency testing
- **Build Verification**: Ensures the application builds and starts correctly

The CI workflow runs on:

- Push to `master` or `main` branch
- Pull requests to `master` or `main` branch

#### Test Coverage

The test suite covers:

- OAuth authorization flow
- Token management and refresh
- Database operations (PostgreSQL and SQLite)
- Provider integration
- MCP proxy functionality
- Error handling and edge cases

## Credits

The code is based on the [Cloudflare Workers OAuth Provider](https://github.com/cloudflare/workers-oauth-provider).

## Security Features

- **Short-lived Access Tokens**: Access tokens expire after 1 hour by default
- **Refresh Token Rotation**: New refresh tokens are issued with each use
- **Token Revocation**: Tokens can be revoked via the revocation endpoint
- **PKCE Support**: Supports PKCE for enhanced security in public clients
- **Rate Limiting**: Built-in rate limiting to prevent abuse
- **CORS Configuration**: Configurable CORS headers for security

## OAuth Provider Support

The proxy supports any OAuth 2.0/OpenID Connect provider through automatic endpoint discovery. It will:

1. **Discover Endpoints**: Automatically discover OAuth endpoints using well-known paths:

   - `/.well-known/oauth-authorization-server`
   - `/.well-known/openid-configuration`

2. **Use Discovered Endpoints**: Use the discovered authorization, token, and userinfo endpoints

3. **Fallback**: If discovery fails, use the provided authorization URL with default endpoint assumptions

### Supported Scopes

The proxy supports standard OAuth scopes:

- `openid`
- `profile`
- `email`

### Configuration

Set these environment variables to configure your OAuth provider:

- `OAUTH_CLIENT_ID`: Your OAuth client ID
- `OAUTH_CLIENT_SECRET`: Your OAuth client secret
- `OAUTH_AUTHORIZE_URL`: The authorization endpoint URL from your provider

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

- `ghcr.io/mcp-oauth-proxy/mcp-oauth-proxy:master` - Latest from master branch
- `ghcr.io/mcp-oauth-proxy/mcp-oauth-proxy:master-abc123` - Branch-specific builds

## License

This project is licensed under the MIT License.
