# oidc-test-issuer

OpenID Connect issuer for tests that signs users in without UI.
Mount it into your application to test "Sign in with SSO" end to end, in a browser or in-process, without running an external identity provider.

- Serves a web-standard `fetch(request)` handler, so any server or test runner can host it.
- Keeps no state: codes and tokens are self-contained signed JWTs, so it works across several processes without sticky sessions or shared storage.
- Runs on the origin of your application, so the issuer has the same HTTPS host as your app.
- Selects a stable user by the standard `login_hint` parameter.

The issuer accepts any client ID and secret and signs tokens with a key published in this package.
Never mount it in production.

## Install

```sh
npm install oidc-test-issuer
```

## Usage

Create the issuer with the path you mount it at:

```ts
import { createTestOidcIssuer } from "oidc-test-issuer"

const issuer = createTestOidcIssuer({ basePath: "/_test/oidc" })
```

Route every request under that path to `issuer.fetch` with its full URL: the issuer URL is the request origin followed by `basePath`.
Register the issuer as a route of your server, as the examples below do, rather than with `use` or `mount`, which strip the path from the URL.

Configure your OpenID Connect client with the issuer URL, any client ID, and any secret:

```ts
issuer.getIssuerUrl("https://app.localhost") // "https://app.localhost/_test/oidc"
```

### Node.js

Convert `issuer.fetch` to a Node.js handler with an adapter such as [srvx](https://srvx.h3.dev).
With Express, register it before body parsers, which consume the request body that the issuer reads:

```ts
import { toNodeHandler } from "srvx/node"

app.all("/_test/oidc/*path", toNodeHandler(issuer.fetch))
```

### Bun

```ts
Bun.serve({
  routes: { "/_test/oidc/*": issuer.fetch },
  fetch: app.fetch,
})
```

### h3

```ts
app.all("/_test/oidc/**", event => issuer.fetch(event.req))
```

### Hono

```ts
app.all("/_test/oidc/*", c => issuer.fetch(c.req.raw))
```

### Test in-process

To run the whole sign-in flow in a unit test, route the HTTP requests of your OpenID Connect client to the issuer.
With openid-client, pass a custom fetch:

```ts
import * as client from "openid-client"

const config = await client.discovery(
  new URL(issuer.getIssuerUrl("https://app.example.com")),
  "client-id",
  "secret",
  undefined,
  {
    [client.customFetch]: (url, options) => issuer.fetch(new Request(url, options)),
  },
)
```

Follow the authorization URL with `issuer.fetch` too: it answers with a redirect to your callback URL.

## Users

The issuer signs in a user as soon as the browser opens the authorization endpoint.
Without `login_hint`, it signs in `defaultTestOidcUser`:

```text
sub: test-oidc-user-000001
email: test-oidc-user-000001@example.invalid
email_verified: true
name: Test OIDC User 000001
```

Pass a short key in `login_hint` to sign in another user: `login_hint=42` signs in `test-oidc-user-000042`.
The key consists of up to 32 Latin letters, digits, `_`, or `-`; numeric keys are zero-padded to 6 digits, and other keys are case-insensitive.
`createTestOidcUser(key)` builds the user that the same `login_hint` selects, so tests can name the claims they expect.

To sign in other users, pass `getUser`.
It receives `login_hint` and returns the user, or `undefined` to deny the sign-in with `error=access_denied`:

```ts
const issuer = createTestOidcIssuer({
  getUser: (loginHint = "user-1") => ({
    sub: loginHint,
    claims: { email: `${loginHint}@example.com`, email_verified: false },
    // Claims that only the UserInfo endpoint returns.
    userinfoClaims: { name: loginHint },
  }),
})
```

## Protocol

The issuer supports the authorization code flow with PKCE S256, which it requires.
It serves discovery, JWKS, authorization, token, and UserInfo endpoints, and returns `iss` in the authorization response.

It checks the client ID, redirect URI, and PKCE verifier on the token endpoint, but ignores the client secret.
Codes and tokens live 5 minutes, and a code can be exchanged more than once.
