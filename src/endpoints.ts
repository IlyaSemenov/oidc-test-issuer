import { publicJwk, signingAlgorithm } from "./keys"
import type { AccessTokenPayload, AuthorizationCodePayload } from "./tokens"
import { createS256CodeChallenge, signToken, tokenTtl, verifyToken } from "./tokens"
import type { GetTestOidcUser } from "./user"

/** Context of a request to an issuer endpoint. */
export interface EndpointContext {
  request: Request
  /** Issuer URL that the request addresses. */
  issuer: string
  getUser: GetTestOidcUser
}

/** Answers the discovery request with endpoints under the issuer URL. */
export function getDiscovery({ issuer }: EndpointContext): Response {
  return Response.json({
    issuer,
    authorization_endpoint: `${issuer}/authorize`,
    token_endpoint: `${issuer}/token`,
    userinfo_endpoint: `${issuer}/userinfo`,
    jwks_uri: `${issuer}/jwks`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code"],
    scopes_supported: ["openid", "email", "profile"],
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: [signingAlgorithm],
    token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post", "none"],
    code_challenge_methods_supported: ["S256"],
    authorization_response_iss_parameter_supported: true,
  })
}

/** Answers the JWKS request with the public signing key. */
export function getJwks(): Response {
  return Response.json({ keys: [publicJwk] })
}

/**
 * Handles an authorization request without UI: it signs the user in at once and redirects back.
 *
 * An invalid `client_id` or `redirect_uri` gets a 400 response, because the issuer cannot trust the redirect target; other errors redirect back with `error`, as RFC 6749 requires.
 */
export async function authorize({ request, issuer, getUser }: EndpointContext): Promise<Response> {
  const params = new URL(request.url).searchParams
  const clientId = params.get("client_id")
  // The code keeps the redirect URI as the client sent it: the token request must repeat it exactly.
  const redirectUriParam = params.get("redirect_uri")
  const redirectUri = parseAbsoluteUrl(redirectUriParam)
  if (!clientId || !redirectUriParam || !redirectUri) {
    return new Response("client_id and an absolute redirect_uri are required.", { status: 400 })
  }

  const redirect = (result: Record<string, string | undefined>) => {
    const state = params.get("state")
    for (const [name, value] of Object.entries({ ...result, state, iss: issuer })) {
      if (value) {
        redirectUri.searchParams.set(name, value)
      }
    }
    return Response.redirect(redirectUri.href, 302)
  }

  if (params.get("response_type") !== "code") {
    return redirect({
      error: "unsupported_response_type",
      error_description: "Only response_type=code is supported.",
    })
  }

  const codeChallenge = params.get("code_challenge")
  if (!codeChallenge || params.get("code_challenge_method") !== "S256") {
    return redirect({
      error: "invalid_request",
      error_description: "PKCE with code_challenge_method=S256 is required.",
    })
  }

  const user = await getUser(params.get("login_hint") ?? undefined)
  if (!user) {
    return redirect({ error: "access_denied", error_description: "Sign-in was denied." })
  }

  const code = await signToken(
    {
      kind: "authorization_code",
      client_id: clientId,
      redirect_uri: redirectUriParam,
      nonce: params.get("nonce") ?? undefined,
      code_challenge: codeChallenge,
      user,
    } satisfies AuthorizationCodePayload,
    { issuer, audience: clientId, subject: user.sub },
  )

  return redirect({ code })
}

/**
 * Exchanges an authorization code for tokens.
 *
 * It checks `client_id`, `redirect_uri`, and the PKCE verifier like a real provider, but ignores the client secret: the issuer checks the shape of the flow, not trust in the client.
 */
export async function exchangeCode({ request, issuer }: EndpointContext): Promise<Response> {
  const body = new URLSearchParams(await request.text())
  if (body.get("grant_type") !== "authorization_code") {
    return tokenError("unsupported_grant_type", "Only grant_type=authorization_code is supported.")
  }

  const code = body.get("code")
  const redirectUri = body.get("redirect_uri")
  const codeVerifier = body.get("code_verifier")
  const basicClientId = getBasicClientId(request.headers.get("authorization"))
  if (basicClientId === null) {
    return tokenError("invalid_client", "The Basic authorization header is malformed.", 401, {
      "www-authenticate": "Basic",
    })
  }

  const clientId = basicClientId ?? body.get("client_id")
  if (!code || !redirectUri || !codeVerifier || !clientId) {
    return tokenError(
      "invalid_request",
      "code, redirect_uri, code_verifier, and client_id are required.",
    )
  }

  const payload = await verifyToken<AuthorizationCodePayload>(code, "authorization_code", {
    issuer,
    audience: clientId,
  })
  if (
    !payload ||
    payload.redirect_uri !== redirectUri ||
    payload.code_challenge !== (await createS256CodeChallenge(codeVerifier))
  ) {
    return tokenError(
      "invalid_grant",
      "The authorization code is invalid, expired, or issued for another request.",
    )
  }

  const { user } = payload
  const audience = { issuer, audience: clientId, subject: user.sub }
  const accessToken = await signToken(
    { kind: "access_token", user } satisfies AccessTokenPayload,
    audience,
  )
  const idToken = await signToken({ ...user.claims, nonce: payload.nonce }, audience)

  return Response.json(
    {
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: tokenTtl,
      id_token: idToken,
    },
    { headers: { "cache-control": "no-store" } },
  )
}

/** Returns the claims of the user that the bearer access token carries. */
export async function getUserinfo({ request, issuer }: EndpointContext): Promise<Response> {
  const [scheme, token] = request.headers.get("authorization")?.split(" ") ?? []
  const payload =
    scheme?.toLowerCase() === "bearer" && token
      ? await verifyToken<AccessTokenPayload>(token, "access_token", { issuer })
      : undefined
  if (!payload) {
    return new Response(null, {
      status: 401,
      headers: { "www-authenticate": 'Bearer error="invalid_token"' },
    })
  }

  const { sub, claims, userinfoClaims } = payload.user
  return Response.json({ ...claims, ...userinfoClaims, sub })
}

function tokenError(
  error: string,
  description: string,
  status = 400,
  headers: Record<string, string> = {},
): Response {
  return Response.json(
    { error, error_description: description },
    { status, headers: { ...headers, "cache-control": "no-store" } },
  )
}

function parseAbsoluteUrl(value: string | null): URL | undefined {
  return value && URL.canParse(value) ? new URL(value) : undefined
}

/**
 * Extracts the client ID from `client_secret_basic` authentication.
 *
 * Returns `undefined` without Basic authentication and `null` for malformed credentials.
 * OAuth clients form-encode the ID before Base64, so it is decoded back.
 */
function getBasicClientId(header: string | null): string | undefined | null {
  const [scheme, encoded] = header?.split(" ") ?? []
  if (scheme?.toLowerCase() !== "basic") {
    return undefined
  }

  try {
    const credentials = atob(encoded ?? "")
    if (!credentials.includes(":")) {
      return null
    }

    return (
      decodeURIComponent(credentials.slice(0, credentials.indexOf(":")).replaceAll("+", " ")) ||
      null
    )
  } catch {
    return null
  }
}
