import { describe, expect, test } from "bun:test"

import type { GetTestOidcUser } from "oidc-test-issuer"
import { createTestOidcIssuer, defaultTestOidcUser } from "oidc-test-issuer"
import * as client from "openid-client"

const origin = "https://app.example.com"
const redirectUri = `${origin}/callback`

/** Runs the authorization code flow of openid-client against the issuer in the same process. */
async function signIn(issuer = createTestOidcIssuer({ basePath: "/oidc" }), loginHint?: string) {
  const fetchIssuer: client.CustomFetch = (url, options) => issuer.fetch(new Request(url, options))
  const config = await client.discovery(
    new URL(issuer.getIssuerUrl(origin)),
    "client-1",
    "secret-1",
    undefined,
    { [client.customFetch]: fetchIssuer },
  )

  const codeVerifier = client.randomPKCECodeVerifier()
  const state = client.randomState()
  const nonce = client.randomNonce()
  const authorizationUrl = client.buildAuthorizationUrl(config, {
    redirect_uri: redirectUri,
    scope: "openid email profile",
    code_challenge: await client.calculatePKCECodeChallenge(codeVerifier),
    code_challenge_method: "S256",
    state,
    nonce,
    ...(loginHint === undefined ? {} : { login_hint: loginHint }),
  })

  const authorization = await issuer.fetch(new Request(authorizationUrl.href))
  expect(authorization.status).toBe(302)
  const callbackUrl = new URL(authorization.headers.get("location")!)

  const tokens = await client.authorizationCodeGrant(config, callbackUrl, {
    pkceCodeVerifier: codeVerifier,
    expectedState: state,
    expectedNonce: nonce,
  })
  const claims = tokens.claims()!
  const userinfo: Record<string, unknown> = await client.fetchUserInfo(
    config,
    tokens.access_token,
    claims.sub,
  )
  return { claims, userinfo }
}

describe("authorization code flow", () => {
  test("signs in the default user without login_hint", async () => {
    const { claims, userinfo } = await signIn()

    expect(claims).toMatchObject({
      iss: "https://app.example.com/oidc",
      aud: "client-1",
      sub: "test-oidc-user-000001",
      email: "test-oidc-user-000001@example.invalid",
      email_verified: true,
      name: "Test OIDC User 000001",
    })
    expect(userinfo).toEqual({ sub: defaultTestOidcUser.sub, ...defaultTestOidcUser.claims })
  })

  test("signs in the user that login_hint selects", async () => {
    const { claims } = await signIn(undefined, "42")

    expect(claims.sub).toBe("test-oidc-user-000042")
  })

  test("returns UserInfo-only claims from UserInfo but not in the ID token", async () => {
    const getUser: GetTestOidcUser = () => ({
      sub: "user-1",
      claims: { name: "User 1" },
      userinfoClaims: { email: "user-1@example.com" },
    })

    const { claims, userinfo } = await signIn(createTestOidcIssuer({ getUser }))

    expect(claims.email).toBeUndefined()
    expect(userinfo).toEqual({ sub: "user-1", name: "User 1", email: "user-1@example.com" })
  })

  test("reports a denied user to openid-client", async () => {
    const issuer = createTestOidcIssuer({ getUser: () => undefined })

    const error = await signIn(issuer).catch((error: unknown) => error)

    expect(error).toBeInstanceOf(client.AuthorizationResponseError)
    expect((error as client.AuthorizationResponseError).error).toBe("access_denied")
  })
})
