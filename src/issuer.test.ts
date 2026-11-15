import { describe, expect, test } from "bun:test"

import { createTestOidcIssuer } from "./issuer"
import type { AuthorizationCodePayload } from "./tokens"
import { createS256CodeChallenge, signToken } from "./tokens"

const issuer = createTestOidcIssuer({ basePath: "/oidc/" })
const issuerUrl = "https://app.example.com/oidc"

test("serves discovery under the base path", async () => {
  const response = await issuer.fetch(new Request(`${issuerUrl}/.well-known/openid-configuration`))

  expect(await response.json()).toMatchObject({
    issuer: issuerUrl,
    token_endpoint: `${issuerUrl}/token`,
  })
})

test("answers 404 outside the base path", async () => {
  const response = await issuer.fetch(new Request("https://app.example.com/oidcx/jwks"))

  expect(response.status).toBe(404)
})

test("answers 405 to an unsupported method", async () => {
  const response = await issuer.fetch(new Request(`${issuerUrl}/token`))

  expect(response.status).toBe(405)
  expect(response.headers.get("allow")).toBe("POST")
})

describe("authorize", () => {
  test("accepts the original redirect_uri without URL normalization", async () => {
    const authorization = await issuer.fetch(
      new Request(
        `${issuerUrl}/authorize?${new URLSearchParams({
          client_id: "client-1",
          redirect_uri: "https://app.example.com",
          response_type: "code",
          code_challenge: await createS256CodeChallenge("verifier-1"),
          code_challenge_method: "S256",
        })}`,
      ),
    )
    const code = new URL(authorization.headers.get("location")!).searchParams.get("code")!

    const response = await issuer.fetch(
      new Request(`${issuerUrl}/token`, {
        method: "POST",
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code,
          code_verifier: "verifier-1",
          client_id: "client-1",
          redirect_uri: "https://app.example.com",
        }),
      }),
    )

    expect(response.status).toBe(200)
  })

  test("rejects a request without an absolute redirect_uri", async () => {
    const response = await issuer.fetch(
      new Request(`${issuerUrl}/authorize?client_id=client-1&redirect_uri=/callback`),
    )

    expect(response.status).toBe(400)
  })

  test("redirects back with an error without PKCE", async () => {
    const response = await issuer.fetch(
      new Request(
        `${issuerUrl}/authorize?client_id=client-1&redirect_uri=https://app.example.com/callback&response_type=code&state=state-1`,
      ),
    )

    const location = new URL(response.headers.get("location")!)
    expect(Object.fromEntries(location.searchParams)).toMatchObject({
      error: "invalid_request",
      state: "state-1",
      iss: issuerUrl,
    })
  })
})

describe("token", () => {
  const redirectUri = "https://app.example.com/callback"

  async function createCode() {
    return await signToken(
      {
        kind: "authorization_code",
        client_id: "client-1",
        redirect_uri: redirectUri,
        code_challenge: await createS256CodeChallenge("verifier-1"),
        user: { sub: "user-1" },
      } satisfies AuthorizationCodePayload,
      { issuer: issuerUrl, audience: "client-1", subject: "user-1" },
    )
  }

  async function exchange(params: Record<string, string>, headers?: Record<string, string>) {
    return await issuer.fetch(
      new Request(`${issuerUrl}/token`, {
        method: "POST",
        headers,
        body: new URLSearchParams({
          grant_type: "authorization_code",
          redirect_uri: redirectUri,
          ...params,
        }),
      }),
    )
  }

  test("accepts the client ID from client_secret_basic", async () => {
    const response = await exchange(
      { code: await createCode(), code_verifier: "verifier-1" },
      { authorization: `Basic ${btoa("client-1:secret")}` },
    )

    expect(response.status).toBe(200)
  })

  test("rejects malformed client_secret_basic credentials", async () => {
    const response = await exchange(
      { code: await createCode(), code_verifier: "verifier-1" },
      { authorization: "Basic !!!" },
    )

    expect(response.status).toBe(401)
    expect(response.headers.get("www-authenticate")).toBe("Basic")
    expect(await response.json()).toMatchObject({ error: "invalid_client" })
  })

  test("rejects a wrong PKCE verifier", async () => {
    const response = await exchange({
      code: await createCode(),
      code_verifier: "verifier-2",
      client_id: "client-1",
    })

    expect(response.status).toBe(400)
    expect(await response.json()).toMatchObject({ error: "invalid_grant" })
  })

  test("rejects a code issued for another redirect_uri", async () => {
    const response = await exchange({
      code: await createCode(),
      code_verifier: "verifier-1",
      client_id: "client-1",
      redirect_uri: "https://app.example.com/other",
    })

    expect(await response.json()).toMatchObject({ error: "invalid_grant" })
  })
})

test("userinfo rejects a request without a bearer token", async () => {
  const response = await issuer.fetch(new Request(`${issuerUrl}/userinfo`))

  expect(response.status).toBe(401)
  expect(response.headers.get("www-authenticate")).toBe('Bearer error="invalid_token"')
})
