import type { JWTPayload } from "jose"
import { base64url, jwtVerify, SignJWT } from "jose"

import { keyId, privateKey, publicKey, signingAlgorithm } from "./keys"
import type { TestOidcUser } from "./user"

/**
 * Self-contained authorization code.
 *
 * The code carries everything the token endpoint checks, so the flow needs no in-memory state, sticky sessions, or shared storage between processes.
 * As a consequence, a code is not single-use.
 */
export interface AuthorizationCodePayload extends JWTPayload {
  kind: "authorization_code"
  client_id: string
  redirect_uri: string
  nonce?: string
  code_challenge: string
  user: TestOidcUser
}

/** Self-contained access token that carries the user for the UserInfo endpoint. */
export interface AccessTokenPayload extends JWTPayload {
  kind: "access_token"
  user: TestOidcUser
}

/** Lifetime of codes and tokens in seconds. */
export const tokenTtl = 300

/** Signs a JWT payload for an audience with the issuer key. */
export async function signToken(
  payload: JWTPayload,
  { issuer, audience, subject }: { issuer: string; audience: string; subject: string },
): Promise<string> {
  return await new SignJWT(payload)
    .setProtectedHeader({ alg: signingAlgorithm, kid: keyId })
    .setIssuer(issuer)
    .setAudience(audience)
    .setSubject(subject)
    .setIssuedAt()
    .setExpirationTime(`${tokenTtl}s`)
    .sign(await privateKey)
}

/**
 * Verifies a token of the issuer and checks its kind.
 *
 * Returns `undefined` for an invalid, expired, or foreign token, so a caller answers with its own protocol error.
 */
export async function verifyToken<TPayload extends { kind: string }>(
  token: string,
  kind: TPayload["kind"],
  options: { issuer: string; audience?: string },
): Promise<TPayload | undefined> {
  const result = await jwtVerify<TPayload>(token, await publicKey, options).catch(() => undefined)
  return result?.payload.kind === kind ? result.payload : undefined
}

/** Computes the PKCE S256 code challenge of a code verifier. */
export async function createS256CodeChallenge(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))
  return base64url.encode(new Uint8Array(digest))
}
