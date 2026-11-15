/** User that the issuer signs in. */
export interface TestOidcUser {
  /** Subject identifier, the `sub` claim. */
  sub: string
  /** Claims that both the ID token and the UserInfo response carry, such as `email`. */
  claims?: Record<string, unknown>
  /** Claims that only the UserInfo response carries. */
  userinfoClaims?: Record<string, unknown>
}

/** Claims of a user that `createTestOidcUser` builds. */
export type DefaultTestOidcUserClaims = {
  email: string
  email_verified: true
  name: string
}

/** User that `createTestOidcUser` builds. */
export interface DefaultTestOidcUser extends TestOidcUser {
  claims: DefaultTestOidcUserClaims
}

/**
 * Selects the user for the `login_hint` of an authorization request.
 *
 * Return `undefined` to deny the sign-in: the issuer redirects back with `error=access_denied`.
 */
export type GetTestOidcUser = (
  loginHint: string | undefined,
) => TestOidcUser | undefined | Promise<TestOidcUser | undefined>

const maxUserKeyLength = 32
const userKeyPattern = /^[\w-]+$/

/**
 * Builds a stable user for a key of up to 32 Latin letters, digits, `_`, or `-`.
 *
 * The key selects the same user as `login_hint` does by default: numeric keys are zero-padded to 6 digits, so `1`, `001`, and `000001` build the same user, and other keys are case-insensitive.
 * Emails use the reserved `example.invalid` domain, so they never reach a real mailbox.
 *
 * @throws {TypeError} The key is invalid.
 */
export function createTestOidcUser(key: string): DefaultTestOidcUser {
  const normalizedKey = normalizeUserKey(key)
  if (!normalizedKey) {
    throw new TypeError(`Invalid test OIDC user key: ${key}`)
  }

  const id = `test-oidc-user-${normalizedKey}`
  return {
    sub: id,
    claims: {
      email: `${id}@example.invalid`,
      email_verified: true,
      name: `Test OIDC User ${normalizedKey}`,
    },
  }
}

/** User that the issuer signs in when an authorization request has no `login_hint`. */
export const defaultTestOidcUser: DefaultTestOidcUser = createTestOidcUser("1")

/**
 * Default user selection: `login_hint` is a key for `createTestOidcUser`.
 *
 * A missing hint selects `defaultTestOidcUser`, and an invalid one denies the sign-in.
 */
export const getDefaultTestOidcUser: GetTestOidcUser = loginHint => {
  if (!loginHint?.trim()) {
    return defaultTestOidcUser
  }

  return normalizeUserKey(loginHint) ? createTestOidcUser(loginHint) : undefined
}

/** Brings a user key to its canonical form, or returns `undefined` for an invalid key. */
function normalizeUserKey(key: string): string | undefined {
  const trimmed = key.trim()
  if (!trimmed || trimmed.length > maxUserKeyLength || !userKeyPattern.test(trimmed)) {
    return undefined
  }

  return /^\d+$/.test(trimmed) ? trimmed.padStart(6, "0") : trimmed.toLowerCase()
}
