import type { EndpointContext } from "./endpoints"
import { authorize, exchangeCode, getDiscovery, getJwks, getUserinfo } from "./endpoints"
import type { GetTestOidcUser } from "./user"
import { getDefaultTestOidcUser } from "./user"

/** Options of `createTestOidcIssuer`. */
export interface TestOidcIssuerOptions {
  /**
   * Path the issuer is mounted at, such as `/_test/oidc`.
   *
   * The issuer URL is the request origin followed by this path, so the handler must receive full request URLs.
   */
  basePath?: string
  /** Selects the user to sign in for the `login_hint` of an authorization request. */
  getUser?: GetTestOidcUser
}

/** OpenID Connect issuer for tests. */
export interface TestOidcIssuer {
  /** Handles a request to the issuer; requests outside `basePath` get 404. */
  fetch: (request: Request) => Promise<Response>
  /** Returns the issuer URL for an origin of the application that mounts the issuer. */
  getIssuerUrl: (origin: string | URL) => string
}

type Endpoint = (context: EndpointContext) => Response | Promise<Response>

const routes: Record<string, Partial<Record<string, Endpoint>>> = {
  "/.well-known/openid-configuration": { GET: getDiscovery },
  "/jwks": { GET: getJwks },
  "/authorize": { GET: authorize },
  "/token": { POST: exchangeCode },
  "/userinfo": { GET: getUserinfo, POST: getUserinfo },
}

/**
 * Creates an OpenID Connect issuer for tests that signs users in without UI.
 *
 * The issuer keeps no state: codes and tokens are self-contained JWTs signed with a fixed key pair published in the package, so any number of processes can serve it.
 * It accepts any client ID and secret.
 */
export function createTestOidcIssuer({
  basePath = "",
  getUser = getDefaultTestOidcUser,
}: TestOidcIssuerOptions = {}): TestOidcIssuer {
  const base = basePath.replace(/\/+$/, "")
  const getIssuerUrl = (origin: string | URL) => new URL(origin).origin + base

  return {
    async fetch(request) {
      const url = new URL(request.url)
      const route = url.pathname.startsWith(`${base}/`)
        ? routes[url.pathname.slice(base.length)]
        : undefined
      if (!route) {
        return new Response(null, { status: 404 })
      }

      const endpoint = route[request.method]
      if (!endpoint) {
        return new Response(null, {
          status: 405,
          headers: { allow: Object.keys(route).join(", ") },
        })
      }

      return await endpoint({ request, issuer: getIssuerUrl(url), getUser })
    },
    getIssuerUrl,
  }
}
