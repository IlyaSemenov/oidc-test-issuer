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
  /**
   * Handles a request to the issuer; requests outside `basePath` get 404.
   *
   * Pass it as the handler of a server route, or as the `fetch` of an OpenID Connect client to route its requests to the issuer without a server.
   */
  fetch: {
    /**
     * Handles a request as is, such as one that a server received.
     *
     * Ignores the second argument, such as the context that a server passes along with the request; to change the request, build a new `Request` from it.
     */
    (request: Request, context?: unknown): Promise<Response>
    /** Handles a request to a URL with the options of the global `fetch`. */
    (url: string | URL, init?: RequestInit): Promise<Response>
  }
  /**
   * Opens an authorization URL as a browser would and returns the callback URL that the issuer redirects to.
   *
   * Rejects when the issuer answers without a redirect, such as to a request without `client_id`.
   */
  authorize: (authorizationUrl: string | URL) => Promise<string>
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

  const fetch: TestOidcIssuer["fetch"] = async (input: Request | string | URL, init?: unknown) => {
    // Servers may pass context as the second argument, so preserve the request unchanged.
    // Check for `url` because requests from another fetch implementation may not pass `instanceof Request`.
    const request =
      typeof input === "object" && "url" in input
        ? input
        : new Request(String(input), init as RequestInit)
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
  }

  return {
    fetch,
    async authorize(authorizationUrl) {
      const response = await fetch(authorizationUrl)
      const location = response.headers.get("location")
      if (!location) {
        throw new Error(
          `The issuer answered the authorization request with ${response.status}: ${await response.text()}`,
        )
      }
      return location
    },
    getIssuerUrl,
  }
}
