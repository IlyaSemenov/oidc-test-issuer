import { createTestOidcIssuer } from "./issuer"

const issuer = createTestOidcIssuer({ basePath: "/_test/oidc" })

/** Bun passes its server along with the request to a route handler. */
export function serveWithBun() {
  return Bun.serve({ routes: { "/_test/oidc/*": issuer.fetch }, fetch: issuer.fetch })
}

/** OpenID Connect clients call `fetch` with a URL string and options. */
export const clientFetch: (url: string, init: RequestInit) => Promise<Response> = issuer.fetch
