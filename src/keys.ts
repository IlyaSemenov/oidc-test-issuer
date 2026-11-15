import type { JWK } from "jose"
import { importJWK } from "jose"

/** Key ID of the signing key, announced in the JWKS and in token headers. */
export const keyId = "oidc-test-issuer"

/** Algorithm that signs authorization codes, access tokens, and ID tokens. */
export const signingAlgorithm = "RS256"

// The key pair is fixed and public, so every process that serves the issuer signs and verifies the same self-contained tokens without shared storage.
// It authenticates nothing: never trust this issuer outside tests.

/** Public signing key published in the JWKS. */
export const publicJwk: JWK = {
  kty: "RSA",
  n: "3fdm3yv2SpZnQiYUigEV_HGw78HNftWmQY6thELZmWMkYsn2sp74GRR703Xxkpqpe7kYBgWcZBlMLmtAk75YiE6Kvhe8PtR99QXFIm4k7ug9shUAAv4PF3l82iLt7wxlIoLVwJcS5X2UN6pEW-Os6BGSutSlyt6ymS0VUrGreqhas8QUBkt2mDHZPCIjQwNEsGwNYev7ZMgKKSZ36j6gRxeB7wb3DoFnwOAe2gPcFZEGA1Gm6M6DF6XY3sDFlO6YlF3fFt3h6n0DhpanWnypiXVo-9E6Mi9q9qCG6tAUu7-UzVoACZ2qogrxQfBhjuAJsA1yB8fwCy8gTPhek7Hl_w",
  e: "AQAB",
  use: "sig",
  alg: signingAlgorithm,
  kid: keyId,
}

const privateJwk: JWK = {
  kty: "RSA",
  n: "3fdm3yv2SpZnQiYUigEV_HGw78HNftWmQY6thELZmWMkYsn2sp74GRR703Xxkpqpe7kYBgWcZBlMLmtAk75YiE6Kvhe8PtR99QXFIm4k7ug9shUAAv4PF3l82iLt7wxlIoLVwJcS5X2UN6pEW-Os6BGSutSlyt6ymS0VUrGreqhas8QUBkt2mDHZPCIjQwNEsGwNYev7ZMgKKSZ36j6gRxeB7wb3DoFnwOAe2gPcFZEGA1Gm6M6DF6XY3sDFlO6YlF3fFt3h6n0DhpanWnypiXVo-9E6Mi9q9qCG6tAUu7-UzVoACZ2qogrxQfBhjuAJsA1yB8fwCy8gTPhek7Hl_w",
  e: "AQAB",
  d: "Aa7rn8ukjYJAfDbvtvA1K3ntPpQ4q7qRDTQ4yqT7I3emAf3IGiisdvw5yCu_zj3QBTktHnaSbgvnEP8NOVGbOEVoNfLWIZ_Y6K_Hg_BT5V_rf9s66crlcGcidEEJjuOILM_TMSe0I_tk0VtAM3YxjHz9oN8V9sjjj9fQrpTcWQzELZ819tt3gaJcA3kqsmKE92LQPBFIlba4etZGc9b2eSqi2uqNhAgkjGPzvrUkJDIbjJT4xDjTlhyhlK9M8FEj2G5oZ9QtMQh8zTRLbbACNVizSxt8_tNsx6P35Q370BRiS7mF4lcDI2NDj8bV5BeD4yOZMFTmlQUZiMHA_N8EEQ",
  p: "8mev6krLflq3Rc0H5bhfP8LgroS_6TTOt8dtp7MLpFKe0AAg6h0jnbK1oGH8Rc0AAGkJzYXOCxEAEOhTW7Bd5NrEmSqOBEKndm94zGbf54kofblWsDJ7ZKgOlV3TiemHmOYxZZGGs95BKomLCHoVHKglD9RnJMyj4Wkf72i1UVc",
  q: "6mpEy2-PPC4YYALXMOUvbYo-0UZ_sd3qzK-gdHhm2Ny4jhuAWu97XZyWl-IyateiJrp2iv5A9DHNmfTxeIMsLP35rdl4CEzUF0sXWShxB1sA3v8dQTWSO1PZx9EKhJuEigMRHFexPqvjCrD65TknpygbuUl7G6OqYXmWolrjX5k",
  dp: "48uCqib9klEHl6W0fTFE-TNWV0pS2oGQnW3g405Da3lk2sy0Ia2ecaymOAC8xI-AJ-KNnsDWPtoL-NeKtkhIBC99vv4ZlXFZ09evak5mrTvcfEF2cIAQKygvBDi2-QwnLA1ucCdQsaj0DlhQ-ndXbaWppnWRNCjG_KYAp8f7VGM",
  dq: "YBS6qd_KB9Kk7wV7CnGF5RIa-VA6Gr9o9AiwbczD6vNdOfIPxDYQjKgYGZz_KUfFELawy_u2x-B58zawmsK5Ip_e7OEMD-rdq8Z9hW_MFEW6r6xFY2r_yw1tYDdQZlYQFzl2k_VlktiFMOalj7rDhAIuit2Rdhy5Q0bA9T7nn1E",
  qi: "Xfvp7ZavCXnOi6_7KyYcSS-KTMRJtkJ6yRnFuOYJzKBzoym-pyPXpwQKRSePdo7F7SdEp6WqCdmiyf_L1JPOq8v9CI9jiqtwhY8hDHxSe_ywEvyts7OABbOW8_0dYh5YHCkopIsMrPXhpFq4HjsbxajU1IeHSJD4MRKjCwtxJE8",
}

/** Imported private key that signs tokens. */
export const privateKey = importJWK(privateJwk, signingAlgorithm)

/** Imported public key that verifies the issuer's own tokens. */
export const publicKey = importJWK(publicJwk, signingAlgorithm)
