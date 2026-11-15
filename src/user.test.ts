import { expect, test } from "bun:test"

import { createTestOidcUser, getDefaultTestOidcUser } from "./user"

test("selects the same user for zero-padded numeric keys", async () => {
  const users = await Promise.all(["1", "001", "000001", undefined].map(getDefaultTestOidcUser))

  expect(new Set(users.map(user => user?.sub))).toEqual(new Set(["test-oidc-user-000001"]))
})

test("selects users by case-insensitive keys", async () => {
  expect((await getDefaultTestOidcUser("Alice"))?.sub).toBe("test-oidc-user-alice")
})

test("builds the user that login_hint selects for the same key", async () => {
  for (const key of ["42", "Alice"]) {
    expect(await getDefaultTestOidcUser(key)).toEqual(createTestOidcUser(key))
  }
})

test("denies invalid keys", async () => {
  expect(await getDefaultTestOidcUser("a b")).toBeUndefined()
  expect(await getDefaultTestOidcUser("a".repeat(33))).toBeUndefined()
  expect(() => createTestOidcUser("a b")).toThrow(TypeError)
})
