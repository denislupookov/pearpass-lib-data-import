import { decodeAegisVault } from './decodeAegis'
import { buildEncryptedAegis } from './testHelpers'

const aegisDb = {
  version: 3,
  entries: [
    {
      type: 'totp',
      name: 'alice@example.com',
      issuer: 'GitHub',
      info: { secret: 'JBSWY3DPEHPK3PXP', algo: 'SHA1', digits: 6, period: 30 }
    }
  ]
}

const plaintextExport = {
  version: 1,
  header: { slots: null, params: null },
  db: aegisDb
}

describe('decodeAegisVault', () => {
  it('returns the db for a plaintext export (string or object)', () => {
    expect(decodeAegisVault(JSON.stringify(plaintextExport))).toEqual(aegisDb)
    expect(decodeAegisVault(plaintextExport)).toEqual(aegisDb)
  })

  it('decrypts an encrypted export with the correct password', () => {
    const encrypted = buildEncryptedAegis(aegisDb, 'hunter2')
    expect(decodeAegisVault(encrypted, 'hunter2')).toEqual(aegisDb)
  })

  it('throws a password-required error for an encrypted export with no password', () => {
    const encrypted = buildEncryptedAegis(aegisDb, 'hunter2')
    expect(() => decodeAegisVault(encrypted)).toThrow(/password is required/i)
  })

  it('throws on invalid JSON', () => {
    expect(() => decodeAegisVault('{ not json')).toThrow(/not valid json/i)
  })

  it('throws when db is missing', () => {
    expect(() => decodeAegisVault({ version: 1, header: {} })).toThrow(
      /missing "db"/i
    )
  })
})
