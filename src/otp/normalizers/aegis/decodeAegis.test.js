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
  it('returns the db for a plaintext export (string or object)', async () => {
    expect(await decodeAegisVault(JSON.stringify(plaintextExport))).toEqual(
      aegisDb
    )
    expect(await decodeAegisVault(plaintextExport)).toEqual(aegisDb)
  })

  it('decrypts an encrypted export with the correct password', async () => {
    const encrypted = buildEncryptedAegis(aegisDb, 'hunter2')
    expect(await decodeAegisVault(encrypted, 'hunter2')).toEqual(aegisDb)
  })

  it('rejects with a password-required error for an encrypted export with no password', async () => {
    const encrypted = buildEncryptedAegis(aegisDb, 'hunter2')
    await expect(decodeAegisVault(encrypted)).rejects.toThrow(
      /password is required/i
    )
  })

  it('rejects on invalid JSON', async () => {
    await expect(decodeAegisVault('{ not json')).rejects.toThrow(
      /not valid json/i
    )
  })

  it('rejects when db is missing', async () => {
    await expect(decodeAegisVault({ version: 1, header: {} })).rejects.toThrow(
      /missing "db"/i
    )
  })
})
