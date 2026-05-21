import { decryptAegisVault } from './decrypt'
import { buildEncryptedAegis } from './testHelpers'

const sampleDb = {
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

describe('decryptAegisVault', () => {
  it('decrypts a password-protected vault (round-trip)', () => {
    const json = buildEncryptedAegis(sampleDb, 'hunter2')
    const db = decryptAegisVault(json, 'hunter2')
    expect(db).toEqual(sampleDb)
  })

  it('throws "Incorrect password" on a wrong password', () => {
    const json = buildEncryptedAegis(sampleDb, 'hunter2')
    expect(() => decryptAegisVault(json, 'wrong')).toThrow(
      /incorrect password/i
    )
  })

  it('throws a password-required error when no password is given', () => {
    const json = buildEncryptedAegis(sampleDb, 'hunter2')
    expect(() => decryptAegisVault(json)).toThrow(/password is required/i)
  })

  it('throws a biometric error when there is no password slot', () => {
    const json = buildEncryptedAegis(sampleDb, 'hunter2', {
      biometricOnly: true
    })
    expect(() => decryptAegisVault(json, 'hunter2')).toThrow(/biometric/i)
  })
})
