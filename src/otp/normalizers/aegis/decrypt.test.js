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
  it('decrypts a password-protected vault (round-trip)', async () => {
    const json = buildEncryptedAegis(sampleDb, 'hunter2')
    const db = await decryptAegisVault(json, 'hunter2')
    expect(db).toEqual(sampleDb)
  })

  it('offloads the KDF via decryptViaWorklet when provided', async () => {
    const json = buildEncryptedAegis(sampleDb, 'hunter2')
    const { scrypt } = await import('@noble/hashes/scrypt')
    const decryptViaWorklet = jest.fn(({ password, salt, n, r, p }) =>
      Promise.resolve(
        scrypt(new TextEncoder().encode(password), Buffer.from(salt, 'hex'), {
          N: n,
          r,
          p,
          dkLen: 32
        })
      )
    )

    const db = await decryptAegisVault(json, 'hunter2', { decryptViaWorklet })
    expect(db).toEqual(sampleDb)
    expect(decryptViaWorklet).toHaveBeenCalledTimes(1)
  })

  it('rejects with "Incorrect password" on a wrong password', async () => {
    const json = buildEncryptedAegis(sampleDb, 'hunter2')
    await expect(decryptAegisVault(json, 'wrong')).rejects.toThrow(
      /incorrect password/i
    )
  })

  it('rejects with a corrupted error (not "Incorrect password") for a malformed slot', async () => {
    const json = buildEncryptedAegis(sampleDb, 'hunter2')
    json.header.slots[0].salt = 'not-hex!!' // structurally invalid
    await expect(decryptAegisVault(json, 'hunter2')).rejects.toThrow(
      /corrupted/i
    )
  })

  it('rejects with a corrupted error for a wrong-length nonce', async () => {
    const json = buildEncryptedAegis(sampleDb, 'hunter2')
    json.header.slots[0].key_params.nonce = 'aabbcc' // 3 bytes, not 12
    await expect(decryptAegisVault(json, 'hunter2')).rejects.toThrow(
      /corrupted/i
    )
  })

  it('rejects with a corrupted error for invalid scrypt params', async () => {
    const json = buildEncryptedAegis(sampleDb, 'hunter2')
    json.header.slots[0].n = 1000 // not a power of two
    await expect(decryptAegisVault(json, 'hunter2')).rejects.toThrow(
      /corrupted/i
    )
  })

  it('rejects with a password-required error when no password is given', async () => {
    const json = buildEncryptedAegis(sampleDb, 'hunter2')
    await expect(decryptAegisVault(json)).rejects.toThrow(
      /password is required/i
    )
  })

  it('rejects with a biometric error when there is no password slot', async () => {
    const json = buildEncryptedAegis(sampleDb, 'hunter2', {
      biometricOnly: true
    })
    await expect(decryptAegisVault(json, 'hunter2')).rejects.toThrow(
      /biometric/i
    )
  })
})
