import { randomBytes } from 'crypto'

import { gcm } from '@noble/ciphers/aes'
import { scrypt } from '@noble/hashes/scrypt'

const toUtf8 = (str) => new TextEncoder().encode(str)
const toHex = (u8) =>
  Array.from(u8, (b) => b.toString(16).padStart(2, '0')).join('')
const toBase64 = (u8) => Buffer.from(u8).toString('base64')

const split = (ctTag) => ({
  ct: ctTag.slice(0, ctTag.length - 16),
  tag: ctTag.slice(ctTag.length - 16)
})

/**
 * Builds an encrypted Aegis export in the real vault format, for tests.
 * Uses small scrypt params (N=1024) so the KDF is fast in CI; the decrypt path
 * reads the slot params, so the code under test runs identically to N=32768.
 *
 * @param {Object} db - the plaintext db ({ version, entries })
 * @param {string} password
 * @param {{ biometricOnly?: boolean }} [options]
 * @returns {Object} encrypted Aegis export JSON
 */
export function buildEncryptedAegis(
  db,
  password,
  { biometricOnly = false } = {}
) {
  const masterKey = new Uint8Array(randomBytes(32))
  const dbNonce = new Uint8Array(randomBytes(12))
  const { ct: dbCt, tag: dbTag } = split(
    gcm(masterKey, dbNonce).encrypt(toUtf8(JSON.stringify(db)))
  )

  const slots = []

  if (biometricOnly) {
    slots.push({ type: 2, uuid: 'bio' })
  } else {
    const salt = new Uint8Array(randomBytes(32))
    const n = 1024
    const r = 8
    const p = 1
    const slotKey = scrypt(toUtf8(password), salt, { N: n, r, p, dkLen: 32 })
    const keyNonce = new Uint8Array(randomBytes(12))
    const { ct: keyCt, tag: keyTag } = split(
      gcm(slotKey, keyNonce).encrypt(masterKey)
    )
    slots.push({
      type: 1,
      uuid: 's1',
      key: toHex(keyCt),
      key_params: { nonce: toHex(keyNonce), tag: toHex(keyTag) },
      n,
      r,
      p,
      salt: toHex(salt),
      repaired: true
    })
  }

  return {
    version: 1,
    header: {
      slots,
      params: { nonce: toHex(dbNonce), tag: toHex(dbTag) }
    },
    db: toBase64(dbCt)
  }
}
