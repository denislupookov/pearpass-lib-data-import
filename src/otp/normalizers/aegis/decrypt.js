import { gcm } from '@noble/ciphers/aes'
import { scrypt } from '@noble/hashes/scrypt'

/**
 * Aegis slot types (see https://github.com/beemdevelopment/Aegis/blob/master/docs/vault.md).
 * Only the password slot (1) can be decrypted with a user-supplied password.
 */
export const AEGIS_SLOT_TYPE = {
  RAW: 0,
  PASSWORD: 1,
  BIOMETRIC: 2
}

const hasBuffer = typeof Buffer !== 'undefined'

const toUtf8 = (str) => new TextEncoder().encode(str)

const fromHex = (hex) => {
  const clean = hex.length % 2 ? `0${hex}` : hex
  const out = new Uint8Array(clean.length / 2)
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16)
  }
  return out
}

const fromBase64 = (b64) =>
  hasBuffer
    ? new Uint8Array(Buffer.from(b64, 'base64'))
    : Uint8Array.from(atob(b64), (c) => c.charCodeAt(0))

const concat = (a, b) => {
  const out = new Uint8Array(a.length + b.length)
  out.set(a, 0)
  out.set(b, a.length)
  return out
}

/**
 * AES-256-GCM decrypt. Aegis stores the ciphertext and the 16-byte auth tag
 * separately, while @noble/ciphers expects them concatenated.
 *
 * @param {Uint8Array} key - 32-byte key
 * @param {Uint8Array} nonce - 12-byte nonce
 * @param {Uint8Array} ciphertext
 * @param {Uint8Array} tag - 16-byte GCM tag
 * @returns {Uint8Array} plaintext
 * @throws if authentication fails (wrong key)
 */
const decryptGcm = (key, nonce, ciphertext, tag) =>
  gcm(key, nonce).decrypt(concat(ciphertext, tag))

/**
 * Recovers the vault master key from a password slot.
 * @param {Object} slot
 * @param {string} password
 * @returns {Uint8Array} 32-byte master key
 * @throws if the password is wrong for this slot (GCM auth failure)
 */
const decryptMasterKeyFromSlot = (slot, password) => {
  const derivedKey = scrypt(toUtf8(password), fromHex(slot.salt), {
    N: slot.n,
    r: slot.r,
    p: slot.p,
    dkLen: 32
  })

  return decryptGcm(
    derivedKey,
    fromHex(slot.key_params.nonce),
    fromHex(slot.key),
    fromHex(slot.key_params.tag)
  )
}

/**
 * Decrypts an encrypted Aegis vault and returns the parsed `db` object.
 *
 * @param {Object} json - the parsed Aegis export (with `db` as a base64 string)
 * @param {string} password - the Aegis export password
 * @returns {{ version?: number, entries?: Object[] }} the decrypted db
 * @throws {Error} biometric-only export, missing password, or wrong password
 */
export const decryptAegisVault = (json, password) => {
  const slots = Array.isArray(json?.header?.slots) ? json.header.slots : []
  const passwordSlots = slots.filter(
    (s) => s?.type === AEGIS_SLOT_TYPE.PASSWORD
  )

  if (passwordSlots.length === 0) {
    throw new Error(
      'This Aegis export is protected with biometrics, not a password. Re-export from Aegis using a password.'
    )
  }

  if (!password) {
    throw new Error('This Aegis export is encrypted. A password is required.')
  }

  let masterKey = null
  for (const slot of passwordSlots) {
    try {
      masterKey = decryptMasterKeyFromSlot(slot, password)
      break
    } catch {
      // Wrong password for this slot — try the next one.
    }
  }

  if (!masterKey) {
    throw new Error('Incorrect password')
  }

  const params = json.header.params
  let plaintext
  try {
    plaintext = decryptGcm(
      masterKey,
      fromHex(params.nonce),
      fromBase64(json.db),
      fromHex(params.tag)
    )
  } catch {
    throw new Error('Decryption failed — corrupted Aegis export')
  }

  return JSON.parse(new TextDecoder().decode(plaintext))
}
