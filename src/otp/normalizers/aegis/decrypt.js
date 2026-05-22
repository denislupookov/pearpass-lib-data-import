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

class WrongPasswordError extends Error {}

const hasBuffer = typeof Buffer !== 'undefined'
const textEncoder = new TextEncoder()
const textDecoder = new TextDecoder()

const toUtf8 = (str) => textEncoder.encode(str)

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

const HEX_RE = /^[0-9a-fA-F]+$/
const isHex = (value) =>
  typeof value === 'string' &&
  value.length > 0 &&
  value.length % 2 === 0 &&
  HEX_RE.test(value)
const isHexBytes = (value, bytes) => isHex(value) && value.length === bytes * 2
const isPow2 = (n) => Number.isInteger(n) && n > 0 && (n & (n - 1)) === 0

/**
 * @param {Object} slot
 * @throws {Error} if the slot is malformed
 */
const validatePasswordSlot = (slot) => {
  if (
    !isHex(slot?.salt) ||
    !isHex(slot?.key) ||
    !isHexBytes(slot?.key_params?.nonce, 12) ||
    !isHexBytes(slot?.key_params?.tag, 16)
  ) {
    throw new Error('Corrupted Aegis export: malformed encryption slot')
  }
  if (
    !isPow2(slot.n) ||
    !Number.isInteger(slot.r) ||
    slot.r <= 0 ||
    !Number.isInteger(slot.p) ||
    slot.p <= 0
  ) {
    throw new Error('Corrupted Aegis export: invalid scrypt parameters')
  }
}

/**
 * Recovers the vault master key from a single password slot.
 *
 * @param {Object} slot
 * @param {string} password
 * @param {{ decryptViaWorklet?: (params: {
 *   password: string, salt: string, n: number, r: number, p: number
 * }) => Promise<Uint8Array> }} [options]
 * @returns {Promise<Uint8Array>} 32-byte master key
 * @throws {WrongPasswordError} if the password is wrong for this slot
 * @throws {Error} if the slot is structurally corrupt
 */
const decryptMasterKeyFromSlot = async (
  slot,
  password,
  { decryptViaWorklet } = {}
) => {
  validatePasswordSlot(slot)

  const derivedKey = decryptViaWorklet
    ? await decryptViaWorklet({
        password,
        salt: slot.salt,
        n: slot.n,
        r: slot.r,
        p: slot.p
      })
    : scrypt(toUtf8(password), fromHex(slot.salt), {
        N: slot.n,
        r: slot.r,
        p: slot.p,
        dkLen: 32
      })

  try {
    return decryptGcm(
      derivedKey,
      fromHex(slot.key_params.nonce),
      fromHex(slot.key),
      fromHex(slot.key_params.tag)
    )
  } catch {
    throw new WrongPasswordError()
  } finally {
    derivedKey.fill?.(0)
  }
}

/**
 * Decrypts an encrypted Aegis vault and returns the parsed `db` object.
 *
 * @param {Object} json - the parsed Aegis export (with `db` as a base64 string)
 * @param {string} password - the Aegis export password
 * @param {{ decryptViaWorklet?: Function }} [options] - optional KDF offload hook
 * @returns {Promise<{ version?: number, entries?: Object[] }>} the decrypted db
 * @throws {Error} biometric-only export, missing password, wrong password, or corrupted export
 */
export const decryptAegisVault = async (
  json,
  password,
  { decryptViaWorklet } = {}
) => {
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
  let hadStructuralError = false
  for (const slot of passwordSlots) {
    try {
      masterKey = await decryptMasterKeyFromSlot(slot, password, {
        decryptViaWorklet
      })
      break
    } catch (error) {
      if (error instanceof WrongPasswordError) continue
      hadStructuralError = true
    }
  }

  if (!masterKey) {
    throw new Error(
      hadStructuralError
        ? 'Corrupted Aegis export: malformed encryption slot'
        : 'Incorrect password'
    )
  }

  const params = json.header?.params
  if (!isHexBytes(params?.nonce, 12) || !isHexBytes(params?.tag, 16)) {
    masterKey.fill?.(0)
    throw new Error('Corrupted Aegis export: malformed vault parameters')
  }

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
  } finally {
    masterKey.fill?.(0)
  }

  try {
    return JSON.parse(textDecoder.decode(plaintext))
  } finally {
    plaintext.fill?.(0)
  }
}
