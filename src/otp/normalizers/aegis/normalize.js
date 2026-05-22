import { OTP_TYPE, OTP_ALGORITHM } from '../../constants.js'

/** @typedef {import('../../interfaces/OTPRecord.js').OTPRecord} OTPRecord */

const TYPE_MAP = {
  totp: OTP_TYPE.TOTP,
  hotp: OTP_TYPE.HOTP
}

const VALID_ALGORITHMS = new Set(Object.values(OTP_ALGORITHM))

/**
 * Maps a single Aegis entry to an OTPRecord.
 * Returns null for entries we can't safely import — an unsupported type (e.g.
 * "steam"), a missing/non-string secret, or an unrecognized algorithm — so the
 * caller can skip them without aborting the whole import.
 *
 * @param {Object} entry - one item from the Aegis `db.entries` array
 * @returns {OTPRecord | null}
 */
function mapEntry(entry) {
  const type = TYPE_MAP[entry?.type]
  if (!type) return null

  const info = entry.info || {}
  if (typeof info.secret !== 'string' || !info.secret) return null

  // Default to SHA1 only when the algorithm is absent. A present-but-invalid
  // algorithm is skipped — never silently coerced to SHA1 (which would generate
  // wrong codes for SHA256/SHA512 secrets), and never thrown (which would abort
  // the whole bulk import over one bad entry).
  const algorithm = info.algo ? info.algo.toUpperCase() : OTP_ALGORITHM.SHA1
  if (!VALID_ALGORITHMS.has(algorithm)) return null

  /** @type {OTPRecord} */
  const record = {
    type,
    label: entry.name || '',
    secret: info.secret.toUpperCase().replace(/\s+/g, ''),
    algorithm,
    digits: typeof info.digits === 'number' ? info.digits : 6,
    raw: entry
  }

  if (entry.issuer) record.issuer = entry.issuer

  if (type === OTP_TYPE.TOTP) {
    record.period = typeof info.period === 'number' ? info.period : 30
  } else {
    record.counter = typeof info.counter === 'number' ? info.counter : 0
  }

  return record
}

/**
 * Normalizes a decrypted Aegis vault (`db` object) into OTPRecord[].
 * Unsupported or secret-less entries are skipped.
 *
 * @param {{ entries?: Object[] }} db
 * @returns {OTPRecord[]}
 */
export function normalizeAegisDb(db) {
  const entries = Array.isArray(db?.entries) ? db.entries : []

  const records = []
  for (const entry of entries) {
    const record = mapEntry(entry)
    if (record) records.push(record)
  }

  return records
}
