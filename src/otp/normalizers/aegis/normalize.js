import { OTP_TYPE, OTP_ALGORITHM } from '../../constants.js'

/** @typedef {import('../../interfaces/OTPRecord.js').OTPRecord} OTPRecord */

const TYPE_MAP = {
  totp: OTP_TYPE.TOTP,
  hotp: OTP_TYPE.HOTP
}

const VALID_ALGORITHMS = new Set(Object.values(OTP_ALGORITHM))

/**
 * Maps a single Aegis entry to an OTPRecord.
 * Returns null for entries we don't support (e.g. "steam") or that lack a
 * secret, so the caller can skip them.
 *
 * @param {Object} entry - one item from the Aegis `db.entries` array
 * @returns {OTPRecord | null}
 */
function mapEntry(entry) {
  const type = TYPE_MAP[entry?.type]
  if (!type) return null

  const info = entry.info || {}
  if (!info.secret) return null

  const algorithmRaw = (info.algo || OTP_ALGORITHM.SHA1).toUpperCase()
  const algorithm = VALID_ALGORITHMS.has(algorithmRaw)
    ? algorithmRaw
    : OTP_ALGORITHM.SHA1

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
